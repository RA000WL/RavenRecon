package asset

import (
	"fmt"
	"time"
)

// maxParameterValues bounds the number of observed values retained per
// parameter.
//
// This is the "huge parameter lists" security bound: a hostile page or a
// noisy observation stream could otherwise grow a single parameter's
// ObservedValues without bound (for example an ID-oracle endpoint
// enumerating thousands of distinct values for one parameter). Retention
// is stable: values already observed are never evicted; only NEW values
// beyond the cap are dropped, and the Parameter's Truncated flag is set so
// consumers know the observed list is incomplete.
const maxParameterValues = 1024

// Single-observation bounds applied by NewParameter and WithValue.
const (
	// maxParameterNameBytes bounds a parameter name. Names are embedded in
	// the identity value, so this also bounds identity sizes.
	maxParameterNameBytes = 512
	// maxParameterValueBytes bounds one observed value.
	maxParameterValueBytes = 8 * 1024
	// maxParameterSourceBytes bounds one source name.
	maxParameterSourceBytes = 128
)

// Parameter is a named parameter observed in a request, gathering every
// value seen for it over time.
//
// A parameter's identity is its NAME within its LOCATION: two observations
// of "q" in the query of different URLs are the same parameter, while "q"
// in the path is a different one. Observed values are observations of that
// identity — not separate assets — so a parameter with many values is one
// asset and the identity never depends on which values were seen.
//
// Names are not normalized beyond validation: distinct raw spellings ("a b"
// vs "a%20b") stay distinct identities, mirroring the URL model's
// value-preserving philosophy.
type Parameter struct {
	// Name is the parameter name exactly as observed.
	Name string `json:"name"`

	// Location is where the parameter was observed: "query" today; "path"
	// and "body" are reserved for future phases. Only allowlisted locations
	// are accepted, and the value must already be canonical (lowercase).
	Location string `json:"location"`

	// ObservedValues is the ordered, deduplicated list of values observed
	// for this parameter, capped at maxParameterValues. Truncated reports
	// dropped observations.
	ObservedValues []string `json:"observed_values,omitempty"`

	// FirstSeen is the time of the earliest observation.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is the time of the latest observation.
	LastSeen time.Time `json:"last_seen"`

	// Sources is the ordered, deduplicated list of sources that observed
	// this parameter.
	Sources []string `json:"sources,omitempty"`

	// Truncated reports whether observations were dropped because the
	// ObservedValues cap was reached. It is sticky: once true it stays true.
	Truncated bool `json:"truncated,omitempty"`

	// Prov records where and when the first observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewParameter builds a validated Parameter from a single observation:
// value observed by source at time at, with provenance p. It returns an
// error when name, location, value, or source fail their bounds.
func NewParameter(name, location string, value string, source string, at time.Time, p Provenance) (Parameter, error) {
	if err := validateParameterName(name); err != nil {
		return Parameter{}, err
	}
	if !validParameterLocation(location) {
		return Parameter{}, fmt.Errorf("unsupported parameter location %q", location)
	}
	if err := validateParameterValue(value); err != nil {
		return Parameter{}, err
	}
	if err := validateParameterSource(source); err != nil {
		return Parameter{}, err
	}
	return Parameter{
		Name:           name,
		Location:       location,
		ObservedValues: []string{value},
		FirstSeen:      at,
		LastSeen:       at,
		Sources:        []string{source},
		Prov:           p,
	}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity value is the location-prefixed, percent-encoded name, e.g.
// "query:page" or "path:file". The location prefix (service.go's
// port-prefix trick) namespaces names so "query:a" can never collide with
// "path:a", and the name is passed through percentEncode so it can never
// blur the location/name boundary: the encoded form contains no ':' and
// percentEncode is injective, so distinct raw names always produce distinct
// identity values. Observed values never enter the identity — they are
// observations of the parameter, not its identity.
func (p Parameter) Identity() Identity {
	return Identity{Kind: KindParameter, Value: p.Location + ":" + percentEncode(p.Name)}
}

// ID returns the canonical identity string.
func (p Parameter) ID() string { return p.Identity().String() }

// String returns the canonical identity value, e.g. "query:page".
func (p Parameter) String() string { return p.Location + ":" + percentEncode(p.Name) }

// WithValue returns a copy of p carrying one more observation of the same
// parameter: value observed by source at time at. It never mutates p.
//
// A value already observed is not appended again (the list stays
// deduplicated), but the observation itself is still recorded: LastSeen
// advances and source is added to Sources once. When the ObservedValues
// cap (maxParameterValues) is reached, NEW values are dropped — existing
// values are never evicted — and Truncated is set. FirstSeen and Prov are
// never changed here; only MergeParameters combines two observation
// histories.
func WithValue(p Parameter, value string, source string, at time.Time) (Parameter, error) {
	if err := validateParameterValue(value); err != nil {
		return Parameter{}, err
	}
	if err := validateParameterSource(source); err != nil {
		return Parameter{}, err
	}
	out := p
	if out.FirstSeen.IsZero() {
		out.FirstSeen = at
	}
	if at.After(out.LastSeen) {
		out.LastSeen = at
	}
	if !containsString(out.Sources, source) {
		out.Sources = append(out.Sources, source)
	}
	if !containsString(out.ObservedValues, value) {
		if len(out.ObservedValues) >= maxParameterValues {
			out.Truncated = true
		} else {
			out.ObservedValues = append(out.ObservedValues, value)
		}
	}
	return out, nil
}

// validParameterLocation reports whether location is allowlisted. "query"
// is the canonical location today; "path" and "body" are reserved for
// future phases and already accepted so the model is stable once they land.
func validParameterLocation(location string) bool {
	switch location {
	case "query", "path", "body":
		return true
	}
	return false
}

// validateParameterName enforces the name bounds: non-empty, at most
// maxParameterNameBytes bytes, and no control characters (C0 controls and
// DEL). Non-ASCII bytes are allowed: they arrive from URL query strings
// exactly as observed and stay as-observed.
func validateParameterName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("parameter name must not be empty")
	}
	if len(name) > maxParameterNameBytes {
		return fmt.Errorf("parameter name is longer than %d bytes", maxParameterNameBytes)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return fmt.Errorf("parameter name %q contains a control character", name)
		}
	}
	return nil
}

// validateParameterValue enforces the value bounds: non-empty and at most
// maxParameterValueBytes bytes. Values are opaque observed bytes; no
// character restrictions apply beyond the size bound.
func validateParameterValue(value string) error {
	if len(value) == 0 {
		return fmt.Errorf("parameter value must not be empty")
	}
	if len(value) > maxParameterValueBytes {
		return fmt.Errorf("parameter value is longer than %d bytes", maxParameterValueBytes)
	}
	return nil
}

// validateParameterSource enforces the source bounds: non-empty and at most
// maxParameterSourceBytes bytes.
func validateParameterSource(source string) error {
	if len(source) == 0 {
		return fmt.Errorf("parameter source must not be empty")
	}
	if len(source) > maxParameterSourceBytes {
		return fmt.Errorf("parameter source is longer than %d bytes", maxParameterSourceBytes)
	}
	return nil
}

// containsString reports whether s is present in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
