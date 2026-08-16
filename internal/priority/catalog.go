package priority

import (
	"fmt"
	"hash/fnv"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SignalField identifies which slice of a scoring signal an indicator
// matches against. Fields map 1:1 onto data the earlier phases actually
// emit (see doc.go); no field exists for data no phase produces.
type SignalField string

const (
	// FieldPath: the canonical path of the asset — an endpoint's URL path,
	// a URL asset's path, or a JavaScript/source-map resource's URL path.
	FieldPath SignalField = "path"
	// FieldHost: the asset's host name (lowercased labels; also the target
	// of the private-address-range regex family).
	FieldHost SignalField = "host"
	// FieldTechName: a detected technology's canonical name.
	FieldTechName SignalField = "tech_name"
	// FieldTechCategory: a detected technology's canonical category (one of
	// the 21 Phase 2 categories, e.g. "authentication", "cloud_provider").
	FieldTechCategory SignalField = "tech_category"
	// FieldServiceName: a service name observed on a port.
	FieldServiceName SignalField = "service_name"
	// FieldPort: the port number (matched as its decimal string).
	FieldPort SignalField = "port"
	// FieldParameterName: an observed parameter name (urlintel).
	FieldParameterName SignalField = "parameter_name"
	// FieldSecretType: an observed secret candidate's canonical type
	// (secrentel / jsintel vocabulary).
	FieldSecretType SignalField = "secret_type"
	// FieldHeader: an observed final-response header, matched as a
	// lowercased "key: value" line (httpprobe's bounded HeaderEntry list
	// rendered by the Round-2 mapper).
	FieldHeader SignalField = "header"
	// FieldJSBundleSize: the observed JavaScript asset body size in bytes
	// (numeric-threshold matcher).
	FieldJSBundleSize SignalField = "js_bundle_size"
	// FieldKind: the asset kind itself (e.g. source_map assets).
	FieldKind SignalField = "kind"
	// FieldEndpointMethod: the endpoint's method field — which jsintel uses
	// to carry the endpoint class ("WS", "SSE", "GQL", "GET").
	FieldEndpointMethod SignalField = "endpoint_method"
)

// Valid reports whether f is a known signal field.
func (f SignalField) Valid() bool {
	switch f {
	case FieldPath, FieldHost, FieldTechName, FieldTechCategory,
		FieldServiceName, FieldPort, FieldParameterName, FieldSecretType,
		FieldHeader, FieldJSBundleSize, FieldKind, FieldEndpointMethod:
		return true
	}
	return false
}

// Catalog validation bounds (fixed constants).
const (
	// maxIndicatorIDBytes bounds an indicator ID.
	maxIndicatorIDBytes = 64
	// maxCategoryBytes bounds a category name.
	maxCategoryBytes = 64
	// maxTermsPerIndicator bounds the literal term list (the high-value
	// secret family legitimately carries one term per canonical type).
	maxTermsPerIndicator = 32
	// maxTermBytes bounds each literal term.
	maxTermBytes = 64
	// maxIndicatorReasonBytes bounds the reason template.
	maxIndicatorReasonBytes = 256
	// maxIndicatorRecommendationBytes bounds the recommendation template.
	maxIndicatorRecommendationBytes = 256
	// verbBytes is the byte length of the %s substitution verb.
	verbBytes = 2
)

// Indicator is one catalog entry: a category's weight when its matcher
// fires on a signal field. Exactly ONE matcher form is present per entry —
// literal Terms, a Regex, a numeric MinJSBytes threshold, or a Kind
// equality — and Load enforces the exclusivity.
//
// Terms are lowercase literals matched as substrings of the lowercased
// field value (per-item for list fields). Regex is an RE2 expression
// applied to the same value. Reason is a template whose single %s is
// substituted with the matched term and whose only percent sign is that
// seam (regex and threshold matchers use the reason verbatim, percent-free).
//
// Recommendation is the reconnaissance-guidance template for the same
// match, with the identical substitution contract and byte bounds as
// Reason: term entries carry exactly one %s that receives the matched term
// and no other percent sign; regex, size, and kind entries carry verbatim,
// percent-free text. The guidance must reference the entry's evidence
// type — generic boilerplate is a data bug the production-table test
// rejects.
type Indicator struct {
	ID             string      `json:"id"`
	Category       string      `json:"category"`
	Weight         float64     `json:"weight"`
	Field          SignalField `json:"field"`
	Terms          []string    `json:"terms,omitempty"`
	Regex          string      `json:"regex,omitempty"`
	MinJSBytes     int64       `json:"min_js_bytes,omitempty"`
	Kind           string      `json:"kind,omitempty"`
	Reason         string      `json:"reason"`
	Recommendation string      `json:"recommendation"`

	// re is Regex compiled exactly once by the compiler; the engine never
	// compiles its own regular expressions.
	re *regexp.Regexp
}

// MatchRe returns the compiled regex (nil for non-regex entries). The
// returned instance is shared and immutable.
func (i Indicator) MatchRe() *regexp.Regexp { return i.re }

// SchemaVersion versions the catalog schemas and data semantics. Round 2's
// cache keys must include it: bumping it invalidates every cached score by
// construction. Never reuse a bumped version number.
const SchemaVersion = 1

// Catalog is an immutable, validated, compile-once indicator catalog. A
// Catalog is produced only by LoadInterestingness / LoadRisk (production
// tables) or CompileForTest; it never mutates after construction.
type Catalog struct {
	schemaVersion int
	name          string
	entries       []Indicator // sorted by ID
}

// SchemaVersion returns the catalog schema version.
func (c *Catalog) SchemaVersion() int { return c.schemaVersion }

// Name returns the catalog's stable name ("interestingness" or "risk" for
// the production catalogs; test catalogs carry their given name).
func (c *Catalog) Name() string { return c.name }

// Len returns the number of entries.
func (c *Catalog) Len() int { return len(c.entries) }

// Entries returns every indicator sorted deterministically by ID. The
// returned slice is a fresh copy (compiled regex pointers are shared and
// never rewritten).
func (c *Catalog) Entries() []Indicator {
	out := make([]Indicator, len(c.entries))
	copy(out, c.entries)
	return out
}

// ByID returns the indicator with the given ID and whether it exists.
func (c *Catalog) ByID(id string) (Indicator, bool) {
	for _, e := range c.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Indicator{}, false
}

// compile validates and compiles raw entries into an immutable catalog.
// Duplicate IDs, malformed regexes, out-of-range weights, non-lowercase
// terms, mixed matcher forms, and field/matcher mismatches fail the load so
// a malformed table can never reach the scoring engine.
func compile(name string, entries []Indicator) (*Catalog, error) {
	c := &Catalog{schemaVersion: SchemaVersion, name: name}
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		if err := validateIndicator(raw); err != nil {
			return nil, err
		}
		if _, dup := seen[raw.ID]; dup {
			return nil, fmt.Errorf("duplicate indicator ID %q in catalog %q", raw.ID, name)
		}
		seen[raw.ID] = struct{}{}
		e := raw
		if e.Regex != "" {
			e.re = regexp.MustCompile(e.Regex)
		}
		c.entries = append(c.entries, e)
	}
	sort.Slice(c.entries, func(i, j int) bool {
		return c.entries[i].ID < c.entries[j].ID
	})
	return c, nil
}

// CompileForTest builds a catalog through exactly the Load pipeline
// (validation, compile-once regexes, deterministic sort) over
// caller-supplied entries, so validation paths are testable without
// touching the production tables.
func CompileForTest(name string, entries []Indicator) (*Catalog, error) {
	return compile(name, entries)
}

// validateIndicator enforces the data model on one raw entry.
func validateIndicator(e Indicator) error {
	if e.ID == "" || len(e.ID) > maxIndicatorIDBytes {
		return fmt.Errorf("indicator ID %q is empty or over %d bytes", e.ID, maxIndicatorIDBytes)
	}
	if err := validateLowercaseToken("ID", e.ID); err != nil {
		return err
	}
	if e.Category == "" || len(e.Category) > maxCategoryBytes {
		return fmt.Errorf("indicator %q category is empty or over %d bytes", e.ID, maxCategoryBytes)
	}
	if err := validateLowercaseToken("category", e.Category); err != nil {
		return err
	}
	// NaN compares false against every bound, so it is rejected explicitly:
	// a NaN weight would propagate into a NaN score through every factor it
	// emits.
	if math.IsNaN(e.Weight) || e.Weight <= 0 || e.Weight > 1 {
		return fmt.Errorf("indicator %q weight %v must satisfy 0 < weight <= 1", e.ID, e.Weight)
	}
	if !e.Field.Valid() {
		return fmt.Errorf("indicator %q has unknown field %q", e.ID, e.Field)
	}

	// Exactly one matcher form per entry; the matcher shape is validated
	// before the text contracts so a structurally broken entry reports its
	// structural problem first.
	matcher := 0
	if len(e.Terms) > 0 {
		matcher++
	}
	if e.Regex != "" {
		matcher++
	}
	if e.MinJSBytes > 0 {
		matcher++
	}
	if e.Kind != "" {
		matcher++
	}
	if matcher != 1 {
		return fmt.Errorf("indicator %q must carry exactly one matcher (terms, regex, min_js_bytes, or kind), got %d", e.ID, matcher)
	}

	if len(e.Terms) > maxTermsPerIndicator {
		return fmt.Errorf("indicator %q has %d terms over bound %d", e.ID, len(e.Terms), maxTermsPerIndicator)
	}
	for _, t := range e.Terms {
		if t == "" {
			return fmt.Errorf("indicator %q has an empty term", e.ID)
		}
		if len(t) > maxTermBytes {
			return fmt.Errorf("indicator %q term %q is over %d bytes", e.ID, t, maxTermBytes)
		}
		if t != lowercaseASCII(t) {
			return fmt.Errorf("indicator %q term %q must be lowercase", e.ID, t)
		}
	}
	if e.Regex != "" {
		if _, err := regexp.Compile(e.Regex); err != nil {
			return fmt.Errorf("indicator %q regex %q does not compile: %w", e.ID, e.Regex, err)
		}
	}
	if e.MinJSBytes < 0 {
		return fmt.Errorf("indicator %q: min_js_bytes %d must not be negative", e.ID, e.MinJSBytes)
	}
	if e.MinJSBytes > 0 && e.Field != FieldJSBundleSize {
		return fmt.Errorf("indicator %q: min_js_bytes is only valid for field js_bundle_size", e.ID)
	}
	if e.Kind != "" && e.Field != FieldKind {
		return fmt.Errorf("indicator %q: kind matcher is only valid for field kind", e.ID)
	}

	// Compile-time rendered-text bounds: a term entry's templates carry
	// exactly one %s each — their only percent sign — rendered with that
	// %s replaced by the matched term, whose worst case is the
	// bound-maximal term, so the rendered reason and recommendation can
	// never exceed their bounds and the emitted Factor (bounded by the
	// same constants) can never violate its own contract. Non-term
	// matchers use both texts verbatim, percent-free.
	if e.Reason == "" {
		return fmt.Errorf("indicator %q reason is empty", e.ID)
	}
	if e.Recommendation == "" {
		return fmt.Errorf("indicator %q recommendation is empty", e.ID)
	}
	if len(e.Terms) > 0 {
		if err := validateRenderedBound("reason", e.ID, e.Reason, maxIndicatorReasonBytes); err != nil {
			return err
		}
		if err := validateRenderedBound("recommendation", e.ID, e.Recommendation, maxIndicatorRecommendationBytes); err != nil {
			return err
		}
	} else {
		if len(e.Reason) > maxIndicatorReasonBytes {
			return fmt.Errorf("indicator %q reason is over %d bytes", e.ID, maxIndicatorReasonBytes)
		}
		if len(e.Recommendation) > maxIndicatorRecommendationBytes {
			return fmt.Errorf("indicator %q recommendation is over %d bytes", e.ID, maxIndicatorRecommendationBytes)
		}
		// Non-term matchers use both texts verbatim and substitute nothing:
		// ANY percent sign would leak into the emitted factor raw.
		for _, tv := range []struct{ what, text string }{
			{"reason", e.Reason}, {"recommendation", e.Recommendation},
		} {
			if strings.Contains(tv.text, "%") {
				return fmt.Errorf("indicator %q non-templated %s must not contain a percent sign (verbatim text substitutes no verb)", e.ID, tv.what)
			}
		}
	}
	return nil
}

// validateLowercaseToken enforces the [a-z0-9_.-] form shared by IDs and
// categories (stable, filesystem- and key-safe).
func validateLowercaseToken(what, s string) error {
	for i := 0; i < len(s); i++ {
		b := s[i]
		allowed := b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.'
		if !allowed {
			return fmt.Errorf("%s %q must be lowercase [a-z0-9_.-]", what, s)
		}
	}
	return nil
}

// validateRenderedBound enforces the templated-text contract for term
// entries: the template must carry EXACTLY ONE %s substitution seam and NO
// other percent sign anywhere (score-time rendering substitutes the matched
// term for exactly one %s occurrence, so any other percent — %q, %d, %v,
// %%, … — would leak into the emitted factor raw), and its worst-case
// rendered length — the template with its %s replaced by a bound-maximal
// term — must stay within bound:
//
//	len(template) − len("%s") + maxTermBytes ≤ bound
//
// so no matched term can push the rendered text past the model-side factor
// bound. The identical contract governs reasons and recommendations.
func validateRenderedBound(what, id, template string, bound int) error {
	if n := strings.Count(template, "%s"); n != 1 {
		return fmt.Errorf("indicator %q %s template must carry exactly one %%s for the matched term, found %d", id, what, n)
	}
	if strings.Contains(template, "%q") {
		return fmt.Errorf("indicator %q %s template must not carry a %%q verb; only the single %%s term seam is substituted", id, what)
	}
	if strings.Contains(strings.Replace(template, "%s", "", 1), "%") {
		return fmt.Errorf("indicator %q %s template must not carry any percent sign beyond the single %%s term seam", id, what)
	}
	if worst := len(template) - verbBytes + maxTermBytes; worst > bound {
		return fmt.Errorf("indicator %q worst-case rendered %s is %d bytes over bound %d", id, what, worst, bound)
	}
	return nil
}

// Digest returns the FNV-1a 64-bit fingerprint of the catalog's rendered
// entries: every entry field that materially changes scoring behavior (ID,
// category, weight, field, matcher, reason, recommendation), rendered in
// deterministic entry order (sorted by ID). Any edit to any entry changes
// the digest, which is what lets cache keys (Round 2) invalidate every
// cached score the moment a catalog changes. The digest is computed over
// the compiled catalog, so it is stable across loads and processes.
func (c *Catalog) Digest() uint64 {
	h := fnv.New64a()
	for _, e := range c.entries {
		h.Write([]byte(e.ID))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Category))
		h.Write([]byte{0x1f})
		h.Write([]byte(strconv.FormatUint(math.Float64bits(e.Weight), 16)))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Field))
		h.Write([]byte{0x1f})
		h.Write([]byte(strings.Join(e.Terms, "\x1e")))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Regex))
		h.Write([]byte{0x1f})
		h.Write([]byte(strconv.FormatInt(e.MinJSBytes, 10)))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Kind))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Reason))
		h.Write([]byte{0x1f})
		h.Write([]byte(e.Recommendation))
		h.Write([]byte{'\n'})
	}
	return h.Sum64()
}

// CatalogsDigest returns the combined fingerprint of both production
// catalogs (interestingness, then risk) as a stable hex string for cache
// keys. Either nil catalog yields "" (the caller decides whether that is an
// error); the combine separator keeps the pair fingerprint unforgeable by
// concatenation.
func CatalogsDigest(interesting, risk *Catalog) string {
	if interesting == nil || risk == nil {
		return ""
	}
	h := fnv.New64a()
	h.Write([]byte(strconv.FormatUint(interesting.Digest(), 16)))
	h.Write([]byte{0x1e})
	h.Write([]byte(strconv.FormatUint(risk.Digest(), 16)))
	return strconv.FormatUint(h.Sum64(), 16)
}

// lowercaseASCII lowercases ASCII bytes only (deterministic on any input).
func lowercaseASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
