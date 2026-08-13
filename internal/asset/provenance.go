package asset

import "time"

// Provenance records where and when a single asset observation came from.
//
// Source names are generic capabilities ("passive-discovery", "http-probe",
// "manual") rather than specific binaries, so the core asset model never
// depends on particular external tools.
type Provenance struct {
	// Source identifies the capability that produced the observation.
	Source string `json:"source,omitempty"`

	// DiscoveredAt is the time the observation was made.
	DiscoveredAt time.Time `json:"discovered_at"`

	// Reference is an optional tool-specific identifier that can trace the
	// observation back to its origin.
	Reference string `json:"reference,omitempty"`

	// Confidence is an optional 0..1 estimate of how reliable the observation is.
	Confidence float64 `json:"confidence,omitempty"`
}

// NewProvenance returns a Provenance for the given source with the current
// timestamp in UTC.
func NewProvenance(source string) Provenance {
	return Provenance{Source: source, DiscoveredAt: time.Now().UTC()}
}
