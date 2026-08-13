package asset

import "fmt"

// Host is a named host in canonical lowercase form, e.g. "api.example.com".
//
// A Host is a hostname, not an IP literal. Bare addresses are represented by
// the IP asset so a single value never has an ambiguous identity.
type Host struct {
	// Name is the canonical, normalized hostname (lowercase, no trailing dot).
	Name string `json:"name"`

	// Original preserves the host exactly as it was first observed.
	Original string `json:"original,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewHost validates and normalizes name into a Host.
func NewHost(name string, p Provenance) (Host, error) {
	canonical, err := normalizeHost(name)
	if err != nil {
		return Host{}, fmt.Errorf("invalid host %q: %w", name, err)
	}
	return Host{Name: canonical, Original: name, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
func (h Host) Identity() Identity {
	return Identity{Kind: KindHost, Value: h.Name}
}

// ID returns the canonical identity string.
func (h Host) ID() string { return h.Identity().String() }

// String returns the canonical hostname.
func (h Host) String() string { return h.Name }
