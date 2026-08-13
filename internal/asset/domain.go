package asset

import "fmt"

// Domain is a DNS domain name in canonical lowercase form.
type Domain struct {
	// Name is the canonical, normalized domain name (lowercase, no trailing dot).
	Name string `json:"name"`

	// Original preserves the domain exactly as it was first observed.
	Original string `json:"original,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewDomain validates and normalizes name into a Domain.
func NewDomain(name string, p Provenance) (Domain, error) {
	canonical, err := normalizeHost(name)
	if err != nil {
		return Domain{}, fmt.Errorf("invalid domain %q: %w", name, err)
	}
	return Domain{Name: canonical, Original: name, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
func (d Domain) Identity() Identity {
	return Identity{Kind: KindDomain, Value: d.Name}
}

// ID returns the canonical identity string.
func (d Domain) ID() string { return d.Identity().String() }

// String returns the canonical domain name.
func (d Domain) String() string { return d.Name }
