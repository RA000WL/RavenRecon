package asset

import (
	"fmt"
	"net/netip"
	"strings"
)

// IP is a canonical IP address (IPv4 or IPv6).
type IP struct {
	// Addr is the canonical address. IPv4-mapped IPv6 addresses are
	// rewritten to IPv4 for deterministic identity.
	Addr netip.Addr `json:"addr"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewIP parses and canonicalizes s into an IP asset.
func NewIP(s string, p Provenance) (IP, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return IP{}, fmt.Errorf("invalid IP %q: %w", s, err)
	}
	return IP{Addr: addr.Unmap(), Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
func (ip IP) Identity() Identity {
	return Identity{Kind: KindIP, Value: ip.Addr.String()}
}

// ID returns the canonical identity string.
func (ip IP) ID() string { return ip.Identity().String() }

// String returns the canonical address string.
func (ip IP) String() string { return ip.Addr.String() }
