package asset

import (
	"strings"
	"testing"
)

func TestNewRelationship(t *testing.T) {
	p := NewProvenance("manual")
	host, _ := NewHost("api.example.com", p)
	ip, _ := NewIP("1.2.3.4", p)

	r, err := NewRelationship(host.Identity(), RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	if r.ID() != "host:api.example.com"+"host_to_ip\x00"+"ip:1.2.3.4" {
		t.Errorf("relationship ID = %q", r.ID())
	}

	r2, err := NewRelationship(host.Identity(), RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	if r.ID() != r2.ID() {
		t.Error("identical edges must deduplicate to the same identity")
	}

	r3, _ := NewRelationship(ip.Identity(), RelationshipIPToPort, r2.To)
	if r3.ID() == r.ID() {
		t.Error("different kinds must not share an identity")
	}

	r4, _ := NewRelationship(r2.To, RelationshipPortToService, r.From)
	if r4.ID() == r.ID() {
		t.Error("reversed edges must not share an identity")
	}
}

func TestNewRelationshipValidation(t *testing.T) {
	p := NewProvenance("manual")
	host, _ := NewHost("api.example.com", p)
	ip, _ := NewIP("1.2.3.4", p)

	cases := []struct {
		name string
		from Identity
		kind RelationshipKind
		to   Identity
	}{
		{"zero from", Identity{}, RelationshipHostToIP, ip.Identity()},
		{"empty kind", host.Identity(), RelationshipKind(""), ip.Identity()},
		{"blank kind", host.Identity(), RelationshipKind("  "), ip.Identity()},
		{"zero to", host.Identity(), RelationshipHostToIP, Identity{}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewRelationship(tt.from, tt.kind, tt.to); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestRelationshipConstants(t *testing.T) {
	kinds := []RelationshipKind{
		RelationshipHostToIP,
		RelationshipIPToPort,
		RelationshipPortToService,
		RelationshipHostToURL,
		RelationshipURLToEndpoint,
		RelationshipURLToJavaScript,
	}
	seen := map[RelationshipKind]bool{}
	for _, k := range kinds {
		if k == "" {
			t.Error("relationship kind must not be empty")
		}
		if seen[k] {
			t.Errorf("duplicate relationship kind %q", k)
		}
		seen[k] = true
	}
}

// TestNewRelationshipKindBounds pins NEW-83: relationship kinds are bounded
// printable-ASCII labels (<= maxRelationshipKindBytes), like the other
// identity-bearing labels of this package.
func TestNewRelationshipKindBounds(t *testing.T) {
	p := NewProvenance("manual")
	host, _ := NewHost("api.example.com", p)
	ip, _ := NewIP("1.2.3.4", p)

	// The longest vocabulary value is well within the bound.
	longest := RelationshipSecretCandidateToEvidence
	if len(longest) >= maxRelationshipKindBytes {
		t.Fatalf("longest vocabulary kind %q reached the bound; revisit maxRelationshipKindBytes", string(longest))
	}

	if _, err := NewRelationship(host.Identity(), RelationshipKind(strings.Repeat("k", maxRelationshipKindBytes)), ip.Identity()); err != nil {
		t.Fatalf("kind exactly at the %d-byte bound must be accepted: %v", maxRelationshipKindBytes, err)
	}
	if _, err := NewRelationship(host.Identity(), RelationshipKind(strings.Repeat("k", maxRelationshipKindBytes+1)), ip.Identity()); err == nil {
		t.Errorf("kind over the %d-byte bound must be rejected", maxRelationshipKindBytes)
	}
	for _, kind := range []RelationshipKind{
		"host_to\x00ip",
		"host_to\nip",
		"host_to\u00a0ip", // NBSP: non-ASCII, previously folded through unchecked
	} {
		if _, err := NewRelationship(host.Identity(), kind, ip.Identity()); err == nil {
			t.Errorf("non-printable kind %q must be rejected", string(kind))
		}
	}
}
