package asset

import "testing"

// TestRelationshipHostToCNAME covers the additive host-to-CNAME edge kind
// introduced with the v0.6 DNS pipeline (milestone 5A). It is a distinct,
// typed edge: the same pair of hosts with a different kind (or the reverse
// direction) must not share an identity.
func TestRelationshipHostToCNAME(t *testing.T) {
	p := NewProvenance("dns")
	host, err := NewHost("www.example.com", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	target, err := NewHost("origin.example.com", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	r, err := NewRelationship(host.Identity(), RelationshipHostToCNAME, target.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	want := "host:www.example.com" + "host_to_cname\x00" + "host:origin.example.com"
	if r.ID() != want {
		t.Errorf("relationship ID = %q, want %q", r.ID(), want)
	}

	r2, err := NewRelationship(host.Identity(), RelationshipHostToCNAME, target.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	if r.ID() != r2.ID() {
		t.Error("identical edges must deduplicate to the same identity")
	}

	// The host-to-IP edge for the same pair of identities must differ.
	ip, err := NewIP("192.0.2.1", p)
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	r3, err := NewRelationship(host.Identity(), RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	if r3.ID() == r.ID() {
		t.Error("different kinds must not share an identity")
	}

	// The reversed edge must differ.
	r4, err := NewRelationship(target.Identity(), RelationshipHostToCNAME, host.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	if r4.ID() == r.ID() {
		t.Error("reversed edges must not share an identity")
	}
}
