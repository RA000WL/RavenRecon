package asset

import "testing"

// TestRelationshipHostToMXNSSRV covers the NEW-126 T2 edge kinds: directed
// host->host edges with the same identity/dedup/sort semantics as the
// existing DNS kinds (host_to_cname). Unknown-kind rejection is preserved.
func TestRelationshipHostToMXNSSRV(t *testing.T) {
	p := NewProvenance("dns")
	host, err := NewHost("www.example.com", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	mx, err := NewHost("mail.example.net", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	ns, err := NewHost("ns1.example.net", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	srv, err := NewHost("sip.example.net", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	kinds := []struct {
		kind RelationshipKind
		to   Host
	}{
		{RelationshipHostToMX, mx},
		{RelationshipHostToNS, ns},
		{RelationshipHostToSRV, srv},
	}
	for _, tc := range kinds {
		t.Run(string(tc.kind), func(t *testing.T) {
			if !tc.kind.Valid() {
				t.Fatalf("kind %q must be valid", string(tc.kind))
			}
			r, err := NewRelationship(host.Identity(), tc.kind, tc.to.Identity())
			if err != nil {
				t.Fatalf("NewRelationship: %v", err)
			}
			want := encodeIdentity(host.Identity().String()) + "\x00" + string(tc.kind) + "\x00" + encodeIdentity(tc.to.Identity().String())
			if r.ID() != want {
				t.Errorf("relationship ID = %q, want %q", r.ID(), want)
			}
			r2, err := NewRelationship(host.Identity(), tc.kind, tc.to.Identity())
			if err != nil {
				t.Fatalf("NewRelationship: %v", err)
			}
			if r.ID() != r2.ID() {
				t.Error("identical edges must deduplicate to the same identity")
			}
			// Reversed edge stays distinct.
			rev, err := NewRelationship(tc.to.Identity(), tc.kind, host.Identity())
			if err != nil {
				t.Fatalf("NewRelationship reversed: %v", err)
			}
			if rev.ID() == r.ID() {
				t.Error("reversed edges must not share an identity")
			}
		})
	}

	// The three new kinds are mutually distinct for the same host pair.
	mk := func(k RelationshipKind) string {
		r, err := NewRelationship(host.Identity(), k, mx.Identity())
		if err != nil {
			t.Fatalf("NewRelationship(%q): %v", string(k), err)
		}
		return r.ID()
	}
	if mk(RelationshipHostToMX) == mk(RelationshipHostToNS) ||
		mk(RelationshipHostToMX) == mk(RelationshipHostToSRV) ||
		mk(RelationshipHostToNS) == mk(RelationshipHostToSRV) {
		t.Error("distinct kinds for the same host pair must not share an identity")
	}
	// New kinds differ from the existing CNAME kind for the same pair.
	cname, err := NewRelationship(host.Identity(), RelationshipHostToCNAME, mx.Identity())
	if err != nil {
		t.Fatalf("NewRelationship cname: %v", err)
	}
	if cname.ID() == mk(RelationshipHostToMX) {
		t.Error("host_to_mx must not collide with host_to_cname for the same pair")
	}
}

// TestRelationshipUnknownKindRejected preserves the fixed-vocabulary
// enforcement after the T2 additions: unknown kinds — including TXT-shaped
// labels (TXT is strings, never a host relation) — are rejected.
func TestRelationshipUnknownKindRejected(t *testing.T) {
	p := NewProvenance("dns")
	host, _ := NewHost("www.example.com", p)
	target, _ := NewHost("mail.example.net", p)
	for _, kind := range []RelationshipKind{
		"host_to_txt",
		"host_to_caa",
		"host_to_soa",
		"host_to_mail",
		"mx",
		"",
		"  ",
	} {
		if _, err := NewRelationship(host.Identity(), kind, target.Identity()); err == nil {
			t.Errorf("unknown kind %q must be rejected", string(kind))
		}
		if kind.Valid() {
			t.Errorf("kind %q must not report Valid", string(kind))
		}
	}
}
