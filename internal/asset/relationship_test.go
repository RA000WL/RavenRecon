package asset

import "testing"

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
