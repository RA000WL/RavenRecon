package asset

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNewTechnology(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "tech-detect", DiscoveredAt: at, Reference: "fp-1", Confidence: 0.9}

	tech, err := NewTechnology("  API   Gateway ", CategoryAPIGateway, p)
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	if tech.Name != "api gateway" {
		t.Errorf("Name = %q, want %q", tech.Name, "api gateway")
	}
	if tech.Category != CategoryAPIGateway {
		t.Errorf("Category = %q, want %q", tech.Category, CategoryAPIGateway)
	}
	if tech.Version != "" {
		t.Errorf("Version = %q, want empty", tech.Version)
	}
	if tech.Prov != p {
		t.Errorf("Prov = %v, want %v", tech.Prov, p)
	}
	if tech.ID() != "technology:api_gateway/api%20gateway" {
		t.Errorf("ID = %q, want technology:api_gateway/api%%20gateway", tech.ID())
	}
	if tech.Identity().Kind != KindTechnology {
		t.Errorf("kind = %q, want %q", tech.Identity().Kind, KindTechnology)
	}
	if tech.String() != "api_gateway/api%20gateway" {
		t.Errorf("String = %q, want api_gateway/api%%20gateway", tech.String())
	}
}

func TestNewTechnologyValidation(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}

	cases := []struct {
		name     string
		techName string
		category TechnologyCategory
		wantSub  string
	}{
		{"empty name", "   ", CategoryServer, "must not be empty"},
		{"oversized name", strings.Repeat("a", 129), CategoryServer, "longer than 128 bytes"},
		{"NUL in name", "ngin\x00x", CategoryServer, "non-printable character"},
		{"DEL in name", "ngin\x7fx", CategoryServer, "non-printable character"},
		{"non-ASCII name", "café", CategoryServer, "non-printable character"},
		{"bad category", "nginx", TechnologyCategory("bogus"), "invalid technology category"},
		{"empty category", "nginx", TechnologyCategory(""), "invalid technology category"},
		{"uppercase category", "nginx", TechnologyCategory("Server"), "invalid technology category"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tech, err := NewTechnology(tt.techName, tt.category, p)
			if err == nil {
				t.Fatalf("expected error, got %#v", tech)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// The exact byte bound is accepted.
	if _, err := NewTechnology(strings.Repeat("a", 128), CategoryServer, p); err != nil {
		t.Errorf("128-byte name must construct: %v", err)
	}
}

func TestTechnologyNameCanonicalization(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}

	cases := []struct{ raw, want string }{
		{"  API   Gateway ", "api gateway"},
		{"Next.js", "next.js"},
		{" CDN ", "cdn"},
		{"PHP\t8", "php 8"},
		{"node  JS", "node js"},
		{"WordPress 6.4.2", "wordpress 6.4.2"},
	}
	for _, tt := range cases {
		tech, err := NewTechnology(tt.raw, CategoryFramework, p)
		if err != nil {
			t.Errorf("NewTechnology(%q): %v", tt.raw, err)
			continue
		}
		if tech.Name != tt.want {
			t.Errorf("canonical name of %q = %q, want %q", tt.raw, tech.Name, tt.want)
		}
	}
}

func TestTechnologyCategories(t *testing.T) {
	// All 21 known values are valid and canonical lowercase, and
	// ParseTechnologyCategory round-trips each one.
	if n := len(KnownCategories()); n != 21 {
		t.Fatalf("KnownCategories has %d entries, want 21", n)
	}
	for _, c := range KnownCategories() {
		if !c.Valid() {
			t.Errorf("%q must be Valid", c)
		}
		got, err := ParseTechnologyCategory(c.String())
		if err != nil {
			t.Errorf("ParseTechnologyCategory(%q): %v", c, err)
			continue
		}
		if got != c {
			t.Errorf("ParseTechnologyCategory(%q) = %q", c, got)
		}
		if c.String() != string(c) {
			t.Errorf("%q String() must be the canonical lowercase value", c)
		}
	}

	// Garbage is rejected, never coerced.
	for _, bad := range []string{"", "bogus", "Framework", "CDN ", " cdn", "cdn/x", "framework ", "CDN"} {
		if _, err := ParseTechnologyCategory(bad); err == nil {
			t.Errorf("ParseTechnologyCategory(%q) must fail", bad)
		}
		if TechnologyCategory(bad).Valid() {
			t.Errorf("%q must not be Valid", bad)
		}
	}
}

func TestKnownCategoriesSortedAndFresh(t *testing.T) {
	first := KnownCategories()
	if len(first) != 21 {
		t.Fatalf("KnownCategories has %d entries, want 21", len(first))
	}
	strs := make([]string, len(first))
	for i, c := range first {
		strs[i] = c.String()
	}
	if !sort.StringsAreSorted(strs) {
		t.Errorf("KnownCategories must be sorted, got %v", strs)
	}

	// The list is a set: no duplicates.
	seen := map[TechnologyCategory]bool{}
	for _, c := range first {
		if seen[c] {
			t.Errorf("duplicate category %q in KnownCategories", c)
		}
		seen[c] = true
	}

	// Mutation of the returned slice must not affect the next call.
	mutated := KnownCategories()
	for i := range mutated {
		mutated[i] = "tampered"
	}
	again := KnownCategories()
	if reflect.DeepEqual(mutated, again) {
		t.Error("KnownCategories must return a fresh copy per call")
	}
	if again[0] != CategoryAnalytics || again[len(again)-1] != CategoryWAF {
		t.Errorf("KnownCategories order changed: %v", again)
	}
}

func TestTechnologyIdentity(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}

	// The identity is "category/name" with the name percent-encoded: a "/"
	// or ":" inside a name can never blur the category/name boundary.
	slash, err := NewTechnology("a/b:c", CategoryCDN, p)
	if err != nil {
		t.Fatal(err)
	}
	if slash.ID() != "technology:cdn/a%2Fb%3Ac" {
		t.Errorf("ID = %q, want technology:cdn/a%%2Fb%%3Ac", slash.ID())
	}

	// The same name in two categories is two distinct technologies.
	framework, _ := NewTechnology("express", CategoryFramework, p)
	other, _ := NewTechnology("express", CategoryServer, p)
	if framework.ID() == other.ID() {
		t.Error("same name in different categories must not share an identity")
	}

	// Determinism: identical inputs produce identical identities.
	dup, _ := NewTechnology("express", CategoryFramework, p)
	if dup.ID() != framework.ID() {
		t.Error("same inputs produced different identities")
	}

	// Version NEVER enters the identity.
	withVer, err := WithVersion(framework, "4.18.2")
	if err != nil {
		t.Fatal(err)
	}
	if withVer.ID() != framework.ID() {
		t.Error("version must not change the identity")
	}
}

func TestTechnologyWithVersion(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	base, err := NewTechnology("nginx", CategoryServer, p)
	if err != nil {
		t.Fatal(err)
	}

	// A valid version is carried; the identity is unaffected.
	got, err := WithVersion(base, "1.25.3")
	if err != nil {
		t.Fatalf("WithVersion: %v", err)
	}
	if got.Version != "1.25.3" {
		t.Errorf("Version = %q, want 1.25.3", got.Version)
	}
	if got.ID() != base.ID() {
		t.Error("version must not change the identity")
	}

	// Copy-not-mutate: the input is unchanged.
	if base.Version != "" {
		t.Error("WithVersion must not mutate its input")
	}

	// The exact byte bound is accepted.
	if _, err := WithVersion(base, strings.Repeat("v", 64)); err != nil {
		t.Errorf("64-byte version must construct: %v", err)
	}

	// The model documents opaque observed bytes such as
	// "nginx/1.25.3 (Ubuntu)" as valid versions: printable ASCII includes
	// the space, and no structure is imposed on the value.
	if _, err := WithVersion(base, "nginx/1.25.3 (Ubuntu)"); err != nil {
		t.Errorf("observed version with spaces must construct: %v", err)
	}

	cases := []struct {
		name    string
		version string
		wantSub string
	}{
		{"empty version", "", "must not be empty"},
		{"oversized version", strings.Repeat("v", 65), "longer than 64 bytes"},
		{"NUL in version", "1.0\x00", "non-printable character"},
		{"tab in version", "1.0\tbeta", "non-printable character"},
		{"DEL in version", "1.0\x7f", "non-printable character"},
		{"non-ASCII version", "1.0β", "non-printable character"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WithVersion(base, tt.version)
			if err == nil {
				t.Fatalf("expected error, got %#v", got)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestMergeTechnologies(t *testing.T) {
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	p1 := Provenance{Source: "s1", DiscoveredAt: t1}
	p2 := Provenance{Source: "s2", DiscoveredAt: t2}

	base, err := NewTechnology("nginx", CategoryServer, p1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewTechnology("apache", CategoryServer, p1)
	if err != nil {
		t.Fatal(err)
	}
	otherCat, err := NewTechnology("nginx", CategoryCDN, p1)
	if err != nil {
		t.Fatal(err)
	}

	// withVer builds a technology carrying the version and provenance. An
	// empty version means no WithVersion call: the technology is plain.
	withVer := func(tech Technology, version string, prov Provenance) Technology {
		t.Helper()
		out := tech
		if version != "" {
			var err error
			out, err = WithVersion(tech, version)
			if err != nil {
				t.Fatal(err)
			}
		}
		out.Prov = prov
		return out
	}

	cases := []struct {
		name     string
		a, b     Technology
		wantVer  string
		wantProv Provenance
	}{
		{"a empty, b set", withVer(base, "", p1), withVer(base, "1.25.3", p2), "1.25.3", p1},
		{"b empty, a set", withVer(base, "1.25.3", p1), withVer(base, "", p2), "1.25.3", p1},
		{"both empty", withVer(base, "", p1), withVer(base, "", p2), "", p1},
		{"equal versions", withVer(base, "1.25.3", p1), withVer(base, "1.25.3", p2), "1.25.3", p1},
		{"differ, b later", withVer(base, "1.0", p1), withVer(base, "2.0", p2), "2.0", p1},
		{"differ, a later", withVer(base, "2.0", p2), withVer(base, "1.0", p1), "2.0", p1},
		{"differ, tie", withVer(base, "2.0", p1), withVer(base, "1.0", p1), "2.0", p1},
		{"differ, zero timestamps", withVer(base, "2.0", Provenance{Source: "s9"}), withVer(base, "1.0", Provenance{Source: "s8"}), "2.0", Provenance{Source: "s8"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, err := MergeTechnologies(tt.a, tt.b)
			if err != nil {
				t.Fatalf("MergeTechnologies: %v", err)
			}
			if m.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", m.Version, tt.wantVer)
			}
			if m.Prov != tt.wantProv {
				t.Errorf("Prov = %v, want %v", m.Prov, tt.wantProv)
			}
			if m.ID() != base.ID() {
				t.Errorf("ID = %q, want %q", m.ID(), base.ID())
			}
		})
	}

	// Provenance is order-independent: merging later-first also yields the
	// earliest observation.
	m, err := MergeTechnologies(withVer(base, "1.0", p2), withVer(base, "2.0", p1))
	if err != nil {
		t.Fatal(err)
	}
	if m.Prov != p1 {
		t.Errorf("merge(b, a) must also yield earliest provenance, got %v", m.Prov)
	}
	if m.Version != "1.0" {
		t.Errorf("merge(b, a) version = %q, want a's 1.0 (tie resolves to first argument)", m.Version)
	}

	// Identity mismatches refuse to merge: different names, and the same
	// name in a different category.
	if _, err := MergeTechnologies(base, other); err == nil {
		t.Error("different names must refuse to merge")
	}
	if _, err := MergeTechnologies(base, otherCat); err == nil {
		t.Error("same name in different categories must refuse to merge")
	}
}

func TestTechnologySerializationRoundTrip(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "tech-detect", DiscoveredAt: at, Reference: "fp-7", Confidence: 0.9}
	tech, err := NewTechnology("cloudflare", CategoryCDN, p)
	if err != nil {
		t.Fatal(err)
	}
	tech, err = WithVersion(tech, "1.25.3")
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(tech)
	if err != nil {
		t.Fatal(err)
	}
	var back Technology
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, tech) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\njson: %s", back, tech, data)
	}
	if back.ID() != tech.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), tech.ID())
	}
}

func TestTechnologyRelationships(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	host, err := NewHost("www.example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := ParseURL("https://www.example.com/", p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEndpoint("GET", "https://www.example.com/", p)
	if err != nil {
		t.Fatal(err)
	}
	tech, err := NewTechnology("nginx", CategoryServer, p)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvidence(MethodHeader, "header:server", "nginx/1.25.3", host.Identity(), p)
	if err != nil {
		t.Fatal(err)
	}

	edges := []struct {
		name string
		from Identity
		kind RelationshipKind
		to   Identity
	}{
		{"host->technology", host.Identity(), RelationshipHostToTechnology, tech.Identity()},
		{"url->technology", u.Identity(), RelationshipURLToTechnology, tech.Identity()},
		{"endpoint->technology", e.Identity(), RelationshipEndpointToTechnology, tech.Identity()},
		{"technology->evidence", tech.Identity(), RelationshipTechnologyToEvidence, ev.Identity()},
	}
	ids := map[string]string{}
	for _, tt := range edges {
		r, err := NewRelationship(tt.from, tt.kind, tt.to)
		if err != nil {
			t.Fatalf("%s relationship: %v", tt.name, err)
		}
		ids[tt.name] = r.ID()

		// Identical edges deduplicate.
		again, err := NewRelationship(tt.from, tt.kind, tt.to)
		if err != nil {
			t.Fatal(err)
		}
		if again.ID() != r.ID() {
			t.Errorf("%s: identical edges must deduplicate", tt.name)
		}

		// The reverse edge is distinct.
		rev, err := NewRelationship(tt.to, tt.kind, tt.from)
		if err != nil {
			t.Fatal(err)
		}
		if rev.ID() == r.ID() {
			t.Errorf("%s: reversed edge must not share an identity", tt.name)
		}
	}

	// Each edge kind is distinct from every other.
	for a, idA := range ids {
		for b, idB := range ids {
			if a != b && idA == idB {
				t.Errorf("edges %q and %q share identity %q", a, b, idA)
			}
		}
	}
}
