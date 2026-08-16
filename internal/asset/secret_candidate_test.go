package asset

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// testSecretCandidateSource returns a non-zero source identity built through
// a Phase 2 normalizer, as callers of NewSecretCandidate would.
func testSecretCandidateSource(t *testing.T) Identity {
	t.Helper()
	h, err := NewHost("www.example.com", Provenance{Source: "manual", DiscoveredAt: fixedTime(1)})
	if err != nil {
		t.Fatal(err)
	}
	return h.Identity()
}

func TestNewSecretCandidate(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "jsintel", DiscoveredAt: at, Reference: "scan-1", Confidence: 0.7}
	src := testSecretCandidateSource(t)

	s, err := NewSecretCandidate(SecretTypeJWT, "eyJhbGciOiJIUzI1NiJ9", src, p)
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	if s.Type != SecretTypeJWT || s.Value != "eyJhbGciOiJIUzI1NiJ9" {
		t.Errorf("fields = %q/%q", s.Type, s.Value)
	}
	if s.Source != src {
		t.Errorf("Source = %v, want %v", s.Source, src)
	}
	if s.Prov != p {
		t.Errorf("Prov = %v, want %v", s.Prov, p)
	}
	if s.Identity().Kind != KindSecretCandidate {
		t.Errorf("kind = %q, want %q", s.Identity().Kind, KindSecretCandidate)
	}
	wantID := "secret_candidate:jwt/eyJhbGciOiJIUzI1NiJ9/host%3Awww%2Eexample%2Ecom"
	if s.ID() != wantID {
		t.Errorf("ID = %q, want %q", s.ID(), wantID)
	}
	if s.String() != "jwt/eyJhbGciOiJIUzI1NiJ9/host%3Awww%2Eexample%2Ecom" {
		t.Errorf("String = %q", s.String())
	}
}

func TestNewSecretCandidateValidation(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	cases := []struct {
		name    string
		typ     SecretType
		value   string
		source  Identity
		wantSub string
	}{
		{"empty type", "", "v", src, "invalid secret type"},
		{"unknown type", SecretType("bogus"), "v", src, "invalid secret type"},
		{"uppercase type", SecretType("JWT"), "v", src, "invalid secret type"},
		{"empty value", SecretTypeJWT, "", src, "must not be empty"},
		{"zero source", SecretTypeJWT, "v", Identity{}, "must not be zero"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSecretCandidate(tt.typ, tt.value, tt.source, p)
			if err == nil {
				t.Fatalf("expected error, got %#v", s)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// A whitespace-only value is non-empty and never truncates to nothing:
	// it is stored verbatim, mirroring evidence's never-reject semantics.
	blank, err := NewSecretCandidate(SecretTypeJWT, "   ", src, p)
	if err != nil {
		t.Fatalf("whitespace-only value must construct: %v", err)
	}
	if blank.Value != "   " {
		t.Errorf("Value = %q, want stored verbatim", blank.Value)
	}

	// Values with identity-hostile characters are accepted (the identity
	// percent-encodes them); only emptiness is rejected.
	hostile, err := NewSecretCandidate(SecretTypeAWS, "AKIA/example:with/slashes\n", src, p)
	if err != nil {
		t.Fatalf("hostile value must construct: %v", err)
	}
	if hostile.Value != "AKIA/example:with/slashes\n" {
		t.Errorf("Value = %q, want stored as observed", hostile.Value)
	}
}

func TestSecretCandidateValueNeverRejectedForLength(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// A hostile 100 KiB observation is truncated, never rejected.
	s, err := NewSecretCandidate(SecretTypeBearer, strings.Repeat("x", 100*1024), src, p)
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	if len(s.Value) != maxSecretCandidateValueBytes {
		t.Errorf("stored value = %d bytes, want %d", len(s.Value), maxSecretCandidateValueBytes)
	}
	if !strings.HasSuffix(s.Value, secretCandidateTruncationMarker) {
		t.Errorf("stored value %q does not end with the truncation marker", s.Value)
	}
	if !utf8.ValidString(s.Value) {
		t.Errorf("stored value is not valid UTF-8: %q", s.Value)
	}
}

func TestSecretCandidateValueTruncation(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Exactly at the bound: unchanged, no marker.
	exact := strings.Repeat("a", maxSecretCandidateValueBytes)
	s, err := NewSecretCandidate(SecretTypeGeneric, exact, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Value != exact {
		t.Errorf("exact-bound value was changed: %d bytes", len(s.Value))
	}

	// One byte over: 509-byte prefix plus the 3-byte marker, total 512.
	s, err = NewSecretCandidate(SecretTypeGeneric, strings.Repeat("a", maxSecretCandidateValueBytes+1), src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 509) + secretCandidateTruncationMarker; s.Value != want {
		t.Errorf("truncated value = %q (%d bytes), want %q", s.Value, len(s.Value), want)
	}

	// Torn 2-byte rune at the cut: "é" (0xC3 0xA9) straddles byte 509.
	torn2 := strings.Repeat("a", 508) + "é" + strings.Repeat("x", 3) // len 514; cut lands after 0xC3
	s, err = NewSecretCandidate(SecretTypeGeneric, torn2, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 508) + secretCandidateTruncationMarker; s.Value != want {
		t.Errorf("torn 2-byte rune: got %q (%d bytes), want %q", s.Value, len(s.Value), want)
	}
	if !utf8.ValidString(s.Value) {
		t.Errorf("torn 2-byte rune: stored value is not valid UTF-8")
	}

	// Torn 3-byte rune at the cut: "€" (0xE2 0x82 0xAC) straddles byte 509.
	torn3 := strings.Repeat("a", 507) + "€" + strings.Repeat("x", 3) // len 514; cut lands after 0xE2 0x82
	s, err = NewSecretCandidate(SecretTypeGeneric, torn3, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 507) + secretCandidateTruncationMarker; s.Value != want {
		t.Errorf("torn 3-byte rune: got %q (%d bytes), want %q", s.Value, len(s.Value), want)
	}
	if !utf8.ValidString(s.Value) {
		t.Errorf("torn 3-byte rune: stored value is not valid UTF-8")
	}

	// A genuine U+FFFD rune immediately before the cut is a complete rune:
	// the marker follows it, never replaces it.
	genuine := strings.Repeat("a", 506) + "\uFFFD" + strings.Repeat("x", 4) // len 514; cut lands after the rune
	s, err = NewSecretCandidate(SecretTypeGeneric, genuine, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 506) + "\uFFFD" + secretCandidateTruncationMarker; s.Value != want {
		t.Errorf("genuine U+FFFD at cut: got %q (%d bytes), want %q", s.Value, len(s.Value), want)
	}
	if !utf8.ValidString(s.Value) {
		t.Errorf("genuine U+FFFD at cut: stored value is not valid UTF-8")
	}
}

func TestSecretCandidateTruncationIdentityCoversStoredValue(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Raw observations that differ only beyond the 512-byte bound are the
	// SAME secret candidate asset, and re-ingesting the stored value
	// reproduces the exact same identity.
	rawA := strings.Repeat("x", 600)
	rawB := strings.Repeat("x", 599) + "y"

	a, err := NewSecretCandidate(SecretTypeGeneric, rawA, src, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSecretCandidate(SecretTypeGeneric, rawB, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != b.ID() {
		t.Fatalf("identities differ for observations that differ only past the bound: %q != %q", a.ID(), b.ID())
	}

	re, err := NewSecretCandidate(SecretTypeGeneric, a.Value, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if re.ID() != a.ID() || re.Value != a.Value {
		t.Errorf("re-ingesting the stored value must reproduce identity and value: %q/%q != %q/%q",
			re.ID(), re.Value, a.ID(), a.Value)
	}

	// The marker is part of the stored value and therefore of the identity:
	// an observation whose raw value is exactly the stored prefix (without
	// the marker) is a DIFFERENT secret candidate asset.
	noMarker, err := NewSecretCandidate(SecretTypeGeneric, strings.Repeat("x", 509), src, p)
	if err != nil {
		t.Fatal(err)
	}
	if noMarker.ID() == a.ID() {
		t.Errorf("stored prefix without marker must not collide with the truncated identity")
	}

	// The canonical identity value for the truncated observation.
	wantID := "secret_candidate:generic/" + strings.Repeat("x", 509) + "%E2%80%A6/host%3Awww%2Eexample%2Ecom"
	if a.ID() != wantID {
		t.Errorf("ID = %q, want %q", a.ID(), wantID)
	}
}

func TestSecretCandidateIdentityEncoding(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Percent-encoding applies to every component: type is unencoded by
	// construction (canonical lowercase), value and the source identity
	// string are encoded.
	s, err := NewSecretCandidate(SecretTypeGitHub, "ghp_abc/def", src, p)
	if err != nil {
		t.Fatal(err)
	}
	want := "secret_candidate:github/ghp%5Fabc%2Fdef/host%3Awww%2Eexample%2Ecom"
	if s.ID() != want {
		t.Errorf("ID = %q, want %q", s.ID(), want)
	}

	// Boundary blur: naive "a/b/c" concatenation could collide, encoding
	// cannot. (type jwt, value "x/y", source S) vs (type jwt, value "x",
	// source S) are distinct; and the same value in two sources is two
	// distinct candidates.
	one, err := NewSecretCandidate(SecretTypeJWT, "x/y", src, p)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewSecretCandidate(SecretTypeJWT, "x", src, p)
	if err != nil {
		t.Fatal(err)
	}
	if one.ID() == two.ID() {
		t.Errorf("values must never blur: %q == %q", one.ID(), two.ID())
	}
	other, err := NewHost("api.example.com", Provenance{Source: "manual", DiscoveredAt: fixedTime(1)})
	if err != nil {
		t.Fatal(err)
	}
	three, err := NewSecretCandidate(SecretTypeJWT, "x/y", other.Identity(), p)
	if err != nil {
		t.Fatal(err)
	}
	if three.ID() == one.ID() {
		t.Errorf("different sources must never blur: %q == %q", three.ID(), one.ID())
	}

	// Determinism: identical inputs produce identical identities.
	dup, err := NewSecretCandidate(SecretTypeJWT, "x/y", src, p)
	if err != nil {
		t.Fatal(err)
	}
	if dup.ID() != one.ID() {
		t.Errorf("same inputs produced different identities: %q != %q", dup.ID(), one.ID())
	}
}

func TestSecretTypeEnum(t *testing.T) {
	// All 35 known values are valid and canonical lowercase, and
	// ParseSecretType round-trips each one.
	if n := len(KnownSecretTypes()); n != 35 {
		t.Fatalf("KnownSecretTypes has %d entries, want 35", n)
	}
	for _, typ := range KnownSecretTypes() {
		if !typ.Valid() {
			t.Errorf("%q must be Valid", typ)
		}
		got, err := ParseSecretType(typ.String())
		if err != nil {
			t.Errorf("ParseSecretType(%q): %v", typ, err)
			continue
		}
		if got != typ {
			t.Errorf("ParseSecretType(%q) = %q", typ, got)
		}
	}

	for _, bad := range []string{"", "bogus", "JWT", "jwt2", "privatekey", " generic"} {
		if _, err := ParseSecretType(bad); err == nil {
			t.Errorf("ParseSecretType(%q) must fail", bad)
		}
		if SecretType(bad).Valid() {
			t.Errorf("%q must not be Valid", bad)
		}
	}
}

func TestKnownSecretTypesSortedAndFresh(t *testing.T) {
	first := KnownSecretTypes()
	strs := make([]string, len(first))
	for i, typ := range first {
		strs[i] = typ.String()
	}
	if !sort.StringsAreSorted(strs) {
		t.Errorf("KnownSecretTypes must be sorted, got %v", strs)
	}

	// The list is a set.
	seen := map[SecretType]bool{}
	for _, typ := range first {
		if seen[typ] {
			t.Errorf("duplicate type %q in KnownSecretTypes", typ)
		}
		seen[typ] = true
	}

	// Mutation of the returned slice must not affect the next call.
	mutated := KnownSecretTypes()
	for i := range mutated {
		mutated[i] = "tampered"
	}
	again := KnownSecretTypes()
	if reflect.DeepEqual(mutated, again) {
		t.Error("KnownSecretTypes must return a fresh copy per call")
	}
	if again[0] != SecretTypeAnthropic || again[len(again)-1] != SecretTypeWebhookURL {
		t.Errorf("KnownSecretTypes order changed: %v", again)
	}
}

func TestMergeSecretCandidates(t *testing.T) {
	src := testSecretCandidateSource(t)
	p1 := Provenance{Source: "jsintel", DiscoveredAt: fixedTime(10)}
	p2 := Provenance{Source: "re-scan", DiscoveredAt: fixedTime(12)}

	a, err := NewSecretCandidate(SecretTypeJWT, "eyJhbGciOiJIUzI1NiJ9", src, p1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSecretCandidate(SecretTypeJWT, "eyJhbGciOiJIUzI1NiJ9", src, p2)
	if err != nil {
		t.Fatal(err)
	}

	m, err := MergeSecretCandidates(a, b)
	if err != nil {
		t.Fatalf("MergeSecretCandidates: %v", err)
	}
	if m.ID() != a.ID() {
		t.Fatalf("merged ID = %q, want %q", m.ID(), a.ID())
	}
	if m.Prov != p1 {
		t.Errorf("expected earliest provenance, got %v", m.Prov)
	}
	if m.Value != a.Value || m.Type != SecretTypeJWT || m.Source != src {
		t.Errorf("identifying fields changed: %#v", m)
	}

	// Order independence: merging later-first also yields the earliest.
	m2, err := MergeSecretCandidates(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Prov != p1 {
		t.Errorf("merge(b, a) must also yield earliest provenance, got %v", m2.Prov)
	}

	// Zero-time provenance on one side falls back to the other side.
	zero := Provenance{Source: "manual"}
	z, err := MergeSecretCandidates(a, SecretCandidate{Type: a.Type, Value: a.Value, Source: a.Source, Prov: zero})
	if err != nil {
		t.Fatal(err)
	}
	if z.Prov != p1 {
		t.Errorf("zero-time side must not clobber provenance, got %v", z.Prov)
	}

	// Distinct identities refuse to merge: different value.
	c, err := NewSecretCandidate(SecretTypeJWT, "eyJother", src, p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeSecretCandidates(a, c); err == nil {
		t.Fatal("expected error for distinct values")
	} else if !strings.Contains(err.Error(), "identities differ") {
		t.Errorf("error %q does not mention differing identities", err)
	}

	// Distinct identities refuse to merge: different source asset.
	d, err := NewSecretCandidate(SecretTypeJWT, a.Value, Identity{Kind: KindHost, Value: "other.example.com"}, p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeSecretCandidates(a, d); err == nil {
		t.Fatal("expected error for distinct sources")
	}

	// A truncated observation and its stored form are the same candidate and
	// merge cleanly (identity covers the stored value).
	raw, err := NewSecretCandidate(SecretTypeBearer, strings.Repeat("x", 600), src, p2)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := NewSecretCandidate(SecretTypeBearer, raw.Value, src, p1)
	if err != nil {
		t.Fatal(err)
	}
	mm, err := MergeSecretCandidates(raw, stored)
	if err != nil {
		t.Fatalf("truncated and stored forms must merge: %v", err)
	}
	if mm.Prov != p1 {
		t.Errorf("merged provenance = %v, want earliest %v", mm.Prov, p1)
	}
}

func TestSecretCandidateSerializationRoundTrip(t *testing.T) {
	src := testSecretCandidateSource(t)
	p := Provenance{Source: "jsintel", DiscoveredAt: fixedTime(10), Reference: "scan-9", Confidence: 0.6}
	s, err := NewSecretCandidate(SecretTypeAWS, "AKIAIOSFODNN7EXAMPLE", src, p)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back SecretCandidate
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v (data: %s)", err, data)
	}
	if !reflect.DeepEqual(back, s) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\njson: %s", back, s, data)
	}
	if back.ID() != s.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), s.ID())
	}
}
