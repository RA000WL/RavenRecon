package asset

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// testEvidenceSource returns a non-zero source identity built through the
// Phase 2 normalizer, as callers of NewEvidence would.
func testEvidenceSource(t *testing.T) Identity {
	t.Helper()
	h, err := NewHost("www.example.com", Provenance{Source: "manual", DiscoveredAt: fixedTime(1)})
	if err != nil {
		t.Fatal(err)
	}
	return h.Identity()
}

func TestNewEvidence(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "http-probe", DiscoveredAt: at, Reference: "ref-1", Confidence: 0.8}
	src := testEvidenceSource(t)

	e, err := NewEvidence(MethodHeader, "header:server", "cloudflare", src, p)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if e.Method != MethodHeader || e.Indicator != "header:server" || e.Value != "cloudflare" {
		t.Errorf("fields = %q/%q/%q", e.Method, e.Indicator, e.Value)
	}
	if e.Source != src {
		t.Errorf("Source = %v, want %v", e.Source, src)
	}
	if e.Prov != p {
		t.Errorf("Prov = %v, want %v", e.Prov, p)
	}
	if e.ID() != "evidence:header/header%3Aserver/cloudflare/host%3Awww%2Eexample%2Ecom" {
		t.Errorf("ID = %q", e.ID())
	}
	if e.String() != "header/header%3Aserver/cloudflare/host%3Awww%2Eexample%2Ecom" {
		t.Errorf("String = %q", e.String())
	}
	if e.Identity().Kind != KindEvidence {
		t.Errorf("kind = %q, want %q", e.Identity().Kind, KindEvidence)
	}
}

func TestNewEvidenceValidation(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	cases := []struct {
		name    string
		method  DetectionMethod
		ind     string
		value   string
		source  Identity
		wantSub string
	}{
		{"empty method", "", "header:server", "v", src, "invalid detection method"},
		{"unknown method", DetectionMethod("bogus"), "header:server", "v", src, "invalid detection method"},
		{"empty indicator", MethodHeader, "", "v", src, "must not be empty"},
		{"oversized indicator", MethodHeader, strings.Repeat("i", 129), "v", src, "longer than 128 bytes"},
		{"tab in indicator", MethodHeader, "header:\tserver", "v", src, "non-printable character"},
		{"NUL in indicator", MethodHeader, "header:\x00server", "v", src, "non-printable character"},
		{"DEL in indicator", MethodHeader, "header:\x7fserver", "v", src, "non-printable character"},
		{"non-ASCII indicator", MethodHeader, "header:servér", "v", src, "non-printable character"},
		{"zero source", MethodHeader, "header:server", "v", Identity{}, "must not be zero"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEvidence(tt.method, tt.ind, tt.value, tt.source, p)
			if err == nil {
				t.Fatalf("expected error, got %#v", e)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestEvidenceValueNeverRejected(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// A hostile 100 KiB observation is truncated, never rejected.
	e, err := NewEvidence(MethodHTML, "html:generator_meta", strings.Repeat("x", 100*1024), src, p)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if len(e.Value) != maxEvidenceValueBytes {
		t.Errorf("stored value = %d bytes, want %d", len(e.Value), maxEvidenceValueBytes)
	}
	if !strings.HasSuffix(e.Value, evidenceTruncationMarker) {
		t.Errorf("stored value %q does not end with the truncation marker", e.Value)
	}
	if !utf8.ValidString(e.Value) {
		t.Errorf("stored value is not valid UTF-8: %q", e.Value)
	}
}

func TestEvidenceValueTruncation(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Exactly at the bound: unchanged, no marker.
	exact := strings.Repeat("a", maxEvidenceValueBytes)
	e, err := NewEvidence(MethodHeader, "header:server", exact, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if e.Value != exact {
		t.Errorf("exact-bound value was changed: %d bytes", len(e.Value))
	}

	// One byte over: 253-byte prefix plus the 3-byte marker, total 256.
	e, err = NewEvidence(MethodHeader, "header:server", strings.Repeat("a", maxEvidenceValueBytes+1), src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 253) + evidenceTruncationMarker; e.Value != want {
		t.Errorf("truncated value = %q (%d bytes), want %q", e.Value, len(e.Value), want)
	}

	// Torn 2-byte rune at the cut: "é" (0xC3 0xA9) straddles byte 253.
	torn2 := strings.Repeat("a", 252) + "é" + strings.Repeat("x", 3) // len 257; cut lands after 0xC3
	e, err = NewEvidence(MethodHeader, "header:server", torn2, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 252) + evidenceTruncationMarker; e.Value != want {
		t.Errorf("torn 2-byte rune: got %q (%d bytes), want %q", e.Value, len(e.Value), want)
	}
	if !utf8.ValidString(e.Value) {
		t.Errorf("torn 2-byte rune: stored value is not valid UTF-8")
	}

	// Torn 3-byte rune at the cut: "€" (0xE2 0x82 0xAC) straddles byte 253.
	torn3 := strings.Repeat("a", 251) + "€" + strings.Repeat("x", 3) // len 257; cut lands after 0xE2 0x82
	e, err = NewEvidence(MethodHeader, "header:server", torn3, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 251) + evidenceTruncationMarker; e.Value != want {
		t.Errorf("torn 3-byte rune: got %q (%d bytes), want %q", e.Value, len(e.Value), want)
	}
	if !utf8.ValidString(e.Value) {
		t.Errorf("torn 3-byte rune: stored value is not valid UTF-8")
	}

	// A genuine U+FFFD rune immediately before the cut is a complete rune:
	// the marker follows it, never replaces it.
	genuine := strings.Repeat("a", 250) + "\uFFFD" + strings.Repeat("x", 4) // len 257; cut lands after the rune
	e, err = NewEvidence(MethodHeader, "header:server", genuine, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", 250) + "\uFFFD" + evidenceTruncationMarker; e.Value != want {
		t.Errorf("genuine U+FFFD at cut: got %q (%d bytes), want %q", e.Value, len(e.Value), want)
	}
	if !utf8.ValidString(e.Value) {
		t.Errorf("genuine U+FFFD at cut: stored value is not valid UTF-8")
	}
}

func TestEvidenceTruncationIdentityCoversStoredValue(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Raw observations that differ only beyond the 256-byte bound are the
	// SAME evidence asset, and re-ingesting the stored value reproduces the
	// exact same identity.
	rawA := strings.Repeat("x", 300)
	rawB := strings.Repeat("x", 299) + "y"

	a, err := NewEvidence(MethodHTML, "html:generator_meta", rawA, src, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewEvidence(MethodHTML, "html:generator_meta", rawB, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != b.ID() {
		t.Fatalf("identities differ for observations that differ only past the bound: %q != %q", a.ID(), b.ID())
	}

	re, err := NewEvidence(MethodHTML, "html:generator_meta", a.Value, src, p)
	if err != nil {
		t.Fatal(err)
	}
	if re.ID() != a.ID() || re.Value != a.Value {
		t.Errorf("re-ingesting the stored value must reproduce identity and value: %q/%q != %q/%q",
			re.ID(), re.Value, a.ID(), a.Value)
	}

	// The marker is part of the stored value and therefore of the identity:
	// an observation whose raw value is exactly the stored prefix (without
	// the marker) is a DIFFERENT evidence asset.
	noMarker, err := NewEvidence(MethodHTML, "html:generator_meta", strings.Repeat("x", 253), src, p)
	if err != nil {
		t.Fatal(err)
	}
	if noMarker.ID() == a.ID() {
		t.Errorf("stored prefix without marker must not collide with the truncated identity")
	}

	// The canonical identity value for the truncated observation.
	wantID := "evidence:html/html%3Agenerator%5Fmeta/" + strings.Repeat("x", 253) + "%E2%80%A6/host%3Awww%2Eexample%2Ecom"
	if a.ID() != wantID {
		t.Errorf("ID = %q, want %q", a.ID(), wantID)
	}
}

func TestEvidenceIdentityEncoding(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	// Percent-encoding applies to every component: method is unencoded by
	// construction (canonical lowercase), indicator and value are encoded,
	// and the source identity string is encoded as its own component.
	e, err := NewEvidence(MethodHeader, "header:server", "nginx/1.25.3 (Ubuntu)", src, p)
	if err != nil {
		t.Fatal(err)
	}
	want := "evidence:header/header%3Aserver/nginx%2F1%2E25%2E3%20%28Ubuntu%29/host%3Awww%2Eexample%2Ecom"
	if e.ID() != want {
		t.Errorf("ID = %q, want %q", e.ID(), want)
	}

	// Boundary blur: naive "a/b/c" concatenation could collide, encoding
	// cannot. (indicator "x", value "y/z") vs (indicator "x/y", value "z").
	one, err := NewEvidence(MethodHeader, "x", "y/z", src, p)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewEvidence(MethodHeader, "x/y", "z", src, p)
	if err != nil {
		t.Fatal(err)
	}
	if one.ID() == two.ID() {
		t.Errorf("component boundaries must never blur: %q == %q", one.ID(), two.ID())
	}
	if want := "evidence:header/x/y%2Fz/host%3Awww%2Eexample%2Ecom"; one.ID() != want {
		t.Errorf("ID = %q, want %q", one.ID(), want)
	}

	// Every component participates in the identity: changing the method,
	// indicator, value, or source changes the identity.
	base, err := NewEvidence(MethodHeader, "header:server", "cloudflare", src, p)
	if err != nil {
		t.Fatal(err)
	}
	variants := []func() (Evidence, error){
		func() (Evidence, error) { return NewEvidence(MethodTLS, "header:server", "cloudflare", src, p) },
		func() (Evidence, error) {
			return NewEvidence(MethodHeader, "header:x-powered-by", "cloudflare", src, p)
		},
		func() (Evidence, error) { return NewEvidence(MethodHeader, "header:server", "nginx", src, p) },
		func() (Evidence, error) {
			other, err := NewHost("api.example.com", Provenance{Source: "manual", DiscoveredAt: fixedTime(1)})
			if err != nil {
				t.Fatal(err)
			}
			return NewEvidence(MethodHeader, "header:server", "cloudflare", other.Identity(), p)
		},
	}
	for i, mk := range variants {
		v, err := mk()
		if err != nil {
			t.Fatal(err)
		}
		if v.ID() == base.ID() {
			t.Errorf("variant %d collides with base identity", i)
		}
	}

	// Determinism: identical inputs produce identical identities.
	dup, err := NewEvidence(MethodHeader, "header:server", "cloudflare", src, p)
	if err != nil {
		t.Fatal(err)
	}
	if dup.ID() != base.ID() {
		t.Errorf("same inputs produced different identities: %q != %q", dup.ID(), base.ID())
	}
}

func TestDetectionMethodParse(t *testing.T) {
	// Every known method round-trips through ParseDetectionMethod.
	for _, m := range KnownMethods() {
		got, err := ParseDetectionMethod(m.String())
		if err != nil {
			t.Errorf("ParseDetectionMethod(%q): %v", m, err)
			continue
		}
		if got != m {
			t.Errorf("ParseDetectionMethod(%q) = %q", m, got)
		}
		if !m.Valid() {
			t.Errorf("%q must be Valid", m)
		}
	}

	for _, bad := range []string{"", "bogus", "Header", "HEADER", " html", "source-map"} {
		if _, err := ParseDetectionMethod(bad); err == nil {
			t.Errorf("ParseDetectionMethod(%q) must fail", bad)
		}
		if DetectionMethod(bad).Valid() {
			t.Errorf("%q must not be Valid", bad)
		}
	}
}

func TestKnownMethodsSortedAndFresh(t *testing.T) {
	first := KnownMethods()
	if len(first) != 13 {
		t.Fatalf("KnownMethods has %d entries, want 13", len(first))
	}
	strs := make([]string, len(first))
	for i, m := range first {
		strs[i] = m.String()
	}
	if !sort.StringsAreSorted(strs) {
		t.Errorf("KnownMethods must be sorted, got %v", strs)
	}

	// Duplicate methods are impossible: the list is a set.
	seen := map[DetectionMethod]bool{}
	for _, m := range first {
		if seen[m] {
			t.Errorf("duplicate method %q in KnownMethods", m)
		}
		seen[m] = true
	}

	// Mutation of the returned slice must not affect the next call.
	mutated := KnownMethods()
	for i := range mutated {
		mutated[i] = "tampered"
	}
	again := KnownMethods()
	if reflect.DeepEqual(mutated, again) {
		t.Error("KnownMethods must return a fresh copy per call")
	}
	if again[0] != MethodAttribute || again[len(again)-1] != MethodTLS {
		t.Errorf("KnownMethods order changed: %v", again)
	}
}

func TestMergeEvidence(t *testing.T) {
	src := testEvidenceSource(t)
	p1 := Provenance{Source: "http-probe", DiscoveredAt: fixedTime(10)}
	p2 := Provenance{Source: "tech-detect", DiscoveredAt: fixedTime(12)}

	a, err := NewEvidence(MethodHeader, "header:server", "cloudflare", src, p1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewEvidence(MethodHeader, "header:server", "cloudflare", src, p2)
	if err != nil {
		t.Fatal(err)
	}

	m, err := MergeEvidence(a, b)
	if err != nil {
		t.Fatalf("MergeEvidence: %v", err)
	}
	if m.ID() != a.ID() {
		t.Fatalf("merged ID = %q, want %q", m.ID(), a.ID())
	}
	if m.Prov != p1 {
		t.Errorf("expected earliest provenance, got %v", m.Prov)
	}
	if m.Value != "cloudflare" || m.Indicator != "header:server" || m.Source != src {
		t.Errorf("merged fields changed: %#v", m)
	}

	// Order independence: merging later-first also yields the earliest.
	m2, err := MergeEvidence(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Prov != p1 {
		t.Errorf("merge(b, a) must also yield earliest provenance, got %v", m2.Prov)
	}

	// Zero-time provenance on one side falls back to the other side.
	zero := Provenance{Source: "manual"}
	z, err := MergeEvidence(a, Evidence{Method: a.Method, Indicator: a.Indicator, Value: a.Value, Source: a.Source, Prov: zero})
	if err != nil {
		t.Fatal(err)
	}
	if z.Prov != p1 {
		t.Errorf("zero-time side must not clobber provenance, got %v", z.Prov)
	}

	// Distinct identities refuse to merge.
	c, err := NewEvidence(MethodHeader, "header:server", "nginx", src, p2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MergeEvidence(a, c)
	if err == nil {
		t.Fatal("expected error for distinct identities")
	}
	if !strings.Contains(err.Error(), "identities differ") {
		t.Errorf("error %q does not mention differing identities", err)
	}

	// A truncated observation and its stored form are the same evidence and
	// merge cleanly (identity covers the stored value).
	raw, err := NewEvidence(MethodHeader, "header:server", strings.Repeat("x", 300), src, p2)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := NewEvidence(MethodHeader, "header:server", raw.Value, src, p1)
	if err != nil {
		t.Fatal(err)
	}
	mm, err := MergeEvidence(raw, stored)
	if err != nil {
		t.Fatalf("truncated and stored forms must merge: %v", err)
	}
	if mm.Prov != p1 {
		t.Errorf("merged provenance = %v, want earliest %v", mm.Prov, p1)
	}
}

func TestEvidenceSerializationRoundTrip(t *testing.T) {
	src := testEvidenceSource(t)
	p := Provenance{Source: "http-probe", DiscoveredAt: fixedTime(10), Reference: "ref-9", Confidence: 0.9}
	e, err := NewEvidence(MethodCookie, "cookie:PHPSESSID", "ab12cd", src, p)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Evidence
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v (data: %s)", err, data)
	}
	if !reflect.DeepEqual(back, e) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\njson: %s", back, e, data)
	}
	if back.ID() != e.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), e.ID())
	}

	// Truncated values serialize and reproduce the same identity.
	big, err := NewEvidence(MethodHTML, "html:generator_meta", strings.Repeat("y", 500), src, p)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	var bigBack Evidence
	if err := json.Unmarshal(data, &bigBack); err != nil {
		t.Fatal(err)
	}
	if bigBack.Value != big.Value || bigBack.ID() != big.ID() {
		t.Errorf("truncated round trip mismatch: %q/%q != %q/%q", bigBack.Value, bigBack.ID(), big.Value, big.ID())
	}
}
