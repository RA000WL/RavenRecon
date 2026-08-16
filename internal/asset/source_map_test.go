package asset

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewSourceMap(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "jsintel", DiscoveredAt: at, Reference: "ref-1", Confidence: 0.8}

	m, err := NewSourceMap("https://example.com/app.js.map?v=1", p)
	if err != nil {
		t.Fatalf("NewSourceMap: %v", err)
	}
	if m.URL.Scheme != "https" || m.URL.HostPort != "example.com" || m.URL.Path != "/app.js.map" {
		t.Errorf("URL = %v, want the canonical form", m.URL)
	}
	if m.URL.Original != "https://example.com/app.js.map?v=1" {
		t.Errorf("Original = %q, want the raw form preserved", m.URL.Original)
	}
	if m.Hash != "" || m.Size != 0 {
		t.Errorf("observations must start unset: %q/%d", m.Hash, m.Size)
	}
	if m.Prov != p {
		t.Errorf("Prov = %v, want %v", m.Prov, p)
	}
	if m.Identity().Kind != KindSourceMap {
		t.Errorf("kind = %q, want %q", m.Identity().Kind, KindSourceMap)
	}
	if want := "source_map:https://example.com/app.js.map?v=1"; m.ID() != want {
		t.Errorf("ID = %q, want %q", m.ID(), want)
	}

	// Observations never enter the identity.
	observed, err := WithHash(m, testJSContentHash(0x30))
	if err != nil {
		t.Fatal(err)
	}
	observed, err = WithSourceMapSize(observed, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ID() != m.ID() {
		t.Errorf("observations changed the identity: %q != %q", observed.ID(), m.ID())
	}
}

func TestNewSourceMapValidation(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	for _, raw := range []string{"", "not-a-url", "https://"} {
		m, err := NewSourceMap(raw, p)
		if err == nil {
			t.Errorf("NewSourceMap(%q) must fail, got %#v", raw, m)
		}
		if !strings.Contains(err.Error(), "invalid source map URL") {
			t.Errorf("error %q does not mention the invalid source map URL", err)
		}
	}
}

func TestSourceMapSetters(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base, err := NewSourceMap("https://example.com/app.js.map", p)
	if err != nil {
		t.Fatal(err)
	}

	// Acceptance: canonical hash, empty hash, and boundary sizes.
	cases := []struct {
		name string
		set  func() (SourceMap, error)
	}{
		{"hash at 64 hex", func() (SourceMap, error) { return WithHash(base, testJSContentHash(0x40)) }},
		{"hash empty", func() (SourceMap, error) { return WithHash(base, "") }},
		{"size 0", func() (SourceMap, error) { return WithSourceMapSize(base, 0) }},
		{"size 1", func() (SourceMap, error) { return WithSourceMapSize(base, 1) }},
		{"size large", func() (SourceMap, error) { return WithSourceMapSize(base, 1<<40) }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.set(); err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
		})
	}

	// Rejection: non-canonical hashes and negative sizes.
	rejects := []struct {
		name    string
		set     func() (SourceMap, error)
		wantSub string
	}{
		{"hash 63 chars", func() (SourceMap, error) { return WithHash(base, strings.Repeat("a", 63)) }, "exactly 64 lowercase hex"},
		{"hash 65 chars", func() (SourceMap, error) { return WithHash(base, strings.Repeat("a", 65)) }, "exactly 64 lowercase hex"},
		{"hash uppercase", func() (SourceMap, error) { return WithHash(base, strings.ToUpper(testJSContentHash(0x41))) }, "lowercase hex"},
		{"hash non-hex", func() (SourceMap, error) { return WithHash(base, "z"+strings.Repeat("a", 63)) }, "lowercase hex"},
		{"size negative", func() (SourceMap, error) { return WithSourceMapSize(base, -1) }, "must not be negative"},
	}
	for _, tt := range rejects {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.set()
			if err == nil {
				t.Fatalf("expected error, got %#v", got)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// Purity: setters never mutate their input.
	baseCopy := base
	if _, err := WithHash(base, testJSContentHash(0x42)); err != nil {
		t.Fatal(err)
	}
	if _, err := WithSourceMapSize(base, 10); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, baseCopy) {
		t.Errorf("setters must not mutate their input: %#v", base)
	}

	// Values are stored as normalized.
	got, err := WithHash(base, testJSContentHash(0x42))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != testJSContentHash(0x42) {
		t.Errorf("Hash = %q, want the canonical hash", got.Hash)
	}
}

func TestMergeSourceMaps(t *testing.T) {
	url := "https://example.com/app.js.map"
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	p1 := Provenance{Source: "s1", DiscoveredAt: t1}
	p2 := Provenance{Source: "s2", DiscoveredAt: t2}
	h1 := testJSContentHash(0x50)
	h2 := testJSContentHash(0x60)

	build := func(prov Provenance, hash string, size int64) SourceMap {
		t.Helper()
		m, err := NewSourceMap(url, prov)
		if err != nil {
			t.Fatal(err)
		}
		if m, err = WithHash(m, hash); err != nil {
			t.Fatal(err)
		}
		if m, err = WithSourceMapSize(m, size); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// Hash conflict: earlier observation wins, in both orders.
	m, err := MergeSourceMaps(build(p1, h1, 100), build(p2, h2, 200))
	if err != nil {
		t.Fatal(err)
	}
	if m.Hash != h1 || m.Size != 100 {
		t.Errorf("earlier observation must win: %q/%d", m.Hash, m.Size)
	}
	if m.Prov != p1 {
		t.Errorf("Prov = %v, want earliest", m.Prov)
	}
	if m.ID() != "source_map:"+url {
		t.Errorf("ID = %q, want source_map:%s", m.ID(), url)
	}

	mBA, err := MergeSourceMaps(build(p2, h2, 200), build(p1, h1, 100))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, mBA) {
		t.Errorf("merge must be order-independent:\n a,b: %#v\n b,a: %#v", m, mBA)
	}

	// Unset on a fills from b.
	m2, err := MergeSourceMaps(build(p1, "", 0), build(p2, h1, 100))
	if err != nil {
		t.Fatal(err)
	}
	if m2.Hash != h1 || m2.Size != 100 {
		t.Errorf("unset on a must fill from b: %q/%d", m2.Hash, m2.Size)
	}
	if m2.Prov != p1 {
		t.Errorf("Prov = %v, want earliest", m2.Prov)
	}

	// Zero-time conflict resolves to a.
	z, err := MergeSourceMaps(build(Provenance{Source: "s9"}, h1, 0), build(Provenance{Source: "s8"}, h2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if z.Hash != h1 {
		t.Errorf("zero-timestamp conflict must resolve to a: %q", z.Hash)
	}

	// Distinct identities refuse to merge.
	other, err := NewSourceMap("https://example.com/other.js.map", p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeSourceMaps(m, other); err == nil {
		t.Fatal("expected error for distinct identities")
	} else if !strings.Contains(err.Error(), "identities differ") {
		t.Errorf("error %q does not mention differing identities", err)
	}

	// Determinism: the same pair merges to the same result every time.
	mAgain, err := MergeSourceMaps(build(p1, h1, 100), build(p2, h2, 200))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, mAgain) {
		t.Errorf("merge must be deterministic:\n first: %#v\n again: %#v", m, mAgain)
	}
}
