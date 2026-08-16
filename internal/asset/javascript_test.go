package asset

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// testJSContentHash returns a deterministic 64-character lowercase hex string
// (the canonical content-hash form). Different seeds produce different
// hashes.
func testJSContentHash(seed byte) string {
	const hexDigit = "0123456789abcdef"
	h := make([]byte, 64)
	for i := range h {
		h[i] = hexDigit[(seed+byte(i))%16]
	}
	return string(h)
}

// testJavaScript builds a JavaScript asset through the public constructor,
// failing the test on any validation error.
func testJavaScript(t *testing.T, rawURL string, p Provenance) JavaScript {
	t.Helper()
	j, err := NewJavaScript(rawURL, p)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// fullJS builds a fully-observed JavaScript asset through the public
// constructor and setters, failing the test on any validation error. Empty
// strings, zero sizes, zero times, and the zero status code mean "not
// observed" and are set through the setters like any other value.
func fullJS(t *testing.T, rawURL string, p Provenance, host, contentHash, contentType, etag, discSource string, size int64, lastModified time.Time, status int, finalURL string) JavaScript {
	t.Helper()
	var err error
	j, err := NewJavaScript(rawURL, p)
	if err != nil {
		t.Fatal(err)
	}
	if j, err = WithHost(j, host); err != nil {
		t.Fatal(err)
	}
	if j, err = WithContentHash(j, contentHash); err != nil {
		t.Fatal(err)
	}
	if j, err = WithSize(j, size); err != nil {
		t.Fatal(err)
	}
	if j, err = WithContentType(j, contentType); err != nil {
		t.Fatal(err)
	}
	if j, err = WithETag(j, etag); err != nil {
		t.Fatal(err)
	}
	if j, err = WithLastModified(j, lastModified); err != nil {
		t.Fatal(err)
	}
	if j, err = WithDiscoverySource(j, discSource); err != nil {
		t.Fatal(err)
	}
	if j, err = WithStatusCode(j, status); err != nil {
		t.Fatal(err)
	}
	if j, err = WithFinalURL(j, finalURL); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestNewJavaScriptIdentity(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "html-scan", DiscoveredAt: at, Reference: "ref-1", Confidence: 0.9}

	j, err := NewJavaScript("https://example.com/app.js?v=1#main", p)
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	if j.URL.Scheme != "https" || j.URL.HostPort != "example.com" || j.URL.Path != "/app.js" {
		t.Errorf("URL = %v, want the canonical form", j.URL)
	}
	if j.URL.Original != "https://example.com/app.js?v=1#main" {
		t.Errorf("Original = %q, want the raw form preserved", j.URL.Original)
	}
	if j.Prov != p {
		t.Errorf("Prov = %v, want %v", j.Prov, p)
	}
	if j.Identity().Kind != KindJavaScript {
		t.Errorf("kind = %q, want %q", j.Identity().Kind, KindJavaScript)
	}
	if want := "javascript:https://example.com/app.js?v=1"; j.ID() != want {
		t.Errorf("ID = %q, want %q", j.ID(), want)
	}

	// Observations never enter the identity.
	observed := fullJS(t, "https://example.com/app.js?v=1#main", p,
		"cdn.example.com", testJSContentHash(0x10), "application/javascript",
		`W/"abc123"`, "html-scan", 4096, fixedTime(9), 200,
		"https://cdn.example.com/app.js?v=1")
	if observed.ID() != j.ID() {
		t.Errorf("observations changed the identity: %q != %q", observed.ID(), j.ID())
	}
}

func TestNewJavaScriptValidation(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	for _, raw := range []string{"", "not-a-url", "//example.com/app.js", "https://"} {
		j, err := NewJavaScript(raw, p)
		if err == nil {
			t.Errorf("NewJavaScript(%q) must fail, got %#v", raw, j)
		}
		if !strings.Contains(err.Error(), "invalid javascript URL") {
			t.Errorf("error %q does not mention the invalid javascript URL", err)
		}
	}
}

func TestJavaScriptSetterAcceptance(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base := testJavaScript(t, "https://example.com/app.js", p)

	cases := []struct {
		name string
		set  func() (JavaScript, error)
	}{
		{"host canonicalized", func() (JavaScript, error) { return WithHost(base, "CDN.Example.COM") }},
		{"host empty clears", func() (JavaScript, error) { return WithHost(base, "") }},
		{"content hash at 64 hex", func() (JavaScript, error) { return WithContentHash(base, testJSContentHash(0x01)) }},
		{"content hash empty", func() (JavaScript, error) { return WithContentHash(base, "") }},
		{"size 0", func() (JavaScript, error) { return WithSize(base, 0) }},
		{"size 1", func() (JavaScript, error) { return WithSize(base, 1) }},
		{"size large", func() (JavaScript, error) { return WithSize(base, 1<<40) }},
		{"content type at 128 bytes", func() (JavaScript, error) { return WithContentType(base, strings.Repeat("c", 128)) }},
		{"content type empty", func() (JavaScript, error) { return WithContentType(base, "") }},
		{"etag at 256 bytes", func() (JavaScript, error) { return WithETag(base, strings.Repeat("e", 256)) }},
		{"etag empty", func() (JavaScript, error) { return WithETag(base, "") }},
		{"last modified set", func() (JavaScript, error) { return WithLastModified(base, fixedTime(9)) }},
		{"last modified zero", func() (JavaScript, error) { return WithLastModified(base, time.Time{}) }},
		{"discovery source at 128 bytes", func() (JavaScript, error) { return WithDiscoverySource(base, strings.Repeat("d", 128)) }},
		{"discovery source empty", func() (JavaScript, error) { return WithDiscoverySource(base, "") }},
		{"status 0 unobserved", func() (JavaScript, error) { return WithStatusCode(base, 0) }},
		{"status 100 accepted", func() (JavaScript, error) { return WithStatusCode(base, 100) }},
		{"status 200 accepted", func() (JavaScript, error) { return WithStatusCode(base, 200) }},
		{"status 599 accepted", func() (JavaScript, error) { return WithStatusCode(base, 599) }},
		{"final url canonicalized", func() (JavaScript, error) { return WithFinalURL(base, "https://CDN.Example.COM:443/app.js?v=2#x") }},
		{"final url empty clears", func() (JavaScript, error) { return WithFinalURL(base, "  ") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.set(); err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
		})
	}

	// Purity: setters never mutate their input.
	baseCopy := base
	if _, err := WithHost(base, "cdn.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := WithFinalURL(base, "https://cdn.example.com/app.js"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, baseCopy) {
		t.Errorf("setters must not mutate their input: %#v", base)
	}

	// Empty-value semantics: empty input clears to the unobserved zero.
	cleared, err := WithHost(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if !cleared.Host.Identity().IsZero() {
		t.Errorf("empty host must clear to the zero Host, got %v", cleared.Host)
	}
	cleared, err = WithFinalURL(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if cleared.FinalURL != (URL{}) {
		t.Errorf("empty final url must clear to the zero URL, got %v", cleared.FinalURL)
	}
	cleared, err = WithContentHash(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if cleared.ContentHash != "" || cleared.Hash != "" {
		t.Errorf("empty content hash must store empty, got %q", cleared.ContentHash)
	}
	cleared, err = WithStatusCode(base, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.StatusCode != 0 {
		t.Errorf("zero status code must store 0, got %d", cleared.StatusCode)
	}

	// Values are stored through the setters exactly as normalized.
	got, err := WithHost(base, "CDN.Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host.Name != "cdn.example.com" {
		t.Errorf("Host = %q, want the canonical form", got.Host.Name)
	}
	got, err = WithFinalURL(base, "https://cdn.example.com/app.js?v=2")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://cdn.example.com/app.js?v=2"; got.FinalURL.String() != want {
		t.Errorf("FinalURL = %q, want %q", got.FinalURL.String(), want)
	}
}

func TestJavaScriptSetterRejection(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base := testJavaScript(t, "https://example.com/app.js", p)

	cases := []struct {
		name    string
		set     func() (JavaScript, error)
		wantSub string
	}{
		{"host with space", func() (JavaScript, error) { return WithHost(base, "bad host") }, "set javascript host"},
		{"host is an IP literal", func() (JavaScript, error) { return WithHost(base, "1.2.3.4") }, "set javascript host"},
		{"content hash 63 chars", func() (JavaScript, error) { return WithContentHash(base, strings.Repeat("a", 63)) }, "exactly 64 lowercase hex"},
		{"content hash 65 chars", func() (JavaScript, error) { return WithContentHash(base, strings.Repeat("a", 65)) }, "exactly 64 lowercase hex"},
		{"content hash uppercase", func() (JavaScript, error) { return WithContentHash(base, strings.ToUpper(testJSContentHash(0x02))) }, "lowercase hex"},
		{"content hash non-hex", func() (JavaScript, error) { return WithContentHash(base, "g"+strings.Repeat("a", 63)) }, "lowercase hex"},
		{"content hash non-ASCII", func() (JavaScript, error) { return WithContentHash(base, "é"+strings.Repeat("a", 63)) }, "lowercase hex"},
		{"size negative", func() (JavaScript, error) { return WithSize(base, -1) }, "must not be negative"},
		{"content type over 128", func() (JavaScript, error) { return WithContentType(base, strings.Repeat("c", 129)) }, "longer than the 128 maximum"},
		{"content type NUL", func() (JavaScript, error) { return WithContentType(base, "a\x00b") }, "non-printable character"},
		{"content type non-ASCII", func() (JavaScript, error) { return WithContentType(base, "application/é") }, "non-printable character"},
		{"etag over 256", func() (JavaScript, error) { return WithETag(base, strings.Repeat("e", 257)) }, "longer than the 256 maximum"},
		{"etag NUL", func() (JavaScript, error) { return WithETag(base, "a\x00b") }, "non-printable character"},
		{"etag DEL", func() (JavaScript, error) { return WithETag(base, "a\x7fb") }, "non-printable character"},
		{"discovery source over 128", func() (JavaScript, error) { return WithDiscoverySource(base, strings.Repeat("d", 129)) }, "longer than the 128 maximum"},
		{"discovery source tab", func() (JavaScript, error) { return WithDiscoverySource(base, "a\tb") }, "non-printable character"},
		{"status 99", func() (JavaScript, error) { return WithStatusCode(base, 99) }, "outside 100..599"},
		{"status 600", func() (JavaScript, error) { return WithStatusCode(base, 600) }, "outside 100..599"},
		{"status negative", func() (JavaScript, error) { return WithStatusCode(base, -200) }, "outside 100..599"},
		{"final url no scheme", func() (JavaScript, error) { return WithFinalURL(base, "cdn.example.com/app.js") }, "set javascript final url"},
		{"final url missing host", func() (JavaScript, error) { return WithFinalURL(base, "https://") }, "set javascript final url"},
	}
	for _, tt := range cases {
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

	// The final URL is stored canonically and re-parses to its own identity.
	got, err := WithFinalURL(base, "https://cdn.example.com/app.js?v=2")
	if err != nil {
		t.Fatal(err)
	}
	re, err := ParseURL(got.FinalURL.String(), Provenance{})
	if err != nil {
		t.Fatalf("stored final url must re-parse: %v", err)
	}
	if !re.Identity().Equal(got.FinalURL.Identity()) {
		t.Errorf("final url %q must re-parse canonically to its own identity", got.FinalURL.String())
	}
}

func TestMergeJavaScriptsObservations(t *testing.T) {
	url := "https://example.com/app.js"
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	p1 := Provenance{Source: "s1", DiscoveredAt: t1}
	p2 := Provenance{Source: "s2", DiscoveredAt: t2}
	h1 := testJSContentHash(0x10)
	h2 := testJSContentHash(0x20)
	zero := time.Time{}

	// build is a compact partial-observation constructor for the table:
	// only the listed fields are set, everything else stays unobserved.
	build := func(prov Provenance, host, hash, contentType, etag, disc string, size int64, mod time.Time, status int, finalURL string) JavaScript {
		t.Helper()
		return fullJS(t, url, prov, host, hash, contentType, etag, disc, size, mod, status, finalURL)
	}

	cases := []struct {
		name string
		a, b JavaScript
		want JavaScript
	}{
		{
			name: "identical observations merge to earliest provenance",
			a:    build(p1, "cdn.example.com", h1, "application/javascript", `W/"1"`, "html-scan", 4096, t1, 200, "https://cdn.example.com/app.js?v=1"),
			b:    build(p2, "cdn.example.com", h1, "application/javascript", `W/"1"`, "html-scan", 4096, t1, 200, "https://cdn.example.com/app.js?v=1"),
			want: build(p1, "cdn.example.com", h1, "application/javascript", `W/"1"`, "html-scan", 4096, t1, 200, "https://cdn.example.com/app.js?v=1"),
		},
		{
			name: "conflict: earlier observation wins",
			a:    build(p1, "host-early", "", "", "", "", 0, zero, 0, ""),
			b:    build(p2, "host-late", "", "", "", "", 0, zero, 0, ""),
			want: build(p1, "host-early", "", "", "", "", 0, zero, 0, ""),
		},
		{
			name: "conflict: earlier wins in both orders",
			a:    build(p2, "host-early", "", "", "", "", 0, zero, 0, ""),
			b:    build(p1, "host-late", "", "", "", "", 0, zero, 0, ""),
			want: build(p1, "host-late", "", "", "", "", 0, zero, 0, ""),
		},
		{
			name: "content hash conflict: earlier observation wins",
			a:    build(p1, "", h1, "", "", "", 0, zero, 0, ""),
			b:    build(p2, "", h2, "", "", "", 0, zero, 0, ""),
			want: build(p1, "", h1, "", "", "", 0, zero, 0, ""),
		},
		{
			name: "content hash unset on a: b's value wins",
			a:    build(p1, "", "", "", "", "", 0, zero, 0, ""),
			b:    build(p2, "", h1, "", "", "", 0, zero, 0, ""),
			want: build(p1, "", h1, "", "", "", 0, zero, 0, ""),
		},
		{
			name: "content hash unset on b: a's value wins",
			a:    build(p1, "", h1, "", "", "", 0, zero, 0, ""),
			b:    build(p2, "", "", "", "", "", 0, zero, 0, ""),
			want: build(p1, "", h1, "", "", "", 0, zero, 0, ""),
		},
		{
			name: "content type conflict: earlier observation wins",
			a:    build(p1, "", "", "application/javascript", "", "", 0, zero, 0, ""),
			b:    build(p2, "", "", "text/javascript", "", "", 0, zero, 0, ""),
			want: build(p1, "", "", "application/javascript", "", "", 0, zero, 0, ""),
		},
		{
			name: "etag conflict: earlier observation wins",
			a:    build(p1, "", "", "", `W/"1"`, "", 0, zero, 0, ""),
			b:    build(p2, "", "", "", `W/"2"`, "", 0, zero, 0, ""),
			want: build(p1, "", "", "", `W/"1"`, "", 0, zero, 0, ""),
		},
		{
			name: "discovery source conflict: earlier observation wins",
			a:    build(p1, "", "", "", "", "html-scan", 0, zero, 0, ""),
			b:    build(p2, "", "", "", "", "js-scan", 0, zero, 0, ""),
			want: build(p1, "", "", "", "", "html-scan", 0, zero, 0, ""),
		},
		{
			name: "size conflict: earlier observation wins",
			a:    build(p1, "", "", "", "", "", 100, zero, 0, ""),
			b:    build(p2, "", "", "", "", "", 200, zero, 0, ""),
			want: build(p1, "", "", "", "", "", 100, zero, 0, ""),
		},
		{
			name: "size unset on b: a's value wins",
			a:    build(p1, "", "", "", "", "", 100, zero, 0, ""),
			b:    build(p2, "", "", "", "", "", 0, zero, 0, ""),
			want: build(p1, "", "", "", "", "", 100, zero, 0, ""),
		},
		{
			name: "last modified conflict: earlier observation wins",
			a:    build(p1, "", "", "", "", "", 0, fixedTime(8), 0, ""),
			b:    build(p2, "", "", "", "", "", 0, fixedTime(9), 0, ""),
			want: build(p1, "", "", "", "", "", 0, fixedTime(8), 0, ""),
		},
		{
			name: "status code conflict: earlier observation wins",
			a:    build(p1, "", "", "", "", "", 0, zero, 200, ""),
			b:    build(p2, "", "", "", "", "", 0, zero, 304, ""),
			want: build(p1, "", "", "", "", "", 0, zero, 200, ""),
		},
		{
			name: "final url conflict: earlier observation wins",
			a:    build(p1, "", "", "", "", "", 0, zero, 0, "https://cdn.example.com/app.js?v=1"),
			b:    build(p2, "", "", "", "", "", 0, zero, 0, "https://cdn.example.com/app.js?v=2"),
			want: build(p1, "", "", "", "", "", 0, zero, 0, "https://cdn.example.com/app.js?v=1"),
		},
		{
			name: "final url unset on a: b's value wins",
			a:    build(p1, "", "", "", "", "", 0, zero, 0, ""),
			b:    build(p2, "", "", "", "", "", 0, zero, 0, "https://cdn.example.com/app.js?v=2"),
			want: build(p1, "", "", "", "", "", 0, zero, 0, "https://cdn.example.com/app.js?v=2"),
		},
		{
			name: "legacy hash follows the same first-wins rule",
			a:    build(p1, "", "", "", "", "", 0, zero, 0, ""),
			b:    build(p2, "", "", "", "", "", 0, zero, 0, ""),
			want: build(p1, "", "", "", "", "", 0, zero, 0, ""),
		},
		{
			name: "conflict with zero timestamps: unresolvable resolves to a",
			a:    build(Provenance{Source: "s9"}, "host-a", "", "", "", "", 0, zero, 0, ""),
			b:    build(Provenance{Source: "s8"}, "host-b", "", "", "", "", 0, zero, 0, ""),
			want: build(Provenance{Source: "s8"}, "host-a", "", "", "", "", 0, zero, 0, ""),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// The legacy Hash field has no setter; inject it directly like
			// the pre-Phase-7 tests do.
			if tt.name == "legacy hash follows the same first-wins rule" {
				tt.a.Hash = "hash-a"
				tt.b.Hash = "hash-b"
				tt.want.Hash = "hash-a" // a is the earlier observation (t1 < t2)
			}
			m, err := MergeJavaScripts(tt.a, tt.b)
			if err != nil {
				t.Fatalf("MergeJavaScripts: %v", err)
			}
			if !reflect.DeepEqual(m, tt.want) {
				t.Errorf("merged = %#v\nwant   = %#v", m, tt.want)
			}
			if m.ID() != "javascript:"+url {
				t.Errorf("ID = %q, want javascript:%s", m.ID(), url)
			}
		})
	}
}

func TestMergeJavaScriptsIdentityMismatch(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	a := testJavaScript(t, "https://example.com/app.js", p)
	b := testJavaScript(t, "https://example.com/other.js", p)

	if _, err := MergeJavaScripts(a, b); err == nil {
		t.Fatal("different URLs must refuse to merge")
	} else if !strings.Contains(err.Error(), "identities differ") {
		t.Errorf("error %q does not mention differing identities", err)
	}
}

// TestMergeJavaScriptsOrderIndependence pins the contract that
// merge(a, b) == merge(b, a) field-for-field whenever the observations'
// DiscoveredAt times differ.
func TestMergeJavaScriptsOrderIndependence(t *testing.T) {
	url := "https://example.com/app.js"
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	a := fullJS(t, url, Provenance{Source: "s1", DiscoveredAt: t1},
		"host-a", testJSContentHash(0x11), "application/javascript", `W/"a"`, "html-scan",
		100, fixedTime(8), 200, "https://cdn.example.com/app.js?v=1")
	a.Hash = "legacy-a"
	b := fullJS(t, url, Provenance{Source: "s2", DiscoveredAt: t2},
		"host-b", testJSContentHash(0x22), "text/javascript", `W/"b"`, "js-scan",
		200, fixedTime(9), 304, "https://cdn.example.com/app.js?v=2")
	b.Hash = "legacy-b"

	mAB, err := MergeJavaScripts(a, b)
	if err != nil {
		t.Fatal(err)
	}
	mBA, err := MergeJavaScripts(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mAB, mBA) {
		t.Errorf("merge(a, b) != merge(b, a):\n a,b: %#v\n b,a: %#v", mAB, mBA)
	}

	// a is the earlier observation, so every conflicting observation field
	// takes a's value.
	if mAB.Host.Name != "host-a" || mAB.ContentHash != testJSContentHash(0x11) ||
		mAB.ContentType != "application/javascript" || mAB.ETag != `W/"a"` ||
		mAB.DiscoverySource != "html-scan" || mAB.Size != 100 ||
		mAB.StatusCode != 200 || mAB.Hash != "legacy-a" {
		t.Errorf("earlier observation's fields must win: %#v", mAB)
	}
	if !mAB.LastModified.Equal(fixedTime(8)) {
		t.Errorf("LastModified = %v, want the earlier observation's", mAB.LastModified)
	}
	if mAB.FinalURL.String() != "https://cdn.example.com/app.js?v=1" {
		t.Errorf("FinalURL = %q, want the earlier observation's", mAB.FinalURL.String())
	}
	if mAB.Prov != (Provenance{Source: "s1", DiscoveredAt: t1}) {
		t.Errorf("Prov = %v, want earliest", mAB.Prov)
	}

	// Determinism: the same pair merges to the same result every time.
	mAgain, err := MergeJavaScripts(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mAB, mAgain) {
		t.Errorf("merge must be deterministic:\n first: %#v\n again: %#v", mAB, mAgain)
	}
}
