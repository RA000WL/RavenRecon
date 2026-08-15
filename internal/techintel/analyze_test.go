package techintel

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

func TestMethodFor(t *testing.T) {
	cases := []struct {
		kind fingerprints.IndicatorKind
		want asset.DetectionMethod
	}{
		{fingerprints.IndicatorHeader, asset.MethodHeader},
		{fingerprints.IndicatorCookie, asset.MethodCookie},
		{fingerprints.IndicatorHTMLRegex, asset.MethodHTML},
		{fingerprints.IndicatorHTMLSubstring, asset.MethodHTML},
		{fingerprints.IndicatorGenerator, asset.MethodGenerator},
		{fingerprints.IndicatorMetaName, asset.MethodMeta},
		{fingerprints.IndicatorScriptName, asset.MethodScript},
		{fingerprints.IndicatorScriptPath, asset.MethodScript},
		{fingerprints.IndicatorCSSPath, asset.MethodCSS},
		{fingerprints.IndicatorAttribute, asset.MethodAttribute},
		{fingerprints.IndicatorEndpointPath, asset.MethodEndpoint},
		{fingerprints.IndicatorTLSIssuer, asset.MethodTLS},
		{fingerprints.IndicatorTLSCN, asset.MethodTLS},
		{fingerprints.IndicatorTLSALPN, asset.MethodTLS},
		{fingerprints.IndicatorDNSCNAME, asset.MethodDNS},
		{fingerprints.IndicatorSourceMapPath, asset.MethodSourceMap},
	}
	for _, tt := range cases {
		if got := methodFor(tt.kind); got != tt.want {
			t.Errorf("methodFor(%q) = %q, want %q", tt.kind, got, tt.want)
		}
	}
	if got := methodFor(fingerprints.IndicatorKind("bogus")); got != "" {
		t.Errorf("methodFor(bogus) = %q, want empty", got)
	}
}

func TestIndicatorKey(t *testing.T) {
	if got := indicatorKey(fingerprints.IndicatorHeader, "server: nginx"); got != "header:server: nginx" {
		t.Errorf("indicatorKey = %q", got)
	}
	if got := indicatorKey(fingerprints.IndicatorHTMLSubstring, "cf-error-details"); got != "html_substring:cf-error-details" {
		t.Errorf("indicatorKey = %q", got)
	}
}

func TestSplitCookiePair(t *testing.T) {
	cases := []struct {
		in     string
		name   string
		value  string
		wantOK bool
	}{
		{"a=b", "a", "b", true},
		{"sid = abc", "sid ", " abc", true},
		{"a=b=c", "a", "b=c", true},
		{"=b", "", "", false},
		{"a", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range cases {
		name, value, ok := splitCookiePair(tt.in)
		if ok != tt.wantOK || name != tt.name || value != tt.value {
			t.Errorf("splitCookiePair(%q) = %q/%q/%v, want %q/%q/%v", tt.in, name, value, ok, tt.name, tt.value, tt.wantOK)
		}
	}
}

func TestFirstCookieName(t *testing.T) {
	if got := firstCookieName("sid=abc; Path=/; HttpOnly"); got != "sid" {
		t.Errorf("firstCookieName = %q, want sid", got)
	}
	if got := firstCookieName("; HttpOnly"); got != "" {
		t.Errorf("firstCookieName = %q, want empty", got)
	}
	if got := firstCookieName(""); got != "" {
		t.Errorf("firstCookieName = %q, want empty", got)
	}
}

func TestScriptBase(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://cdn.example.com/static/js/react.js", "react.js"},
		{"/_next/static/chunks/main.js?ts=1", "main.js"},
		{"main.js#top", "main.js"},
		{"app.min.js", "app.min.js"},
		{"https://example.com/", ""},
	}
	for _, tt := range cases {
		if got := scriptBase(tt.in); got != tt.want {
			t.Errorf("scriptBase(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseTag(t *testing.T) {
	cases := []struct {
		in        string
		wantName  string
		wantAttrs []tagAttr
	}{
		{`img src="a.png" alt='b' width=100 /`, "img", []tagAttr{{"src", "a.png"}, {"alt", "b"}, {"width", "100"}}},
		{`DIV data-root="x"`, "div", []tagAttr{{"data-root", "x"}}},
		{`link rel=stylesheet href="/s.css"`, "link", []tagAttr{{"rel", "stylesheet"}, {"href", "/s.css"}}},
		{`/div`, "div", nil},
		{`!-- comment`, "-- comment", nil},
		{`script src="/js/main.js"`, "script", []tagAttr{{"src", "/js/main.js"}}},
		{`meta content="x"`, "meta", []tagAttr{{"content", "x"}}},
	}
	for _, tt := range cases {
		name, attrs := parseTag(tt.in)
		if name != tt.wantName {
			t.Errorf("parseTag(%q) name = %q, want %q", tt.in, name, tt.wantName)
		}
		if len(attrs) != len(tt.wantAttrs) {
			t.Errorf("parseTag(%q) attrs = %v, want %v", tt.in, attrs, tt.wantAttrs)
			continue
		}
		for i, a := range attrs {
			if a != tt.wantAttrs[i] {
				t.Errorf("parseTag(%q) attr[%d] = %v, want %v", tt.in, i, a, tt.wantAttrs[i])
			}
		}
	}

	// attrValue resolves case-insensitively.
	name, attrs := parseTag(`div NG-VERSION="17.2.0"`)
	if name != "div" {
		t.Errorf("tag name = %q, want div", name)
	}
	if got := attrValue(attrs, "ng-version"); got != "17.2.0" {
		t.Errorf("attrValue = %q, want 17.2.0", got)
	}
	if got := attrValue(attrs, "missing"); got != "" {
		t.Errorf("attrValue(missing) = %q, want empty", got)
	}
}

func TestScanHTML(t *testing.T) {
	body := `<html><head>` +
		`<meta name="generator" content="WordPress 6.4.2">` +
		`<link rel="stylesheet" href="/css/site.css">` +
		`<link rel="alternate" href="/feed.xml">` +
		`</head><body>` +
		`<div data-v-7ba5bd90="" ng-app class="app">` +
		`<script src="https://cdn.example.com/react.js"></script>` +
		`<script src="/_next/static/main.js"></script>` +
		`</body></html>` +
		`//# sourceMappingURL=/static/js/main.js.map`

	out := scanHTML(body)
	if len(out.scripts) != 2 || out.scripts[0] != "https://cdn.example.com/react.js" || out.scripts[1] != "/_next/static/main.js" {
		t.Errorf("scripts = %v", out.scripts)
	}
	if len(out.css) != 1 || out.css[0] != "/css/site.css" {
		t.Errorf("css = %v", out.css)
	}
	if len(out.metas) != 1 || out.metas[0].name != "generator" || out.metas[0].content != "WordPress 6.4.2" {
		t.Errorf("metas = %v", out.metas)
	}
	if len(out.generators) != 1 || out.generators[0] != "WordPress 6.4.2" {
		t.Errorf("generators = %v", out.generators)
	}
	if len(out.sourcemaps) != 1 || out.sourcemaps[0] != "/static/js/main.js.map" {
		t.Errorf("sourcemaps = %v", out.sourcemaps)
	}
	// Every tag's attributes feed the attribute analyzer in document order:
	// meta (2), link (2 + 2), div (3), scripts (1 + 1).
	wantAttrs := []attrEntry{
		{"name", "generator"}, {"content", "WordPress 6.4.2"},
		{"rel", "stylesheet"}, {"href", "/css/site.css"},
		{"rel", "alternate"}, {"href", "/feed.xml"},
		{"data-v-7ba5bd90", ""}, {"ng-app", ""}, {"class", "app"},
		{"src", "https://cdn.example.com/react.js"}, {"src", "/_next/static/main.js"},
	}
	if len(out.attrs) != len(wantAttrs) {
		t.Fatalf("attrs = %v, want %v", out.attrs, wantAttrs)
	}
	for i, a := range out.attrs {
		if a != wantAttrs[i] {
			t.Errorf("attr[%d] = %v, want %v", i, a, wantAttrs[i])
		}
	}
	if out.truncated {
		t.Error("small page must not be flagged truncated")
	}
}

func TestScanHTMLCaps(t *testing.T) {
	// More scripts than the cap: retained set is capped in document order
	// and truncated is set.
	var b strings.Builder
	for i := 0; i < maxHTMLScripts+3; i++ {
		b.WriteString(`<script src="/s/` + strings.Repeat("x", i) + `.js"></script>`)
	}
	out := scanHTML(b.String())
	if len(out.scripts) != maxHTMLScripts {
		t.Errorf("scripts = %d, want cap %d", len(out.scripts), maxHTMLScripts)
	}
	if !out.truncated {
		t.Error("cap exceeded must set truncated")
	}

	// Attribute cap.
	b.Reset()
	for i := 0; i < maxHTMLAttributes+2; i++ {
		b.WriteString(`<div a` + strings.Repeat("b", i) + `="1"></div>`)
	}
	out = scanHTML(b.String())
	if len(out.attrs) != maxHTMLAttributes {
		t.Errorf("attrs = %d, want cap %d", len(out.attrs), maxHTMLAttributes)
	}
	if !out.truncated {
		t.Error("attribute cap exceeded must set truncated")
	}
}

// TestBuildCorpusCookies pins the Set-Cookie attribute policy (the L1
// review contract): only the FIRST pair of a Set-Cookie header is a real
// cookie; later pairs are ingested ONLY when their name is a real RFC 6265
// attribute on the allow-list (Path, Domain, Expires, Max-Age, SameSite,
// Secure, HttpOnly, Partitioned — case-insensitive), and everything else is
// dropped at ingest. Bare flag directives (HttpOnly, Secure) carry no '=',
// so they are never cookie entries at all — they are evidence-only session
// flags (see TestAnalyzeCookieFlagEvidence). The flag scanner reads the
// real attribute segments (both ";secure" and "; Secure" fire; a flag
// inside a QUOTED value is data, never a directive).
func TestBuildCorpusCookies(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Cookies = []CookieEntry{{Name: "caller1", Value: "v"}}
	o.Headers = []HeaderEntry{
		{Name: "Cookie", Value: "hdr1=a; hdr2=b; notacookie"},
		{Name: "Set-Cookie", Value: "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"},
	}
	c := buildCorpus(o)
	want := []cookieEntry{
		{"caller1", "v"},
		{"hdr1", "a"},
		{"hdr2", "b"},
		{"sid", "abc"},
		// Set-Cookie pairs beyond the first are ingested only when their
		// name is an allow-listed attribute (Path and SameSite here); the
		// flag analyzer reads the directives separately.
		{"Path", "/"},
		{"SameSite", "Lax"},
	}
	if len(c.cookies) != len(want) {
		t.Fatalf("cookies = %v, want %v", c.cookies, want)
	}
	for i, ck := range c.cookies {
		if ck != want[i] {
			t.Errorf("cookie[%d] = %v, want %v", i, ck, want[i])
		}
	}
	if len(c.cookieFlags) != 3 {
		t.Fatalf("cookieFlags = %v, want 3", c.cookieFlags)
	}
	if c.cookieFlags[0].cookieName != "sid" || c.cookieFlags[0].indicator != cookieFlagIndicatorHTTPOnly {
		t.Errorf("cookieFlag[0] = %v", c.cookieFlags[0])
	}
	if c.cookieFlags[1].indicator != cookieFlagIndicatorSecure || c.cookieFlags[2].indicator != cookieFlagIndicatorSameSite {
		t.Errorf("cookieFlag indicators = %v", c.cookieFlags)
	}
	if c.truncated || c.overflow.Cookies {
		t.Error("small cookie set must not overflow")
	}
}

// TestBuildCorpusSetCookieAttributePolicy exercises the allow-list policy
// beyond the pinned happy path: non-attribute directives are DROPPED (the
// old deliberate attribute-ingestion ingested every "name=value" pair), the
// allow-list itself is case-insensitive, the no-space ";secure" form fires
// the flag, and a flag-looking token inside a QUOTED attribute value is
// data, never a directive.
func TestBuildCorpusSetCookieAttributePolicy(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Set-Cookie", Value: `sid=abc; path=/app; Bogus=junk; Foo=bar; Max-Age=3600; HttpOnly;secure; Expires="Thu, 01 Jan 1970 00:00:00 GMT; Secure"; Custom=kept?no`}}
	c := buildCorpus(o)

	// Cookie entries: the first pair plus exactly the allow-listed
	// attribute pairs (case-insensitive). Bogus/Foo/Custom are not cookie
	// attributes and must never be ingested; the quoted "; Secure" inside
	// the Expires value is part of that value, not a segment of its own.
	want := []cookieEntry{
		{"sid", "abc"},
		{"path", "/app"},
		{"Max-Age", "3600"},
		{"Expires", `"Thu, 01 Jan 1970 00:00:00 GMT; Secure"`},
	}
	if len(c.cookies) != len(want) {
		t.Fatalf("cookies = %v, want %v (unknown directives must be dropped)", c.cookies, want)
	}
	for i, ck := range c.cookies {
		if ck != want[i] {
			t.Errorf("cookie[%d] = %v, want %v", i, ck, want[i])
		}
	}

	// Session flags: HttpOnly (with space), Secure (no space after ';'),
	// and SameSite none here — the quoted "; Secure" inside the Expires
	// value must NOT fire, and neither may any dropped directive.
	wantFlags := []string{cookieFlagIndicatorHTTPOnly, cookieFlagIndicatorSecure}
	if len(c.cookieFlags) != len(wantFlags) {
		t.Fatalf("cookieFlags = %v, want %v", c.cookieFlags, wantFlags)
	}
	for i, f := range wantFlags {
		if c.cookieFlags[i].cookieName != "sid" || c.cookieFlags[i].indicator != f {
			t.Errorf("cookieFlag[%d] = %v, want %s", i, c.cookieFlags[i], f)
		}
	}
}

func TestBuildCorpusCookieCap(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	for i := 0; i < maxObservationCookies+10; i++ {
		o.Cookies = append(o.Cookies, CookieEntry{Name: "c", Value: "v"})
	}
	c := buildCorpus(o)
	if len(c.cookies) != maxObservationCookies {
		t.Errorf("cookies = %d, want cap %d", len(c.cookies), maxObservationCookies)
	}
	if !c.overflow.Cookies || !c.truncated {
		t.Error("cookie overflow must be flagged")
	}
}

// testCorpus builds a fresh corpus for one-off match testing; the caller
// mutates the channel it cares about.
func testCorpus(o Observation) *obsCorpus {
	c := buildCorpus(o)
	return &c
}

func TestMatchIndicator(t *testing.T) {
	ind := func(kind fingerprints.IndicatorKind, match string) fingerprints.Indicator {
		return fingerprints.Indicator{Kind: kind, Match: match, Weight: 0.5}
	}

	t.Run("header slots and case folding", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Headers = []HeaderEntry{
			{Name: "Server", Value: "nginx/1.25.3"},
			{Name: "X-Powered-By", Value: "PHP/8.2"},
		}
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorHeader, "SERVER: nginx"), c)
		if len(ms) != 1 || ms[0].slot != 0 || ms[0].value != "Server: nginx/1.25.3" {
			t.Errorf("header match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorHeader, "x-powered-by: php"), c)
		if len(ms) != 1 || ms[0].slot != 1 || ms[0].value != "X-Powered-By: PHP/8.2" {
			t.Errorf("header match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorHeader, "server: apache"), c)
		if len(ms) != 0 {
			t.Errorf("no-match header must produce no slots: %v", ms)
		}
	})

	t.Run("cookie name and value", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Cookies = []CookieEntry{{Name: "phx_session", Value: "abc"}, {Name: "grafana", Value: "grafana_session=1"}}
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorCookie, "PHX_SESSION"), c)
		if len(ms) != 1 || ms[0].slot != 0 || ms[0].value != "phx_session" {
			t.Errorf("cookie name match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorCookie, "grafana_session"), c)
		if len(ms) != 1 || ms[0].slot != 1 || ms[0].value != "grafana_session=1" {
			t.Errorf("cookie value match = %v", ms)
		}
	})

	t.Run("html substring preserves observed case", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = "Hello WORLD"
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorHTMLSubstring, "world"), c)
		if len(ms) != 1 || ms[0].value != "WORLD" {
			t.Errorf("html substring match = %v", ms)
		}
	})

	t.Run("html regex without compiled regex never matches", func(t *testing.T) {
		// Hand-built fixtures have no compiled MatchRe; the analyzer must
		// treat that as "never matches" (compile-once contract), not panic.
		o := newObs(t, "https://ok.example/")
		o.Body = "anything"
		c := testCorpus(o)
		if ms := matchIndicator(ind(fingerprints.IndicatorHTMLRegex, "any.*"), c); len(ms) != 0 {
			t.Errorf("uncompiled regex must never match: %v", ms)
		}
		if ms := matchIndicator(ind(fingerprints.IndicatorGenerator, ".*"), c); len(ms) != 0 {
			t.Errorf("uncompiled generator must never match: %v", ms)
		}
	})

	t.Run("meta name", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<meta name="generator" content="WordPress">`
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorMetaName, "GENERATOR"), c)
		if len(ms) != 1 || ms[0].slot != 0 || ms[0].value != "generator" {
			t.Errorf("meta match = %v", ms)
		}
	})

	t.Run("script name and path", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<script src="https://cdn.example.com/static/js/react.js"></script>` +
			`<script src="/_next/static/chunks/main.js"></script>`
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorScriptName, "react.JS"), c)
		if len(ms) != 1 || ms[0].value != "react.js" {
			t.Errorf("script name match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorScriptPath, "/_next/"), c)
		if len(ms) != 1 || ms[0].value != "/_next/static/chunks/main.js" {
			t.Errorf("script path match = %v", ms)
		}
	})

	t.Run("css path", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<link rel="stylesheet" href="/assets/site.css">`
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorCSSPath, "site.css"), c)
		if len(ms) != 1 || ms[0].value != "/assets/site.css" {
			t.Errorf("css match = %v", ms)
		}
	})

	t.Run("attribute carries version target", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<div ng-app ng-version="17.2.0">`
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorAttribute, "NG-VERSION"), c)
		if len(ms) != 1 || ms[0].value != "ng-version" || ms[0].attrValue != "17.2.0" {
			t.Errorf("attribute match = %v", ms)
		}
	})

	t.Run("endpoint path", func(t *testing.T) {
		o := newObs(t, "https://ok.example/api/graphql")
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorEndpointPath, "/graphql"), c)
		if len(ms) != 1 || ms[0].slot != 0 || ms[0].value != "/api/graphql" {
			t.Errorf("endpoint match = %v", ms)
		}
	})

	t.Run("tls issuer cn and alpn", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.TLS = &TLSInfo{
			ALPN:    []string{"h2", "h3"},
			Issuer:  "CN=WR2,O=Google Trust Services",
			Subject: "*.example.com",
		}
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorTLSIssuer, "google trust"), c)
		if len(ms) != 1 || ms[0].value != "CN=WR2,O=Google Trust Services" {
			t.Errorf("tls issuer match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorTLSCN, "EXAMPLE.COM"), c)
		if len(ms) != 1 || ms[0].value != "*.example.com" {
			t.Errorf("tls cn match = %v", ms)
		}
		ms = matchIndicator(ind(fingerprints.IndicatorTLSALPN, "h3"), c)
		if len(ms) != 1 || ms[0].slot != 1 || ms[0].value != "h3" {
			t.Errorf("tls alpn match = %v", ms)
		}
		// No TLS info, no match.
		o2 := newObs(t, "https://ok.example/")
		c2 := testCorpus(o2)
		if ms := matchIndicator(ind(fingerprints.IndicatorTLSIssuer, "google"), c2); len(ms) != 0 {
			t.Errorf("tls issuer without tls info must not match: %v", ms)
		}
	})

	t.Run("dns cname", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.DNS = &DNSInfo{CNAMEChain: []string{"edge.example.cloudflare.net", "origin.example.com"}}
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorDNSCNAME, "cloudflare.net"), c)
		if len(ms) != 1 || ms[0].slot != 0 || ms[0].value != "edge.example.cloudflare.net" {
			t.Errorf("dns match = %v", ms)
		}
	})

	t.Run("sourcemap path", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = "//# sourceMappingURL=/static/js/main.js.map"
		c := testCorpus(o)
		ms := matchIndicator(ind(fingerprints.IndicatorSourceMapPath, "main.js.map"), c)
		if len(ms) != 1 || ms[0].value != "/static/js/main.js.map" {
			t.Errorf("sourcemap match = %v", ms)
		}
	})
}

// TestHTMLSubstringEvidenceNonASCIIPrefix is the H1 regression test: the
// folded-body matcher must not index the ORIGINAL body with FOLDED offsets.
// Simple case folding shrinks some runes ("İ" 2 bytes folds to 1, "ẞ" 3
// bytes folds to 2), so a non-ASCII prefix before a matched marker makes
// the folded index land bytes EARLY in the original body — the pre-fix
// code tore UTF-8 runes and produced evidence values that did not match
// the observed body. This test pins byte-for-byte equality between the
// evidence value and the matched span of the ORIGINAL body.
func TestHTMLSubstringEvidenceNonASCIIPrefix(t *testing.T) {
	// Shrinking runes only: every non-ASCII prefix rune below must fold to
	// FEWER bytes than it occupies ("İ" 2->1, "ẞ" 3->2), so the folded
	// offset of the marker is genuinely different from the original offset
	// and the old folded-index code would tear the evidence value.
	prefix := "\u0130\u1E9E \u1E9E\u0130 "
	marker := `<DIV CF-ERROR-DETAILS="static/challenge">`
	body := prefix + marker + " tail"

	o := newObs(t, "https://ok.example/")
	o.Body = body
	c := testCorpus(o)

	ind := fingerprints.Indicator{Kind: fingerprints.IndicatorHTMLSubstring, Match: "cf-error-details", Weight: 0.8}
	ms := matchIndicator(ind, c)
	if len(ms) != 1 {
		t.Fatalf("matches = %d, want 1", len(ms))
	}
	// The evidence value must be the EXACT span of the original body —
	// byte-for-byte, rune-aligned, with the observed casing.
	want := body[strings.Index(body, "CF-ERROR-DETAILS"):][:len("CF-ERROR-DETAILS")]
	if ms[0].value != "CF-ERROR-DETAILS" {
		t.Errorf("evidence value = %q, want the observed marker %q", ms[0].value, want)
	}
	if ms[0].value != want {
		t.Errorf("evidence value = %q, want byte-exact original span %q", ms[0].value, want)
	}
	// The value must be valid UTF-8 (a torn rune fails this) and must
	// never carry bytes from BEFORE the marker's original position.
	if !utf8.ValidString(ms[0].value) {
		t.Errorf("evidence value %q is not valid UTF-8 (rune tearing)", ms[0].value)
	}
	origIdx := strings.Index(body, want)
	if ms[0].value != body[origIdx:origIdx+len(want)] {
		t.Errorf("evidence value %q diverges from the original span %q", ms[0].value, body[origIdx:origIdx+len(want)])
	}
}

// TestAnalyzeHTMLSubstringVersionNonASCIIPrefix is the H1 regression test
// for version extraction THROUGH the html_substring path: the version
// pattern applies to the original-span evidence value, and a shrinking
// non-ASCII prefix before the marker must not corrupt the span (a torn span
// would both produce a wrong evidence value AND fail the version regex).
func TestAnalyzeHTMLSubstringVersionNonASCIIPrefix(t *testing.T) {
	db, err := fingerprints.CompileForTest([]fingerprints.Fingerprint{{
		Name:     "fixture widget",
		Category: asset.CategoryFramework,
		Indicators: []fingerprints.Indicator{{
			Kind:    fingerprints.IndicatorHTMLSubstring,
			Match:   "widget-12.3.4",
			Weight:  0.9,
			Version: &fingerprints.VersionSpec{Pattern: `widget-([0-9]+\.[0-9]+\.[0-9]+)`, Group: 1},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	body := "\u0130\u1E9E<pre>widget-12.3.4</pre>"
	o := newObs(t, "https://ok.example/")
	o.Body = body

	out := analyze(o, db.Fingerprints(), 128, 512, testProv())
	if len(out.technologies) != 1 {
		t.Fatalf("technologies = %d, want 1", len(out.technologies))
	}
	tr := out.technologies[0]
	if tr.Technology.Name != "fixture widget" {
		t.Errorf("technology = %q", tr.Technology.Name)
	}
	if v := tr.Technology.Version; v != "12.3.4" {
		t.Errorf("version = %q, want 12.3.4 (extracted from the original span)", v)
	}
	if len(out.evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(out.evidence))
	}
	ev := out.evidence[0]
	if ev.Method != asset.MethodHTML || ev.Indicator != "html_substring:widget-12.3.4" {
		t.Errorf("evidence = %+v", ev)
	}
	// Byte-for-byte: the evidence value must be the marker exactly as the
	// ORIGINAL body carried it, never a folded or torn span.
	if ev.Value != "widget-12.3.4" {
		t.Errorf("evidence value = %q, want widget-12.3.4", ev.Value)
	}
	origIdx := strings.Index(body, "widget-12.3.4")
	if ev.Value != body[origIdx:origIdx+len("widget-12.3.4")] {
		t.Errorf("evidence value diverges from the original span: %q vs %q",
			ev.Value, body[origIdx:origIdx+len("widget-12.3.4")])
	}
	ids := out.techEvidence[tr.Technology.ID()]
	if len(ids) != 1 || ids[0] != ev.ID() {
		t.Errorf("techEvidence = %v, want [%s]", ids, ev.ID())
	}
}

// testFP builds a hand-built fingerprint; literal indicator kinds only (the
// regex kinds need the DB compiler).
func testFP(name string, inds ...fingerprints.Indicator) fingerprints.Fingerprint {
	return fingerprints.Fingerprint{Name: name, Category: asset.CategoryFramework, Indicators: inds}
}

func hdrInd(match string, w float64) fingerprints.Indicator {
	return fingerprints.Indicator{Kind: fingerprints.IndicatorHeader, Match: match, Weight: w}
}

func testProv() asset.Provenance {
	return asset.Provenance{Source: "test", DiscoveredAt: fixedTime}
}

func TestAnalyzeFiresTechnology(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	fps := []fingerprints.Fingerprint{testFP("nginx", hdrInd("server: nginx", 0.9))}

	out := analyze(o, fps, 128, 512, testProv())
	if len(out.technologies) != 1 {
		t.Fatalf("technologies = %d, want 1", len(out.technologies))
	}
	tr := out.technologies[0]
	if tr.Technology.Name != "nginx" || tr.Technology.Category != asset.CategoryFramework {
		t.Errorf("technology = %v", tr.Technology)
	}
	// Spoofable-only (header) 0.9 is capped to 0.59 -> Medium.
	if tr.Score != spoofableScoreCap || tr.Level != LevelMedium {
		t.Errorf("score/level = %v/%q, want %v/medium", tr.Score, tr.Level, spoofableScoreCap)
	}
	if tr.Technology.Prov.Source != "test" {
		t.Errorf("prov source = %q, want test", tr.Technology.Prov.Source)
	}

	if len(out.evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(out.evidence))
	}
	ev := out.evidence[0]
	if ev.Method != asset.MethodHeader || ev.Indicator != "header:server: nginx" ||
		ev.Value != "Server: nginx/1.25.3" || !ev.Source.Equal(o.identity()) {
		t.Errorf("evidence = %+v", ev)
	}
	ids := out.techEvidence[tr.Technology.ID()]
	if len(ids) != 1 || ids[0] != ev.ID() {
		t.Errorf("techEvidence = %v, want [%s]", ids, ev.ID())
	}
	if out.conflicts != 0 || out.truncated {
		t.Errorf("conflicts/truncated = %d/%v", out.conflicts, out.truncated)
	}
}

func TestAnalyzeVersionExtractionFromDB(t *testing.T) {
	db, err := fingerprints.Load()
	if err != nil {
		t.Fatal(err)
	}
	fpByName := func(name string) fingerprints.Fingerprint {
		for _, fp := range db.Fingerprints() {
			if fp.Name == name {
				return fp
			}
		}
		t.Fatalf("fingerprint %q not found", name)
		return fingerprints.Fingerprint{}
	}

	t.Run("header version", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3 (Ubuntu)"}}
		out := analyze(o, []fingerprints.Fingerprint{fpByName("nginx")}, 128, 512, testProv())
		if len(out.technologies) != 1 {
			t.Fatalf("technologies = %d", len(out.technologies))
		}
		if v := out.technologies[0].Technology.Version; v != "1.25.3" {
			t.Errorf("version = %q, want 1.25.3", v)
		}
	})

	t.Run("attribute version", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<div ng-app ng-version="17.2.0">`
		out := analyze(o, []fingerprints.Fingerprint{fpByName("angular")}, 128, 512, testProv())
		if len(out.technologies) != 1 {
			t.Fatalf("technologies = %d", len(out.technologies))
		}
		tr := out.technologies[0]
		if v := tr.Technology.Version; v != "17.2.0" {
			t.Errorf("version = %q, want 17.2.0", v)
		}
		// Attribute (1.0) + html substring (0.7): both structural, no cap.
		if tr.Score < 0.99 || tr.Level != LevelHigh {
			t.Errorf("score/level = %v/%q, want ~1.0/high", tr.Score, tr.Level)
		}
	})

	t.Run("generator version", func(t *testing.T) {
		o := newObs(t, "https://ok.example/")
		o.Body = `<meta name="generator" content="WordPress 6.4.2">`
		out := analyze(o, []fingerprints.Fingerprint{fpByName("wordpress")}, 128, 512, testProv())
		if len(out.technologies) != 1 {
			t.Fatalf("technologies = %d", len(out.technologies))
		}
		if v := out.technologies[0].Technology.Version; v != "6.4.2" {
			t.Errorf("version = %q, want 6.4.2", v)
		}
	})
}

func TestAnalyzeEvidenceDedupe(t *testing.T) {
	// Two identical header lines matching the same indicator are one
	// evidence record (same identity), but two distinct slots.
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{
		{Name: "X-Tech", Value: "present"},
		{Name: "X-Tech", Value: "present"},
	}
	fps := []fingerprints.Fingerprint{testFP("tech", hdrInd("x-tech", 0.8))}
	out := analyze(o, fps, 128, 512, testProv())
	if len(out.evidence) != 1 {
		t.Fatalf("evidence = %d, want 1 deduplicated record", len(out.evidence))
	}
	ids := out.techEvidence[out.technologies[0].Technology.ID()]
	if len(ids) != 1 {
		t.Errorf("techEvidence = %v, want 1 id", ids)
	}
}

func TestAnalyzeConflicts(t *testing.T) {
	// Two fingerprints agree on the same header line: one conflict.
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	fps := []fingerprints.Fingerprint{
		testFP("nginx", hdrInd("server: nginx", 0.5)),
		testFP("nginx alias", hdrInd("server: nginx/1.25.3", 0.4)),
	}
	out := analyze(o, fps, 128, 512, testProv())
	if out.conflicts != 1 {
		t.Errorf("conflicts = %d, want 1", out.conflicts)
	}
	if len(out.technologies) != 2 {
		t.Errorf("technologies = %d, want 2", len(out.technologies))
	}

	// Matches on different slots are not conflicts.
	o2 := newObs(t, "https://ok.example/")
	o2.Headers = []HeaderEntry{{Name: "A", Value: "x"}, {Name: "B", Value: "y"}}
	fps2 := []fingerprints.Fingerprint{
		testFP("a", hdrInd("a: x", 0.5)),
		testFP("b", hdrInd("b: y", 0.5)),
	}
	out2 := analyze(o2, fps2, 128, 512, testProv())
	if out2.conflicts != 0 {
		t.Errorf("conflicts = %d, want 0", out2.conflicts)
	}
}

func TestAnalyzeCookieFlagEvidence(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Set-Cookie", Value: "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}}
	out := analyze(o, nil, 128, 512, testProv())
	if len(out.technologies) != 0 {
		t.Errorf("technologies = %d, want 0 (evidence-only)", len(out.technologies))
	}
	if len(out.evidence) != 3 {
		t.Fatalf("evidence = %d, want 3 cookie-flag records", len(out.evidence))
	}
	keys := map[string]bool{}
	for _, ev := range out.evidence {
		keys[ev.Indicator] = true
		if ev.Method != asset.MethodCookie {
			t.Errorf("method = %q, want cookie", ev.Method)
		}
		if ev.Value != "sid" || ev.Source.String() != o.identity().String() {
			t.Errorf("flag evidence = %+v", ev)
		}
	}
	for _, k := range []string{cookieFlagIndicatorHTTPOnly, cookieFlagIndicatorSecure, cookieFlagIndicatorSameSite} {
		if !keys[k] {
			t.Errorf("missing cookie flag indicator %q", k)
		}
	}

	// The flag scan survives the attribute allow-list: junk directives are
	// dropped as cookies but their presence neither suppresses the real
	// flags nor produces extra evidence.
	o2 := newObs(t, "https://ok.example/")
	o2.Headers = []HeaderEntry{{Name: "Set-Cookie", Value: "sid=abc; HttpOnly; Bogus=1; CommonName=nope; Secure"}}
	out2 := analyze(o2, nil, 128, 512, testProv())
	if len(out2.evidence) != 2 {
		t.Fatalf("junk-directive evidence = %d, want exactly the 2 real flags (dropped directives fire nothing)", len(out2.evidence))
	}
	for _, ev := range out2.evidence {
		if ev.Value != "sid" {
			t.Errorf("flag evidence value = %q, want sid", ev.Value)
		}
		switch ev.Indicator {
		case cookieFlagIndicatorHTTPOnly, cookieFlagIndicatorSecure:
		default:
			t.Errorf("unexpected evidence indicator %q from a dropped directive", ev.Indicator)
		}
	}
}

func TestAnalyzeTechnologiesCap(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	fps := []fingerprints.Fingerprint{
		testFP("cc", hdrInd("x-cc: 1", 1.0)),
		testFP("aa", hdrInd("x-aa: 1", 1.0)),
		testFP("bb", hdrInd("x-bb: 1", 1.0)),
	}
	o.Headers = []HeaderEntry{
		{Name: "X-Cc", Value: "1"},
		{Name: "X-Aa", Value: "1"},
		{Name: "X-Bb", Value: "1"},
	}
	out := analyze(o, fps, 2, 512, testProv())
	if len(out.technologies) != 2 {
		t.Fatalf("technologies = %d, want 2 (cap)", len(out.technologies))
	}
	if !out.overflow.Technologies {
		t.Error("technology overflow must be flagged")
	}
	// Deterministic retention: score desc, then name asc.
	if out.technologies[0].Technology.Name != "aa" || out.technologies[1].Technology.Name != "bb" {
		t.Errorf("retained order = %v", out.technologies)
	}
	// Evidence for the dropped technology is still reported, but has no
	// technology edge.
	if len(out.evidence) != 3 {
		t.Errorf("evidence = %d, want 3 (all matches retained)", len(out.evidence))
	}
	if len(out.techEvidence) != 2 {
		t.Errorf("techEvidence keys = %d, want 2 (dropped tech has no edges)", len(out.techEvidence))
	}
}

func TestAnalyzeIndicatorsCap(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{
		{Name: "X-A", Value: "1"}, {Name: "X-B", Value: "2"},
		{Name: "X-C", Value: "3"}, {Name: "X-D", Value: "4"},
	}
	fps := []fingerprints.Fingerprint{testFP("multi", hdrInd("x-a: 1", 0.5), hdrInd("x-b: 2", 0.6), hdrInd("x-c: 3", 0.7), hdrInd("x-d: 4", 0.8))}
	out := analyze(o, fps, 128, 2, testProv())
	if len(out.evidence) != 2 {
		t.Fatalf("evidence = %d, want 2 (cap)", len(out.evidence))
	}
	if !out.overflow.Indicators {
		t.Error("indicator overflow must be flagged")
	}
	// The retained matches are the first in DB/slot order.
	if out.evidence[0].Indicator != "header:x-a: 1" || out.evidence[1].Indicator != "header:x-b: 2" {
		t.Errorf("retained evidence = %v", out.evidence)
	}
}
