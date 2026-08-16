package jsintel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestParseLineForms(t *testing.T) {
	base := mustURL(t, "http://example.com/page/index.html")
	cfgWithBase := Config{Base: base}
	cfgNoBase := Config{}

	tests := []struct {
		name          string
		cfg           Config
		line          string
		wantCands     []string
		wantMalformed int
		wantSecret    bool
		wantSecretTyp asset.SecretType
		wantDropped   bool
		wantProgress  string // canonical URL when the line is a progress form
	}{
		{name: "empty", cfg: cfgWithBase, line: ""},
		{name: "blank", cfg: cfgWithBase, line: "  \t "},
		{name: "absolute http", cfg: cfgNoBase, line: "http://example.com/a.js", wantCands: []string{"http://example.com/a.js"}},
		{name: "absolute https with query", cfg: cfgNoBase, line: "https://example.com:8443/a.js?x=1", wantCands: []string{"https://example.com:8443/a.js?x=1"}},
		{name: "absolute canonicalized", cfg: cfgNoBase, line: "HTTP://EXAMPLE.COM/A.JS", wantCands: []string{"http://example.com/A.JS"}},
		{name: "progress form bracketed", cfg: cfgNoBase, line: "[ + ] URL: <http://example.com/a.js>", wantCands: []string{"http://example.com/a.js"}, wantProgress: "http://example.com/a.js"},
		{name: "progress form bare", cfg: cfgNoBase, line: "[ + ] URL: http://example.com/a.js", wantCands: []string{"http://example.com/a.js"}, wantProgress: "http://example.com/a.js"},
		{name: "protocol-relative with base", cfg: cfgWithBase, line: "//cdn.example.com/lib.js", wantCands: []string{"http://cdn.example.com/lib.js"}},
		{name: "protocol-relative without base", cfg: cfgNoBase, line: "//cdn.example.com/lib.js", wantMalformed: 1},
		{name: "root-relative with base", cfg: cfgWithBase, line: "/lib.js", wantCands: []string{"http://example.com/lib.js"}},
		{name: "relative dot with base", cfg: cfgWithBase, line: "./x.js", wantCands: []string{"http://example.com/page/x.js"}},
		{name: "relative dotdot with base", cfg: cfgWithBase, line: "../x.js", wantCands: []string{"http://example.com/x.js"}},
		{name: "bare text is malformed", cfg: cfgWithBase, line: "react", wantMalformed: 1},
		{name: "data scheme is malformed", cfg: cfgWithBase, line: "data:text/plain,hello", wantMalformed: 1},
		{name: "javascript scheme is malformed", cfg: cfgWithBase, line: "javascript:void(0)", wantMalformed: 1},
		{name: "ftp scheme is malformed", cfg: cfgWithBase, line: "ftp://example.com/x", wantMalformed: 1},
		{name: "secret line typed google", cfg: cfgWithBase, line: "google_api_key\t->\tAIzaSyA-test-key-123456789012345678901234", wantSecret: true, wantSecretTyp: asset.SecretTypeGoogle},
		{name: "secret line typed jwt", cfg: cfgWithBase, line: "json_web_token\t->\teyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", wantSecret: true, wantSecretTyp: asset.SecretTypeJWT},
		{name: "secret line typed aws", cfg: cfgWithBase, line: "amazon_aws_access_key_id\t->\tAKIAIOSFODNN7EXAMPLE", wantSecret: true, wantSecretTyp: asset.SecretTypeAWS},
		{name: "secret line typed firebase", cfg: cfgWithBase, line: "firebase_api_key\t->\tAIzaSyA-test-key-123456789012345678901234", wantSecret: true, wantSecretTyp: asset.SecretTypeFirebase},
		{name: "secret line typed stripe", cfg: cfgWithBase, line: "stripe_secret_key\t->\tsk_" + "live_1234567890abcdefghij", wantSecret: true, wantSecretTyp: asset.SecretTypeStripe},
		{name: "secret line typed github", cfg: cfgWithBase, line: "github_token\t->\tghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12", wantSecret: true, wantSecretTyp: asset.SecretTypeGitHub},
		{name: "secret line typed private key", cfg: cfgWithBase, line: "private_key\t->\t-----BEGIN RSA PRIVATE KEY-----", wantSecret: true, wantSecretTyp: asset.SecretTypePrivateKey},
		{name: "secret line typed bearer", cfg: cfgWithBase, line: "bearer\t->\tBearer abcdefghijklmnopqrstuvwxyz0123456789", wantSecret: true, wantSecretTyp: asset.SecretTypeBearer},
		{name: "secret line unknown name is generic", cfg: cfgWithBase, line: "api_key\t->\tsecret-value", wantSecret: true, wantSecretTyp: asset.SecretTypeGeneric},
		{name: "secret line name case-insensitive", cfg: cfgWithBase, line: "Google_API_Key\t->\tAIzaSyA-test-key-123456789012345678901234", wantSecret: true, wantSecretTyp: asset.SecretTypeGoogle},
		{name: "secret line empty value dropped", cfg: cfgWithBase, line: "google_api_key\t->\t", wantSecret: true, wantDropped: true},
		{name: "secret line overlong value dropped", cfg: cfgWithBase, line: "google_api_key\t->\t" + strings.Repeat("v", maxLineSecretValueBytes+1), wantSecret: true, wantDropped: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cands, malformed, secret, progress := parseLine(tt.cfg, tt.line)
			if (secret != nil) != tt.wantSecret {
				t.Fatalf("secret = %v, want %v", secret != nil, tt.wantSecret)
			}
			if secret != nil {
				if secret.dropped != tt.wantDropped {
					t.Errorf("secret.dropped = %v, want %v", secret.dropped, tt.wantDropped)
				}
				if !tt.wantDropped && secret.typ != tt.wantSecretTyp {
					t.Errorf("secret type = %q, want %q", secret.typ, tt.wantSecretTyp)
				}
			}
			if malformed != tt.wantMalformed {
				t.Errorf("malformed = %d, want %d", malformed, tt.wantMalformed)
			}
			var got []string
			for _, c := range cands {
				got = append(got, c.String())
			}
			if len(got) != len(tt.wantCands) {
				t.Fatalf("candidates = %v, want %v", got, tt.wantCands)
			}
			for i := range got {
				if got[i] != tt.wantCands[i] {
					t.Errorf("candidate %d = %q, want %q", i, got[i], tt.wantCands[i])
				}
			}
			var prog string
			if !progress.IsZero() {
				prog = progress.String()
			}
			if prog != tt.wantProgress {
				t.Errorf("progress = %q, want %q", prog, tt.wantProgress)
			}
		})
	}
}

func TestParseHTMLScriptSrcForms(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Body: `<script src="/a.js"></script>
<script src='b.js'></script>
<script src=c.js></script>
<script src = "/d.js" ></script>
`,
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	want := []string{
		"http://example.com/a.js",
		"http://example.com/page/b.js",
		"http://example.com/page/c.js",
		"http://example.com/d.js",
	}
	if malformed != 0 || dropped != 0 {
		t.Fatalf("malformed = %d, dropped = %d, want 0/0", malformed, dropped)
	}
	if len(cands) != len(want) {
		t.Fatalf("candidates = %v, want %v", candStrings(cands), want)
	}
	for i, w := range want {
		if cands[i].String() != w {
			t.Errorf("candidate %d = %q, want %q", i, cands[i], w)
		}
	}
}

func TestParseHTMLLinkQualification(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Body: `<link rel="modulepreload" href="/m.js">
<link rel="preload" as="script" href="/p.js">
<link rel="prefetch" as="script" href="/pf.js">
<link rel="preload" href="/np.js">
<link rel="prefetch" href="/nf.js">
<link rel="stylesheet" href="/s.css">
<LINK REL="MODULEPRELOAD" HREF="/U.JS">
<link rel="preload" as=script href="/uq.js">
`,
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	want := []string{
		"http://example.com/m.js",
		"http://example.com/p.js",
		"http://example.com/pf.js",
		"http://example.com/U.JS",
		"http://example.com/uq.js",
	}
	if malformed != 0 || dropped != 0 {
		t.Fatalf("malformed = %d, dropped = %d, want 0/0", malformed, dropped)
	}
	if len(cands) != len(want) {
		t.Fatalf("candidates = %v, want %v", candStrings(cands), want)
	}
	for i, w := range want {
		if cands[i].String() != w {
			t.Errorf("candidate %d = %q, want %q", i, cands[i], w)
		}
	}
}

func TestParseHTMLLinkHeader(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Headers: []HeaderEntry{{
			Name: "Link",
			Value: `<https://example.com/a.js>; rel=modulepreload, <b.js>; rel=preload; as=script, ` +
				`<c.js>; rel=stylesheet, <https://example.com/x,y.js>; rel=modulepreload`,
		}},
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	want := []string{
		"https://example.com/a.js",
		"http://example.com/page/b.js",
		"https://example.com/x,y.js",
	}
	if malformed != 0 || dropped != 0 {
		t.Fatalf("malformed = %d, dropped = %d, want 0/0", malformed, dropped)
	}
	if len(cands) != len(want) {
		t.Fatalf("candidates = %v, want %v", candStrings(cands), want)
	}
	for i, w := range want {
		if cands[i].String() != w {
			t.Errorf("candidate %d = %q, want %q", i, cands[i], w)
		}
	}

	// A dangling '<' ends the scan: only the first entry contributes.
	item2 := item
	item2.Headers = []HeaderEntry{{Name: "Link", Value: `<https://example.com/a.js>; rel=modulepreload, <unterminated`}}
	cands, malformed, _ = parseHTML(item2, NewParser(), 128)
	if len(cands) != 1 || cands[0].String() != "https://example.com/a.js" {
		t.Fatalf("dangling '<' candidates = %v, want just a.js", candStrings(cands))
	}
}

func TestParseHTMLInlineImports(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Body: `<script>import "./x.js"; import "react"; import("/abs.js"); import("data:text/plain,a");</script>`,
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	want := []string{
		"http://example.com/page/x.js",
		"http://example.com/abs.js",
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
	if malformed != 1 {
		t.Errorf("malformed = %d, want 1 (the data: specifier)", malformed)
	}
	if len(cands) != len(want) {
		t.Fatalf("candidates = %v, want %v", candStrings(cands), want)
	}
	for i, w := range want {
		if cands[i].String() != w {
			t.Errorf("candidate %d = %q, want %q", i, cands[i], w)
		}
	}
}

func TestParseHTMLMaxScriptsCap(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Body: `<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`,
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 2)
	if len(cands) != 2 {
		t.Errorf("candidates = %v, want 2", candStrings(cands))
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if malformed != 0 {
		t.Errorf("malformed = %d, want 0", malformed)
	}
}

func TestParseHTMLBodyTruncation(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Body: strings.Repeat("a", MaxHTMLBody) + `<script src="/x.js"></script>`,
	}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	if len(cands) != 0 {
		t.Errorf("candidates = %v, want none (the script tag lies beyond the body cap)", candStrings(cands))
	}
	if malformed != 0 || dropped != 0 {
		t.Errorf("malformed = %d, dropped = %d, want 0/0", malformed, dropped)
	}
}

func TestParseHTMLHostileNoPanic(t *testing.T) {
	page := mustURL(t, "http://example.com/page/index.html")
	parser := NewParser()

	// An unterminated tag ends the scan; nothing crashes.
	item := Item{Kind: ItemHTML, URL: page, Body: `<script src="/a.js"`}
	if cands, malformed, dropped := parseHTML(item, parser, 128); len(cands) != 0 || malformed != 0 || dropped != 0 {
		t.Errorf("unterminated tag: candidates = %v, malformed = %d, dropped = %d", candStrings(cands), malformed, dropped)
	}

	// Binary garbage and a trailing "<script" never panic.
	item.Body = "\x00\x01\x02\xff<script"
	if _, _, _ = parseHTML(item, parser, 128); true {
		// reaching here is the assertion (no panic)
	}

	// An over-long attribute value is cut at the cap and the scan continues
	// with the remainder; the cut value itself resolves as a (bounded)
	// relative candidate and the later real tag still contributes.
	item.Body = `<script src="` + strings.Repeat("x", 5000) + `"><script src="/b.js"></script>`
	cands, malformed, dropped := parseHTML(item, parser, 128)
	if len(cands) != 2 {
		t.Fatalf("oversized attr: candidates = %v, want the capped value and b.js", candStrings(cands))
	}
	if !strings.HasPrefix(cands[0].String(), "http://example.com/page/") {
		t.Errorf("oversized attr: candidate 0 = %q, want a page-relative URL", cands[0])
	}
	if wantPath := len("/page/") + maxAttrValueBytes; len(cands[0].Path) != wantPath {
		t.Errorf("oversized attr: candidate 0 path length = %d, want %d (value cut at the attr cap)", len(cands[0].Path), wantPath)
	}
	if cands[1].String() != "http://example.com/b.js" {
		t.Errorf("oversized attr: candidate 1 = %q, want b.js", cands[1])
	}
	if malformed != 0 || dropped != 0 {
		t.Errorf("oversized attr: malformed = %d, dropped = %d, want 0/0", malformed, dropped)
	}
}

func TestParseHTMLZeroPageURL(t *testing.T) {
	item := Item{Kind: ItemHTML, Body: `<script src="/a.js"></script>`}
	cands, malformed, dropped := parseHTML(item, NewParser(), 128)
	if len(cands) != 0 || malformed != 0 || dropped != 0 {
		t.Errorf("zero page URL: candidates = %v, malformed = %d, dropped = %d", candStrings(cands), malformed, dropped)
	}
}

func TestScanTagAttrs(t *testing.T) {
	// Quoted values may contain '>'; attribute names are lowercased; values
	// may be single-, double-, or unquoted; bare attributes have "".
	attrs, end, ok := scanTagAttrs(`<img src="a>b" alt='c' data-x=unquoted defer>`, len("<img"))
	if !ok {
		t.Fatal("tag must terminate")
	}
	if attrs["src"] != "a>b" || attrs["alt"] != "c" || attrs["data-x"] != "unquoted" || attrs["defer"] != "" {
		t.Errorf("attrs = %v", attrs)
	}
	if body := `<img src="a>b" alt='c' data-x=unquoted defer>`; end != len(body)-1 {
		t.Errorf("end = %d, want %d (index of '>')", end, len(body)-1)
	}

	// Case-insensitive names.
	attrs, _, ok = scanTagAttrs(`<A HREF="/x">`, len("<A"))
	if !ok || attrs["href"] != "/x" {
		t.Errorf("uppercase attrs = %v, ok = %v", attrs, ok)
	}

	// Missing closing quote: the value runs to the end, the tag never
	// terminates.
	attrs, _, ok = scanTagAttrs(`<a href="unterminated`, len("<a"))
	if ok {
		t.Error("unterminated tag must report ok = false")
	}
	if attrs["href"] != "unterminated" {
		t.Errorf("attrs = %v, want href captured up to the end", attrs)
	}

	// Self-closing tag terminates at the '/'.
	attrs, _, ok = scanTagAttrs(`<a href="/x"/>`, len("<a"))
	if !ok || attrs["href"] != "/x" {
		t.Errorf("self-closing: attrs = %v, ok = %v", attrs, ok)
	}
}

func TestParseLinkHeader(t *testing.T) {
	v := `<https://example.com/a.js>; rel=modulepreload, <b.js>; rel=preload; as=script, <c.js>; rel=stylesheet`
	hrefs := parseLinkHeader(v)
	want := []string{"https://example.com/a.js", "b.js"}
	if len(hrefs) != len(want) {
		t.Fatalf("hrefs = %v, want %v", hrefs, want)
	}
	for i, w := range want {
		if hrefs[i] != w {
			t.Errorf("href %d = %q, want %q", i, hrefs[i], w)
		}
	}

	if got := parseLinkHeader(""); len(got) != 0 {
		t.Errorf("empty header hrefs = %v, want none", got)
	}
	if got := parseLinkHeader("<unterminated"); len(got) != 0 {
		t.Errorf("dangling '<' hrefs = %v, want none", got)
	}
}

func TestParseLinkParams(t *testing.T) {
	rel, as := parseLinkParams(` rel="modulepreload"`)
	if len(rel) != 1 || rel[0] != "modulepreload" || as != "" {
		t.Errorf("rel = %v, as = %q", rel, as)
	}
	rel, as = parseLinkParams(` rel=preload; as="script"`)
	if len(rel) != 1 || rel[0] != "preload" || as != "script" {
		t.Errorf("rel = %v, as = %q", rel, as)
	}
	rel, as = parseLinkParams(` REL=Preload; AS=SCRIPT`)
	if len(rel) != 1 || rel[0] != "preload" || as != "SCRIPT" {
		t.Errorf("case: rel = %v, as = %q", rel, as)
	}
	// A parameter without '=' is ignored.
	rel, as = parseLinkParams(`rel=preload; crossorigin; as=script`)
	if len(rel) != 1 || rel[0] != "preload" || as != "script" {
		t.Errorf("rel = %v, as = %q", rel, as)
	}
}

func TestLinkQualifies(t *testing.T) {
	tests := []struct {
		rel  []string
		as   string
		want bool
	}{
		{rel: []string{"modulepreload"}, want: true},
		{rel: []string{"ModulePreload"}, want: true},
		{rel: []string{"preload"}, as: "script", want: true},
		{rel: []string{"preload"}, as: "style", want: false},
		{rel: []string{"preload"}, want: false},
		{rel: []string{"prefetch"}, as: "script", want: true},
		{rel: []string{"stylesheet"}, want: false},
		{rel: []string{"preload", "stylesheet"}, as: "script", want: true},
	}
	for _, tt := range tests {
		if got := linkQualifies(tt.rel, tt.as); got != tt.want {
			t.Errorf("linkQualifies(%v, %q) = %v, want %v", tt.rel, tt.as, got, tt.want)
		}
	}
}

func TestFindNextTag(t *testing.T) {
	at, isScript, ok := findNextTag(`<link ...><script ...>`, 0)
	if !ok || isScript || at != 0 {
		t.Errorf("link first: at = %d, isScript = %v, ok = %v", at, isScript, ok)
	}
	at, isScript, ok = findNextTag(`x<script ...><link ...>`, 0)
	if !ok || !isScript || at != 1 {
		t.Errorf("script first: at = %d, isScript = %v, ok = %v", at, isScript, ok)
	}
	// "<scriptx" is not a script tag; the scan must not match it.
	at, isScript, ok = findNextTag(`<scriptx>`, 0)
	if !ok || isScript || at != 0 {
		t.Errorf("scriptx: at = %d, isScript = %v, ok = %v", at, isScript, ok)
	}
	if _, _, ok := findNextTag(`no tags here`, 0); ok {
		t.Error("no tags must report ok = false")
	}
}

// candStrings renders candidates for diagnostics.
func candStrings(cands []asset.URL) []string {
	var out []string
	for _, c := range cands {
		out = append(out, c.String())
	}
	return out
}
