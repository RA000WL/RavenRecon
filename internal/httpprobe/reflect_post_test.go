package httpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// postObservedRequest records one request seen by postReflectTransport.
type postObservedRequest struct {
	method      string
	url         string
	rawQuery    string
	contentType string
	body        string
}

// postReflectTransport is a hermetic RoundTripper for POST reflection
// tests: it records method, query, content type, and body of every
// request and answers from synthetic modes, never dialing.
//
// getMode/postMode are each one of "echo" (decoded values raw),
// "encode" (values percent-encoded), or "silent" (static page). A GET
// whose query carries a substituted canary (percent-encoded ':') is a
// reflection GET; other GETs are answered static (liveness-shaped).
type postReflectTransport struct {
	mu       sync.Mutex
	reqs     []postObservedRequest
	getMode  string
	postMode string
	status   int
}

func (t *postReflectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(data)
	}
	t.mu.Lock()
	t.reqs = append(t.reqs, postObservedRequest{
		method:      req.Method,
		url:         req.URL.String(),
		rawQuery:    req.URL.RawQuery,
		contentType: req.Header.Get("Content-Type"),
		body:        body,
	})
	t.mu.Unlock()
	if req.Method == http.MethodPost {
		return t.answerPost(req, body), nil
	}
	if strings.Contains(req.URL.RawQuery, "%3A") {
		return t.answerValues(t.getMode, queryValues(req.URL.RawQuery)), nil
	}
	return reflectTestResponse(t.statusOr200(), "<html><body>liveness static</body></html>"), nil
}

func (t *postReflectTransport) statusOr200() int {
	if t.status != 0 {
		return t.status
	}
	return 200
}

func (t *postReflectTransport) answerPost(req *http.Request, body string) *http.Response {
	var vals []string
	switch {
	case strings.HasPrefix(req.Header.Get("Content-Type"), "application/json"):
		var m map[string]string
		if err := json.Unmarshal([]byte(body), &m); err == nil {
			for _, v := range m {
				vals = append(vals, v)
			}
		}
	default:
		vals = queryValues(body)
	}
	return t.answerValues(t.postMode, vals)
}

func (t *postReflectTransport) answerValues(mode string, vals []string) *http.Response {
	switch mode {
	case "echo":
		return reflectTestResponse(t.statusOr200(), "<html><body>\n"+strings.Join(vals, "\n")+"\n</body></html>")
	case "encode":
		enc := make([]string, 0, len(vals))
		for _, v := range vals {
			enc = append(enc, url.QueryEscape(v))
		}
		return reflectTestResponse(t.statusOr200(), "<html><body>\n"+strings.Join(enc, "\n")+"\n</body></html>")
	default: // "silent" and anything else: static page, no echo.
		return reflectTestResponse(t.statusOr200(), "<html><body>static page, no echo</body></html>")
	}
}

// queryValues decodes form-style pairs into values.
func queryValues(body string) []string {
	q, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}
	var vals []string
	for _, vs := range q {
		vals = append(vals, vs...)
	}
	return vals
}

func (t *postReflectTransport) requests() []postObservedRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]postObservedRequest(nil), t.reqs...)
}

func (t *postReflectTransport) posts() []postObservedRequest {
	var out []postObservedRequest
	for _, r := range t.requests() {
		if r.method == http.MethodPost {
			out = append(out, r)
		}
	}
	return out
}

func postFormConfig(tr *postReflectTransport) Config {
	return Config{Concurrency: 2, QueueSize: 4, Transport: tr}
}

func TestReflectPOSTFormEcho(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &postReflectTransport{postMode: "echo"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	if len(rep.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(rep.Records))
	}
	rec := rep.Records[0]
	if rec.Err != nil {
		t.Fatalf("record err = %v, want nil", rec.Err)
	}
	if rec.Scope != ReflectScopePostForm {
		t.Fatalf("scope = %q, want %q", rec.Scope, ReflectScopePostForm)
	}
	got := reflectVerdictsByParam(t, rec)
	for _, p := range []string{"q", "page"} {
		if got[p] != ReflectUnencoded {
			t.Errorf("param %q verdict = %q, want %q", p, got[p], ReflectUnencoded)
		}
	}
	posts := tr.posts()
	if len(posts) != 1 {
		t.Fatalf("POST requests = %d, want 1 (single POST per URL+kind)", len(posts))
	}
	if len(tr.requests()) != 1 {
		t.Fatalf("total requests = %d, want 1 (POST probe issues no GET)", len(tr.requests()))
	}
	p := posts[0]
	if p.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want the form type", p.contentType)
	}
	if p.rawQuery == "" {
		t.Error("POST dropped the original query string (canaries travel in the body; the URL stays intact)")
	}
	// Same canary scheme as GET: the body carries reflectCanary(urlID, param).
	for _, name := range []string{"q", "page"} {
		want := reflectCanary(u.Identity().String(), name)
		q, err := url.ParseQuery(p.body)
		if err != nil {
			t.Fatalf("ParseQuery POST body: %v", err)
		}
		if q.Get(name) != want {
			t.Errorf("form field %q = %q, want canary %q", name, q.Get(name), want)
		}
	}
	if rec.Status != 200 {
		t.Errorf("status = %d, want 200", rec.Status)
	}
}

// TestReflectPOSTFormEncoded pins percent-encoded body echo as
// reflected-encoded.
func TestReflectPOSTFormEncoded(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &postReflectTransport{postMode: "encode"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	got := reflectVerdictsByParam(t, rep.Records[0])
	for _, p := range []string{"q", "page"} {
		if got[p] != ReflectEncoded {
			t.Errorf("param %q verdict = %q, want %q", p, got[p], ReflectEncoded)
		}
	}
}

// TestReflectPOSTFormSilent pins a fully-read body without canaries as
// not-reflected (never unknown without truncation).
func TestReflectPOSTFormSilent(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &postReflectTransport{postMode: "silent"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	rec := rep.Records[0]
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectAbsent {
		t.Errorf("param q verdict = %q, want %q", got, ReflectAbsent)
	}
	if rec.Truncated {
		t.Error("Truncated = true, want false for a fully-read body")
	}
}

// TestReflectPOSTJSONModes pins the JSON probe across echo/encode/silent:
// the body is a param→canary object served as application/json.
func TestReflectPOSTJSONModes(t *testing.T) {
	cases := []struct {
		mode string
		want ReflectVerdict
	}{
		{"echo", ReflectUnencoded},
		{"encode", ReflectEncoded},
		{"silent", ReflectAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			domain := mustDomainProbe(t, "example.com")
			u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
			tr := &postReflectTransport{postMode: tc.mode}
			rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostJSON, postFormConfig(tr))
			if err != nil {
				t.Fatalf("ReflectPOSTURLs: %v", err)
			}
			rec := rep.Records[0]
			if rec.Scope != ReflectScopePostJSON {
				t.Fatalf("scope = %q, want %q", rec.Scope, ReflectScopePostJSON)
			}
			got := reflectVerdictsByParam(t, rec)
			for _, p := range []string{"q", "page"} {
				if got[p] != tc.want {
					t.Errorf("param %q verdict = %q, want %q", p, got[p], tc.want)
				}
			}
			posts := tr.posts()
			if len(posts) != 1 {
				t.Fatalf("POST requests = %d, want 1", len(posts))
			}
			if posts[0].contentType != "application/json" {
				t.Errorf("Content-Type = %q, want the JSON type", posts[0].contentType)
			}
			var m map[string]string
			if err := json.Unmarshal([]byte(posts[0].body), &m); err != nil {
				t.Fatalf("POST body is not a JSON object: %v", err)
			}
			for _, p := range []string{"q", "page"} {
				if m[p] != reflectCanary(u.Identity().String(), p) {
					t.Errorf("JSON field %q = %q, want the GET-scheme canary", p, m[p])
				}
			}
		})
	}
}

// TestReflectPOSTFormBodyShape pins the exact deterministic rendering:
// sorted canonical params, QueryEscape-d names and canaries, "&"-joined.
// Field names render the first-seen ORIGINAL spelling; verdict attribution
// stays lowercased.
func TestReflectPOSTFormBodyShape(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &postReflectTransport{postMode: "silent"}
	if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr)); err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	posts := tr.posts()
	if len(posts) != 1 {
		t.Fatalf("POST requests = %d, want 1", len(posts))
	}
	want := url.QueryEscape("page") + "=" + url.QueryEscape(reflectCanary(u.Identity().String(), "page")) +
		"&" + url.QueryEscape("q") + "=" + url.QueryEscape(reflectCanary(u.Identity().String(), "q"))
	if posts[0].body != want {
		t.Errorf("form body = %q, want %q (sorted, escaped, deterministic)", posts[0].body, want)
	}
}

// TestReflectPOSTMixedCaseBodySpelling pins first-seen ORIGINAL field
// spellings in the POST body with lowercased verdict attribution:
// ?Q=term&Page=2 renders "Page" and "Q" on the wire while verdicts stay
// "page" and "q".
func TestReflectPOSTMixedCaseBodySpelling(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?Q=term&Page=2")
	tr := &postReflectTransport{postMode: "echo"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	rec := rep.Records[0]
	got := reflectVerdictsByParam(t, rec)
	for _, p := range []string{"q", "page"} {
		if got[p] != ReflectUnencoded {
			t.Errorf("param %q verdict = %q, want %q (attribution stays lowercased)", p, got[p], ReflectUnencoded)
		}
	}
	posts := tr.posts()
	if len(posts) != 1 {
		t.Fatalf("POST requests = %d, want 1", len(posts))
	}
	// Canonical order is [page q]; wire spellings are the first-seen
	// originals "Page" and "Q".
	want := url.QueryEscape("Page") + "=" + url.QueryEscape(reflectCanary(u.Identity().String(), "page")) +
		"&" + url.QueryEscape("Q") + "=" + url.QueryEscape(reflectCanary(u.Identity().String(), "q"))
	if posts[0].body != want {
		t.Errorf("form body = %q, want %q (first-seen original spellings, sorted by canonical)", posts[0].body, want)
	}
	// The JSON channel renders the same original spellings as object keys
	// in sorted canonical order.
	trJSON := &postReflectTransport{postMode: "silent"}
	if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostJSON, postFormConfig(trJSON)); err != nil {
		t.Fatalf("ReflectPOSTURLs json: %v", err)
	}
	jposts := trJSON.posts()
	if len(jposts) != 1 {
		t.Fatalf("JSON POST requests = %d, want 1", len(jposts))
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(jposts[0].body), &m); err != nil {
		t.Fatalf("JSON body is not an object: %v", err)
	}
	if m["Page"] != reflectCanary(u.Identity().String(), "page") {
		t.Errorf("JSON field %q = %q, want the page canary under its original spelling", "Page", m["Page"])
	}
	if m["Q"] != reflectCanary(u.Identity().String(), "q") {
		t.Errorf("JSON field %q = %q, want the q canary under its original spelling", "Q", m["Q"])
	}
	if _, ok := m["page"]; ok {
		t.Error("JSON body carries lowercased \"page\": want the original \"Page\" spelling")
	}
	if _, ok := m["q"]; ok {
		t.Error("JSON body carries lowercased \"q\": want the original \"Q\" spelling")
	}
}

// TestReflectPOSTNoParams pins zero requests for a param-less URL.
func TestReflectPOSTNoParams(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/about")
	tr := &postReflectTransport{postMode: "echo"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	if len(rep.Records) != 1 || len(rep.Records[0].Verdicts) != 0 {
		t.Fatalf("records = %+v, want one empty verdict set", rep.Records)
	}
	if rep.Records[0].Err != nil {
		t.Fatalf("record err = %v, want nil", rep.Records[0].Err)
	}
	if len(tr.requests()) != 0 {
		t.Fatalf("requests = %d, want 0", len(tr.requests()))
	}
}

// TestReflectPOSTBareParamSkipped pins bare "?q" as Skipped with zero
// requests — a bare parameter is never substituted, so it must never
// verdict not-reflected (AGENTS §0.6), on POST exactly as on GET.
func TestReflectPOSTBareParamSkipped(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q")
	tr := &postReflectTransport{postMode: "echo"}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	rec := rep.Records[0]
	if rec.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1", rec.Skipped)
	}
	if len(rec.Verdicts) != 0 {
		t.Fatalf("verdicts = %v, want none", rec.Verdicts)
	}
	if len(tr.requests()) != 0 {
		t.Fatalf("requests = %d, want 0", len(tr.requests()))
	}
}

// TestReflectPOSTRejectsNonBodyScope pins kind validation before any
// request: only body kinds are probeable via POST.
func TestReflectPOSTRejectsNonBodyScope(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	for _, kind := range []ReflectScope{ReflectScopeQueryGET, "", "header-x"} {
		tr := &postReflectTransport{postMode: "echo"}
		if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, kind, postFormConfig(tr)); err == nil {
			t.Errorf("scope %q accepted, want rejection before any request", kind)
		}
		if len(tr.requests()) != 0 {
			t.Errorf("scope %q issued %d requests, want 0", kind, len(tr.requests()))
		}
	}
}

// TestReflectPOSTScopeRejectsOutOfDomain pins scope validation before any
// request.
func TestReflectPOSTScopeRejectsOutOfDomain(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://evil.com/search?q=term")
	tr := &postReflectTransport{postMode: "echo"}
	if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, postFormConfig(tr)); err == nil {
		t.Fatal("out-of-domain URL accepted, want rejection before any request")
	}
	if len(tr.requests()) != 0 {
		t.Fatalf("requests = %d, want 0", len(tr.requests()))
	}
}

// TestReflectKeySeparation pins distinct cache keys per channel: the same
// (URL, params) under GET, post-form, and post-json — and across sessions
// — never share a key.
func TestReflectKeySeparation(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	get, err := reflectKey(u, domain, []string{"q"}, "")
	if err != nil {
		t.Fatalf("reflectKey: %v", err)
	}
	form, err := reflectPostKey(u, domain, []string{"q"}, "", ReflectScopePostForm)
	if err != nil {
		t.Fatalf("reflectPostKey form: %v", err)
	}
	js, err := reflectPostKey(u, domain, []string{"q"}, "", ReflectScopePostJSON)
	if err != nil {
		t.Fatalf("reflectPostKey json: %v", err)
	}
	formSession, err := reflectPostKey(u, domain, []string{"q"}, "digest-abc", ReflectScopePostForm)
	if err != nil {
		t.Fatalf("reflectPostKey session: %v", err)
	}
	for name, pair := range map[string][2]cache.Key{
		"get-vs-form":     {get, form},
		"get-vs-json":     {get, js},
		"form-vs-json":    {form, js},
		"form-vs-session": {form, formSession},
	} {
		if pair[0] == pair[1] {
			t.Errorf("keys equal for %s (%q): channels must never share an entry", name, pair[0])
		}
	}
	// The scope resolver reproduces the GET key byte-identically (old
	// entries stay valid) and routes POST kinds to POST keys.
	getViaScope, err := reflectKeyForScope(u, domain, []string{"q"}, "", ReflectScopeQueryGET)
	if err != nil {
		t.Fatalf("reflectKeyForScope GET: %v", err)
	}
	if getViaScope != get {
		t.Errorf("GET scope key = %q, want the original reflectKey %q", getViaScope, get)
	}
	formViaScope, err := reflectKeyForScope(u, domain, []string{"q"}, "", ReflectScopePostForm)
	if err != nil {
		t.Fatalf("reflectKeyForScope form: %v", err)
	}
	if formViaScope != form {
		t.Errorf("form scope key = %q, want the POST key %q", formViaScope, form)
	}
}

// TestReflectPOSTVerdictNeverServedForGET is the behavioral key-separation
// proof: a cached GET verdict never serves a POST probe (and vice versa) —
// each channel issues its own request on a cold channel cache.
func TestReflectPOSTVerdictNeverServedForGET(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	// GET echoes query values; POST bodies are answered static: a GET
	// verdict (unencoded) must never leak into the POST channel (absent).
	tr := &postReflectTransport{getMode: "echo", postMode: "silent"}
	getRep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr})
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	if got := reflectVerdictsByParam(t, getRep.Records[0])["q"]; got != ReflectUnencoded {
		t.Fatalf("GET verdict = %q, want %q", got, ReflectUnencoded)
	}
	postRep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr})
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	postRec := postRep.Records[0]
	if postRec.Cached {
		t.Fatal("POST served from cache after a GET-only run: channels share an entry")
	}
	if got := reflectVerdictsByParam(t, postRec)["q"]; got != ReflectAbsent {
		t.Errorf("POST verdict = %q, want %q (the GET verdict must never serve POST)", got, ReflectAbsent)
	}
	if postRec.Scope != ReflectScopePostForm {
		t.Errorf("POST scope = %q, want %q", postRec.Scope, ReflectScopePostForm)
	}
	if n := len(tr.posts()); n != 1 {
		t.Errorf("POST requests = %d, want 1 (a cold channel always probes)", n)
	}
	// And the reverse in a fresh cache: a cached POST verdict never
	// serves a GET probe.
	dir2 := t.TempDir()
	c2, err := cache.Open(dir2)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	tr2 := &postReflectTransport{getMode: "silent", postMode: "echo"}
	postSeed, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: tr2})
	if err != nil {
		t.Fatalf("seed ReflectPOSTURLs: %v", err)
	}
	if got := reflectVerdictsByParam(t, postSeed.Records[0])["q"]; got != ReflectUnencoded {
		t.Fatalf("seed POST verdict = %q, want %q", got, ReflectUnencoded)
	}
	getRep2, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: tr2})
	if err != nil {
		t.Fatalf("second ReflectURLs: %v", err)
	}
	if getRep2.Records[0].Cached {
		t.Fatal("GET served from cache: the POST entry leaked into the GET channel")
	}
	if got := reflectVerdictsByParam(t, getRep2.Records[0])["q"]; got != ReflectAbsent {
		t.Errorf("GET verdict = %q, want %q (the POST verdict must never serve GET)", got, ReflectAbsent)
	}
}

// TestReflectPOSTCacheHit pins warm-run parity: the second POST run is
// served without a request, verdicts and scope identical.
func TestReflectPOSTCacheHit(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &postReflectTransport{postMode: "echo"}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr}
	r1, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg)
	if err != nil {
		t.Fatalf("first ReflectPOSTURLs: %v", err)
	}
	if r1.Records[0].Cached {
		t.Fatal("first run must not be cached")
	}
	if len(tr.requests()) != 1 {
		t.Fatalf("first run requests = %d, want 1", len(tr.requests()))
	}
	cfg2 := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: &failingPostTransport{}}
	r2, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg2)
	if err != nil {
		t.Fatalf("second ReflectPOSTURLs: %v", err)
	}
	if !r2.Records[0].Cached {
		t.Fatal("second run must be served from cache")
	}
	if r2.Records[0].Scope != ReflectScopePostForm {
		t.Errorf("cached scope = %q, want %q", r2.Records[0].Scope, ReflectScopePostForm)
	}
	v1 := reflectVerdictsByParam(t, r1.Records[0])
	v2 := reflectVerdictsByParam(t, r2.Records[0])
	for p, want := range v1 {
		if v2[p] != want {
			t.Errorf("cached param %q verdict = %q, want %q", p, v2[p], want)
		}
	}
}

// failingPostTransport fails every request (warm-run proof).
type failingPostTransport struct{}

func (t *failingPostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("must not be called: cache hit expected")
}

// TestReflectPOSTTruncatedNeverServed pins truncation honesty for POST:
// an over-cap body without an observed canary verdicts unknown with the
// Truncated flag, is stored incomplete, and never serves a later run.
func TestReflectPOSTTruncatedNeverServed(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	big := strings.Repeat("x", reflectMaxBodyBytes+1024)
	tr := &countingPostTransport{body: big, status: 200}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr}
	r1, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg)
	if err != nil {
		t.Fatalf("first ReflectPOSTURLs: %v", err)
	}
	rec := r1.Records[0]
	if !rec.Truncated {
		t.Fatal("Truncated = false, want true for an over-cap body")
	}
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnknown {
		t.Fatalf("param q verdict = %q, want %q (absence under truncation proves nothing)", got, ReflectUnknown)
	}
	if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg); err != nil {
		t.Fatalf("second ReflectPOSTURLs: %v", err)
	}
	if tr.count() != 2 {
		t.Fatalf("requests = %d, want 2 (truncated records are stored incomplete, never served)", tr.count())
	}
}

// countingPostTransport serves one fixed body to every request.
type countingPostTransport struct {
	mu     sync.Mutex
	n      int
	body   string
	status int
}

func (t *countingPostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
	if req.Method != http.MethodPost {
		return nil, errors.New("want POST only")
	}
	return reflectTestResponse(t.status, t.body), nil
}

func (t *countingPostTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// TestReflectPOSTUnknownOnError pins fail-open unknown with the transport
// cause retained, and that failed probes never serve later runs.
func TestReflectPOSTUnknownOnError(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: &failingPostTransport{}}
	r1, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg)
	if err != nil {
		t.Fatalf("first ReflectPOSTURLs: %v", err)
	}
	rec := r1.Records[0]
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnknown {
		t.Errorf("param q verdict = %q, want %q on transport error", got, ReflectUnknown)
	}
	if rec.Err == nil {
		t.Error("record Err = nil, want the transport cause")
	}
	if _, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, cfg); err != nil {
		t.Fatalf("second ReflectPOSTURLs: %v", err)
	}
	// Failed probes are stored failed (never served): a later run with an
	// echoing transport must still probe and decide.
	tr := &postReflectTransport{postMode: "echo"}
	r3, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr})
	if err != nil {
		t.Fatalf("third ReflectPOSTURLs: %v", err)
	}
	if r3.Records[0].Cached {
		t.Fatal("failed probe served from cache: failures must never serve")
	}
	if got := reflectVerdictsByParam(t, r3.Records[0])["q"]; got != ReflectUnencoded {
		t.Errorf("param q verdict = %q, want %q after re-probe", got, ReflectUnencoded)
	}
}

// TestReflectPOSTRedirectObservedNeverFollowed pins that a 3xx POST
// response is observed (status kept, body verdict-ed) with exactly one
// request — redirects are never followed on POST either.
func TestReflectPOSTRedirectObservedNeverFollowed(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &redirectPostTransport{}
	rep, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostJSON, Config{Concurrency: 1, QueueSize: 4, Transport: tr})
	if err != nil {
		t.Fatalf("ReflectPOSTURLs: %v", err)
	}
	rec := rep.Records[0]
	if rec.Err != nil {
		t.Fatalf("record err = %v, want nil (a 3xx is an observed response)", rec.Err)
	}
	if rec.Status != 302 {
		t.Errorf("status = %d, want 302 (observed, never followed)", rec.Status)
	}
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectAbsent {
		t.Errorf("param q verdict = %q, want %q (static 302 body)", got, ReflectAbsent)
	}
	if tr.count() != 1 {
		t.Errorf("requests = %d, want exactly 1 (never follow)", tr.count())
	}
	for _, r := range tr.requests() {
		if r.method != http.MethodPost {
			t.Errorf("request method = %q, want POST", r.method)
		}
	}
}

type redirectPostTransport struct {
	mu   sync.Mutex
	reqs []postObservedRequest
}

func (t *redirectPostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.reqs = append(t.reqs, postObservedRequest{method: req.Method, url: req.URL.String()})
	t.mu.Unlock()
	return &http.Response{
		StatusCode:    302,
		Header:        http.Header{"Location": []string{"http://example.com/other"}},
		Body:          io.NopCloser(strings.NewReader("<html>moved</html>")),
		ContentLength: -1,
	}, nil
}

func (t *redirectPostTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.reqs)
}

func (t *redirectPostTransport) requests() []postObservedRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]postObservedRequest(nil), t.reqs...)
}

// TestReflectPOSTEvidenceScopeContract pins the scoped evidence writer and
// its readers: POST evidence round-trips its scope, the GET-only reader
// refuses every POST record (triage gating flows exactly as before POST),
// and the scope reader reports every channel while refusing foreign
// records.
func TestReflectPOSTEvidenceScopeContract(t *testing.T) {
	src := mustReflectURL(t, "http://example.com/search?q=term").Identity()
	for _, scope := range []ReflectScope{ReflectScopePostForm, ReflectScopePostJSON} {
		ev, err := ReflectPostEvidence(src, "q", ReflectUnencoded, scope)
		if err != nil {
			t.Fatalf("ReflectPostEvidence(%s): %v", scope, err)
		}
		if got, ok := ReflectEvidenceScope(ev); !ok || got != scope {
			t.Errorf("ReflectEvidenceScope = %q/%v, want %q/true", got, ok, scope)
		}
		if _, _, ok := ParseReflectEvidence(ev); ok {
			t.Errorf("ParseReflectEvidence accepted a %s record (triage must never parse POST as query)", scope)
		}
	}
	// GET evidence keeps its channel and still parses as before.
	get, err := ReflectEvidence(src, "q", ReflectUnencoded)
	if err != nil {
		t.Fatalf("ReflectEvidence: %v", err)
	}
	if got, ok := ReflectEvidenceScope(get); !ok || got != ReflectScopeQueryGET {
		t.Errorf("ReflectEvidenceScope(GET) = %q/%v, want query-get-only/true", got, ok)
	}
	if param, v, ok := ParseReflectEvidence(get); !ok || param != "q" || v != ReflectUnencoded {
		t.Errorf("ParseReflectEvidence(GET) = %q/%q/%v, want q/unencoded/true", param, v, ok)
	}
	// Builders refuse unknown verdicts and non-body scopes.
	if _, err := ReflectPostEvidence(src, "q", ReflectUnknown, ReflectScopePostForm); err == nil {
		t.Error("ReflectPostEvidence accepted unknown (fail-open: unknown carries no evidence)")
	}
	for _, scope := range []ReflectScope{ReflectScopeQueryGET, "", "header-x"} {
		if _, err := ReflectPostEvidence(src, "q", ReflectUnencoded, scope); err == nil {
			t.Errorf("ReflectPostEvidence accepted scope %q, want rejection", scope)
		}
	}
	// Foreign records claim no scope.
	foreign, err := asset.NewEvidence(asset.MethodJS, "reflect-post-form:q", string(ReflectUnencoded), src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("foreign evidence: %v", err)
	}
	if _, ok := ReflectEvidenceScope(foreign); ok {
		t.Error("ReflectEvidenceScope accepted a foreign-method record")
	}
	bad, err := asset.NewEvidence(asset.MethodEndpoint, "reflect-post-form:q", "maybe", src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("bad evidence: %v", err)
	}
	if _, ok := ReflectEvidenceScope(bad); ok {
		t.Error("ReflectEvidenceScope accepted a non-vocabulary verdict value")
	}
	if _, _, ok := ParseReflectEvidence(bad); ok {
		t.Error("ParseReflectEvidence accepted a non-vocabulary verdict value")
	}
	// Unknown claims no scope on any channel: builders never emit it, and
	// a hand-crafted unknown must not gate or cite.
	for _, tc := range []struct {
		indicator string
		value     string
	}{
		{"reflect:q", string(ReflectUnknown)},
		{"reflect-post-form:q", string(ReflectUnknown)},
		{"reflect-post-json:q", string(ReflectUnknown)},
	} {
		unk, err := asset.NewEvidence(asset.MethodEndpoint, tc.indicator, tc.value, src, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("unknown evidence %q: %v", tc.indicator, err)
		}
		if got, ok := ReflectEvidenceScope(unk); ok {
			t.Errorf("ReflectEvidenceScope(%q unknown) = %q/true, want false (unknown carries no channel claim)", tc.indicator, got)
		}
	}
}

// TestReflectGETScopeStamped pins that GET records carry query-get-only:
// every verdict carries its channel, on GET exactly as on POST.
func TestReflectGETScopeStamped(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &postReflectTransport{getMode: "echo"}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, postFormConfig(tr))
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	if got := rep.Records[0].Scope; got != ReflectScopeQueryGET {
		t.Errorf("GET record scope = %q, want %q", got, ReflectScopeQueryGET)
	}
}

// errReadTransport serves one response whose body fails on read: the probe
// sees a received status but no complete body (partial prefix possible).
type errReadTransport struct {
	mu sync.Mutex
	n  int
}

func (t *errReadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
	return &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(errReader{err: errors.New("synthetic body read failure")}),
		ContentLength: -1,
	}, nil
}

func (t *errReadTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestReflectBodyReadErrorNeverServed pins that a body-read failure is
// truncated (stored incomplete, never served): a seeded read-error under
// cache re-probes on the next run instead of serving unknown.
func TestReflectBodyReadErrorNeverServed(t *testing.T) {
	// GET channel.
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	bad := &errReadTransport{}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: bad}
	r1, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("first ReflectURLs: %v", err)
	}
	rec := r1.Records[0]
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnknown {
		t.Fatalf("param q verdict = %q, want %q on read error", got, ReflectUnknown)
	}
	if !rec.Truncated {
		t.Fatal("Truncated = false, want true (a partial prefix may have arrived before the failure)")
	}
	if rec.Err == nil {
		t.Fatal("record Err = nil, want the read cause")
	}
	good := &reflectHandlerTransport{handle: echoRawHandler}
	r2, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: good})
	if err != nil {
		t.Fatalf("second ReflectURLs: %v", err)
	}
	if r2.Records[0].Cached {
		t.Fatal("read-error served from cache: truncated records must never serve")
	}
	if got := reflectVerdictsByParam(t, r2.Records[0])["q"]; got != ReflectUnencoded {
		t.Fatalf("param q verdict = %q, want %q after re-probe (no served-unknown)", got, ReflectUnencoded)
	}
	if bad.count()+good.count() != 2 {
		t.Fatalf("requests = %d, want 2 (read-error re-probes)", bad.count()+good.count())
	}
	// POST channel mirrors the GET honesty.
	dir2 := t.TempDir()
	c2, err := cache.Open(dir2)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	badPost := &errReadTransport{}
	rp1, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: badPost})
	if err != nil {
		t.Fatalf("first ReflectPOSTURLs: %v", err)
	}
	prec := rp1.Records[0]
	if got := reflectVerdictsByParam(t, prec)["q"]; got != ReflectUnknown {
		t.Fatalf("POST param q verdict = %q, want %q on read error", got, ReflectUnknown)
	}
	if !prec.Truncated {
		t.Fatal("POST Truncated = false, want true on read error")
	}
	echo := &postReflectTransport{postMode: "echo"}
	rp2, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: echo})
	if err != nil {
		t.Fatalf("second ReflectPOSTURLs: %v", err)
	}
	if rp2.Records[0].Cached {
		t.Fatal("POST read-error served from cache: truncated records must never serve")
	}
	if got := reflectVerdictsByParam(t, rp2.Records[0])["q"]; got != ReflectUnencoded {
		t.Fatalf("POST param q verdict = %q, want %q after re-probe", got, ReflectUnencoded)
	}
}

// TestReflectLegacyScopeLessServedAsGET pins that a scope-less stored entry
// (pre-scope layout) serves a GET lookup with zero requests as
// query-get-only, while a POST-scoped entry never serves a GET lookup.
func TestReflectLegacyScopeLessServedAsGET(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	// Seed a legacy scope-less completed entry under the GET key.
	legacy := storedReflect{
		Target:     u.String(),
		Params:     []string{"q"},
		Verdicts:   []ParamVerdict{{Param: "q", Verdict: ReflectUnencoded}},
		StatusCode: 200,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	key, err := reflectKey(u, domain, []string{"q"}, "")
	if err != nil {
		t.Fatalf("reflectKey: %v", err)
	}
	if err := c.Put(context.Background(), key, cache.Record{
		Operation: ReflectOperation,
		Target:    u.Identity().String(),
		Status:    cache.StatusCompleted,
		Meta:      map[string]string{"scheme": u.Scheme},
		Data:      data,
	}); err != nil {
		t.Fatalf("Put legacy: %v", err)
	}
	cold := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("must not be called: legacy hit expected")
	}}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: cold})
	if err != nil {
		t.Fatalf("ReflectURLs legacy: %v", err)
	}
	rec := rep.Records[0]
	if !rec.Cached {
		t.Fatal("legacy scope-less entry missed: want a zero-request Cached hit")
	}
	if rec.Scope != ReflectScopeQueryGET {
		t.Errorf("legacy scope = %q, want %q (scope-less normalizes to the lookup scope)", rec.Scope, ReflectScopeQueryGET)
	}
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnencoded {
		t.Errorf("legacy verdict = %q, want %q", got, ReflectUnencoded)
	}
	if cold.count() != 0 {
		t.Errorf("requests = %d, want 0 (legacy hit issues no request)", cold.count())
	}
	// A POST-scoped entry never serves a GET lookup: seed POST, then GET
	// must re-probe.
	dir2 := t.TempDir()
	c2, err := cache.Open(dir2)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	seedTR := &postReflectTransport{getMode: "silent", postMode: "echo"}
	seed, err := ReflectPOSTURLs(context.Background(), domain, []asset.URL{u}, ReflectScopePostForm, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: seedTR})
	if err != nil {
		t.Fatalf("seed ReflectPOSTURLs: %v", err)
	}
	if got := reflectVerdictsByParam(t, seed.Records[0])["q"]; got != ReflectUnencoded {
		t.Fatalf("seed POST verdict = %q, want %q", got, ReflectUnencoded)
	}
	probe := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return reflectTestResponse(200, "<html><body>static page, no echo</body></html>"), nil
	}}
	got, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, Config{Concurrency: 1, QueueSize: 4, Cache: c2, Transport: probe})
	if err != nil {
		t.Fatalf("ReflectURLs after POST seed: %v", err)
	}
	if got.Records[0].Cached {
		t.Fatal("GET served from a POST-scoped entry: channels must never share")
	}
	if probe.count() != 1 {
		t.Errorf("GET requests = %d, want 1 (POST entry misses GET lookup, re-probe)", probe.count())
	}
	if v := reflectVerdictsByParam(t, got.Records[0])["q"]; v != ReflectAbsent {
		t.Errorf("GET verdict = %q, want %q (static body, not the POST verdict)", v, ReflectAbsent)
	}
}
