package httpprobe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// reflectHandlerTransport is a hermetic RoundTripper for reflection tests:
// it records every request URL and answers through a handler, never dialing.
type reflectHandlerTransport struct {
	mu       sync.Mutex
	requests []string
	handle   func(req *http.Request) (*http.Response, error)
}

func (t *reflectHandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, req.URL.String())
	t.mu.Unlock()
	return t.handle(req)
}

func (t *reflectHandlerTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

func reflectTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// echoRawHandler reflects every decoded query value raw into the body.
func echoRawHandler(req *http.Request) (*http.Response, error) {
	q, _ := url.ParseQuery(req.URL.RawQuery)
	var vals []string
	for _, vs := range q {
		vals = append(vals, vs...)
	}
	return reflectTestResponse(200, "<html><body>\n"+strings.Join(vals, "\n")+"\n</body></html>"), nil
}

// echoEncodedHandler reflects every value percent-encoded into the body.
func echoEncodedHandler(req *http.Request) (*http.Response, error) {
	q, _ := url.ParseQuery(req.URL.RawQuery)
	var vals []string
	for _, vs := range q {
		for _, v := range vs {
			vals = append(vals, url.QueryEscape(v))
		}
	}
	return reflectTestResponse(200, "<html><body>\n"+strings.Join(vals, "\n")+"\n</body></html>"), nil
}

func mustReflectURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL %q: %v", raw, err)
	}
	return u
}

func reflectVerdictsByParam(t testing.TB, rec ReflectRecord) map[string]ReflectVerdict {
	t.Helper()
	out := make(map[string]ReflectVerdict, len(rec.Verdicts))
	for _, pv := range rec.Verdicts {
		out[pv.Param] = pv.Verdict
	}
	return out
}

func TestReflectCanaryShape(t *testing.T) {
	a := reflectCanary("url:http://example.com/?q=1", "q")
	b := reflectCanary("url:http://example.com/?q=1", "q")
	if a != b {
		t.Fatalf("canary not deterministic: %q vs %q", a, b)
	}
	if reflectCanary("url:http://example.com/?q=1", "q") == reflectCanary("url:http://example.com/?q=1", "id") {
		t.Fatal("canary must differ per param")
	}
	if reflectCanary("url:http://example.com/?q=1", "q") == reflectCanary("url:http://example.com/?id=1", "q") {
		t.Fatal("canary must differ per URL")
	}
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '~' || r == ':') {
			t.Fatalf("canary %q contains non-URL-safe rune %q", a, r)
		}
	}
	if strings.ContainsAny(a, "&=?# ") {
		t.Fatalf("canary %q contains a query-breaking character", a)
	}
	if url.QueryEscape(a) == a {
		t.Fatalf("canary %q has no encodable character: encoded reflection would be indistinguishable", a)
	}
}

func TestReflectURLsReflectedUnencoded(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2&lang=en")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	if len(rep.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(rep.Records))
	}
	rec := rep.Records[0]
	if rec.Err != nil {
		t.Fatalf("record err = %v, want nil", rec.Err)
	}
	got := reflectVerdictsByParam(t, rec)
	for _, p := range []string{"q", "page", "lang"} {
		if got[p] != ReflectUnencoded {
			t.Errorf("param %q verdict = %q, want %q", p, got[p], ReflectUnencoded)
		}
	}
	if tr.count() != 1 {
		t.Errorf("requests = %d, want 1 (all params substituted in a single GET)", tr.count())
	}
	if rec.Status != 200 {
		t.Errorf("status = %d, want 200", rec.Status)
	}
}

func TestReflectURLsReflectedEncoded(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &reflectHandlerTransport{handle: echoEncodedHandler}
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	got := reflectVerdictsByParam(t, rep.Records[0])
	for _, p := range []string{"q", "page"} {
		if got[p] != ReflectEncoded {
			t.Errorf("param %q verdict = %q, want %q", p, got[p], ReflectEncoded)
		}
	}
}

func TestReflectURLsReflectedEncodedLowercaseHex(t *testing.T) {
	// Encoded search is case-insensitive on the percent-hex: a handler
	// emitting lowercase %3a must still verdict reflected-encoded.
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		q, _ := url.ParseQuery(req.URL.RawQuery)
		var vals []string
		for _, vs := range q {
			for _, v := range vs {
				vals = append(vals, strings.ToLower(url.QueryEscape(v)))
			}
		}
		return reflectTestResponse(200, "<html><body>\n"+strings.Join(vals, "\n")+"\n</body></html>"), nil
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	if got := reflectVerdictsByParam(t, rep.Records[0])["q"]; got != ReflectEncoded {
		t.Fatalf("param q verdict = %q, want %q (lowercase percent-hex)", got, ReflectEncoded)
	}
}

func TestReflectURLsBareParamSkipped(t *testing.T) {
	// A bare "?q" (no "=") is never targeted: it counts Skipped at
	// extraction and never verdicts not-reflected (a false-absent would
	// violate §0.6 — the canary was never sent).
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	rec := rep.Records[0]
	if rec.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (bare ?q is never targeted)", rec.Skipped)
	}
	if len(rec.Verdicts) != 0 {
		t.Fatalf("verdicts = %v, want none (bare ?q is never verdict-ed)", rec.Verdicts)
	}
	if got := reflectVerdictsByParam(t, rec)["q"]; got != "" {
		t.Fatalf("param q verdict = %q, want absent (never targeted, never not-reflected)", got)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0 (nothing targeted, nothing probed)", tr.count())
	}
}

func TestReflectURLsNotReflected(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return reflectTestResponse(200, "<html><body>static page, no echo</body></html>"), nil
	}}
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	got := reflectVerdictsByParam(t, rep.Records[0])
	for _, p := range []string{"q", "page"} {
		if got[p] != ReflectAbsent {
			t.Errorf("param %q verdict = %q, want %q", p, got[p], ReflectAbsent)
		}
	}
	if rep.Records[0].Truncated {
		t.Error("Truncated = true, want false for a fully-read body")
	}
}

func TestReflectURLsUnknownOnTimeout(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	block := make(chan struct{})
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		select {
		case <-block:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return reflectTestResponse(200, "late"), nil
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr, RequestTimeout: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rep, err := ReflectURLs(ctx, domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	got := reflectVerdictsByParam(t, rep.Records[0])
	if got["q"] != ReflectUnknown {
		t.Errorf("param q verdict = %q, want %q on timeout", got["q"], ReflectUnknown)
	}
	if rep.Records[0].Err == nil {
		t.Error("record Err = nil, want the timeout cause")
	}
	close(block)
}

func TestReflectURLsUnknownOnTruncation(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	big := strings.Repeat("x", reflectMaxBodyBytes+1024)
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return reflectTestResponse(200, big), nil
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	rec := rep.Records[0]
	if !rec.Truncated {
		t.Fatal("Truncated = false, want true for an over-cap body")
	}
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnknown {
		t.Errorf("param q verdict = %q, want %q (absence under truncation proves nothing)", got, ReflectUnknown)
	}
}

func TestReflectURLsReflectedDespiteTruncation(t *testing.T) {
	// Found is found: a canary observed before the cap is a solid reflected
	// verdict even though the record carries the honest truncation flag.
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	canary := reflectCanary(u.Identity().String(), "q")
	body := "prefix " + canary + " " + strings.Repeat("y", reflectMaxBodyBytes+1024)
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return reflectTestResponse(200, body), nil
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	rec := rep.Records[0]
	if got := reflectVerdictsByParam(t, rec)["q"]; got != ReflectUnencoded {
		t.Errorf("param q verdict = %q, want %q (canary observed before the cap)", got, ReflectUnencoded)
	}
	if !rec.Truncated {
		t.Error("Truncated = false, want true (the body still exceeded the cap)")
	}
}

func TestReflectURLsCacheHit(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term&page=2")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 2, QueueSize: 4, Cache: c, Transport: tr}
	r1, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("first ReflectURLs: %v", err)
	}
	if r1.Records[0].Cached {
		t.Fatal("first run must not be cached")
	}
	if tr.count() != 1 {
		t.Fatalf("first run requests = %d, want 1", tr.count())
	}
	tr2 := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("must not be called: cache hit expected")
	}}
	cfg2 := Config{Concurrency: 2, QueueSize: 4, Cache: c, Transport: tr2}
	r2, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg2)
	if err != nil {
		t.Fatalf("second ReflectURLs: %v", err)
	}
	if !r2.Records[0].Cached {
		t.Fatal("second run must be served from cache")
	}
	if tr2.count() != 0 {
		t.Fatalf("second run requests = %d, want 0", tr2.count())
	}
	v1 := reflectVerdictsByParam(t, r1.Records[0])
	v2 := reflectVerdictsByParam(t, r2.Records[0])
	if len(v1) != len(v2) {
		t.Fatalf("cached verdicts = %v, want %v", v2, v1)
	}
	for p, want := range v1 {
		if v2[p] != want {
			t.Errorf("cached param %q verdict = %q, want %q", p, v2[p], want)
		}
	}
}

func TestReflectURLsTruncatedNeverServed(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	big := strings.Repeat("x", reflectMaxBodyBytes+1024)
	tr := &reflectHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return reflectTestResponse(200, big), nil
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr}
	if _, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg); err != nil {
		t.Fatalf("first ReflectURLs: %v", err)
	}
	if _, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg); err != nil {
		t.Fatalf("second ReflectURLs: %v", err)
	}
	if tr.count() != 2 {
		t.Fatalf("requests = %d, want 2 (truncated records are stored incomplete, never served)", tr.count())
	}
}

func TestReflectURLsScopeRejectsOutOfDomain(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://evil.com/search?q=term")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	if _, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg); err == nil {
		t.Fatal("out-of-domain URL accepted, want rejection before any request")
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0", tr.count())
	}
}

func TestReflectURLsNoParams(t *testing.T) {
	// A URL without a query string has nothing to reflect: completed with
	// zero verdicts and zero network requests.
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/about")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	if len(rep.Records) != 1 || len(rep.Records[0].Verdicts) != 0 {
		t.Fatalf("records = %+v, want one empty verdict set", rep.Records)
	}
	if rep.Records[0].Err != nil {
		t.Fatalf("record err = %v, want nil", rep.Records[0].Err)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0", tr.count())
	}
}

func TestReflectURLsParamCapHonest(t *testing.T) {
	// More params than maxReflectParams: the sorted head is probed, the
	// remainder is counted Skipped — never silently dropped.
	domain := mustDomainProbe(t, "example.com")
	var q strings.Builder
	for i := 0; i < maxReflectParams+5; i++ {
		if i > 0 {
			q.WriteByte('&')
		}
		q.WriteString("p" + padReflect(i) + "=v")
	}
	u := mustReflectURL(t, "http://example.com/search?"+q.String())
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	rep, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ReflectURLs: %v", err)
	}
	rec := rep.Records[0]
	if len(rec.Verdicts) != maxReflectParams {
		t.Fatalf("verdicts = %d, want %d (capped head)", len(rec.Verdicts), maxReflectParams)
	}
	if rec.Skipped != 5 {
		t.Fatalf("skipped = %d, want 5 (the cut tail, honestly counted)", rec.Skipped)
	}
}

func padReflect(i int) string {
	return string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

func TestReflectEvidenceContract(t *testing.T) {
	// The writer (urllive adapter) → reader (triage pack) contract:
	// MethodEndpoint + "reflect:<param>" indicator + verdict value +
	// URL-identity source, round-tripping through ParseReflectEvidence.
	src := mustReflectURL(t, "http://example.com/search?q=term").Identity()
	ev, err := ReflectEvidence(src, "q", ReflectUnencoded)
	if err != nil {
		t.Fatalf("ReflectEvidence: %v", err)
	}
	param, verdict, ok := ParseReflectEvidence(ev)
	if !ok {
		t.Fatalf("ParseReflectEvidence refused its own contract record: %+v", ev)
	}
	if param != "q" || verdict != ReflectUnencoded {
		t.Errorf("parsed = %q/%q, want q/reflected-unencoded", param, verdict)
	}
	// Foreign methods and indicators must not parse (no cross-talk with
	// technology/secret evidence sharing the snapshot channel).
	other, err := asset.NewEvidence(asset.MethodJS, "reflect:q", string(ReflectUnencoded), src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if _, _, ok := ParseReflectEvidence(other); ok {
		t.Error("ParseReflectEvidence accepted a non-endpoint method record")
	}
	plain, err := asset.NewEvidence(asset.MethodEndpoint, "header:server", "nginx", src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if _, _, ok := ParseReflectEvidence(plain); ok {
		t.Error("ParseReflectEvidence accepted a non-reflect indicator")
	}
	bad, err := asset.NewEvidence(asset.MethodEndpoint, "reflect:q", "maybe", src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if _, _, ok := ParseReflectEvidence(bad); ok {
		t.Error("ParseReflectEvidence accepted a non-vocabulary verdict value")
	}
}

func TestReflectURLsTamperedEnvelopeSelfHeals(t *testing.T) {
	// A completed record stored under this key with a mismatched operation
	// or target is deleted and re-executed, never served.
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustReflectURL(t, "http://example.com/search?q=term")
	tr := &reflectHandlerTransport{handle: echoRawHandler}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr}
	if _, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg); err != nil {
		t.Fatalf("seed ReflectURLs: %v", err)
	}
	if tr.count() != 1 {
		t.Fatalf("seed requests = %d, want 1", tr.count())
	}
	key, err := reflectKey(u, domain, []string{"q"}, "")
	if err != nil {
		t.Fatalf("reflectKey: %v", err)
	}
	out := c.Get(context.Background(), key)
	if !out.IsHit() || out.Record == nil {
		t.Fatal("seed record missing: want a completed hit to tamper")
	}
	tampered := *out.Record
	tampered.Operation = "tampered.operation"
	tampered.Target = "domain:evil.example"
	if err := c.Put(context.Background(), key, tampered); err != nil {
		t.Fatalf("tamper Put: %v", err)
	}
	if _, err := ReflectURLs(context.Background(), domain, []asset.URL{u}, cfg); err != nil {
		t.Fatalf("re-run after tamper: %v", err)
	}
	if tr.count() != 2 {
		t.Fatalf("requests = %d, want 2 (tampered envelope must re-execute)", tr.count())
	}
}
