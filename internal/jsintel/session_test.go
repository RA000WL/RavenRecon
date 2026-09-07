package jsintel

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Session-header tests (NEW-125): operator headers ride same-host
// requests, strip on cross-host hops, never leak into errors/records,
// and bind cache keys by digest (never values).

// captureTransport records request headers per URL and answers through
// a handler, never dialing.
type captureTransport struct {
	mu     sync.Mutex
	got    map[string]http.Header
	handle func(req *http.Request) (*http.Response, error)
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.got == nil {
		t.got = make(map[string]http.Header)
	}
	cp := make(http.Header, len(req.Header))
	for k, vs := range req.Header {
		cp[k] = append([]string(nil), vs...)
	}
	t.got[req.URL.String()] = cp
	t.mu.Unlock()
	return t.handle(req)
}

func (t *captureTransport) headerFor(url string) http.Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.got[url]
}

func jsOK(body string) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/javascript"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}
}

func sessionTestHeaders() FetchConfig {
	cfg := testFetchConfig()
	cfg.RequestHeaders = http.Header{"Cookie": []string{"session=synthetic-abc123"}}
	return cfg
}

func TestNormalizeRequestHeadersJS(t *testing.T) {
	got, digest, err := normalizeRequestHeaders(http.Header{
		"x-custom": {"b"},
		"Cookie":   {"session=one"},
		"cookie":   {"session=two"},
	})
	if err != nil {
		t.Fatalf("normalizeRequestHeaders: %v", err)
	}
	if len(got) != 2 || len(got["Cookie"]) != 2 {
		t.Fatalf("normalized = %v, want canonical merged keys", got)
	}
	if digest == "" {
		t.Fatal("digest empty for non-empty headers")
	}
	for name, h := range map[string]http.Header{
		"empty map":      {},
		"bad token":      {"Bad Name": {"v"}},
		"host header":    {"Host": {"evil.example.com"}},
		"empty value":    {"X-Token": {""}},
		"control value":  {"X-Token": {"a\x7fb"}},
		"overlong name":  {strings.Repeat("n", 257): {"v"}},
		"overlong value": {"X-Token": {strings.Repeat("v", 8193)}},
		"over-count":     overCountSessionHeaders(),
	} {
		if _, _, err := normalizeRequestHeaders(h); err == nil {
			t.Errorf("normalizeRequestHeaders accepted %s", name)
		}
	}
}

func overCountSessionHeaders() http.Header {
	h := make(http.Header)
	for i := 0; i < maxSessionHeaderCount+1; i++ {
		h["X-Over-"+strings.Repeat("a", 8)+"-"+string(rune('0'+i/100))+string(rune('0'+i/10%10))+string(rune('0'+i%10))] = []string{"v"}
	}
	return h
}

func TestSessionDigestJS(t *testing.T) {
	a := http.Header{"Cookie": {"session=one"}, "X-T": {"v"}}
	b := http.Header{"X-T": {"v"}, "Cookie": {"session=one"}}
	if sessionDigest(a) != sessionDigest(b) {
		t.Fatal("digest order-dependent (must be order-independent)")
	}
	c := http.Header{"Cookie": {"session=two"}, "X-T": {"v"}}
	if sessionDigest(c) == sessionDigest(a) {
		t.Fatal("digest unchanged for different values (keys would collide across sessions)")
	}
	if sessionDigest(nil) != "" {
		t.Fatal("empty digest must be empty (anonymous keys byte-identical)")
	}
}

func TestFetchSendsSessionHeaders(t *testing.T) {
	tr := &captureTransport{handle: jsOK("var a = 1;\n")}
	cfg := sessionTestHeaders()
	cfg.Transport = tr

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://js.test/app.js"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	if got := tr.headerFor("http://js.test/app.js").Get("Cookie"); got != "session=synthetic-abc123" {
		t.Errorf("Cookie = %q, want the session value", got)
	}
}

func TestFetchSessionRedirectStripsCrossHost(t *testing.T) {
	// /start 302s cross-host (in-domain sibling): the hop is followed
	// (public stub resolution) but must NOT inherit the session.
	tr := &captureTransport{handle: func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/start" {
			h := http.Header{"Content-Type": []string{"text/plain"}}
			h.Set("Location", "http://cdn.js.test/final.js")
			return &http.Response{StatusCode: 302, Header: h,
				Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		return jsOK("var a = 1;\n")(req)
	}}
	cfg := sessionTestHeaders()
	cfg.Transport = tr
	cfg.ResolveIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://js.test/start"))
	if res.Redirects != 1 {
		t.Fatalf("redirects = %d, want 1 (hop followed, session stripped)", res.Redirects)
	}
	var startCookies, finalCookies string
	for url, h := range tr.got {
		if strings.HasSuffix(url, "/start") {
			startCookies = h.Get("Cookie")
		} else {
			finalCookies = h.Get("Cookie")
		}
	}
	if startCookies == "" {
		t.Error("origin hop missing session Cookie")
	}
	if finalCookies != "" {
		t.Errorf("cross-host hop carries Cookie %q (credential leak across hosts)", finalCookies)
	}
}

func TestFetchSessionKeySeparation(t *testing.T) {
	u := mustURL(t, "http://example.com/app.js")
	kAnon, err := fetchKey(u, "")
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	kAuth, err := fetchKey(u, "digest-abc")
	if err != nil {
		t.Fatalf("fetchKey session: %v", err)
	}
	if kAnon == kAuth {
		t.Fatal("session fetch key equals anonymous key")
	}
	aAnon, err := analyzeKey(u, "")
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	aAuth, err := analyzeKey(u, "digest-abc")
	if err != nil {
		t.Fatalf("analyzeKey session: %v", err)
	}
	if aAnon == aAuth {
		t.Fatal("session analyze key equals anonymous key")
	}
}

func TestEngineSessionCacheSeparation(t *testing.T) {
	body := "var a = 1;\n"
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(body))
	})
	counting := countingRT{inner: transportFor(t, srv.srv)}
	shared := openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: srv.url() + "/app.js"}}
	mkcfg := func(authed bool) Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Transport = &counting
		cfg.Cache = shared
		if authed {
			cfg.RequestHeaders = http.Header{"Cookie": []string{"session=synthetic-abc123"}}
		}
		return cfg
	}
	runEngine(t, mkcfg(false), items)
	runEngine(t, mkcfg(true), items)
	if counting.calls() != 2 {
		t.Fatalf("round trips = %d, want 2 (anon + authed cold, distinct keys)", counting.calls())
	}
	runEngine(t, mkcfg(true), items)
	if counting.calls() != 2 {
		t.Fatalf("round trips = %d, want 2 (warm authed hit, zero network)", counting.calls())
	}
}

func TestEngineInvalidSessionHeadersRejected(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("var a = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.RequestHeaders = http.Header{"Bad Name": {"v"}}
	before := srv.count()
	if err := RunInto(context.Background(), cfg, SliceSource([]Item{{Kind: ItemLine, Line: srv.url() + "/app.js"}}), NewAccumulator(cfg)); err == nil {
		t.Fatal("RunInto accepted invalid session headers (want whole-run rejection)")
	}
	if srv.count() != before {
		t.Fatalf("requests served = %d, want none (rejected before the pool)", srv.count()-before)
	}
}

// TestNormalizeRejectsFramingHeadersJS pins F4 (review wave 2026-09):
// framing headers and User-Agent must never arrive via session headers.
func TestNormalizeRejectsFramingHeadersJS(t *testing.T) {
	for _, name := range []string{
		"Content-Length", "Transfer-Encoding", "Connection", "User-Agent",
		"content-length", "transfer-encoding", "connection", "user-agent",
		"HOST",
	} {
		if _, _, err := normalizeRequestHeaders(http.Header{name: {"synthetic-value"}}); err == nil {
			t.Errorf("normalizeRequestHeaders accepted %q (want fail-closed rejection)", name)
		}
	}
}

// TestNormalizeRejectsManyValuesJS pins F6 (review wave 2026-09): a
// single key carrying 65 values exceeds the total-values bound.
func TestNormalizeRejectsManyValuesJS(t *testing.T) {
	vs := make([]string, 0, maxSessionHeaderValues+1)
	for i := 0; i < maxSessionHeaderValues+1; i++ {
		vs = append(vs, "synthetic-value")
	}
	if _, _, err := normalizeRequestHeaders(http.Header{"X-Multi": vs}); err == nil {
		t.Fatalf("normalizeRequestHeaders accepted %d values on one key (bound %d)",
			maxSessionHeaderValues+1, maxSessionHeaderValues)
	}
}

// TestFetchRejectsInvalidSessionHeaders pins F5 (review wave 2026-09):
// direct Fetch validates session headers at entry and fails without
// dispatching — a Host override or control bytes never reach the wire.
func TestFetchRejectsInvalidSessionHeaders(t *testing.T) {
	for name, headers := range map[string]http.Header{
		"host header":   {"Host": {"evil.example.com"}},
		"control bytes": {"X-Token": {"a\x01b"}},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &captureTransport{handle: jsOK("var a = 1;\n")}
			cfg := testFetchConfig()
			cfg.Transport = tr
			cfg.RequestHeaders = headers
			res := Fetch(context.Background(), cfg, mustURL(t, "http://js.test/app.js"))
			if res.Status != FetchFailed {
				t.Fatalf("status = %s, want failed (invalid session headers)", res.Status)
			}
			tr.mu.Lock()
			n := len(tr.got)
			tr.mu.Unlock()
			if n != 0 {
				t.Fatalf("dispatches = %d, want 0 (rejected before dispatch)", n)
			}
		})
	}
}
