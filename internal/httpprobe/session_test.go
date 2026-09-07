package httpprobe

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Session-header tests (NEW-125): operator-supplied headers ride
// in-scope requests, never leak into logs/errors/records, and bind
// cache keys by digest (never values).

// headerCaptureTransport records request headers per URL and answers
// canned statuses.
type headerCaptureTransport struct {
	mu      sync.Mutex
	got     map[string]http.Header
	status  map[string]int
	loc     map[string]string
	n       int
	failAll bool
}

func (t *headerCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.got == nil {
		t.got = make(map[string]http.Header)
	}
	cp := make(http.Header, len(req.Header))
	for k, vs := range req.Header {
		cp[k] = append([]string(nil), vs...)
	}
	t.got[req.URL.String()] = cp
	t.n++
	t.mu.Unlock()
	if t.failAll {
		return nil, errors.New("synthetic transport failure")
	}
	status := 200
	if s, ok := t.status[req.URL.String()]; ok {
		status = s
	}
	h := http.Header{"Content-Type": []string{"text/plain"}}
	if loc, ok := t.loc[req.URL.String()]; ok {
		h.Set("Location", loc)
		status = 302
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func (t *headerCaptureTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

func (t *headerCaptureTransport) headerFor(url string) http.Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.got[url]
}

func sessionTestHeaders(t testing.TB) Config {
	t.Helper()
	cfg := testConfig()
	cfg.RequestHeaders = http.Header{"Cookie": []string{"session=synthetic-abc123"}}
	return cfg
}

func TestNormalizeRequestHeaders(t *testing.T) {
	// Lowercase canonicalizes; duplicates merge in sorted order.
	got, digest, err := normalizeRequestHeaders(http.Header{
		"x-custom": {"b"},
		"Cookie":   {"session=one"},
		"cookie":   {"session=two"},
	})
	if err != nil {
		t.Fatalf("normalizeRequestHeaders: %v", err)
	}
	if len(got) != 2 || len(got["Cookie"]) != 2 || got["Cookie"][0] != "session=one" || got["Cookie"][1] != "session=two" {
		t.Fatalf("normalized = %v, want canonical keys with file-order values", got)
	}
	if digest == "" {
		t.Fatal("digest empty for non-empty headers")
	}
	for name, h := range map[string]http.Header{
		"empty map":      {},
		"bad token":      {"Bad Name": {"v"}},
		"host header":    {"Host": {"evil.example.com"}},
		"host lowercase": {"host": {"evil.example.com"}},
		"empty value":    {"X-Token": {""}},
		"control value":  {"X-Token": {"a\x7fb"}},
		"overlong name":  {strings.Repeat("n", 257): {"v"}},
		"overlong value": {"X-Token": {strings.Repeat("v", 8193)}},
		"over-count":     overCountHeaders(),
	} {
		if _, _, err := normalizeRequestHeaders(h); err == nil {
			t.Errorf("normalizeRequestHeaders accepted %s", name)
		}
	}
}

func overCountHeaders() http.Header {
	h := make(http.Header)
	for i := 0; i < maxSessionHeaderCount+1; i++ {
		h["X-Over-"+strings.Repeat("a", 8)+"-"+strings.Repeat("b", 4)+"-"+string(rune('0'+i/100))+string(rune('0'+i/10%10))+string(rune('0'+i%10))] = []string{"v"}
	}
	return h
}

func TestSessionDigestHTTP(t *testing.T) {
	a := http.Header{"Cookie": {"session=one"}, "X-T": {"v"}}
	b := http.Header{"X-T": {"v"}, "Cookie": {"session=one"}}
	if sessionDigest(a) != sessionDigest(b) {
		t.Fatal("digest order-dependent (must be order-independent)")
	}
	c := http.Header{"Cookie": {"session=two"}, "X-T": {"v"}}
	if sessionDigest(c) == sessionDigest(a) {
		t.Fatal("digest unchanged for different values (keys would collide across sessions)")
	}
	if sessionDigest(nil) != "" || sessionDigest(http.Header{}) != "" {
		t.Fatal("empty digest must be empty (anonymous keys byte-identical)")
	}
}

func TestProbeSendsSessionHeaders(t *testing.T) {
	tr := &headerCaptureTransport{status: map[string]int{"http://www.example.com/": 200}}
	cfg := sessionTestHeaders(t)
	cfg.Transport = tr
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	if got := tr.headerFor("http://www.example.com/").Get("Cookie"); got != "session=synthetic-abc123" {
		t.Errorf("Cookie on root probe = %q, want the session value", got)
	}
	if got := tr.headerFor("https://www.example.com/").Get("Cookie"); got != "session=synthetic-abc123" {
		t.Errorf("Cookie on https probe = %q, want the session value", got)
	}
}

func TestProbeSessionRedirectStripsCrossHost(t *testing.T) {
	// a.example.com 302s to in-scope b.example.com: the hop is
	// followed (in-domain) but must NOT inherit the session.
	tr := &headerCaptureTransport{
		status: map[string]int{"http://b.example.com/": 200},
		loc:    map[string]string{"http://a.example.com/": "http://b.example.com/"},
	}
	cfg := sessionTestHeaders(t)
	cfg.Transport = tr
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "a.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "a.example.com")
	httpPr := probeResultFor(hr, "http")
	if httpPr.StatusCode != 200 || len(httpPr.RedirectChain) != 1 {
		t.Fatalf("http probe = %+v, want followed 302 to b", httpPr)
	}
	if got := tr.headerFor("http://a.example.com/").Get("Cookie"); got == "" {
		t.Error("origin hop missing session Cookie")
	}
	if got := tr.headerFor("http://b.example.com/").Get("Cookie"); got != "" {
		t.Errorf("cross-host hop carries Cookie %q (credential leak across hosts)", got)
	}
}

func TestProbeSessionCacheSeparation(t *testing.T) {
	c := openTestCache(t, func() time.Time { return fixedTime }, 0)
	tr := &headerCaptureTransport{status: map[string]int{"http://www.example.com/": 200}}
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	anon := testConfig()
	anon.Transport = tr
	anon.Cache = c
	if _, err := Probe(context.Background(), domain, hosts, nil, anon); err != nil {
		t.Fatalf("anon Probe: %v", err)
	}
	authed := sessionTestHeaders(t)
	authed.Transport = tr
	authed.Cache = c
	if _, err := Probe(context.Background(), domain, hosts, nil, authed); err != nil {
		t.Fatalf("authed Probe: %v", err)
	}
	// Distinct keys: authed cold run re-requests (no stale anonymous hit).
	if tr.count() != 4 {
		t.Fatalf("requests = %d, want 4 (anon pair + authed cold pair, distinct keys)", tr.count())
	}
	if _, err := Probe(context.Background(), domain, hosts, nil, authed); err != nil {
		t.Fatalf("warm authed Probe: %v", err)
	}
	if tr.count() != 4 {
		t.Fatalf("requests = %d, want 4 (warm authed hit, zero network)", tr.count())
	}
}

func TestProbeInvalidSessionHeadersRejected(t *testing.T) {
	tr := &headerCaptureTransport{}
	cfg := testConfig()
	cfg.Transport = tr
	cfg.RequestHeaders = http.Header{"Bad Name": {"v"}}
	_, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err == nil {
		t.Fatal("Probe accepted invalid session headers (want whole-call rejection)")
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0 (rejected before the pool)", tr.count())
	}
}

func TestSessionKeySeparation(t *testing.T) {
	u := mustURLProbe(t, "http://example.com/")
	domain := mustDomainProbe(t, "example.com")
	kAnon, err := probeKey(u, domain, "")
	if err != nil {
		t.Fatalf("probeKey: %v", err)
	}
	kAuth, err := probeKey(u, domain, "digest-abc")
	if err != nil {
		t.Fatalf("probeKey session: %v", err)
	}
	if kAnon == kAuth {
		t.Fatal("session key equals anonymous key (authed runs would serve anonymous records)")
	}
	lAnon, err := liveKey(u, domain, "")
	if err != nil {
		t.Fatalf("liveKey: %v", err)
	}
	lAuth, err := liveKey(u, domain, "digest-abc")
	if err != nil {
		t.Fatalf("liveKey session: %v", err)
	}
	if lAnon == lAuth {
		t.Fatal("live session key equals anonymous key")
	}
	rAnon, err := reflectKey(u, domain, []string{"q"}, "")
	if err != nil {
		t.Fatalf("reflectKey: %v", err)
	}
	rAuth, err := reflectKey(u, domain, []string{"q"}, "digest-abc")
	if err != nil {
		t.Fatalf("reflectKey session: %v", err)
	}
	if rAnon == rAuth {
		t.Fatal("reflect session key equals anonymous key")
	}
}

// TestNormalizeRejectsEmptyName pins F3 (review wave 2026-09): an empty
// header name is not a token, so the whole call is rejected before any
// request.
func TestNormalizeRejectsEmptyName(t *testing.T) {
	if validHeaderToken("") {
		t.Fatal("validHeaderToken(\"\") = true, want false")
	}
	if _, _, err := normalizeRequestHeaders(http.Header{"": {"v"}}); err == nil {
		t.Fatal("normalizeRequestHeaders accepted an empty name (want whole-call rejection)")
	}
	tr := &headerCaptureTransport{}
	cfg := testConfig()
	cfg.Transport = tr
	cfg.RequestHeaders = http.Header{"": {"v"}}
	if _, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg); err == nil {
		t.Fatal("Probe accepted an empty session header name (want whole-call rejection)")
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0 (rejected before the pool)", tr.count())
	}
}

// TestNormalizeRejectsFramingHeaders pins F4 (review wave 2026-09):
// framing headers and User-Agent must never arrive via session headers.
func TestNormalizeRejectsFramingHeaders(t *testing.T) {
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

// TestNormalizeRejectsManyValues pins F6 (review wave 2026-09): a single
// key carrying 65 values exceeds the total-values bound.
func TestNormalizeRejectsManyValues(t *testing.T) {
	vs := make([]string, 0, maxSessionHeaderValues+1)
	for i := 0; i < maxSessionHeaderValues+1; i++ {
		vs = append(vs, "synthetic-value")
	}
	if _, _, err := normalizeRequestHeaders(http.Header{"X-Multi": vs}); err == nil {
		t.Fatalf("normalizeRequestHeaders accepted %d values on one key (bound %d)",
			maxSessionHeaderValues+1, maxSessionHeaderValues)
	}
}
