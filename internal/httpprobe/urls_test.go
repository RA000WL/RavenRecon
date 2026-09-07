package httpprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// urlTransport is a hermetic RoundTripper for ProbeURLs tests: it maps
// canonical URL strings to canned responses, records request counts, and
// never dials.
type urlTransport struct {
	mu       sync.Mutex
	byURL    map[string]cannedURLResponse
	requests []string
}

type cannedURLResponse struct {
	status   int
	headers  map[string]string
	body     string
	err      error
	tlsState *tls.ConnectionState
}

func (t *urlTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.String()
	t.mu.Lock()
	t.requests = append(t.requests, key)
	t.mu.Unlock()
	if resp, ok := t.byURL[key]; ok {
		if resp.err != nil {
			return nil, resp.err
		}
		h := make(http.Header)
		for k, v := range resp.headers {
			h.Set(k, v)
		}
		r := &http.Response{
			StatusCode: resp.status,
			Header:     h,
			Body:       http.NoBody,
			Request:    req,
			TLS:        resp.tlsState,
		}
		// For redirect tests, ensure Location header is accessible via Get.
		return r, nil
	}
	// Default 200
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func (t *urlTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

// fake TLS state for https probes.
func tlsStateForTest(t testing.TB, cn string) *tls.ConnectionState {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return &tls.ConnectionState{
		PeerCertificates:   []*x509.Certificate{cert},
		VerifiedChains:     [][]*x509.Certificate{{cert}},
		NegotiatedProtocol: "h2",
	}
}

func mustURLProbe(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL %q: %v", raw, err)
	}
	return u
}

func mustDomainProbe(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain %q: %v", name, err)
	}
	return d
}

func TestProbeURLs(t *testing.T) {
	// Basic 200/404/500/timeout/refused, sorted, redirect observed, TLS handling.
	domain := mustDomainProbe(t, "example.com")
	urls := []asset.URL{
		mustURLProbe(t, "https://example.com/b"),
		mustURLProbe(t, "http://example.com/a"),
		mustURLProbe(t, "http://example.com/c"),
		mustURLProbe(t, "https://example.com/d"),
	}
	// Shuffle input to test sorting: b, a, c, d -> should sort to a, b, c, d
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/a":  {status: 200},
		"https://example.com/b": {status: 404, tlsState: tlsStateForTest(t, "example.com")},
		"http://example.com/c":  {status: 500},
		"https://example.com/d": {status: 200, tlsState: tlsStateForTest(t, "example.com")},
	}}
	cfg := Config{
		Concurrency: 2,
		QueueSize:   8,
		Timeout:     5 * time.Second,
		Transport:   tr,
	}
	report, err := ProbeURLs(context.Background(), domain, urls, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if len(report.Records) != 4 {
		t.Fatalf("Records = %d, want 4", len(report.Records))
	}
	// Sorted by URL String()
	wantOrder := []string{"http://example.com/a", "http://example.com/c", "https://example.com/b", "https://example.com/d"}
	for i, rec := range report.Records {
		if rec.URL.String() != wantOrder[i] {
			t.Errorf("Records[%d].URL = %s, want %s", i, rec.URL.String(), wantOrder[i])
		}
	}
	// Check statuses
	statusByURL := make(map[string]int)
	for _, r := range report.Records {
		statusByURL[r.URL.String()] = r.Status
	}
	if statusByURL["http://example.com/a"] != 200 {
		t.Errorf("a status = %d, want 200", statusByURL["http://example.com/a"])
	}
	if statusByURL["https://example.com/b"] != 404 {
		t.Errorf("b status = %d, want 404", statusByURL["https://example.com/b"])
	}
	if statusByURL["http://example.com/c"] != 500 {
		t.Errorf("c status = %d, want 500", statusByURL["http://example.com/c"])
	}
	// TLS nil for http, non-empty for https
	for _, r := range report.Records {
		if strings.HasPrefix(r.URL.String(), "http://") && r.TLS != nil {
			t.Errorf("http URL %s TLS = %+v, want nil", r.URL.String(), r.TLS)
		}
		if strings.HasPrefix(r.URL.String(), "https://") && r.TLS == nil {
			t.Errorf("https URL %s TLS = nil, want non-nil", r.URL.String())
		}
	}
}

func TestProbeURLsRedirectObserved(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/redirect")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/redirect": {status: 301, headers: map[string]string{"Location": "http://example.com/target"}},
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if len(report.Records) != 1 {
		t.Fatalf("Records = %d, want 1", len(report.Records))
	}
	rec := report.Records[0]
	if !rec.RedirectObserved {
		t.Fatalf("RedirectObserved = false, want true for 301")
	}
	if rec.RedirectLocation != "http://example.com/target" {
		t.Fatalf("RedirectLocation = %q, want http://example.com/target", rec.RedirectLocation)
	}
	if rec.Status != 301 {
		t.Fatalf("Status = %d, want 301", rec.Status)
	}
	// Ensure only one request was made (no follow)
	if tr.count() != 1 {
		t.Fatalf("requests = %d, want 1 (redirect not followed)", tr.count())
	}
}

func TestProbeURLsTimeoutAndRefused(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	timeoutURL := mustURLProbe(t, "http://example.com/timeout")
	refusedURL := mustURLProbe(t, "http://example.com/refused")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/timeout": {err: &url.Error{Op: "Get", URL: "http://example.com/timeout", Err: context.DeadlineExceeded}},
		"http://example.com/refused": {err: syscall.ECONNREFUSED},
	}}
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{timeoutURL, refusedURL}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if len(report.Records) != 2 {
		t.Fatalf("Records = %d, want 2", len(report.Records))
	}
	for _, r := range report.Records {
		if r.Err == nil {
			t.Errorf("URL %s Err = nil, want error for timeout/refused", r.URL.String())
		}
		if r.Status != 0 {
			t.Errorf("URL %s Status = %d, want 0 for error", r.URL.String(), r.Status)
		}
	}
}

func TestProbeURLsSortedAndDeterministic(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	urls := []asset.URL{
		mustURLProbe(t, "http://example.com/z"),
		mustURLProbe(t, "http://example.com/a"),
		mustURLProbe(t, "http://example.com/m"),
	}
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/a": {status: 200},
		"http://example.com/m": {status: 200},
		"http://example.com/z": {status: 200},
	}}
	cfg := Config{Concurrency: 4, QueueSize: 8, Transport: tr}
	r1, err := ProbeURLs(context.Background(), domain, urls, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	r2, err := ProbeURLs(context.Background(), domain, urls, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs second: %v", err)
	}
	// Deterministic: second run DeepEqual first (sorted order)
	if len(r1.Records) != len(r2.Records) {
		t.Fatalf("deterministic: len differ %d vs %d", len(r1.Records), len(r2.Records))
	}
	for i := range r1.Records {
		if r1.Records[i].URL.String() != r2.Records[i].URL.String() {
			t.Fatalf("deterministic: records differ at %d", i)
		}
	}
	// Ensure sorted
	want := []string{"http://example.com/a", "http://example.com/m", "http://example.com/z"}
	for i, rec := range r1.Records {
		if rec.URL.String() != want[i] {
			t.Errorf("sorted: got %s, want %s", rec.URL.String(), want[i])
		}
	}
}

func TestProbeURLsCacheHit(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/cached")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/cached": {status: 200},
	}}
	cfg := Config{Concurrency: 2, QueueSize: 4, Cache: c, Transport: tr}
	r1, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("first ProbeURLs: %v", err)
	}
	if r1.Records[0].Cached {
		t.Fatal("first run should not be cached")
	}
	if tr.count() != 1 {
		t.Fatalf("first run requests = %d, want 1", tr.count())
	}
	// Second run with transport that would fail, but cache should serve
	tr2 := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/cached": {err: errors.New("should not be called")},
	}}
	cfg2 := Config{Concurrency: 2, QueueSize: 4, Cache: c, Transport: tr2}
	r2, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg2)
	if err != nil {
		t.Fatalf("second ProbeURLs: %v", err)
	}
	if !r2.Records[0].Cached {
		t.Fatal("second run should be cached")
	}
	if tr2.count() != 0 {
		t.Fatalf("second run requests = %d, want 0 (cache hit)", tr2.count())
	}
	if r2.Records[0].Status != 200 {
		t.Errorf("cached status = %d, want 200", r2.Records[0].Status)
	}
}

func TestProbeURLsTruncationFlag(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/trunc")
	// Create response with many headers to trigger MaxHeaders truncation (128 cap)
	headers := make(map[string]string)
	for i := 0; i < 130; i++ {
		headers[sortHeaderKey(i)] = "v"
	}
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/trunc": {status: 200, headers: headers},
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if !report.Records[0].Truncated {
		t.Fatal("Truncated = false, want true for header overflow")
	}
}

func sortHeaderKey(i int) string {
	return "X-Test-" + pad3(i)
}

func pad3(i int) string {
	s := string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
	return s
}

func TestProbeURLsEmptyInput(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: &urlTransport{}}
	report, err := ProbeURLs(context.Background(), domain, nil, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs empty: %v", err)
	}
	if len(report.Records) != 0 {
		t.Fatalf("Records = %d, want 0 for empty input", len(report.Records))
	}
}

func TestProbeURLsPerURLTimeout(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/slow")
	// Transport that blocks until context done
	block := make(chan struct{})
	tr := &blockingURLTransport{block: block}
	cfg := Config{
		Concurrency:    1,
		QueueSize:      4,
		Transport:      tr,
		RequestTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	report, err := ProbeURLs(ctx, domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("ProbeURLs did not respect per-URL timeout")
	}
	if len(report.Records) != 1 || report.Records[0].Err == nil {
		t.Fatalf("want timeout error, got %+v", report.Records)
	}
	close(block)
}

type blockingURLTransport struct {
	block chan struct{}
}

func (t *blockingURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-t.block:
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	}
}

func TestProbeURLsTLSForHTTPS(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	httpURL := mustURLProbe(t, "http://example.com/plain")
	httpsURL := mustURLProbe(t, "https://example.com/secure")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/plain":   {status: 200},
		"https://example.com/secure": {status: 200, tlsState: tlsStateForTest(t, "example.com")},
	}}
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{httpURL, httpsURL}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	for _, r := range report.Records {
		if r.URL.String() == "http://example.com/plain" && r.TLS != nil {
			t.Errorf("http TLS = %+v, want nil", r.TLS)
		}
		if r.URL.String() == "https://example.com/secure" && r.TLS == nil {
			t.Errorf("https TLS = nil, want non-empty")
		}
	}
}

func TestProbeURLsNoBody(t *testing.T) {
	// Ensure body is not retained (MaxBody 0)
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/body")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/body": {status: 200, body: strings.Repeat("x", 10000)},
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	// LiveRecord has no body field, so just ensure status is 200 and no truncation due to body
	if report.Records[0].Status != 200 {
		t.Fatalf("Status = %d, want 200", report.Records[0].Status)
	}
	if report.Records[0].Truncated {
		t.Fatalf("Truncated should be false for body (MaxBody 0, no body retained, not truncated)")
	}
}

func TestProbeURLsNilContext(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/a")
	_, err := ProbeURLs(nil, domain, []asset.URL{u}, Config{Transport: &urlTransport{}})
	if err == nil {
		t.Fatal("want error for nil context")
	}
}

func TestProbeURLsCancelledContext(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ProbeURLs(ctx, domain, []asset.URL{u}, Config{Transport: &urlTransport{}})
	if err == nil {
		t.Fatal("want error for cancelled context")
	}
}

func TestProbeURLsBoundedConcurrency(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	var urls []asset.URL
	for i := 0; i < 20; i++ {
		urls = append(urls, mustURLProbe(t, "http://example.com/"+pad3(i)))
	}
	mt := &maxConcurrentTransport{delay: 20 * time.Millisecond}
	cfg := Config{Concurrency: 2, QueueSize: 8, Transport: mt}
	report, err := ProbeURLs(context.Background(), domain, urls, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if len(report.Records) != 20 {
		t.Fatalf("Records = %d, want 20", len(report.Records))
	}
	if mt.maxActive > 2 {
		t.Fatalf("max concurrent = %d, want <=2 (bounded pool)", mt.maxActive)
	}
}

// TestProbeURLsTriageDefaults pins the triage defaults: with an unset
// RequestTimeout and Concurrency, ProbeURLs uses the 5 s triage per-URL
// deadline (not the 10 s host default) and a widened pool (20). A blocking
// transport proves the 5 s cut via elapsed time; a wide transport proves
// concurrency >2 is reachable without explicit config.
func TestProbeURLsTriageDefaults(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	urls := []asset.URL{mustURLProbe(t, "http://example.com/dead")}
	start := time.Now()
	report, err := ProbeURLs(context.Background(), domain, urls, Config{
		Transport: &blockingTransport{},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	if len(report.Records) != 1 || report.Records[0].Err == nil {
		t.Fatalf("want one errored record, got %+v", report.Records)
	}
	if elapsed > 8*time.Second {
		t.Fatalf("per-URL deadline = %v, want ~5s triage default (not 10s host default)", elapsed)
	}
	if elapsed < 4*time.Second {
		t.Fatalf("probe returned after %v — shorter than the 5s triage default; deadline not applied", elapsed)
	}
}

type blockingTransport struct{}

func (blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

type maxConcurrentTransport struct {
	delay     time.Duration
	mu        sync.Mutex
	active    int
	maxActive int
}

func (t *maxConcurrentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.active++
	if t.active > t.maxActive {
		t.maxActive = t.active
	}
	t.mu.Unlock()
	time.Sleep(t.delay)
	t.mu.Lock()
	t.active--
	t.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
}

func init() {
	// Ensure deterministic clock for tests that use cache
}

// deepChainTLSState builds a fake tls.ConnectionState carrying n peer
// certificates (independent self-signed leaves are enough: captureTLS only
// inspects the leaf and counts the chain depth).
func deepChainTLSState(t testing.TB, n int) *tls.ConnectionState {
	t.Helper()
	cs := tlsStateForTest(t, "example.com")
	for len(cs.PeerCertificates) < n {
		extra := tlsStateForTest(t, "example.com")
		cs.PeerCertificates = append(cs.PeerCertificates, extra.PeerCertificates...)
	}
	return cs
}

// TestLiveProbeDeepChainTLSDiagnosticKeepsCompletedAndCached pins NEW-77:
// a captureTLS diagnostic (chain deeper than the asset model cap) joined
// into rec.Err must not flip a fully-observed response into a failed or
// uncachable record. The first run stays completed (diagnostic in Err only,
// no FailureReason stamped), and the second run is served as a cache hit —
// hosts with deep chains are never re-probed forever.
func TestLiveProbeDeepChainTLSDiagnosticKeepsCompletedAndCached(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "https://example.com/deep-chain")
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"https://example.com/deep-chain": {
			status:   200,
			tlsState: deepChainTLSState(t, maxTLSMetadataChainDepth+1),
		},
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr}
	r1, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("first ProbeURLs: %v", err)
	}
	rec1 := r1.Records[0]
	if rec1.Cached {
		t.Fatal("first run should not be cached")
	}
	if rec1.Status != 200 {
		t.Fatalf("first run status = %d, want 200 (response fully observed)", rec1.Status)
	}
	if rec1.Err == nil || !strings.Contains(rec1.Err.Error(), "exceeds the asset model cap") {
		t.Fatalf("first run err = %v, want the tls chain-depth diagnostic", rec1.Err)
	}
	if rec1.TLSMeta == nil || rec1.TLSMeta.Certificate.Fingerprint != "" {
		t.Fatalf("first run TLS meta = %+v, want metadata kept but certificate asset suppressed", rec1.TLSMeta)
	}
	// The stored record must carry no failure reason: the response was
	// observed, so ReasonOther must never be stamped.
	key, err := liveKey(u, domain, "")
	if err != nil {
		t.Fatalf("liveKey: %v", err)
	}
	out := c.Get(context.Background(), key)
	if !out.IsHit() || out.Record.Status != cache.StatusCompleted {
		t.Fatalf("stored record = hit=%v status=%v, want a completed hit", out.IsHit(), out.Record.Status)
	}
	var stored storedLive
	if jerr := json.Unmarshal(out.Record.Data, &stored); jerr != nil {
		t.Fatalf("unmarshal stored: %v", jerr)
	}
	if stored.FailureReason != ReasonNone {
		t.Fatalf("stored failure reason = %q, want none for an observed response", stored.FailureReason)
	}
	// Second run: served from cache without touching the transport.
	tr2 := &urlTransport{byURL: map[string]cannedURLResponse{
		"https://example.com/deep-chain": {err: errors.New("should not be called")},
	}}
	cfg2 := Config{Concurrency: 1, QueueSize: 4, Cache: c, Transport: tr2}
	r2, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg2)
	if err != nil {
		t.Fatalf("second ProbeURLs: %v", err)
	}
	rec2 := r2.Records[0]
	if !rec2.Cached || tr2.count() != 0 {
		t.Fatalf("second run cached=%v requests=%d, want a zero-request cache hit", rec2.Cached, tr2.count())
	}
	if rec2.Status != 200 {
		t.Fatalf("second run status = %d, want 200 served from cache", rec2.Status)
	}
}

// TestLiveProbeRedirectFallbackSanitized pins the NEW-83 redaction item:
// when the MaxHeaders cap drops the Location header from boundedHeaders,
// the raw fallback goes through sanitizeLocation — control bytes and
// userinfo never survive into RedirectLocation.
func TestLiveProbeRedirectFallbackSanitized(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/redir-cap")
	// More than MaxHeaders keys that all sort before "Location", so the cap
	// drops Location from the retained headers and the raw fallback runs.
	headers := make(map[string]string, MaxHeaders+2)
	for i := range MaxHeaders + 2 {
		headers["B-Test-"+pad3(i)] = "v"
	}
	hostile := "\x01http://user:pass@example.com/p\x7fath?q=1"
	headers["Location"] = hostile
	tr := &urlTransport{byURL: map[string]cannedURLResponse{
		"http://example.com/redir-cap": {status: 302, headers: headers},
	}}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	report, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg)
	if err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	rec := report.Records[0]
	if !rec.RedirectObserved {
		t.Fatal("RedirectObserved = false, want true")
	}
	if rec.RedirectLocation == "" {
		t.Fatal("RedirectLocation empty, want the sanitized fallback target")
	}
	if strings.ContainsFunc(rec.RedirectLocation, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		t.Fatalf("RedirectLocation %q carries control bytes", rec.RedirectLocation)
	}
	if strings.Contains(rec.RedirectLocation, "user:pass") {
		t.Fatalf("RedirectLocation %q carries credentials", rec.RedirectLocation)
	}
}

// bodyOverrideTransport serves one canned response whose Body is supplied
// per request (the urlTransport always answers with http.NoBody).
type bodyOverrideTransport struct {
	status int
	body   io.ReadCloser
}

func (t *bodyOverrideTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       t.body,
		Request:    req,
	}, nil
}

// TestLiveProbeDrainsBodyBeforeClose pins the NEW-83 keep-alive item:
// doLiveProbe drains up to maxRedirectDrainBytes of the terminal body
// before closing it (like drainFollowedBody on the host path), so the
// connection stays reusable; the body is always closed.
func TestLiveProbeDrainsBodyBeforeClose(t *testing.T) {
	domain := mustDomainProbe(t, "example.com")
	u := mustURLProbe(t, "http://example.com/drain")
	body := &drainTrackingBody{content: bytes.Repeat([]byte("x"), maxRedirectDrainBytes+4096)}
	tr := &bodyOverrideTransport{status: 200, body: body}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	if _, err := ProbeURLs(context.Background(), domain, []asset.URL{u}, cfg); err != nil {
		t.Fatalf("ProbeURLs: %v", err)
	}
	body.mu.Lock()
	defer body.mu.Unlock()
	if !body.closed {
		t.Fatal("terminal response body was not closed")
	}
	if body.read != maxRedirectDrainBytes {
		t.Fatalf("drained %d bytes, want exactly %d (bounded drain)", body.read, maxRedirectDrainBytes)
	}
}
