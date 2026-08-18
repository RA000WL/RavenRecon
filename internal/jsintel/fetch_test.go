package jsintel

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// testTimeout bounds every potentially blocking test below; tests that
// exceed it fail instead of hanging the suite.
const testTimeout = 15 * time.Second

// mustFinish runs fn with a hard test-level bound, so a regression that
// hangs Fetch fails fast instead of wedging the package.
func mustFinish(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("%s did not finish within %s", what, testTimeout)
	}
}

// mustURL normalizes a raw URL or fails the test.
func mustURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// testFetchConfig returns a deterministic FetchConfig for unit tests: a
// short per-attempt deadline so a hung server fails fast, one explicit
// retry, and no pacing (the limiter is pinned by dedicated tests).
func testFetchConfig() FetchConfig {
	return FetchConfig{RequestTimeout: 5 * time.Second, Retries: 1}
}

// recordingServer wraps an httptest server with a mutex-guarded log of the
// requests it served: count, request URIs, and user agents.
type recordingServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	n    int
	uris []string
	uas  []string
}

// newServer starts a plain-HTTP server whose handler records every request.
func newServer(t *testing.T, handle http.HandlerFunc) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.n++
		rs.uris = append(rs.uris, r.URL.String())
		rs.uas = append(rs.uas, r.Header.Get("User-Agent"))
		rs.mu.Unlock()
		handle(w, r)
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

// count reports how many requests were served.
func (rs *recordingServer) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.n
}

// url returns the server's base URL.
func (rs *recordingServer) url() string { return rs.srv.URL }

// uri reports the i-th request's URI (the URL as the server received it:
// no fragment, no userinfo, canonical form).
func (rs *recordingServer) uri(i int) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.uris[i]
}

// ua reports the i-th request's user agent.
func (rs *recordingServer) ua(i int) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.uas[i]
}

// countingRT wraps a RoundTripper and counts the round trips it performed.
type countingRT struct {
	inner http.RoundTripper
	n     atomic.Int64
}

func (c *countingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.inner.RoundTrip(req)
}

// calls reports the number of round trips performed.
func (c *countingRT) calls() int64 { return c.n.Load() }

// flakyRT fails the first failN round trips with err, then delegates to
// inner.
type flakyRT struct {
	inner http.RoundTripper
	err   error
	failN atomic.Int64
}

func (f *flakyRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.failN.Add(-1) >= 0 {
		return nil, f.err
	}
	return f.inner.RoundTrip(req)
}

// errorRT fails every round trip with err.
type errorRT struct{ err error }

func (e errorRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// blockingRT blocks until the request's context is done, then returns the
// context error: it makes cancellation mid-flight deterministic.
type blockingRT struct{}

func (blockingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// ctxFirstRT blocks until the request's context is done and then fails with
// a PLAIN error (not the context error): it simulates a transport whose
// failure surfaces after the caller's context has already died, so the
// classification must consult the context and stop the retry loop.
type ctxFirstRT struct{ err error }

func (r ctxFirstRT) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, r.err
}

// newTestTransport returns an *http.Transport that dials addr for ANY
// destination, so requests keep their canonical host (and Host header) while
// the loopback test server receives them. tlsConfig, when non-nil, is used
// for https requests (typically a RootCAs pool trusting the test server's
// certificate). Keep-alives are disabled so no idle keep-alive connection
// goroutine can outlive a run.
func newTestTransport(addr string, tlsConfig *tls.Config) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = tlsConfig
	return tr
}

// transportFor returns a test transport routing every request to the given
// httptest server, trusting its TLS certificate when it is a TLS server.
func transportFor(t testing.TB, srv *httptest.Server) *http.Transport {
	t.Helper()
	var tlsConfig *tls.Config
	if srv.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		tlsConfig = &tls.Config{RootCAs: pool}
	}
	return newTestTransport(srv.Listener.Addr().String(), tlsConfig)
}

// plainResponder is a deterministic "non-TLS server": it answers EVERY
// connection with a plain-text HTTP 400 and closes. A TLS ClientHello sent
// to it therefore fails the handshake with "tls: first record does not look
// like a TLS handshake" deterministically.
type plainResponder struct {
	addr string
	ln   net.Listener
}

func newPlainResponder(t testing.TB) *plainResponder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("plain responder listen: %v", err)
	}
	pr := &plainResponder{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return pr
}

// refusedLoopbackAddr finds a loopback port that verifiably refuses
// connections and stays verifiably refused for the whole test. The port is
// deliberately never bound by this process: it sits below the kernel's
// ephemeral allocation range on an alternate loopback address (127.0.0.3
// first — 127/8 is loopback on every platform), so the OS can never hand it
// out as a transient source port and no freed-listener state can exist for
// it. Mirrors the httpprobe helper.
func refusedLoopbackAddr(t *testing.T) string {
	t.Helper()
	for _, base := range []string{"127.0.0.3", "127.0.0.2", "127.0.0.1"} {
		for port := 20000; port < 20030; port++ {
			addr := net.JoinHostPort(base, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				continue // something listens there; try the next candidate
			}
			if errors.Is(err, syscall.ECONNREFUSED) {
				return addr // verifiably refused: the "service absent" observation
			}
		}
	}
	t.Fatal("no reliably refused loopback port found")
	return ""
}

// fetchOrTimeout runs Fetch with a hard test-level bound and returns its
// result, so a regression that hangs the fetch fails fast instead of
// wedging the suite.
func fetchOrTimeout(t *testing.T, ctx context.Context, cfg FetchConfig, u asset.URL) FetchResult {
	t.Helper()
	done := make(chan FetchResult, 1)
	go func() { done <- Fetch(ctx, cfg, u) }()
	select {
	case res := <-done:
		return res
	case <-time.After(testTimeout):
		t.Fatalf("Fetch(%s) did not finish within %s", u.String(), testTimeout)
		return FetchResult{}
	}
}

func TestFetchCompleted(t *testing.T) {
	lm := time.Date(2026, 8, 1, 10, 30, 0, 0, time.UTC)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "  application/javascript  ")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", lm.Format(http.TimeFormat))
		w.Header().Set("X-SourceMap", "/app.js.map")
		w.Write([]byte("var a = 1;\n"))
	})

	// The requested URL carries a fragment and userinfo in its ORIGINAL
	// form; the request must be built from the canonical form (no
	// userinfo, no fragment).
	raw := strings.Replace(srv.url(), "http://", "http://user:pass@", 1) + "/app.js?v=2#section"
	u := mustURL(t, raw)
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)
	cfg.Clock = wallClock{}

	res := fetchOrTimeout(t, context.Background(), cfg, u)
	if res.Status != FetchCompleted || res.Reason != ReasonNone {
		t.Fatalf("status = %s/%s, want completed/none", res.Status, res.Reason)
	}
	if res.Err != nil {
		t.Fatalf("err = %v, want nil", res.Err)
	}
	want := []byte("var a = 1;\n")
	if string(res.Content) != string(want) {
		t.Errorf("content = %q, want %q", res.Content, want)
	}
	if res.Size != int64(len(want)) {
		t.Errorf("size = %d, want %d", res.Size, len(want))
	}
	sum := sha256.Sum256(want)
	if res.Hash != hex.EncodeToString(sum[:]) {
		t.Errorf("hash = %s, want sha256 of content", res.Hash)
	}
	if res.Truncated {
		t.Error("truncated = true, want false")
	}
	if res.StatusCode != 200 {
		t.Errorf("status code = %d, want 200", res.StatusCode)
	}
	if res.ContentType != "application/javascript" {
		t.Errorf("content type = %q, want trimmed value", res.ContentType)
	}
	if res.ETag != `"abc123"` {
		t.Errorf("etag = %q", res.ETag)
	}
	if !res.LastModified.Equal(lm) {
		t.Errorf("last modified = %v, want %v", res.LastModified, lm)
	}
	if res.XSourceMap != "/app.js.map" {
		t.Errorf("x-source-map = %q", res.XSourceMap)
	}
	if res.ContentLength != int64(len(want)) {
		t.Errorf("content length = %d, want %d", res.ContentLength, len(want))
	}
	if res.Redirects != 0 {
		t.Errorf("redirects = %d, want 0", res.Redirects)
	}
	if res.FinalURL.String() != u.String() {
		t.Errorf("final url = %s, want %s", res.FinalURL.String(), u.String())
	}
	// The wire request must be the canonical form: no fragment, no
	// userinfo, query preserved, and the fixed RavenRecon user agent.
	if got := srv.uri(0); got != "/app.js?v=2" {
		t.Errorf("request uri = %q, want %q (no fragment/userinfo)", got, "/app.js?v=2")
	}
	if got := srv.ua(0); got != userAgent {
		t.Errorf("user agent = %q, want %q", got, userAgent)
	}
}

func TestFetchGzip(t *testing.T) {
	body := []byte("var big = " + strings.Repeat("x", 4096) + ";")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write(body)
		gz.Close()
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/a.js"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	// The transport decompresses transparently: the retained content is
	// the DECOMPRESSED bytes, and the declared length is unknown (-1).
	if string(res.Content) != string(body) {
		t.Errorf("content = %q, want decompressed body", res.Content)
	}
	if res.ContentLength != -1 {
		t.Errorf("content length = %d, want -1 (transport-decompressed)", res.ContentLength)
	}
	if res.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", res.Size, len(body))
	}
}

func TestFetchContentLengthPrecheck(t *testing.T) {
	const declared = int64(10 << 30) // 10 GiB, far above any cap
	block := make(chan struct{})
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(declared, 10))
		w.Write([]byte("prefix"))
		w.(http.Flusher).Flush()
		// Block forever (until the test ends): a fetch that drained the
		// body would hang here waiting for more bytes, so the test would
		// fail its bound — proving the pre-check closes without reading.
		<-block
	})
	t.Cleanup(func() { close(block) })
	cfg := testFetchConfig()
	cfg.MaxJSBytes = 64 << 10 // the clamped minimum
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/huge.js"))
	if res.Status != FetchTruncated {
		t.Fatalf("status = %s, want incomplete (truncated)", res.Status)
	}
	if !res.Truncated {
		t.Error("truncated = false, want true")
	}
	if res.Size != 0 || res.Content != nil || res.Hash != "" {
		t.Errorf("retained content = size %d, %d bytes, hash %q; want none", res.Size, len(res.Content), res.Hash)
	}
	if res.ContentLength != declared {
		t.Errorf("content length = %d, want declared %d", res.ContentLength, declared)
	}
	if res.StatusCode != 200 {
		t.Errorf("status code = %d, want 200 (the response WAS observed)", res.StatusCode)
	}
}

func TestFetchStreamedCap(t *testing.T) {
	capBytes := int64(64 << 10) // the clamped minimum
	chunk := strings.Repeat("y", 1024)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Chunked: flush per chunk so the server never declares a
		// Content-Length and the cap is discovered while streaming.
		for i := 0; int64(i) <= capBytes+10*1024; i += len(chunk) {
			w.Write([]byte(chunk))
			w.(http.Flusher).Flush()
		}
	})
	cfg := testFetchConfig()
	cfg.MaxJSBytes = capBytes
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/big.js"))
	if res.Status != FetchTruncated {
		t.Fatalf("status = %s, want incomplete (truncated)", res.Status)
	}
	if !res.Truncated {
		t.Error("truncated = false, want true")
	}
	if res.Size != 0 || res.Content != nil || res.Hash != "" {
		t.Errorf("retained content = size %d, %d bytes, hash %q; want none", res.Size, len(res.Content), res.Hash)
	}
	if res.ContentLength != -1 {
		t.Errorf("content length = %d, want -1 (chunked)", res.ContentLength)
	}
}

func TestFetchExactCapRetained(t *testing.T) {
	// A body exactly at the cap is fully retained: only bodies OVER the
	// cap truncate.
	body := strings.Repeat("z", 64<<10)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
	cfg := testFetchConfig()
	cfg.MaxJSBytes = 64 << 10
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/exact.js"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	if res.Truncated {
		t.Error("truncated = true, want false")
	}
	if res.Size != int64(len(body)) || string(res.Content) != body {
		t.Errorf("retained %d bytes, want the full %d-byte body", res.Size, len(body))
	}
}

func TestFetchRedirect(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "/final?x=1")
			w.WriteHeader(http.StatusFound)
		case "/final":
			w.Write([]byte("final-body"))
		default:
			http.NotFound(w, r)
		}
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/start"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	if res.Redirects != 1 {
		t.Errorf("redirects = %d, want 1", res.Redirects)
	}
	if got, want := res.FinalURL.String(), srv.url()+"/final?x=1"; got != want {
		t.Errorf("final url = %s, want %s", got, want)
	}
	if string(res.Content) != "final-body" {
		t.Errorf("content = %q, want the redirect target's body", res.Content)
	}
	if res.StatusCode != 200 {
		t.Errorf("status code = %d, want 200", res.StatusCode)
	}
	if srv.count() != 2 {
		t.Errorf("requests = %d, want 2 (initial + hop)", srv.count())
	}
}

func TestFetchRedirectCap(t *testing.T) {
	var past atomic.Int64 // requests to the cap-exceeding hop
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r"+strconv.Itoa(MaxRedirects+1) {
			past.Add(1)
		}
		// Every endpoint redirects to the next: /r0 -> /r1 -> ... -> /r6.
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r")); err == nil {
			w.Header().Set("Location", "/r"+strconv.Itoa(n+1))
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/r0"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	// The walk stops at the cap: the terminal 3xx response IS the
	// observation; the cap-exceeding hop is observed but never requested.
	if res.Redirects != MaxRedirects {
		t.Errorf("redirects = %d, want %d", res.Redirects, MaxRedirects)
	}
	if res.StatusCode != http.StatusFound {
		t.Errorf("status code = %d, want %d (terminal 3xx)", res.StatusCode, http.StatusFound)
	}
	if got, want := res.FinalURL.String(), srv.url()+"/r"+strconv.Itoa(MaxRedirects); got != want {
		t.Errorf("final url = %s, want %s", got, want)
	}
	if res.Truncated {
		t.Error("truncated = true: the redirect cap is NOT a content truncation")
	}
	if n := past.Load(); n != 0 {
		t.Errorf("cap-exceeding hop requested %d times, want 0", n)
	}
	if srv.count() != MaxRedirects+1 {
		t.Errorf("requests = %d, want %d", srv.count(), MaxRedirects+1)
	}
}

func TestFetchRedirectUnparseableLocation(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		// An invalid absolute URL: url.Parse fails on the unterminated
		// IPv6 bracket, so the walk must end with THIS response.
		w.Header().Set("Location", "http://[::1")
		w.WriteHeader(http.StatusFound)
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/start"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	if res.Redirects != 0 {
		t.Errorf("redirects = %d, want 0", res.Redirects)
	}
	if res.StatusCode != http.StatusFound {
		t.Errorf("status code = %d, want %d", res.StatusCode, http.StatusFound)
	}
	if got, want := res.FinalURL.String(), srv.url()+"/start"; got != want {
		t.Errorf("final url = %s, want %s (current response is final)", got, want)
	}
	if srv.count() != 1 {
		t.Errorf("requests = %d, want 1", srv.count())
	}
}

func TestFetchRedirectNonHTTPSchemeNotFollowed(t *testing.T) {
	// A redirect to a NON-http(s) target is observed, never followed: the
	// walk ends with the redirect response as the final observation — the
	// same semantics as the unparseable-Location path (completed, the
	// terminal 3xx response, no follow attempted). asset.ParseURL accepts
	// any syntactically valid scheme, so ftp:// passes the parse and is
	// stopped by the explicit scheme gate; file:///etc/passwd is stopped
	// by ParseURL's missing-host rule. Either way the target is never
	// requested and the observation is completed, never failed — one
	// scheme-incompatible redirect cannot wedge the URL in retries.
	for _, tc := range []struct {
		name     string
		location string
	}{
		{name: "ftp scheme", location: "ftp://ftp.example.com/x.js"},
		{name: "file scheme", location: "file:///etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tc.location)
				w.WriteHeader(http.StatusFound)
			})
			cfg := testFetchConfig()
			cfg.Transport = transportFor(t, srv.srv)

			res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/start"))
			if res.Status != FetchCompleted || res.Reason != ReasonNone {
				t.Fatalf("status/reason = %s/%s, want completed/none", res.Status, res.Reason)
			}
			if res.Err != nil {
				t.Fatalf("err = %v, want nil (the redirect is observed, not failed)", res.Err)
			}
			if res.StatusCode != http.StatusFound {
				t.Errorf("status code = %d, want %d (the terminal redirect response IS the observation)", res.StatusCode, http.StatusFound)
			}
			if res.Redirects != 0 {
				t.Errorf("redirects = %d, want 0 (the refused hop is observed, never followed)", res.Redirects)
			}
			if got, want := res.FinalURL.String(), srv.url()+"/start"; got != want {
				t.Errorf("final url = %s, want %s (the walk ends at the redirect response)", got, want)
			}
			if srv.count() != 1 {
				t.Errorf("requests = %d, want 1 (the %s target must never be requested)", srv.count(), tc.location)
			}
		})
	}
}

func TestFetchRedirectCrossHostFollowed(t *testing.T) {
	// Cross-host http(s) redirects ARE followed by design: jsintel has no
	// declared-scope concept, and fetch targets come from the operator's
	// own corpus. The test transport routes ANY destination to the
	// loopback server, so the other-host target reaches the same handler.
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "http://other-host.test/final.js")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("cross-host-body"))
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/start"))
	if res.Status != FetchCompleted || res.Reason != ReasonNone {
		t.Fatalf("status/reason = %s/%s, want completed/none", res.Status, res.Reason)
	}
	if res.Redirects != 1 {
		t.Errorf("redirects = %d, want 1 (the cross-host hop was followed)", res.Redirects)
	}
	if got, want := res.FinalURL.String(), "http://other-host.test/final.js"; got != want {
		t.Errorf("final url = %s, want %s", got, want)
	}
	if string(res.Content) != "cross-host-body" {
		t.Errorf("content = %q, want the cross-host target's body", res.Content)
	}
	if srv.count() != 2 {
		t.Errorf("requests = %d, want 2 (initial + cross-host hop)", srv.count())
	}
}

func TestFetchConnRefused(t *testing.T) {
	addr := refusedLoopbackAddr(t)
	cfg := testFetchConfig()
	cfg.Transport = newTestTransport(addr, nil)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://"+addr+"/"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed (negative observation)", res.Status)
	}
	if res.Reason != ReasonConnRefused {
		t.Errorf("reason = %q, want conn_refused", res.Reason)
	}
	if res.StatusCode != 0 || res.Content != nil || res.Size != 0 {
		t.Errorf("completed negative carries a response observation: status %d, %d bytes", res.StatusCode, res.Size)
	}
	if res.FinalURL.String() != "http://"+addr+"/" {
		t.Errorf("final url = %s, want the targeted url", res.FinalURL.String())
	}
}

func TestFetchTLSFailure(t *testing.T) {
	pr := newPlainResponder(t)
	cfg := testFetchConfig()
	cfg.Transport = newTestTransport(pr.addr, nil)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "https://"+pr.addr+"/"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed (negative observation)", res.Status)
	}
	if res.Reason != ReasonTLS {
		t.Errorf("reason = %q, want tls", res.Reason)
	}
	if res.StatusCode != 0 || res.Content != nil {
		t.Errorf("completed negative carries a response observation: status %d, %d bytes", res.StatusCode, res.Size)
	}
}

func TestFetchTimeout(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond) // longer than the per-attempt deadline
		w.Write([]byte("late"))
	})
	cfg := testFetchConfig()
	cfg.RequestTimeout = 200 * time.Millisecond
	cfg.Retries = 1
	cfg.Transport = transportFor(t, srv.srv)

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/slow.js"))
	if res.Status != FetchFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
	if res.Reason != ReasonTimeout {
		t.Errorf("reason = %q, want timeout", res.Reason)
	}
	if res.Err == nil {
		t.Error("err = nil, want the deadline error")
	}
	// A timeout is a failed attempt and is retried (immediately, bounded).
	if n := srv.count(); n != 2 {
		t.Errorf("requests = %d, want 2 (1 + 1 retry)", n)
	}
}

func TestFetchDNS(t *testing.T) {
	rt := countingRT{inner: errorRT{err: &net.DNSError{Err: "no such host", Name: "none.invalid", IsNotFound: true}}}
	cfg := testFetchConfig()
	cfg.Retries = 2
	cfg.Transport = &rt

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://none.invalid/app.js"))
	if res.Status != FetchFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
	if res.Reason != ReasonDNS {
		t.Errorf("reason = %q, want dns", res.Reason)
	}
	if n := rt.calls(); n != 3 {
		t.Errorf("attempts = %d, want 3 (1 + 2 retries)", n)
	}
}

func TestFetchRetries(t *testing.T) {
	body := []byte("ok")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	boom := errors.New("transient upstream failure")

	t.Run("transient then success", func(t *testing.T) {
		rt := &flakyRT{inner: transportFor(t, srv.srv), err: boom}
		rt.failN.Store(2)
		counting := countingRT{inner: rt}
		cfg := testFetchConfig()
		cfg.Retries = 2
		cfg.Transport = &counting

		res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/t.js"))
		if res.Status != FetchCompleted {
			t.Fatalf("status = %s, want completed", res.Status)
		}
		if res.Reason != ReasonNone || res.Err != nil {
			t.Errorf("reason/err = %q/%v, want none/nil", res.Reason, res.Err)
		}
		if string(res.Content) != string(body) {
			t.Errorf("content = %q, want %q", res.Content, body)
		}
		if n := counting.calls(); n != 3 {
			t.Errorf("attempts = %d, want 3 (2 failures + success)", n)
		}
	})

	t.Run("always failing", func(t *testing.T) {
		counting := countingRT{inner: errorRT{err: boom}}
		cfg := testFetchConfig()
		cfg.Retries = 2
		cfg.Transport = &counting

		res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://example.com/f.js"))
		if res.Status != FetchFailed {
			t.Fatalf("status = %s, want failed", res.Status)
		}
		if res.Reason != ReasonOther {
			t.Errorf("reason = %q, want other", res.Reason)
		}
		if n := counting.calls(); n != 3 {
			t.Errorf("attempts = %d, want 3 (1 + 2 retries)", n)
		}
	})

	t.Run("response is never retried", func(t *testing.T) {
		srv5 := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		counting := countingRT{inner: transportFor(t, srv5.srv)}
		cfg := testFetchConfig()
		cfg.Retries = 2
		cfg.Transport = &counting

		res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv5.url()+"/e.js"))
		if res.Status != FetchCompleted {
			t.Fatalf("status = %s, want completed (an HTTP response is an observation)", res.Status)
		}
		if res.StatusCode != 500 {
			t.Errorf("status code = %d, want 500", res.StatusCode)
		}
		if n := counting.calls(); n != 1 {
			t.Errorf("attempts = %d, want 1 (500 is not retried)", n)
		}
	})

	t.Run("no retry once the context is done", func(t *testing.T) {
		// The transport blocks until the caller cancels, then fails with a
		// plain error: the attempt would classify as failed, but the done
		// context must stop the retry loop — a retry could only fail again.
		counting := countingRT{inner: ctxFirstRT{err: boom}}
		cfg := testFetchConfig()
		cfg.Retries = 2
		cfg.Transport = &counting

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		res := fetchOrTimeout(t, ctx, cfg, mustURL(t, "http://example.com/g.js"))
		if res.Status != FetchCancelled {
			t.Fatalf("status = %s, want cancelled (ctx done takes precedence)", res.Status)
		}
		if n := counting.calls(); n != 1 {
			t.Errorf("attempts = %d, want 1 (no retry after cancellation)", n)
		}
	})
}

func TestFetchCancelledBeforeDispatch(t *testing.T) {
	cfg := testFetchConfig()
	cfg.Transport = errorRT{err: errors.New("must not be called")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := Fetch(ctx, cfg, mustURL(t, "http://example.com/a.js"))
	if res.Status != FetchCancelled {
		t.Fatalf("status = %s, want cancelled", res.Status)
	}
	if res.Reason != ReasonOther {
		t.Errorf("reason = %q, want other", res.Reason)
	}
	if res.Err == nil {
		t.Error("err = nil, want the context error")
	}
	if res.FinalURL != (asset.URL{}) {
		t.Errorf("final url = %s, want zero (nothing was dispatched)", res.FinalURL.String())
	}
}

func TestFetchCancelledInFlight(t *testing.T) {
	u := mustURL(t, "http://example.com/slow.js")
	cfg := testFetchConfig()
	cfg.Transport = blockingRT{}

	var res FetchResult
	mustFinish(t, "fetch", func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		res = Fetch(ctx, cfg, u)
	})
	if res.Status != FetchCancelled {
		t.Fatalf("status = %s, want cancelled", res.Status)
	}
	if res.Reason != ReasonOther {
		t.Errorf("reason = %q, want other", res.Reason)
	}
	if res.FinalURL.String() != u.String() {
		t.Errorf("final url = %s, want %s (the targeted url)", res.FinalURL.String(), u.String())
	}
}

func TestFetchLimiterFunctional(t *testing.T) {
	// A real limiter with a generous rate: the fetch must work through the
	// central dispatch gate, and every hop must pass through it. Token
	// accounting is asserted by the cache-hit test in record_fetch_test.go.
	limiter, err := runtime.NewLimiter(1000, 1)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("limited"))
	})
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv.srv)
	cfg.Limiter = limiter

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, srv.url()+"/a"))
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}
	if res.Redirects != 1 || string(res.Content) != "limited" {
		t.Errorf("redirects/content = %d/%q, want 1/%q", res.Redirects, res.Content, "limited")
	}
}

func TestFetchConfigValidation(t *testing.T) {
	t.Run("negatives rejected", func(t *testing.T) {
		for name, c := range map[string]FetchConfig{
			"request timeout": {RequestTimeout: -1},
			"max js bytes":    {MaxJSBytes: -1},
			"retries":         {Retries: -1},
		} {
			if _, err := c.validated(); err == nil {
				t.Errorf("%s: validated() accepted a negative value", name)
			}
		}
	})

	t.Run("zero means default", func(t *testing.T) {
		c, err := (FetchConfig{}).validated()
		if err != nil {
			t.Fatalf("validated: %v", err)
		}
		if c.RequestTimeout != requestTimeoutDefault {
			t.Errorf("request timeout = %v, want %v", c.RequestTimeout, requestTimeoutDefault)
		}
		if c.MaxJSBytes != defaultMaxJSBytes {
			t.Errorf("max js bytes = %d, want %d", c.MaxJSBytes, defaultMaxJSBytes)
		}
		if c.Retries != defaultRetries {
			t.Errorf("retries = %d, want %d", c.Retries, defaultRetries)
		}
	})

	t.Run("clamps", func(t *testing.T) {
		c, err := (FetchConfig{MaxJSBytes: 10, Retries: 99, RequestTimeout: time.Hour}).validated()
		if err != nil {
			t.Fatalf("validated: %v", err)
		}
		if c.MaxJSBytes != minMaxJSBytes {
			t.Errorf("max js bytes = %d, want clamped minimum %d", c.MaxJSBytes, minMaxJSBytes)
		}
		if c.Retries != maxRetries {
			t.Errorf("retries = %d, want clamped maximum %d", c.Retries, maxRetries)
		}
		if c.RequestTimeout != time.Hour {
			t.Errorf("request timeout = %v, want hour (no clamp at this layer)", c.RequestTimeout)
		}
		c, err = (FetchConfig{MaxJSBytes: 1 << 30}).validated()
		if err != nil {
			t.Fatalf("validated: %v", err)
		}
		if c.MaxJSBytes != maxMaxJSBytes {
			t.Errorf("max js bytes = %d, want clamped maximum %d", c.MaxJSBytes, maxMaxJSBytes)
		}
	})
}

func TestFetchNilContext(t *testing.T) {
	res := Fetch(nil, testFetchConfig(), mustURL(t, "http://example.com/a.js"))
	if res.Status != FetchFailed || res.Reason != ReasonOther || res.Err == nil {
		t.Fatalf("status/reason/err = %s/%s/%v, want failed/other/non-nil", res.Status, res.Reason, res.Err)
	}
}

func TestFetchInvalidURLConfigPath(t *testing.T) {
	// An invalid config must classify as failed/other without a panic and
	// without dispatching anything.
	res := Fetch(context.Background(), FetchConfig{Retries: -1}, mustURL(t, "http://example.com/a.js"))
	if res.Status != FetchFailed || res.Reason != ReasonOther || res.Err == nil {
		t.Fatalf("status/reason/err = %s/%s/%v, want failed/other/non-nil", res.Status, res.Reason, res.Err)
	}
}

func TestFetchSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("  text/javascript; charset=utf-8  ", maxContentTypeBytes); got != "text/javascript; charset=utf-8" {
		t.Errorf("trim: got %q", got)
	}
	if got := sanitizeHeader("app\x01lication/x", maxContentTypeBytes); got != "application/x" {
		t.Errorf("control bytes dropped: got %q", got)
	}
	long := strings.Repeat("a", 300)
	if got := sanitizeHeader(long, 128); len(got) != 128 {
		t.Errorf("cap: got %d bytes, want 128", len(got))
	}
	if got := sanitizeHeader("", 128); got != "" {
		t.Errorf("empty: got %q", got)
	}
}
