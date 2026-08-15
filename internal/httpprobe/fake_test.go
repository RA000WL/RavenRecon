package httpprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	goruntime "runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// testTimeout bounds every potentially blocking test below; tests that exceed
// it fail instead of hanging the suite.
const testTimeout = 15 * time.Second

// mustFinish runs fn with a hard test-level bound, so a regression that
// hangs Probe fails fast instead of wedging the package.
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

// fixedTime is the deterministic provenance timestamp used by tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// fakeClock is a deterministic runtime.Clock. It starts at fixedTime and only
// advances when advance is called. After timers fire when advance passes
// their target, matching the runtime limiter's expectations.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters map[chan time.Time]time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, waiters: make(map[chan time.Time]time.Time)}
}

// Now implements runtime.Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements runtime.Clock.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters[ch] = c.now.Add(d)
	return ch
}

// advance moves the clock forward by d and fires every After timer whose
// target has been reached.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for ch, target := range c.waiters {
		if !target.After(c.now) {
			ch <- c.now
			delete(c.waiters, ch)
		}
	}
}

// waiterCount reports how many After timers are currently registered: the
// number of pending waits parked on the fake clock. Tests use it to observe
// that a limiter wait has actually started (a token request registered its
// wake-up timer) before advancing the clock.
func (c *fakeClock) waiterCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

var _ runtime.Clock = (*fakeClock)(nil)

// mustDomain normalizes a domain or fails the test.
func mustDomain(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

// mustHost normalizes a host or fails the test.
func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// mustIP normalizes an address or fails the test.
func mustIP(t testing.TB, addr string) asset.IP {
	t.Helper()
	ip, err := asset.NewIP(addr, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP(%q): %v", addr, err)
	}
	return ip
}

// testConfig returns a fast, deterministic Config for unit tests: a short
// per-job timeout so a hung server fails fast, and modest pool bounds.
func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 16
	cfg.Timeout = 5 * time.Second
	cfg.Rate = 0 // pacing disabled: rate limiting is pinned by the fake-clock tests in run_test.go (TestProbeRateLimiterGatesEveryRequest, TestProbeRateLimiterDisabled, TestProbeRedirectHopConsumesToken)
	return cfg
}

// newTestTransport returns an *http.Transport that dials addr for ANY
// destination, so requests keep their canonical host (and Host header) while
// the loopback test server receives them. tlsConfig, when non-nil, is used
// for https requests (typically a RootCAs pool trusting the test server's
// certificate). Keep-alives are disabled so no idle keep-alive connection
// goroutine can outlive a run; the goroutine-leak test
// (TestProbeNoGoroutineLeak) and the benchmarks depend on that property.
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

// leafCertForTest returns a fresh self-signed ECDSA leaf certificate valid
// for www.example.com (so the probe seam's canonical Host header and SNI
// verify), with a distinct key and serial per call — two calls produce two
// certificates with distinct DER encodings and fingerprints, which is what
// the redirect-leak test needs.
func leafCertForTest(t testing.TB, cn string, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{"www.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSWithCert starts an httptest TLS server presenting the given
// certificate.
func startTLSWithCert(t testing.TB, cert tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// pathRouter routes requests by path to two transports: "/" to a, any other
// path to b. It lets one probe walk a redirect between two different TLS
// backends presenting different certificates.
type pathRouter struct {
	a, b http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (r pathRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/" {
		return r.a.RoundTrip(req)
	}
	return r.b.RoundTrip(req)
}

// countingServer wraps an httptest server with a request counter, a
// concurrent-request tracker (global and per-Host-header), and an optional
// first-request hook. Handlers run concurrently; all access is mutex-guarded.
type countingServer struct {
	srv *httptest.Server

	mu         sync.Mutex
	count      int
	active     int
	maxActive  int
	hostActive map[string]int // in-flight requests per Host header
	hostMax    map[string]int // max in-flight per Host header
	firstSeen  chan struct{}  // closed on the first request (buffered once)
	firstHook  func()
	handle     func(w http.ResponseWriter, r *http.Request)
	sleep      time.Duration
	statusCode int
	body       []byte
	headers    map[string]string
}

// newCountingServer starts a plain-HTTP server whose handler records the
// request and serves the configured status, headers, and body (defaults:
// 200, "ok").
func newCountingServer(t testing.TB, status int, body string) *countingServer {
	return newCountingServerWith(t, status, body, false)
}

// newTLSCountingServer is the TLS variant: an https probe reaches the same
// handler over a real TLS handshake (httptest's certificate covers
// example.com and www.example.com).
func newTLSCountingServer(t testing.TB, status int, body string) *countingServer {
	return newCountingServerWith(t, status, body, true)
}

func newCountingServerWith(t testing.TB, status int, body string, tls bool) *countingServer {
	t.Helper()
	cs := &countingServer{
		firstSeen:  make(chan struct{}),
		statusCode: status,
		body:       []byte(body),
		headers:    make(map[string]string),
		hostActive: make(map[string]int),
		hostMax:    make(map[string]int),
	}
	if tls {
		cs.srv = httptest.NewTLSServer(http.HandlerFunc(cs.serve))
	} else {
		cs.srv = httptest.NewServer(http.HandlerFunc(cs.serve))
	}
	t.Cleanup(cs.srv.Close)
	return cs
}

func (cs *countingServer) serve(w http.ResponseWriter, r *http.Request) {
	cs.mu.Lock()
	cs.count++
	cs.active++
	if cs.active > cs.maxActive {
		cs.maxActive = cs.active
	}
	host := r.Host
	cs.hostActive[host]++
	if cs.hostActive[host] > cs.hostMax[host] {
		cs.hostMax[host] = cs.hostActive[host]
	}
	hook := cs.firstHook
	cs.firstHook = nil
	handle := cs.handle
	status := cs.statusCode
	body := cs.body
	headers := cs.headers
	sleep := cs.sleep
	cs.mu.Unlock()

	if hook != nil {
		select {
		case <-cs.firstSeen:
		default:
			close(cs.firstSeen)
		}
		hook()
	}
	defer func() {
		cs.mu.Lock()
		cs.active--
		cs.hostActive[host]--
		cs.mu.Unlock()
	}()
	if handle != nil {
		// The handler owns the complete response (status, headers, body).
		handle(w, r)
		return
	}
	if sleep > 0 {
		time.Sleep(sleep)
	}
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		w.Write(body)
	}
}

// requestCount reports the number of requests served.
func (cs *countingServer) requestCount() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.count
}

// maxConcurrent reports the maximum number of concurrently served requests.
func (cs *countingServer) maxConcurrent() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.maxActive
}

// maxConcurrentForHost reports the maximum number of concurrently served
// requests carrying the given Host header (the per-host concurrency the
// probe seam observes).
func (cs *countingServer) maxConcurrentForHost(host string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hostMax[host]
}

// setFirstHook arms a one-shot hook invoked exactly once, on the first
// request, before it is served (the request then proceeds normally).
func (cs *countingServer) setFirstHook(hook func()) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.firstHook = hook
}

// setHandler replaces the per-request response logic entirely.
func (cs *countingServer) setHandler(handle func(w http.ResponseWriter, r *http.Request)) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.handle = handle
}

// setSleep makes every request sleep before responding.
func (cs *countingServer) setSleep(d time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.sleep = d
}

// schemeRouter dispatches requests by scheme to two different transports, so
// tests can serve the http and https probes of one host from different
// deterministic backends.
type schemeRouter struct {
	httpRT  http.RoundTripper
	httpsRT http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (r schemeRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return r.httpsRT.RoundTrip(req)
	}
	return r.httpRT.RoundTrip(req)
}

// plainResponder is a deterministic "non-TLS server": it answers EVERY
// connection with a plain-text HTTP 400 and closes. A TLS ClientHello sent
// to it therefore fails the handshake with "tls: first record does not look
// like a TLS handshake" deterministically — unlike a real net/http server,
// which would block reading a binary ClientHello whenever it contains no
// newline byte.
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
				// A fixed, plain-text HTTP response: readable by an HTTP
				// client, and unreadable as a TLS first record by an https
				// client (deterministic TLS handshake failure).
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
// it. This matters because a JUST-FREED ephemeral port is not reliable on
// WSL2 (mirrored networking shares 127.0.0.1 with the Windows host): dialing
// one can transiently be answered by a phantom listener and reset (or even
// accepted) instead of refused, which flakes conn_refused tests. The
// behavior was reproduced with a standalone program, independent of this
// package.
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

// probeOne runs one Probe over the given server and host, returning the
// report. The http probes are routed to the given (plain) test server and
// the https probes to a deterministic plain-HTTP responder, so the https
// probe of a host served over plain HTTP fails its TLS handshake
// deterministically (completed, ReasonTLS). The declared domain is
// example.com.
func probeOne(t *testing.T, srv *httptest.Server, hosts []asset.Host, cfg Config) Report {
	t.Helper()
	pr := newPlainResponder(t)
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(t, srv),
		httpsRT: newTestTransport(pr.addr, nil),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"), hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return rep
}

// hostByName finds a host result by canonical name.
func hostByName(t testing.TB, rep Report, name string) HostResult {
	t.Helper()
	for _, hr := range rep.Results {
		if hr.Host.Name == name {
			return hr
		}
	}
	t.Fatalf("no result for host %q", name)
	return HostResult{}
}

// probeResultFor returns the probe result for the given scheme, or the zero
// ProbeResult when absent.
func probeResultFor(hr HostResult, scheme string) ProbeResult {
	for _, pr := range hr.Probes {
		if pr.Scheme == scheme {
			return pr
		}
	}
	return ProbeResult{}
}

// relationshipIDs renders a host result's relationships as sorted IDs for
// deterministic assertions.
func relationshipIDs(hr HostResult) []string {
	ids := make([]string, 0, len(hr.Relationships))
	for _, r := range hr.Relationships {
		ids = append(ids, r.ID())
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

// urlNames renders URL assets as canonical strings.
func urlNames(urls []asset.URL) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, u.String())
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// requireEqualStrings fails when the slices differ in length or element
// order.
func requireEqualStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// waitForGoroutines patience-waits until the goroutine count returns to at
// most baseline+2 (bounded patience, never timing-fragile: it only fails on
// a genuine leak). Mirrors the DNS pipeline's helper.
func waitForGoroutines(t *testing.T, baseline int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		goruntime.GC()
		if n := goruntime.NumGoroutine(); n <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := goruntime.NumGoroutine()
	t.Fatalf("goroutines = %d after run (baseline %d); possible leak", n, baseline)
}

// waitUntil patience-polls cond until it becomes true or budget elapses
// (bounded patience with small sleeps, never timing-fragile: it only fails
// on a genuine stall, not on a slow machine). Mirrors waitForGoroutines'
// patience convention.
func waitUntil(t *testing.T, what string, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not happen within %s", what, budget)
}
