package adapt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// httpProbeFixedTime is the deterministic provenance timestamp for adapter tests.
var httpProbeFixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// httpProbeFixedClock is a deterministic runtime.Clock: Now always returns httpProbeFixedTime,
// and After returns a channel that never fires. Adapter tests run with rate
// limiting disabled (DefaultStageConfig Rate 0), so no limiter wait is ever
// parked on the clock; After is never consulted.
type httpProbeFixedClock struct{}

func (httpProbeFixedClock) Now() time.Time { return httpProbeFixedTime }
func (httpProbeFixedClock) After(time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

var _ runtime.Clock = httpProbeFixedClock{}

// cannedResponse is one deterministic fake response for a probe target.
type cannedResponse struct {
	status    int
	body      string
	headers   map[string]string
	err       error                // when set, RoundTrip returns it (classifies the probe)
	oversized bool                 // when true, RoundTrip returns a body exceeding engine caps (1 MiB for httpprobe)
	tlsState  *tls.ConnectionState // when set, rides the response as resp.TLS (hermetic handshake state)
}

// cannedTransport is a hermetic http.RoundTripper: it answers every request
// from a per-host map (host -> scheme -> response) plus an optional
// path-scoped map (scheme://host/path -> response), records the requests it
// served, and never dials anything. An absent entry fails the probe with a
// DNS-style error (ProbeFailed/ReasonDNS), so "host not served" is expressed
// deterministically without touching the network. When blockUntil is non-nil
// (never closed), RoundTrip blocks until the request's context is done — the
// seam for in-flight cancellation and per-request-deadline tests.
//
// Path-scoped entries take precedence over host-only entries: a request for
// http://host/path is first looked up by its exact scheme://host/path key
// (including query when present), then by host/scheme. Bare-host entries
// (registered via cannedHost) answer both schemes for any path not
// explicitly registered; scheme-specific host entries answer one scheme.
// Oversized entries generate a body larger than the engine's retention cap
// (1 MiB for httpprobe) so truncation is exercised honestly.
type cannedTransport struct {
	mu         sync.Mutex
	byHost     map[string]map[string]cannedResponse
	byPath     map[string]cannedResponse // "scheme://host/path[?query]" -> response
	requests   []string                  // "scheme://host" of every served request
	blockUntil chan struct{}
}

// RoundTrip implements http.RoundTripper.
func (t *cannedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Scheme + "://" + req.URL.Host
	t.mu.Lock()
	t.requests = append(t.requests, key)
	// Path-scoped lookup first: exact scheme://host + path (+ query when present).
	pathKey := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	if req.URL.RawQuery != "" {
		pathKey += "?" + req.URL.RawQuery
	}
	resp, pathOk := t.byPath[pathKey]
	var hostOk bool
	var byScheme map[string]cannedResponse
	if !pathOk {
		byScheme, hostOk = t.byHost[req.URL.Host]
		if hostOk {
			resp = byScheme[req.URL.Scheme]
		}
	} else {
		hostOk = true
	}
	block := t.blockUntil
	t.mu.Unlock()

	if block != nil {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-block:
		}
	}

	if resp.err != nil {
		return nil, resp.err
	}
	if (!hostOk && !pathOk) || resp.status == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: req.URL.Host, IsTimeout: false}
	}
	body := resp.body
	if resp.oversized {
		// Exceed httpprobe MaxBodyBytes (1 MiB) and jsintel MaxJSBytes (2 MiB)
		// when the same transport is used for js fetches via the rewrite
		// seam — generate deterministically sized content so truncation is
		// honest without storing a huge literal in the manifest.
		body = strings.Repeat("x", (1<<20)+4096)
		// For the js path the body will be served via the same transport
		// in some tests; the larger 2 MiB+ body is also produced when the
		// request path indicates a js fetch (heuristic: ends with .js).
		if strings.HasSuffix(req.URL.Path, ".js") {
			body = strings.Repeat("x\n", (2<<20)/2+512)
		}
	}
	h := make(http.Header, len(resp.headers))
	for k, v := range resp.headers {
		h.Set(k, v)
	}
	out := &http.Response{
		StatusCode:    resp.status,
		Status:        fmt.Sprintf("%d %s", resp.status, http.StatusText(resp.status)),
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	// Hermetic TLS handshake state: when the canned response carries one,
	// it rides the response exactly like a real transport's would, so the
	// engine's 5C TLS capture observes the synthetic certificate without
	// any network or real handshake.
	if resp.tlsState != nil {
		out.TLS = resp.tlsState
	}
	return out, nil
}

// requestCount reports how many requests the transport has served.
func (t *cannedTransport) requestCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

// served reports whether a request for the given scheme://host was served.
func (t *cannedTransport) served(scheme, host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range t.requests {
		if r == scheme+"://"+host {
			return true
		}
	}
	return false
}

// httpProbeMustDomain normalizes a domain or fails the test.
func httpProbeMustDomain(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

// httpProbeMustHost normalizes a host or fails the test.
func httpProbeMustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// httpProbeMustURL normalizes a URL or fails the test.
func httpProbeMustURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// cannedHost registers canned responses for both probe schemes of a host.
func cannedHost(tr *cannedTransport, host string, resp cannedResponse) {
	if tr.byHost == nil {
		tr.byHost = make(map[string]map[string]cannedResponse)
	}
	tr.byHost[host] = map[string]cannedResponse{"http": resp, "https": resp}
}

// cannedHostPath registers one path-scoped canned response for a single
// scheme/host/path triple. It takes precedence over the host-only entries
// in RoundTrip: an exact scheme://host/path lookup is tried before the
// host/scheme fallback.
func cannedHostPath(tr *cannedTransport, host, scheme, path string, resp cannedResponse) {
	if tr.byPath == nil {
		tr.byPath = make(map[string]cannedResponse)
	}
	tr.byPath[scheme+"://"+host+path] = resp
}

// testStage returns the adapter under test with the given transport seam.
func testStage(tr http.RoundTripper) pipeline.Stage {
	return NewHTTPProbeStage(tr)
}

// httpProbeStageInput assembles a StageInput with the deterministic bounds, clock,
// params, and cache of one test.
func httpProbeStageInput(t testing.TB, target string, hosts []asset.Host, params map[string]string, c cache.Cache) pipeline.StageInput {
	t.Helper()
	return pipeline.StageInput{
		Target: httpProbeMustDomain(t, target),
		Hosts:  hosts,
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  httpProbeFixedClock{},
		Cache:  c,
	}
}

// httpProbeRunBounded runs the stage with a hard test-level bound, so a regression
// that hangs Run fails fast instead of wedging the suite.
func httpProbeRunBounded(t *testing.T, s pipeline.Stage, ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	t.Helper()
	type outcome struct {
		res pipeline.StageResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := s.Run(ctx, in)
		ch <- outcome{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-time.After(15 * time.Second):
		t.Fatal("stage Run did not finish within 15s")
		return pipeline.StageResult{}, errors.New("run timed out")
	}
}

// httpProbeWaitForRequests patience-polls until the transport has served at least n
// requests (bounded patience, small sleeps — it only fails on a genuine
// stall).
func httpProbeWaitForRequests(t *testing.T, tr *cannedTransport, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tr.requestCount() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("transport served %d requests, want at least %d", tr.requestCount(), n)
}

// httpProbeRequireStrings fails when the slices differ in length or element order.
func httpProbeRequireStrings(t *testing.T, what string, got, want []string) {
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

// httpProbeURLStrings renders URL assets as canonical strings.
func httpProbeURLStrings(urls []asset.URL) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, u.String())
	}
	return out
}

// httpProbeHostStrings renders host assets as canonical names.
func httpProbeHostStrings(hosts []asset.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return out
}

// TestHTTPProbeStageName pins the stage identity and the nil-transport
// construction (nil = production engine transport; the engine's bounded
// default transport is the engine's own tested behavior, never exercised
// here — the seam is injected in every other test).
func TestHTTPProbeStageName(t *testing.T) {
	if got := testStage(nil).Name(); got != pipeline.StageHTTPProbe {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageHTTPProbe)
	}
	if got := testStage(&cannedTransport{}).Name(); got != pipeline.StageHTTPProbe {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageHTTPProbe)
	}
}

// TestHTTPProbeStageAliveHostsAdditions verifies the happy path: live hosts
// fold to completed and their hosts and probe-target URLs become Additions.
func TestHTTPProbeStageAliveHostsAdditions(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "api.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 2/0", res.ItemsProcessed, res.ItemsFailed)
	}
	httpProbeRequireStrings(t, "Additions.Hosts", httpProbeHostStrings(res.Additions.Hosts),
		[]string{"api.example.com", "www.example.com"})
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{
			"http://api.example.com/",
			"http://www.example.com/",
			"https://api.example.com/",
			"https://www.example.com/",
		})
	if got := tr.requestCount(); got != 4 {
		t.Fatalf("requests = %d, want 4", got)
	}
}

// TestHTTPProbeStageResultsChannel pins the T3d results wiring: the engine's
// canonical Phase 2 assets flow through the results channel — open ports,
// confirmed services, probe endpoints, and the graph edges — while IPs stay
// empty (the corpus has no IPs; the adapter's ips map is nil, v1.3 note) and
// TLS certificates stay empty (the canned transport completes no real TLS
// handshake, so no 5C observation exists).
func TestHTTPProbeStageResultsChannel(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "api.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}

	// Open ports are host-agnostic assets ("80/tcp", "443/tcp"), merged
	// across both hosts.
	var portStrs []string
	for _, p := range res.Results.Ports {
		portStrs = append(portStrs, p.String())
	}
	requireEqualStrings(t, "results ports", portStrs, []string{"443/tcp", "80/tcp"})

	// Services are host-agnostic too: the canonical Service identity is
	// Port.String() + "/" + encoded name (asset/service.go), and the engine
	// builds its probe ports with Protocol "tcp" (httpprobe observe.go
	// portForScheme) — so the canonical identities carry the protocol:
	// https on 443/tcp and http on 80/tcp. The adapter copies the engine's
	// canonical assets and never rebuilds them, so these are exactly the
	// forms the report produced.
	var svcStrs []string
	for _, s := range res.Results.Services {
		svcStrs = append(svcStrs, s.Identity().String())
	}
	requireEqualStrings(t, "results services", svcStrs, []string{"service:443/tcp/https", "service:80/tcp/http"})

	// One endpoint per probe target URL (GET on each of the 4 scheme-host
	// pairs).
	requireEqualStrings(t, "results endpoints", endpointStrings(res.Results.Endpoints), []string{
		"GET http://api.example.com/",
		"GET http://www.example.com/",
		"GET https://api.example.com/",
		"GET https://www.example.com/",
	})

	// Edges: per host host->url (2) + url->endpoint (2) + port->service (2)
	// = 6, across 2 hosts = 12. The port->service edges repeat across the
	// two hosts: the engine's per-host assemble() dedupes within a host
	// only, and AllRelationships sorts without cross-host dedup — collapsing
	// the duplicates is the RUNNER's first-seen per-edge merge
	// (mergeResults), not the adapter's job.
	if got := len(res.Results.Relationships); got != 12 {
		t.Errorf("results relationships = %d, want 12 (6 per host x 2 hosts)", got)
	}

	// No IPs and no TLS certificates: the IPs channel IS wired (AllIPs from
	// the report) but the engine derives IP assets only from caller-provided
	// addresses, and this adapter passes no ips map (the corpus carries no
	// IPs — v1.3 note), so the honest result is empty. TLS certificates
	// stay empty because the canned transport completes no real TLS
	// handshake, so no 5C observation exists.
	if len(res.Results.IPs) != 0 {
		t.Errorf("results IPs = %v, want empty (the corpus has no IPs)", res.Results.IPs)
	}
	if len(res.Results.TLSCertificates) != 0 {
		t.Errorf("results TLS certificates = %d, want 0 (no 5C observation)", len(res.Results.TLSCertificates))
	}
}

// endpointStrings renders endpoint assets as their canonical identity value.
func endpointStrings(eps []asset.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.Identity().Value)
	}
	return out
}

// TestHTTPProbeStageResultsDeterminism pins the determinism contract for the
// results channel: two identical runs over the same canned transport
// (fixed clock) produce DeepEqual StageResults, including every results
// channel the stage contributes — ports, services, endpoints, and
// relationships (IPs and TLS certificates stay empty through this adapter,
// as pinned above).
func TestHTTPProbeStageResultsDeterminism(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})

	run := func() pipeline.StageResult {
		t.Helper()
		in := httpProbeStageInput(t, "example.com", []asset.Host{
			httpProbeMustHost(t, "www.example.com"),
			httpProbeMustHost(t, "api.example.com"),
		}, nil, nil)
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}
	res1, res2 := run(), run()
	if !reflect.DeepEqual(res1, res2) {
		t.Fatalf("two identical runs differ:\nrun 1: %+v\nrun 2: %+v", res1, res2)
	}
	if len(res1.Results.Ports) == 0 || len(res1.Results.Services) == 0 ||
		len(res1.Results.Endpoints) == 0 || len(res1.Results.Relationships) == 0 {
		t.Fatal("determinism pin exercised no results output (ports/services/endpoints/relationships all empty)")
	}
}

// TestHTTPProbeStageOutOfDomainInputFiltered verifies the mandatory input
// boundary: an out-of-domain corpus host is filtered out before the engine
// sees the list — the engine rejects the whole call on any out-of-domain
// host, so a successful run with the host absent from every request and
// addition proves the filter ran first.
func TestHTTPProbeStageOutOfDomainInputFiltered(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "evil.example.net"), // out-of-domain: must never reach the engine
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v (an out-of-domain host reaching the engine rejects the call)", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 1/0 (only the in-domain host is processed)", res.ItemsProcessed, res.ItemsFailed)
	}
	httpProbeRequireStrings(t, "Additions.Hosts", httpProbeHostStrings(res.Additions.Hosts), []string{"www.example.com"})
	for _, u := range res.Additions.URLs {
		if strings.Contains(u.HostPort, "evil.example.net") {
			t.Fatalf("out-of-domain URL leaked into additions: %s", u)
		}
	}
	if tr.served("http", "evil.example.net") || tr.served("https", "evil.example.net") {
		t.Fatal("the engine probed an out-of-domain host")
	}
	if !tr.served("http", "www.example.com") || !tr.served("https", "www.example.com") {
		t.Fatal("the engine did not probe the in-domain host")
	}
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// TestHTTPProbeStageOutOfDomainURLsFiltered pins the output-side URL filter
// directly: in-domain hosts (including a port-bearing canonical URL) are
// kept, while out-of-domain hosts, IP literals, and the zero URL are dropped.
// The engine's probe targets are always in-domain by construction, so this
// defensive boundary is exercised through its helper.
func TestHTTPProbeStageOutOfDomainURLsFiltered(t *testing.T) {
	declared := httpProbeMustDomain(t, "example.com")
	urls := []asset.URL{
		httpProbeMustURL(t, "http://www.example.com/"),
		httpProbeMustURL(t, "http://api.example.com:8080/"), // non-default port retained in HostPort
		httpProbeMustURL(t, "http://evil.example.net/"),     // out-of-domain
		httpProbeMustURL(t, "http://93.184.216.34/"),        // IP literal: never in-domain
		httpProbeMustURL(t, "http://[2001:db8::1]/"),        // IPv6 literal: never in-domain
		{}, // zero URL: never a valid observation
	}
	// filterURLs is stable: it preserves input order (deterministic), so the
	// expected slice mirrors the input's in-domain entries in input order.
	got := filterURLs(declared, urls)
	httpProbeRequireStrings(t, "filtered URLs", httpProbeURLStrings(got),
		[]string{"http://www.example.com/", "http://api.example.com:8080/"})

	// The host extraction used by the filter is the asset model's canonical
	// form: a port-bearing host strips back to the bare hostname.
	h, ok := urlHost(httpProbeMustURL(t, "http://api.example.com:8080/"))
	if !ok || h.Name != "api.example.com" {
		t.Fatalf("urlHost(port-bearing) = %q/%v, want api.example.com/true", h.Name, ok)
	}
	if _, ok := urlHost(httpProbeMustURL(t, "http://93.184.216.34/")); ok {
		t.Fatal("urlHost accepted an IP literal")
	}
	if _, ok := urlHost(asset.URL{}); ok {
		t.Fatal("urlHost accepted a zero URL")
	}
}

// TestHTTPProbeStageAllFailed verifies the all-failed fold: every probe of
// every host failed, so the stage is failed with the honest counters; the
// probe targets are still retained as Additions (the stage's honest retained
// output, merged even from a failed stage).
func TestHTTPProbeStageAllFailed(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{err: &net.DNSError{Err: "no such host", Name: "www.example.com"}})

	in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	httpProbeRequireStrings(t, "Additions.Hosts", httpProbeHostStrings(res.Additions.Hosts), []string{"www.example.com"})
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{"http://www.example.com/", "https://www.example.com/"})
}

// TestHTTPProbeStageMixedPartial verifies the mixed fold: some hosts
// completed, some failed — the stage is partial with the honest failed count.
func TestHTTPProbeStageMixedPartial(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHost(tr, "dead.example.com", cannedResponse{err: &net.DNSError{Err: "no such host", Name: "dead.example.com"}})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "dead.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want partial", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 2/1", res.ItemsProcessed, res.ItemsFailed)
	}
	httpProbeRequireStrings(t, "Additions.Hosts", httpProbeHostStrings(res.Additions.Hosts),
		[]string{"dead.example.com", "www.example.com"})
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{
			"http://dead.example.com/",
			"http://www.example.com/",
			"https://dead.example.com/",
			"https://www.example.com/",
		})
}

// TestHTTPProbeStageFailedWithIncompleteOnly pins the unified fold corner
// (MEDIUM-1 review unification): failed + engine-incomplete with no completed
// host folds to failed, exactly like the dns adapter — the unified shape is
// cancelled > failed&&!completed > completed > partial, so an incomplete host
// can no longer demote an otherwise-failed run to partial. (Prior behavior:
// anyFailed && !anyCompleted && !anyIncomplete held failed, so this corner
// fell through to partial.)
func TestHTTPProbeStageFailedWithIncompleteOnly(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "example.com"}
	tr := &cannedTransport{}
	// Per-scheme responses (cannedHost sets both schemes identically, so
	// build the map directly): dead.example.com fails every probe →
	// StatusFailed; mix.example.com completes http but fails https →
	// StatusIncomplete (one failed + one completed probe).
	tr.byHost = map[string]map[string]cannedResponse{
		"dead.example.com": {
			"http":  {err: dnsErr},
			"https": {err: dnsErr},
		},
		"mix.example.com": {
			"http":  {status: 200, body: "ok"},
			"https": {err: dnsErr},
		},
	}

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "dead.example.com"),
		httpProbeMustHost(t, "mix.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed (failed + incomplete with no completed host)", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 2/1 (only the all-failed host counts as failed)", res.ItemsProcessed, res.ItemsFailed)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	httpProbeRequireStrings(t, "Additions.Hosts", httpProbeHostStrings(res.Additions.Hosts),
		[]string{"dead.example.com", "mix.example.com"})
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{
			"http://dead.example.com/",
			"http://mix.example.com/",
			"https://dead.example.com/",
			"https://mix.example.com/",
		})
}

// TestHTTPProbeStageCancellation verifies both cancellation paths: a context
// cancelled before the engine is invoked reports cancelled with the context
// error (the engine rejects a pre-cancelled context), and an in-flight
// cancellation reports cancelled while retaining the honest observations.
func TestHTTPProbeStageCancellation(t *testing.T) {
	t.Run("pre-cancelled context", func(t *testing.T) {
		tr := &cannedTransport{}
		cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, nil)
		res, err := httpProbeRunBounded(t, testStage(tr), ctx, in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
		}
		if !errors.Is(res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", res.Err)
		}
		if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 0/0 (no report)", res.ItemsProcessed, res.ItemsFailed)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never invoked)", got)
		}
	})

	t.Run("in-flight cancellation", func(t *testing.T) {
		tr := &cannedTransport{}
		cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
		tr.blockUntil = make(chan struct{}) // never closed: block every request

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		type outcome struct {
			res pipeline.StageResult
			err error
		}
		ch := make(chan outcome, 1)
		go func() {
			res, err := testStage(tr).Run(ctx, httpProbeStageInput(t, "example.com",
				[]asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, nil))
			ch <- outcome{res, err}
		}()

		httpProbeWaitForRequests(t, tr, 1) // the http probe is in flight, parked on blockUntil
		cancel()

		var o outcome
		select {
		case o = <-ch:
		case <-time.After(15 * time.Second):
			t.Fatal("stage Run did not finish within 15s after cancellation")
		}
		if o.err != nil {
			t.Fatalf("Run: %v", o.err)
		}
		if o.res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", o.res.Outcome)
		}
		if !errors.Is(o.res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", o.res.Err)
		}
		if o.res.ItemsProcessed != 1 {
			t.Fatalf("ItemsProcessed = %d, want 1 (the host was observed)", o.res.ItemsProcessed)
		}
		// The probe targets of the observed host are the stage's honest
		// retained output, even on cancellation.
		httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(o.res.Additions.URLs),
			[]string{"http://www.example.com/", "https://www.example.com/"})
	})
}

// TestHTTPProbeStageCachePassedThrough verifies that in.Cache reaches the
// engine's cache-before-execute: the first run probes and stores completed
// records, the second run with the same cache issues ZERO network requests
// and still reports completed with the same additions.
func TestHTTPProbeStageCachePassedThrough(t *testing.T) {
	c, err := cache.Open(t.TempDir(), cache.WithClock(httpProbeFixedClock{}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})

	run := func() pipeline.StageResult {
		t.Helper()
		in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, c)
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	res1 := run()
	if res1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("first run Outcome = %q, want completed", res1.Outcome)
	}
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("first run requests = %d, want 2 (one miss per probe target)", got)
	}

	res2 := run()
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("second run Outcome = %q, want completed (served from cache)", res2.Outcome)
	}
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("second run requests = %d, want 2 (unchanged: a cache hit performs zero requests)", got)
	}
	httpProbeRequireStrings(t, "second run Additions.URLs", httpProbeURLStrings(res2.Additions.URLs),
		[]string{"http://www.example.com/", "https://www.example.com/"})
}

// TestHTTPProbeStageEmptyFilteredShortCircuit verifies the empty-filtered
// short-circuit: when every corpus host is out-of-domain the stage completes
// with zero additions and zero counters WITHOUT invoking the engine (the
// transport serves nothing). A cancelled context on that path reports
// cancelled, mirroring the engine, which checks the context before its own
// empty-list branch.
func TestHTTPProbeStageEmptyFilteredShortCircuit(t *testing.T) {
	t.Run("completed short-circuit", func(t *testing.T) {
		tr := &cannedTransport{}
		in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "evil.example.net")}, nil, nil)
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", res.Outcome)
		}
		if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
		}
		if len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
			t.Fatalf("additions = %v/%v, want empty", res.Additions.Hosts, res.Additions.URLs)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never called)", got)
		}
	})

	t.Run("cancelled short-circuit", func(t *testing.T) {
		tr := &cannedTransport{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "evil.example.net")}, nil, nil)
		res, err := httpProbeRunBounded(t, testStage(tr), ctx, in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
		}
		if !errors.Is(res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", res.Err)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never called)", got)
		}
	})

	t.Run("non-canonical target falls through to the engine", func(t *testing.T) {
		// LOW-1 review finding: the short-circuit must not mask the engine's
		// own scope-validation error for a hand-built non-canonical target
		// ("Example.com" is not the form asset.NewDomain produces), exactly
		// as the dns adapter behaves.
		tr := &cannedTransport{}
		in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "evil.example.net")}, nil, nil)
		in.Target = asset.Domain{Name: "Example.com"}
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if res.Outcome != pipeline.OutcomeFailed {
			t.Fatalf("Outcome = %q, want failed (the engine's scope error surfaces)", res.Outcome)
		}
		if err == nil || !strings.Contains(err.Error(), "stage httpprobe:") {
			t.Fatalf("err = %v, want a wrapped stage error", err)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (the engine rejected the call before probing)", got)
		}
	})
}

// TestRequestTimeoutParamParsing pins the request_timeout StageParam
// parsing: a valid positive Go duration passes through; absent, unparseable,
// zero, and negative values resolve to 0 (the engine's 10 s default); unknown
// params are ignored.
func TestRequestTimeoutParamParsing(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		want   time.Duration
	}{
		{"absent", nil, 0},
		{"empty", map[string]string{"request_timeout": ""}, 0},
		{"unparseable", map[string]string{"request_timeout": "bogus"}, 0},
		{"bare number", map[string]string{"request_timeout": "5"}, 0},
		{"zero", map[string]string{"request_timeout": "0s"}, 0},
		{"negative clamped to default", map[string]string{"request_timeout": "-5s"}, 0},
		{"seconds", map[string]string{"request_timeout": "5s"}, 5 * time.Second},
		{"milliseconds", map[string]string{"request_timeout": "1500ms"}, 1500 * time.Millisecond},
		{"unknown params ignored", map[string]string{"other_key": "5s"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestTimeoutFromParams(tc.params); got != tc.want {
				t.Fatalf("requestTimeoutFromParams(%v) = %v, want %v", tc.params, got, tc.want)
			}
		})
	}
}

// TestHTTPProbeStageRequestTimeoutParam verifies end-to-end that the
// request_timeout StageParam reaches the engine: with a transport that blocks
// every request and a 50 ms per-request deadline, the probes fail on the
// deadline (failed/timeout) and the run completes promptly. The stage context
// is bounded to 3 s, so a broken parse (deadline silently defaulted to the
// engine's 10 s) surfaces as cancelled instead of failed — failing fast.
func TestHTTPProbeStageRequestTimeoutParam(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	tr.blockUntil = make(chan struct{}) // never closed: every request parks until its deadline

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"request_timeout": "50ms"}, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), ctx, in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed (both probes hit the 50 ms per-request deadline)", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestHTTPProbeStageTruncatedFlag verifies that the engine's truncation
// marker is never swallowed: a response with more headers than the engine's
// retention cap truncates the probe (ProbeStatus "truncated-incomplete"),
// which folds the host to incomplete → partial, and records Truncated with
// the probe_truncated sticky flag (AGENTS §0.6).
func TestHTTPProbeStageTruncatedFlag(t *testing.T) {
	// MaxHeaders (the engine's retention cap) is 128; serve 130 headers so
	// boundedHeaders truncates deterministically. The whole block stays far
	// below the 64 KiB byte cap (which the canned transport does not enforce).
	headers := make(map[string]string, 130)
	for i := 0; i < 130; i++ {
		headers[fmt.Sprintf("X-Test-%03d", i)] = "v"
	}
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok", headers: headers})

	in := httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want partial (host folded incomplete: truncated probes)", res.Outcome)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (the truncation marker must never be swallowed)")
	}
	if !res.StickyFlags[HTTPProbeStickyFlag] {
		t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, HTTPProbeStickyFlag)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 1/0 (incomplete is partial, not failed)", res.ItemsProcessed, res.ItemsFailed)
	}
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{"http://www.example.com/", "https://www.example.com/"})
}

// httpProbeMarkedCert builds a synthetic TLS certificate asset carrying the
// asset model's DNSNamesTruncated marker (a MergeTLSCertificates union cut
// at the model's 32-name cap). The marker cannot arise from a live probe
// today (same-fingerprint observations carry identical SAN lists, so the
// engine's union never exceeds the cap), which is exactly why the adapter
// wiring is pinned at the buildResult boundary with a synthetic report.
func httpProbeMarkedCert(t testing.TB, marked bool) asset.TLSCertificate {
	t.Helper()
	c, err := asset.NewTLSCertificate(fmt.Sprintf("%064x", 1), asset.Provenance{Source: "synthetic"})
	if err != nil {
		t.Fatalf("NewTLSCertificate: %v", err)
	}
	c.DNSNamesTruncated = marked
	return c
}

// TestHTTPProbeStageTLSDNSNamesTruncatedFlag pins the OPT-P1-4 adapter
// wiring: a returned certificate carrying TLSCertificate.DNSNamesTruncated
// sets Truncated and the probe_tls_dns_names_truncated sticky flag while the
// outcome stays whatever the probes earned (completed + flag is the legal
// §0.6 carve-out); an unmarked certificate sets neither.
func TestHTTPProbeStageTLSDNSNamesTruncatedFlag(t *testing.T) {
	target := httpProbeMustDomain(t, "example.com")
	host := httpProbeMustHost(t, "www.example.com")

	marked := httpprobe.Report{
		Target: target,
		Results: []httpprobe.HostResult{{
			Host:            host,
			Status:          httpprobe.StatusCompleted,
			TLSCertificates: []asset.TLSCertificate{httpProbeMarkedCert(t, true)},
		}},
	}
	res := buildResult(target, marked, pipeline.OutcomeCompleted, nil, probeResultOptions{sanExpansion: true})
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("outcome = %s, want completed (the marker never changes the outcome)", res.Outcome)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true (an asset-level drop marker is never swallowed)")
	}
	if !res.StickyFlags[HTTPProbeTLSDNSNamesStickyFlag] {
		t.Errorf("StickyFlags = %v, want %q set", res.StickyFlags, HTTPProbeTLSDNSNamesStickyFlag)
	}
	if len(res.Results.TLSCertificates) != 1 || !res.Results.TLSCertificates[0].DNSNamesTruncated {
		t.Error("the returned certificates must carry the marker through unchanged")
	}

	clean := httpprobe.Report{
		Target: target,
		Results: []httpprobe.HostResult{{
			Host:            host,
			Status:          httpprobe.StatusCompleted,
			TLSCertificates: []asset.TLSCertificate{httpProbeMarkedCert(t, false)},
		}},
	}
	resClean := buildResult(target, clean, pipeline.OutcomeCompleted, nil, probeResultOptions{sanExpansion: true})
	if resClean.Truncated || len(resClean.StickyFlags) != 0 {
		t.Errorf("unmarked certs: Truncated=%v StickyFlags=%v, want no signal",
			resClean.Truncated, resClean.StickyFlags)
	}
}

// TestHTTPProbeStageTruncationFlagsAccumulate pins that the per-probe cap
// signal and the asset-level SAN-name merge marker can fire together and
// their flags ACCUMULATE (no clobbering).
func TestHTTPProbeStageTruncationFlagsAccumulate(t *testing.T) {
	target := httpProbeMustDomain(t, "example.com")
	host := httpProbeMustHost(t, "www.example.com")
	rep := httpprobe.Report{
		Target: target,
		Results: []httpprobe.HostResult{{
			Host:            host,
			Status:          httpprobe.StatusIncomplete,
			Probes:          []httpprobe.ProbeResult{{Status: httpprobe.ProbeTruncated, Truncated: true}},
			TLSCertificates: []asset.TLSCertificate{httpProbeMarkedCert(t, true)},
		}},
	}
	res := buildResult(target, rep, pipeline.OutcomePartial, nil, probeResultOptions{sanExpansion: true})
	if !res.Truncated {
		t.Fatal("Truncated = false, want true when both signals fire")
	}
	if len(res.StickyFlags) != 2 ||
		!res.StickyFlags[HTTPProbeStickyFlag] ||
		!res.StickyFlags[HTTPProbeTLSDNSNamesStickyFlag] {
		t.Errorf("StickyFlags = %v, want both %q and %q set",
			res.StickyFlags, HTTPProbeStickyFlag, HTTPProbeTLSDNSNamesStickyFlag)
	}
}

// TestHTTPProbeStageTLSDNSNamesMarkerCacheRoundTrip pins the §0.6 chain for
// the marker across a cache round trip: the flag survives encode → decode
// (what a warm run serves from a stored record) and STILL fires on the
// replayed assets — computed from whatever the stage returns, on every path.
func TestHTTPProbeStageTLSDNSNamesMarkerCacheRoundTrip(t *testing.T) {
	target := httpProbeMustDomain(t, "example.com")
	host := httpProbeMustHost(t, "www.example.com")

	data, err := json.Marshal(httpProbeMarkedCert(t, true))
	if err != nil {
		t.Fatal(err)
	}
	var replayed asset.TLSCertificate
	if err := json.Unmarshal(data, &replayed); err != nil {
		t.Fatal(err)
	}
	if !replayed.DNSNamesTruncated {
		t.Fatal("marker lost in encode → decode; the warm run could never fire the flag")
	}

	rep := httpprobe.Report{
		Target: target,
		Results: []httpprobe.HostResult{{
			Host:            host,
			Status:          httpprobe.StatusCompleted,
			TLSCertificates: []asset.TLSCertificate{replayed},
		}},
	}
	res := buildResult(target, rep, pipeline.OutcomeCompleted, nil, probeResultOptions{sanExpansion: true})
	if !res.Truncated || !res.StickyFlags[HTTPProbeTLSDNSNamesStickyFlag] {
		t.Errorf("warm-run replay: Truncated=%v StickyFlags=%v, want the flag to fire from the replayed marker",
			res.Truncated, res.StickyFlags)
	}
}

// syntheticTLSCert returns a self-signed leaf certificate carrying the given
// subject CN and SAN DNS names (synthetic values only — never real target
// data), suitable for a hermetic tls.ConnectionState fixture.
func syntheticTLSCert(t testing.TB, cn string, sans ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// tlsStateFor wraps a leaf in a ConnectionState shaped like a completed
// handshake (the engine's captureTLS reads PeerCertificates and the
// negotiated protocol only).
func tlsStateFor(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
}

// registerHTTPSWithTLS registers an https-only canned response carrying the
// given handshake state (the http scheme stays TLS-free, modeling reality).
func registerHTTPSWithTLS(tr *cannedTransport, host string, resp cannedResponse) {
	if tr.byHost == nil {
		tr.byHost = make(map[string]map[string]cannedResponse)
	}
	tr.byHost[host] = map[string]cannedResponse{
		"http":  {status: resp.status, body: resp.body},
		"https": resp,
	}
}

// TestHTTPProbeStageTLSSANExpansion is the Enhancement A acceptance proof:
// a canned https response whose synthetic leaf carries an unlisted in-domain
// SAN ("hidden.example.com") plus one already-known name ("api.example.com"
// arrives via the corpus) — the unlisted SAN appears in Additions.Hosts, the
// known one does not duplicate, and probing itself still folds completed.
func TestHTTPProbeStageTLSSANExpansion(t *testing.T) {
	tr := &cannedTransport{}
	cert := syntheticTLSCert(t, "www.example.com",
		"www.example.com", "hidden.example.com", "api.example.com")
	registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})
	// api.example.com is already in the corpus — serve it so its own probes
	// complete (the dedup claim under test is about SAN expansion, not the
	// per-host outcome fold).
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "api.example.com"), // already in the corpus
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if len(res.Results.TLSCertificates) != 1 {
		t.Fatalf("TLSCertificates = %d, want 1 (the canned handshake)", len(res.Results.TLSCertificates))
	}
	got := httpProbeHostStrings(res.Additions.Hosts)
	// Engine-sorted report hosts first (api, www), the SAN-derived newcomer
	// appended after — the documented deterministic placement.
	want := []string{"api.example.com", "www.example.com", "hidden.example.com"}
	httpProbeRequireStrings(t, "Additions.Hosts", got, want)

	// Provenance marks the SAN-derived host.
	var provOK bool
	for _, h := range res.Additions.Hosts {
		if h.Name == "hidden.example.com" && h.Prov.Source == "tls-san" {
			provOK = true
		}
	}
	if !provOK {
		t.Fatalf("SAN-derived host provenance missing (want Source %q)", "tls-san")
	}
}

// TestHTTPProbeStageTLSSANExpansionDisabled pins the opt-out: the exact value
// "false" keeps additions exactly what the engine report produced.
func TestHTTPProbeStageTLSSANExpansionDisabled(t *testing.T) {
	tr := &cannedTransport{}
	cert := syntheticTLSCert(t, "www.example.com",
		"www.example.com", "hidden.example.com")
	registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, map[string]string{"tls_san_expansion": "false"}, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := httpProbeHostStrings(res.Additions.Hosts)
	want := []string{"www.example.com"}
	httpProbeRequireStrings(t, "Additions.Hosts", got, want)
	if len(res.Results.TLSCertificates) != 1 {
		t.Fatalf("TLSCertificates = %d, want 1 (capture unaffected by the gate)",
			len(res.Results.TLSCertificates))
	}
}

// TestHTTPProbeStageTLSSANExpansionDropsNonHosts pins the boundary: wildcard
// and IP-literal SANs are not Host assets, out-of-domain SANs leave scope,
// and only the valid in-domain newcomer survives.
func TestHTTPProbeStageTLSSANExpansionDropsNonHosts(t *testing.T) {
	tr := &cannedTransport{}
	cert := syntheticTLSCert(t, "www.example.com",
		"*.example.com",     // wildcard: not a hostname asset
		"192.168.1.1",       // IP literal: routed to the IP asset class, rejected here
		"evil.example.net",  // out-of-domain: dropped by the mandatory output filter
		"fresh.example.com", // the only qualifier
	)
	registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := httpProbeHostStrings(res.Additions.Hosts)
	// Report hosts first, SAN-derived names appended after (sorted among
	// themselves) — the documented deterministic placement.
	want := []string{"www.example.com", "fresh.example.com"}
	httpProbeRequireStrings(t, "Additions.Hosts", got, want)
}

// TestHTTPProbeStageTLSSANExpansionNoCertificates guards the default path:
// without TLS observations (every pre-existing canned run) expansion is inert
// and results carry no certificates.
func TestHTTPProbeStageTLSSANExpansionNoCertificates(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, nil, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := httpProbeHostStrings(res.Additions.Hosts)
	want := []string{"www.example.com"}
	httpProbeRequireStrings(t, "Additions.Hosts", got, want)
	if len(res.Results.TLSCertificates) != 0 {
		t.Fatalf("TLSCertificates = %d, want 0", len(res.Results.TLSCertificates))
	}
}

// takeoverCNAMEFixture builds DNS-edge fixtures: ghost has a CNAME to a
// target with no addresses (dangling); www has a CNAME to a target WITH
// addresses (resolving, never a candidate).
func takeoverCNAMEFixture(t testing.TB) (ghost, www asset.Host, rels []asset.Relationship) {
	t.Helper()
	ghost = httpProbeMustHost(t, "ghost.example.com")
	www = httpProbeMustHost(t, "www.example.com")
	dangling := httpProbeMustHost(t, "dangling.example.net")
	cdn := httpProbeMustHost(t, "cdn.example.net")
	mkrel := func(from asset.Host, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
		r, err := asset.NewRelationship(from.Identity(), kind, to)
		if err != nil {
			t.Fatalf("NewRelationship: %v", err)
		}
		return r
	}
	ip, err := asset.NewIP("93.184.216.34", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	rels = []asset.Relationship{
		mkrel(ghost, asset.RelationshipHostToCNAME, dangling.Identity()),
		mkrel(www, asset.RelationshipHostToCNAME, cdn.Identity()),
		mkrel(cdn, asset.RelationshipHostToIP, ip.Identity()),
	}
	return ghost, www, rels
}

// TestConfirmTakeoverTransportErrorFlag pins the review-wave honesty
// fix: verdicts carrying transport errors mark the confirmation set
// truncated — an unreachable host is never silently completed.
func TestConfirmTakeoverTransportErrorFlag(t *testing.T) {
	stage := &HTTPProbeStage{transport: &failLiveTransport{}}
	in := httpProbeStageInput(t, "example.com",
		[]asset.Host{httpProbeMustHost(t, "ghost.example.com")}, nil, nil)
	cfg := httpprobe.Config{
		Concurrency: 2,
		QueueSize:   4,
		Transport:   &failLiveTransport{},
	}
	evs, truncated, err := stage.confirmTakeover(context.Background(), in,
		[]asset.Host{httpProbeMustHost(t, "ghost.example.com")}, cfg)
	if err != nil {
		t.Fatalf("confirmTakeover hard error = %v, want nil (per-host errors stay in verdicts)", err)
	}
	if len(evs) != 0 {
		t.Fatalf("evidence = %d, want 0", len(evs))
	}
	if !truncated {
		t.Fatal("truncated = false, want true (errored verdicts are an incomplete set)")
	}
}

// TestHTTPProbeStageTakeoverConfirms pins NEW-122 end to end at stage
// level: a dangling host's provider page becomes takeover evidence,
// while a resolving CNAME host is never fetched for confirmation.
func TestHTTPProbeStageTakeoverConfirms(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "ghost.example.com", cannedResponse{status: 200, body: "roots"})
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "roots"})
	cannedHostPath(tr, "ghost.example.com", "https", "/", cannedResponse{status: 404, body: "<h1>There isn't a GitHub Pages site here.</h1>"})
	cannedHostPath(tr, "ghost.example.com", "http", "/", cannedResponse{status: 404, body: "<h1>There isn't a GitHub Pages site here.</h1>"})
	ghost, www, rels := takeoverCNAMEFixture(t)
	stage := &HTTPProbeStage{transport: tr}
	in := httpProbeStageInput(t, "example.com", []asset.Host{ghost, www}, nil, nil)
	in.Results.Relationships = rels

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Evidence for the dangling host only, parsed back through the
	// pack-facing contract.
	found := false
	for _, ev := range res.Results.Evidence {
		provider, ok := httpprobe.ParseTakeoverEvidence(ev)
		if !ok {
			t.Fatalf("non-takeover evidence in takeover output: %+v", ev)
		}
		if ev.Source.String() != "host:ghost.example.com" {
			t.Errorf("evidence source = %s, want the dangling host", ev.Source)
		}
		if provider != "github-pages" {
			t.Errorf("provider = %q, want github-pages", provider)
		}
		found = true
	}
	if !found {
		t.Fatal("no takeover evidence for the confirmed dangling host")
	}
	// Roots (2×2) + confirmation pair for ghost only: www's resolving
	// CNAME is never fetched for confirmation.
	if got := tr.requestCount(); got != 6 {
		t.Errorf("requests = %d, want 6 (4 roots + ghost confirmation pair)", got)
	}
}

// TestHTTPProbeStageTakeoverSilentNoEvidence pins the quiet path: a
// dangling host serving a clean page yields no evidence and no flags.
func TestHTTPProbeStageTakeoverSilentNoEvidence(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "ghost.example.com", cannedResponse{status: 200, body: "<h1>legit site</h1>"})
	ghost, _, rels := takeoverCNAMEFixture(t)
	stage := &HTTPProbeStage{transport: tr}
	in := httpProbeStageInput(t, "example.com", []asset.Host{ghost}, nil, nil)
	in.Results.Relationships = rels

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("evidence = %v, want none (clean page)", res.Results.Evidence)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("truncated/flags = %v/%v, want clean", res.Truncated, res.StickyFlags)
	}
}

// TestHTTPProbeStageTakeoverDisabled pins the opt-out: takeover_confirm
// false means no confirmation traffic and no evidence.
func TestHTTPProbeStageTakeoverDisabled(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "ghost.example.com", cannedResponse{status: 200, body: "roots"})
	cannedHostPath(tr, "ghost.example.com", "https", "/", cannedResponse{status: 404, body: "There isn't a GitHub Pages site here."})
	ghost, _, rels := takeoverCNAMEFixture(t)
	stage := &HTTPProbeStage{transport: tr}
	in := httpProbeStageInput(t, "example.com", []asset.Host{ghost},
		map[string]string{"takeover_confirm": "false"}, nil)
	in.Results.Relationships = rels

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("evidence = %v, want none (confirmation disabled)", res.Results.Evidence)
	}
	if got := tr.requestCount(); got != 2 {
		t.Errorf("requests = %d, want 2 (roots only)", got)
	}
}

// TestHTTPProbeStageTakeoverOverflowFlag pins the per-run candidate
// bound: beyond maxTakeoverConfirmHosts the sorted head is confirmed
// and the cut rides the flag on a completed result.
func TestHTTPProbeStageTakeoverOverflowFlag(t *testing.T) {
	tr := &cannedTransport{}
	var hosts []asset.Host
	var rels []asset.Relationship
	for i := 0; i < maxTakeoverConfirmHosts+1; i++ {
		name := "dangling" + padTakeover(i) + ".example.com"
		h := httpProbeMustHost(t, name)
		hosts = append(hosts, h)
		cannedHost(tr, name, cannedResponse{status: 404, body: "There isn't a GitHub Pages site here."})
		tgt := httpProbeMustHost(t, "target"+padTakeover(i)+".example.net")
		r1, err := asset.NewRelationship(h.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
		if err != nil {
			t.Fatalf("NewRelationship: %v", err)
		}
		rels = append(rels, r1)
	}
	stage := &HTTPProbeStage{transport: tr}
	in := httpProbeStageInput(t, "example.com", hosts, nil, nil)
	in.Results.Relationships = rels

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed (overflow rides the flag)", res.Outcome)
	}
	if !res.StickyFlags[httpprobeTakeoverOverflowFlag] {
		t.Fatalf("flags = %v, want %q", res.StickyFlags, httpprobeTakeoverOverflowFlag)
	}
	if len(res.Results.Evidence) != maxTakeoverConfirmHosts {
		t.Fatalf("evidence = %d, want %d (sorted head)", len(res.Results.Evidence), maxTakeoverConfirmHosts)
	}
}

func padTakeover(i int) string {
	return string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

func TestMistakePathsEnabled(t *testing.T) {
	if mistakePathsEnabled(nil) {
		t.Error("nil params must leave mistake paths disabled (default OFF)")
	}
	for _, v := range []string{"true", "1", "yes", "on", " TRUE ", "On"} {
		if !mistakePathsEnabled(map[string]string{"mistake_paths": v}) {
			t.Errorf("mistake_paths=%q must enable", v)
		}
	}
	for _, v := range []string{"false", "FALSE", "no", "0", "", "robot"} {
		if mistakePathsEnabled(map[string]string{"mistake_paths": v}) {
			t.Errorf("mistake_paths=%q must not enable", v)
		}
	}
}
func TestDefaultMistakePathsBounded(t *testing.T) {
	if len(defaultMistakePaths) == 0 || len(defaultMistakePaths) > 64 {
		t.Fatalf("%d curated paths, want 1..64 (engine bound)", len(defaultMistakePaths))
	}
	seen := make(map[string]struct{}, len(defaultMistakePaths))
	for _, p := range defaultMistakePaths {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "://") {
			t.Fatalf("curated path %q is not a bare absolute path", p)
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("curated path %q duplicated", p)
		}
		seen[p] = struct{}{}
	}
}

// TestDefaultMistakePathsCountGuardsCommentAccuracy pins the curated-set
// length the "mistake_paths" prose cites ("38 extra targets"): if the set
// grows or shrinks, the prose must move with it — update the count in the
// stage doc comment, the param comment, and ARCHITECTURE.md together.
func TestDefaultMistakePathsCountGuardsCommentAccuracy(t *testing.T) {
	if len(defaultMistakePaths) != 38 {
		t.Fatalf("curated set = %d paths, want 38 (the count the prose cites)", len(defaultMistakePaths))
	}
}

func TestHTTPProbeStageMistakePaths(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHostPath(tr, "www.example.com", "https", "/robots.txt", cannedResponse{status: 200, body: "User-agent: *"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, map[string]string{"mistake_paths": "true"}, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	found := false
	for _, u := range res.Additions.URLs {
		if u.String() == "https://www.example.com/robots.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("robots.txt URL missing from additions: %v", httpProbeURLStrings(res.Additions.URLs))
	}
	// 2 roots + the full curated set on the responding (https) scheme.
	if want := 2 + len(defaultMistakePaths); tr.requestCount() != want {
		t.Fatalf("requests = %d, want %d (2 roots + curated set)", tr.requestCount(), want)
	}
}

func TestHTTPProbeStageMistakePathsDefaultOff(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, map[string]string{"mistake_paths": "false"}, nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{"http://www.example.com/", "https://www.example.com/"})
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2 (opt-out is root-only)", got)
	}
}
