package adapt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
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
	status  int
	body    string
	headers map[string]string
	err     error // when set, RoundTrip returns it (classifies the probe)
}

// cannedTransport is a hermetic http.RoundTripper: it answers every request
// from a per-host map (host -> scheme -> response), records the requests it
// served, and never dials anything. An absent entry fails the probe with a
// DNS-style error (ProbeFailed/ReasonDNS), so "host not served" is expressed
// deterministically without touching the network. When blockUntil is non-nil
// (never closed), RoundTrip blocks until the request's context is done — the
// seam for in-flight cancellation and per-request-deadline tests.
type cannedTransport struct {
	mu         sync.Mutex
	byHost     map[string]map[string]cannedResponse
	requests   []string // "scheme://host" of every served request
	blockUntil chan struct{}
}

// RoundTrip implements http.RoundTripper.
func (t *cannedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Scheme + "://" + req.URL.Host
	t.mu.Lock()
	t.requests = append(t.requests, key)
	byScheme, ok := t.byHost[req.URL.Host]
	var resp cannedResponse
	if ok {
		resp = byScheme[req.URL.Scheme]
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
	if !ok || resp.status == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: req.URL.Host, IsTimeout: false}
	}
	h := make(http.Header, len(resp.headers))
	for k, v := range resp.headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode:    resp.status,
		Status:        fmt.Sprintf("%d %s", resp.status, http.StatusText(resp.status)),
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(resp.body)),
		ContentLength: int64(len(resp.body)),
		Request:       req,
	}, nil
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
