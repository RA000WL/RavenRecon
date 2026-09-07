package httpprobe

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestNormalizeWellKnownPaths(t *testing.T) {
	out, err := normalizeWellKnownPaths(nil)
	if err != nil || out != nil {
		t.Fatalf("nil = %v, %v; want nil, nil", out, err)
	}
	out, err = normalizeWellKnownPaths([]string{"/b", "/a", "/a", "/", "  ", "/b"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(out) != 2 || out[0] != "/a" || out[1] != "/b" {
		t.Fatalf("normalized = %v, want [/a /b] sorted deduped without the root", out)
	}
	for _, bad := range [][]string{
		{"relative/path"},
		{"https://example.com/x"},
		{"/" + strings.Repeat("a", maxWellKnownPathBytes)},
	} {
		if _, err := normalizeWellKnownPaths(bad); err == nil {
			t.Fatalf("paths %q accepted, want rejection", bad)
		}
	}
	big := make([]string, maxWellKnownPaths+1)
	for i := range big {
		big[i] = "/p" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
	}
	if _, err := normalizeWellKnownPaths(big); err == nil {
		t.Fatalf("%d paths accepted, want over-bound rejection", len(big))
	}
}

func TestProbeWellKnownPathsLiveHost(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/robots.txt", "/.git/HEAD":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		default:
			w.WriteHeader(404)
		}
	})
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	cfg.WellKnownPaths = []string{"/robots.txt", "/.git/HEAD", "/missing-xyz"}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	// Plain loopback server: the https root fails TLS (completed
	// negative, zero HTTP requests), the http root serves, so paths ride
	// http: 1 counted root + 3 paths = 4 requests.
	if got := cs.requestCount(); got != 4 {
		t.Fatalf("requests = %d, want 4 (1 http root + 3 paths on http)", got)
	}
	var robots, git, missing bool
	for _, pr := range hr.Probes {
		switch pr.URL.Path {
		case "/robots.txt":
			robots = pr.StatusCode == 200
		case "/.git/HEAD":
			git = pr.StatusCode == 200
		case "/missing-xyz":
			missing = pr.StatusCode == 404
		}
		if pr.Scheme != "http" && pr.URL.Path != "/" {
			t.Fatalf("path probe %s on scheme %s, want http (only root responded)", pr.URL.Path, pr.Scheme)
		}
	}
	if !robots || !git || !missing {
		t.Fatalf("path observations wrong: robots=%v git=%v missing404=%v", robots, git, missing)
	}
	// Path surfaces join the corpus: URLs and GET endpoints exist for
	// every probed path.
	for _, want := range []string{"http://www.example.com/robots.txt", "http://www.example.com/.git/HEAD"} {
		found := false
		for _, u := range hr.URLs {
			if u.String() == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("URLs lack %s: %v", want, hr.URLs)
		}
	}
}

func TestProbeWellKnownPathsSkippedWhenDead(t *testing.T) {
	addr := refusedLoopbackAddr(t)
	cfg := testConfig()
	cfg.Transport = newTestTransport(addr, nil)
	cfg.WellKnownPaths = []string{"/robots.txt", "/.git/HEAD"}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	// Both roots refused without an HTTP response: no server proven, so
	// only the 2 root attempts exist — zero path requests.
	if len(hr.Probes) != 2 {
		t.Fatalf("probes = %d, want exactly the 2 roots (paths skipped)", len(hr.Probes))
	}
}

func TestProbeWellKnownPathsInvalidConfig(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	cfg.WellKnownPaths = []string{"not-absolute"}
	if _, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg); err == nil {
		t.Fatal("Probe accepted a relative path, want rejection before any request")
	}
	if got := cs.requestCount(); got != 0 {
		t.Fatalf("requests = %d; invalid input must be rejected before any request", got)
	}
}

// TestProbeWellKnownPathsShortTimeoutCancelsContractually pins the HIGH
// tuning contract: one job probes the whole surface sequentially, so a
// Timeout sized for roots alone expires mid-surface and the host folds
// to Cancelled (cancelled-first vocabulary) even though the completed
// root proved a server. Cancelled here is contractual — the operator
// must size Timeout to cover 2 roots + port pairs + one request per
// path — not a bug in path probing.
func TestProbeWellKnownPathsShortTimeoutCancelsContractually(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Paths never respond: the per-job deadline fires while the
			// first path request is in flight (mirrors
			// TestProbeTimeoutClassifiesFailed's hanging handler).
			<-r.Context().Done()
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	cfg := testConfig()
	cfg.Timeout = 300 * time.Millisecond
	cfg.Transport = transportFor(t, cs.srv)
	cfg.WellKnownPaths = []string{"/a", "/b", "/c"}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	// Exact outcome: both roots complete (the http root proves the
	// server, so all 3 paths are planned), the first path fails on the
	// deadline, the remaining paths are never attempted, and
	// cancelled-first folds the mostly-completed host to Cancelled.
	if hr.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled (contractual short-Timeout outcome)", hr.Status)
	}
	if len(hr.Probes) != 5 {
		t.Fatalf("probes = %d, want 5 (2 roots + 3 paths, all recorded)", len(hr.Probes))
	}
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeCompleted || httpPr.StatusCode != 200 {
		t.Fatalf("http probe = %+v, want completed 200 (the server-proving root)", httpPr)
	}
	pathA := probeResultForURL(hr, "http://www.example.com/a")
	if pathA.Status != ProbeFailed || pathA.FailureReason != ReasonTimeout {
		t.Fatalf("first path probe = %+v, want failed timeout", pathA)
	}
	cancelled := 0
	for _, pr := range hr.Probes {
		if pr.Status == ProbeCancelled {
			cancelled++
		}
	}
	if cancelled != 2 {
		t.Fatalf("cancelled probes = %d, want 2 (the unattempted paths)", cancelled)
	}
	// Counter: exactly two requests ever reached the server — the root
	// and the in-flight first path. Nothing else was attempted after
	// the deadline.
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2 (root + in-flight path only)", got)
	}
}

// roundTripFunc adapts a closure to http.RoundTripper for tests that
// route requests between deterministic backends.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestProbeWellKnownPathsPortResponsesDoNotGate pins the v1 gating rule:
// only a ROOT target that completed with an HTTP response enables paths.
// Here both roots are dead (refused / TLS failure, zero HTTP responses)
// while the :8443 port pair is served — the served port must not enable
// a single path request.
func TestProbeWellKnownPathsPortResponsesDoNotGate(t *testing.T) {
	cs := newCountingServer(t, 200, "ok-port")
	refusedRT := newTestTransport(refusedLoopbackAddr(t), nil)
	servedRT := transportFor(t, cs.srv)
	pr := newPlainResponder(t)
	httpsRT := newTestTransport(pr.addr, nil)
	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Only the :8443 port target reaches the server; every
			// other http target (both roots) is refused.
			if req.URL.Port() == "8443" {
				return servedRT.RoundTrip(req)
			}
			return refusedRT.RoundTrip(req)
		}),
		// Every https target (root and :8443) hits the deterministic
		// plain responder: a completed TLS failure, never an HTTP
		// response.
		httpsRT: httpsRT,
	}
	cfg.HostPorts = map[string][]int{"www.example.com": {8443}}
	cfg.WellKnownPaths = []string{"/robots.txt", "/.git/HEAD"}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	// Zero path observations despite the served port: 2 roots + the
	// 8443 pair only.
	if len(hr.Probes) != 4 {
		t.Fatalf("probes = %d, want 4 (2 roots + 8443 pair, zero paths)", len(hr.Probes))
	}
	for _, pr := range hr.Probes {
		if pr.URL.Path != "/" {
			t.Fatalf("path probe %q issued although no root proved a server", pr.URL.Path)
		}
	}
	httpPort := probeResultForURL(hr, "http://www.example.com:8443/")
	if httpPort.Status != ProbeCompleted || httpPort.StatusCode != 200 {
		t.Fatalf("http:8443 probe = %+v, want completed 200 (the served port)", httpPort)
	}
	// Counter: exactly the one served http request reached the server —
	// zero path requests.
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("requests = %d, want 1 (http:8443 only, zero paths)", got)
	}
}

// TestProbeWellKnownPathCacheDistinct pins cache separation for mistake
// paths, mirroring TestProbePortCacheDistinct: path targets key by their
// own URL identity — a warm run serves them with zero new requests and
// the Cached flag set.
func TestProbeWellKnownPathCacheDistinct(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	cfg.WellKnownPaths = []string{"/robots.txt", "/.git/HEAD"}
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	rep1 := probeOne(t, cs.srv, hosts, cfg)
	pr1 := probeResultForURL(hostByName(t, rep1, "www.example.com"), "http://www.example.com/robots.txt")
	if pr1.Cached || pr1.StatusCode != 200 {
		t.Fatalf("cold path probe = %+v, want fresh 200", pr1)
	}
	// The plain responder answers the https root with a deterministic
	// TLS failure: cold cost is 1 http root + 2 http paths = 3.
	if got := cs.requestCount(); got != 3 {
		t.Fatalf("cold requests = %d, want 3 (1 http root + 2 paths on http)", got)
	}
	rep2 := probeOne(t, cs.srv, hosts, cfg)
	pr2 := probeResultForURL(hostByName(t, rep2, "www.example.com"), "http://www.example.com/robots.txt")
	if !pr2.Cached || pr2.StatusCode != 200 {
		t.Fatalf("warm path probe = %+v, want a cached 200", pr2)
	}
	git := probeResultForURL(hostByName(t, rep2, "www.example.com"), "http://www.example.com/.git/HEAD")
	if !git.Cached || git.StatusCode != 200 {
		t.Fatalf("warm git probe = %+v, want a cached 200", git)
	}
	if got := cs.requestCount(); got != 3 {
		t.Fatalf("requests = %d, want 3 (warm run performs zero network)", got)
	}
}
