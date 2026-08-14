package httpprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestProbeCompletedHTTPStatusCodes(t *testing.T) {
	// 404 and 500 are ordinary completed observations: any HTTP status code
	// is a trustworthy result, and each is stored completed and served from
	// cache on the next run.
	for _, status := range []int{404, 500} {
		t.Run(itoa(status), func(t *testing.T) {
			cs := newCountingServer(t, status, "err")
			cfg := testConfig()
			cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
			hosts := []asset.Host{mustHost(t, "www.example.com")}

			rep1 := probeOne(t, cs.srv, hosts, cfg)
			pr1 := probeResultFor(hostByName(t, rep1, "www.example.com"), "http")
			if pr1.Status != ProbeCompleted || pr1.StatusCode != status || pr1.FailureReason != ReasonNone {
				t.Fatalf("http probe = %+v (want completed %d)", pr1, status)
			}
			// Stored completed, served as a zero-request hit on the next run.
			rep2 := probeOne(t, cs.srv, hosts, cfg)
			pr2 := probeResultFor(hostByName(t, rep2, "www.example.com"), "http")
			if !pr2.Cached || pr2.StatusCode != status {
				t.Fatalf("second run http probe = %+v (want a cached %d)", pr2, status)
			}
			if got := cs.requestCount(); got != 1 {
				t.Fatalf("requests = %d, want 1 (miss once, then pure hits)", got)
			}
		})
	}
}

func TestProbeCompletedHTTP(t *testing.T) {
	cs := newCountingServer(t, 200, "hello")
	cs.headers["X-Test"] = "v1"

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}

	// The https probe fails: the plain HTTP server cannot complete a TLS
	// handshake — a legitimate completed negative observation.
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeCompleted || httpPr.StatusCode != 200 || httpPr.Cached {
		t.Fatalf("http probe = %+v", httpPr)
	}
	if httpPr.FinalURL.String() != "http://www.example.com/" {
		t.Fatalf("final url = %q", httpPr.FinalURL.String())
	}
	if httpPr.ResponseSize != 5 {
		t.Fatalf("response size = %d, want 5", httpPr.ResponseSize)
	}
	found := false
	for _, h := range httpPr.Headers {
		if h.Key == "X-Test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("headers = %+v, want an X-Test entry", httpPr.Headers)
	}
	if httpPr.TLS {
		t.Fatal("http probe must not report TLS")
	}

	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCompleted || httpsPr.FailureReason != ReasonTLS || httpsPr.StatusCode != 0 {
		t.Fatalf("https probe = %+v (want completed tls failure)", httpsPr)
	}

	// Assets: both probe targets, the open http port, the http service, and
	// the tls-proven https port.
	requireEqualStrings(t, "urls", urlNames(hr.URLs), []string{
		"http://www.example.com/", "https://www.example.com/",
	})
	requireEqualStrings(t, "ports", portNames(hr.Ports), []string{"443/tcp", "80/tcp"})
	requireEqualStrings(t, "services", serviceNames(hr.Services), []string{"service:80/tcp/http"})
	if len(hr.Relationships) != 4 {
		t.Fatalf("relationships = %v, want 4", relationshipIDs(hr))
	}
	if cs.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1 (only the http probe hits the plain server)", cs.requestCount())
	}
}

func TestProbeCompletedHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	pr := newPlainResponder(t)

	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT:  newTestTransport(pr.addr, nil),
		httpsRT: transportFor(t, srv),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	httpPr := probeResultFor(hr, "http")
	httpsPr := probeResultFor(hr, "https")
	if httpPr.Status != ProbeCompleted || httpPr.StatusCode != 400 {
		t.Fatalf("http probe against a non-TLS responder = %+v (want completed 400)", httpPr)
	}
	if httpsPr.Status != ProbeCompleted || httpsPr.StatusCode != 204 || !httpsPr.TLS {
		t.Fatalf("https probe = %+v", httpsPr)
	}
	// The plain responder SERVED the http probe (400): port 80 is open with
	// an http service; 443 serves https. Sorted by identity.
	requireEqualStrings(t, "services", serviceNames(hr.Services),
		[]string{"service:443/tcp/https", "service:80/tcp/http"})
}

func TestProbeConnRefused(t *testing.T) {
	// Dialing a port with no listener fails with ECONNREFUSED — the
	// legitimate negative observation "service absent". The target port
	// must stay verifiably refused for the whole test: a just-freed
	// ephemeral port is not reliable here (on WSL2, dialing one can
	// transiently be answered by a phantom listener and reset instead of
	// refused), so use a fixed port below the kernel's ephemeral
	// allocation range that no transient socket can claim mid-test.
	addr := refusedLoopbackAddr(t)

	cfg := testConfig()
	cfg.Transport = newTestTransport(addr, nil)
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	for _, scheme := range []string{"http", "https"} {
		pr := probeResultFor(hr, scheme)
		if pr.Status != ProbeCompleted || pr.FailureReason != ReasonConnRefused {
			t.Fatalf("%s probe = %+v (want completed conn_refused)", scheme, pr)
		}
		if pr.StatusCode != 0 || len(pr.Headers) != 0 {
			t.Fatalf("%s probe must carry no response fields: %+v", scheme, pr)
		}
	}
	// No ports, no services, no edges beyond the endpoints.
	if len(hr.Ports) != 0 || len(hr.Services) != 0 {
		t.Fatalf("ports/services must be empty for refused connections: %+v %+v", hr.Ports, hr.Services)
	}
	if len(hr.Relationships) != 2 {
		t.Fatalf("relationships = %v, want only the 2 endpoint edges", relationshipIDs(hr))
	}
}

func TestProbeDNSFailure(t *testing.T) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}

	cfg := testConfig()
	cfg.Transport = tr
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", hr.Status)
	}
	for _, scheme := range []string{"http", "https"} {
		pr := probeResultFor(hr, scheme)
		if pr.Status != ProbeFailed || pr.FailureReason != ReasonDNS {
			t.Fatalf("%s probe = %+v (want failed dns)", scheme, pr)
		}
	}
}

func TestProbeTimeoutClassifiesFailed(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		// Never respond: the per-job deadline fires while the request is
		// in flight.
		<-r.Context().Done()
	})

	cfg := testConfig()
	cfg.Timeout = 300 * time.Millisecond
	cfg.Transport = transportFor(t, cs.srv)
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeFailed || httpPr.FailureReason != ReasonTimeout {
		t.Fatalf("http probe = %+v (want failed timeout)", httpPr)
	}
	// The second target is never attempted once the deadline fired.
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCancelled {
		t.Fatalf("https probe = %+v (want cancelled)", httpsPr)
	}
}

func TestProbeCancellationMidFlight(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cs.setFirstHook(cancel) // cancel the run when the first request lands

	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	rep, err := Probe(ctx, mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", hr.Status)
	}
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeCancelled {
		t.Fatalf("http probe = %+v (want cancelled)", httpPr)
	}
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCancelled {
		t.Fatalf("https probe = %+v (want cancelled)", httpsPr)
	}
}

func TestProbeRedirectInScope(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/a")
			w.WriteHeader(302)
		case "/a":
			w.Header().Set("Location", "b")
			w.WriteHeader(301)
		case "/b":
			w.WriteHeader(200)
			w.Write([]byte("final"))
		default:
			w.WriteHeader(404)
		}
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeCompleted || pr.StatusCode != 200 {
		t.Fatalf("http probe = %+v", pr)
	}
	if pr.FinalURL.String() != "http://www.example.com/b" {
		t.Fatalf("final url = %q, want /b (relative Location \"b\" resolves against /a)", pr.FinalURL.String())
	}
	if len(pr.RedirectChain) != 2 {
		t.Fatalf("chain = %+v, want 2 hops", pr.RedirectChain)
	}
	if !pr.RedirectChain[0].InScope || !pr.RedirectChain[0].Followed ||
		pr.RedirectChain[0].Target != "http://www.example.com/a" {
		t.Fatalf("hop 0 = %+v", pr.RedirectChain[0])
	}
	if !pr.RedirectChain[1].InScope || !pr.RedirectChain[1].Followed ||
		pr.RedirectChain[1].Target != "http://www.example.com/b" {
		t.Fatalf("hop 1 = %+v", pr.RedirectChain[1])
	}
	if pr.ResponseSize != 5 {
		t.Fatalf("response size = %d, want 5", pr.ResponseSize)
	}
	// The host served a URL: host->url edge plus the service edges.
	if len(hr.Relationships) == 0 {
		t.Fatal("no relationships for a served host")
	}
}

func TestProbeRedirectOutOfScopeNeverRequested(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "https://evil.example.net/x?b=2&a=1")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(404)
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeCompleted || pr.StatusCode != 302 {
		t.Fatalf("http probe = %+v (want completed redirect response)", pr)
	}
	if len(pr.RedirectChain) != 1 {
		t.Fatalf("chain = %+v, want 1 hop", pr.RedirectChain)
	}
	hop := pr.RedirectChain[0]
	if hop.InScope || hop.Followed {
		t.Fatalf("hop = %+v, want out-of-scope and never requested", hop)
	}
	if hop.Target != "https://evil.example.net/x?b=2&a=1" {
		t.Fatalf("hop target = %q", hop.Target)
	}
	if pr.FinalURL.String() != "http://www.example.com/" {
		t.Fatalf("final url = %q, want the last REQUESTED url", pr.FinalURL.String())
	}
	// The out-of-scope host was never requested: exactly 1 request total
	// (the http probe; the https probe hits the deterministic plain
	// responder).
	if cs.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1 (never request out-of-scope)", cs.requestCount())
	}
}

func TestProbeRedirectIPLiteralNeverRequested(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// A redirect into an address: IP literals are never in scope, so
			// this can never become a rebinding vector.
			w.Header().Set("Location", "http://127.0.0.1:1/x")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(404)
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	hop := pr.RedirectChain[0]
	if hop.InScope || hop.Followed {
		t.Fatalf("IP-literal hop = %+v, want out-of-scope and never requested", hop)
	}
	if cs.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1", cs.requestCount())
	}
}

func TestProbeRedirectCapTruncates(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		// /r0 -> /r1 -> ... -> /rN: an endless in-scope chain. The probe
		// starts at "/".
		var n int
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/r0")
			w.WriteHeader(302)
		default:
			if _, err := fmt.Sscanf(r.URL.Path, "/r%d", &n); err == nil {
				w.Header().Set("Location", fmt.Sprintf("/r%d", n+1))
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(404)
		}
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeTruncated || pr.Truncated != true {
		t.Fatalf("http probe = %+v (want truncated)", pr)
	}
	if pr.FailureReason != ReasonTooManyRedirects {
		t.Fatalf("failure reason = %q, want too_many_redirects", pr.FailureReason)
	}
	if len(pr.RedirectChain) != MaxRedirects+1 {
		t.Fatalf("chain = %d hops, want %d", len(pr.RedirectChain), MaxRedirects+1)
	}
	last := pr.RedirectChain[len(pr.RedirectChain)-1]
	if !last.InScope || last.Followed {
		t.Fatalf("cap-exceeding hop = %+v, want in-scope observed but never requested", last)
	}
	// Every hop before the last was followed.
	for i, hop := range pr.RedirectChain[:len(pr.RedirectChain)-1] {
		if !hop.Followed {
			t.Fatalf("hop %d = %+v, want followed", i, hop)
		}
	}
	// The host is incomplete: the https probe also hit the cap.
	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete", hr.Status)
	}
}

func TestProbeHeaderEntryCapTruncates(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < MaxHeaders+10; i++ {
			w.Header().Set("X-Key-"+itoa(i), "v")
		}
		w.WriteHeader(200)
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeTruncated || !pr.Truncated {
		t.Fatalf("http probe = %+v (want truncated)", pr)
	}
	if len(pr.Headers) != MaxHeaders {
		t.Fatalf("retained headers = %d, want %d", len(pr.Headers), MaxHeaders)
	}
	if pr.StatusCode != 200 {
		t.Fatalf("status code = %d, want 200 (the response was received)", pr.StatusCode)
	}
}

func TestProbeHeaderByteCapTruncates(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		// A single header value larger than MaxHeaderBytes: the transport
		// aborts the response.
		w.Header().Set("X-Big", strings.Repeat("a", MaxHeaderBytes+1024))
		w.WriteHeader(200)
	})

	cfg := testConfig()
	tr := transportFor(t, cs.srv)
	tr.MaxResponseHeaderBytes = MaxHeaderBytes
	plain := newPlainResponder(t)
	cfg.Transport = schemeRouter{httpRT: tr, httpsRT: newTestTransport(plain.addr, nil)}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeTruncated || !pr.Truncated {
		t.Fatalf("http probe = %+v (want truncated)", pr)
	}
	if pr.FailureReason != ReasonNone {
		t.Fatalf("failure reason = %q, want none", pr.FailureReason)
	}
}

func TestProbeBodyCapTruncates(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	body := strings.Repeat("x", MaxBodyBytes+4096)
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeTruncated || !pr.Truncated {
		t.Fatalf("http probe = %+v (want truncated)", pr)
	}
	if pr.ResponseSize != MaxBodyBytes {
		t.Fatalf("response size = %d, want %d (capped)", pr.ResponseSize, MaxBodyBytes)
	}
}

func TestProbeAssembleAssetsAndRelationships(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	plain := newPlainResponder(t)
	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(t, cs.srv),
		httpsRT: newTestTransport(plain.addr, nil),
	}
	ips := map[string]asset.IP{
		"www.example.com": mustIP(t, "192.0.2.1"),
		"api.example.com": mustIP(t, "192.0.2.2"),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"), []asset.Host{
		mustHost(t, "www.example.com"), mustHost(t, "api.example.com"),
	}, ips, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	www := hostByName(t, rep, "www.example.com")
	api := hostByName(t, rep, "api.example.com")
	requireEqualStrings(t, "www ips", ipNames(www.IPs), []string{"192.0.2.1"})
	requireEqualStrings(t, "api ips", ipNames(api.IPs), []string{"192.0.2.2"})

	// www: 80 served (http), 443 tls-proven -> ip->port edges for both.
	wantWWWRels := []string{
		"host:www.example.comhost_to_url\x00url:http://www.example.com/",
		"ip:192.0.2.1ip_to_port\x00port:443/tcp",
		"ip:192.0.2.1ip_to_port\x00port:80/tcp",
		"port:80/tcpport_to_service\x00service:80/tcp/http",
		"url:http://www.example.com/url_to_endpoint\x00endpoint:GET http://www.example.com/",
		"url:https://www.example.com/url_to_endpoint\x00endpoint:GET https://www.example.com/",
	}
	requireEqualStrings(t, "www relationships", relationshipIDs(www), wantWWWRels)
	if len(api.Relationships) == 0 {
		t.Fatal("api host must carry relationships too")
	}

	// Cross-host merge helpers on the report.
	if got := len(rep.AllHosts()); got != 2 {
		t.Fatalf("AllHosts = %d, want 2", got)
	}
	if got := len(rep.AllURLs()); got != 4 {
		t.Fatalf("AllURLs = %d, want 4", got)
	}
	if got := len(rep.AllIPs()); got != 2 {
		t.Fatalf("AllIPs = %d, want 2", got)
	}
	if got := len(rep.AllRelationships()); got != 12 {
		t.Fatalf("AllRelationships = %d, want 12", got)
	}
}

func TestProbeRejectsInvalidInputsBeforeAnyRequest(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	domain := mustDomain(t, "example.com")

	cases := []struct {
		name  string
		hosts []asset.Host
		ips   map[string]asset.IP
	}{
		{"out-of-scope host", []asset.Host{{Name: "evil.net"}}, nil},
		{"non-canonical host", []asset.Host{{Name: "WWW.Example.com"}}, nil},
		{"out-of-scope ip key", []asset.Host{mustHost(t, "www.example.com")},
			map[string]asset.IP{"evil.net": mustIP(t, "192.0.2.1")}},
		{"non-canonical ip key", []asset.Host{mustHost(t, "www.example.com")},
			map[string]asset.IP{"WWW.Example.com": mustIP(t, "192.0.2.1")}},
		{"invalid ip value", []asset.Host{mustHost(t, "www.example.com")},
			map[string]asset.IP{"www.example.com": {}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Probe(context.Background(), domain, tc.hosts, tc.ips, cfg); err == nil {
				t.Fatal("Probe accepted invalid input")
			}
			if cs.requestCount() != 0 {
				t.Fatalf("requests = %d; invalid input must be rejected before any request", cs.requestCount())
			}
		})
	}
}

func TestProbeEmptyHosts(t *testing.T) {
	cfg := testConfig()
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"), nil, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(rep.Results) != 0 || rep.Target.Name != "example.com" {
		t.Fatalf("report = %+v", rep)
	}
}

func TestProbeDeduplicatesAndSortsHosts(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	hosts := []asset.Host{
		mustHost(t, "b.example.com"),
		mustHost(t, "a.example.com"),
		mustHost(t, "b.example.com"),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"), hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2 (deduplicated)", len(rep.Results))
	}
	if rep.Results[0].Host.Name != "a.example.com" || rep.Results[1].Host.Name != "b.example.com" {
		t.Fatalf("results not sorted: %q, %q", rep.Results[0].Host.Name, rep.Results[1].Host.Name)
	}
	if cs.requestCount() != 2 {
		t.Fatalf("requests = %d, want 2 (2 hosts x http probes)", cs.requestCount())
	}
}

func TestProbeErrorSurfaces(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	if _, err := Probe(ctx, mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg); err == nil {
		t.Fatal("Probe accepted a cancelled context")
	}
}

func TestProbeCancelledBeforeSubmitKeepsHonestStatus(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Concurrency = 1
	cfg.QueueSize = 1
	cfg.Transport = transportFor(t, cs.srv)
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cs.setFirstHook(func() {
		// Cancel after the first request is in flight; with concurrency 1,
		// queued jobs behind it are dropped by the pool.
		cancel()
	})

	var hosts []asset.Host
	for i := 0; i < 10; i++ {
		hosts = append(hosts, mustHost(t, "h"+itoa(i)+".example.com"))
	}
	rep, err := Probe(ctx, mustDomain(t, "example.com"), hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(rep.Results) != 10 {
		t.Fatalf("results = %d, want 10", len(rep.Results))
	}
	cancelled := 0
	withProbes := 0
	withCause := 0
	withNeither := 0
	for _, hr := range rep.Results {
		if hr.Status != StatusCancelled {
			t.Fatalf("host %s status = %s, want cancelled", hr.Host.Name, hr.Status)
		}
		// Three legitimate outcomes under cancellation, all honestly marked
		// cancelled:
		//   - the executed job (h0) carries its two cancelled probes;
		//   - jobs whose Submit never completed carry the not-submitted cause;
		//   - a queued job dropped by the pool's abort keeps the initialized
		//     cancelled status with neither (it never ran, so there is
		//     nothing to report and no terminal event is emitted).
		// Probes and a cause are mutually exclusive.
		if len(hr.Probes) > 0 && hr.Err != nil {
			t.Fatalf("host %s has both probes and a cause: %+v", hr.Host.Name, hr)
		}
		switch {
		case len(hr.Probes) > 0:
			withProbes++
		case hr.Err != nil:
			withCause++
		default:
			withNeither++
		}
		cancelled++
	}
	if cancelled != 10 {
		t.Fatalf("cancelled = %d, want 10", cancelled)
	}
	if withProbes == 0 {
		t.Fatal("no host result carried cancelled probes (the executed job)")
	}
	if withCause == 0 {
		t.Fatal("no host result carried the not-submitted cause")
	}
	if withNeither == 0 {
		t.Fatal("no host result was a queued job dropped without probes or cause (the queued-drop path)")
	}
}

func TestProbeURLErrorsNeverLeakCredentials(t *testing.T) {
	// Redirect hops with userinfo must never surface credentials anywhere:
	// hop targets, the typed URL assets' Original fields (which asset.URL
	// preserves by design), errors, AND the on-disk cache records (the
	// HIGH-2 regression — the leak was previously proven to reach both the
	// report and the cache).
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "http://user:supersecret@www.example.com/private")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	})

	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, cfg)
	hr := hostByName(t, rep, "www.example.com")
	for _, pr := range hr.Probes {
		for _, hop := range pr.RedirectChain {
			if strings.Contains(hop.Target, "supersecret") {
				t.Fatalf("credentials leaked into hop target %q", hop.Target)
			}
			if strings.Contains(hop.URL.Original, "supersecret") || strings.Contains(hop.URL.Original, "@") {
				t.Fatalf("credentials leaked into hop URL original %q", hop.URL.Original)
			}
		}
		if strings.Contains(pr.FinalURL.String(), "supersecret") {
			t.Fatalf("credentials leaked into final url %q", pr.FinalURL.String())
		}
		if strings.Contains(pr.FinalURL.Original, "supersecret") || strings.Contains(pr.FinalURL.Original, "@") {
			t.Fatalf("credentials leaked into final url original %q", pr.FinalURL.Original)
		}
		if pr.Err != nil && strings.Contains(pr.Err.Error(), "supersecret") {
			t.Fatalf("credentials leaked into error %v", pr.Err)
		}
	}
	// The in-scope redirect was followed once: 2 requests on the http probe.
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2 (redirect followed once)", got)
	}
	// The on-disk cache records must not contain the credentials either
	// (inspected through the cache API, exactly as a later run would read
	// them back).
	for _, scheme := range []string{"http", "https"} {
		out := cfg.Cache.Get(context.Background(), probeKeyFor(t, mustHost(t, "www.example.com"), scheme))
		if !out.IsHit() {
			t.Fatalf("%s record state = %s, want hit", scheme, out.State)
		}
		data := string(out.Record.Data)
		if strings.Contains(data, "supersecret") || strings.Contains(data, "user:supersecret") {
			t.Fatalf("credentials leaked into the on-disk %s cache record: %s", scheme, data)
		}
	}
}

func TestUserAgentSent(t *testing.T) {
	var gotUA string
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	})
	probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	if gotUA == "" || !strings.HasPrefix(gotUA, "RavenRecon/") {
		t.Fatalf("user agent = %q, want RavenRecon/...", gotUA)
	}
}

func TestProbePartialHTTPOKHTTPSFailNeverDiscardsSuccess(t *testing.T) {
	// Partial results: the http probe completes with 200 while the https
	// probe stalls and hits the PER-REQUEST timeout. The completed http
	// observation must be retained in the report (never discarded), the
	// https probe must be classified failed(timeout), and the host is
	// incomplete.
	httpCS := newCountingServer(t, 200, "http-ok")
	httpsCS := newTLSCountingServer(t, 200, "ok")
	httpsCS.setHandler(func(w http.ResponseWriter, r *http.Request) {
		// Stall until the per-request deadline fires: the slowloris
		// budget, not the job deadline, bounds this probe.
		<-r.Context().Done()
	})

	cfg := testConfig()
	cfg.RequestTimeout = 300 * time.Millisecond
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(t, httpCS.srv),
		httpsRT: transportFor(t, httpsCS.srv),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete (one completed, one failed)", hr.Status)
	}
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeCompleted || httpPr.StatusCode != 200 || httpPr.ResponseSize != 7 {
		t.Fatalf("http probe = %+v; the completed success must be retained", httpPr)
	}
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeFailed || httpsPr.FailureReason != ReasonTimeout {
		t.Fatalf("https probe = %+v (want failed timeout)", httpsPr)
	}
	// The retained success still contributes its assets and edges.
	if len(hr.Services) != 1 || len(hr.Relationships) == 0 {
		t.Fatalf("services/relationships of the retained success = %v / %v", hr.Services, relationshipIDs(hr))
	}
	if httpCS.requestCount() != 1 || httpsCS.requestCount() != 1 {
		t.Fatalf("requests = %d/%d, want 1 http + 1 https", httpCS.requestCount(), httpsCS.requestCount())
	}
}

func TestProbePerHostConcurrencyNeverExceedsCap(t *testing.T) {
	// The per-host politeness contract (MaxConcurrentPerHost): with one job
	// per host, at most one request per host is in flight at any instant,
	// and the observed per-host concurrency must never exceed the cap. The
	// run overlaps hosts against one server (proving the servers sees real
	// concurrency) while every single host stays sequential.
	cs := newCountingServer(t, 200, "ok")
	cs.setSleep(50 * time.Millisecond) // force the hosts' requests to overlap
	cfg := testConfig()
	cfg.Concurrency = 8
	cfg.QueueSize = 64
	cfg.Transport = transportFor(t, cs.srv)

	const n = 8
	var hosts []asset.Host
	for i := 0; i < n; i++ {
		hosts = append(hosts, mustHost(t, "h"+itoa(i)+".example.com"))
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"), hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(rep.Results) != n {
		t.Fatalf("results = %d, want %d", len(rep.Results), n)
	}
	for i := 0; i < n; i++ {
		name := "h" + itoa(i) + ".example.com"
		got := cs.maxConcurrentForHost(name)
		if got < 1 {
			t.Fatalf("host %s never probed (max concurrent %d)", name, got)
		}
		if got > MaxConcurrentPerHost {
			t.Fatalf("host %s observed concurrency %d, cap %d", name, got, MaxConcurrentPerHost)
		}
	}
	// The probing actually overlapped across hosts — the assertion above is
	// about real concurrency, not an empty run.
	if got := cs.maxConcurrent(); got < 2 {
		t.Fatalf("server max concurrent = %d, want >= 2 (the run must actually overlap)", got)
	}
}

func TestProbeNoGoroutineLeak(t *testing.T) {
	// A full Probe run — a clean run, and the cancellation + queued-drop
	// teardown path — must leave no goroutines behind. The test transports
	// disable keep-alives so idle connection goroutines cannot pollute the
	// count (see newTestTransport). The pool's forced-drain budget path
	// (drain context expiry with a job stuck ignoring cancellation) is the
	// runtime engine's own tested concern; Probe's drain here completes
	// promptly because every job honors cancellation.
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	// Clean run.
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	probeOne(t, cs.srv, hosts, cfg) // warm up so runtime internals settle
	runtime.GC()
	baseline := runtime.NumGoroutine()
	mustFinish(t, "Probe", func() {
		if _, err := Probe(context.Background(), domain, hosts, nil, cfg); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	})
	waitForGoroutines(t, baseline, 5*time.Second)

	// Cancellation + queued-drop teardown: concurrency 1 with a full queue,
	// cancel mid-flight, then assert the whole run unwinds.
	cs2 := newCountingServer(t, 200, "ok")
	cs2.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cs2.setFirstHook(cancel)
	cfg2 := testConfig()
	cfg2.Concurrency = 1
	cfg2.QueueSize = 1
	cfg2.Transport = transportFor(t, cs2.srv)
	var many []asset.Host
	for i := 0; i < 10; i++ {
		many = append(many, mustHost(t, "h"+itoa(i)+".example.com"))
	}
	runtime.GC()
	baseline = runtime.NumGoroutine()
	mustFinish(t, "Probe (cancelled)", func() {
		if _, err := Probe(ctx, domain, many, nil, cfg2); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	})
	waitForGoroutines(t, baseline, 5*time.Second)
}

func TestProbeTLSFlagOnRedirectTerminal(t *testing.T) {
	// MEDIUM-5 regression: an https probe that completes its TLS handshake
	// but ends on a redirect (here: a 302 with an out-of-scope Location,
	// observed never requested) must still report TLS=true on the terminal
	// path, and the stored record must carry the same value. A plain-HTTP
	// target reports TLS=false.
	httpsCS := newTLSCountingServer(t, 302, "")
	httpsCS.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.example.net/x")
		w.WriteHeader(302)
	})

	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT:  newTestTransport(refusedLoopbackAddr(t), nil),
		httpsRT: transportFor(t, httpsCS.srv),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCompleted || httpsPr.StatusCode != 302 || !httpsPr.TLS {
		t.Fatalf("https probe = %+v (want completed 302 with TLS=true)", httpsPr)
	}
	if len(httpsPr.RedirectChain) != 1 || httpsPr.RedirectChain[0].InScope {
		t.Fatalf("chain = %+v, want one out-of-scope hop", httpsPr.RedirectChain)
	}
	httpPr := probeResultFor(hr, "http")
	if httpPr.TLS {
		t.Fatalf("http probe against a refused port must not report TLS: %+v", httpPr)
	}

	// The stored record carries the correct TLS value.
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	rep2, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	httpsPr2 := probeResultFor(hr2, "https")
	if !httpsPr2.TLS {
		t.Fatalf("https probe with cache = %+v (want TLS=true)", httpsPr2)
	}
	out := cfg.Cache.Get(context.Background(), probeKeyFor(t, mustHost(t, "www.example.com"), "https"))
	if !out.IsHit() {
		t.Fatalf("https record state = %s, want hit", out.State)
	}
	var st storedProbe
	if err := json.Unmarshal(out.Record.Data, &st); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	if !st.TLS || st.StatusCode != 302 {
		t.Fatalf("stored payload = %+v (want TLS=true, status 302)", st)
	}

	// MEDIUM-5 follow-up: a walk that FOLLOWS an in-scope hop and then fails
	// on the next request must not carry the followed hop's handshake state
	// into the terminal negative observation. The terminal request completed
	// no handshake, so TLS must be false — and the completed conn_refused
	// record must stay servable as a zero-request cache hit (a stale true
	// would be refused by decodeStoredProbe and recomputed on every run).
	httpsCS2 := newTLSCountingServer(t, 302, "")
	httpsCS2.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://www.example.com/next")
		w.WriteHeader(302)
	})
	cfg2 := testConfig()
	cfg2.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	cfg2.Transport = schemeRouter{
		httpRT:  newTestTransport(refusedLoopbackAddr(t), nil),
		httpsRT: transportFor(t, httpsCS2.srv),
	}
	rep3, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg2)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	httpsPr3 := probeResultFor(hostByName(t, rep3, "www.example.com"), "https")
	if httpsPr3.Status != ProbeCompleted || httpsPr3.FailureReason != ReasonConnRefused || httpsPr3.StatusCode != 0 {
		t.Fatalf("https probe = %+v (want completed conn_refused)", httpsPr3)
	}
	if httpsPr3.TLS {
		t.Fatalf("terminal refusal after a followed hop must not report TLS: %+v", httpsPr3)
	}
	if len(httpsPr3.RedirectChain) != 1 || !httpsPr3.RedirectChain[0].InScope || !httpsPr3.RedirectChain[0].Followed {
		t.Fatalf("chain = %+v, want one followed in-scope hop", httpsPr3.RedirectChain)
	}
	rep4, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg2)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	httpsPr4 := probeResultFor(hostByName(t, rep4, "www.example.com"), "https")
	if !httpsPr4.Cached || httpsPr4.FailureReason != ReasonConnRefused || httpsPr4.TLS {
		t.Fatalf("second run https probe = %+v (want a cached conn_refused with TLS=false)", httpsPr4)
	}
	if got := httpsCS2.requestCount(); got != 1 {
		t.Fatalf("requests = %d, want 1 (miss once, then a pure hit)", got)
	}
}

func TestProbeRejectsNilContext(t *testing.T) {
	cfg := testConfig()
	if _, err := Probe(nil, mustDomain(t, "example.com"), nil, nil, cfg); err == nil {
		t.Fatal("Probe accepted a nil context")
	}
}

// TestProbeRateLimiterGatesEveryRequest verifies the central request
// limiter with a frozen clock: with Burst 1, exactly one request may ever
// dispatch — every later outbound request blocks on the limiter until its
// job deadline. This is deterministic (no sleeps): the fake clock never
// advances, so tokens can never refill. Ported from the DNS pipeline's
// TestResolveRateLimiterGatesEveryQuery.
func TestProbeRateLimiterGatesEveryRequest(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")

	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Rate = 1                         // one token per second...
	cfg.Burst = 1                        // ...and the clock never advances: exactly one request ever
	cfg.Timeout = 500 * time.Millisecond // jobs give up fast on the frozen limiter
	cfg.Clock = clk

	hosts := []asset.Host{mustHost(t, "www.example.com"), mustHost(t, "api.example.com")}
	mustFinish(t, "Probe", func() {
		probeOne(t, cs.srv, hosts, cfg)
	})
	// Exactly ONE request dispatched in total: the only burst token.
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("requests = %d, want exactly 1 (burst=1, clock frozen)", got)
	}
}

// TestProbeRateLimiterDisabled verifies Rate <= 0 disables pacing: every
// outbound request dispatches immediately, with no token waits.
func TestProbeRateLimiterDisabled(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig() // Rate 0 from testConfig

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com"), mustHost(t, "api.example.com")}, cfg)
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2 (pacing disabled)", got)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
}

// TestProbeRedirectHopConsumesToken pins that a followed redirect hop is an
// outbound request too and gates on the central limiter: with Burst 1 and a
// frozen clock, the hop must NOT dispatch until a token is released. The
// run has no real deadline (Timeout 0 — token release is driven by the fake
// clock alone, so no real-time race can cut the probe short); the test
// cancels the run once the hop has been observed, and every wait is a
// bounded patience poll. The hop's pending token wait is observable as a
// registered fake-clock timer, which makes the "not dispatched yet" pin
// deterministic rather than probabilistic.
func TestProbeRedirectHopConsumesToken(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/a")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	})

	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.Timeout = 0 // no real deadline: the fake clock alone gates token release
	cfg.Clock = clk
	plain := newPlainResponder(t)
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(t, cs.srv),
		httpsRT: newTestTransport(plain.addr, nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var rep Report
	var perr error
	go func() {
		rep, perr = Probe(ctx, mustDomain(t, "example.com"),
			[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
		close(done)
	}()

	// The probe dispatches on the burst token, follows the redirect, and
	// its next token wait becomes observable as a registered fake-clock
	// timer.
	waitUntil(t, "the hop's token wait to register", 2*time.Second, func() bool {
		return clk.waiterCount() >= 1
	})
	// The hop has been followed but has NOT dispatched: its token has not
	// been released (deterministic: no token exists, and the https probe
	// cannot start before this one finishes).
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("requests = %d before the token releases, want exactly 1 (the probe only)", got)
	}
	// Release the token: only now may the hop dispatch.
	clk.advance(time.Second)
	waitUntil(t, "the hop request to dispatch", 2*time.Second, func() bool {
		return cs.requestCount() >= 2
	})
	cancel() // end the run: the https probe is parked on the frozen limiter
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("Probe did not finish within %s", testTimeout)
	}
	if perr != nil {
		t.Fatalf("Probe: %v", perr)
	}
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want exactly 2 (probe + followed hop)", got)
	}
	pr := probeResultFor(hostByName(t, rep, "www.example.com"), "http")
	if pr.FinalURL.String() != "http://www.example.com/a" {
		t.Fatalf("final url = %q, want the followed hop http://www.example.com/a", pr.FinalURL.String())
	}
	if len(pr.RedirectChain) != 1 || !pr.RedirectChain[0].InScope || !pr.RedirectChain[0].Followed ||
		pr.RedirectChain[0].Target != "http://www.example.com/a" {
		t.Fatalf("chain = %+v, want one followed in-scope hop to /a", pr.RedirectChain)
	}
}

// TestProbeDeadlineDuringTokenWaitRetainsChain is the regression test for
// the limiter-wait error path: when the job deadline fires during a token
// wait AFTER hops were followed, the report must still carry the last
// targeted URL as FinalURL and the observed redirect chain — mirroring the
// round-trip error path — instead of a zero FinalURL with lost hops. The
// fake clock is frozen (tokens never refill) and the real per-job deadline
// fires mid-wait, deterministically.
func TestProbeDeadlineDuringTokenWaitRetainsChain(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/a")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	})

	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.Timeout = 500 * time.Millisecond // the job deadline fires mid token wait
	cfg.Clock = clk

	var rep Report
	mustFinish(t, "Probe", func() {
		rep = probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, cfg)
	})
	hr := hostByName(t, rep, "www.example.com")
	pr := probeResultFor(hr, "http")
	if pr.Status != ProbeFailed || pr.FailureReason != ReasonTimeout {
		t.Fatalf("http probe = %+v (want failed timeout)", pr)
	}
	if pr.FinalURL.String() != "http://www.example.com/a" {
		t.Fatalf("final url = %q, want the last targeted URL http://www.example.com/a", pr.FinalURL.String())
	}
	if len(pr.RedirectChain) != 1 {
		t.Fatalf("chain = %+v, want 1 observed hop", pr.RedirectChain)
	}
	hop := pr.RedirectChain[0]
	if !hop.InScope || !hop.Followed || hop.Target != "http://www.example.com/a" {
		t.Fatalf("hop = %+v, want the followed in-scope hop to /a", hop)
	}
	// The hop never dispatched: no token was ever released.
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("requests = %d, want exactly 1 (the hop's token never released)", got)
	}
	// The terminal path completed no handshake: TLS must stay false.
	if pr.TLS {
		t.Fatalf("http probe = %+v, must not report TLS", pr)
	}
	// The deadline fired while the http probe was still waiting: the https
	// target was never attempted and reports cancelled.
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCancelled {
		t.Fatalf("https probe = %+v (want cancelled)", httpsPr)
	}
}
