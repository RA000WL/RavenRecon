package httpprobe

import (
	"net/http"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

func TestClassifyHost(t *testing.T) {
	cases := []struct {
		name   string
		probes []ProbeStatus
		want   Status
	}{
		{"both completed", []ProbeStatus{ProbeCompleted, ProbeCompleted}, StatusCompleted},
		{"completed + conn-refused negative", []ProbeStatus{ProbeCompleted, ProbeCompleted}, StatusCompleted},
		{"one failed", []ProbeStatus{ProbeFailed, ProbeCompleted}, StatusIncomplete},
		{"both failed", []ProbeStatus{ProbeFailed, ProbeFailed}, StatusFailed},
		{"truncated dominates", []ProbeStatus{ProbeTruncated, ProbeCompleted}, StatusIncomplete},
		{"cancelled dominates everything", []ProbeStatus{ProbeCancelled, ProbeFailed}, StatusCancelled},
		{"cancelled + completed", []ProbeStatus{ProbeCancelled, ProbeCompleted}, StatusCancelled},
		{"all cancelled", []ProbeStatus{ProbeCancelled, ProbeCancelled}, StatusCancelled},
		{"no probes", nil, StatusCompleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probes := make([]ProbeResult, len(tc.probes))
			for i, st := range tc.probes {
				probes[i] = ProbeResult{Scheme: []string{"http", "https"}[i], Status: st}
			}
			if got := classifyHost(probes); got != tc.want {
				t.Fatalf("classifyHost(%v) = %s, want %s", tc.probes, got, tc.want)
			}
		})
	}
}

// testEnv returns an env for assemble tests: a fixed clock and the given
// caller-provided addresses.
func testEnv(ips map[string]asset.IP) env {
	return env{clock: newFakeClock(fixedTime), ips: ips}
}

func TestAssembleServed(t *testing.T) {
	host := mustHost(t, "www.example.com")
	clk := newFakeClock(fixedTime)
	httpURL := mustProbeURL(t, host, "http", clk)
	httpsURL := mustProbeURL(t, host, "https", clk)

	probes := []ProbeResult{
		{
			Host: host, URL: httpURL, Scheme: "http", Status: ProbeCompleted,
			Executed: true, StatusCode: 200, FinalURL: httpURL,
		},
		{
			Host: host, URL: httpsURL, Scheme: "https", Status: ProbeCompleted,
			Executed: true, StatusCode: 301, FinalURL: httpsURL,
		},
	}
	hr := assemble(host, probes, &env{clock: clk})

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	requireEqualStrings(t, "urls", urlNames(hr.URLs), []string{
		"http://www.example.com/", "https://www.example.com/",
	})
	requireEqualStrings(t, "ports", portNames(hr.Ports), []string{"443/tcp", "80/tcp"})
	requireEqualStrings(t, "services", serviceNames(hr.Services), []string{"service:443/tcp/https", "service:80/tcp/http"})
	if len(hr.Endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(hr.Endpoints))
	}
	wantRels := []string{
		"host:www.example.comhost_to_url\x00url:http://www.example.com/",
		"host:www.example.comhost_to_url\x00url:https://www.example.com/",
		"port:443/tcpport_to_service\x00service:443/tcp/https",
		"port:80/tcpport_to_service\x00service:80/tcp/http",
		"url:http://www.example.com/url_to_endpoint\x00endpoint:GET http://www.example.com/",
		"url:https://www.example.com/url_to_endpoint\x00endpoint:GET https://www.example.com/",
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), wantRels)
}

func TestAssembleLegitimateNegatives(t *testing.T) {
	host := mustHost(t, "www.example.com")
	clk := newFakeClock(fixedTime)
	httpURL := mustProbeURL(t, host, "http", clk)
	httpsURL := mustProbeURL(t, host, "https", clk)

	probes := []ProbeResult{
		// Connection refused: service absent on 80. Completed, no response,
		// no port, no service, no edges.
		{
			Host: host, URL: httpURL, Scheme: "http", Status: ProbeCompleted,
			Executed: true, FailureReason: ReasonConnRefused, FinalURL: httpURL,
		},
		// TLS failure: listener proven on 443 (https not served). Open port
		// with an ip->port edge when an address was provided, but no service.
		{
			Host: host, URL: httpsURL, Scheme: "https", Status: ProbeCompleted,
			Executed: true, FailureReason: ReasonTLS, FinalURL: httpsURL,
		},
	}
	ips := map[string]asset.IP{host.Name: mustIP(t, "192.0.2.7")}
	hr := assemble(host, probes, &env{clock: clk, ips: ips})

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	requireEqualStrings(t, "ports", portNames(hr.Ports), []string{"443/tcp"})
	if len(hr.Services) != 0 {
		t.Fatalf("services = %v, want none (no confirmed service)", hr.Services)
	}
	requireEqualStrings(t, "ips", ipNames(hr.IPs), []string{"192.0.2.7"})
	// Only the endpoint edge for each probe and the ip->port edge for 443
	// (sorted by edge identity: "ip:..." < "url:...").
	wantRels := []string{
		"ip:192.0.2.7ip_to_port\x00port:443/tcp",
		"url:http://www.example.com/url_to_endpoint\x00endpoint:GET http://www.example.com/",
		"url:https://www.example.com/url_to_endpoint\x00endpoint:GET https://www.example.com/",
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), wantRels)
}

func TestAssembleFailedAndCancelled(t *testing.T) {
	host := mustHost(t, "www.example.com")
	clk := newFakeClock(fixedTime)
	httpURL := mustProbeURL(t, host, "http", clk)
	httpsURL := mustProbeURL(t, host, "https", clk)

	probes := []ProbeResult{
		{
			Host: host, URL: httpURL, Scheme: "http", Status: ProbeFailed,
			Executed: true, FailureReason: ReasonTimeout, FinalURL: httpURL,
		},
		// Cancelled in flight: the job ran, so the endpoint shape exists,
		// but cancellation dominates the host status.
		{
			Host: host, URL: httpsURL, Scheme: "https", Status: ProbeCancelled,
			Executed: true, Err: errCancelled,
		},
	}
	hr := assemble(host, probes, &env{clock: clk})

	if hr.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled (cancellation dominates)", hr.Status)
	}
	if len(hr.Probes) != 2 {
		t.Fatalf("probes = %d, want 2 (the observations are retained)", len(hr.Probes))
	}
	requireEqualStrings(t, "urls", urlNames(hr.URLs), []string{
		"http://www.example.com/", "https://www.example.com/",
	})
	if len(hr.Endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2 (executed jobs, regardless of outcome)", len(hr.Endpoints))
	}
	// The executed jobs still contribute their endpoint shapes.
	wantRels := []string{
		"url:http://www.example.com/url_to_endpoint\x00endpoint:GET http://www.example.com/",
		"url:https://www.example.com/url_to_endpoint\x00endpoint:GET https://www.example.com/",
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), wantRels)
}

func TestBoundedHeaders(t *testing.T) {
	h := http.Header{}
	for i := 0; i < MaxHeaders+10; i++ {
		h.Set("X-Hdr", "v") // same key: counts as ONE entry
	}
	for i := 0; i < MaxHeaders; i++ {
		h.Set("X-Key-"+itoa(i), "v")
	}
	entries, truncated := boundedHeaders(h)
	if !truncated {
		t.Fatal("boundedHeaders did not report truncation")
	}
	if len(entries) != MaxHeaders {
		t.Fatalf("entries = %d, want %d", len(entries), MaxHeaders)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Key >= entries[i].Key {
			t.Fatalf("entries not sorted at %d: %q >= %q", i, entries[i-1].Key, entries[i].Key)
		}
	}

	small := http.Header{"X-Test": {"a", "b"}}
	entries, truncated = boundedHeaders(small)
	if truncated || len(entries) != 1 || entries[0].Key != "X-Test" || len(entries[0].Values) != 2 {
		t.Fatalf("boundedHeaders(%v) = %v, %v", small, entries, truncated)
	}
}

func TestReportMergeHelpers(t *testing.T) {
	clk := newFakeClock(fixedTime)
	h1 := mustHost(t, "www.example.com")
	h2 := mustHost(t, "api.example.com")
	u1 := mustProbeURL(t, h1, "http", clk)
	u2 := mustProbeURL(t, h2, "http", clk)
	p1 := mustPort(t, 80)
	p2 := mustPort(t, 443)
	s1 := mustService(t, "http", p1)
	ip := mustIP(t, "192.0.2.1")

	rep := Report{Target: mustDomain(t, "example.com"), Results: []HostResult{
		{
			Host: h1, URLs: []asset.URL{u1}, Ports: []asset.Port{p1},
			Services: []asset.Service{s1}, Endpoints: []asset.Endpoint{mustEndpoint(t, "GET", u1)},
			IPs:           []asset.IP{ip},
			Relationships: []asset.Relationship{mustRel(t, h1.Identity(), asset.RelationshipHostToURL, u1.Identity())},
		},
		{
			Host: h2, URLs: []asset.URL{u2}, Ports: []asset.Port{p1, p2},
			Services: []asset.Service{s1}, Endpoints: []asset.Endpoint{mustEndpoint(t, "GET", u2)},
		},
	}}

	// Hosts merge by identity (duplicate www entries collapse).
	dup := append([]HostResult(nil), rep.Results...)
	dup = append(dup, HostResult{Host: h1, URLs: []asset.URL{u1}})
	dupRep := Report{Target: rep.Target, Results: dup}
	if got := len(dupRep.AllHosts()); got != 2 {
		t.Fatalf("AllHosts = %d, want 2", got)
	}
	if got := len(rep.AllURLs()); got != 2 {
		t.Fatalf("AllURLs = %d, want 2", got)
	}
	if got := len(rep.AllPorts()); got != 2 {
		t.Fatalf("AllPorts = %d, want 2", got)
	}
	if got := len(rep.AllServices()); got != 1 {
		t.Fatalf("AllServices = %d, want 1", got)
	}
	if got := len(rep.AllEndpoints()); got != 2 {
		t.Fatalf("AllEndpoints = %d, want 2", got)
	}
	if got := len(rep.AllIPs()); got != 1 {
		t.Fatalf("AllIPs = %d, want 1", got)
	}
	if got := len(rep.AllRelationships()); got != 1 {
		t.Fatalf("AllRelationships = %d, want 1", got)
	}
}

// --- small helpers -------------------------------------------------------

// errCancelled is a sentinel for never-executed probes in unit tests.
var errCancelled = errCancelledType{}

type errCancelledType struct{}

func (errCancelledType) Error() string { return "cancelled" }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func mustProbeURL(t *testing.T, host asset.Host, scheme string, clk runtime.Clock) asset.URL {
	t.Helper()
	u, err := probeTargetURL(host, scheme, clk)
	if err != nil {
		t.Fatalf("probeTargetURL(%s, %s): %v", host.Name, scheme, err)
	}
	return u
}

func mustPort(t *testing.T, n int) asset.Port {
	t.Helper()
	p, err := asset.NewPort(n, "tcp", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewPort(%d): %v", n, err)
	}
	return p
}

func mustService(t *testing.T, name string, port asset.Port) asset.Service {
	t.Helper()
	s, err := asset.NewService(name, port, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewService(%q): %v", name, err)
	}
	return s
}

func mustEndpoint(t *testing.T, method string, u asset.URL) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, u.String(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEndpoint(%q, %q): %v", method, u.String(), err)
	}
	return ep
}

func mustRel(t *testing.T, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	r, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return r
}

func portNames(ports []asset.Port) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, p.String())
	}
	return out
}

func serviceNames(services []asset.Service) []string {
	out := make([]string, 0, len(services))
	for _, s := range services {
		out = append(out, s.Identity().String())
	}
	return out
}

func ipNames(ips []asset.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Addr.String())
	}
	return out
}
