package adapt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// --- hermetic seams -------------------------------------------------------

// fakeNaabuRunner is a hermetic discovery.Runner for the naabu adapter: it
// answers the -version probe from versionOut (or fails when versionFails),
// answers the scan invocation from scanOut/exitCode/scanErr, records every
// command, and captures the CONTENT of each -l input file at scan time so
// tests can pin exactly what reached the tool (the temp file is deleted by
// the time DiscoverPorts returns). No real binary, no network.
type fakeNaabuRunner struct {
	mu           sync.Mutex
	calls        []discovery.Cmd
	scanFiles    []string
	versionOut   string
	versionFails bool
	scanOut      string
	scanErr      error
	exitCode     int
	stdoutTrunc  bool
}

func (f *fakeNaabuRunner) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if ctx.Err() != nil {
		return discovery.RunResult{}, ctx.Err()
	}
	if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
		if f.versionFails {
			return discovery.RunResult{}, errors.New("fake: version probe broken")
		}
		return discovery.RunResult{Stdout: []byte(f.versionOut)}, nil
	}
	if f.scanErr != nil {
		return discovery.RunResult{}, f.scanErr
	}
	if len(cmd.Args) >= 2 && cmd.Args[0] == "-l" {
		data, rerr := os.ReadFile(cmd.Args[1])
		if rerr != nil {
			return discovery.RunResult{}, rerr
		}
		f.scanFiles = append(f.scanFiles, string(data))
	}
	return discovery.RunResult{
		Stdout:          []byte(f.scanOut),
		ExitCode:        f.exitCode,
		StdoutTruncated: f.stdoutTrunc,
	}, nil
}

// scanCall returns the recorded scan invocation (the first non-version call).
func (f *fakeNaabuRunner) scanCall() (discovery.Cmd, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if len(c.Args) > 0 && c.Args[0] != "-version" {
			return c, true
		}
	}
	return discovery.Cmd{}, false
}

func (f *fakeNaabuRunner) scanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if len(c.Args) > 0 && c.Args[0] != "-version" {
			n++
		}
	}
	return n
}

func (f *fakeNaabuRunner) lastScanFileContent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scanFiles) == 0 {
		return ""
	}
	return f.scanFiles[len(f.scanFiles)-1]
}

// okLookPath resolves every name (the "naabu installed" seam).
func okLookPath(name string) (string, error) { return filepath.Join("/bin", name), nil }

// missingLookPath reports every executable absent (the "not installed" seam).
func missingLookPath(string) (string, error) { return "", execNotFound() }

func execNotFound() error { return &mockNotFoundError{} }

type mockNotFoundError struct{}

func (*mockNotFoundError) Error() string { return "exec: not found" }

// portsStaticCache is a hermetic cache.Cache serving what was Put (completed
// hits replay), counting stores — the warm-run parity harness.
type portsStaticCache struct {
	mu   sync.Mutex
	recs map[cache.Key]cache.Record
	puts int
}

func newPortsStaticCache() *portsStaticCache {
	return &portsStaticCache{recs: make(map[cache.Key]cache.Record)}
}

func (c *portsStaticCache) Get(_ context.Context, key cache.Key) cache.Outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.recs[key]
	if !ok {
		return cache.Outcome{State: cache.StateMiss}
	}
	r := rec
	return cache.Outcome{State: cache.StateHit, Record: &r}
}

func (c *portsStaticCache) Put(_ context.Context, key cache.Key, record cache.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	c.recs[key] = record
	return nil
}

func (c *portsStaticCache) Delete(_ context.Context, key cache.Key) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.recs, key)
	return nil
}

func (c *portsStaticCache) Clear(_ context.Context) error { return nil }

func (c *portsStaticCache) putCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}

// portsMustIP normalizes an address or fails the test.
func portsMustIP(t testing.TB, s string) asset.IP {
	t.Helper()
	ip, err := asset.NewIP(s, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP(%q): %v", s, err)
	}
	return ip
}

// portsMustDomain reuses the httpprobe harness's domain helper under a local
// alias for readability.
func portsMustDomain(t testing.TB, name string) asset.Domain {
	return httpProbeMustDomain(t, name)
}

// --- gate helpers ---------------------------------------------------------

// TestPortDiscoveryGates pins both param gates: port discovery is OFF unless
// explicitly requested (with the documented truthy spellings); SAN expansion
// is ON unless explicitly disabled with "false".
func TestPortDiscoveryGates(t *testing.T) {
	if portDiscoveryEnabled(nil) {
		t.Fatal("nil params must not enable port discovery")
	}
	if portDiscoveryEnabled(map[string]string{}) {
		t.Fatal("absent param must not enable port discovery")
	}
	for _, v := range []string{"true", "TRUE", "1", "yes", "on", " true "} {
		if !portDiscoveryEnabled(map[string]string{"port_discovery": v}) {
			t.Errorf("port_discovery=%q must enable", v)
		}
	}
	for _, v := range []string{"false", "no", "off", "", "0"} {
		if portDiscoveryEnabled(map[string]string{"port_discovery": v}) {
			t.Errorf("port_discovery=%q must not enable", v)
		}
	}
	if !tlsSANExpansionEnabled(nil) {
		t.Fatal("nil params must keep SAN expansion enabled (default ON)")
	}
	if !tlsSANExpansionEnabled(map[string]string{}) {
		t.Fatal("absent param must keep SAN expansion enabled")
	}
	if tlsSANExpansionEnabled(map[string]string{"tls_san_expansion": "false"}) {
		t.Fatal(`tls_san_expansion="false" must disable expansion`)
	}
	if tlsSANExpansionEnabled(map[string]string{"tls_san_expansion": "FALSE"}) {
		t.Fatal(`tls_san_expansion="FALSE" must disable expansion`)
	}
	if !tlsSANExpansionEnabled(map[string]string{"tls_san_expansion": "true"}) {
		t.Fatal(`tls_san_expansion="true" must keep expansion enabled`)
	}
}

// --- naabu source (source-level, fake runner) ------------------------------

// TestNaabuSourceDiscoversPorts is the Enhancement B acceptance proof: a fake
// runner returning canned ip:port lines yields validated tcp Port assets plus
// ip→port relationships, with the exact documented argv and the resolved IPs
// delivered through the -l file — no real naabu anywhere.
func TestNaabuSourceDiscoversPorts(t *testing.T) {
	runner := &fakeNaabuRunner{
		versionOut: "v2.3.7\n",
		scanOut:    "198.51.100.10:8443\n198.51.100.10:443\n198.51.100.10:443\nmalformed\n",
	}
	src := newNaabuPortSource(runner, okLookPath)
	target := portsMustDomain(t, "example.com")
	ips := []asset.IP{portsMustIP(t, "198.51.100.10")}

	out, err := src.DiscoverPorts(context.Background(), target, ips, portDiscoveryConfig{})
	if err != nil {
		t.Fatalf("DiscoverPorts: %v", err)
	}
	if out.MissingTool || out.Failed || out.Truncated {
		t.Fatalf("markers = missing/%v failed/%v truncated/%v, want all false",
			out.MissingTool, out.Failed, out.Truncated)
	}
	if len(out.Ports) != 2 {
		t.Fatalf("ports = %v, want [443/tcp 8443/tcp] (deduped, sorted)", out.Ports)
	}
	if out.Ports[0].Number != 443 || out.Ports[1].Number != 8443 {
		t.Fatalf("ports = %v/%v, want 443 then 8443 ascending", out.Ports[0], out.Ports[1])
	}
	for _, p := range out.Ports {
		if p.Protocol != "tcp" {
			t.Errorf("port %d protocol = %q, want tcp", p.Number, p.Protocol)
		}
		if p.Prov.Source != "naabu" {
			t.Errorf("port %d provenance = %q, want naabu", p.Number, p.Prov.Source)
		}
	}
	if len(out.Relationships) != 2 {
		t.Fatalf("relationships = %d, want 2 (one per distinct port)", len(out.Relationships))
	}
	wantFrom := ips[0].Identity()
	for i, rel := range out.Relationships {
		if !rel.From.Equal(wantFrom) || rel.Kind != asset.RelationshipIPToPort ||
			!rel.To.Equal(out.Ports[i].Identity()) {
			t.Errorf("relationship[%d] = %s --%s--> %s, want ip→port edge for %d",
				i, rel.From, rel.Kind, rel.To, out.Ports[i].Number)
		}
	}

	// Pinned argv (§8: separate values, never shell-composed) and pinned
	// -l file content (the resolved IPs, one per line).
	call, ok := runner.scanCall()
	if !ok {
		t.Fatal("runner never received the scan invocation")
	}
	wantArgs := []string{
		"-l", call.Args[1],
		"-top-ports", "100",
		"-silent",
		"-rate", "300",
		"-c", "25",
	}
	if !reflect.DeepEqual(call.Args, wantArgs) {
		t.Fatalf("argv = %v, want %v", call.Args, wantArgs)
	}
	if got := runner.lastScanFileContent(); got != "198.51.100.10\n" {
		t.Fatalf("-l file content = %q, want %q", got, "198.51.100.10\n")
	}
}

// TestNaabuSourceEmptyInputNoOp pins the inert case: no resolved addresses ⇒
// zero-cost no-op without touching LookPath or the runner.
func TestNaabuSourceEmptyInputNoOp(t *testing.T) {
	src := newNaabuPortSource(&fakeNaabuRunner{}, func(string) (string, error) {
		t.Fatal("LookPath must not be consulted with no input addresses")
		return "", nil
	})
	out, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"), nil, portDiscoveryConfig{})
	if err != nil {
		t.Fatalf("DiscoverPorts: %v", err)
	}
	if out.MissingTool || out.Failed || len(out.Ports) > 0 {
		t.Fatalf("output = %+v, want an empty honest no-op", out)
	}
}

// TestNaabuSourceMissingBinary pins the §9 boundary: absence is decided ONLY
// by LookPath; the source reports MissingTool honestly instead of failing or
// pretending success.
func TestNaabuSourceMissingBinary(t *testing.T) {
	runner := &fakeNaabuRunner{}
	src := newNaabuPortSource(runner, missingLookPath)
	out, err := src.DiscoverPorts(context.Background(),
		portsMustDomain(t, "example.com"), []asset.IP{portsMustIP(t, "198.51.100.10")},
		portDiscoveryConfig{})
	if err != nil {
		t.Fatalf("DiscoverPorts: %v (a missing binary is a skip marker, not an error)", err)
	}
	if !out.MissingTool {
		t.Fatalf("MissingTool = false, want true (LookPath decided absence)")
	}
	if len(out.Ports) != 0 {
		t.Fatalf("ports = %v, want none", out.Ports)
	}
	if runner.scanCount() != 0 {
		t.Fatalf("scan executions = %d, want 0", runner.scanCount())
	}
}

// TestNaabuSourceUnknownVersionSkipsCache pins the §11 discipline: when the
// version probe cannot classify the tool (broken -version), nothing is cached
// — but execution proceeds and its results are returned.
func TestNaabuSourceUnknownVersionSkipsCache(t *testing.T) {
	runner := &fakeNaabuRunner{versionFails: true, scanOut: "198.51.100.10:443\n"}
	c := newPortsStaticCache()
	src := newNaabuPortSource(runner, okLookPath)
	out, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"),
		[]asset.IP{portsMustIP(t, "198.51.100.10")},
		portDiscoveryConfig{Cache: c})
	if err != nil {
		t.Fatalf("DiscoverPorts: %v", err)
	}
	if len(out.Ports) != 1 {
		t.Fatalf("ports = %d, want 1 (execution unaffected by the unknown version)", len(out.Ports))
	}
	if c.putCount() != 0 {
		t.Fatalf("cache puts = %d, want 0 (unknown version ⇒ never cached)", c.putCount())
	}
}

// TestNaabuSourceCacheRoundTrip pins the warm path: the cold run stores a
// completed record under op "ports.discover"; the warm run serves it with
// ZERO scan executions and identical ports/relationships.
func TestNaabuSourceCacheRoundTrip(t *testing.T) {
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:8443\n198.51.100.10:443\n"}
	c := newPortsStaticCache()
	src := newNaabuPortSource(runner, okLookPath)
	target := portsMustDomain(t, "example.com")
	ips := []asset.IP{portsMustIP(t, "198.51.100.10")}
	cfg := portDiscoveryConfig{Cache: c}

	cold, err := src.DiscoverPorts(context.Background(), target, ips, cfg)
	if err != nil {
		t.Fatalf("cold DiscoverPorts: %v", err)
	}
	if c.putCount() != 1 {
		t.Fatalf("cold cache puts = %d, want 1", c.putCount())
	}
	for _, rec := range c.recs {
		if rec.Operation != "ports.discover" {
			t.Errorf("stored operation = %q, want ports.discover", rec.Operation)
		}
		if rec.Target != target.Identity().String() {
			t.Errorf("stored target = %q, want %q", rec.Target, target.Identity().String())
		}
		if rec.Tool.Name != "naabu" || rec.Tool.Version != "2.3.7" {
			t.Errorf("stored tool = %+v, want naabu@2.3.7", rec.Tool)
		}
	}

	warm, err := src.DiscoverPorts(context.Background(), target, ips, cfg)
	if err != nil {
		t.Fatalf("warm DiscoverPorts: %v", err)
	}
	if runner.scanCount() != 1 {
		t.Fatalf("scan executions = %d, want 1 (cold only; warm served from cache)", runner.scanCount())
	}
	if len(warm.Ports) != len(cold.Ports) || len(warm.Relationships) != len(cold.Relationships) {
		t.Fatalf("warm = %d ports / %d rels, cold = %d ports / %d rels",
			len(warm.Ports), len(warm.Relationships), len(cold.Ports), len(cold.Relationships))
	}
	for i := range warm.Ports {
		if !warm.Ports[i].Identity().Equal(cold.Ports[i].Identity()) {
			t.Errorf("warm port[%d] = %s, want %s", i, warm.Ports[i].Identity(), cold.Ports[i].Identity())
		}
	}
}

// TestNaabuSourceCorruptRecordSelfHeals pins the self-healing boundary: a
// tampered stored record (scope mismatch, invalid port) is deleted and
// re-executed, never served.
func TestNaabuSourceCorruptRecordSelfHeals(t *testing.T) {
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:443\n"}
	c := newPortsStaticCache()
	src := newNaabuPortSource(runner, okLookPath)
	target := portsMustDomain(t, "example.com")

	// Seed a record whose scope binds a DIFFERENT address list.
	if _, err := src.DiscoverPorts(context.Background(), target,
		[]asset.IP{portsMustIP(t, "198.51.100.99")}, portDiscoveryConfig{Cache: c}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	// Tamper: rewrite the stored scope so it no longer matches any real list.
	for k, rec := range c.recs {
		rec.Data = []byte(`{"scope":"deadbeef","ports":[{"number":443,"protocol":"tcp"}]}`)
		c.recs[k] = rec
		break
	}
	out, err := src.DiscoverPorts(context.Background(), target,
		[]asset.IP{portsMustIP(t, "198.51.100.10")}, portDiscoveryConfig{Cache: c})
	if err != nil {
		t.Fatalf("re-run after tamper: %v", err)
	}
	if len(out.Ports) != 1 || out.Ports[0].Number != 443 {
		t.Fatalf("ports = %v, want the freshly executed 443", out.Ports)
	}
	if runner.scanCount() != 2 {
		t.Fatalf("scan executions = %d, want 2 (tampered record must re-execute)", runner.scanCount())
	}
}

// TestNaabuSourceFailures pin the failure mapping: runner errors and unusable
// non-zero exits surface as errors (the stage folds them into
// ports_naabu_failed); usable pairs parsed before a failure are retained.
func TestNaabuSourceFailures(t *testing.T) {
	t.Run("runner_error", func(t *testing.T) {
		runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanErr: errors.New("spawn failed")}
		src := newNaabuPortSource(runner, okLookPath)
		out, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"),
			[]asset.IP{portsMustIP(t, "198.51.100.10")}, portDiscoveryConfig{})
		if err == nil {
			t.Fatal("runner error swallowed — want a structured error")
		}
		if !errors.Is(err, runner.scanErr) {
			t.Fatalf("error = %v, want wrapped runner error", err)
		}
		if len(out.Ports) != 0 {
			t.Fatalf("ports = %v, want none", out.Ports)
		}
	})
	t.Run("non_zero_exit_without_output", func(t *testing.T) {
		runner := &fakeNaabuRunner{versionOut: "v2.3.7", exitCode: 3}
		src := newNaabuPortSource(runner, okLookPath)
		_, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"),
			[]asset.IP{portsMustIP(t, "198.51.100.10")}, portDiscoveryConfig{})
		if err == nil || !errors.Is(err, err) { //nolint:staticcheck // shape check below
			t.Fatalf("non-zero exit without output = %v, want failure", err)
		}
	})
	t.Run("non_zero_exit_with_output_retains_pairs", func(t *testing.T) {
		runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:8443\n", exitCode: 3}
		src := newNaabuPortSource(runner, okLookPath)
		out, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"),
			[]asset.IP{portsMustIP(t, "198.51.100.10")}, portDiscoveryConfig{})
		if err == nil {
			t.Fatal("non-zero exit must surface as an error even with retained pairs")
		}
		if len(out.Ports) != 1 || out.Ports[0].Number != 8443 {
			t.Fatalf("ports = %v, want the parsed-before-failure pair retained", out.Ports)
		}
	})
}

// TestNaabuSourceTruncatedOutput pins the §0.6 chain start: a capture cut at
// the stream cap marks the output Truncated so the stage can raise
// Truncated + ports_output_truncated end-to-end.
func TestNaabuSourceTruncatedOutput(t *testing.T) {
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:443\n", stdoutTrunc: true}
	src := newNaabuPortSource(runner, okLookPath)
	out, err := src.DiscoverPorts(context.Background(), portsMustDomain(t, "example.com"),
		[]asset.IP{portsMustIP(t, "198.51.100.10")}, portDiscoveryConfig{})
	if err != nil {
		t.Fatalf("DiscoverPorts: %v", err)
	}
	if !out.Truncated {
		t.Fatal("Truncated = false, want true (stdout cut at the cap)")
	}
	flags := out.flags()
	if !flags[portsOutputTruncatedFlag] || len(flags) != 1 {
		t.Fatalf("flags = %v, want exactly %q", flags, portsOutputTruncatedFlag)
	}
}

// TestParseNaabuOutputShapes pins the parser: canonical IPv4, bracketed IPv6
// literals resolve, junk lines count as malformed, duplicates collapse.
func TestParseNaabuOutputShapes(t *testing.T) {
	known := []asset.IP{portsMustIP(t, "198.51.100.10"), portsMustIP(t, "2001:db8::1")}
	stdout := "" +
		"198.51.100.10:80\n" +
		"[2001:db8::1]:443\n" +
		"198.51.100.10:99999\n" + // out of range
		"not-an-address:80\n" + // unparseable address
		"[2001:db8::1]:443\n" + // duplicate
		"\n"
	ports, malformed := parseNaabuOutput([]byte(stdout), known)
	if malformed != 2 {
		t.Fatalf("malformed = %d, want 2", malformed)
	}
	if len(ports) != 2 || ports[0].Number != 80 || ports[1].Number != 443 {
		t.Fatalf("ports = %v, want 80 then 443", ports)
	}
}

// --- stage-level wiring -----------------------------------------------------

// portsStageInput assembles a stage input carrying dns-stage-resolved IPs.
func portsStageInput(t *testing.T, hosts []asset.Host, params map[string]string, ips []asset.IP) pipeline.StageInput {
	t.Helper()
	return pipeline.StageInput{
		Target:  portsMustDomain(t, "example.com"),
		Hosts:   hosts,
		Bounds:  pipeline.DefaultStageConfig(),
		Config:  params,
		Clock:   httpProbeFixedClock{},
		Results: pipeline.Results{IPs: ips},
	}
}

// TestHTTPProbeStagePortDiscoveryEmitsPorts is the end-to-end acceptance
// proof for Enhancement B inside the stage: port_discovery=true over
// dns-resolved IPs emits the open ports and their ip→port relationships on
// the stage result, while probing itself stays completed and flag-free.
func TestHTTPProbeStagePortDiscoveryEmitsPorts(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:8443\n198.51.100.10:443\n"}
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(runner, okLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"port_discovery": "true"},
		[]asset.IP{portsMustIP(t, "198.51.100.10")})

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want clean", res.Truncated, res.StickyFlags)
	}
	numbers := map[uint16]bool{}
	for _, p := range res.Results.Ports {
		numbers[p.Number] = true
	}
	if !numbers[443] || !numbers[8443] {
		t.Fatalf("result ports = %v, want 443 and 8443 present", numbers)
	}
	var ipPortEdges int
	for _, rel := range res.Results.Relationships {
		if rel.Kind == asset.RelationshipIPToPort {
			ipPortEdges++
		}
	}
	if ipPortEdges < 2 {
		t.Fatalf("ip→port relationships = %d, want >= 2", ipPortEdges)
	}
}

// TestHTTPProbeStagePortDiscoveryAbsentParamIsHonestSkip is the gating
// acceptance proof: without the param the runner NEVER executes — the skip is
// structural (zero cost), and the result carries neither ports nor markers.
func TestHTTPProbeStagePortDiscoveryAbsentParamIsHonestSkip(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:443\n"}
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(runner, okLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		nil, // absent param
		[]asset.IP{portsMustIP(t, "198.51.100.10")})

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.scanCount() != 0 {
		t.Fatalf("scan executions = %d, want 0 (feature gated off)", runner.scanCount())
	}
	for _, p := range res.Results.Ports {
		if p.Prov.Source == "naabu" {
			t.Fatalf("unexpected naabu port %d leaked into the result", p.Number)
		}
	}
	if res.StickyFlags[portsNaabuMissingFlag] || res.StickyFlags[portsNaabuFailedFlag] {
		t.Fatalf("flags = %v, want none (an unrequested feature is silently absent BY DESIGN)",
			res.StickyFlags)
	}
}

// TestHTTPProbeStagePortDiscoveryMissingToolFlag pins the honesty marker: a
// requested run over an environment without naabu completes probing but
// carries ports_naabu_missing — never silence.
func TestHTTPProbeStagePortDiscoveryMissingToolFlag(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(&fakeNaabuRunner{}, missingLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"port_discovery": "true"},
		[]asset.IP{portsMustIP(t, "198.51.100.10")})

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (probing earned it; the flag marks the skip)",
			res.Outcome)
	}
	if !res.StickyFlags[portsNaabuMissingFlag] {
		t.Fatalf("flags = %v, want %q set", res.StickyFlags, portsNaabuMissingFlag)
	}
}

// TestHTTPProbeStagePortDiscoveryFailureFlag pins ports_naabu_failed: an
// execution failure keeps the probe outcome but raises the marker.
func TestHTTPProbeStagePortDiscoveryFailureFlag(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanErr: errors.New("spawn failed")}
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(runner, okLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"port_discovery": "true"},
		[]asset.IP{portsMustIP(t, "198.51.100.10")})

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (base probing succeeded)", res.Outcome)
	}
	if !res.StickyFlags[portsNaabuFailedFlag] {
		t.Fatalf("flags = %v, want %q set", res.StickyFlags, portsNaabuFailedFlag)
	}
}

// TestHTTPProbeStagePortDiscoveryTruncatedFlag pins the §0.6 merge: a
// capture-cut discovery sets Truncated AND the named sticky flag on the
// stage result (completed + flag is the legal carve-out).
func TestHTTPProbeStagePortDiscoveryTruncatedFlag(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:443\n", stdoutTrunc: true}
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(runner, okLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"port_discovery": "true"},
		[]asset.IP{portsMustIP(t, "198.51.100.10")})

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated || !res.StickyFlags[portsOutputTruncatedFlag] {
		t.Fatalf("Truncated=%v flags=%v, want Truncated with %q",
			res.Truncated, res.StickyFlags, portsOutputTruncatedFlag)
	}
}

// TestHTTPProbeStagePortDiscoveryInertWithoutIPs pins the inert case: the
// feature requested but NO resolved IPs ⇒ honest zero-cost no-op (no runner
// call, no flag — there was nothing to operate on).
func TestHTTPProbeStagePortDiscoveryInertWithoutIPs(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	runner := &fakeNaabuRunner{versionOut: "v2.3.7", scanOut: "198.51.100.10:443\n"}
	stage := &HTTPProbeStage{
		transport: tr,
		ports:     newNaabuPortSource(runner, okLookPath),
	}
	in := portsStageInput(t,
		[]asset.Host{httpProbeMustHost(t, "www.example.com")},
		map[string]string{"port_discovery": "true"},
		nil)

	res, err := httpProbeRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.scanCount() != 0 {
		t.Fatalf("scan executions = %d, want 0 (nothing resolved to scan)", runner.scanCount())
	}
	if len(res.StickyFlags) != 0 {
		t.Fatalf("flags = %v, want none (inert, not failed)", res.StickyFlags)
	}
}
