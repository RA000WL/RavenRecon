package adapt

// T4 determinism coverage (milestone T4 — determinism, discovery clock
// seam): the FULL ten-stage pipeline with the REAL discovery adapter
// (hermetic fake runner + fake lookPath constructor seams) driving the
// remaining nine real stages, pinning the v1.3 acceptance criterion
// "pipeline runs are deterministic for the same input and config" across
// the discovery stage — the one stage the T3d3 integration run excluded by
// contract (a fake seed stage stood in under the discover name).
//
// The run is fully hermetic (same shapes as t3d_integration_test.go): a
// fake resolver, a canned HTTP transport, a scripted gau runner, a
// loopback HTTP server serving synthetic script bodies, the package's
// synthetic secret database and priority catalogs, a hermetic detect
// registry, and a capture reporter. Synthetic values only (AGENTS §0.8).
//
// What the tests prove:
//
//   - TestT4FullRunDeterminismWithRealDiscovery: three identical runs with
//     the discovery stage at Concurrency 4 DeepEqual pairwise — the pin
//     that the per-source discovery result order is selection order
//     (never pool-completion order) and that no scheduling effect leaks
//     into the RunReport. The proof runs under GENUINELY overlapping
//     jobs: the discovery stage's rate limit stays disabled (the
//     pipeline's Rate-0 default — pacing would serialize the jobs) and a
//     barrier in the fake runner holds all three discovery executions
//     inside Run until every one has arrived, on every run; every corpus
//     host's provenance DiscoveredAt is the fixed clock instant (the clock
//     bridge is the only clock the engine can see).
//   - TestT4FullRunCacheHitParity: a second run over the same filesystem
//     cache serves the known-version discovery sources (subfinder, amass)
//     from cache — zero discovery executions for them; assetfinder (no
//     detectable version, NON-CACHEABLE by policy) still executes — and
//     the RunReport DeepEquals the first run. Zero-request pins for the
//     downstream stages' own caches (dns, httpprobe, jsintel) prove the
//     whole run was served warm.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

func init() {
	if os.Getenv("PDCP_API_KEY") == "" {
		_ = os.Setenv("PDCP_API_KEY", "testkey")
	}
}

// t4DiscoveryScript scripts the four built-in discovery tools to emit
// exactly the corpus the T3d3 harness seeds (www/api/admin.example.com),
// so the downstream stages exercise the same pinned shapes. The duplicate
// www line (subfinder + assetfinder) pins the cross-source provenance
// merge: earliest-wins with ties resolving to the first source in
// selection order (subfinder). admin is emitted by assetfinder AND amass
// AND chaos, so its provenance source is assetfinder (first-encountered).
//
// The "-version"/"-h" entries are the detection probes (the engine's
// tool-specific detection argv, internal/discovery/{subfinder,assetfinder,
// amass,chaos}.go); the remaining entries are the discovery executions.
// Chaos returns a duplicate admin host so the merged corpus stays 3 hosts
// and the downstream pins (3 IPs, 15 surfaces, etc.) remain stable.
func t4DiscoveryScript() map[string]func(discovery.Cmd) (discovery.RunResult, error) {
	return map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"subfinder -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("Current Version: v2.6.3\n")}, nil
		},
		"assetfinder -h": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stderr: []byte("Usage: assetfinder [domain]\n"), ExitCode: 2}, nil
		},
		"amass -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("v3.23.0\n")}, nil
		},
		"chaos -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("chaos v0.5.3\n")}, nil
		},
		"subfinder -d example.com -silent": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
		},
		"assetfinder example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("www.example.com\nadmin.example.com\n")}, nil
		},
		"amass enum -passive -d example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("admin.example.com\n")}, nil
		},
		"chaos -d example.com -silent -json": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("{\"domain\":\"admin.example.com\"}\n")}, nil
		},
	}
}

// t4DiscoveryExecutions counts the runner invocations that are discovery
// EXECUTIONS (not detection probes): the engine's detection invocations
// are exactly the "-version"/"-h" argv forms, everything else is a
// discovery execution. A cached source performs no discovery execution on
// a warm run, but its detection probe still runs (the detected version is
// the cache key's tool identity).
func t4DiscoveryExecutions(r *fakeRunner) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if len(c.cmd.Args) == 0 {
			continue
		}
		switch c.cmd.Args[0] {
		case "-version", "-h":
		default:
			n++
		}
	}
	return n
}

// t4GauExecutions counts the urlintel stage's gau EXECUTIONS (argv
// "gau <domain>", Path "gau") — the tool's detection probe is "gau
// -version" (same Path) and must not count.
func t4GauExecutions(r *fakeRunner) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.cmd.Path == "gau" && len(c.cmd.Args) > 0 && c.cmd.Args[0] != "-version" {
			n++
		}
	}
	return n
}

// t4JSLoopback starts the loopback server serving t3dScriptBodies plus a
// fallback body for every other path (the corpus root/graphql URLs the
// other stages produced), exactly like t3dJSLoopback, plus a request
// counter so the cache-hit test can prove the jsintel stage performs zero
// HTTP requests on the warm run.
func t4JSLoopback(t *testing.T) (*httptest.Server, *rewriteTransport, func() int) {
	t.Helper()
	bodies := t3dScriptBodies()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		body, ok := bodies[r.URL.Path]
		if !ok {
			body = "window.ready = true;\n"
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &rewriteTransport{base: srv.URL}, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// t4Harness bundles every hermetic fixture the full-run tests share, so
// the two tests exercise byte-identical stage wiring and only vary the
// run mode (fresh runs vs cache-warm runs).
type t4Harness struct {
	discoveryRunner *fakeRunner
	gauRunner       *fakeRunner
	resolver        *fakeResolver
	transport       *cannedTransport
	jsTransport     *rewriteTransport
	jsRequests      func() int
	detectReg       *detect.Registry
	reportReg       *report.Registry
	interesting     *priority.Catalog
	risk            *priority.Catalog
	secretDB        *patterns.DB
	models          []*report.Model
}

func newT4Harness(t *testing.T) *t4Harness {
	t.Helper()
	h := &t4Harness{
		discoveryRunner: newFakeRunner(t4DiscoveryScript()),
		gauRunner:       newFakeRunner(gauLines("example.com", "http://www.example.com/app.js", "http://api.example.com/lib.js?v=2", "http://www.example.com/graphql", "http://www.example.com/app.js")),
		secretDB:        testSecretDB(t),
	}
	h.resolver = newFakeResolver()
	h.resolver.set("www.example.com", dns.TypeA, "93.184.216.34")
	h.resolver.set("api.example.com", dns.TypeA, "93.184.216.35")
	h.resolver.set("admin.example.com", dns.TypeA, "93.184.216.36")

	h.transport = &cannedTransport{}
	for _, host := range []string{"www.example.com", "api.example.com", "admin.example.com"} {
		cannedHost(h.transport, host, cannedResponse{
			status:  200,
			body:    "<!doctype html><html><body>hello</body></html>",
			headers: map[string]string{"Content-Type": "text/html"},
		})
	}

	_, h.jsTransport, h.jsRequests = t4JSLoopback(t)

	h.detectReg = newDetectRegistry(t, t3dTechListingRule(t))
	h.reportReg = newReportRegistry(t, captureReporter("capture", func(m *report.Model) { h.models = append(h.models, m) }))
	h.interesting, h.risk = priorityCatalogs(t)
	return h
}

// stages wires the full ten-stage pipeline: the REAL discovery adapter
// driving the nine real engines (the T3d3 shapes, re-used verbatim). The
// discovery stage runs through the shared fake runner, whose barrier is a
// pass-through until armed: the determinism test arms it (armBarrier) so
// the three discovery executions genuinely overlap inside the runner; the
// cache-hit test leaves it unarmed (zero behavior change).
func (h *t4Harness) stages() []pipeline.Stage {
	return []pipeline.Stage{
		NewDiscoveryStage(h.discoveryRunner, fakeLookup),
		NewDNSStage(h.resolver),
		NewHTTPProbeStage(h.transport),
		NewURLIntelStage(h.gauRunner, fakeLookup),
		NewTechIntelStage(nil), // production fingerprint database
		NewJSIntelStage(h.jsTransport),
		NewSecretIntelStage(h.secretDB),
		NewPriorityStage(h.interesting, h.risk),
		NewDetectStage(h.detectReg),
		NewReportStage(h.reportReg),
	}
}

// t4ScanConfig is the full ten-stage selection with the discovery stage's
// concurrency explicitly pinned to 4 (the pipeline default is already 4;
// the explicit bound makes the race-condition proof self-documenting).
// Rate stays at the pipeline default 0 — job-start rate limiting disabled
// (the discovery engine disables it for Rate <= 0) — so pacing can never
// serialize the three discovery jobs: the Concurrency-4 overlap proof must
// come from the jobs themselves racing on the pool, not from the absence
// of rate-limit serialization.
func t4ScanConfig(t *testing.T) pipeline.ScanConfig {
	t.Helper()
	return pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: pipeline.AllStages(),
		StageBounds: map[pipeline.StageName]pipeline.StageConfig{
			pipeline.StageDiscover: {
				MaxConcurrency: 4,
				QueueSize:      8,
				Rate:           0, // the pipeline default: rate limiting disabled (0 disables)
			},
		},
	}
}

// t4HostNames returns the hosts' canonical names in corpus order.
func t4HostNames(hosts []asset.Host) []string {
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Name
	}
	return names
}

// TestT4FullRunDeterminismWithRealDiscovery is the T4 determinism pin:
// THREE identical full-pipeline runs with the REAL discovery adapter at
// Concurrency 4 DeepEqual pairwise. The proof has three parts, all under
// genuinely overlapping discovery jobs:
//
//   - the discovery stage's per-source report order is selection order at
//     any concurrency (pre-allocated slots, internal/discovery/pipeline.go
//     — never pool-completion order), so the merged corpus handed to the
//     downstream stages is identical across racing runs; the rate limiter
//     stays disabled (the pipeline's Rate-0 default — pacing would
//     serialize the jobs) and a barrier in the fake runner (armBarrier)
//     holds all three discovery executions inside Run until every one has
//     arrived, so the jobs race on the pool for real on every run;
//   - every corpus host's provenance DiscoveredAt is the fixed clock
//     instant with the tool-name source (the adapter's clock bridge is the
//     only clock the engine can see — no wall clock reaches the report);
//   - the downstream nine stages consume a byte-identical corpus and
//     produce a byte-identical RunReport (the T3d3-pinned shapes, now
//     driven by real discovery input).
func TestT4FullRunDeterminismWithRealDiscovery(t *testing.T) {
	h := newT4Harness(t)
	cfg := t4ScanConfig(t)
	clk := fixedClock{now: fixedTime}

	run := func() pipeline.RunReport {
		// Re-arm the barrier per run: an already-open gate would let the
		// later runs' jobs pass through unblocked (serialized), so every
		// run must re-prove the overlap.
		h.discoveryRunner.armBarrier(4)
		cfg.OutputDir = t.TempDir()
		rep, err := pipeline.Run(context.Background(), cfg, nil, clk, h.stages())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	r1, r2, r3 := run(), run(), run()
	for _, pair := range [][2]pipeline.RunReport{{r1, r2}, {r1, r3}, {r2, r3}} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Fatalf("identical runs differ:\nrun A: %+v\nrun B: %+v", pair[0], pair[1])
		}
	}

	// --- Run-level outcome vocabulary ---
	if r1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", r1.Outcome)
	}
	if len(r1.Stages) != 10 {
		t.Fatalf("Stages = %d, want 10", len(r1.Stages))
	}
	for i, sr := range r1.Stages {
		if sr.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("stage %d (%s) outcome = %q, want completed", i, sr.Name, sr.Outcome)
		}
	}
	if r1.Truncated || len(r1.StickyFlags) != 0 {
		t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty", r1.Truncated, r1.StickyFlags)
	}
	if r1.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", r1.ItemsFailed)
	}

	// --- Corpus: the discovery stage's merged host set, in the engine's
	// deterministic selection-order merge (per-source reports sorted by
	// canonical name, merged first-seen). The discovery adapter adds NO
	// domains (the declared target lives in Target, never in
	// Additions.Domains — adapt/discovery.go), so the domain corpus stays
	// empty and the priority surfaces reflect hosts + URLs only. ---
	if len(r1.Domains) != 0 {
		t.Errorf("Domains = %+v, want empty (the discovery adapter reports hosts only)", r1.Domains)
	}
	wantHosts := []string{"admin.example.com", "api.example.com", "www.example.com"}
	if got := t4HostNames(r1.Hosts); !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("Hosts = %v, want %v (merged in the sorted All() order)", got, wantHosts)
	}
	if len(r1.URLs) != 12 {
		t.Errorf("URLs = %d, want 12 (6 probed roots + 3 urlintel additions + 3 jsintel feedback)", len(r1.URLs))
	}

	// --- Provenance: every corpus host's DiscoveredAt is the injected
	// clock instant — the clock bridge — and the source is the tool that
	// first observed it (earliest-wins merge; ties resolve to the
	// first-encountered source in selection order). ---
	provByHost := make(map[string]asset.Provenance, len(r1.Hosts))
	for _, hh := range r1.Hosts {
		provByHost[hh.Name] = hh.Prov
	}
	wantProv := map[string]string{
		"www.example.com":   "subfinder",   // subfinder + assetfinder → first source
		"api.example.com":   "subfinder",   // subfinder only
		"admin.example.com": "assetfinder", // assetfinder + amass → first source
	}
	for name, src := range wantProv {
		p, ok := provByHost[name]
		if !ok {
			t.Errorf("corpus missing host %s", name)
			continue
		}
		if !p.DiscoveredAt.Equal(fixedTime) {
			t.Errorf("host %s provenance DiscoveredAt = %v, want %v (the injected clock, never the wall clock)", name, p.DiscoveredAt, fixedTime)
		}
		if p.Source != src {
			t.Errorf("host %s provenance source = %q, want %q", name, p.Source, src)
		}
	}

	// --- Results channels: the T3d3-pinned producer shapes, minus the
	// domain surface the seed stage used to add (12 = 3 hosts + 9 URLs). ---
	res := r1.Results
	if got := len(res.IPs); got != 3 {
		t.Errorf("IPs = %d, want 3 (one canonical A record per host)", got)
	}
	if got := len(res.Parameters); got != 1 {
		t.Errorf("Parameters = %d, want 1 (the query parameter of lib.js?v=2)", got)
	}
	if got := len(res.Findings); got != 1 {
		t.Errorf("Findings = %d, want 1 (the technology-listing rule)", got)
	}
	if got := len(res.Surfaces); got != 15 {
		t.Errorf("Surfaces = %d, want 15 (3 hosts + 12 URLs; discovery adds no domain surface)", got)
	}
	if got := len(res.Groups); got != 1 {
		t.Fatalf("Groups = %d, want 1 (every surface anchors at example.com)", got)
	}
	if got := res.Groups[0].Anchor.String(); got != "domain:example.com" {
		t.Errorf("group anchor = %s, want domain:example.com", got)
	}
	if got := len(res.Groups[0].Members); got != 15 {
		t.Errorf("group members = %d, want 15", got)
	}
	if got := len(res.AttackPaths); got != 1 {
		t.Errorf("AttackPaths = %d, want 1 (the admin host is a factor-carrying member)", got)
	}

	// --- Documents: the jsintel → secrentel flow carries the synthetic
	// key. ---
	docByID := make(map[string]pipeline.Document, len(r1.Documents))
	for _, d := range r1.Documents {
		docByID[d.Identity.String()] = d
	}
	appJS, err := asset.NewJavaScript("http://www.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	appDoc, ok := docByID[appJS.Identity().String()]
	if !ok {
		t.Fatalf("Documents missing the app.js document (got %d documents)", len(r1.Documents))
	}
	if appDoc.Truncated || !strings.Contains(string(appDoc.Content), awsKey(7)) {
		t.Errorf("app.js document: Truncated=%v, carries the synthetic key = %v",
			appDoc.Truncated, strings.Contains(string(appDoc.Content), awsKey(7)))
	}

	// --- The report stage's captured models: one per run (the harness
	// appends every capture into h.models, so the assertion is not
	// last-run-only), each with the fixed-clock bracket. The pairwise
	// RunReport DeepEqual above already pins cross-run determinism; the
	// per-run model check makes the model assertion honest for every run.
	// ---
	if len(h.models) != 3 {
		t.Fatalf("captured report models = %d, want 3 (one per run)", len(h.models))
	}
	for i, m := range h.models {
		if m == nil {
			t.Fatalf("captured report model %d is nil", i)
		}
		if m.Target != "example.com" || !m.StartedAt.Equal(fixedTime) || !m.EndedAt.Equal(fixedTime) {
			t.Errorf("model %d target/bracket = %q %v..%v, want example.com %v..%v",
				i, m.Target, m.StartedAt, m.EndedAt, fixedTime, fixedTime)
		}
	}
}

// TestT4FullRunCacheHitParity pins cache-hit vs execute parity at the
// FULL-run level: a second run over the same filesystem cache serves the
// known-version discovery sources from cache — zero discovery executions
// for subfinder and amass; assetfinder (no detectable version,
// NON-CACHEABLE by policy) executes fresh — and the RunReport DeepEquals
// the cold run. The downstream stages' own caches are pinned as a bonus:
// zero new dns queries, zero new http probes, and zero jsintel HTTP
// requests on the warm run. The urlintel stage's tool invocation is NOT
// cached by design (its per-URL extraction records are), so gau executes
// once per run — the warm run's extraction still comes from cache.
func TestT4FullRunCacheHitParity(t *testing.T) {
	h := newT4Harness(t)
	cfg := t4ScanConfig(t)
	clk := fixedClock{now: fixedTime}
	c, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}

	run := func() pipeline.RunReport {
		cfg.OutputDir = t.TempDir()
		rep, err := pipeline.Run(context.Background(), cfg, c, clk, h.stages())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	r1 := run()
	if r1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("cold run Outcome = %q, want completed", r1.Outcome)
	}
	if got := t4DiscoveryExecutions(h.discoveryRunner); got != 4 {
		t.Fatalf("cold run discovery executions = %d, want 4 (subfinder + assetfinder + amass + chaos)", got)
	}
	dnsAfterCold := h.resolver.callCount()
	httpAfterCold := h.transport.requestCount()
	gauAfterCold := t4GauExecutions(h.gauRunner)
	jsAfterCold := h.jsRequests()
	if jsAfterCold == 0 {
		t.Fatal("cold run made no jsintel HTTP requests, want >= 1")
	}

	r2 := run()
	if r2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("warm run Outcome = %q, want completed", r2.Outcome)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("cache-hit run differs from the cold run:\ncold: %+v\nwarm: %+v", r1, r2)
	}
	// Known-version tools (subfinder, amass, chaos) served from cache: exactly
	// ONE discovery execution on the warm run — assetfinder, the
	// NON-CACHEABLE unknown-version source (its -h detection probe still
	// runs, but that is detection, not discovery).
	if got := t4DiscoveryExecutions(h.discoveryRunner); got != 5 {
		t.Fatalf("warm run discovery executions = %d, want 5 (4 cold + 1 warm assetfinder execution)", got)
	}
	// Bonus zero-request pins: every downstream stage's cache-before-
	// execute served the warm run.
	if got := h.resolver.callCount(); got != dnsAfterCold {
		t.Errorf("warm run dns queries = %d, want %d (zero new queries)", got, dnsAfterCold)
	}
	if got := h.transport.requestCount(); got != httpAfterCold {
		t.Errorf("warm run http requests = %d, want %d (zero new probes)", got, httpAfterCold)
	}
	if got := t4GauExecutions(h.gauRunner); got != gauAfterCold+1 {
		t.Errorf("warm run gau executions = %d, want %d (the tool invocation is not cached; only per-URL extraction is)", got, gauAfterCold+1)
	}
	if got := h.jsRequests(); got != jsAfterCold {
		t.Errorf("warm run jsintel requests = %d, want %d (zero new fetches)", got, jsAfterCold)
	}
}
