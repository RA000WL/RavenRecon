package adapt

// T5 hermetic E2E coverage (milestone T5 — full-run partial failure and
// retry): pins the v1.3 acceptance criteria "End-to-end tests cover
// success, partial failure, and retry paths" (the SUCCESS path was pinned
// by T3d3's TestT3dEndToEndRun; partial failure and retry are T5's) and
// "Intermediate failures do not corrupt the final report" at the FULL-RUN
// level, through the REAL adapters over hermetic fixtures — INCLUDING the
// real discovery stage, driven through the T4 seam (a scripted fake
// discovery.Runner plus a fake LookupFunc constructor hook, exactly
// t4_determinism_test.go's harness; no executables, no network).
//
// The discovery stage is the REAL adapter (NewDiscoveryStage) over the
// hermetic runner, emitting exactly the three in-scope hosts the T3d3
// harness used to seed (www/api/admin.example.com for the declared target
// example.com) with tool-name provenance at the injected clock. Discovery
// reports HOSTS ONLY — Additions.Domains is always empty (the declared
// target lives in StageInput.Target; adapt/discovery.go) — so every corpus
// shape follows T4's pins: 0 domains, 3 hosts (in the discovery engine's
// sorted All() merge order: admin, api, www), 9 URLs (6 probed roots + 3
// urlintel additions), 12 priority surfaces (3 hosts + 9 URLs — discovery
// adds no domain surface), one group of 12 members anchored at
// domain:example.com, one attack path. All downstream fixtures are the
// T3d3/T4 shapes: fake resolver, canned HTTP transport, scripted gau
// runner, loopback HTTP serving synthetic script bodies, synthetic secret
// database and priority catalogs, hermetic detect registry, capture
// reporter — synthetic values only (AGENTS §0.8).
//
// Discovery cache note (T4-pinned; the retry counts mirror it): the
// known-version sources are cached, but the unknown-version source
// (assetfinder, capability-probed with -h) is NON-CACHEABLE —
// internal/discovery/pipeline.go:418-426: no key, no Get, no Put; every
// run executes fresh. The retry tests count discovery executions like T4's
// cache-parity test: 3 after the cold run, 4 after the warm run
// (subfinder/amass served from cache, assetfinder re-executed).
//
// The failure-injection pattern is deterministic and hermetic: a typed
// per-host resolver failure for exactly ONE of the three discovered hosts,
// scripted on the package's fakeResolver (persistent) or through a
// stateful healing wrapper (first call per (host, record type) fails,
// every later call succeeds). The discovery stage must report completed so
// the injected failure stays where the retry contract puts it: the dns
// per-host resolver failure for ONE host. The dns engine classifies a
// plain error as TypeFailed (dns.applyAnswers default branch,
// internal/dns/run.go), so all three of the host's record types
// (A/AAAA/CNAME — dns.hostTypes) fail -> the host is dns.StatusFailed
// ("no usable observations", classifyHost: failed && !completed) -> the
// adapter's per-host fold yields partial (anyFailed && anyCompleted) with
// ItemsFailed = 1, and the runner's foldOutcome over partial + 9 completed
// is partial (pipeline_test.go TestRunPartialWithCompleted: partial +
// completed = partial; failed-with-completed is partial, never failed).
//
// The failure is a FAILURE, never a truncation: no sticky flags, no
// Truncated marker anywhere in the report — the tests assert the absence
// explicitly (AGENTS §0.6: failure != truncation).
//
// Cache contract for failed jobs (what the retry assertions assume,
// evidence-based — see the report): the dns engine stores EVERY terminal
// type classification as a statused Phase 3 record, failed ones included
// (internal/dns/run.go storeType:558-601, typeStatusToCache maps
// TypeFailed/TypeTimedOut -> cache.StatusFailed, cache.go:133-143), but
// the Phase 3 cache NEVER serves a non-completed record as a hit
// (internal/cache/cache.go evaluate:207-209 — any record whose Status is
// not StatusCompleted resolves to StateIncomplete, and internal/dns/run.go
// lookupType:434-443 treats every non-hit as "execute"). A failed job is
// therefore RE-ATTEMPTED on the next run — never cached as success and
// never skipped — while a completed job is served with zero queries. The
// retry tests count resolver invocations to prove both halves: the
// succeeded hosts perform zero additional queries on the warm run, and
// the failed host's queries are re-issued (exactly its 3 types).
//
// What the tests prove:
//
//   - TestT5FullRunPartialFailure: a full ten-stage run with a
//     deterministic mid-pipeline (dns) failure folds the RUN to partial,
//     records the failing stage honestly (partial + ItemsFailed = 1),
//     CONTINUES through all remaining stages to the report, retains only
//     the honest sets (the failed host contributes no IP; every surviving
//     host's downstream work is present and complete), never corrupts the
//     final report model, fires the stage_started/stage_finished event
//     pair for every stage with the failing stage's payload mirroring its
//     StageRecord, sets no spurious truncation flags, and reproduces
//     byte-identically (a second identical run DeepEquals the first,
//     including the event stream).
//
//   - TestT5FullRunRetryHealing: run 1 has one failure point that HEALS
//     on run 2 (stateful resolver fixture). Run 2 over the SAME cache
//     serves every succeeded unit from cache (zero re-execution — no
//     resolver calls for the healed hosts, zero http probes, zero jsintel
//     fetches), RE-ATTEMPTS exactly the failed work (the failed host's 3
//     queries), and completes — DeepEqual against a fresh cold run of the
//     same healed state.
//
//   - TestT5FullRunRetryPersistent: the same failing fixture fails
//     deterministically on every run; run 2 serves the succeeded parts
//     from cache, re-attempts the failing part, fails again — same
//     partial outcome, same ItemsFailed, and the two RunReports are
//     DeepEqual (cache metadata is not part of RunReport; T4 pinned
//     cache-hit parity for the success path, T5 extends the pin to the
//     persistent-failure path).

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// t5Harness bundles every hermetic fixture the three T5 full-run tests
// share, so the tests exercise byte-identical stage wiring and only vary
// the failure injection (the resolver seam), the run mode (fresh runs vs
// cache-warm runs), and the output directories. The discovery runner is
// the shared T4 script (t4DiscoveryScript) — the three T5 tests drive the
// REAL discovery adapter over it, without the T4 determinism test's
// overlap barrier (unarmed, zero behavior change).
type t5Harness struct {
	discoveryRunner *fakeRunner
	gauRunner       *fakeRunner
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

// newT5Harness builds the shared fixtures: the scripted discovery runner
// (the three built-in tools emitting the three in-scope hosts), canned 200
// responses for all three hosts (the transport serves the FULL corpus
// regardless of the dns failure — the pipeline continuing through the
// remaining stages is the point), scripted gau with the T3d3 line set (the
// duplicate app.js line pins first-seen dedup), the loopback JS server
// with a request counter, the hermetic detect registry, the capture
// reporter, the synthetic priority catalogs, and the synthetic secret
// database.
func newT5Harness(t *testing.T) *t5Harness {
	t.Helper()
	h := &t5Harness{
		discoveryRunner: newFakeRunner(t4DiscoveryScript()),
		gauRunner: newFakeRunner(gauLines("example.com",
			"http://www.example.com/app.js",
			"http://api.example.com/lib.js?v=2",
			"http://www.example.com/graphql",
			"http://www.example.com/app.js",
		)),
		secretDB: testSecretDB(t),
	}
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

// t5Stages wires the full ten-stage pipeline: the REAL discovery adapter
// over the hermetic runner (the T4 seam) plus the nine real adapters (the
// T3d3 shapes). resolver is the failure-injection seam each test provides;
// the report stage's commit target comes from the ScanConfig's OutputDir
// (set per run by the tests).
func (h *t5Harness) stages(t *testing.T, resolver dns.Resolver) []pipeline.Stage {
	return []pipeline.Stage{
		NewDiscoveryStage(h.discoveryRunner, fakeLookup),
		NewDNSStage(resolver),
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

// t5DiscoveryExecutions counts the discovery stage's executions through the
// shared runner — exactly T4's helper semantics: detection probes
// ("-version"/"-h") never count. 3 after a cold run; the warm run over the
// same cache adds exactly 1 (the NON-CACHEABLE unknown-version assetfinder
// source re-executes; subfinder/amass are served from cache —
// internal/discovery/pipeline.go:418-426).
func (h *t5Harness) discoveryExecutions() int {
	return t4DiscoveryExecutions(h.discoveryRunner)
}

// t5ScriptedDNSFailure scripts a persistent typed resolution failure for
// one host on every record type the engine queries (dns.hostTypes:
// A/AAAA/CNAME). A plain error classifies as TypeFailed (dns.applyAnswers
// default branch), so every type fails -> the host is StatusFailed and
// the stage folds partial with ItemsFailed = 1.
func t5ScriptedDNSFailure(resolver *fakeResolver, host string) {
	for _, rt := range []dns.RecordType{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		resolver.setErr(host, rt, errors.New("synthetic resolver failure (hermetic fixture)"))
	}
}

// healingResolver is the stateful, race-free healing seam: the FIRST
// Lookup for each (host, record type) pair of the configured failing host
// fails with a plain error (classified TypeFailed by the dns engine),
// every later lookup for that pair delegates to the wrapped fakeResolver.
// All other hosts always delegate — only the injected failure point
// heals. A mutex guards the per-pair state; the dns engine queries the
// hosts' types from concurrent jobs, so the first-call-failure invariant
// must hold under -race. It counts every invocation so tests can prove
// exactly which queries were re-attempted.
type healingResolver struct {
	mu       sync.Mutex
	base     *fakeResolver
	failHost string
	failed   map[string]bool
	calls    int
}

func newHealingResolver(base *fakeResolver, failHost string) *healingResolver {
	return &healingResolver{base: base, failHost: failHost, failed: make(map[string]bool)}
}

// Lookup implements dns.Resolver.
func (h *healingResolver) Lookup(ctx context.Context, host string, rt dns.RecordType) ([]string, error) {
	key := host + "\x00" + string(rt)
	h.mu.Lock()
	h.calls++
	first := false
	if host == h.failHost {
		first = !h.failed[key]
		if first {
			h.failed[key] = true
		}
	}
	h.mu.Unlock()
	if first {
		return nil, fmt.Errorf("synthetic resolver failure for %s %s (hermetic fixture)", host, rt)
	}
	return h.base.Lookup(ctx, host, rt)
}

// callCount reports the total number of Lookup invocations (including the
// ones that failed).
func (h *healingResolver) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// t5Observer is a concurrency-safe event.Observer recording every event,
// exactly like the pipeline package's recordingObserver (the adapt package
// cannot import it — it is unexported). Run emits synchronously in the
// caller's goroutine, so the recorded order is the emission order; the
// mutex keeps the recorder honest under -race.
type t5Observer struct {
	mu     sync.Mutex
	events []event.Event
}

func (o *t5Observer) Observe(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *t5Observer) snapshot() []event.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]event.Event, len(o.events))
	copy(out, o.events)
	return out
}

// t5stageEventKinds flattens a recorded event stream to its kinds.
func t5stageEventKinds(events []event.Event) []event.Kind {
	kinds := make([]event.Kind, len(events))
	for i, ev := range events {
		kinds[i] = ev.Kind
	}
	return kinds
}

// t5ipValues renders the IP results channel as address strings.
func t5ipValues(ips []asset.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// TestT5FullRunPartialFailure is the partial-failure E2E pin: a full
// ten-stage run — REAL discovery over the hermetic runner, then the real
// dns/httpprobe/urlintel/techintel/jsintel/secrentel/priority/detect/
// report stages — in which the DNS resolver fails deterministically for
// exactly ONE of the three discovered hosts (admin.example.com, on every
// record type). It proves, evidence-based:
//
//   - the run folds PARTIAL (partial + 9 completed — never failed, never
//     completed; pipeline foldOutcome precedence);
//   - the discovery stage genuinely ran and completed (ItemsProcessed 5 =
//     the three tools' per-source host lists; three discovery executions;
//     no failures; hosts-only additions with the injected-clock
//     provenance);
//   - the failing stage's StageRecord is honest: partial, ItemsProcessed
//     3, ItemsFailed 1, Err nil (per-host failures fold into the outcome,
//     they are not stage errors), no truncation marker, no sticky flags —
//     failure != truncation (AGENTS §0.6);
//   - the pipeline CONTINUED through all nine remaining stages to the
//     report (every later stage completed, the report model was captured);
//   - the retained data is honest: the failed host contributes no IP (the
//     IPs channel carries exactly the two surviving hosts' addresses), the
//     surviving hosts' downstream work is present and complete (jsintel/
//     urlintel/techintel/secrentel/priority/detect shapes match the
//     T4-pinned success shapes, which are unchanged because the discovery
//     corpus and the surviving stages' fixtures are untouched by the dns
//     failure), and every results channel holds only the honest retained
//     sets;
//   - the captured report model is complete and internally consistent
//     (every channel reaches the report, the failing stage's absence is
//     reflected as IPs = 2, never a corrupt or partial model);
//   - stage events fired for every stage: exactly one started + one
//     finished per stage entry in stage order, the dns finished payload
//     mirroring the recorded StageRecord field for field;
//   - the run is REPRODUCIBLE: a second identical run (fresh dirs, same
//     fixtures) DeepEquals the first, including the event stream.
func TestT5FullRunPartialFailure(t *testing.T) {
	h := newT5Harness(t)

	// Failure injection: admin.example.com fails persistently on every
	// record type; www/api resolve normally.
	resolver := newFakeResolver()
	resolver.set("www.example.com", dns.TypeA, "93.184.216.34")
	resolver.set("api.example.com", dns.TypeA, "93.184.216.35")
	resolver.set("admin.example.com", dns.TypeA, "93.184.216.36")
	t5ScriptedDNSFailure(resolver, "admin.example.com")

	cfg := t4ScanConfig(t)
	clk := fixedClock{now: fixedTime}
	obs := &t5Observer{}
	cfg.Observer = obs

	run := func() pipeline.RunReport {
		cfg.OutputDir = t.TempDir()
		rep, err := pipeline.Run(context.Background(), cfg, nil, clk, h.stages(t, resolver))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	r1 := run()

	// --- Run-level outcome vocabulary: ONE partial stage among ten
	// completed stages folds the run to partial (pipeline_test.go
	// TestRunPartialWithCompleted), never failed and never completed. ---
	if r1.Outcome != pipeline.OutcomePartial {
		for i, sr := range r1.Stages {
			t.Logf("stage %d %s: outcome=%s processed=%d failed=%d truncated=%v flags=%v err=%v",
				i, sr.Name, sr.Outcome, sr.ItemsProcessed, sr.ItemsFailed, sr.Truncated, sr.StickyFlags, sr.Err)
		}
		t.Fatalf("Outcome = %q, want partial", r1.Outcome)
	}
	if len(r1.Stages) != 10 {
		t.Fatalf("Stages = %d, want 10", len(r1.Stages))
	}
	for i, sr := range r1.Stages {
		if i == 1 { // dns: the failing stage
			continue
		}
		if sr.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("stage %d (%s) outcome = %q, want completed (the pipeline continued)", i, sr.Name, sr.Outcome)
		}
	}

	// --- The REAL discovery stage ran and completed: three tool
	// executions, 5 processed per-source hosts (subfinder 2 + assetfinder
	// 2 + amass 1), zero failures, hosts-only additions (no domains). ---
	discRec := r1.Stages[0]
	if discRec.Name != pipeline.StageDiscover {
		t.Fatalf("Stages[0].Name = %q, want discover", discRec.Name)
	}
	if discRec.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("discovery stage outcome = %q, want completed (the failure injection belongs to the dns stage)", discRec.Outcome)
	}
	if discRec.ItemsProcessed != 5 {
		t.Errorf("discovery ItemsProcessed = %d, want 5 (subfinder 2 + assetfinder 2 + amass 1 per-source hosts)", discRec.ItemsProcessed)
	}
	if discRec.ItemsFailed != 0 {
		t.Errorf("discovery ItemsFailed = %d, want 0 (no malformed lines in the scripted output)", discRec.ItemsFailed)
	}
	if h.discoveryExecutions() != 3 {
		t.Errorf("discovery executions = %d, want 3 (subfinder + assetfinder + amass)", h.discoveryExecutions())
	}

	// --- The failing stage's record is honest. ---
	dnsRec := r1.Stages[1]
	if dnsRec.Name != pipeline.StageDNS {
		t.Fatalf("Stages[1].Name = %q, want dns", dnsRec.Name)
	}
	if dnsRec.Outcome != pipeline.OutcomePartial {
		t.Errorf("dns stage outcome = %q, want partial (completed + failed hosts)", dnsRec.Outcome)
	}
	if dnsRec.ItemsProcessed != 3 {
		t.Errorf("dns ItemsProcessed = %d, want 3 (one host result per discovered host)", dnsRec.ItemsProcessed)
	}
	if dnsRec.ItemsFailed != 1 {
		t.Errorf("dns ItemsFailed = %d, want 1 (admin.example.com, no usable observation)", dnsRec.ItemsFailed)
	}
	if dnsRec.Err != nil {
		t.Errorf("dns Err = %v, want nil (per-host failures fold into the outcome, not the error)", dnsRec.Err)
	}
	// Failure != truncation: the failed host's absence must never surface
	// as a truncation marker or a sticky flag (AGENTS §0.6).
	if dnsRec.Truncated {
		t.Error("dns Truncated = true, want false (a failure is not a truncation)")
	}
	if len(dnsRec.StickyFlags) != 0 {
		t.Errorf("dns StickyFlags = %v, want empty", dnsRec.StickyFlags)
	}
	if r1.Truncated {
		t.Error("run Truncated = true, want false (no cap fired anywhere)")
	}
	if len(r1.StickyFlags) != 0 {
		t.Errorf("run StickyFlags = %v, want empty (no spurious truncation flags from the failure)", r1.StickyFlags)
	}
	if r1.ItemsFailed != 1 {
		t.Errorf("run ItemsFailed = %d, want 1", r1.ItemsFailed)
	}

	// --- Corpus: the discovery stage's hosts-only additions, merged into
	// the engine's sorted All() order. The declared target never enters
	// Additions.Domains (adapt/discovery.go), so the domain corpus stays
	// empty — the T4-pinned shape, NOT the T3d3 seed's 1-domain shape. The
	// failing host stays in the corpus (a failed host is still a reported
	// host; only its observations disappear), so all 3 hosts and all 9
	// URLs (6 probed roots + 3 urlintel additions) survive the failure. ---
	if len(r1.Domains) != 0 {
		t.Errorf("Domains = %+v, want empty (the discovery adapter reports hosts only; the declared target lives in Target)", r1.Domains)
	}
	if got := t4HostNames(r1.Hosts); !reflect.DeepEqual(got, []string{"admin.example.com", "api.example.com", "www.example.com"}) {
		t.Errorf("Hosts = %v, want the three discovered hosts in the engine's sorted merge order (the corpus keeps the failed host; the failed stage simply adds no observation)", got)
	}
	// Provenance: every discovered host carries the injected clock instant
	// and the tool that first observed it (the T4-pinned earliest-wins
	// merge) — real discovery ran, not a seed.
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
	if len(r1.URLs) != 9 {
		t.Errorf("URLs = %d, want 9 (6 probed roots + 3 urlintel additions, unchanged)", len(r1.URLs))
	}
	urlSet := make(map[string]bool)
	for _, u := range r1.URLs {
		urlSet[u.Identity().String()] = true
	}
	for _, want := range []string{
		mustURL(t, "http://www.example.com/app.js").Identity().String(),
		mustURL(t, "http://api.example.com/lib.js?v=2").Identity().String(),
		mustURL(t, "http://www.example.com/graphql").Identity().String(),
	} {
		if !urlSet[want] {
			t.Errorf("URL corpus missing %s", want)
		}
	}

	// --- Results channels: only the honest retained sets. The dns failure
	// shows up EXACTLY where it belongs — the IPs channel carries the two
	// surviving hosts' addresses and nothing else — and every other
	// channel matches the T4-pinned success shapes (the surviving hosts'
	// downstream work is present and complete). ---
	res := r1.Results
	if got := t5ipValues(res.IPs); !reflect.DeepEqual(got, []string{"93.184.216.34", "93.184.216.35"}) {
		t.Errorf("IPs = %v, want exactly the two surviving hosts' addresses (admin contributed no observation)", got)
	}
	if len(res.Ports) < 2 || len(res.Services) < 2 {
		t.Errorf("Ports/Services = %d/%d, want >= 2/2 (http/https observed on the probed hosts)", len(res.Ports), len(res.Services))
	}
	if len(res.Endpoints) < 3 {
		t.Errorf("Endpoints = %d, want >= 3", len(res.Endpoints))
	}
	if got := len(res.TLSCertificates); got != 0 {
		t.Errorf("TLSCertificates = %d, want 0 (the canned transport performs no TLS handshake)", got)
	}
	if got := len(res.Parameters); got != 1 {
		t.Errorf("Parameters = %d, want 1 (the query parameter of lib.js?v=2)", got)
	} else if res.Parameters[0].Name != "v" {
		t.Errorf("Parameter = %+v, want name %q", res.Parameters[0], "v")
	}
	if len(res.Technologies) < 3 {
		t.Errorf("Technologies = %d, want >= 3 (graphql from techintel + react/webpack from jsintel)", len(res.Technologies))
	}
	if len(res.JavaScript) < 4 {
		t.Errorf("JavaScript = %d, want >= 4 (app.js, lib.js, shared.js, and the fetched root URLs)", len(res.JavaScript))
	}
	if len(res.SourceMaps) < 1 {
		t.Errorf("SourceMaps = %d, want >= 1 (app.js.map)", len(res.SourceMaps))
	}
	secretValues := make(map[string]bool)
	secretTypes := make(map[asset.SecretType]bool)
	for _, s := range res.Secrets {
		secretValues[s.Value] = true
		secretTypes[s.Type] = true
	}
	if !secretValues[awsKey(7)] {
		t.Errorf("Secrets missing value %q (got %d entries)", awsKey(7), len(res.Secrets))
	}
	if len(res.Secrets) != 2 || !secretTypes[asset.SecretTypeGoogle] {
		t.Errorf("Secrets = %d entries / types %v, want 2 entries incl. the google candidate", len(res.Secrets), secretTypes)
	}
	if len(res.Evidence) < 1 {
		t.Errorf("Evidence = %d, want >= 1", len(res.Evidence))
	}
	if len(res.Relationships) < 1 {
		t.Errorf("Relationships = %d, want >= 1", len(res.Relationships))
	}
	if got := len(res.Findings); got != 1 {
		t.Fatalf("Findings = %d, want 1 (the technology-listing rule emitted one)", got)
	}
	if res.Findings[0].RuleID != "t3d.integration.tech-listing" {
		t.Errorf("finding RuleID = %q, want t3d.integration.tech-listing", res.Findings[0].RuleID)
	}
	if res.Findings[0].Subject.Kind != asset.KindTechnology {
		t.Errorf("finding subject = %s, want a technology identity from the snapshot", res.Findings[0].Subject)
	}
	// Surfaces and group members follow the T4-pinned real-discovery
	// shape: 12 = 3 hosts + 9 URLs (discovery adds no domain surface).
	if got := len(res.Surfaces); got != 12 {
		t.Errorf("Surfaces = %d, want 12 (3 hosts + 9 URLs — no domain surface; discovery reports hosts only)", got)
	}
	if got := len(res.Groups); got != 1 {
		t.Fatalf("Groups = %d, want 1 (every surface anchors at example.com)", got)
	}
	if got := res.Groups[0].Anchor.String(); got != "domain:example.com" {
		t.Errorf("group anchor = %s, want domain:example.com", got)
	}
	if got := len(res.Groups[0].Members); got != 12 {
		t.Errorf("group members = %d, want 12", got)
	}
	if got := len(res.AttackPaths); got != 1 {
		t.Fatalf("AttackPaths = %d, want 1 (the admin host is a factor-carrying group member)", got)
	}
	if got := res.AttackPaths[0].Root.String(); got != "domain:example.com" {
		t.Errorf("attack path root = %s, want domain:example.com", got)
	}

	// --- Documents: the jsintel -> secrentel flow is intact (the
	// surviving hosts' retained bodies reach the secrentel stage). ---
	docByID := make(map[string]pipeline.Document)
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
	if got := r1.Stages[5].ItemsProcessed; got != len(r1.Documents) {
		t.Errorf("jsintel ItemsProcessed = %d, want %d (one processed entry per document)", got, len(r1.Documents))
	}
	if got := r1.Stages[6].ItemsProcessed; got != len(r1.Documents) {
		t.Errorf("secrentel ItemsProcessed = %d, want %d (every pipeline document scanned)", got, len(r1.Documents))
	}

	// --- The report stage ran and the captured model is complete and
	// internally consistent: the failure never corrupted the report. ---
	if len(h.models) != 1 {
		t.Fatalf("captured report models = %d, want 1 (one per run; run 2 follows below)", len(h.models))
	}
	model := h.models[0]
	if model == nil {
		t.Fatal("report model never captured")
	}
	if model.Target != "example.com" {
		t.Errorf("model.Target = %q, want example.com", model.Target)
	}
	if !model.StartedAt.Equal(fixedTime) || !model.EndedAt.Equal(fixedTime) {
		t.Errorf("model bracket = %v..%v, want %v..%v", model.StartedAt, model.EndedAt, fixedTime, fixedTime)
	}
	if len(model.Domains) != 0 || len(model.Hosts) != 3 || len(model.URLs) != 9 {
		t.Errorf("model corpus = %d domains / %d hosts / %d URLs, want 0/3/9 (the real-discovery shape)",
			len(model.Domains), len(model.Hosts), len(model.URLs))
	}
	if got := len(model.IPs); got != 2 {
		t.Errorf("model IPs = %d, want 2 (the honest retained set, matching the run's IPs channel)", got)
	}
	modelChannels := []struct {
		name  string
		count int
	}{
		{"Ports", len(model.Ports)}, {"Services", len(model.Services)},
		{"Endpoints", len(model.Endpoints)}, {"JavaScript", len(model.JavaScript)},
		{"Parameters", len(model.Parameters)}, {"Technologies", len(model.Technologies)},
		{"Secrets", len(model.Secrets)}, {"Evidence", len(model.Evidence)},
		{"Findings", len(model.Findings)}, {"SourceMaps", len(model.SourceMaps)},
		{"Relationships", len(model.Relationships)}, {"Surfaces", len(model.Surfaces)},
		{"Groups", len(model.Groups)}, {"AttackPaths", len(model.AttackPaths)},
	}
	for _, ch := range modelChannels {
		if ch.count < 1 {
			t.Errorf("model %s = %d, want >= 1 (the report Context carries the whole results channel)", ch.name, ch.count)
		}
	}
	if got := len(model.TLSCertificates); got != 0 {
		t.Errorf("model TLSCertificates = %d, want 0 (no TLS observations in the canned run)", got)
	}

	// --- Stage events: exactly one started + one finished per stage in
	// stage order; the failing stage's finished payload mirrors its
	// StageRecord field for field (T3a contract). ---
	events := obs.snapshot()
	if len(events) != 20 {
		t.Fatalf("events = %d, want 20 (10 stages x started+finished)", len(events))
	}
	wantKinds := make([]event.Kind, 0, 20)
	for i := 0; i < 10; i++ {
		wantKinds = append(wantKinds, event.KindStageStarted, event.KindStageFinished)
	}
	if got := t5stageEventKinds(events); !reflect.DeepEqual(got, wantKinds) {
		t.Fatalf("event kinds = %v, want %v", got, wantKinds)
	}
	for i, ev := range events {
		if ev.Sequence != 0 {
			t.Errorf("events[%d].Sequence = %d, want 0 (the bus assigns on publish)", i, ev.Sequence)
		}
		if !ev.At.Equal(fixedTime) {
			t.Errorf("events[%d].At = %v, want %v (injected clock)", i, ev.At, fixedTime)
		}
		if ev.Phase != "stage" {
			t.Errorf("events[%d].Phase = %q, want \"stage\"", i, ev.Phase)
		}
	}
	// The dns finished event mirrors the recorded dns StageRecord.
	fin, ok := events[3].Payload.(event.StageFinished)
	if !ok {
		t.Fatalf("events[3] payload type = %T, want event.StageFinished", events[3].Payload)
	}
	if fin.Name != string(dnsRec.Name) || fin.Outcome != string(dnsRec.Outcome) ||
		fin.ItemsProcessed != dnsRec.ItemsProcessed || fin.ItemsFailed != dnsRec.ItemsFailed ||
		fin.Truncated != dnsRec.Truncated || fin.Duration != dnsRec.Duration || fin.Err != "" {
		t.Errorf("dns finished payload = %+v, want the recorded StageRecord mirror (partial, 3 processed, 1 failed, no error)", fin)
	}
	// The discovery stage (index 0) also emitted its completed pair.
	discFin, ok := events[1].Payload.(event.StageFinished)
	if !ok {
		t.Fatalf("events[1] payload type = %T, want event.StageFinished", events[1].Payload)
	}
	if discFin.Name != string(pipeline.StageDiscover) || discFin.Outcome != string(pipeline.OutcomeCompleted) {
		t.Errorf("discovery finished payload = %+v, want completed (the real discovery stage ran and finished)", discFin)
	}
	// The report stage (the last entry) still completed and emitted its
	// finished event.
	lastFin, ok := events[19].Payload.(event.StageFinished)
	if !ok {
		t.Fatalf("events[19] payload type = %T, want event.StageFinished", events[19].Payload)
	}
	if lastFin.Name != string(pipeline.StageReport) || lastFin.Outcome != string(pipeline.OutcomeCompleted) {
		t.Errorf("report finished payload = %+v, want completed (the pipeline reached the report)", lastFin)
	}

	// --- Reproducibility: a second identical run DeepEquals the first,
	// including the event stream. ---
	r2 := run()
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("two identical partial runs differ:\nrun 1: %+v\nrun 2: %+v", r1, r2)
	}
	// Both runs are cold (nil cache): each re-executes all three discovery
	// tools — no cache interplay in the reproducible-run proof.
	if h.discoveryExecutions() != 6 {
		t.Errorf("discovery executions after run 2 = %d, want 6 (3 per cold run)", h.discoveryExecutions())
	}
	events = obs.snapshot()
	if len(events) != 40 {
		t.Fatalf("events after run 2 = %d, want 40", len(events))
	}
	if !reflect.DeepEqual(events[:20], events[20:]) {
		t.Fatalf("the two runs' event streams differ:\nrun 1: %+v\nrun 2: %+v", events[:20], events[20:])
	}
	// Run 2 captured its own model, identical to run 1's.
	if len(h.models) != 2 {
		t.Fatalf("captured report models after run 2 = %d, want 2", len(h.models))
	}
	if h.models[1] == nil {
		t.Fatal("run 2 report model never captured")
	}
	if !reflect.DeepEqual(h.models[0], h.models[1]) {
		t.Fatalf("the two runs' report models differ:\nrun 1: %+v\nrun 2: %+v", h.models[0], h.models[1])
	}
}

// TestT5FullRunRetryHealing is retry Scenario A: run 1 has ONE
// deterministic failure point (admin.example.com's resolution) that HEALS
// on run 2 — a stateful resolver fixture whose first call per (host,
// record type) fails and whose later calls succeed. Run 2 over the SAME
// cache:
//
//   - serves every succeeded unit from cache — zero re-execution: no
//     resolver calls for www/api (their 6 type queries are completed
//     records), zero new http probes, zero new jsintel fetches (gau still
//     runs once per run by design — its tool invocation is not cached, T4
//     pinned);
//   - RE-ATTEMPTS the failed work — exactly admin's 3 type queries are
//     re-issued (the cache never serves a failed record as a hit:
//     internal/cache/cache.go evaluate:207-209; internal/dns/run.go
//     lookupType:434-443 treats every non-hit as "execute"), and they
//     succeed now;
//   - re-executes ONLY the discovery stage's NON-CACHEABLE source on the
//     warm run (discovery executions 3 → 4: subfinder/amass are served
//     from cache, the unknown-version assetfinder executes fresh —
//     internal/discovery/pipeline.go:418-426);
//   - completes: all ten stages completed, run Outcome completed, IPs = 3
//     (admin healed);
//   - is deterministic: the healed run's RunReport DeepEquals a fresh
//     COLD run of the same healed state (fresh cache, always-working
//     resolver) — the full-run cache-hit parity pin extended to the
//     heal-after-failure path.
func TestT5FullRunRetryHealing(t *testing.T) {
	h := newT5Harness(t)

	// The healing fixture: www/api resolve normally from the first call;
	// admin's FIRST call per record type fails, every later call succeeds.
	base := newFakeResolver()
	base.set("www.example.com", dns.TypeA, "93.184.216.34")
	base.set("api.example.com", dns.TypeA, "93.184.216.35")
	base.set("admin.example.com", dns.TypeA, "93.184.216.36")
	healing := newHealingResolver(base, "admin.example.com")

	cfg := t4ScanConfig(t)
	clk := fixedClock{now: fixedTime}
	c, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}

	run := func() pipeline.RunReport {
		cfg.OutputDir = t.TempDir()
		rep, err := pipeline.Run(context.Background(), cfg, c, clk, h.stages(t, healing))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	r1 := run()
	// Run 1: the failure is present and honest.
	if r1.Outcome != pipeline.OutcomePartial {
		t.Fatalf("cold run Outcome = %q, want partial", r1.Outcome)
	}
	if r1.Stages[1].ItemsFailed != 1 || r1.Stages[1].Outcome != pipeline.OutcomePartial {
		t.Fatalf("cold dns stage = %+v, want partial with ItemsFailed 1", r1.Stages[1])
	}
	if got := t5ipValues(r1.Results.IPs); !reflect.DeepEqual(got, []string{"93.184.216.34", "93.184.216.35"}) {
		t.Fatalf("cold IPs = %v, want the two surviving hosts' addresses", got)
	}
	// Every (host, type) pair was attempted exactly once: 3 hosts x 3
	// types = 9 queries.
	if got := healing.callCount(); got != 9 {
		t.Fatalf("cold resolver calls = %d, want 9 (3 hosts x A/AAAA/CNAME)", got)
	}
	// The failed host's queries never reached the wire (the failure is
	// the resolver's own, before any answer); the surviving hosts' 6
	// queries all did.
	if base.seenHosts()["admin.example.com"] {
		t.Fatal("cold run reached the wire for admin.example.com, want the first calls to fail at the resolver")
	}
	if got := base.seenCount("www.example.com") + base.seenCount("api.example.com"); got != 6 {
		t.Fatalf("cold wire queries for the surviving hosts = %d, want 6 (2 hosts x 3 types)", got)
	}
	if got := h.discoveryExecutions(); got != 3 {
		t.Fatalf("cold discovery executions = %d, want 3 (subfinder + assetfinder + amass)", got)
	}
	httpAfterCold := h.transport.requestCount()
	jsAfterCold := h.jsRequests()
	gauAfterCold := t4GauExecutions(h.gauRunner)
	if jsAfterCold == 0 {
		t.Fatal("cold run made no jsintel HTTP requests, want >= 1")
	}

	// Run 2 over the same cache: the failure heals.
	r2 := run()
	if r2.Outcome != pipeline.OutcomeCompleted {
		for i, sr := range r2.Stages {
			t.Logf("stage %d %s: outcome=%s processed=%d failed=%d err=%v",
				i, sr.Name, sr.Outcome, sr.ItemsProcessed, sr.ItemsFailed, sr.Err)
		}
		t.Fatalf("warm healed Outcome = %q, want completed", r2.Outcome)
	}
	for i, sr := range r2.Stages {
		if sr.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("stage %d (%s) outcome = %q, want completed", i, sr.Name, sr.Outcome)
		}
	}
	if r2.Stages[1].ItemsFailed != 0 {
		t.Errorf("warm dns ItemsFailed = %d, want 0 (admin healed)", r2.Stages[1].ItemsFailed)
	}
	if got := t5ipValues(r2.Results.IPs); !reflect.DeepEqual(got, []string{"93.184.216.34", "93.184.216.35", "93.184.216.36"}) {
		t.Fatalf("warm IPs = %v, want all three hosts' addresses (admin healed)", got)
	}

	// (a) Succeeded work served from cache: exactly the failed host's 3
	// type queries were re-issued — www/api's 6 queries were completed
	// records and performed ZERO new resolver calls.
	if got := healing.callCount(); got != 12 {
		t.Fatalf("warm resolver calls = %d, want 12 (9 cold + exactly 3 re-attempted admin queries)", got)
	}
	if !base.seenHosts()["admin.example.com"] {
		t.Fatal("warm run never reached the wire for admin.example.com, want the re-attempted queries to execute")
	}
	if got := base.seenCount("admin.example.com"); got != 3 {
		t.Fatalf("warm wire queries for admin = %d, want 3 (its 3 re-attempted types)", got)
	}
	if got := base.seenCount("www.example.com") + base.seenCount("api.example.com"); got != 6 {
		t.Fatalf("warm wire queries for the surviving hosts = %d, want 6 (unchanged — zero re-execution)", got)
	}
	// (a') Discovery re-executes only its NON-CACHEABLE source: 4 total
	// executions (3 cold + 1 warm assetfinder; subfinder/amass served
	// from cache — internal/discovery/pipeline.go:418-426).
	if got := h.discoveryExecutions(); got != 4 {
		t.Errorf("warm discovery executions = %d, want 4 (3 cold + 1 warm assetfinder execution, the NON-CACHEABLE unknown-version source)", got)
	}
	// (b) Zero re-execution of the succeeded downstream work.
	if got := h.transport.requestCount(); got != httpAfterCold {
		t.Errorf("warm http requests = %d, want %d (zero new probes)", got, httpAfterCold)
	}
	if got := h.jsRequests(); got != jsAfterCold {
		t.Errorf("warm jsintel requests = %d, want %d (zero new fetches)", got, jsAfterCold)
	}
	if got := t4GauExecutions(h.gauRunner); got != gauAfterCold+1 {
		t.Errorf("warm gau executions = %d, want %d (the tool invocation is not cached; only per-URL extraction is)", got, gauAfterCold+1)
	}

	// (d) Determinism: the healed warm run DeepEquals a fresh cold run of
	// the same healed state (fresh cache, always-working resolver).
	c2, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open (healed cold): %v", err)
	}
	healedResolver := newFakeResolver()
	healedResolver.set("www.example.com", dns.TypeA, "93.184.216.34")
	healedResolver.set("api.example.com", dns.TypeA, "93.184.216.35")
	healedResolver.set("admin.example.com", dns.TypeA, "93.184.216.36")
	cfg.OutputDir = t.TempDir()
	r3, err := pipeline.Run(context.Background(), cfg, c2, clk, h.stages(t, healedResolver))
	if err != nil {
		t.Fatalf("Run (healed cold): %v", err)
	}
	if r3.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("healed cold Outcome = %q, want completed", r3.Outcome)
	}
	if !reflect.DeepEqual(r2, r3) {
		t.Fatalf("healed warm run differs from a fresh cold healed run:\nwarm: %+v\ncold: %+v", r2, r3)
	}
	// The healed cold run re-executes all three discovery tools against
	// the fresh cache: 7 total executions (4 + 3).
	if got := h.discoveryExecutions(); got != 7 {
		t.Errorf("healed cold discovery executions = %d, want 7 (4 through run 2 + 3 fresh)", got)
	}
}

// TestT5FullRunRetryPersistent is retry Scenario B: the same failing
// fixture (admin.example.com's resolution) fails deterministically on
// EVERY run. Run 2 over the same cache serves the succeeded parts from
// cache (zero new resolver calls for www/api, zero new http probes, zero
// new jsintel fetches), re-executes only the discovery stage's
// NON-CACHEABLE source (3 → 4 executions), RE-ATTEMPTS the failing part
// (exactly admin's 3 type queries are re-issued), and fails again — the
// same partial outcome, the same ItemsFailed, and the two RunReports are
// fully DeepEqual (cache metadata is not part of RunReport; T4's
// cache-hit parity pin holds on the persistent-failure path too).
func TestT5FullRunRetryPersistent(t *testing.T) {
	h := newT5Harness(t)

	resolver := newFakeResolver()
	resolver.set("www.example.com", dns.TypeA, "93.184.216.34")
	resolver.set("api.example.com", dns.TypeA, "93.184.216.35")
	resolver.set("admin.example.com", dns.TypeA, "93.184.216.36")
	t5ScriptedDNSFailure(resolver, "admin.example.com")

	cfg := t4ScanConfig(t)
	clk := fixedClock{now: fixedTime}
	c, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}

	run := func() pipeline.RunReport {
		cfg.OutputDir = t.TempDir()
		rep, err := pipeline.Run(context.Background(), cfg, c, clk, h.stages(t, resolver))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	r1 := run()
	if r1.Outcome != pipeline.OutcomePartial {
		t.Fatalf("cold run Outcome = %q, want partial", r1.Outcome)
	}
	if r1.Stages[1].ItemsFailed != 1 {
		t.Fatalf("cold dns ItemsFailed = %d, want 1", r1.Stages[1].ItemsFailed)
	}
	// One (host, type) query per pair: 3 hosts x A/AAAA/CNAME = 9 total.
	coldQueries := func() int {
		return resolver.seenCount("www.example.com") + resolver.seenCount("api.example.com") + resolver.seenCount("admin.example.com")
	}
	if got := coldQueries(); got != 9 {
		t.Fatalf("cold resolver queries = %d, want 9 (3 hosts x A/AAAA/CNAME)", got)
	}
	if got := resolver.seenCount("admin.example.com"); got != 3 {
		t.Fatalf("cold admin queries = %d, want 3 (its A/AAAA/CNAME all attempted and failed)", got)
	}
	if got := h.discoveryExecutions(); got != 3 {
		t.Fatalf("cold discovery executions = %d, want 3 (subfinder + assetfinder + amass)", got)
	}
	httpAfterCold := h.transport.requestCount()
	jsAfterCold := h.jsRequests()

	r2 := run()
	if r2.Outcome != pipeline.OutcomePartial {
		t.Fatalf("warm run Outcome = %q, want partial (the failing part failed again)", r2.Outcome)
	}
	if r2.Stages[1].Outcome != pipeline.OutcomePartial || r2.Stages[1].ItemsFailed != 1 {
		t.Fatalf("warm dns stage = %+v, want partial with ItemsFailed 1 (same honest outcome)", r2.Stages[1])
	}
	// The failing part was RE-ATTEMPTED: exactly admin's 3 type queries
	// were re-issued; www/api's completed records served with zero calls.
	if got := coldQueries(); got != 12 {
		t.Fatalf("warm resolver queries = %d, want 12 (9 cold + exactly 3 re-attempted admin queries)", got)
	}
	if got := resolver.seenCount("admin.example.com"); got != 6 {
		t.Fatalf("warm admin queries = %d, want 6 (3 cold + 3 re-attempted)", got)
	}
	if got := resolver.seenCount("www.example.com") + resolver.seenCount("api.example.com"); got != 6 {
		t.Fatalf("warm surviving-host queries = %d, want 6 (unchanged — served from cache)", got)
	}
	// Discovery re-executes only its NON-CACHEABLE source on the warm run
	// (subfinder/amass served from cache; assetfinder executes fresh —
	// internal/discovery/pipeline.go:418-426).
	if got := h.discoveryExecutions(); got != 4 {
		t.Errorf("warm discovery executions = %d, want 4 (3 cold + 1 warm assetfinder execution)", got)
	}
	// The succeeded parts were served from cache: zero new probes/fetches.
	if got := h.transport.requestCount(); got != httpAfterCold {
		t.Errorf("warm http requests = %d, want %d (zero new probes)", got, httpAfterCold)
	}
	if got := h.jsRequests(); got != jsAfterCold {
		t.Errorf("warm jsintel requests = %d, want %d (zero new fetches)", got, jsAfterCold)
	}
	// The run reports are fully DeepEqual across the two runs.
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("persistent-failure runs differ:\nrun 1: %+v\nrun 2: %+v", r1, r2)
	}
}
