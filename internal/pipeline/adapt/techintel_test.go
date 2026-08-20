package adapt

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/techintel"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// techintel tests are hermetic: no network, no real filesystem, no external
// tools — the engine's ONLY constructor seam is the fingerprint DB
// (NewTechIntelStage, adapt/doc.go), injected as a synthetic database via
// fingerprints.CompileForTest. Every stage test exercises the real
// techintel.Ingest path (bounded pool from in.Bounds, cache-before-execute,
// merge, report) with the adapter's fixed clock. Test identifiers use the
// TestTechIntel prefix per the package convention.
//
// Contract coverage maps 1:1 onto techIntelStage.Run's doc comment: the
// outcome mapping table, malformed observations (ItemsFailed, never folded),
// the truncation sticky flag (never swallowed — AGENTS §0.6), the error
// paths (failed / cancelled / errors.Join), the empty-corpus short-circuit,
// the non-canonical-target fall-through, and the boundary filter.
//
// The fold table, counters, and truncation mapping are pinned BOTH directly
// (foldTechOutcome / techProcessed / techFailed / techTruncated /
// buildTechResult unit tables) and through the stage where the engine makes
// it deterministically forceable. The engine's analysis detail (which
// technologies fire) is the engine package's own contract — the adapter's
// contract is the outcome/counter/flag translation, which is what these
// tests pin.

// techintelInput builds a StageInput for the techintel stage with the
// resolved default bounds and the deterministic fixed clock the package's
// other tests share.
func techintelInput(target asset.Domain, urls []asset.URL, params map[string]string, c cache.Cache) pipeline.StageInput {
	return pipeline.StageInput{
		Target: target,
		URLs:   urls,
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  fixedClock{now: fixedTime},
		Cache:  c,
	}
}

// techURL parses a canonical URL asset for tests, failing the test on an
// unexpected parse error.
func techURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// techTestDB builds a synthetic fingerprint database through the exact Load
// pipeline (compile-once regexes, validation, deterministic sort). One
// fingerprint fires an IndicatorEndpointPath match on "/admin" from the
// observation URL's path — the only indicator kind matchable from a
// URL-identity-only observation (techIntelStage.Run doc, adapt/doc.go D3).
func techTestDB(t testing.TB) *fingerprints.DB {
	t.Helper()
	db, err := fingerprints.CompileForTest([]fingerprints.Fingerprint{{
		Name:     "synthetic-cms",
		Category: asset.CategoryCMS,
		Indicators: []fingerprints.Indicator{{
			Kind:   fingerprints.IndicatorEndpointPath,
			Match:  "/admin",
			Weight: 0.8,
		}},
	}})
	if err != nil {
		t.Fatalf("CompileForTest: %v", err)
	}
	return db
}

// techStage returns a stage wired with the synthetic DB seam.
func techStage(t testing.TB) pipeline.Stage {
	t.Helper()
	return NewTechIntelStage(techTestDB(t))
}

func TestTechIntelStageName(t *testing.T) {
	s := NewTechIntelStage(nil)
	if got := s.Name(); got != pipeline.StageTechIntel {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageTechIntel)
	}
}

func TestTechIntelStageHappyPath(t *testing.T) {
	// Two in-scope canonical URLs: every observation is processed fresh
	// (cache-before-execute: Get per URL), stored (Put per completed entry),
	// and counted honestly. The stage produces NO corpus additions
	// (technologies/evidence are results, T2c — adapt/doc.go).
	target := mustDomain(t, "example.com")
	rec := &recordingCache{}
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/admin"),
		techURL(t, "https://example.com/login"),
	}, nil, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 2 {
		t.Fatalf("ItemsProcessed = %d, want 2 (one entry per processed URL)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Fatalf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	if res.Truncated {
		t.Fatal("Truncated = true on a clean run, want false")
	}
	if len(res.Additions.URLs) != 0 || len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 {
		t.Fatalf("Additions carry corpus kinds the stage must not produce: urls=%d domains=%d hosts=%d",
			len(res.Additions.URLs), len(res.Additions.Domains), len(res.Additions.Hosts))
	}
	// Cache-before-execute proof: one Get and one Put per processed URL.
	if got := len(rec.getKeys()); got != 2 {
		t.Fatalf("cache Gets = %d, want 2 (one per processed URL)", got)
	}
	if got := rec.putCount(); got != 2 {
		t.Fatalf("cache Puts = %d, want 2 (one completed record per processed URL)", got)
	}
	// T3d results wiring: only the /admin observation matches the synthetic
	// fingerprint — one technology, one evidence observation, and the graph
	// edges (host->technology, url->technology, technology->evidence).
	// The engine's canonical assets are copied, never rebuilt.
	if got := len(res.Results.Technologies); got != 1 {
		t.Fatalf("results technologies = %d, want 1 (only /admin matches synthetic-cms)", got)
	}
	if got := res.Results.Technologies[0].Name; got != "synthetic-cms" {
		t.Errorf("results technology = %q, want synthetic-cms", got)
	}
	if got := len(res.Results.Evidence); got != 1 {
		t.Errorf("results evidence = %d, want 1 (the indicator match observation)", got)
	}
	if got := len(res.Results.Relationships); got != 3 {
		t.Errorf("results relationships = %d, want 3 (host->technology + url->technology + technology->evidence)", got)
	}
}

// TestTechIntelStageResultsDeduped pins the results-channel dedup through
// the adapter: two observations matching the same fingerprint merge into
// ONE canonical technology (the report identity-merges technology results),
// while evidence stays per observation (its identity embeds the observation
// source) and the shared host->technology edge is deduplicated by edge
// identity. The adapter copies the merged report verbatim, never rebuilt.
func TestTechIntelStageResultsDeduped(t *testing.T) {
	target := mustDomain(t, "example.com")
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/admin"),
		techURL(t, "https://example.com/admin/x"), // substring path match fires the same fingerprint
	}, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if got := len(res.Results.Technologies); got != 1 {
		t.Fatalf("results technologies = %d, want 1 (identity-merged across the two observations)", got)
	}
	if got := len(res.Results.Evidence); got != 2 {
		t.Errorf("results evidence = %d, want 2 (evidence identity embeds the observation source)", got)
	}
	// 1 host->technology (same host, deduped) + 2 url->technology +
	// 2 technology->evidence.
	if got := len(res.Results.Relationships); got != 5 {
		t.Errorf("results relationships = %d, want 5 (1 host->technology + 2 url->technology + 2 technology->evidence)", got)
	}
}

// TestTechIntelStageResultsDeterminism pins the determinism contract for the
// results channel: two identical runs over the synthetic DB (fixed clock)
// produce DeepEqual StageResults, including every results channel the stage
// contributes — technologies, evidence, and relationships.
func TestTechIntelStageResultsDeterminism(t *testing.T) {
	run := func() pipeline.StageResult {
		t.Helper()
		res, err := techStage(t).Run(context.Background(), techintelInput(mustDomain(t, "example.com"), []asset.URL{
			techURL(t, "https://example.com/admin"),
			techURL(t, "https://example.com/login"),
		}, nil, nil))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}
	res1, res2 := run(), run()
	if !reflect.DeepEqual(res1, res2) {
		t.Fatalf("two identical runs differ:\nrun 1: %+v\nrun 2: %+v", res1, res2)
	}
	if len(res1.Results.Technologies) == 0 || len(res1.Results.Evidence) == 0 ||
		len(res1.Results.Relationships) == 0 {
		t.Fatal("determinism pin exercised no results output (technologies/evidence/relationships all empty)")
	}
}

func TestTechIntelStageProductionDBDefault(t *testing.T) {
	// NewTechIntelStage(nil) uses the engine's production default:
	// fingerprints.Load (the compile-once database). One URL still
	// processes and completes — the constructor seam is optional.
	target := mustDomain(t, "example.com")
	s := NewTechIntelStage(nil)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/page"),
	}, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 1 {
		t.Fatalf("ItemsProcessed = %d, want 1", res.ItemsProcessed)
	}
}

func TestTechIntelStageOutOfDomainFiltered(t *testing.T) {
	// Boundary filtering, input side (adapt/doc.go): out-of-domain URLs are
	// dropped BEFORE the engine — the engine must never see them. Only the
	// in-domain URL is processed and counted.
	target := mustDomain(t, "example.com")
	rec := &recordingCache{}
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/a"),
		techURL(t, "https://evil.com/x"),
		techURL(t, "https://example.org/y"),
		techURL(t, "https://sub.example.com/b"),
	}, nil, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 2 {
		t.Fatalf("ItemsProcessed = %d, want 2 (only in-domain URLs reach the engine)", res.ItemsProcessed)
	}
	if got := len(rec.getKeys()); got != 2 {
		t.Fatalf("cache Gets = %d, want 2 (out-of-domain URLs never reach the engine)", got)
	}
}

func TestTechIntelStageEmptyCorpusShortCircuit(t *testing.T) {
	// No in-scope URLs + canonical target: the stage short-circuits with a
	// vacuous completed result — the engine is never invoked (zero cache
	// reads) and the counters are honest zeros.
	target := mustDomain(t, "example.com")
	rec := &recordingCache{}
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, nil, nil, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q (vacuously completed)", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if got := len(rec.getKeys()); got != 0 {
		t.Fatalf("cache Gets = %d, want 0 (short-circuit must not touch the engine)", got)
	}
}

func TestTechIntelStageNonCanonicalTargetFallsThrough(t *testing.T) {
	// A non-canonical target with no in-scope URLs falls through to the
	// engine with an empty observation source instead of short-circuiting:
	// the engine treats an empty source as valid input and returns an empty
	// report (vacuously completed) — the canonicality gate is kept so a
	// future engine-side target validation would surface honestly
	// (techIntelStage.Run doc).
	bad := asset.Domain{Name: "Example.COM"}
	rec := &recordingCache{}
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(bad, nil, nil, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if got := len(rec.getKeys()); got != 0 {
		t.Fatalf("cache Gets = %d, want 0 (empty source, nothing processed)", got)
	}
}

func TestTechIntelStageMalformedObservation(t *testing.T) {
	// A hand-built URL with an uppercase hostname survives the input filter
	// (asset.NewHost canonicalizes it, so it IS in-domain) but is NOT
	// canonical in its own identity (the URL's canonical string lowercases
	// the host): the ENGINE rejects it at ingest as malformed — counted,
	// never analyzed (prepareObservation). The engine surfaces the bounded
	// diagnostic as its run error, and the stage must surface it honestly:
	// failed, wrapped with the stage name, with the malformed observation in
	// ItemsFailed (techIntelStage.Run doc — "never silently dropped").
	//
	// Note: at the FOLD level the malformed count is a diagnostic that never
	// folds into the outcome (pinned by TestTechIntelFoldOutcome); at the
	// ENGINE level the malformed diagnostic is a joined run error, and this
	// test pins that the stage reports it instead of swallowing it.
	target := mustDomain(t, "example.com")
	bad := asset.URL{Scheme: "https", HostPort: "EXAMPLE.com", Path: "/a"}
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{bad}, nil, nil))
	if err == nil {
		t.Fatal("Run: nil error, want the engine's malformed-observation diagnostic")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q (the engine rejected the observation)", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage techintel") || !strings.Contains(err.Error(), "malformed observation") {
		t.Fatalf("error = %q, want the stage name and the malformed diagnostic", err)
	}
	if res.ItemsFailed != 1 {
		t.Fatalf("ItemsFailed = %d, want 1 (the malformed observation)", res.ItemsFailed)
	}
	if res.ItemsProcessed != 0 {
		t.Fatalf("ItemsProcessed = %d, want 0 (malformed observations are never analyzed)", res.ItemsProcessed)
	}
}

func TestTechIntelStageEngineConfigError(t *testing.T) {
	// Zero bounds pass through verbatim (adapt/doc.go: zero means the
	// ENGINE's semantics, not pre-resolved pipeline defaults). A direct
	// caller passing Concurrency 0 hits the engine's own config validation,
	// which the stage surfaces as failed, wrapped with the stage name.
	target := mustDomain(t, "example.com")
	in := techintelInput(target, []asset.URL{techURL(t, "https://example.com/a")}, nil, nil)
	in.Bounds = pipeline.StageConfig{MaxConcurrency: 0, QueueSize: 64}
	s := techStage(t)

	res, err := s.Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run: nil error, want the engine's config-validation error")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage techintel") || !strings.Contains(err.Error(), "Concurrency") {
		t.Fatalf("error = %q, want the stage name and the engine's validation detail", err)
	}
}

func TestTechIntelStageCacheErrorSurfaced(t *testing.T) {
	// A diagnosed cache-read failure (stateErrorCache) is a run diagnostic
	// for the engine, never fatal: the observation still falls through to a
	// fresh analysis and completes. The stage surfaces the joined
	// diagnostic as failed with the honest processed count — nothing is
	// swallowed (engine.go lookupTech StateError path).
	target := mustDomain(t, "example.com")
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/a"),
	}, nil, stateErrorCache{}))
	if err == nil {
		t.Fatal("Run: nil error, want the engine's cache diagnostic")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage techintel") || !strings.Contains(err.Error(), "cache get") {
		t.Fatalf("error = %q, want the stage name and the cache diagnostic", err)
	}
	if res.ItemsProcessed != 1 {
		t.Fatalf("ItemsProcessed = %d, want 1 (the observation still processed honestly)", res.ItemsProcessed)
	}
}

func TestTechIntelStagePreCancelled(t *testing.T) {
	// A pre-cancelled context: the engine returns an empty report with a
	// nil error, and the stage's own context check reports cancelled with
	// the context error attached (techIntelStage.runIngest doc). The
	// adapter's cancellation convention: the Go error return stays nil —
	// the outcome, not the error field, carries cancellation, with the
	// context error attached to res.Err (stage.go contract). The engine
	// performs zero work on the run (zero cache reads).
	target := mustDomain(t, "example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &recordingCache{}
	s := techStage(t)

	res, err := s.Run(ctx, techintelInput(target, []asset.URL{techURL(t, "https://example.com/a")}, nil, rec))
	if err != nil {
		t.Fatalf("Run returned a Go error for cancellation: %v (the outcome carries it)", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("res.Err = %v, want context.Canceled", res.Err)
	}
	if got := len(rec.getKeys()); got != 0 {
		t.Fatalf("cache Gets = %d, want 0 (no engine work on a pre-cancelled run)", got)
	}
}

func TestTechIntelStageEngineErrorWithCancelledContext(t *testing.T) {
	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal and the engine's detail is
	// errors.Join-ed so NOTHING is lost (techIntelStage.runIngest doc) —
	// carried on res.Err with a nil Go error return, the adapter's
	// cancellation convention. Forced hermetically with an invalid config
	// (engine validation error) plus a pre-fired context.
	target := mustDomain(t, "example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := techintelInput(target, []asset.URL{techURL(t, "https://example.com/a")}, nil, nil)
	in.Bounds = pipeline.StageConfig{MaxConcurrency: 0, QueueSize: 64}
	s := techStage(t)

	res, err := s.Run(ctx, in)
	if err != nil {
		t.Fatalf("Run returned a Go error for cancellation: %v (the outcome carries it)", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q (cancellation dominates)", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("res.Err = %v, want context.Canceled", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "Concurrency") {
		t.Fatalf("res.Err = %v, want the engine's detail joined in", res.Err)
	}
}

func TestTechIntelStageNilCache(t *testing.T) {
	// A nil cache disables cache-before-execute; the run still completes
	// with honest counters (engine.go Config.Cache doc).
	target := mustDomain(t, "example.com")
	s := techStage(t)

	res, err := s.Run(context.Background(), techintelInput(target, []asset.URL{
		techURL(t, "https://example.com/a"),
	}, nil, nil))
	if err != nil {
		t.Fatalf("Run (nil cache): %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 1/0", res.ItemsProcessed, res.ItemsFailed)
	}
}

func TestTechIntelStageNilContext(t *testing.T) {
	// The stage guards a nil context directly, mirroring the urlintel and
	// httpprobe adapters: a structured failed outcome naming the stage,
	// never a degradation through the engine (review LOW-2).
	target := mustDomain(t, "example.com")
	s := techStage(t)
	res, err := s.Run(nil, techintelInput(target, nil, nil, nil))
	if err == nil {
		t.Fatal("Run(nil ctx): nil error, want the structured guard error")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage techintel") || !strings.Contains(err.Error(), "context must not be nil") {
		t.Fatalf("error = %q, want the stage name and the guard message", err)
	}
}

func TestTechIntelStageTruncationFlagMapping(t *testing.T) {
	// buildTechResult must never swallow ANY engine truncation/overflow
	// signal: Report.Truncated and every Overflow field set Truncated=true
	// plus the documented sticky flag (AGENTS §0.6 carve-out: completed +
	// flag). The flag name is pinned literally per the package convention
	// (adapt/doc.go: <engine>_<what>_truncated). The engine-level retention
	// caps cannot fire hermetically through the stage (observations carry
	// URL identity only — no bodies/headers/cookies), so the mapping itself
	// is pinned directly on synthetic reports.
	s := techStage(t).(*techIntelStage)
	base := techintel.Report{}
	res := s.buildTechResult(base, pipeline.OutcomeCompleted, nil)
	if res.Truncated {
		t.Fatal("Truncated = true for a clean report, want false")
	}
	if len(res.StickyFlags) != 0 {
		t.Fatalf("StickyFlags = %v for a clean report, want none", res.StickyFlags)
	}

	cases := []struct {
		name string
		rep  techintel.Report
	}{
		{"report truncated", techintel.Report{Truncated: true}},
		{"overflow technologies", techintel.Report{Overflow: techintel.Overflow{Technologies: true}}},
		{"overflow indicators", techintel.Report{Overflow: techintel.Overflow{Indicators: true}}},
		{"overflow cookies", techintel.Report{Overflow: techintel.Overflow{Cookies: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := s.buildTechResult(tc.rep, pipeline.OutcomeCompleted, nil)
			if !res.Truncated {
				t.Fatalf("Truncated = false, want true (%s must never be swallowed)", tc.name)
			}
			if !res.StickyFlags["tech_indicators_truncated"] {
				t.Fatalf("StickyFlags[%q] unset, want true", techIndicatorsTruncatedFlag)
			}
			if len(res.StickyFlags) != 1 {
				t.Fatalf("StickyFlags = %v, want exactly the one documented flag", res.StickyFlags)
			}
		})
	}
}

func TestTechIntelFoldOutcome(t *testing.T) {
	// The stage fold over the engine's observation counts, pinned as the
	// documented table on techIntelStage.Run: cancelled > failed&&!completed
	// > completed > partial. Malformed is a diagnostic and NEVER folds (a
	// malformed-only report is vacuously completed) — exactly the unified
	// adapter precedence (adapt/doc.go, T2b MEDIUM-1 unification).
	cases := []struct {
		name string
		obs  techintel.ReportObservations
		want pipeline.Outcome
	}{
		{"empty report", techintel.ReportObservations{}, pipeline.OutcomeCompleted},
		{"all completed", techintel.ReportObservations{Completed: 3}, pipeline.OutcomeCompleted},
		{"malformed only", techintel.ReportObservations{Malformed: 2}, pipeline.OutcomeCompleted},
		{"completed with malformed", techintel.ReportObservations{Completed: 2, Malformed: 1}, pipeline.OutcomeCompleted},
		{"any cancelled", techintel.ReportObservations{Cancelled: 1}, pipeline.OutcomeCancelled},
		{"cancelled beats failed", techintel.ReportObservations{Failed: 1, Cancelled: 1}, pipeline.OutcomeCancelled},
		{"failed only", techintel.ReportObservations{Failed: 1}, pipeline.OutcomeFailed},
		{"failed with malformed", techintel.ReportObservations{Failed: 1, Malformed: 1}, pipeline.OutcomeFailed},
		{"mixed completed and failed", techintel.ReportObservations{Completed: 2, Failed: 1}, pipeline.OutcomePartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := foldTechOutcome(tc.obs); got != tc.want {
				t.Fatalf("foldTechOutcome(%+v) = %q, want %q", tc.obs, got, tc.want)
			}
		})
	}
}

func TestTechIntelCounters(t *testing.T) {
	// techProcessed = every entry the engine processed (completed +
	// cancelled + failed); techFailed = everything that could not be
	// processed (engine-failed + rejected malformed). Pinned directly on
	// synthetic reports; the engine-path values are asserted through the
	// stage in the malformed and happy-path tests above.
	cases := []struct {
		name       string
		obs        techintel.ReportObservations
		wantProc   int
		wantFailed int
	}{
		{"empty", techintel.ReportObservations{}, 0, 0},
		{"completed only", techintel.ReportObservations{Completed: 4}, 4, 0},
		{"cancelled counts as processed", techintel.ReportObservations{Cancelled: 2}, 2, 0},
		{"failed counts both ways", techintel.ReportObservations{Failed: 1}, 1, 1},
		{"malformed is failed, not processed", techintel.ReportObservations{Malformed: 3}, 0, 3},
		{"mixed", techintel.ReportObservations{Completed: 5, Cancelled: 1, Failed: 2, Malformed: 4}, 8, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := techintel.Report{Observations: tc.obs}
			if got := techProcessed(rep); got != tc.wantProc {
				t.Fatalf("techProcessed(%+v) = %d, want %d", tc.obs, got, tc.wantProc)
			}
			if got := techFailed(rep); got != tc.wantFailed {
				t.Fatalf("techFailed(%+v) = %d, want %d", tc.obs, got, tc.wantFailed)
			}
		})
	}
}
