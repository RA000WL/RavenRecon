package discovery

// T4 engine-level determinism pin (milestone T4 — determinism, discovery
// clock seam): two Run calls with identical fake payloads and a fixed clock
// produce DeepEqual reports at Concurrency > 1, and every ordered surface
// the pipeline consumes (per-source host lists, the merged list) is sorted.
//
// The pinned contract (internal/discovery/pipeline.go): the report's
// Results slice is PRE-ALLOCATED in selection order and every pool job
// writes only its own slot, so the per-source report order is the
// selection order at ANY pool concurrency — never pool-completion order.
// Per-source host lists are deduplicated by Phase 2 identity and sorted by
// canonical name (parse.go); Report.All merges across sources and sorts
// the merged list (pipeline.go). These tests pin that selection-order
// contract (the slot array mechanism) under GENUINELY overlapping jobs:
// the rate limiter is disabled (Rate 0 — the inherited default of 2/s
// with Burst 1 would pace the instant fakes 500 ms apart and serialize
// them) and a barrier in the fake runner holds every discovery execution
// inside Run — already counted in the runner's active counter — until all
// three have arrived, so the three jobs race on the 4-worker pool for
// real. The fakeRunner's maxConcurrent counter then proves the overlap
// (> 1), and the cross-run DeepEqual proves the slot-array selection
// order is scheduling-independent.

import (
	"reflect"
	"testing"
)

// TestRunDeterministicAcrossRunsConcurrency pins cross-run determinism at
// Concurrency 4: two identical runs DeepEqual the whole report — per-source
// order, per-source contents, statuses, detections, and the merged host
// list — under genuinely overlapping jobs. The rate limiter is disabled
// (Rate 0; the inherited default of 2/s with Burst 1 would pace the instant
// fakes 500 ms apart and serialize them) and a barrier in the fake runner
// (armBarrier, fakes_test.go) holds all four discovery executions inside
// Run before any returns, so the jobs actually race on the pool;
// maxConcurrent > 1 is the overlap proof. The cross-run DeepEqual then
// pins the selection-order contract (the slot array mechanism: pipeline.go
// pre-allocates the Results slice in selection order and every job writes
// only its own slot — never pool-completion order).
func TestRunDeterministicAcrossRunsConcurrency(t *testing.T) {
	target := mustDomain(t, "example.com")
	run := func() (*fakeRunner, Report) {
		r := newFakeRunner(t, fullScript())
		cfg := testConfig(r, newFakeLookup())
		cfg.Concurrency = 4 // four jobs race on the pool
		cfg.Rate = 0        // no job-start pacing: workers take jobs as fast as they can
		r.armBarrier(4)     // all four discovery executions overlap inside Run
		return r, mustRun(t, target, cfg)
	}
	r1, rep1 := run()
	r2, rep2 := run()
	// Overlap proof: the barrier gate sits inside the fake runner AFTER the
	// active/maxConcurrent counters are bumped and before the script runs,
	// so when the gate opens all four executions are inside Run and
	// counted — maxConcurrent must exceed 1 (it reaches 4) on every run,
	// on any scheduler.
	for i, rr := range []*fakeRunner{r1, r2} {
		if rr.maxConcurrent <= 1 {
			t.Fatalf("run %d maxConcurrent = %d, want > 1 (the barrier must make the jobs genuinely overlap)", i+1, rr.maxConcurrent)
		}
	}
	if !reflect.DeepEqual(rep1, rep2) {
		t.Fatalf("two identical runs at Concurrency 4 differ:\nrun 1: %+v\nrun 2: %+v", rep1, rep2)
	}
	// Per-source report order is the selection order (subfinder,
	// assetfinder, amass, chaos — builtInNames), never pool-completion order.
	wantOrder := []string{"subfinder", "assetfinder", "amass", "chaos"}
	for i, res := range rep1.Results {
		if res.Source != wantOrder[i] {
			t.Fatalf("results[%d].Source = %q, want %q (selection order, not completion order)",
				i, res.Source, wantOrder[i])
		}
	}
	// Per-source contents: deduplicated and sorted by canonical name.
	want := map[string][]string{
		"subfinder":   {"api.example.com", "www.example.com"},
		"assetfinder": {"blog.example.com", "www.example.com"},
		"amass":       {"api.example.com", "mail.example.com"},
		"chaos":       {"chaos.example.com"},
	}
	for _, res := range rep1.Results {
		got := names(res.Hosts)
		if !reflect.DeepEqual(got, want[res.Source]) {
			t.Errorf("%s hosts = %v, want %v (sorted by canonical name)", res.Source, got, want[res.Source])
		}
	}
	// The merged list Report.All() is sorted by canonical name (the order
	// the pipeline adapter propagates into the shared corpus).
	wantAll := []string{"api.example.com", "blog.example.com", "chaos.example.com", "mail.example.com", "www.example.com"}
	if got := names(rep1.All()); !reflect.DeepEqual(got, wantAll) {
		t.Errorf("All() = %v, want %v (sorted by canonical name)", got, wantAll)
	}
}

// TestRunDeterministicProvenanceAcrossRuns pins the clock seam at engine
// level: with a fixed injected Now every host in every source carries the
// fixed instant, and the merged earliest-wins provenance is identical
// across runs even at Concurrency 4 under genuinely overlapping jobs — the
// same disabled rate limiter + runner barrier as the sibling test (the
// merged identity keeps the earliest observation's provenance; ties
// resolve to the first source in selection order — deterministic because
// the report order is).
func TestRunDeterministicProvenanceAcrossRuns(t *testing.T) {
	target := mustDomain(t, "example.com")
	run := func() (*fakeRunner, Report) {
		r := newFakeRunner(t, fullScript())
		cfg := testConfig(r, newFakeLookup())
		cfg.Concurrency = 4
		cfg.Rate = 0    // no job-start pacing (see the sibling test)
		r.armBarrier(4) // all four discovery executions overlap inside Run
		return r, mustRun(t, target, cfg)
	}
	r1, rep1 := run()
	r2, rep2 := run()
	for i, rr := range []*fakeRunner{r1, r2} {
		if rr.maxConcurrent <= 1 {
			t.Fatalf("run %d maxConcurrent = %d, want > 1 (the barrier must make the jobs genuinely overlap)", i+1, rr.maxConcurrent)
		}
	}
	if !reflect.DeepEqual(rep1, rep2) {
		t.Fatalf("two identical runs at Concurrency 4 differ: %+v vs %+v", rep1, rep2)
	}
	for _, h := range rep1.All() {
		if !h.Prov.DiscoveredAt.Equal(fixedTime) {
			t.Errorf("host %s provenance = %v, want %v (the injected clock, never the wall clock)",
				h.Name, h.Prov.DiscoveredAt, fixedTime)
		}
	}
}

// TestRunPerSourceHostsSorted pins the per-source ordering contract
// directly: every source's host list is sorted by canonical name even when
// the tool emits the same set in scrambled order (a hostile or noisy tool
// cannot inject scheduling-dependent order into the report). The rate
// limiter is disabled so pacing cannot serialize the run (see the sibling
// tests).
func TestRunPerSourceHostsSorted(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("www.example.com\napi.example.com\nblog.example.com\napi.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 4
	cfg.Rate = 0 // no job-start pacing (see the sibling tests)
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	want := []string{"api.example.com", "blog.example.com", "www.example.com"}
	if got := names(rep.Results[0].Hosts); !reflect.DeepEqual(got, want) {
		t.Fatalf("subfinder hosts = %v, want %v (deduplicated + sorted)", got, want)
	}
	if rep.Results[0].Malformed != 0 {
		t.Fatalf("malformed = %d, want 0 (the duplicate line is deduplicated, not malformed)", rep.Results[0].Malformed)
	}
}
