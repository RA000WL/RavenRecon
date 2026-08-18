package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

func TestRunEmptyRegistry(t *testing.T) {
	rep, err := Run(context.Background(), DefaultEngineConfig(NewRegistry()), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != OutcomeCompleted || len(rep.Rules) != 0 {
		t.Fatalf("empty run must be completed with no rules: %+v", rep)
	}
}

func TestRunSingleRule(t *testing.T) {
	reg := newTestRegistry(t, makeRule(t, "a.b", nil))
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != OutcomeCompleted || rep.Completed != 1 {
		t.Fatalf("outcome %s, completed %d", rep.Outcome, rep.Completed)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings %d, want 1", len(rep.Findings))
	}
	res := resultOf(t, rep, "a.b")
	if res.Status != RuleStatusCompleted || res.Cached || res.Findings != 1 {
		t.Fatalf("rule result wrong: %+v", res)
	}
}

func TestRunExecutionOrderRespectsDependencies(t *testing.T) {
	var mu sync.Mutex
	events := []string{}
	record := func(id string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, id)
	}
	// Chain: root → mid → leaf; a wide pair at level 1.
	mk := func(id string, deps ...string) Rule {
		return makeRule(t, id, &ruleOptions{
			deps: deps,
			detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
				record(id)
				f, err := testFinding(dctx, id, "Rule "+id, CategoryInformation, 0)
				if err != nil {
					return nil, err
				}
				return []asset.Finding{f}, nil
			},
		})
	}
	reg := newTestRegistry(t,
		mk("leaf.z", "mid.y"),
		mk("mid.y", "root.x"),
		mk("root.x"),
		mk("wide.a", "root.x"),
	)
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Completed != 4 || rep.Levels != 3 {
		t.Fatalf("completed %d levels %d: %+v", rep.Completed, rep.Levels, rep)
	}
	mu.Lock()
	defer mu.Unlock()
	pos := func(id string) int {
		for i, e := range events {
			if e == id {
				return i
			}
		}
		return -1
	}
	if pos("root.x") > pos("mid.y") || pos("root.x") > pos("wide.a") || pos("mid.y") > pos("leaf.z") {
		t.Fatalf("execution order violated dependency levels: %v", events)
	}
}

func TestRunParallelExecutionWithinLevel(t *testing.T) {
	// N rules that all block until every detector has entered: they only
	// complete if the engine runs them concurrently.
	const n = 4
	var entered int32
	release := make(chan struct{})
	detector := func(id string) Detector {
		return func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			if atomic.AddInt32(&entered, 1) == n {
				close(release)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, errors.New("parallelism test timed out")
			}
			return nil, nil // a rule may legitimately find nothing
		}
	}
	rules := make([]Rule, n)
	for i := range rules {
		id := fmt.Sprintf("parallel.%02d", i)
		rules[i] = makeRule(t, id, &ruleOptions{detector: detector(id)})
	}
	reg := newTestRegistry(t, rules...)
	cfg := DefaultEngineConfig(reg)
	cfg.Concurrency = n
	start := time.Now()
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Completed != n {
		t.Fatalf("completed %d, want %d: %+v", rep.Completed, n, rep)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("rules did not run in parallel (elapsed %s)", elapsed)
	}
}

func TestRunDisabledAndKindAbsentRulesSkipped(t *testing.T) {
	disabled := makeRuleDisabled(t, "disabled.x")
	needsJS := makeRule(t, "needs.js", &ruleOptions{required: []asset.Kind{asset.KindJavaScript}})
	normal := makeRule(t, "normal.x", nil)
	reg := newTestRegistry(t, disabled, needsJS, normal)
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("skips must not force a non-completed outcome: %s", rep.Outcome)
	}
	r1 := resultOf(t, rep, "disabled.x")
	if r1.Status != RuleStatusSkipped || !strings.Contains(r1.SkipReason, "disabled") {
		t.Fatalf("disabled rule: %+v", r1)
	}
	r2 := resultOf(t, rep, "needs.js")
	if r2.Status != RuleStatusSkipped || !strings.Contains(r2.SkipReason, "javascript") {
		t.Fatalf("kind-absent rule: %+v", r2)
	}
	if resultOf(t, rep, "normal.x").Status != RuleStatusCompleted {
		t.Fatalf("normal rule must complete")
	}
	// A rule depending on a skipped rule cascades an honest skip.
	dependent := makeRule(t, "dependent.x", &ruleOptions{deps: []string{"needs.js"}})
	reg2 := newTestRegistry(t, needsJS, dependent)
	rep2, err := Run(context.Background(), DefaultEngineConfig(reg2), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rd := resultOf(t, rep2, "dependent.x")
	if rd.Status != RuleStatusSkipped || !strings.Contains(rd.SkipReason, "needs.js") {
		t.Fatalf("dependent rule: %+v", rd)
	}
}

func TestRunDependencyFailureCascades(t *testing.T) {
	failing := makeRule(t, "failing.x", &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
		return nil, errors.New("synthetic detector failure")
	}})
	dependent := makeRule(t, "dependent.x", &ruleOptions{deps: []string{"failing.x"}})
	independent := makeRule(t, "independent.x", nil)
	reg := newTestRegistry(t, failing, dependent, independent)
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != OutcomeIncomplete {
		t.Fatalf("failed alongside completed must be incomplete: %s", rep.Outcome)
	}
	rf := resultOf(t, rep, "failing.x")
	if rf.Status != RuleStatusFailed || rf.Err == nil || !strings.Contains(rf.Err.Error(), "synthetic detector failure") {
		t.Fatalf("failing rule: %+v", rf)
	}
	rd := resultOf(t, rep, "dependent.x")
	if rd.Status != RuleStatusSkipped || !strings.Contains(rd.SkipReason, "failing.x") {
		t.Fatalf("dependent must cascade-skip: %+v", rd)
	}
	if resultOf(t, rep, "independent.x").Status != RuleStatusCompleted {
		t.Fatalf("independent rule must still complete")
	}
	if rep.Failed != 1 || rep.Skipped != 1 || rep.Completed != 1 {
		t.Fatalf("counts wrong: %+v", rep)
	}
}

func TestRunTimeout(t *testing.T) {
	slow := makeRule(t, "slow.x", &ruleOptions{
		timeout: 50 * time.Millisecond,
		detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return nil, nil
			}
		},
	})
	fast := makeRule(t, "fast.x", nil)
	reg := newTestRegistry(t, slow, fast)
	m := &Metrics{}
	cfg := DefaultEngineConfig(reg)
	cfg.Metrics = m
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rs := resultOf(t, rep, "slow.x")
	if rs.Status != RuleStatusFailed || rs.Err == nil || !strings.Contains(rs.Err.Error(), "timed out") {
		t.Fatalf("slow rule: %+v", rs)
	}
	if resultOf(t, rep, "fast.x").Status != RuleStatusCompleted {
		t.Fatalf("fast rule must complete")
	}
	if rep.Outcome != OutcomeIncomplete {
		t.Fatalf("outcome %s, want incomplete", rep.Outcome)
	}
	sn := m.Snapshot()
	if sn.Timeouts != 1 {
		t.Fatalf("timeout not counted in metrics: %+v", sn)
	}
	for _, rs2 := range sn.Rules {
		if rs2.ID == "slow.x" && rs2.Timeouts != 1 {
			t.Fatalf("per-rule timeout missing: %+v", rs2)
		}
	}
}

func TestRunPanicRecovery(t *testing.T) {
	before := runtime.NumGoroutine()
	panicking := makeRule(t, "panicking.x", &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
		panic("synthetic detector panic")
	}})
	healthy := makeRule(t, "healthy.x", nil)
	reg := newTestRegistry(t, panicking, healthy)
	m := &Metrics{}
	cfg := DefaultEngineConfig(reg)
	cfg.Metrics = m
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rp := resultOf(t, rep, "panicking.x")
	if rp.Status != RuleStatusFailed || rp.Err == nil || !strings.Contains(rp.Err.Error(), "panicked") {
		t.Fatalf("panicking rule: %+v", rp)
	}
	if resultOf(t, rep, "healthy.x").Status != RuleStatusCompleted {
		t.Fatalf("healthy rule must complete (panic isolation)")
	}
	if rep.Outcome != OutcomeIncomplete {
		t.Fatalf("outcome %s, want incomplete", rep.Outcome)
	}
	if sn := m.Snapshot(); sn.Panics != 1 {
		t.Fatalf("panic not counted: %+v", sn)
	}
	// No goroutine leaked from the recovered panic.
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutine leak: before %d after %d", before, after)
	}
}

func TestRunDetectorContractViolations(t *testing.T) {
	// Foreign-rule attribution.
	spoof := makeRule(t, "spoof.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		return []asset.Finding{mustFinding(t, ctx2Finding(t, "other.rule", "Rule other.rule", CategoryInformation))}, nil
	}})
	// Unobserved subject.
	unobserved := makeRule(t, "unobserved.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		f := mustFinding(t, ctx2Finding(t, "unobserved.x", "Rule unobserved.x", CategoryInformation))
		f.Subject = asset.Identity{Kind: asset.KindURL, Value: "https://unobserved.example.net/x"}
		return []asset.Finding{f}, nil
	}})
	// Excessive findings.
	excessive := makeRule(t, "excessive.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		out := make([]asset.Finding, 0, maxFindingsPerRule+1)
		for i := 0; i <= maxFindingsPerRule; i++ {
			out = append(out, mustFinding(t, ctx2Finding(t, "excessive.x", "Rule excessive.x", CategoryInformation)))
		}
		return out, nil
	}})
	reg := newTestRegistry(t, spoof, unobserved, excessive)
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, id := range []string{"spoof.x", "unobserved.x", "excessive.x"} {
		r := resultOf(t, rep, id)
		if r.Status != RuleStatusFailed || r.Err == nil {
			t.Fatalf("rule %q must fail its contract violation: %+v", id, r)
		}
	}
	if rep.Failed != 3 || rep.Outcome != OutcomeFailed {
		t.Fatalf("every attempted rule failed: %+v", rep)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("violating findings must not reach the report")
	}
}

// ctx2Finding builds a finding through the standard path without a Context.
func ctx2Finding(t *testing.T, ruleID, ruleName string, category Category) asset.Finding {
	t.Helper()
	f, err := testFinding(nil, ruleID, ruleName, category, 0)
	if err != nil {
		t.Fatalf("testFinding: %v", err)
	}
	return f
}

func mustFinding(t *testing.T, f asset.Finding) asset.Finding {
	t.Helper()
	g, err := asset.NewFinding(f)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return g
}

func TestRunStreamingEmit(t *testing.T) {
	var mu sync.Mutex
	emitted := []string{}
	cfg := DefaultEngineConfig(newTestRegistry(t,
		makeRule(t, "a.x", nil),
		makeRule(t, "b.x", &ruleOptions{deps: []string{"a.x"}}),
	))
	cfg.Emit = func(ctx context.Context, f asset.Finding) error {
		mu.Lock()
		defer mu.Unlock()
		emitted = append(emitted, f.ID())
		return nil
	}
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != len(rep.Findings) {
		t.Fatalf("emitted %d, report %d", len(emitted), len(rep.Findings))
	}
	seen := map[string]bool{}
	for _, id := range emitted {
		if seen[id] {
			t.Fatalf("finding emitted twice: %s", id)
		}
		seen[id] = true
	}

	// A panicking emit hook is contained and never loses findings.
	cfg2 := DefaultEngineConfig(newTestRegistry(t, makeRule(t, "a.x", nil)))
	cfg2.Emit = func(ctx context.Context, f asset.Finding) error {
		panic("emit hook panic")
	}
	rep2, err := Run(context.Background(), cfg2, testSnapshot(t))
	if err == nil || !strings.Contains(err.Error(), "emit hook panicked") {
		t.Fatalf("emit panic must surface as a diagnostic: %v", err)
	}
	if len(rep2.Findings) != 1 {
		t.Fatalf("emit panic lost the findings: %d", len(rep2.Findings))
	}
	if resultOf(t, rep2, "a.x").Status != RuleStatusCompleted {
		t.Fatalf("emit panic must not fail the rule")
	}
}

func TestRunCancellation(t *testing.T) {
	before := runtime.NumGoroutine()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	detector := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rules := []Rule{
		makeRule(t, "l0.a", &ruleOptions{detector: detector}),
		makeRule(t, "l0.b", &ruleOptions{detector: detector}),
		makeRule(t, "l1.a", &ruleOptions{deps: []string{"l0.a", "l0.b"}, detector: detector}),
		makeRule(t, "l2.a", &ruleOptions{deps: []string{"l1.a"}, detector: detector}),
	}
	reg := newTestRegistry(t, rules...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-entered // first rule started
		<-entered
		cancel()
		close(release)
	}()
	rep, err := Run(ctx, DefaultEngineConfig(reg), testSnapshot(t))
	<-done
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != OutcomeCancelled {
		t.Fatalf("outcome %s, want cancelled", rep.Outcome)
	}
	if rep.Cancelled == 0 {
		t.Fatalf("cancelled count %d", rep.Cancelled)
	}
	if rep.Completed != 0 && rep.Cancelled == 0 {
		t.Fatalf("honest cancellation requires cancelled statuses")
	}
	// Every registered rule appears with an honest status.
	ids := map[string]bool{}
	for _, r := range rep.Rules {
		ids[r.RuleID] = true
	}
	for _, want := range []string{"l0.a", "l0.b", "l1.a", "l2.a"} {
		if !ids[want] {
			t.Fatalf("rule %q missing from the cancelled report", want)
		}
	}
	// No goroutine outlives the cancelled run (±2 tolerance for
	// runtime-internal goroutines, mirroring the panic-recovery check).
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutine leak after cancelled run: before %d after %d", before, after)
	}
}

func TestRunNoGoroutineLeak(t *testing.T) {
	run := func() {
		reg := newTestRegistry(t,
			makeRule(t, "a.x", nil),
			makeRule(t, "b.x", &ruleOptions{deps: []string{"a.x"}}),
			makeRule(t, "c.x", nil),
		)
		if _, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t)); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	before := runtime.NumGoroutine()
	run()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutine leak after normal run: before %d after %d", before, after)
	}
}

func TestRunCacheHitSkipsExecution(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	counting := makeRule(t, "counting.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "counting.x", "Rule counting.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg := newTestRegistry(t, counting)
	snap := testSnapshot(t)

	cfg := DefaultEngineConfig(reg)
	cfg.Cache = fs
	m1 := &Metrics{}
	cfg.Metrics = m1
	rep1, err := Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	if rep1.Completed != 1 || rep1.CacheHits != 0 {
		t.Fatalf("cold run must execute: %+v", rep1)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("executions %d, want 1", executions)
	}

	cfg2 := DefaultEngineConfig(reg)
	cfg2.Cache = fs
	m2 := &Metrics{}
	cfg2.Metrics = m2
	rep2, err := Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("warm run must perform ZERO executions: %d", executions)
	}
	r := resultOf(t, rep2, "counting.x")
	if !r.Cached || r.Status != RuleStatusCompleted || r.Findings != 1 {
		t.Fatalf("warm result: %+v", r)
	}
	if rep2.CacheHits != 1 {
		t.Fatalf("cache hits %d, want 1", rep2.CacheHits)
	}
	if sn := m2.Snapshot(); sn.CacheHits != 1 || sn.CacheMisses != 0 || sn.Executions != 0 {
		t.Fatalf("warm metrics: %+v", sn)
	}
	// The warm report is identical to the cold one modulo the cached flag.
	if len(rep2.Findings) != len(rep1.Findings) ||
		rep2.Findings[0].ID() != rep1.Findings[0].ID() {
		t.Fatalf("warm findings differ from cold findings")
	}
}

// TestRunEmitOnCacheHit pins that the emit hook fires for cache-served
// findings too, not only fresh ones.
func TestRunEmitOnCacheHit(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := newTestRegistry(t, makeRule(t, "emit.x", nil))
	snap := testSnapshot(t)
	cfgCold := DefaultEngineConfig(reg)
	cfgCold.Cache = fs
	if _, err := Run(context.Background(), cfgCold, snap); err != nil {
		t.Fatalf("cold Run: %v", err)
	}

	var mu sync.Mutex
	emitted := []string{}
	cfgWarm := DefaultEngineConfig(reg)
	cfgWarm.Cache = fs
	cfgWarm.Emit = func(ctx context.Context, f asset.Finding) error {
		mu.Lock()
		defer mu.Unlock()
		emitted = append(emitted, f.ID())
		return nil
	}
	rep, err := Run(context.Background(), cfgWarm, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	r := resultOf(t, rep, "emit.x")
	if !r.Cached || rep.CacheHits != 1 {
		t.Fatalf("warm run must be cache-served: %+v (hits %d)", r, rep.CacheHits)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != len(rep.Findings) || (len(emitted) > 0 && emitted[0] != rep.Findings[0].ID()) {
		t.Fatalf("emit must fire for cached findings: %v vs %v", emitted, rep.Findings)
	}
}

// TestRunEmptyFindingsCacheRoundTrip pins that a rule that finds nothing
// still stores a completed record and is served from the cache on the warm
// run — an empty hit is a hit, not a miss.
func TestRunEmptyFindingsCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	empty := makeRule(t, "empty.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		return nil, nil // a rule may legitimately find nothing
	}})
	reg := newTestRegistry(t, empty)
	snap := testSnapshot(t)
	cfg := DefaultEngineConfig(reg)
	cfg.Cache = fs

	rep1, err := Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	if r := resultOf(t, rep1, "empty.x"); r.Status != RuleStatusCompleted || r.Findings != 0 || r.Cached {
		t.Fatalf("cold empty run: %+v", r)
	}

	rep2, err := Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("the empty result must be served from the cache: %d executions", executions)
	}
	r := resultOf(t, rep2, "empty.x")
	if !r.Cached || r.Status != RuleStatusCompleted || r.Findings != 0 {
		t.Fatalf("warm empty run must be a cache hit: %+v", r)
	}
	if rep2.CacheHits != 1 || len(rep2.Findings) != 0 {
		t.Fatalf("warm empty run report wrong: hits %d findings %d", rep2.CacheHits, len(rep2.Findings))
	}
}

func TestRunNeverCachesPartialExecutions(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var calls int32
	failing := makeRule(t, "failing.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("always fails")
	}})
	reg := newTestRegistry(t, failing)
	snap := testSnapshot(t)
	for run := 0; run < 2; run++ {
		cfg := DefaultEngineConfig(reg)
		cfg.Cache = fs
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run %d: %v", run, err)
		}
		if resultOf(t, rep, "failing.x").Status != RuleStatusFailed {
			t.Fatalf("run %d: rule must fail", run)
		}
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("failed executions must never be served from cache: %d calls", calls)
	}
}

func TestRunTamperedCacheRecordRecomputed(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := newTestRegistry(t, makeRule(t, "a.x", nil))
	snap := testSnapshot(t)
	cfg := DefaultEngineConfig(reg)
	cfg.Cache = fs
	if _, err := Run(context.Background(), cfg, snap); err != nil {
		t.Fatalf("cold Run: %v", err)
	}

	// Tamper with the stored record directly: rewrite the payload to
	// findings attributed to a foreign rule.
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fp, err := fingerprintSnapshot(corpus)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	rule, _ := reg.Get("a.x")
	key, err := ruleKey(rule, fp, nil)
	if err != nil {
		t.Fatalf("ruleKey: %v", err)
	}
	foreign, _ := testFinding(nil, "other.rule", "Rule a.x", CategoryInformation, 0)
	tampered, _ := encodeStoredFindings("a.x", []asset.Finding{foreign}, time.Now())
	if err := fs.Put(context.Background(), key, tampered); err != nil {
		t.Fatalf("tamper Put: %v", err)
	}

	var executions int32
	tamperedRule := makeRule(t, "a.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "a.x", "Rule a.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg2 := newTestRegistry(t, tamperedRule)
	cfg2 := DefaultEngineConfig(reg2)
	cfg2.Cache = fs
	rep, err := Run(context.Background(), cfg2, snap)
	if err == nil || !strings.Contains(err.Error(), "cache hit rejected") {
		t.Fatalf("tampered record must surface as a diagnostic: %v", err)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("tampered record must be evicted and recomputed: %d executions", executions)
	}
	r := resultOf(t, rep, "a.x")
	if r.Cached || r.Status != RuleStatusCompleted {
		t.Fatalf("recomputed result: %+v", r)
	}
}

func TestRunConfigEntersCacheKey(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	counting := makeRule(t, "a.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "a.x", "Rule a.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg := newTestRegistry(t, counting)
	snap := testSnapshot(t)
	run := func(cfgMap map[string]string) {
		cfg := DefaultEngineConfig(reg)
		cfg.Cache = fs
		cfg.Config = cfgMap
		if _, err := Run(context.Background(), cfg, snap); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	run(map[string]string{"threshold": "0.5"})
	run(map[string]string{"threshold": "0.5"})
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("same config must hit the cache")
	}
	run(map[string]string{"threshold": "0.9"})
	if atomic.LoadInt32(&executions) != 2 {
		t.Fatalf("different config must miss the cache")
	}
}

func TestRunRuleVersionInvalidatesCache(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	det := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "a.x", "Rule a.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}
	v1 := makeRule(t, "a.x", &ruleOptions{detector: det})
	reg1 := newTestRegistry(t, v1)
	snap := testSnapshot(t)
	cfg := DefaultEngineConfig(reg1)
	cfg.Cache = fs
	if _, err := Run(context.Background(), cfg, snap); err != nil {
		t.Fatalf("Run v1: %v", err)
	}
	v2 := makeRule(t, "a.x", &ruleOptions{detector: det, version: "1.0.1"})
	reg2 := newTestRegistry(t, v2)
	cfg2 := DefaultEngineConfig(reg2)
	cfg2.Cache = fs
	rep, err := Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run v2: %v", err)
	}
	if atomic.LoadInt32(&executions) != 2 {
		t.Fatalf("version bump must invalidate the cached result: %d executions", executions)
	}
	if resultOf(t, rep, "a.x").Cached {
		t.Fatalf("bumped version must not be served from the v1 record")
	}
}

func TestRunMetricsAndLogging(t *testing.T) {
	ruleA := makeRule(t, "log.a", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		dctx.Logger.Log(LevelInfo, "log.a", "scanning assets")
		dctx.Logger.Log(LevelWarn, "log.a", "suspicious shape")
		f, err := testFinding(dctx, "log.a", "Rule log.a", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg := newTestRegistry(t, ruleA)
	m := &Metrics{}
	cfg := DefaultEngineConfig(reg)
	cfg.Metrics = m
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sn := m.Snapshot()
	if sn.Executions != 1 || sn.Findings != 1 || len(sn.Rules) != 1 {
		t.Fatalf("metrics wrong: %+v", sn)
	}
	if sn.Rules[0].ID != "log.a" || sn.Rules[0].Findings != 1 {
		t.Fatalf("per-rule stats wrong: %+v", sn.Rules[0])
	}
	if len(rep.Logs) != 2 {
		t.Fatalf("logs retained %d, want 2: %+v", len(rep.Logs), rep.Logs)
	}
	if rep.Logs[0].Level != LevelInfo || rep.Logs[1].Level != LevelWarn {
		t.Fatalf("logs not sorted by level within the rule: %+v", rep.Logs)
	}

	// A caller-provided Logger replaces the default collector.
	external := &recordingLogger{}
	cfg2 := DefaultEngineConfig(reg)
	cfg2.Logger = external
	rep2, err := Run(context.Background(), cfg2, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run with external logger: %v", err)
	}
	if len(rep2.Logs) != 0 {
		t.Fatalf("external logger must not feed the report logs")
	}
	if got := len(external.snapshot()); got != 2 {
		t.Fatalf("external logger received %d entries, want 2", got)
	}
}

// fixedClock pins Now to a constant (After still fires in real time, so the
// Clock contract holds; rate limiting is disabled in these runs anyway).
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func TestRunDeterminism(t *testing.T) {
	build := func() *Registry {
		return newTestRegistry(t,
			makeRule(t, "a.x", nil),
			makeRule(t, "b.x", &ruleOptions{deps: []string{"a.x"}}),
			makeRule(t, "c.x", nil),
			makeRule(t, "d.x", &ruleOptions{deps: []string{"c.x", "a.x"}}),
		)
	}
	clock := fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	snap := testSnapshot(t)
	run := func() Report {
		cfg := DefaultEngineConfig(build())
		cfg.Clock = clock
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()
	b1, err := json.Marshal(rep1)
	if err != nil {
		t.Fatalf("marshal rep1: %v", err)
	}
	b2, err := json.Marshal(rep2)
	if err != nil {
		t.Fatalf("marshal rep2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("identical runs (fixed clock) produced different reports")
	}
	if rep1.Levels != 2 || len(rep1.Findings) != 4 {
		t.Fatalf("deterministic shape wrong: %+v", rep1)
	}
}

func TestRunSameIdentityFindingsMerge(t *testing.T) {
	many := makeRule(t, "many.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		out := make([]asset.Finding, 0, 16)
		for i := 0; i < 16; i++ {
			f, err := testFinding(dctx, "many.x", "Rule many.x", CategoryInformation, i)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		return out, nil
	}})
	reg := newTestRegistry(t, many)
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Same-identity findings (same rule, same subject) merge to ONE.
	if len(rep.Findings) != 1 {
		t.Fatalf("same-identity findings must merge: %d", len(rep.Findings))
	}
	if resultOf(t, rep, "many.x").Findings != 1 {
		t.Fatalf("result must count the merged finding")
	}
}

func TestResultAccumulatorRunCap(t *testing.T) {
	acc := newResultAccumulator()
	findings := make([]asset.Finding, 0, maxFindingsPerRun+10)
	subject := asset.Identity{Kind: asset.KindURL, Value: testSubjectURL}
	for i := 0; i < maxFindingsPerRun+10; i++ {
		f, err := testFinding(nil, fmt.Sprintf("rule.%03d", i), "Rule", CategoryInformation, 0)
		if err != nil {
			t.Fatalf("testFinding: %v", err)
		}
		if f.Subject != subject {
			t.Fatalf("subject drifted")
		}
		findings = append(findings, f)
	}
	acc.addFindings(findings)
	_, kept, truncated := acc.snapshot()
	if len(kept) != maxFindingsPerRun {
		t.Fatalf("cap not applied: %d", len(kept))
	}
	if !truncated {
		t.Fatalf("truncation not flagged")
	}
	// The findings kept are the earliest by submission order and are
	// sorted deterministically by identity.
	for i := 1; i < len(kept); i++ {
		if kept[i-1].Identity().String() >= kept[i].Identity().String() {
			t.Fatalf("snapshot findings not sorted by identity")
		}
	}
}

// TestRunFindingsCapOutcome exercises buildReport end-to-end through Run:
// an over-cap run is cut at maxFindingsPerRun with FindingsTruncated set
// and reports Outcome incomplete (truncated results are never completed,
// even though every per-rule status is completed); an under-cap run of the
// same shape reports Outcome completed.
func TestRunFindingsCapOutcome(t *testing.T) {
	// maxFindingsPerRule distinct observed subjects, reused by every rule
	// (finding identities stay distinct across rules through the rule ID).
	n := maxFindingsPerRule
	subs := make([]asset.Identity, 0, n)
	snap := Snapshot{Assets: make([]asset.Identity, 0, n)}
	for i := 0; i < n; i++ {
		u, err := asset.ParseURL(fmt.Sprintf("https://example.com/p/%03d", i), asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("ParseURL: %v", err)
		}
		subs = append(subs, u.Identity())
		snap.Assets = append(snap.Assets, u.Identity())
	}
	run := func(rules int) Report {
		list := make([]Rule, rules)
		for i := range list {
			id := fmt.Sprintf("cap.%03d", i)
			list[i] = makeRule(t, id, &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
				out := make([]asset.Finding, 0, len(subs))
				for j, subj := range subs {
					f, err := subjectFinding(dctx, id, "Rule "+id, CategoryInformation, subj, j)
					if err != nil {
						return nil, err
					}
					out = append(out, f)
				}
				return out, nil
			}})
		}
		rep, err := Run(context.Background(), DefaultEngineConfig(newTestRegistry(t, list...)), snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	// Over-cap: 17 rules × 256 findings = 4352 > 4096.
	over := run(maxFindingsPerRun/maxFindingsPerRule + 1)
	if over.Outcome != OutcomeIncomplete || !over.FindingsTruncated {
		t.Fatalf("over-cap run: outcome %s truncated %v, want incomplete + truncated", over.Outcome, over.FindingsTruncated)
	}
	if len(over.Findings) != maxFindingsPerRun {
		t.Fatalf("over-cap run kept %d findings, want the %d cap", len(over.Findings), maxFindingsPerRun)
	}
	if over.Completed != maxFindingsPerRun/maxFindingsPerRule+1 || over.Failed != 0 {
		t.Fatalf("per-rule statuses must all stay completed: %+v", over)
	}

	// Under-cap: the same shape under the cap reports completed.
	under := run(2)
	if under.Outcome != OutcomeCompleted || under.FindingsTruncated {
		t.Fatalf("under-cap run: outcome %s truncated %v, want completed", under.Outcome, under.FindingsTruncated)
	}
	if len(under.Findings) != 2*n {
		t.Fatalf("under-cap run kept %d findings, want %d", len(under.Findings), 2*n)
	}
}

func TestRunRejectsInvalidInputs(t *testing.T) {
	// Nil registry.
	if _, err := Run(context.Background(), DefaultEngineConfig(nil), testSnapshot(t)); err == nil {
		t.Fatalf("nil registry must be rejected")
	}
	// Invalid concurrency.
	cfg := DefaultEngineConfig(newTestRegistry(t, makeRule(t, "a.x", nil)))
	cfg.Concurrency = 0
	if _, err := Run(context.Background(), cfg, testSnapshot(t)); err == nil {
		t.Fatalf("invalid concurrency must be rejected")
	}
	// Over-bound snapshot.
	big := make([]asset.Identity, maxSnapshotAssets+1)
	if _, err := Run(context.Background(), DefaultEngineConfig(NewRegistry()), Snapshot{Assets: big}); err == nil {
		t.Fatalf("over-bound snapshot must be rejected")
	}
	// Over-bound configuration.
	cfg2 := DefaultEngineConfig(newTestRegistry(t, makeRule(t, "a.x", nil)))
	cfg2.Config = map[string]string{"k": strings.Repeat("v", MaxContextConfigValueBytes+1)}
	if _, err := Run(context.Background(), cfg2, testSnapshot(t)); err == nil {
		t.Fatalf("over-bound config must be rejected")
	}
	// Cyclic registry.
	cyclic := newTestRegistry(t,
		makeRule(t, "a.x", &ruleOptions{deps: []string{"b.x"}}),
		makeRule(t, "b.x", &ruleOptions{deps: []string{"a.x"}}),
	)
	if _, err := Run(context.Background(), DefaultEngineConfig(cyclic), testSnapshot(t)); err == nil {
		t.Fatalf("cyclic registry must be rejected")
	}
}

func TestRunContextDeliversCorpus(t *testing.T) {
	var got struct {
		assets, rels, evidence, techs, secrets, scripts, endpoints int
		config                                                     map[string]string
		logger                                                     Logger
		clock                                                      bool
	}
	det := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		got.assets = len(dctx.Assets)
		got.rels = len(dctx.Relationships)
		got.evidence = len(dctx.Evidence)
		got.techs = len(dctx.Technologies)
		got.secrets = len(dctx.Secrets)
		got.scripts = len(dctx.JavaScript)
		got.endpoints = len(dctx.Endpoints)
		got.config = dctx.Config
		got.logger = dctx.Logger
		got.clock = dctx.Clock != nil
		return nil, nil
	}
	reg := newTestRegistry(t, makeRule(t, "probe.x", &ruleOptions{detector: det}))
	cfg := DefaultEngineConfig(reg)
	cfg.Config = map[string]string{"mode": "synthetic"}
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resultOf(t, rep, "probe.x").Status != RuleStatusCompleted {
		t.Fatalf("probe rule must complete")
	}
	if got.assets != 2 || got.evidence != 1 || got.techs != 1 || got.endpoints != 1 {
		t.Fatalf("corpus not delivered: %+v", got)
	}
	if got.rels != 0 || got.secrets != 0 || got.scripts != 0 {
		t.Fatalf("unexpected domains delivered: %+v", got)
	}
	if got.config["mode"] != "synthetic" {
		t.Fatalf("config not delivered: %v", got.config)
	}
	if got.logger == nil {
		t.Fatalf("logger not delivered")
	}
	if !got.clock {
		t.Fatalf("clock not delivered")
	}
}
