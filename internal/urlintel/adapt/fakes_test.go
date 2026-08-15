package adapt

import (
	"context"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/urlintel"
)

// testTimeout bounds every potentially blocking test below; tests that exceed
// it fail instead of hanging the suite.
const testTimeout = 30 * time.Second

// fixedTime is the deterministic provenance timestamp used by tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// fakeClock is a deterministic runtime.Clock. It starts at fixedTime and only
// advances when advance is called. After timers fire when advance passes
// their target, matching the runtime limiter's expectations.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters map[chan time.Time]time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, waiters: make(map[chan time.Time]time.Time)}
}

// Now implements runtime.Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements runtime.Clock.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters[ch] = c.now.Add(d)
	return ch
}

// advance moves the clock forward by d and fires every After timer whose
// target has been reached.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for ch, target := range c.waiters {
		if !target.After(c.now) {
			ch <- c.now
			delete(c.waiters, ch)
		}
	}
}

var _ runtime.Clock = (*fakeClock)(nil)

// runStep is one scripted fake-runner response. When the response queue is
// exhausted, the LAST step repeats (so a version probe plus several
// identical run responses needs only two entries).
type runStep struct {
	out    []byte // captured stdout
	errOut []byte // captured stderr
	code   int    // exit code (runner contract: nil error + code)
	trunc  bool   // StdoutTruncated
	runErr error  // runner error (process never ran to completion)
	block  bool   // wait for ctx.Done, then return ctx.Err()
	panics bool   // panic instead of returning (hostile runner)
}

// fakeRunner is a scripted discovery.Runner. Every Run call consumes the
// next step (the last one repeats). Calls and their argv are recorded for
// assertions; whether the caller supplied a context deadline is recorded
// too, so detection-budget tests are deterministic.
type fakeRunner struct {
	mu       sync.Mutex
	steps    []runStep
	cur      int
	calls    []discovery.Cmd
	deadline bool
}

func newFakeRunner(steps ...runStep) *fakeRunner {
	return &fakeRunner{steps: steps}
}

// Run implements discovery.Runner.
func (f *fakeRunner) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	if _, ok := ctx.Deadline(); ok {
		f.deadline = true
	}
	i := f.cur
	if len(f.steps) > 0 && f.cur < len(f.steps)-1 {
		f.cur++
	}
	var step runStep
	if len(f.steps) > 0 {
		step = f.steps[i]
	}
	f.mu.Unlock()

	if step.panics {
		panic("fake runner panic")
	}
	if step.block {
		<-ctx.Done()
		return discovery.RunResult{}, ctx.Err()
	}
	if step.runErr != nil {
		return discovery.RunResult{}, step.runErr
	}
	return discovery.RunResult{
		Stdout:          step.out,
		Stderr:          step.errOut,
		ExitCode:        step.code,
		StdoutTruncated: step.trunc,
	}, nil
}

// callCount returns how many Run calls happened.
func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// argsOf returns the argv of the n-th call (0-based), or nil.
func (f *fakeRunner) argsOf(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n < 0 || n >= len(f.calls) {
		return nil
	}
	return f.calls[n].Args
}

// sawDeadline reports whether any Run call observed a context deadline.
func (f *fakeRunner) sawDeadline() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline
}

// lookupStep is one scripted fake-lookup response; the last step repeats.
type lookupStep struct {
	path string
	err  error
}

// fakeLookup is a scripted discovery.LookupFunc, keyed by the requested name.
// A name with no script resolves to /fake/bin/<name>.
type fakeLookup struct {
	mu    sync.Mutex
	calls []string
	steps map[string][]lookupStep
	cur   map[string]int
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{steps: make(map[string][]lookupStep), cur: make(map[string]int)}
}

// Add scripts the k-th lookup of name to return path.
func (f *fakeLookup) Add(name, path string) {
	f.steps[name] = append(f.steps[name], lookupStep{path: path})
}

// AddErr scripts the k-th lookup of name to fail.
func (f *fakeLookup) AddErr(name string, err error) {
	f.steps[name] = append(f.steps[name], lookupStep{err: err})
}

// LookPath implements discovery.LookupFunc.
func (f *fakeLookup) LookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	steps := f.steps[name]
	i := f.cur[name]
	if len(steps) > 0 && f.cur[name] < len(steps)-1 {
		f.cur[name]++
	}
	if len(steps) == 0 {
		return "/fake/bin/" + name, nil
	}
	s := steps[i]
	return s.path, s.err
}

// requested returns the names looked up so far.
func (f *fakeLookup) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// asFunc adapts the fake to the discovery.LookupFunc named func type.
func (f *fakeLookup) asFunc() discovery.LookupFunc { return f.LookPath }

// mustHost normalizes a target hostname or fails the test.
func mustHost(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "test", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// testConfig returns a deterministic adapt configuration: the given tools, a
// frozen clock, a small bounded pool, no job-start pacing, no cache (tests
// that need the cache set cfg.Cache explicitly).
func testConfig(tools []Tool, targets []asset.Host) Config {
	cfg := DefaultConfig()
	cfg.Tools = tools
	cfg.Targets = targets
	cfg.Concurrency = 2
	cfg.QueueSize = 16
	cfg.Timeout = 0 // no per-job deadline: local work and fake runners never block
	cfg.Rate = 0
	cfg.Burst = 0
	cfg.IngestWorkers = 2
	cfg.Clock = newFakeClock(fixedTime)
	return cfg
}

// runOnce runs Run and fails the test on error.
func runOnce(t *testing.T, cfg Config) RunReport {
	t.Helper()
	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// entryStrings returns the canonical URL strings of a report's entries.
func entryStrings(rep urlintel.Report) []string {
	out := make([]string, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		out = append(out, e.URL.String())
	}
	return out
}

// requireEqualStrings compares two string slices exactly (tests construct
// the expected order deterministically or sort both sides).
func requireEqualStrings(t *testing.T, what string, got, want []string) {
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

// sortedStrings returns a sorted copy of xs.
func sortedStrings(xs []string) []string {
	out := append([]string(nil), xs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// waitUntil patience-polls cond until it becomes true or budget elapses
// (bounded patience with small sleeps, never timing-fragile: it only fails
// on a genuine stall, not on a slow machine). Mirrors the engine tests'
// convention.
func waitUntil(t *testing.T, what string, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not happen within %s", what, budget)
}

// waitForGoroutines patience-waits until the goroutine count returns to at
// most baseline+2 (bounded patience, never timing-fragile: it only fails on
// a genuine leak). Mirrors the engine tests' convention.
func waitForGoroutines(t *testing.T, baseline int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		goruntime.GC()
		if n := goruntime.NumGoroutine(); n <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := goruntime.NumGoroutine()
	t.Fatalf("goroutines = %d after run (baseline %d); possible leak", n, baseline)
}

// findEntry returns the report entry for the canonical URL string, failing
// the test when absent.
func findEntry(t *testing.T, rep urlintel.Report, canonical string) urlintel.URLEntry {
	t.Helper()
	for _, e := range rep.Entries {
		if e.URL.String() == canonical {
			return e
		}
	}
	t.Fatalf("no entry for %q; entries: %v", canonical, entryStrings(rep))
	return urlintel.URLEntry{}
}
