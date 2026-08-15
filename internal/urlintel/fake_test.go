package urlintel

import (
	"context"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// testTimeout bounds every potentially blocking test below; tests that exceed
// it fail instead of hanging the suite.
const testTimeout = 30 * time.Second

// mustFinish runs fn with a hard test-level bound, so a regression that
// hangs Ingest fails fast instead of wedging the package.
func mustFinish(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("%s did not finish within %s", what, testTimeout)
	}
}

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

// waiterCount reports how many After timers are currently registered: the
// number of pending waits parked on the fake clock. Tests use it to observe
// that a rate-limiter wait has actually started (a token request registered
// its wake-up timer) before advancing the clock.
func (c *fakeClock) waiterCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

var _ runtime.Clock = (*fakeClock)(nil)

// testConfig returns a deterministic run configuration: a frozen clock, a
// small bounded pool, no rate limiting, and no cache (tests that need the
// cache set cfg.Cache explicitly).
func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 64
	cfg.Timeout = 0 // no per-job deadline: local work never blocks
	cfg.Rate = 0
	cfg.Burst = 0
	cfg.Adapter = "test-adapter"
	cfg.ParseParameters = true
	cfg.Clock = newFakeClock(fixedTime)
	return cfg
}

// openTestCache opens a real filesystem-backed Phase 3 cache under a
// temporary directory, driven by the same fake clock as the pipeline (so
// expiry tests advance both clocks consistently). ttl 0 disables expiration.
func openTestCache(t *testing.T, clk *fakeClock, ttl time.Duration) *cache.FS {
	t.Helper()
	c, err := cache.Open(t.TempDir(), cache.WithTTL(ttl), cache.WithClock(func() time.Time {
		return clk.Now()
	}))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

// runIngest runs one ingest over lines and fails the test on error.
func runIngest(t *testing.T, cfg Config, lines []string) Report {
	t.Helper()
	rep, err := Ingest(context.Background(), cfg, SliceSource(lines))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return rep
}

// mustURL parses raw into a canonical URL asset or fails the test.
func mustURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// findEntry returns the report entry for the canonical URL string, failing
// the test when absent.
func findEntry(t *testing.T, rep Report, canonical string) URLEntry {
	t.Helper()
	for _, e := range rep.Entries {
		if e.URL.String() == canonical {
			return e
		}
	}
	got := make([]string, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		got = append(got, e.URL.String())
	}
	t.Fatalf("no entry for %q; entries: %v", canonical, got)
	return URLEntry{}
}

// entryStrings returns the canonical URL strings of a report's entries.
func entryStrings(rep Report) []string {
	out := make([]string, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		out = append(out, e.URL.String())
	}
	return out
}

// requireEqualStrings compares two string slices ignoring order (they are
// sorted copies, so the comparison itself is deterministic).
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
	out := make([]string, len(xs))
	copy(out, xs)
	sortStrings(out)
	return out
}

// sortStrings sorts xs in place (name shadowing keeps the test helper
// independent of the package's own sort usage).
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}

// relationIDs returns the sorted relationship IDs of an entry.
func relationIDs(e URLEntry) []string {
	out := make([]string, 0, len(e.Relationships))
	for _, r := range e.Relationships {
		out = append(out, r.ID())
	}
	return sortedStrings(out)
}

// paramIDs returns the sorted parameter identities of an entry.
func paramIDs(e URLEntry) []string {
	out := make([]string, 0, len(e.Parameters))
	for _, p := range e.Parameters {
		out = append(out, p.ID())
	}
	return sortedStrings(out)
}

// waitForGoroutines patience-waits until the goroutine count returns to at
// most baseline+2 (bounded patience, never timing-fragile: it only fails on
// a genuine leak). Mirrors the DNS pipeline's helper.
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

// waitUntil patience-polls cond until it becomes true or budget elapses
// (bounded patience with small sleeps, never timing-fragile: it only fails
// on a genuine stall, not on a slow machine). Mirrors waitForGoroutines'
// patience convention.
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
