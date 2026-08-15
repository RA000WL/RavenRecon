package techintel

import (
	"context"
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
// advances when advance is called.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

// Now implements runtime.Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements runtime.Clock (fire-and-forget channel; the pool only uses
// it for rate-limit timing).
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	go func() {
		time.Sleep(d)
		ch <- c.Now()
	}()
	return ch
}

// testConfig returns a minimal valid Config with an injected clock and a
// temp-dir cache.
func testConfig(t *testing.T) Config {
	t.Helper()
	c := DefaultConfig()
	c.Clock = newFakeClock(fixedTime)
	c.Cache = openTestCache(t)
	c.Concurrency = 2
	c.QueueSize = 16
	c.Timeout = 5 * time.Second
	return c
}

// openTestCache opens a per-test filesystem cache in a temp dir.
func openTestCache(t *testing.T) *cache.FS {
	t.Helper()
	dir := t.TempDir()
	db, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("open test cache: %v", err)
	}
	return db
}

// mustURL parses a canonical URL asset.
func mustURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

// newObs builds a test observation for the given raw URL.
func newObs(t *testing.T, raw string) Observation {
	t.Helper()
	return Observation{URL: mustURL(t, raw), Source: "test", ObservedAt: fixedTime}
}

// findTech returns the TechnologyResult for a technology name, or nil.
func findTech(ts []TechnologyResult, name string) *TechnologyResult {
	for i := range ts {
		if ts[i].Technology.Name == name {
			return &ts[i]
		}
	}
	return nil
}

// findReportTech returns the report-level merged technology for a name, or
// nil.
func findReportTech(rep *Report, name string) *asset.Technology {
	for i := range rep.Technologies {
		if rep.Technologies[i].Name == name {
			return &rep.Technologies[i]
		}
	}
	return nil
}

// stubCache is a scriptable cache.Cache for hit-path tests: Get returns a
// canned outcome; Put/Delete/Clear are no-ops.
type stubCache struct {
	outcome cache.Outcome
}

func (c *stubCache) Get(ctx context.Context, key cache.Key) cache.Outcome { return c.outcome }
func (c *stubCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	return nil
}
func (c *stubCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (c *stubCache) Clear(ctx context.Context) error                 { return nil }

var _ runtime.Clock = (*fakeClock)(nil)
var _ cache.Cache = (*stubCache)(nil)
