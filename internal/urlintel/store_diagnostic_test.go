package urlintel

// Regression coverage for TODO.md NEW-57's honesty half: cache WRITE
// failures must surface in the run's bounded error summary exactly like
// read-side failures already do (lookupURL), never be silently absorbed
// into per-entry Err alone. Before the fix, an entire cold pass could lose
// every store (for example ENOSPC once a scratch volume's inodes ran out)
// while Ingest still returned nil and the run looked fully successful.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// failingPutCache fails every write with a fixed synthetic error while
// serving reads as misses: the minimal harness for store-path diagnostics.
type failingPutCache struct {
	err error
}

func (c *failingPutCache) Get(context.Context, cache.Key) cache.Outcome {
	return cache.Outcome{State: cache.StateMiss}
}

func (c *failingPutCache) Put(context.Context, cache.Key, cache.Record) error {
	return c.err
}

func (c *failingPutCache) Delete(context.Context, cache.Key) error { return nil }

func (c *failingPutCache) Clear(context.Context) error { return nil }

var _ cache.Cache = (*failingPutCache)(nil)

func TestStoreFailuresSurfaceAsRunDiagnostics(t *testing.T) {
	putErr := errors.New("synthetic put failure: no space left on device")
	cfg := testConfig()
	cfg.Cache = &failingPutCache{err: putErr}
	cfg.Metrics = &Metrics{}
	lines := []string{
		"http://a.example.com/p?a=1",
		"http://b.example.com/p?a=2",
		"http://c.example.com/p?a=3",
	}

	rep, err := Ingest(context.Background(), cfg, SliceSource(lines))
	if err == nil {
		t.Fatal("Ingest returned nil error; want the cache-put failure surfaced as a run diagnostic")
	}
	if !strings.Contains(err.Error(), "cache put") || !strings.Contains(err.Error(), putErr.Error()) {
		t.Fatalf("run error does not name the cache-put failure: %v", err)
	}

	// Every observation is still completed with the diagnostic on its entry:
	// extraction succeeded, only persistence failed.
	if len(rep.Entries) != len(lines) {
		t.Fatalf("entries = %d, want %d", len(rep.Entries), len(lines))
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCompleted {
			t.Fatalf("entry %s status = %s, want completed (extraction succeeded)", e.URL.String(), e.Status)
		}
		if e.Err == nil || !strings.Contains(e.Err.Error(), "cache put") {
			t.Fatalf("entry %s Err = %v, want joined cache-put diagnostic", e.URL.String(), e.Err)
		}
	}

	snap := cfg.Metrics.Snapshot()
	if snap.Stored != 0 || snap.Extracted != len(lines) {
		t.Fatalf("metrics = %+v; want all extractions counted, zero stores", snap)
	}
}

func TestCancelledStoreFailureStaysOutOfRunDiagnostics(t *testing.T) {
	// Cancellation-class write failures keep the documented filtering
	// contract: they surface through entry statuses/Err, never as spurious
	// run diagnostics (mirrors recordCacheDiagnostic's read-side behavior).
	cfg := testConfig()
	cfg.Cache = &failingPutCache{err: fmt.Errorf("cache put x: %w", context.Canceled)}
	lines := []string{"http://a.example.com/p?a=1"}

	rep, err := Ingest(context.Background(), cfg, SliceSource(lines))
	if err != nil {
		t.Fatalf("run error = %v; want cancellation-class store failures filtered out of run diagnostics", err)
	}
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
	}
	e := rep.Entries[0]
	if e.Status != StatusCompleted || e.Err == nil || !errors.Is(e.Err, context.Canceled) {
		t.Fatalf("entry status=%s err=%v; want completed with joined cancellation cause on the entry", e.Status, e.Err)
	}
}
