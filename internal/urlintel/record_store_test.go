// Direct-branch unit tests for the store path in record.go: the key-build
// failure branch (storeKeyFailed) and the write side behind a derived key
// (storeURLByKey). A key-build failure is unreachable through public paths
// today — the operation is a non-empty constant and every canonical URL
// identity is non-empty, so urlKey cannot fail on real inputs — which is why
// these tests pin the branches directly instead of fault-injecting through
// Ingest. They pin the NEW-87 regression shape: a key-build error must be
// handled distinctly (never silently overwritten by json.Marshal's error)
// and must never reach Marshal/Put under an empty key.
package urlintel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// recordingCache is a scriptable cache.Cache that records every Put so the
// store-path tests can prove exactly which keys reach the write side. It
// carries no mutable state of its own beyond the mutex-guarded log.
type recordingCache struct {
	mu       sync.Mutex
	putKeys  []cache.Key
	putRecs  []cache.Record
	putError error // when non-nil, returned by Put after recording
}

func (c *recordingCache) Get(_ context.Context, _ cache.Key) cache.Outcome {
	return cache.Outcome{}
}

func (c *recordingCache) Put(_ context.Context, key cache.Key, record cache.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putKeys = append(c.putKeys, key)
	c.putRecs = append(c.putRecs, record)
	return c.putError
}

func (c *recordingCache) Delete(_ context.Context, _ cache.Key) error { return nil }
func (c *recordingCache) Clear(_ context.Context) error               { return nil }

// puts returns a snapshot of the recorded Put keys.
func (c *recordingCache) puts() []cache.Key {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cache.Key(nil), c.putKeys...)
}

// storeTestEnv returns an env over rec with known-version observation
// parameters (the cacheable-by-policy configuration).
func storeTestEnv(rec cache.Cache) *env {
	return &env{
		cache:       rec,
		adapter:     "test-adapter",
		toolVersion: "v1.0.0",
		parseParams: true,
	}
}

// completedEntry returns a minimal realistic completed entry for u.
func completedEntry(u asset.URL) URLEntry {
	return URLEntry{
		URL:       u,
		Status:    StatusCompleted,
		Sources:   []string{"test-adapter"},
		FirstSeen: fixedTime,
		LastSeen:  fixedTime,
	}
}

// TestStoreKeyBuildFailurePreservesCompletedResultAndDiagnoses pins the
// NEW-87 branch semantics directly: a key-build failure on the store side is
// surfaced with its own classification ("build cache key", mirroring
// lookupURL's read-side wording), joined onto the entry WITHOUT downgrading
// the already-completed result (extraction succeeded — only persistence
// failed), recorded as a bounded run diagnostic, and never reaches Marshal
// or Put — where it would previously have been silently overwritten by
// json.Marshal's error and resurfaced as a misleading "cache put" diagnostic.
func TestStoreKeyBuildFailurePreservesCompletedResultAndDiagnoses(t *testing.T) {
	u, err := asset.ParseURL("http://example.com/a?q=1",
		asset.Provenance{Source: "test-adapter", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	entry := completedEntry(u)
	rec := &recordingCache{}
	e := storeTestEnv(rec)

	sentinel := errors.New("key derivation unavailable")
	got := storeKeyFailed(u, entry, e, sentinel)

	if got.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed (the extraction succeeded; only persistence failed)", got.Status)
	}
	if got.Err == nil || !errors.Is(got.Err, sentinel) || !strings.Contains(got.Err.Error(), "build cache key") {
		t.Fatalf("entry Err = %v, want a joined \"build cache key\" error wrapping the cause", got.Err)
	}
	runDiag := e.runError()
	if runDiag == nil || !errors.Is(runDiag, sentinel) || !strings.Contains(runDiag.Error(), "build cache key") {
		t.Fatalf("run diagnostics = %v, want the classification-grade key-build diagnostic", runDiag)
	}
	if puts := rec.puts(); len(puts) != 0 {
		t.Fatalf("Put called %d time(s) with key %q; a key-build failure must never reach the cache", len(puts), puts[0])
	}
}

// TestStoreURLByKeyPutsDerivedKeyAndCompletedRecord pins the write side
// behind the derivation point: the record lands under EXACTLY the derived
// key — never "" — with matching identity fields and a decodable structured
// payload, and success leaves the entry untouched.
func TestStoreURLByKeyPutsDerivedKeyAndCompletedRecord(t *testing.T) {
	u, err := asset.ParseURL("http://example.com/a?q=1",
		asset.Provenance{Source: "test-adapter", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	entry := completedEntry(u)
	rec := &recordingCache{}
	e := e2metrics(storeTestEnv(rec))

	key, err := urlKey(u, e.adapter, e.toolVersion, e.parseParams)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}

	got := storeURLByKey(context.Background(), u, entry, e, key)
	if got.Err != nil {
		t.Fatalf("entry Err = %v, want none on a clean store", got.Err)
	}
	puts := rec.puts()
	if len(puts) != 1 {
		t.Fatalf("Put calls = %d, want exactly 1", len(puts))
	}
	if puts[0] != key {
		t.Fatalf("stored under key %q, want the derived key %q", puts[0], key)
	}
	rec.mu.Lock()
	record := rec.putRecs[0]
	rec.mu.Unlock()
	if record.Operation != Operation || record.Target != u.Identity().String() || record.Status != cache.StatusCompleted {
		t.Fatalf("record identity = %s/%s/%s, want %s/%s/completed",
			record.Operation, record.Target, record.Status, Operation, u.Identity().String())
	}
	var st storedURL
	if err := json.Unmarshal(record.Data, &st); err != nil {
		t.Fatalf("decode stored payload: %v", err)
	}
	if st.Target != u.Identity().String() || st.Adapter != e.adapter {
		t.Fatalf("payload identity = %s/%s, want %s/%s", st.Target, st.Adapter, u.Identity().String(), e.adapter)
	}
	if snap := e.metrics.Snapshot(); snap.Stored != 1 {
		t.Fatalf("Stored metric = %d, want 1", snap.Stored)
	}
}

// TestStoreURLWritesOnlyTheDerivedKey walks the full store path end to end
// with a valid observation: exactly one Put carrying urlKey's exact result,
// entry preserved unchanged. This proves the split into storeKeyFailed /
// storeURLByKey left the happy path byte-for-byte equivalent — and that no
// reachable input can steer the write side toward an empty key.
func TestStoreURLWritesOnlyTheDerivedKey(t *testing.T) {
	u, err := asset.ParseURL("http://example.com/a?q=1",
		asset.Provenance{Source: "test-adapter", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	entry := completedEntry(u)
	rec := &recordingCache{}
	e := e2metrics(storeTestEnv(rec))

	key, err := urlKey(u, e.adapter, e.toolVersion, e.parseParams)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}

	got := storeURL(context.Background(), u, entry, e)
	if got.Status != StatusCompleted || got.Err != nil {
		t.Fatalf("entry = %+v, want unchanged completed entry with nil Err", got)
	}
	puts := rec.puts()
	if len(puts) != 1 || puts[0] != key {
		t.Fatalf("Put calls = %v, want exactly [%s]", puts, key)
	}
}

// e2metrics attaches a fresh Metrics to e (a tiny helper keeping the test
// env literals readable).
func e2metrics(e *env) *env {
	e.metrics = &Metrics{}
	return e
}
