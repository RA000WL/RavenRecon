package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

func openTestCache(t *testing.T, opts ...cache.Option) *cache.FS {
	t.Helper()
	base := []cache.Option{cache.WithClock(func() time.Time { return fixedTime })}
	c, err := cache.Open(t.TempDir(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

// keyFor derives the cache key for a source and version against a target.
func keyFor(t *testing.T, target asset.Domain, srcName, version string) cache.Key {
	t.Helper()
	src := registry[srcName](toolEnv{name: srcName})
	k, err := cacheKey(target, src, Detection{Version: version})
	if err != nil {
		t.Fatalf("cacheKey: %v", err)
	}
	return k
}

// TestRunCacheMissThenHit verifies cache-before-execute: the first run
// executes every source and stores completed records; the second run with an
// identical key serves hits without executing the tools again.
func TestRunCacheMissThenHit(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	rep1 := mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != 3 {
		t.Fatalf("first run executes = %d, want 3", got)
	}

	// Every source stored a completed record.
	det := rep1.Results[0].Detection
	k := keyFor(t, target, "subfinder", det.Version)
	out := c.Get(context.Background(), k)
	if !out.IsHit() {
		t.Fatalf("subfinder record state = %s, want hit", out.State)
	}
	if out.Record.Status != cache.StatusCompleted {
		t.Fatalf("subfinder record status = %q, want completed", out.Record.Status)
	}
	if out.Record.Operation != Operation {
		t.Fatalf("record operation = %q, want %q", out.Record.Operation, Operation)
	}
	if out.Record.Target != target.Identity().String() {
		t.Fatalf("record target = %q, want %q", out.Record.Target, target.Identity().String())
	}
	if out.Record.Tool.Name != "subfinder" || out.Record.Tool.Version != "v2.6.3" {
		t.Fatalf("record tool = %+v, want subfinder v2.6.3", out.Record.Tool)
	}

	// Second run is served entirely from cache.
	execsBefore := r.discoverCallCount()
	rep2 := mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execsBefore {
		t.Fatalf("cache hits must not re-execute tools: executes %d -> %d", execsBefore, got)
	}
	for i := range rep2.Results {
		if !rep2.Results[i].Cached {
			t.Fatalf("%s result not served from cache", rep2.Results[i].Source)
		}
		if rep2.Results[i].Status != OutCompleted {
			t.Fatalf("%s cached status = %s, want completed", rep2.Results[i].Source, rep2.Results[i].Status)
		}
		if len(rep1.Results[i].Hosts) != len(rep2.Results[i].Hosts) {
			t.Fatalf("%s hosts changed across the cache hit: %d -> %d", rep2.Results[i].Source, len(rep1.Results[i].Hosts), len(rep2.Results[i].Hosts))
		}
	}

	// Records are reusable across cache instances over the same directory.
	c2, err := cache.Open(c.Dir())
	if err != nil {
		t.Fatalf("reopen cache: %v", err)
	}
	cfg.Cache = c2
	mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execsBefore {
		t.Fatalf("records must persist per cache dir: executes %d -> %d", execsBefore, got)
	}
}

// TestRunCacheDisabledExecutesEveryTime verifies default behavior: with no
// cache configured nothing is read or written and every run executes.
func TestRunCacheDisabledExecutesEveryTime(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	target := mustDomain(t, "example.com")
	mustRun(t, target, cfg)
	mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != 6 {
		t.Fatalf("executes = %d, want 6 (two uncached runs)", got)
	}
}

// TestRunCachePartialStoredIncomplete verifies partial results (non-zero exit
// with usable output) are stored as StatusIncomplete with the data attached,
// and are never treated as hits by later runs.
func TestRunCachePartialStoredIncomplete(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("api.example.com\n"), ExitCode: 1}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	rep := mustRun(t, target, cfg)
	if rep.Results[0].Status != OutPartial {
		t.Fatalf("subfinder status = %s, want partial", rep.Results[0].Status)
	}
	det := rep.Results[0].Detection
	k := keyFor(t, target, "subfinder", det.Version)
	out := c.Get(context.Background(), k)
	if out.IsHit() || !out.IsMiss() {
		t.Fatalf("partial record must be a miss, got state %s", out.State)
	}
	if out.State != cache.StateIncomplete {
		t.Fatalf("state = %s, want incomplete", out.State)
	}
	if out.Record.Status != cache.StatusIncomplete {
		t.Fatalf("record status = %q, want incomplete", out.Record.Status)
	}
	if !bytes.Contains(out.Record.Data, []byte("api.example.com")) {
		t.Fatalf("partial data must retain the discovered host: %s", out.Record.Data)
	}
	// A later run must re-execute (partial results are never hits).
	execs := r.discoverCallCount()
	mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execs+1 {
		t.Fatalf("later run must re-execute the partial source: %d -> %d", execs, got)
	}
}

// TestRunCacheCancelledStored verifies a cancelled run stores a
// StatusCancelled record (with its partial data), so no later run mistakes it
// for a completed result.
func TestRunCacheCancelledStored(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	r.blockKeys = map[string]bool{"subfinder -d example.com -silent": true}
	r.blockStarted = make(chan struct{})
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var rep Report
	go func() {
		rep, _ = Run(ctx, target, cfg)
		close(done)
	}()
	<-r.blockStarted
	cancel()
	<-done

	if rep.Results[0].Status != OutCancelled {
		t.Fatalf("subfinder status = %s, want cancelled", rep.Results[0].Status)
	}
	det := rep.Results[0].Detection
	k := keyFor(t, target, "subfinder", det.Version)
	out := c.Get(context.Background(), k)
	if out.IsHit() {
		t.Fatal("a cancelled record must never be a hit")
	}
	if out.State != cache.StateIncomplete || out.Record.Status != cache.StatusCancelled {
		t.Fatalf("state = %s record status = %q, want incomplete/cancelled", out.State, out.Record.Status)
	}
}

// TestRunCacheFailedStored verifies a clean failure is stored as StatusFailed
// and later runs re-execute instead of trusting it.
func TestRunCacheFailedStored(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{}, errors.New("permission denied")
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	rep := mustRun(t, target, cfg)
	if rep.Results[0].Status != OutFailed {
		t.Fatalf("subfinder status = %s, want failed", rep.Results[0].Status)
	}
	det := rep.Results[0].Detection
	k := keyFor(t, target, "subfinder", det.Version)
	out := c.Get(context.Background(), k)
	if out.IsHit() || out.State != cache.StateIncomplete || out.Record.Status != cache.StatusFailed {
		t.Fatalf("state = %s record status = %q, want incomplete/failed", out.State, out.Record.Status)
	}
	execs := r.discoverCallCount()
	mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execs+1 {
		t.Fatalf("later run must re-execute the failed source: %d -> %d", execs, got)
	}
}

// TestRunCacheEmptySuccessIsCompletedHit verifies empty-but-successful output
// is a legitimate completed result and a hit on the next run.
func TestRunCacheEmptySuccessIsCompletedHit(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	rep := mustRun(t, target, cfg)
	if rep.Results[0].Status != OutCompleted || len(rep.Results[0].Hosts) != 0 {
		t.Fatalf("subfinder = %s with %d hosts, want completed empty", rep.Results[0].Status, len(rep.Results[0].Hosts))
	}
	execs := r.discoverCallCount()
	rep2 := mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execs {
		t.Fatalf("empty completed result must be a hit: executes %d -> %d", execs, got)
	}
	if !rep2.Results[0].Cached {
		t.Fatal("empty result not served from cache")
	}
}

// TestRunCacheTTLExpiry verifies expired records are never hits and trigger
// re-execution.
func TestRunCacheTTLExpiry(t *testing.T) {
	clk := newFakeClock(fixedTime)
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Now = clk.now
	base := []cache.Option{
		cache.WithTTL(time.Hour),
		cache.WithClock(clk.now),
	}
	cached, err := cache.Open(t.TempDir(), base...)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = cached
	target := mustDomain(t, "example.com")

	mustRun(t, target, cfg)
	execs := r.discoverCallCount()

	clk.advance(2 * time.Hour)
	mustRun(t, target, cfg)
	if got := r.discoverCallCount(); got != execs+3 {
		t.Fatalf("expired records must re-execute: %d -> %d", execs, got)
	}
}

// TestRunCacheKeyDiffersPerToolAndVersion verifies the tool identity is part
// of the key, so different tools or versions never share records.
func TestRunCacheKeyDiffersPerToolAndVersion(t *testing.T) {
	target := mustDomain(t, "example.com")
	k1 := keyFor(t, target, "subfinder", "v2.6.3")
	k2 := keyFor(t, target, "subfinder", "v2.6.4")
	k3 := keyFor(t, target, "assetfinder", "")
	if k1 == k2 || k1 == k3 {
		t.Fatal("tool identity must differentiate cache keys")
	}
}

// TestRunCacheKeyIncludesMode verifies the result-relevant configuration
// (passive mode) is part of the key.
func TestRunCacheKeyIncludesMode(t *testing.T) {
	target := mustDomain(t, "example.com")
	src := registry["subfinder"](toolEnv{name: "subfinder"})
	k1, err := cacheKey(target, src, Detection{Version: "v2.6.3"})
	if err != nil {
		t.Fatalf("cacheKey: %v", err)
	}
	k2, err := cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    target.Identity().String(),
		Config:    map[string]string{"mode": "active"},
		Tool:      cache.ToolInfo{Name: "subfinder", Version: "v2.6.3"},
	})
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if k1 == k2 {
		t.Fatal("a different mode must produce a different key")
	}
}

// TestStoredResultDecodeRejectsForeignTarget verifies decodeStored refuses a
// payload whose target does not match the query.
func TestStoredResultDecodeRejectsForeignTarget(t *testing.T) {
	foreign, err := json.Marshal(storedResult{Source: "subfinder", Target: "domain:other.org", Hosts: []asset.Host{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decodeStored(foreign, mustDomain(t, "example.com"), "subfinder"); err == nil {
		t.Fatal("expected a mismatch error")
	}
}

// TestStoredResultDecodeRejectsOutOfDomainHost verifies decodeStored refuses
// a payload whose hosts are not contained in the queried domain: a tampered
// or legacy record can never inject foreign hosts.
func TestStoredResultDecodeRejectsOutOfDomainHost(t *testing.T) {
	target := mustDomain(t, "example.com")
	bad, err := json.Marshal(storedResult{
		Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "evil.com"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decodeStored(bad, target, "subfinder"); err == nil || !strings.Contains(err.Error(), "outside target domain") {
		t.Fatalf("want out-of-domain rejection, got %v", err)
	}

	// A subdomain and the apex itself are both contained.
	good, err := json.Marshal(storedResult{
		Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "api.example.com"}, {Name: "example.com"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decodeStored(good, target, "subfinder"); err != nil {
		t.Fatalf("contained hosts must decode, got %v", err)
	}

	// A host that normalizes INTO the target domain but is not in canonical
	// form must be rejected and never served with its raw name: NewHost
	// trims leading whitespace and trailing dots without error, so a raw
	// HasSuffix containment check on the stored string passes while the
	// stored host breaks dedup and formatting (leading-whitespace bypass).
	// Rejecting non-canonical stored hosts mirrors validateTarget's
	// canonicality requirement; runSource deletes such a record and
	// recomputes it (self-healing), never serving it with its raw name.
	for _, h := range []string{" api.example.com", "api.example.com."} {
		nonCanonical, err := json.Marshal(storedResult{
			Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
			Hosts: []asset.Host{{Name: h}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := decodeStored(nonCanonical, target, "subfinder"); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("host %q: want canonical-form rejection, got %v", h, err)
		}
	}
}

// TestStoredResultDecodeRejectsWrongSource verifies decodeStored refuses a
// payload whose Source field names a different tool than the queried source.
func TestStoredResultDecodeRejectsWrongSource(t *testing.T) {
	target := mustDomain(t, "example.com")
	payload, err := json.Marshal(storedResult{
		Source: "amass", Version: "v3.23.0", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "api.example.com"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decodeStored(payload, target, "subfinder"); err == nil || !strings.Contains(err.Error(), "does not match queried source") {
		t.Fatalf("want wrong-source rejection, got %v", err)
	}
}

// craftedRecord builds a completed cache record for the subfinder key against
// example.com with the given payload bytes and tool identity, for tamper
// tests.
func craftedRecord(t *testing.T, c *cache.FS, key cache.Key, target asset.Domain, data []byte, tool cache.ToolInfo) {
	t.Helper()
	rec := cache.Record{
		Operation: Operation,
		Target:    target.Identity().String(),
		Tool:      tool,
		Status:    cache.StatusCompleted,
		Data:      data,
	}
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("cache.Put crafted record: %v", err)
	}
}

// TestRunCacheRejectsTamperedRecordIdentity verifies a completed record whose
// RECORD-LEVEL tool identity does not match the query is rejected: never
// served as a hit, never emitted as a host, reported as failed with the
// cause. This branch faults hard (rather than self-healing like a payload
// that fails decodeStored) because a record under this key with a foreign
// tool identity cannot belong to this tool at all — the key itself was
// computed from the tool identity, so such a record could only be tampered
// with. Defense in depth against tampered or legacy records.
func TestRunCacheRejectsTamperedRecordIdentity(t *testing.T) {
	target := mustDomain(t, "example.com")
	key := keyFor(t, target, "subfinder", "v2.6.3")

	payload, err := json.Marshal(storedResult{
		Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "api.example.com"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c := openTestCache(t)
	craftedRecord(t, c, key, target, payload, cache.ToolInfo{Name: "amass", Version: "v3.23.0"})

	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c
	execCalls := 0
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		execCalls++
		return RunResult{Stdout: []byte("api.example.com\n")}, nil
	}
	rep := mustRun(t, target, cfg)

	res := rep.Results[0]
	if res.Cached {
		t.Fatal("a tampered record must never be served as a hit")
	}
	if res.Status != OutFailed {
		t.Fatalf("subfinder status = %s, want failed", res.Status)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "tool identity") {
		t.Fatalf("subfinder error = %v, want %q", res.Err, "tool identity")
	}
	if len(res.Hosts) != 0 {
		t.Fatalf("a failed subfinder result must emit no hosts, got %v", names(res.Hosts))
	}
	if execCalls != 0 {
		t.Fatalf("a rejected record must not execute the tool, got %d subfinder executions", execCalls)
	}
}

// recordingCache wraps a cache.Cache and counts Delete calls, so tests can
// prove a deletion actually happened (not just that a later Put overwrote the
// entry).
type recordingCache struct {
	cache.Cache
	mu      sync.Mutex
	deletes int
}

func (c *recordingCache) Delete(ctx context.Context, key cache.Key) error {
	c.mu.Lock()
	c.deletes++
	c.mu.Unlock()
	return c.Cache.Delete(ctx, key)
}

func (c *recordingCache) deleteCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deletes
}

// TestRunCacheTamperedRecordSelfHeals is the self-healing regression test for
// records that fail decodeStored (out-of-domain hosts, foreign payload
// source, non-canonical hosts): the first run must reject the record — never
// served as a hit, never emitted — delete it, execute the tool to recompute,
// and store the canonical completed record; later runs then serve that
// canonical record as a hit. Before the fix, the rejected record stayed a hit
// for every future run and the source failed on each of them without ever
// executing, contradicting the documented "recompute on the next run"
// behavior; this test pins the full chain reject -> delete -> execute ->
// canonical store -> hit.
func TestRunCacheTamperedRecordSelfHeals(t *testing.T) {
	target := mustDomain(t, "example.com")
	key := keyFor(t, target, "subfinder", "v2.6.3")

	marshal := func(sr storedResult) []byte {
		t.Helper()
		b, err := json.Marshal(sr)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	cases := map[string]struct {
		payload storedResult
		wantErr string
	}{
		"out-of-domain host": {
			payload: storedResult{Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
				Hosts: []asset.Host{{Name: "evil.com"}}},
			wantErr: "outside target domain",
		},
		"payload source names another tool": {
			payload: storedResult{Source: "amass", Version: "v3.23.0", Target: target.Identity().String(),
				Hosts: []asset.Host{{Name: "api.example.com"}}},
			wantErr: "does not match queried source",
		},
		"non-canonical host": {
			payload: storedResult{Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
				Hosts: []asset.Host{{Name: " api.example.com"}}},
			wantErr: "canonical",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := &recordingCache{Cache: openTestCache(t)}
			craftedRecord(t, c.Cache.(*cache.FS), key, target, marshal(tc.payload), cache.ToolInfo{Name: "subfinder", Version: "v2.6.3"})

			execCalls := 0
			script := fullScript()
			script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
				execCalls++
				return RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
			}
			r := newFakeRunner(t, script)
			cfg := testConfig(r, newFakeLookup())
			cfg.Cache = c
			execsBefore := r.discoverCallCount()

			// Run 1: reject (no hit, no emit), delete, execute, store canonical.
			rep1 := mustRun(t, target, cfg)
			res := rep1.Results[0]
			if res.Cached {
				t.Fatal("a tampered record must never be served as a hit")
			}
			if res.Status != OutCompleted {
				t.Fatalf("subfinder status = %s, want completed (the run recomputed)", res.Status)
			}
			if res.Err == nil || !strings.Contains(res.Err.Error(), tc.wantErr) {
				t.Fatalf("subfinder error = %v, want the rejection cause %q surfaced", res.Err, tc.wantErr)
			}
			if !strings.Contains(res.Err.Error(), "discarded unusable cached result") {
				t.Fatalf("subfinder error = %v, want the discard diagnostic", res.Err)
			}
			if len(res.Hosts) != 2 || names(res.Hosts)[0] != "api.example.com" {
				t.Fatalf("run 1 hosts = %v, want the recomputed payload [api.example.com www.example.com]", names(res.Hosts))
			}
			if execCalls != 1 {
				t.Fatalf("run 1 executions = %d, want 1 (the fall-through recompute)", execCalls)
			}
			for _, h := range rep1.All() {
				if h.Name == "evil.com" {
					t.Fatalf("tampered record host %q must not be emitted", h.Name)
				}
			}
			if got := c.deleteCount(); got != 1 {
				t.Fatalf("cache deletes = %d, want 1 (the stale record must be deleted, not just overwritten)", got)
			}
			// The stored record is now the canonical recomputed one: it
			// decodes cleanly and the tampered payload is gone.
			out := c.Get(context.Background(), key)
			if !out.IsHit() || out.Record.Status != cache.StatusCompleted {
				t.Fatalf("after healing, state = %s status = %q, want hit/completed", out.State, out.Record.Status)
			}
			if _, err := decodeStored(out.Record.Data, target, "subfinder"); err != nil {
				t.Fatalf("stored record must be canonical after healing, decode: %v", err)
			}
			if bytes.Contains(out.Record.Data, []byte("evil.com")) {
				t.Fatal("the tampered payload is still stored; deletion did not happen")
			}

			// Run 2: the canonical record is served as a hit; no execution.
			rep2 := mustRun(t, target, cfg)
			res2 := rep2.Results[0]
			if !res2.Cached {
				t.Fatal("run 2 must serve the healed record as a hit")
			}
			if res2.Status != OutCompleted || len(res2.Hosts) != 2 {
				t.Fatalf("run 2 = %s with %d hosts, want completed with the canonical hosts", res2.Status, len(res2.Hosts))
			}
			if execCalls != 1 || r.discoverCallCount() != execsBefore+3 {
				t.Fatalf("run 2 must not execute: subfinder executions = %d, discovery calls %d -> %d (want %d: each source exactly once)",
					execCalls, execsBefore, r.discoverCallCount(), execsBefore+3)
			}

			// Run 3: still a hit; the healed record is stable.
			rep3 := mustRun(t, target, cfg)
			if !rep3.Results[0].Cached {
				t.Fatal("run 3 must still serve the healed record as a hit")
			}
			if execCalls != 1 {
				t.Fatalf("run 3 must not execute: executions = %d, want 1 total", execCalls)
			}
		})
	}
}

// TestRunCachePutFailureSurfacesError verifies a completed run whose cache
// write fails reports the error on the result: the user must learn the
// results were not cached (a completed outcome is not exempt from errors).
func TestRunCachePutFailureSurfacesError(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	fc := &fakeCache{putErr: errors.New("disk full")}
	cfg.Cache = fc
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	res := rep.Results[0]
	if res.Status != OutCompleted {
		t.Fatalf("subfinder status = %s, want completed", res.Status)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "cache put") {
		t.Fatalf("completed result must carry the cache put error, got %v", res.Err)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("hosts = %v, want the executed payload retained", names(res.Hosts))
	}
	// Every source attempted (and failed) its write; the loss of the error
	// would have made the warning invisible.
	if got := fc.putCount(); got != 3 {
		t.Fatalf("cache puts attempted = %d, want 3", got)
	}
}

// TestRunCacheVersionChangeReexecutes verifies end-to-end that a tool version
// change between runs changes the cache key, forcing a miss and a fresh
// execution whose new payload is returned.
func TestRunCacheVersionChangeReexecutes(t *testing.T) {
	versionCalls := 0
	execCalls := 0
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		versionCalls++
		if versionCalls == 1 {
			return RunResult{Stdout: []byte("v1.0.0\n")}, nil
		}
		return RunResult{Stdout: []byte("v2.0.0\n")}, nil
	}
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		execCalls++
		if execCalls == 1 {
			return RunResult{Stdout: []byte("old.example.com\n")}, nil
		}
		return RunResult{Stdout: []byte("new.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	mustRun(t, target, cfg)
	rep2 := mustRun(t, target, cfg)

	sub := rep2.Results[0]
	if sub.Cached {
		t.Fatal("a version change must invalidate the cache key")
	}
	if len(sub.Hosts) != 1 || sub.Hosts[0].Name != "new.example.com" {
		t.Fatalf("run 2 hosts = %v, want [new.example.com] (the fresh payload)", names(sub.Hosts))
	}
	if execCalls != 2 {
		t.Fatalf("subfinder executions = %d, want 2", execCalls)
	}
	// Sources whose version did not change keep serving from cache.
	for i := 1; i < 3; i++ {
		if !rep2.Results[i].Cached {
			t.Fatalf("%s must stay cached when its version is unchanged", rep2.Results[i].Source)
		}
	}
}

// TestRunCacheUnknownVersionToKnownVersionReexecutes covers the "" vs
// "v2.6.3" transition: a WARN detection (unrecognizable version output)
// yields an empty version key; when the version flag starts working again
// the key changes and the source re-executes.
func TestRunCacheUnknownVersionToKnownVersionReexecutes(t *testing.T) {
	versionCalls := 0
	execCalls := 0
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		versionCalls++
		if versionCalls == 1 {
			return RunResult{Stdout: []byte("???\n")}, nil // no recognizable version -> WARN, version ""
		}
		return RunResult{Stdout: []byte("Current Version: v2.6.3\n")}, nil
	}
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		execCalls++
		return RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	rep1 := mustRun(t, target, cfg)
	if rep1.Results[0].Detection.Status != StatusWarn || rep1.Results[0].Version != "" {
		t.Fatalf("run 1 detection = %s version %q, want warn with empty version",
			rep1.Results[0].Detection.Status, rep1.Results[0].Version)
	}
	execs := execCalls
	rep2 := mustRun(t, target, cfg)
	if rep2.Results[0].Version != "v2.6.3" {
		t.Fatalf("run 2 version = %q, want v2.6.3", rep2.Results[0].Version)
	}
	if rep2.Results[0].Cached {
		t.Fatal("the unknown-version record must not serve the known-version query")
	}
	if execCalls != execs+1 {
		t.Fatalf("run 2 must re-execute after the version transition: %d -> %d", execs, execCalls)
	}
	if len(rep2.Results[0].Hosts) != 2 {
		t.Fatalf("run 2 hosts = %v, want the executed payload", names(rep2.Results[0].Hosts))
	}
}
