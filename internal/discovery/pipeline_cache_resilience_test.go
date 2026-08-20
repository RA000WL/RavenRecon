package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// rawEntryPath derives the documented on-disk location of a key:
//
//	<dir>/entries/<aa>/<bb>/<key>.json
//
// It mirrors internal/cache's layout so tests can plant hostile filesystem
// objects (corrupt bytes, directories, FIFOs) directly at an entry path
// through the real cache's own directory.
func rawEntryPath(c *cache.FS, key cache.Key) string {
	return filepath.Join(c.Dir(), "entries", string(key)[0:2], string(key)[2:4], string(key)+".json")
}

// writeRawEntry writes raw bytes directly at a key's entry path, bypassing
// the cache's Put entirely to simulate a corrupt, tampered, or malicious
// on-disk entry.
func writeRawEntry(t *testing.T, c *cache.FS, key cache.Key, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(rawEntryPath(c, key)), 0o700); err != nil {
		t.Fatalf("mkdir shard: %v", err)
	}
	if err := os.WriteFile(rawEntryPath(c, key), content, 0o600); err != nil {
		t.Fatalf("write raw entry: %v", err)
	}
}

// TestRunCacheCorruptEntrySelfHeals verifies the corrupt-record path end to
// end: garbage bytes at the key's entry path make Get surface StateCorrupt,
// the run warns ("cache get"), falls through to a fresh execution, stores the
// canonical record, and the follow-up run is a hit on the recomputed record.
func TestRunCacheCorruptEntrySelfHeals(t *testing.T) {
	target := mustDomain(t, "example.com")
	c := openTestCache(t)
	key := keyFor(t, target, "subfinder", "v2.6.3")
	writeRawEntry(t, c, key, []byte("this is not json {{{"))

	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c

	rep := mustRun(t, target, cfg)
	res := rep.Results[0]
	if res.Cached {
		t.Fatal("a corrupt record must never be served as a hit")
	}
	if res.Status != OutCompleted {
		t.Fatalf("subfinder status = %s, want completed (the run executes fresh)", res.Status)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("subfinder hosts = %v, want the executed payload", names(res.Hosts))
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "cache get") {
		t.Fatalf("a corrupt record must surface a cache-get warning, got %v", res.Err)
	}

	// Follow-up run: the recomputed canonical record is a hit, warning-free.
	rep2 := mustRun(t, target, cfg)
	if !rep2.Results[0].Cached {
		t.Fatal("run 2 must hit the recomputed record")
	}
	if rep2.Results[0].Err != nil {
		t.Fatalf("a clean hit must carry no errors, got %v", rep2.Results[0].Err)
	}
}

// TestRunConcurrentCacheAccess runs 8 concurrent discovery Runs over one FS
// cache for the same target/source/detection. All runs must complete (bounded
// by mustFinish), race-free, and the final stored records must be consistent:
// the next Get on every versioned source hits and decodes cleanly. The
// never-cached assetfinder must not have been stored by any run.
func TestRunConcurrentCacheAccess(t *testing.T) {
	target := mustDomain(t, "example.com")
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c

	const n = 8
	reps := make([]Report, n)
	errs := make([]error, n)
	mustFinish(t, 60*time.Second, "8 concurrent cached runs", func() {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				reps[i], errs[i] = Run(context.Background(), target, cfg)
			}(i)
		}
		wg.Wait()
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent run %d: %v", i, err)
		}
	}
	for i := range reps {
		if len(reps[i].Results) != 3 {
			t.Fatalf("run %d results = %d, want 3", i, len(reps[i].Results))
		}
	}

	// Final records are complete, consistent, and canonical.
	for _, tc := range []struct {
		src string
		ver string
	}{
		{"subfinder", "v2.6.3"},
		{"amass", "v3.23.0"},
	} {
		k := keyFor(t, target, tc.src, tc.ver)
		out := c.Get(context.Background(), k)
		if !out.IsHit() {
			t.Fatalf("%s final record state = %s, want hit", tc.src, out.State)
		}
		if _, err := decodeStored(out.Record.Data, target, tc.src); err != nil {
			t.Fatalf("%s final record must decode cleanly: %v", tc.src, err)
		}
	}
	if o := c.Get(context.Background(), keyFor(t, target, "assetfinder", "")); o.State != cache.StateMiss {
		t.Fatalf("unknown-version assetfinder must never be cached, got state %s", o.State)
	}
}

// TestRunCacheConcurrentCorruptionCompletes interleaves a goroutine that
// repeatedly corrupts the subfinder entry path with concurrent discovery
// runs. Every run must still complete within the bound — a corrupt entry must
// never block or fail a run — and after the corruptor stops, the entry
// deterministically heals to a canonical hit.
func TestRunCacheConcurrentCorruptionCompletes(t *testing.T) {
	target := mustDomain(t, "example.com")
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	c := openTestCache(t)
	cfg.Cache = c
	key := keyFor(t, target, "subfinder", "v2.6.3")
	if err := os.MkdirAll(filepath.Dir(rawEntryPath(c, key)), 0o700); err != nil {
		t.Fatalf("mkdir shard: %v", err)
	}

	corruptorDone := make(chan struct{})
	corruptErr := make(chan error, 1)
	go func() {
		defer close(corruptorDone)
		for i := 0; i < 25; i++ {
			if err := os.WriteFile(rawEntryPath(c, key), []byte("corrupt {{{"), 0o600); err != nil {
				corruptErr <- err
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	const n = 6
	errs := make([]error, n)
	mustFinish(t, 60*time.Second, "6 runs with interleaved corruption", func() {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = Run(context.Background(), target, cfg)
			}(i)
		}
		wg.Wait()
	})
	<-corruptorDone
	select {
	case err := <-corruptErr:
		t.Fatalf("corruptor failed: %v", err)
	default:
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("run %d during interleaved corruption: %v", i, err)
		}
	}

	// With the corruptor stopped, a final run deterministically heals: a hit
	// or a corrupt entry (self-healed and recomputed within the run) both end
	// with a canonical stored record.
	mustRun(t, target, cfg)
	out := c.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("final subfinder record state = %s, want hit", out.State)
	}
	if _, err := decodeStored(out.Record.Data, target, "subfinder"); err != nil {
		t.Fatalf("final subfinder record must decode cleanly: %v", err)
	}
}

// TestRunCacheRepeatedInvalidFreshOutput pins the repeatedly-invalid case: a
// source whose fresh output ALWAYS decodes as invalid (a deterministic
// out-of-domain host, with a KNOWN version so it is keyed and stored). With
// an invalid completed record seeded, every one of three consecutive runs
// must return the executed results — never OutFailed on cache grounds, never
// served as a hit — surface the discard diagnostic each run, reject and
// delete the invalid stored record, and leave exactly one entry file (no
// unbounded growth).
func TestRunCacheRepeatedInvalidFreshOutput(t *testing.T) {
	target := mustDomain(t, "example.com")
	c := &recordingCache{Cache: openTestCache(t)}
	key := keyFor(t, target, "subfinder", "v2.6.3")
	seed, err := json.Marshal(storedResult{
		Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "evil.com"}},
	})
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	craftedRecord(t, c.Cache.(*cache.FS), key, target, seed, cache.ToolInfo{Name: "subfinder", Version: "v2.6.3"})

	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		// A syntactically valid host that decodeStored rejects as outside the
		// target domain.
		return RunResult{Stdout: []byte("evil.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c

	for i := 1; i <= 3; i++ {
		rep := mustRun(t, target, cfg)
		res := rep.Results[0]
		if res.Cached {
			t.Fatalf("run %d: an invalid record must never be served as a hit", i)
		}
		if res.Status != OutCompleted {
			t.Fatalf("run %d: status = %s, want completed (never OutFailed on cache grounds)", i, res.Status)
		}
		if len(res.Hosts) != 1 || res.Hosts[0].Name != "evil.com" {
			t.Fatalf("run %d: hosts = %v, want the executed payload", i, names(res.Hosts))
		}
		if res.Err == nil || !strings.Contains(res.Err.Error(), "discarded unusable cached result") {
			t.Fatalf("run %d: err = %v, want the discard diagnostic", i, res.Err)
		}
	}
	if got := c.deleteCount(); got != 3 {
		t.Fatalf("deletes = %d, want 3 (every run rejects and deletes the invalid stored record)", got)
	}
	if got := c.putCountFor("subfinder"); got != 3 {
		t.Fatalf("subfinder puts = %d, want 3 (each run stores its fresh output)", got)
	}
	files, err := os.ReadDir(filepath.Dir(rawEntryPath(c.Cache.(*cache.FS), key)))
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	if len(files) != 1 {
		for _, f := range files {
			t.Logf("shard file: %s", f.Name())
		}
		t.Fatalf("shard must hold exactly one entry file (no unbounded growth), got %d", len(files))
	}
}

// TestRunCancellationDuringSelfHeal cancels deterministically in the middle
// of the self-healing path: a tampered completed record is present, Get
// serves it as a hit, decodeStored rejects it, and the Delete succeeds before
// the fall-through execution blocks on ctx.Done. Cancelling then must return
// promptly (no hang, no panic) with the discard diagnostic and a cancelled
// outcome; a follow-up run heals the entry to a canonical hit.
func TestRunCancellationDuringSelfHeal(t *testing.T) {
	target := mustDomain(t, "example.com")
	key := keyFor(t, target, "subfinder", "v2.6.3")
	payload, err := json.Marshal(storedResult{
		Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(),
		Hosts: []asset.Host{{Name: "evil.com"}},
	})
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	c := &recordingCache{Cache: openTestCache(t)}
	craftedRecord(t, c.Cache.(*cache.FS), key, target, payload, cache.ToolInfo{Name: "subfinder", Version: "v2.6.3"})

	// Deterministic sequencing: the fake runner blocks Discover on ctx.Done
	// and closes blockStarted on entry, so cancelling after blockStarted is
	// observably "during the self-heal phase" (the tampered record was
	// already deleted, the healing execution is in flight).
	r := newFakeRunner(t, fullScript())
	r.blockKeys = map[string]bool{"subfinder -d example.com -silent": true}
	r.blockStarted = make(chan struct{})
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c

	ctx, cancel := context.WithCancel(context.Background())
	var res SourceResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		src := registry["subfinder"](cfg.env("subfinder"))
		det := Detection{Source: "subfinder", Status: StatusOK, Version: "v2.6.3", Capable: true}
		res, _, _ = runSource(ctx, target, src, det, cfg)
	}()
	<-r.blockStarted
	cancel()
	mustFinish(t, 30*time.Second, "runSource cancelled during self-heal", func() { <-done })

	if res.Status != OutCancelled {
		t.Fatalf("status = %s, want cancelled", res.Status)
	}
	if res.Cached {
		t.Fatal("the tampered record must never be served as a hit")
	}
	// The fall-through execution's cancellation error replaces the earlier
	// joined diagnostics (runSource assigns res.Err = err on execution
	// errors); the delete count proves the self-heal branch ran and removed
	// the tampered record before the cancellation landed.
	if res.Err == nil || !strings.Contains(res.Err.Error(), "context canceled") && !strings.Contains(res.Err.Error(), "context cancelled") {
		t.Fatalf("err = %v, want the cancellation cause", res.Err)
	}
	if got := c.deleteCount(); got != 1 {
		t.Fatalf("deletes = %d, want 1 (the tampered record was deleted before the cancellation)", got)
	}

	// Follow-up run heals: the cancelled record is never a hit, the source
	// re-executes and stores a canonical completed record.
	r2 := newFakeRunner(t, fullScript())
	cfg2 := testConfig(r2, newFakeLookup())
	cfg2.Cache = c
	rep2 := mustRun(t, target, cfg2)
	if rep2.Results[0].Cached || rep2.Results[0].Status != OutCompleted {
		t.Fatalf("follow-up run = cached %t status %s, want a fresh completed execution", rep2.Results[0].Cached, rep2.Results[0].Status)
	}
	out := c.Get(context.Background(), key)
	if !out.IsHit() || out.Record.Status != cache.StatusCompleted {
		t.Fatalf("after healing: state = %s status = %q, want hit/completed", out.State, out.Record.Status)
	}
	if _, err := decodeStored(out.Record.Data, target, "subfinder"); err != nil {
		t.Fatalf("healed record must decode cleanly: %v", err)
	}
	rep3 := mustRun(t, target, cfg2)
	if !rep3.Results[0].Cached {
		t.Fatal("the healed record must be served as a hit")
	}
}

// TestRunDirectoryAtEntryPathCompletes plants a DIRECTORY at the entry path:
// the run must return results within the bound (never blocked), surface a
// cache-get warning, and the Get's self-healing must remove the directory so
// the second run completes as a hit.
func TestRunDirectoryAtEntryPathCompletes(t *testing.T) {
	target := mustDomain(t, "example.com")
	c := openTestCache(t)
	key := keyFor(t, target, "subfinder", "v2.6.3")
	path := rawEntryPath(c, key)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir at entry path: %v", err)
	}

	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c

	var rep Report
	var runErr error
	mustFinish(t, 30*time.Second, "run with a directory at the entry path", func() {
		rep, runErr = Run(context.Background(), target, cfg)
	})
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	res := rep.Results[0]
	if res.Cached || res.Status != OutCompleted {
		t.Fatalf("subfinder = cached %t status %s, want a fresh completed execution", res.Cached, res.Status)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("subfinder hosts = %v, want the executed payload", names(res.Hosts))
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "cache get") {
		t.Fatalf("a problematic filesystem object must surface a cache-get warning, got %v", res.Err)
	}
	// The Get's self-healing removed the directory and this run's storage
	// replaced it with the canonical regular record file at the same path.
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("entry path must hold the stored regular record after self-heal (lstat err %v, mode %v)", err, fi.Mode())
	}
	// Second run completes as a hit.
	rep2 := mustRun(t, target, cfg)
	if !rep2.Results[0].Cached {
		t.Fatal("run 2 must hit the recomputed record")
	}
	if rep2.Results[0].Err != nil {
		t.Fatalf("a clean hit must carry no errors, got %v", rep2.Results[0].Err)
	}
}

// TestRunUnknownVersionSourceNeverCached pins the unknown-version policy end
// to end: two consecutive runs of an unknown-version source (WARN detection,
// Version == "") BOTH execute fresh and store nothing — no Put, no Delete, no
// Get — while a known-version source on the same cache behaves normally.
func TestRunUnknownVersionSourceNeverCached(t *testing.T) {
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("???\n")}, nil // no recognizable version -> WARN, version ""
	}
	subExecs := 0
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		subExecs++
		return RunResult{Stdout: []byte("api.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	c := &recordingCache{Cache: openTestCache(t)}
	cfg.Cache = c
	target := mustDomain(t, "example.com")

	for i := 1; i <= 2; i++ {
		rep := mustRun(t, target, cfg)
		if rep.Results[0].Cached {
			t.Fatalf("run %d: an unknown-version source must never be served from cache", i)
		}
		if rep.Results[0].Detection.Status != StatusWarn || rep.Results[0].Version != "" {
			t.Fatalf("run %d: detection = %s version %q, want warn with empty version",
				i, rep.Results[0].Detection.Status, rep.Results[0].Version)
		}
	}
	if subExecs != 2 {
		t.Fatalf("both unknown-version runs must execute fresh: %d subfinder executions, want 2", subExecs)
	}
	if got := c.putCountFor("subfinder"); got != 0 {
		t.Fatalf("an unknown-version source must store nothing, got %d subfinder puts", got)
	}
	if got := c.putCountFor("assetfinder"); got != 0 {
		t.Fatalf("the versionless assetfinder must store nothing, got %d puts", got)
	}
	if got := c.deleteCount(); got != 0 {
		t.Fatalf("unknown-version runs must never delete, got %d deletes", got)
	}
	// The known-version source on the same cache cached normally: only the
	// first run stored, and later runs hit.
	if got := c.putCountFor("amass"); got != 1 {
		t.Fatalf("amass puts = %d, want 1 (only the first run stores)", got)
	}
	rep3 := mustRun(t, target, cfg)
	if !rep3.Results[2].Cached {
		t.Fatal("the known-version amass must be served from cache")
	}
	if subExecs != 3 {
		t.Fatalf("the unknown-version source must execute on every run: %d executions, want 3", subExecs)
	}
	if got := c.putCountFor("amass"); got != 1 {
		t.Fatalf("a cache-hit run must not store again, got %d amass puts", got)
	}
}

// TestRunUnknownVersionDoesNotTouchKnownRecord verifies the two identities
// never interact: a known-version record exists; a run with Version "" must
// execute fresh, store nothing, and leave the known-version record untouched
// (not served, not deleted, content unchanged); a later known-version run
// still hits it.
func TestRunUnknownVersionDoesNotTouchKnownRecord(t *testing.T) {
	target := mustDomain(t, "example.com")

	// Phase 1: known version seeds the record.
	r1 := newFakeRunner(t, fullScript())
	cfg1 := testConfig(r1, newFakeLookup())
	c := &recordingCache{Cache: openTestCache(t)}
	cfg1.Cache = c
	mustRun(t, target, cfg1)
	keyKnown := keyFor(t, target, "subfinder", "v2.6.3")
	out := c.Cache.Get(context.Background(), keyKnown)
	if !out.IsHit() {
		t.Fatalf("seeded known-version record state = %s, want hit", out.State)
	}

	// Phase 2: the version flag is broken -> unknown-version run.
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("???\n")}, nil
	}
	subExecs := 0
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		subExecs++
		return RunResult{Stdout: []byte("x.example.com\n")}, nil
	}
	r2 := newFakeRunner(t, script)
	cfg2 := testConfig(r2, newFakeLookup())
	cfg2.Cache = c
	rep2 := mustRun(t, target, cfg2)
	res := rep2.Results[0]
	if res.Cached {
		t.Fatal("an unknown-version run must not serve the known-version record")
	}
	if subExecs != 1 {
		t.Fatalf("the unknown-version run must execute fresh: %d executions, want 1", subExecs)
	}
	if got := c.putCountFor("subfinder"); got != 1 {
		t.Fatalf("the unknown-version run must store nothing (only the phase-1 seed): %d subfinder puts", got)
	}
	if got := c.deleteCount(); got != 0 {
		t.Fatalf("the unknown-version run must delete nothing, got %d deletes", got)
	}
	// The known-version record survived untouched and still decodes.
	out2 := c.Cache.Get(context.Background(), keyKnown)
	if !out2.IsHit() {
		t.Fatalf("known-version record must survive the unknown-version run, got %s", out2.State)
	}
	if !bytes.Contains(out2.Record.Data, []byte("api.example.com")) {
		t.Fatalf("known-version record content changed: %s", out2.Record.Data)
	}
	if _, err := decodeStored(out2.Record.Data, target, "subfinder"); err != nil {
		t.Fatalf("known-version record must still decode cleanly: %v", err)
	}

	// Phase 3: version detection works again -> the surviving record hits.
	r3 := newFakeRunner(t, fullScript())
	cfg3 := testConfig(r3, newFakeLookup())
	cfg3.Cache = c
	rep3 := mustRun(t, target, cfg3)
	if !rep3.Results[0].Cached {
		t.Fatal("a later known-version run must hit the surviving record")
	}
	if got := r3.discoverCallCount(); got != 1 {
		t.Fatalf("known-version run must re-execute only the never-cached assetfinder, got %d executions", got)
	}
}
