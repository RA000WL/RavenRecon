package adapt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/importer"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// ingestFixtures writes the synthetic import corpus into a fresh temp dir:
// a plain URL list and an httpx NDJSON export (synthetic values only).
func ingestFixtures(t *testing.T) (dir, urlsPath, httpxPath string) {
	t.Helper()
	dir = t.TempDir()
	urlsPath = filepath.Join(dir, "urls.txt")
	httpxPath = filepath.Join(dir, "httpx.json")
	content := strings.Join([]string{
		"http://api.example.com/login",
		"https://api.example.com/admin",
		"http://www.example.com/",
	}, "\n") + "\n"
	if err := os.WriteFile(urlsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write urls.txt: %v", err)
	}
	httpx := strings.Join([]string{
		`{"url":"https://www.example.com/","status_code":200,"title":"Example","tech":["nginx"]}`,
		`{"url":"https://api.example.com/v2/","status_code":200,"title":"API"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(httpxPath, []byte(httpx), 0o600); err != nil {
		t.Fatalf("write httpx.json: %v", err)
	}
	return dir, urlsPath, httpxPath
}

// ingestCountingCache wraps cache.Cache with hit/put/delete counters and
// captures every Put record so tests can pin store-time decisions (e.g. a
// truncated import must store StatusIncomplete). Put runs concurrently
// across file jobs, so the captured slice is mutex-guarded.
type ingestCountingCache struct {
	inner            cache.Cache
	gets, hits, puts atomic.Int64
	deletes          atomic.Int64
	incompleteGets   atomic.Int64

	mu         sync.Mutex
	putRecords []cache.Record
}

func (c *ingestCountingCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	c.gets.Add(1)
	out := c.inner.Get(ctx, key)
	if out.IsHit() {
		c.hits.Add(1)
	}
	if out.State == cache.StateIncomplete {
		// A well-formed record existed for the key but was refused for its
		// status — proof the StatusIncomplete-refusal path fired (not a
		// miss on an absent key).
		c.incompleteGets.Add(1)
	}
	return out
}

func (c *ingestCountingCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	c.puts.Add(1)
	c.mu.Lock()
	c.putRecords = append(c.putRecords, record)
	c.mu.Unlock()
	return c.inner.Put(ctx, key, record)
}

// storedRecords snapshots the captured Put records.
func (c *ingestCountingCache) storedRecords() []cache.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cache.Record(nil), c.putRecords...)
}

func (c *ingestCountingCache) Delete(ctx context.Context, key cache.Key) error {
	c.deletes.Add(1)
	return c.inner.Delete(ctx, key)
}

func (c *ingestCountingCache) Clear(ctx context.Context) error { return c.inner.Clear(ctx) }

func ingestInput(t *testing.T, clk runtime.Clock, c cache.Cache, paths string, extra map[string]string) pipeline.StageInput {
	t.Helper()
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	cfg := map[string]string{"paths": paths}
	for k, v := range extra {
		cfg[k] = v
	}
	return pipeline.StageInput{
		Target: target,
		Bounds: pipeline.DefaultStageConfig(),
		Config: cfg,
		Clock:  clk,
		Cache:  c,
	}
}

// TestIngestStageEndToEnd runs the composed stage over the synthetic corpus
// and pins the canonical assets, the provenance sidecar, and the honest
// counters.
func TestIngestStageEndToEnd(t *testing.T) {
	dir, urlsPath, httpxPath := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	stage := NewIngestStage()

	res, err := stage.Run(context.Background(), ingestInput(t, clk, nil,
		strings.Join([]string{urlsPath, httpxPath}, "\n"), nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (err=%v flags=%v)", res.Outcome, res.Err, res.StickyFlags)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("unexpected truncation: %v %v", res.Truncated, res.StickyFlags)
	}

	// Corpus additions: every imported URL is in-domain; the two files
	// share no URLs so all five survive. The plain/JSON URL families
	// produce URL assets only — no separate Host entries — and Domains stay
	// nil here.
	if len(res.Additions.URLs) < 5 {
		t.Fatalf("additions too small: hosts=%d urls=%d", len(res.Additions.Hosts), len(res.Additions.URLs))
	}
	for _, h := range res.Additions.Hosts {
		if !pipeline.InDomain(inTarget(t), h) {
			t.Fatalf("out-of-domain host %q reached the corpus", h.Name)
		}
	}

	// Results channels: httpx carries IPs only when the fixture has them —
	// it does not, but the JS/findings channels must be empty here while
	// provenance must cover every retained asset from both files.
	if len(res.Results.JavaScript) != 0 || len(res.Results.Findings) != 0 {
		t.Fatalf("unexpected results-channel output: js=%d findings=%d",
			len(res.Results.JavaScript), len(res.Results.Findings))
	}

	// Provenance sidecar: one record per retained asset, each naming its
	// importer and file.
	if len(res.Provenance) < 5 {
		t.Fatalf("provenance records = %d, want >= 5", len(res.Provenance))
	}
	importers := map[string]bool{}
	files := map[string]bool{}
	for _, rec := range res.Provenance {
		importers[rec.Importer] = true
		files[rec.Filename] = true
		if rec.Identity == "" {
			t.Fatalf("provenance record without identity: %+v", rec)
		}
		if !rec.ImportTime.Equal(fixedTime) {
			t.Fatalf("provenance ImportTime = %s, want injected clock %s", rec.ImportTime, fixedTime)
		}
	}
	if !importers["plain-urls"] || !importers["json-httpx"] {
		t.Fatalf("expected both importers in sidecar, got %v", importers)
	}
	if !files["urls.txt"] || !files["httpx.json"] {
		t.Fatalf("expected both filenames in sidecar, got %v", files)
	}
	if res.ItemsProcessed < 5 || res.ItemsFailed != 0 {
		t.Fatalf("counters processed=%d failed=%d, want processed>=5 failed=0",
			res.ItemsProcessed, res.ItemsFailed)

	}
	_ = dir
}

func inTarget(t *testing.T) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("domain: %v", err)
	}
	return d
}

// TestIngestStageCacheHitWithoutReparse proves the warm path: the same files
// through the same cache produce identical assets, every lookup hits, nothing
// is re-stored — and (the airtight proof) a counting importer inside a custom
// registry executes exactly once across both runs.
func TestIngestStageCacheHitWithoutReparse(t *testing.T) {
	_, urlsPath, httpxPath := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	cacheDir := t.TempDir()
	fsCache, err := cache.Open(cacheDir, cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cc := &ingestCountingCache{inner: fsCache}
	stage := NewIngestStage()
	in := ingestInput(t, clk, cc, strings.Join([]string{urlsPath, httpxPath}, "\n"), nil)

	first, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("first outcome = %q", first.Outcome)
	}
	putsAfterCold := cc.puts.Load()
	if putsAfterCold < 2 {
		t.Fatalf("cold run stored %d records, want >= 2", putsAfterCold)
	}
	// Store-time honesty, non-truncated direction: a clean engine
	// invocation stores completed (status is incomplete exactly when
	// stats.Truncated).
	for i, rec := range cc.storedRecords() {
		if rec.Status != cache.StatusCompleted {
			t.Fatalf("cold put[%d] status = %q, want completed for an untruncated import", i, rec.Status)
		}
	}

	second, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := cc.hits.Load(); got < 2 {
		t.Fatalf("warm run had %d cache hits, want >= 2", got)
	}
	if got := cc.puts.Load(); got != putsAfterCold {
		t.Fatalf("warm run stored %d additional records (puts=%d), want none — a hit must not re-store", got-putsAfterCold, got)
	}
	// Identical assets served from cache: same identities, same order.
	if fmt.Sprint(identities(first)) != fmt.Sprint(identities(second)) {
		t.Fatalf("warm-run assets differ from cold run")
	}
	// The sidecar survives the warm path byte-for-byte (attribution input
	// must not degrade when served from cache).
	if fmt.Sprint(provenanceRows(first)) != fmt.Sprint(provenanceRows(second)) {
		t.Fatalf("warm-run provenance differs from cold run")
	}
	if second.Outcome != pipeline.OutcomeCompleted || second.ItemsProcessed != first.ItemsProcessed {
		t.Fatalf("warm outcome/counters differ: %q %d vs %q %d",
			second.Outcome, second.ItemsProcessed, first.Outcome, first.ItemsProcessed)
	}
}

// TestIngestStageImportCounterProvesNoReparse composes a registry whose fake
// importer counts executions: two runs over an unchanged file must execute
// the engine exactly once.
func TestIngestStageImportCounterProvesNoReparse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example.com\nb.example.com\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}

	reg := importer.NewRegistry()
	counter := &countingImporter{imp: importer.NewPlainDomainsImporter()}
	if err := reg.Register(counter); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg.Seal()
	stage := &ingestStage{registry: reg}

	fsCache, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	in := ingestInput(t, clk, fsCache, path, nil)
	for i := 0; i < 2; i++ {
		res, err := stage.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("run %d outcome = %q", i+1, res.Outcome)
		}
	}
	if got := counter.imports.Load(); got != 1 {
		t.Fatalf("importer executed %d times across two runs, want exactly 1 (cache hit must not re-parse)", got)
	}
}

// TestIngestStageCorruptedCacheSelfHeals plants a corrupt entry under the
// content-hash key: the next run must delete it, re-execute fresh, and still
// serve the full result set.
func TestIngestStageCorruptedCacheSelfHeals(t *testing.T) {
	_, urlsPath, _ := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	cacheDir := t.TempDir()
	fsCache, err := cache.Open(cacheDir, cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	stage := NewIngestStage()
	in := ingestInput(t, clk, fsCache, urlsPath, nil)

	cold, err := stage.Run(context.Background(), in)
	if err != nil || cold.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("cold run: %q %v", cold.Outcome, err)
	}

	// Corrupt every cached entry on disk (garbage bytes, valid location).
	entries := filepath.Join(cacheDir, "entries")
	corrupted := 0
	err = filepath.Walk(entries, func(p string, d os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if d.Mode().IsRegular() && strings.HasSuffix(p, ".json") {
			if werr := os.WriteFile(p, []byte("{corrupted"), 0o600); werr != nil {
				return werr
			}
			corrupted++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("corrupt entries: %v", err)
	}
	if corrupted == 0 {
		t.Fatalf("no cache entries found to corrupt")
	}

	warm, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("warm run after corruption: %v", err)
	}
	if warm.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("self-healed outcome = %q", warm.Outcome)
	}
	if fmt.Sprint(identities(cold)) != fmt.Sprint(identities(warm)) {
		t.Fatalf("self-healed assets differ from cold run")
	}
}

// TestIngestStageTamperedURLSelfHeals plants a stored record whose URL is
// parseable but no longer canonical (uppercased host): validate must refuse
// it, delete it, and re-execute fresh so the served assets match a cold run.
func TestIngestStageTamperedURLSelfHeals(t *testing.T) {
	_, urlsPath, _ := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	fsCache, err := cache.Open(t.TempDir(), cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cc := &ingestCountingCache{inner: fsCache}
	stage := NewIngestStage()
	in := ingestInput(t, clk, cc, urlsPath, nil)

	cold, err := stage.Run(context.Background(), in)
	if err != nil || cold.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("cold run: %q %v", cold.Outcome, err)
	}

	// Tamper the captured payload: uppercase one stored host — still
	// parses, but re-canonicalization lowers it, so the stored form is not
	// its own canonical form.
	records := cc.storedRecords()
	if len(records) != 1 {
		t.Fatalf("cold run stored %d records, want 1", len(records))
	}
	var payload map[string]any
	if err := json.Unmarshal(records[0].Data, &payload); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	urls, ok := payload["urls"].([]any)
	if !ok || len(urls) == 0 {
		t.Fatalf("stored payload carries no urls: %v", payload)
	}
	u0, ok := urls[0].(map[string]any)
	if !ok {
		t.Fatalf("stored url 0 has unexpected shape: %v", urls[0])
	}
	host, _ := u0["hostport"].(string)
	u0["hostport"] = strings.ToUpper(host)
	tampered, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}

	served := &ingestStaticCache{rec: &cache.Record{
		Operation: records[0].Operation,
		Target:    records[0].Target,
		Tool:      records[0].Tool,
		Status:    cache.StatusCompleted,
		Data:      tampered,
	}}
	warm, err := stage.Run(context.Background(), ingestInput(t, clk, served, urlsPath, nil))
	if err != nil {
		t.Fatalf("warm run over tampered record: %v", err)
	}
	if warm.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("self-healed outcome = %q", warm.Outcome)
	}
	if got := served.deletes.Load(); got != 1 {
		t.Fatalf("tampered record deleted %d times, want exactly 1 (refuse-and-heal)", got)
	}
	// A fresh execution always ends in a store, so puts on the serving
	// fake prove the file was re-parsed rather than served tampered.
	if got := served.puts.Load(); got < 1 {
		t.Fatalf("fresh executions after refusal = %d, want >= 1", got)
	}
	if fmt.Sprint(identities(cold)) != fmt.Sprint(identities(warm)) {
		t.Fatalf("self-healed assets differ from cold run")
	}
}

// TestIngestFoldPreservesNonTruncationStickyFlags pins the fold contract:
// engine sticky flags survive even when nothing truncated — the fold must
// never swallow a future non-truncation flag.
func TestIngestFoldPreservesNonTruncationStickyFlags(t *testing.T) {
	in := pipeline.StageInput{Target: inTarget(t)}
	outcomes := []ingestFileOutcome{{
		status: ingestCompleted,
		stats: importer.ImportStats{
			ItemsProcessed: 3,
			StickyFlags:    map[string]bool{"future_engine_flag": true},
		},
	}}
	res, err := foldIngestOutcomes(in, []string{"clean.txt"}, outcomes)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if !res.StickyFlags["future_engine_flag"] {
		t.Fatalf("non-truncation sticky flag dropped by fold: %v", res.StickyFlags)
	}
	if res.Truncated || res.StickyFlags[ingestTruncatedFlag] {
		t.Fatalf("clean fold flagged truncation: %v %v", res.Truncated, res.StickyFlags)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed", res.Outcome)
	}
}

// TestIngestStageCancellationMidImport uses a blocking importer that returns
// partial stats plus the context error once the context fires: the stage must
// report cancelled honestly.
func TestIngestStageCancellationMidImport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example.com\nb.example.com\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}

	reg := importer.NewRegistry()
	blocker := &blockingImporter{imp: importer.NewPlainDomainsImporter()}
	if err := reg.Register(blocker); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg.Seal()
	stage := &ingestStage{registry: reg}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res, err := stage.Run(ctx, ingestInput(t, clk, nil, path, nil))
	if err != nil {
		t.Fatalf("Run returned error on cancellation: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome = %q, want cancelled", res.Outcome)
	}
}

// --- NEW-108: the ingest never-error invariant on the cancellation path ---

// TestIngestStageCancelledNilRunErrorWithCacheDiagnostics pins the stage's
// never-error invariant end to end: cancelling mid-import with a warm-but-
// corrupt cache entry present must report Outcome cancelled with a nil Go
// error return, and the attached Err must be the pure context signal — no
// best-effort self-heal cache-delete diagnostic may leak into it (the
// self-heal path is diagnostic-only by design, and skipped outright once
// the context has fired).
func TestIngestStageCancelledNilRunErrorWithCacheDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example.com\nb.example.com\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}
	corrupt := &cache.Record{Data: []byte("{not json")}
	c := &ingestStaticCache{
		rec:       corrupt,
		deleteErr: errors.New("cache delete diagnostic: simulated backend failure"),
	}
	reg := importer.NewRegistry()
	blocker := &blockingImporter{imp: importer.NewPlainDomainsImporter()}
	if err := reg.Register(blocker); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg.Seal()
	stage := &ingestStage{registry: reg}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res, err := stage.Run(ctx, ingestInput(t, clk, c, path, nil))
	if err != nil {
		t.Fatalf("Run returned error on cancellation: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome = %q (err=%v flags=%v), want cancelled", res.Outcome, res.Err, res.StickyFlags)
	}
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("res.Err = %v, want the pure context cancellation signal", res.Err)
	}
	if strings.Contains(res.Err.Error(), "delete") || strings.Contains(res.Err.Error(), "simulated backend failure") {
		t.Fatalf("res.Err = %v, want no cache-delete diagnostic leaked into the cancelled result", res.Err)
	}
}

// TestImportOneCancelledSkipsSelfHealDelete pins the importOne half of the
// invariant deterministically: on an already-fired context the self-heal
// delete of a semantically-wrong cached record is SKIPPED (deletes == 0),
// the fresh execution it would enable can never run, and the outcome is
// honestly cancelled — never failed by anything on this path.
func TestImportOneCancelledSkipsSelfHealDelete(t *testing.T) {
	_, urlsPath, _ := ingestFixtures(t)
	s := NewIngestStage().(*ingestStage)
	env := importer.ImportEnv{Bounds: importer.Bounds{MaxOutput: 100000}}
	c := &ingestStaticCache{
		rec:       &cache.Record{Data: []byte("{not json")},
		deleteErr: errors.New("cache delete diagnostic: simulated backend failure"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	oc := s.importOne(ctx, env, c, urlsPath, env.Bounds)
	if got := c.deletes.Load(); got != 0 {
		t.Fatalf("self-heal deletes on cancelled context = %d, want 0 (skipped outright)", got)
	}
	if oc.status != ingestCancelled {
		t.Fatalf("status = %d, want cancelled", oc.status)
	}
	if oc.err != nil && !errors.Is(oc.err, context.Canceled) {
		t.Fatalf("err = %v, want the context cancellation", oc.err)
	}
}

// TestImportOneLiveDeleteFailureStaysDiagnostic pins the other half: with a
// LIVE context the self-heal delete runs exactly once, and even a failing
// delete stays a swallowed diagnostic — the fresh execution proceeds and
// completes; nothing surfaces into the outcome.
func TestImportOneLiveDeleteFailureStaysDiagnostic(t *testing.T) {
	_, urlsPath, _ := ingestFixtures(t)
	s := NewIngestStage().(*ingestStage)
	env := importer.ImportEnv{Bounds: importer.Bounds{MaxOutput: 100000}}
	c := &ingestStaticCache{
		rec:       &cache.Record{Data: []byte("{not json")},
		deleteErr: errors.New("cache delete diagnostic: simulated backend failure"),
	}

	oc := s.importOne(context.Background(), env, c, urlsPath, env.Bounds)
	if got := c.deletes.Load(); got != 1 {
		t.Fatalf("self-heal deletes = %d, want exactly 1", got)
	}
	if oc.status != ingestCompleted {
		t.Fatalf("status = %d (err=%v), want completed via the fresh execution", oc.status, oc.err)
	}
	if oc.err != nil {
		t.Fatalf("err = %v, want nil (the delete failure is diagnostic-only)", oc.err)
	}
}

// TestFoldIngestCancelledKeepsGenuineFailureDetail pins the honesty side of
// the NEW-108 invariant: when cancelled precedence wins the fold, files
// that genuinely FAILED still surface through the fold's error join —
// cancellation must not become a sink that silently drops real failures
// (the stage attaches them alongside the context error).
func TestFoldIngestCancelledKeepsGenuineFailureDetail(t *testing.T) {
	in := pipeline.StageInput{Target: inTarget(t)}
	outcomes := []ingestFileOutcome{
		{status: ingestFailed, err: errors.New("no importer claims aaa.bin")},
		{status: ingestCancelled},
	}
	res, execErr := foldIngestOutcomes(in, []string{"aaa.bin", "b.txt"}, outcomes)
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome = %q, want cancelled (precedence unchanged)", res.Outcome)
	}
	if execErr == nil || !strings.Contains(execErr.Error(), "no importer claims aaa.bin") {
		t.Fatalf("execErr = %v, want the genuinely failed file's detail preserved", execErr)
	}
}

// TestIngestStageTruncatedPartialSticky drives max_output to 2 over three
// URLs: the retained set cuts at the cap → partial + Truncated + the engine's
// own sticky flag, with honest counters, and the truncated record is stored
// incomplete so a warm run can never serve it as a hit.
func TestIngestStageTruncatedPartialSticky(t *testing.T) {
	_, urlsPath, _ := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	cacheDir := t.TempDir()
	fsCache, err := cache.Open(cacheDir, cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cc := &ingestCountingCache{inner: fsCache}
	stage := NewIngestStage()
	// ONE overrides map shared by both runs: the bounds enter
	// importer.CacheKeyForFile's config, so any difference here changes the
	// key and the warm leg would miss for the wrong reason instead of
	// exercising the StatusIncomplete-refusal path.
	overrides := map[string]string{
		"max_output":     "2",
		"max_line_bytes": "4096",
	}
	in := ingestInput(t, clk, cc, urlsPath, overrides)
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("outcome = %q, want partial", res.Outcome)
	}
	if !res.Truncated {
		t.Fatalf("truncation marker lost")
	}
	if !res.StickyFlags[ingestTruncatedFlag] {
		t.Fatalf("sticky flag %q missing: %v", ingestTruncatedFlag, res.StickyFlags)
	}
	if len(res.Additions.URLs) != 2 {
		t.Fatalf("retained urls = %d, want 2 (tail-drop at cap)", len(res.Additions.URLs))
	}

	// Store-time honesty: every record the cold run stored carries
	// StatusIncomplete exactly because stats.Truncated held.
	coldRecords := cc.storedRecords()
	if len(coldRecords) == 0 {
		t.Fatalf("cold run stored no records")
	}
	for i, rec := range coldRecords {
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("cold put[%d] status = %q, want incomplete (a truncated retained set must never be stored completed)", i, rec.Status)
		}
	}

	// A truncated import stores StatusIncomplete: never servable as a hit.
	// Same overrides → same key → the warm leg's Get finds the well-formed
	// record and refuses it on status (incompleteGets), forcing an honest
	// fresh execution.
	in2 := ingestInput(t, clk, cc, urlsPath, overrides)
	putsAfterCold := cc.puts.Load()
	warm, err := stage.Run(context.Background(), in2)
	if err != nil {
		t.Fatalf("warm run: %v", err)
	}
	if got := cc.incompleteGets.Load(); got < 1 {
		t.Fatalf("warm run saw %d incomplete-state Gets, want >= 1 — the StatusIncomplete refusal path did not fire", got)
	}
	if got := cc.puts.Load(); got <= putsAfterCold {
		t.Fatalf("warm run stored nothing (puts=%d): it was served from cache instead of re-executing the truncated import", got)
	}
	if warm.Outcome != pipeline.OutcomePartial || !warm.Truncated {
		t.Fatalf("re-executed truncation lost honesty: %q truncated=%v", warm.Outcome, warm.Truncated)
	}
	for i, rec := range cc.storedRecords()[len(coldRecords):] {
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("warm put[%d] status = %q, want incomplete", i, rec.Status)
		}
	}
}

// TestIngestStagePathValidation pins the structured-error paths: missing
// entries fail with a named error, ".." traversal segments are rejected, and
// non-file/non-dir entries are refused.
func TestIngestStagePathValidation(t *testing.T) {
	clk := fixedClock{now: fixedTime}
	stage := NewIngestStage()

	t.Run("missing path", func(t *testing.T) {
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil,
			filepath.Join(t.TempDir(), "nope.txt"), nil))
		if err == nil || !strings.Contains(err.Error(), "nope.txt") {
			t.Fatalf("err = %v, want structured missing-path error", err)
		}
	})

	t.Run("traversal escape", func(t *testing.T) {
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil,
			filepath.Join("..", "..", "etc", "passwd"), nil))
		if err == nil || !strings.Contains(err.Error(), "..") {
			t.Fatalf("err = %v, want traversal rejection", err)
		}
	})

	t.Run("invalid bound override", func(t *testing.T) {
		_, _, httpxPath := ingestFixtures(t)
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil, httpxPath,
			map[string]string{"max_output": "-3"}))
		if err == nil || !strings.Contains(err.Error(), "max_output") {
			t.Fatalf("err = %v, want invalid max_output error", err)
		}
	})

	t.Run("directory with no regular files", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty-drop")
		if err := os.Mkdir(empty, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil, empty, nil))
		if err == nil || !strings.Contains(err.Error(), empty) {
			t.Fatalf("err = %v, want structured zero-expansion error naming %s", err, empty)
		}
	})

	t.Run("symlink-only drop directory", func(t *testing.T) {
		root := t.TempDir()
		real := filepath.Join(root, "real.txt")
		if err := os.WriteFile(real, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatalf("write real file: %v", err)
		}
		drop := filepath.Join(root, "drop")
		if err := os.Mkdir(drop, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(real, filepath.Join(drop, "linked.txt")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		// The walk does not follow in-dir symlinks (cycle safety), so this
		// drop-dir expands to zero files — a structured error naming the
		// directory, never a silent vacuous success.
		res, err := stage.Run(context.Background(), ingestInput(t, clk, nil, drop, nil))
		if err == nil || !strings.Contains(err.Error(), drop) {
			t.Fatalf("res=%+v err = %v, want structured zero-expansion error naming %s", res, err, drop)
		}
	})

	// NEW-73 residual: separators are reserved inside individual paths. A
	// path containing ',' or '\n' must be REJECTED with a structured error
	// naming it — never silently mis-parsed into fragments or mangled into
	// a nonexistent joined blob.
	t.Run("reserved separator rejected (comma filename)", func(t *testing.T) {
		dir := t.TempDir()
		ok := filepath.Join(dir, "ok.txt")
		if err := os.WriteFile(ok, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatalf("write ok fixture: %v", err)
		}
		comma := filepath.Join(dir, "naughty,name.txt")
		if err := os.WriteFile(comma, []byte("b.example.com\n"), 0o600); err != nil {
			t.Fatalf("write comma-named fixture: %v", err)
		}
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil,
			strings.Join([]string{ok, comma}, "\n"), nil))
		if err == nil {
			t.Fatalf("err = nil, want a structured reserved-separator rejection naming %s (old behavior silently imported it)", comma)
		}
		if !strings.Contains(err.Error(), "reserved separator") {
			t.Fatalf("err = %v, want the reserved-separator reason stated", err)
		}
		if !strings.Contains(err.Error(), comma) {
			t.Fatalf("err = %v, want the offending path %s named", err, comma)
		}
	})

	t.Run("reserved separator rejected (comma-joined list)", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "one.txt")
		f2 := filepath.Join(dir, "two.txt")
		if err := os.WriteFile(f1, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatalf("write f1: %v", err)
		}
		if err := os.WriteFile(f2, []byte("b.example.com\n"), 0o600); err != nil {
			t.Fatalf("write f2: %v", err)
		}
		// The legacy comma-joined form never actually split (the old parse
		// used strings.Split with the two-character separator "\n,", a
		// literal-substring match): it surfaced as a confusing stat error
		// over the whole joined blob. It now gets the honest structured
		// rejection — commas are reserved, pass paths newline-separated.
		_, err := stage.Run(context.Background(), ingestInput(t, clk, nil, f1+","+f2, nil))
		if err == nil {
			t.Fatalf("err = nil, want a structured reserved-separator rejection for %q", f1+","+f2)
		}
		if !strings.Contains(err.Error(), "reserved separator") {
			t.Fatalf("err = %v, want the reserved-separator reason stated", err)
		}
	})

	// Companion pin for the reserved-separator rule: legitimate multi-path
	// input is unchanged — newline-joined entries still expand to every
	// file.
	t.Run("multi-path newline form unchanged", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "one.txt")
		f2 := filepath.Join(dir, "two.txt")
		if err := os.WriteFile(f1, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatalf("write f1: %v", err)
		}
		if err := os.WriteFile(f2, []byte("b.example.com\n"), 0o600); err != nil {
			t.Fatalf("write f2: %v", err)
		}
		res, err := stage.Run(context.Background(), ingestInput(t, clk, nil, f1+"\n"+f2, nil))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("outcome = %q (%v)", res.Outcome, res.Err)
		}
		if res.ItemsProcessed != 2 {
			t.Fatalf("ItemsProcessed = %d, want 2 files imported", res.ItemsProcessed)
		}
	})
}

// TestIngestStageDeduplicatesExpandedPaths pins the compaction pass: a file
// reachable both explicitly and under its listed directory is imported
// exactly once — no double-counted ItemsProcessed.
func TestIngestStageDeduplicatesExpandedPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example.com\nb.example.com\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}

	reg := importer.NewRegistry()
	counter := &countingImporter{imp: importer.NewPlainDomainsImporter()}
	if err := reg.Register(counter); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg.Seal()
	stage := &ingestStage{registry: reg}

	in := ingestInput(t, clk, nil, strings.Join([]string{dir, path}, "\n"), nil)
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome = %q (%v)", res.Outcome, res.Err)
	}
	if got := counter.imports.Load(); got != 1 {
		t.Fatalf("file imported %d times, want exactly 1 despite being reachable twice", got)
	}
	if res.ItemsProcessed != 2 {
		t.Fatalf("ItemsProcessed = %d, want 2 (double import would double-count)", res.ItemsProcessed)
	}
}

// TestIngestStageRegistryComposition pins the caller-side composition point:
// all eighteen importers registered, sealed, and Detect functional.
func TestIngestStageRegistryComposition(t *testing.T) {
	stage := NewIngestStage()
	s, ok := stage.(*ingestStage)
	if !ok {
		t.Fatalf("NewIngestStage returned %T", stage)
	}
	if got := len(s.registry.List()); got != 18 {
		t.Fatalf("registry holds %d importers, want 18", got)
	}
	_, _, httpxPath := ingestFixtures(t)
	data, err := os.ReadFile(httpxPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	matches := s.registry.Detect("httpx.json", data)
	if len(matches) == 0 || matches[0].Importer.Name() != "json-httpx" {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Importer.Name())
		}
		t.Fatalf("detect top match = %v, want json-httpx primary", names)
	}
}

// TestIngestStageAmbiguousPrimaryWins feeds a file two specific importers
// could claim and pins the documented resolution: Detect's top match wins.
func TestIngestStageAmbiguousPrimaryWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.json")
	// url-key object: json-katana claims {"url":...,"method":...} while
	// json-httpx claims bare url objects — katana's method field wins per
	// detect.go's httpx-vs-katana tiebreak.
	content := `{"url":"https://example.com/api","method":"GET"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}
	stage := NewIngestStage()
	res, err := stage.Run(context.Background(), ingestInput(t, clk, nil, path, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome = %q (%v)", res.Outcome, res.Err)
	}
	importerNames := map[string]bool{}
	for _, rec := range res.Provenance {
		importerNames[rec.Importer] = true
	}
	if len(importerNames) != 1 {
		t.Fatalf("ambiguous file produced importers %v, want exactly the primary", importerNames)
	}
	for name := range importerNames {
		if name != "json-katana" {
			t.Fatalf("primary = %q, want json-katana", name)
		}
	}
}

// TestIngestStageDeterministicColdRuns runs the same corpus twice through
// fresh caches and pins byte-determinism: identical outcomes, counters,
// asset identities (sorted walk, sealed registry order), and provenance
// sidecar rows under the injected clock.
func TestIngestStageDeterministicColdRuns(t *testing.T) {
	_, urlsPath, httpxPath := ingestFixtures(t)
	clk := fixedClock{now: fixedTime}
	stage := NewIngestStage()
	in := ingestInput(t, clk, nil, strings.Join([]string{httpxPath, urlsPath}, "\n"), nil)

	var firstIDs, firstRows []string
	for i := 0; i < 2; i++ {
		res, err := stage.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("run %d outcome = %q", i+1, res.Outcome)
		}
		ids := identities(res)
		for j := range ids {
			for k := j + 1; k < len(ids); k++ {
				if ids[j] == ids[k] {
					t.Fatalf("duplicate identity %q within one run", ids[j])
				}
			}
		}
		if i == 0 {
			firstIDs, firstRows = ids, provenanceRows(res)
			continue
		}
		if fmt.Sprint(ids) != fmt.Sprint(firstIDs) {
			t.Fatalf("cold-run asset order differs between runs")
		}
		if fmt.Sprint(provenanceRows(res)) != fmt.Sprint(firstRows) {
			t.Fatalf("cold-run provenance differs between runs")
		}
	}
}

// ---- fakes ----

// ingestStaticCache serves one fixed record for every Get (a planted cache
// entry, e.g. tampered) and counts deletes/puts. It never touches disk.
type ingestStaticCache struct {
	rec       *cache.Record
	gets      atomic.Int64
	deletes   atomic.Int64
	puts      atomic.Int64
	deleteErr error // when non-nil, every Delete fails with it (diagnostic-only)
}

func (c *ingestStaticCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	c.gets.Add(1)
	if c.rec == nil {
		return cache.Outcome{State: cache.StateMiss}
	}
	return cache.Outcome{State: cache.StateHit, Record: c.rec}
}

func (c *ingestStaticCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	c.puts.Add(1)
	return nil
}

func (c *ingestStaticCache) Delete(ctx context.Context, key cache.Key) error {
	c.deletes.Add(1)
	return c.deleteErr
}

func (c *ingestStaticCache) Clear(ctx context.Context) error { return nil }

// countingImporter wraps a real importer and counts Import invocations.
type countingImporter struct {
	imp     importer.Importer
	imports atomic.Int64
}

func (c *countingImporter) Name() string    { return c.imp.Name() }
func (c *countingImporter) Version() string { return c.imp.Version() }

func (c *countingImporter) CanImport(path string, peek []byte) (float64, bool) {
	return c.imp.CanImport(path, peek)
}

func (c *countingImporter) Import(ctx context.Context, env importer.ImportEnv, path string, out *importer.Sink) (importer.ImportStats, error) {
	c.imports.Add(1)
	return c.imp.Import(ctx, env, path, out)
}

// blockingImporter blocks inside Import until its context fires, then
// returns the importer's own cancelled-stats shape (partial stats +
// context error) — the engine's documented cancellation contract.
type blockingImporter struct {
	imp    importer.Importer
	cancel context.CancelFunc
}

func (b *blockingImporter) Name() string    { return b.imp.Name() }
func (b *blockingImporter) Version() string { return b.imp.Version() }

func (b *blockingImporter) CanImport(path string, peek []byte) (float64, bool) {
	return b.imp.CanImport(path, peek)
}

func (b *blockingImporter) Import(ctx context.Context, env importer.ImportEnv, path string, out *importer.Sink) (importer.ImportStats, error) {
	<-ctx.Done()
	stats := importer.ImportStats{
		ItemsProcessed: 1,
		StickyFlags:    map[string]bool{},
	}
	return stats, ctx.Err()
}

// ---- helpers shared by the e2e assertions ----

func identities(res pipeline.StageResult) []string {
	var out []string
	for _, h := range res.Additions.Hosts {
		out = append(out, h.Identity().String())
	}
	for _, u := range res.Additions.URLs {
		out = append(out, u.Identity().String())
	}
	return out
}

func provenanceRows(res pipeline.StageResult) []string {
	out := make([]string, 0, len(res.Provenance))
	for _, r := range res.Provenance {
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d", r.Identity, r.Importer, r.Filename, r.ImportTime.Format(time.RFC3339Nano), int(r.Confidence*100)))
	}
	return out
}

// --- NEW-63 / H-3: imported URLs with explicit non-default ports ---

// TestFilterIngestURLsRetainsNonDefaultPort is the H-3 regression: the
// canonical HostPort retains explicit ports ("api.example.com:8443"), and
// asset.NewHost rejects ':' — the pre-fix filter silently dropped EVERY
// port-bearing URL. The filter must strip the port through the shared
// urlHost helper before the domain check.
func TestFilterIngestURLsRetainsNonDefaultPort(t *testing.T) {
	target := inTarget(t)
	urls := []asset.URL{
		mustURL(t, "http://api.example.com:8443/"),
		mustURL(t, "http://www.example.com/"),
		mustURL(t, "http://evil.com/out"),
		mustURL(t, "http://93.184.216.34/x"), // IP literal: never in-domain
	}
	got := filterIngestURLs(target, urls)
	if len(got) != 2 {
		t.Fatalf("filterIngestURLs kept %d URLs, want 2 (ported + plain in-domain)", len(got))
	}
	if got[0].Identity().String() != urls[0].Identity().String() ||
		got[1].Identity().String() != urls[1].Identity().String() {
		t.Fatalf("kept = %v/%v, want the two in-domain URLs in input order",
			got[0].Identity(), got[1].Identity())
	}
}

// TestIngestStageRetainsPortedURLsEndToEnd drives the whole ingest stage
// over a plain-URLs file carrying an explicit :8443 URL: the ported URL
// must reach Additions.URLs, not vanish into a silent skip.
func TestIngestStageRetainsPortedURLsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	content := strings.Join([]string{
		"http://api.example.com:8443/",
		"http://www.example.com/",
		"http://evil.com/out",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clk := fixedClock{now: fixedTime}

	res, err := NewIngestStage().Run(context.Background(),
		ingestInput(t, clk, nil, path, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, u := range res.Additions.URLs {
		got = append(got, u.Identity().String())
	}
	want := []string{"url:http://api.example.com:8443/", "url:http://www.example.com/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Additions.URLs = %v, want %v", got, want)
	}
}

// --- NEW-61 / H-2: cancellation with queued files never deadlocks ---

// TestIngestStageCancelWithQueuedFilesReturnsPromptly is the H-2 regression:
// concurrency 1 over four files means three jobs sit queued while the first
// blocks. Cancelling mid-run drops those queued jobs WITHOUT executing their
// Func (the pool's forced-shutdown path) — the old caller-side WaitGroup's
// Done lived only inside the closures, so wg.Wait blocked forever before the
// deferred Shutdown could run. Run must return promptly and fold every
// never-executed file as cancelled.
func TestIngestStageCancelWithQueuedFilesReturnsPromptly(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, fmt.Sprintf("domains%d.txt", i))
		if err := os.WriteFile(p, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		paths = append(paths, p)
	}
	clk := fixedClock{now: fixedTime}

	reg := importer.NewRegistry()
	blocker := &blockingImporter{imp: importer.NewPlainDomainsImporter()}
	if err := reg.Register(blocker); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg.Seal()
	stage := &ingestStage{registry: reg}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	in := ingestInput(t, clk, nil, strings.Join(paths, "\n"), nil)
	in.Bounds.MaxConcurrency = 1

	done := make(chan struct{})
	var res pipeline.StageResult
	go func() {
		res, _ = stage.Run(ctx, in)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stage.Run did not return after cancellation — join point deadlocks on queued jobs")
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
	}
}
