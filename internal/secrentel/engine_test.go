package secrentel

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// fakeClock is the deterministic runtime.Clock seam.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1700000000, 0).UTC()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- c.now.Add(d)
	return ch
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// openTestCache opens a real filesystem-backed cache in a temp dir.
func openTestCache(t *testing.T) *cache.FS {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

func baseCfg() Config {
	return Config{Concurrency: 4, QueueSize: 64, Timeout: 30 * time.Second}
}

func testDocuments() []Document {
	return []Document{
		{Kind: KindJS, Content: []byte(fmt.Sprintf(`const cfg={aws_access_key_id:"%s",aws_secret_access_key:"%s"};fetch("https://my-bucket.s3.us-west-2.amazonaws.com/x")`, awsKeyID, awsSecret)), Technology: []string{"aws-sdk"}},
		{Kind: KindEnv, Content: []byte("DATABASE_URL=postgres://admin:hunter2strong@db.internal.example.com:5432/prod"), Filename: "config/production.env"},
		{Kind: KindJSON, Content: []byte(fmt.Sprintf(`{"github_token":"%s"}`, githubToken))},
		{Kind: KindHTML, Content: []byte("<html><!-- no secrets --></html>")},
	}
}

func sliceSource(docs []Document) *SliceDocumentSource {
	s := SliceDocumentSource(docs)
	return &s
}

func TestIngestFreshScan(t *testing.T) {
	clock := newFakeClock()
	cfg := baseCfg()
	cfg.Clock = clock
	var metrics Metrics
	cfg.Metrics = &metrics

	rep, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if rep.Documents.Completed != 4 || rep.Documents.Malformed != 0 {
		t.Errorf("documents = %+v", rep.Documents)
	}
	if len(rep.Secrets) < 4 {
		t.Errorf("secrets = %d, want at least 4 (aws key, aws secret, postgres, github): %+v", len(rep.Secrets), rep.Secrets)
	}
	m := metrics.Snapshot()
	if m.Documents != 4 || m.Scanned != 4 {
		t.Errorf("metrics = %+v", m)
	}

	// The AWS pair correlation must produce a High candidate.
	var high bool
	for _, s := range rep.Secrets {
		if s.Type.String() == "aws" && s.Confidence.Level == LevelHigh {
			high = true
		}
	}
	if !high {
		t.Error("correlated AWS pair should produce a High candidate")

	}

	// Every result is structural — no anonymous strings.
	for _, s := range rep.Secrets {
		if s.Candidate.ID() == "" || len(s.PatternIDs) == 0 || s.Confidence.Factors == nil {
			t.Errorf("result is not fully structural: %+v", s)
		}
		if s.Observations != 1 || len(s.Sources) != 1 {
			t.Errorf("observation accounting broken: %+v", s)
		}
	}

	// The verification queue holds the medium+ unflagged candidates,
	// ordered by score desc.
	for i := 1; i < len(rep.Queue); i++ {
		if rep.Queue[i-1].Score < rep.Queue[i].Score {
			t.Errorf("queue not ordered by score: %+v", rep.Queue)
		}
		if rep.Queue[i-1].Priority != i {
			t.Errorf("priority = %d, want %d", rep.Queue[i-1].Priority, i)
		}
	}
}

func TestIngestDeterministicAcrossRuns(t *testing.T) {
	clock := newFakeClock()
	cfg := baseCfg()
	cfg.Clock = clock

	rep1, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatal(err)
	}
	if !equalReports(rep1, rep2) {
		t.Error("two identical runs must produce identical reports")
	}
}

// equalReports compares the deterministic core of two reports (metrics and
// queue timestamps aside — same clock means equal anyway, but Cached flags
// differ between cold and warm runs).
func equalReports(a, b Report) bool {
	if fmt.Sprint(a.Documents) != fmt.Sprint(b.Documents) {
		return false
	}
	if len(a.Secrets) != len(b.Secrets) {
		return false
	}
	for i := range a.Secrets {
		x, y := a.Secrets[i], b.Secrets[i]
		x.Cached, y.Cached = false, false
		if fmt.Sprint(x) != fmt.Sprint(y) {
			return false
		}
	}
	return true
}

func TestIngestCacheRoundTrip(t *testing.T) {
	fs := openTestCache(t)
	clock := newFakeClock()

	cfg := baseCfg()
	cfg.Clock = clock
	cfg.Cache = fs
	var metrics1, metrics2 Metrics

	cfg.Metrics = &metrics1
	rep1, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatal(err)
	}
	if s := metrics1.Snapshot(); s.Stored != 4 {
		t.Errorf("stored = %d, want 4: %+v", s.Stored, s)
	}

	// Warm run: every completed document is a cache hit — ZERO fresh scans.
	cfg.Metrics = &metrics2
	rep2, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatal(err)
	}
	s := metrics2.Snapshot()
	if s.Scanned != 0 {
		t.Errorf("warm run scanned %d documents, want 0 (cache hits)", s.Scanned)
	}
	if s.Reads != 4 {
		t.Errorf("warm run reads = %d, want 4", s.Reads)
	}
	if !equalReports(rep1, rep2) {
		t.Error("cache-served report must equal the fresh report")
	}
	for _, sec := range rep2.Secrets {
		if !sec.Cached {
			t.Errorf("warm-run secret must be marked cached: %+v", sec)
		}
	}

	// A changed document (different content) is a cache miss by
	// construction: the scan identity covers the content.
	changed := testDocuments()
	changed[2].Content = []byte(fmt.Sprintf(`{"github_token":"%s","extra":true}`, githubToken))
	var metrics3 Metrics
	cfg.Metrics = &metrics3
	_, err = Ingest(context.Background(), cfg, sliceSource(changed))
	if err != nil {
		t.Fatal(err)
	}
	if s := metrics3.Snapshot(); s.Scanned != 1 {
		t.Errorf("changed document scanned = %d, want 1", s.Scanned)
	}
}

func TestIngestTruncatedDocumentNeverServedFromCache(t *testing.T) {
	fs := openTestCache(t)
	clock := newFakeClock()
	big := Document{Kind: KindJS, Content: make([]byte, MaxDocumentBytes+64)}
	for i := range big.Content {
		big.Content[i] = byte('a' + i%26)
	}

	cfg := baseCfg()
	cfg.Clock = clock
	cfg.Cache = fs
	var m1, m2 Metrics

	cfg.Metrics = &m1
	rep, err := Ingest(context.Background(), cfg, sliceSource([]Document{big}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Documents.Incomplete != 1 || rep.Documents.Completed != 0 {
		t.Errorf("truncated document status = %+v", rep.Documents)
	}
	if !rep.Truncated {
		t.Error("report must carry the truncated flag")
	}

	// The truncated record is stored incomplete; the second run rescans.
	cfg.Metrics = &m2
	_, err = Ingest(context.Background(), cfg, sliceSource([]Document{big}))
	if err != nil {
		t.Fatal(err)
	}
	if s := m2.Snapshot(); s.Scanned != 1 {
		t.Errorf("truncated document must be rescanned (never served), scanned = %d", s.Scanned)
	}
}

func TestIngestMalformedDocuments(t *testing.T) {
	docs := []Document{
		{Kind: "bogus", Content: []byte("x")},
		{Kind: KindEnv, Content: []byte("A=1")},
	}
	rep, err := Ingest(context.Background(), baseCfg(), sliceSource(docs))
	if err == nil || !strings.Contains(err.Error(), "unknown document kind") {
		t.Errorf("malformed document must surface a diagnostic, got %v", err)
	}
	if rep.Documents.Malformed != 1 || rep.Documents.Completed != 1 {
		t.Errorf("documents = %+v", rep.Documents)
	}
}

func TestIngestCancellation(t *testing.T) {
	// A source that yields one document then blocks until cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	src := &blockingSource{docs: testDocuments(), cancelAfter: 1, ctx: ctx, cancel: cancel}

	rep, err := Ingest(ctx, baseCfg(), src)
	if err != nil {
		t.Fatalf("Ingest with cancelled context: %v", err)
	}
	if rep.Documents.Completed > 4 {
		t.Errorf("completed = %d, want <= 4", rep.Documents.Completed)
	}
	if rep.Documents.Completed == 0 && rep.Documents.Cancelled == 0 {
		t.Errorf("expected some honest outcome: %+v", rep.Documents)
	}
}

// blockingSource yields docs one by one; after the first Next it cancels the
// context and then blocks until ctx is done (then returns EOF), modeling a
// caller-side interruption.
type blockingSource struct {
	docs        []Document
	cancelAfter int
	ctx         context.Context
	cancel      context.CancelFunc
	calls       int
}

func (b *blockingSource) Next(ctx context.Context) (Document, error) {
	if b.calls >= b.cancelAfter {
		b.cancel()
		<-b.ctx.Done()
		return Document{}, ctx.Err()
	}
	b.calls++
	d := b.docs[0]
	b.docs = b.docs[1:]
	return d, nil
}

func TestIngestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	_, _ = Ingest(context.Background(), baseCfg(), sliceSource(testDocuments()))
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine leak: before %d, after %d", before, after)
	}
}

func TestIngestCancellationNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	src := &blockingSource{docs: testDocuments(), cancelAfter: 1, ctx: ctx, cancel: cancel}
	_, _ = Ingest(ctx, baseCfg(), src)
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine leak after cancellation: before %d, after %d", before, after)
	}
}

func TestRepeatLiftsZeroSupportStructuredCap(t *testing.T) {
	// The evidence-model pin for the zero-support cap (structuredCap): a
	// lone structured candidate with PATTERN-ONLY factors (no entropy rule
	// on the pattern, no assignment/JSON-key context, no correlation
	// signals — the value is the provider endpoint, so the endpoint factor
	// is suppressed) scans at score <= structuredCap in a single document.
	// The same (type, value) observed under a second document identity
	// gains the repeat factor at report build — supporting evidence — and
	// the score lands ABOVE structuredCap, gated to Medium (one non-pattern
	// factor, never High).
	webhook := "https://discord.com/api/webhooks/123456789012345678/" + detRand(60, alnumMixed, 7, 23)

	// One document: pattern-only factors, zero-support cap binds.
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte(`fetch("` + webhook + `")`)})
	w := findByValue(out, "https://discord.com")
	if w == nil {
		t.Fatalf("discord webhook must be scanned: %+v", out.candidates)
	}
	if n := countNonPattern(w.confidence.Factors); n != 0 {
		t.Errorf("lone structured candidate must carry pattern-only factors, got %d non-pattern: %+v", n, w.confidence.Factors)
	}
	if w.confidence.Score > structuredCap {
		t.Errorf("lone structured score = %v, want <= %v (zero-support cap)", w.confidence.Score, structuredCap)
	}
	if w.confidence.Level != LevelLow {
		t.Errorf("lone structured level = %s, want low (zero-support gate): %+v", w.confidence.Level, w.confidence.Factors)
	}

	// Two documents: repeat is supporting evidence that lifts the cap.
	docs := []Document{
		{Kind: KindJS, Content: []byte(`fetch("` + webhook + `")`)},
		{Kind: KindJSON, Content: []byte(`{"list":["` + webhook + `"]}`)},
	}
	rep, err := Ingest(context.Background(), baseCfg(), sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	var ws []*SecretResult
	for i := range rep.Secrets {
		if rep.Secrets[i].Type == asset.SecretTypeWebhookURL {
			ws = append(ws, &rep.Secrets[i])
		}
	}
	if len(ws) != 2 {
		t.Fatalf("expected 2 webhook results (one per document identity, attribution never merged), got %d: %+v", len(ws), rep.Secrets)
	}
	for _, r := range ws {
		if r.Observations != 2 {
			t.Errorf("observations = %d, want 2: %+v", r.Observations, r)
		}
		if !hasFactor(r.Confidence, "repeat") {
			t.Errorf("repeat factor missing: %+v", r.Confidence.Factors)
		}
		if r.Confidence.Score <= structuredCap {
			t.Errorf("repeated score = %v, want > %v (repeat lifts the zero-support cap)", r.Confidence.Score, structuredCap)
		}
		if r.Confidence.Level != LevelMedium {
			t.Errorf("repeated level = %s, want medium (one non-pattern factor, never High): %+v", r.Confidence.Level, r.Confidence)
		}
	}
}

func TestIngestRepeatedCandidateAcrossDocuments(t *testing.T) {
	// The same GitHub token in two different documents: one merged result
	// with Observations=2 and the repeat factor applied.
	docs := []Document{
		{Kind: KindJS, Content: []byte(fmt.Sprintf("a=%q", githubToken))},
		{Kind: KindEnv, Content: []byte("GITHUB_TOKEN=" + githubToken), Filename: "deploy.env"},
	}
	rep, err := Ingest(context.Background(), baseCfg(), sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	var found *SecretResult
	for i := range rep.Secrets {
		if rep.Secrets[i].Type.String() == "github" {
			found = &rep.Secrets[i]
		}
	}
	if found == nil {
		t.Fatal("github token not found")
	}
	if found.Observations != 2 {
		t.Errorf("observations = %d, want 2", found.Observations)
	}
	hasRepeat := false
	for _, f := range found.Confidence.Factors {
		if f.Name == "repeat" {
			hasRepeat = true
		}
	}
	if !hasRepeat {
		t.Errorf("repeat factor missing: %+v", found.Confidence.Factors)
	}
	if len(found.Sources) != 1 {
		t.Errorf("sources = %v", found.Sources)
	}
}

func TestIngestQueueExcludesFlaggedAndWeak(t *testing.T) {
	docs := []Document{
		{Kind: KindEnv, Content: []byte("key=" + awsKeyID), Filename: "config/test.env"}, // capped Low + flagged
		{Kind: KindJSON, Content: []byte(`{"note":"nothing here"}`)},
	}
	rep, err := Ingest(context.Background(), baseCfg(), sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rep.Secrets {
		if len(s.FPFlags) > 0 {
			for _, q := range rep.Queue {
				if q.CandidateID == s.Candidate.ID() {
					t.Errorf("flagged candidate %q must not be queued", q.CandidateID)
				}
			}
		}
		if s.Confidence.Level.rank() < queueMinLevel.rank() {
			for _, q := range rep.Queue {
				if q.CandidateID == s.Candidate.ID() {
					t.Errorf("weak candidate must not be queued")
				}
			}
		}
	}
}

func TestIngestQueueLevelsForURLCandidates(t *testing.T) {
	// The verification queue reflects the URL overreach fixes: a Discord
	// webhook (genuinely sensitive) and a credential-bearing connection
	// string are queued; a bare S3 bucket URL and a credential-less
	// DATABASE_URL are clamped at Low and stay out of the queue.
	docs := []Document{
		{Kind: KindEnv, Content: []byte(fmt.Sprintf("DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/%s", strings.Repeat("a", 60)))},
		{Kind: KindJS, Content: []byte(`const u = "https://my-bucket.s3.us-east-1.amazonaws.com/file.txt";`)},
		{Kind: KindEnv, Content: []byte("DATABASE_URL=postgres://db.example.com/prod")},
		{Kind: KindEnv, Content: []byte("DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod")},
	}
	rep, err := Ingest(context.Background(), baseCfg(), sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Documents.Completed != 4 {
		t.Fatalf("documents = %+v", rep.Documents)
	}

	queued := make(map[string]bool)
	for _, q := range rep.Queue {
		if queued[q.CandidateID] {
			t.Errorf("duplicate queue entry %s", q.CandidateID)
		}
		queued[q.CandidateID] = true
	}
	seen := map[asset.SecretType]bool{}
	for _, s := range rep.Secrets {
		seen[s.Type] = true
		switch s.Type {
		case asset.SecretTypeWebhookURL:
			if s.Confidence.Level != LevelMedium {
				t.Errorf("discord webhook level = %s, want medium", s.Confidence.Level)
			}
			if !queued[s.Candidate.ID()] {
				t.Errorf("discord webhook must be queued (level %s)", s.Confidence.Level)
			}
		case asset.SecretTypeS3:
			if s.Confidence.Level.rank() > LevelLow.rank() {
				t.Errorf("S3 bucket URL level = %s, want low", s.Confidence.Level)
			}
			if queued[s.Candidate.ID()] {
				t.Error("S3 bucket URL must not be queued")
			}
		case asset.SecretTypeDatabaseURL:
			if s.Confidence.Level.rank() > LevelLow.rank() {
				t.Errorf("credential-less DB URL level = %s, want low", s.Confidence.Level)
			}
			if queued[s.Candidate.ID()] {
				t.Error("credential-less DB URL must not be queued")
			}
		case asset.SecretTypePostgreSQLURL:
			if s.Confidence.Level.rank() < LevelMedium.rank() {
				t.Errorf("userinfo DB URL level = %s, want >= medium", s.Confidence.Level)
			}
			if !queued[s.Candidate.ID()] {
				t.Errorf("userinfo DB URL must be queued (level %s)", s.Confidence.Level)
			}
		}
	}
	for _, want := range []asset.SecretType{asset.SecretTypeWebhookURL, asset.SecretTypeS3, asset.SecretTypeDatabaseURL, asset.SecretTypePostgreSQLURL} {
		if !seen[want] {
			t.Errorf("missing %s candidate", want)
		}
	}
}

func TestIngestEmitHook(t *testing.T) {
	var mu sync.Mutex
	var seen []asset.Identity
	cfg := baseCfg()
	cfg.Emit = func(ctx context.Context, d DocumentRef, e ReportEntry) error {
		if e.Status != StatusCompleted {
			return fmt.Errorf("unexpected status %s", e.Status)
		}
		mu.Lock()
		seen = append(seen, e.ID)
		mu.Unlock()
		return nil
	}
	if _, err := Ingest(context.Background(), cfg, sliceSource(testDocuments())); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 4 {
		t.Errorf("emit called %d times, want 4", len(seen))
	}

	// A panicking emit hook is contained and reported, never fatal.
	cfg.Emit = func(ctx context.Context, d DocumentRef, e ReportEntry) error {
		panic("boom")
	}
	_, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()[:1]))
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("panic must surface as a diagnostic, got %v", err)
	}
}
func TestIngestConcurrentDocumentsRaceSafe(t *testing.T) {
	// 64 documents over 8 workers: the merge accumulator and metrics are
	// exercised concurrently (run under -race).
	var docs []Document
	for i := 0; i < 64; i++ {
		docs = append(docs, Document{
			Kind:     KindJS,
			Content:  []byte(fmt.Sprintf(`const k%d="%s";`, i, detRand(32, alnumMixed, 7, i))),
			Hostname: fmt.Sprintf("host-%d.example.com", i%4),
		})
	}
	rep, err := Ingest(context.Background(), Config{Concurrency: 8, QueueSize: 16, Timeout: 30 * time.Second}, sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Documents.Completed != 64 {
		t.Errorf("completed = %d, want 64 (%+v)", rep.Documents.Completed, rep.Documents)
	}
}

func TestIngestZeroValueDocumentsRejected(t *testing.T) {
	if _, err := Ingest(context.Background(), Config{}, nil); err == nil {
		t.Error("nil source must fail")
	}
	if _, err := Ingest(context.Background(), Config{Concurrency: 0, QueueSize: 8}, sliceSource(nil)); err == nil {
		t.Error("invalid concurrency must fail")
	}
	if _, err := Ingest(context.Background(), Config{Concurrency: 2, QueueSize: 0}, sliceSource(nil)); err == nil {
		t.Error("invalid queue size must fail")
	}
}

func TestIngestSourceError(t *testing.T) {
	src := errSource{}
	if _, err := Ingest(context.Background(), baseCfg(), src); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("source error must surface: %v", err)
	}
}

var errSourceFailure = errors.New("boom")

type errSource struct{}

func (errSource) Next(ctx context.Context) (Document, error) { return Document{}, errSourceFailure }

func TestIngestStreamingBackpressure(t *testing.T) {
	// A bounded queue (2) with slow-ish jobs exercises Submit backpressure;
	// the reader must block, not grow memory.
	var docs []Document
	for i := 0; i < 32; i++ {
		docs = append(docs, Document{Kind: KindJSON, Content: []byte(`{"k":"` + detRand(64, alnumMixed, 7, i) + `"}`)})
	}
	cfg := Config{Concurrency: 2, QueueSize: 2, Timeout: 30 * time.Second}
	rep, err := Ingest(context.Background(), cfg, sliceSource(docs))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Documents.Completed != 32 {
		t.Errorf("completed = %d, want 32", rep.Documents.Completed)
	}
}

func TestMergeEntriesPreserveScanCounts(t *testing.T) {
	// Regression: the pre-registered cancelled placeholder carries zero
	// counts; the processed contributor's accounting must survive a merge.
	processed := ReportEntry{
		ID:     asset.Identity{Kind: "document", Value: "x"},
		Status: StatusCompleted,
		Counts: scanCounts{SuppressedFP: 3, DroppedEntropy: 2},
	}
	placeholder := ReportEntry{
		ID:     processed.ID,
		Status: StatusCancelled,
	}
	for _, order := range [][2]*ReportEntry{{&placeholder, &processed}, {&processed, &placeholder}} {
		merged, err := mergeEntries(order[0], order[1])
		if err != nil {
			t.Fatal(err)
		}
		if merged.Counts.SuppressedFP != 3 || merged.Counts.DroppedEntropy != 2 {
			t.Errorf("merge(%s, %s) lost the processed counts: %+v",
				order[0].Status, order[1].Status, merged.Counts)
		}
		if merged.Status != StatusCompleted {
			t.Errorf("merged status = %s, want completed", merged.Status)
		}
	}
}
