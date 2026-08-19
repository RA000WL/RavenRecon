package adapt

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/secrentel"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// --- synthetic pattern database (hermetic; never patterns.Load) ---

// testSecretDB compiles a synthetic database with exactly the AWS access
// key pattern — the only shape the tests below use. Synthetic values only
// (AGENTS §0.8).
func testSecretDB(t *testing.T) *patterns.DB {
	t.Helper()
	db, err := patterns.CompileForTest([]patterns.Pattern{{
		ID:        "aws-access-key-id",
		Type:      asset.SecretTypeAWS,
		Provider:  "aws",
		Family:    patterns.FamilyStructured,
		Regex:     `(?:AKIA|ASIA)[0-9A-Z]{16}`,
		Strength:  0.9,
		MinLen:    20,
		MaxLen:    20,
		Validator: patterns.ValidatorMixedAlnum,
		Negatives: []string{"EXAMPLE"},
	}})
	if err != nil {
		t.Fatalf("CompileForTest: %v", err)
	}
	return db
}

// awsKey returns the i-th distinct synthetic AWS access key ID: 20 mixed
// alphanumeric characters (AKIA + 12 A's + a hex index), validator-valid,
// no "EXAMPLE" substring. Distinct by construction.
func awsKey(i int) string {
	return "AKIA" + strings.Repeat("A", 12) + fmt.Sprintf("%04X", i)
}

// scriptDocument is a pipeline document channel entry with the canonical
// identity of the JavaScript asset at rawURL and the given content.
func scriptDocument(t *testing.T, rawURL, content string) pipeline.Document {
	t.Helper()
	j, err := asset.NewJavaScript(rawURL, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript(%q): %v", rawURL, err)
	}
	return pipeline.Document{Identity: j.Identity(), Content: []byte(content)}
}

// secretInput builds the StageInput the adapter tests drive with: the
// canonical declared target, positive bounds, the deterministic clock, and
// the given document channel. The engine config validation requires
// positive Concurrency/QueueSize, exactly as the runner always resolves.
func secretInput(t *testing.T, docs ...pipeline.Document) pipeline.StageInput {
	t.Helper()
	return pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		Bounds: pipeline.StageConfig{
			MaxConcurrency: 4,
			QueueSize:      64,
			Timeout:        30 * time.Second,
		},
		Clock:     fixedClock{now: fixedTime},
		Documents: docs,
	}
}

// jsDocProducer is a hermetic pipeline.Stage simulating the future jsintel
// document-channel producer (T3d — no adapter produces documents yet): it
// emits the given documents through the channel and completes.
type jsDocProducer struct {
	docs []pipeline.Document
}

func (p *jsDocProducer) Name() pipeline.StageName { return pipeline.StageJSIntel }

func (p *jsDocProducer) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if len(in.Documents) != 0 {
		panic("producer must never receive documents")
	}
	return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted, Documents: p.docs}, nil
}

func TestSecretIntelStageName(t *testing.T) {
	if got := NewSecretIntelStage(nil).Name(); got != pipeline.StageSecretIntel {
		t.Errorf("Name() = %q, want %q", got, pipeline.StageSecretIntel)
	}
}

func TestSecretIntelHappyPath(t *testing.T) {
	// Two documents, one and two distinct AWS keys respectively: every
	// scannable document is processed, the canonical secret candidates and
	// evidence land in the results channel, counters are honest.
	d1 := scriptDocument(t, "https://cdn.example.com/app.js", `var k1 = "`+awsKey(1)+`";`)
	d2 := scriptDocument(t, "https://cdn.example.com/vendor.js",
		`var k2 = "`+awsKey(2)+`"; var k3 = "`+awsKey(3)+`";`)
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), secretInput(t, d1, d2))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 2/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if len(res.Results.Secrets) != 3 {
		t.Fatalf("secrets = %d, want 3 (one per distinct key)", len(res.Results.Secrets))
	}
	// The candidate's source is the pipeline document's canonical identity
	// (SourceAsset): the jsintel dedup contract. Sources are PER-DOCUMENT:
	// candidates from d1 carry d1.Identity and candidates from d2 carry
	// d2.Identity — distinct per-document sources pin that the engine
	// attributes each candidate to its own document (a shared-buffer or
	// loop-variable aliasing regression would collapse the two documents'
	// sources onto one identity).
	wantSource := map[string]asset.Identity{
		awsKey(1): d1.Identity,
		awsKey(2): d2.Identity,
		awsKey(3): d2.Identity,
	}
	for _, s := range res.Results.Secrets {
		if s.Type != asset.SecretTypeAWS {
			t.Errorf("secret type = %s, want aws", s.Type)
		}
		want, ok := wantSource[s.Value]
		if !ok {
			t.Errorf("unexpected secret value %q", s.Value)
			continue
		}
		if s.Source != want {
			t.Errorf("secret source for value %q = %v, want %v (per-document source attribution)", s.Value, s.Source, want)
		}
	}
	// Evidence and relationships pass through (never rebuilt).
	if len(res.Results.Evidence) == 0 {
		t.Error("evidence must be produced for the found secrets")
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Errorf("truncation = %v flags %v, want none", res.Truncated, res.StickyFlags)
	}
	if len(res.Documents) != 0 {
		t.Errorf("Documents = %d, want 0 (the secrentel stage never produces documents)", len(res.Documents))
	}
}

func TestSecretIntelSkipsTruncatedAndNilContent(t *testing.T) {
	// Truncated documents and nil-content documents are skipped — nothing
	// honest to scan — and skipped documents are not counted.
	trunc := scriptDocument(t, "https://cdn.example.com/trunc.js", `var k = "`+awsKey(4)+`";`)
	trunc.Truncated = true
	nilContent := scriptDocument(t, "https://cdn.example.com/empty.js", "")
	nilContent.Content = nil
	good := scriptDocument(t, "https://cdn.example.com/app.js", `var k = "`+awsKey(5)+`";`)
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), secretInput(t, trunc, nilContent, good))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 1/0 (skipped documents are not counted)", res.ItemsProcessed, res.ItemsFailed)
	}
	if len(res.Results.Secrets) != 1 || res.Results.Secrets[0].Value != awsKey(5) {
		t.Errorf("secrets = %+v, want exactly the good document's key", res.Results.Secrets)
	}
}

func TestSecretIntelEmptyInputShortCircuit(t *testing.T) {
	// No scannable documents + canonical target: the stage short-circuits
	// with a vacuous completed result and never touches the engine — zero
	// cache reads.
	var rc recordingCache
	in := secretInput(t)
	in.Cache = &rc
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed (vacuous)", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if len(res.Results.Secrets) != 0 {
		t.Errorf("secrets = %+v, want none", res.Results.Secrets)
	}
	if got := rc.getKeys(); len(got) != 0 {
		t.Errorf("cache reads = %d, want 0 (engine never invoked)", len(got))
	}
}

func TestSecretIntelNonCanonicalTargetFallThrough(t *testing.T) {
	// A non-canonical target with no scannable documents falls through to
	// the engine with an empty source (the engine treats empty input as
	// valid and completes vacuously — the canonicality gate never masks a
	// fabricated error).
	in := secretInput(t)
	in.Target = asset.Domain{Name: "Example.COM"} // hand-built, non-canonical
	var rc recordingCache
	in.Cache = &rc
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed (engine's vacuous empty-source completion)", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
}

func TestSecretIntelNilContext(t *testing.T) {
	_, err := NewSecretIntelStage(testSecretDB(t)).Run(nil, secretInput(t))
	if err == nil || !strings.Contains(err.Error(), "context must not be nil") {
		t.Fatalf("Run(nil ctx) error = %v, want context-must-not-be-nil", err)
	}
}

func TestSecretIntelInvalidEngineConfig(t *testing.T) {
	// A direct caller passing zero Concurrency gets the engine's own
	// config-validation error, mapped to failed with the stage wrapped.
	in := secretInput(t, scriptDocument(t, "https://cdn.example.com/app.js", `var k = "`+awsKey(6)+`";`))
	in.Bounds = pipeline.StageConfig{} // Concurrency/QueueSize 0: engine rejects
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run succeeded, want engine config error")
	}
	if !strings.Contains(err.Error(), "stage secrentel") {
		t.Errorf("error %q not wrapped with the stage name", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Errorf("Outcome = %q, want failed", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
}

func TestSecretIntelPreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := secretInput(t, scriptDocument(t, "https://cdn.example.com/app.js", `var k = "`+awsKey(7)+`";`))
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("Err = %v, want context.Canceled attached", res.Err)
	}
}

func TestSecretIntelEngineErrorWithFiredContextJoins(t *testing.T) {
	// Engine error while the stage context is also firing: cancellation is
	// dominant and the engine's detail is errors.Join-ed, nothing lost.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := secretInput(t, scriptDocument(t, "https://cdn.example.com/app.js", `var k = "`+awsKey(8)+`";`))
	in.Bounds = pipeline.StageConfig{} // engine rejects the config too
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled (dominant signal)", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("Err = %v, want context.Canceled present", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "config") {
		t.Errorf("Err = %v, want the engine's config error joined", res.Err)
	}
}

func TestSecretIntelOverflowFlags(t *testing.T) {
	// One document with 80 distinct AWS keys: the engine's fixed
	// per-document candidate cap (64) overflows honestly — the report
	// carries the overflow signal, the stage maps it to Truncated + the
	// secrentel_overflow sticky flag, and the outcome stays completed (the
	// §0.6 carve-out; the flag, never the outcome alone, marks the retained
	// set incomplete).
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteString(fmt.Sprintf("var k%d = %q;\n", i, awsKey(10+i)))
	}
	in := secretInput(t, scriptDocument(t, "https://cdn.example.com/bundle.js", b.String()))
	res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed (carve-out, flag marks the set)", res.Outcome)
	}
	if !res.Truncated {
		t.Error("Truncated must be set when the engine reported overflow")
	}
	if !res.StickyFlags[secretIntelOverflowFlag] {
		t.Errorf("StickyFlags = %v, want secrentel_overflow", res.StickyFlags)
	}
	if res.StickyFlags[secretIntelTruncatedFlag] {
		t.Errorf("StickyFlags = %v, secrentel_truncated must NOT be set (only overflow fires through this adapter)", res.StickyFlags)
	}
	// The candidate cap is fixed at 64: exactly 64 candidates retained, the
	// overflow counted but never silently dropped from the report.
	if len(res.Results.Secrets) != 64 {
		t.Errorf("secrets = %d, want the capped 64", len(res.Results.Secrets))
	}
}

func TestSecretIntelOverflowFlagsCacheHitRegression(t *testing.T) {
	// §0.6 chain regression: the overflow flag survives a cache hit
	// end-to-end (result → RunReport → report). Run the same document twice
	// against a real filesystem cache: the second run is served from cache
	// (zero Puts), the stored overflow flag replays, and the stage reports
	// the identical flags — never swallowed.
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteString(fmt.Sprintf("var k%d = %q;\n", i, awsKey(40+i)))
	}
	doc := scriptDocument(t, "https://cdn.example.com/bundle.js", b.String())

	fs, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cc := &countingCache{Cache: fs}

	stage := NewSecretIntelStage(testSecretDB(t))
	runOnce := func() (pipeline.StageResult, error) {
		in := secretInput(t, doc)
		in.Cache = cc
		return stage.Run(context.Background(), in)
	}

	res1, err := runOnce()
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if !res1.StickyFlags[secretIntelOverflowFlag] || res1.Truncated != true {
		t.Fatalf("first run flags = %v truncated %v, want overflow flag set", res1.StickyFlags, res1.Truncated)
	}
	putsAfterFirst := cc.putCount()
	if putsAfterFirst == 0 {
		t.Fatal("first run stored nothing — cache-before-execute flow broken")
	}

	res2, err := runOnce()
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := cc.putCount(); got != putsAfterFirst {
		t.Errorf("second run Put count = %d, want %d (cache hit must not re-store)", got, putsAfterFirst)
	}
	if cc.getCount() <= putsAfterFirst {
		t.Errorf("second run reads = %d, want a cache hit", cc.getCount())
	}
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("second run Outcome = %q, want completed", res2.Outcome)
	}
	if !res2.Truncated || !res2.StickyFlags[secretIntelOverflowFlag] {
		t.Errorf("second run flags = %v truncated %v, want overflow flag replayed from cache (never swallowed)", res2.StickyFlags, res2.Truncated)
	}
	if len(res2.Results.Secrets) != 64 {
		t.Errorf("second run secrets = %d, want the cached 64 candidates", len(res2.Results.Secrets))
	}
}

func TestFoldSecretIntelOutcomeTable(t *testing.T) {
	cases := []struct {
		name  string
		stats secrentel.DocumentStats
		want  pipeline.Outcome
	}{
		{"any cancelled beats everything", secrentel.DocumentStats{Cancelled: 1, Completed: 3}, pipeline.OutcomeCancelled},
		{"cancelled with failed", secrentel.DocumentStats{Cancelled: 1, Failed: 2}, pipeline.OutcomeCancelled},
		{"failed and no completed", secrentel.DocumentStats{Failed: 1}, pipeline.OutcomeFailed},
		{"failed with incomplete", secrentel.DocumentStats{Failed: 1, Incomplete: 1}, pipeline.OutcomeFailed},
		{"failed with cancelled", secrentel.DocumentStats{Failed: 1, Cancelled: 1}, pipeline.OutcomeCancelled},
		{"incomplete and no completed", secrentel.DocumentStats{Incomplete: 1}, pipeline.OutcomePartial},
		{"incomplete with cancelled", secrentel.DocumentStats{Incomplete: 1, Cancelled: 1}, pipeline.OutcomeCancelled},
		{"completed mixed with failed", secrentel.DocumentStats{Completed: 2, Failed: 1}, pipeline.OutcomePartial},
		{"completed mixed with incomplete", secrentel.DocumentStats{Completed: 2, Incomplete: 1}, pipeline.OutcomePartial},
		{"all completed", secrentel.DocumentStats{Completed: 3}, pipeline.OutcomeCompleted},
		{"empty report completes vacuously", secrentel.DocumentStats{}, pipeline.OutcomeCompleted},
		{"malformed-only completes vacuously with honest counters", secrentel.DocumentStats{Malformed: 5}, pipeline.OutcomeCompleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := foldSecretIntelOutcome(tc.stats); got != tc.want {
				t.Errorf("foldSecretIntelOutcome(%+v) = %q, want %q", tc.stats, got, tc.want)
			}
		})
	}
}

func TestSecretIntelThroughPipelineRun(t *testing.T) {
	// Full-pipeline integration: a fake jsintel producer emits documents
	// through the document channel; the secrentel stage consumes them; the
	// run report carries the final document channel AND the derived secret
	// candidates in its results channel. Deterministic across runs.
	d1 := scriptDocument(t, "https://cdn.example.com/app.js", `var k1 = "`+awsKey(20)+`";`)
	d2 := scriptDocument(t, "https://cdn.example.com/vendor.js", `var k2 = "`+awsKey(21)+`";`)
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageJSIntel, pipeline.StageSecretIntel},
	}
	clk := fixedClock{now: fixedTime}
	stages := func() []pipeline.Stage {
		return []pipeline.Stage{&jsDocProducer{docs: []pipeline.Document{d1, d2}}, NewSecretIntelStage(testSecretDB(t))}
	}
	r1, err := pipeline.Run(context.Background(), cfg, nil, clk, stages())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if !reflect.DeepEqual(r1.Documents, []pipeline.Document{d1, d2}) {
		t.Errorf("report.Documents = %+v, want [d1 d2]", r1.Documents)
	}
	if len(r1.Results.Secrets) != 2 {
		t.Fatalf("report.Results.Secrets = %d, want 2 (one per document)", len(r1.Results.Secrets))
	}
	if r1.Stages[0].Outcome != pipeline.OutcomeCompleted || r1.Stages[1].Outcome != pipeline.OutcomeCompleted {
		t.Errorf("stage outcomes = %q/%q, want completed/completed", r1.Stages[0].Outcome, r1.Stages[1].Outcome)
	}
	if r1.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", r1.Outcome)
	}
	if r1.Truncated || len(r1.StickyFlags) != 0 {
		t.Errorf("flags = %v truncated %v, want none", r1.StickyFlags, r1.Truncated)
	}
	r2, err := pipeline.Run(context.Background(), cfg, nil, clk, stages())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Errorf("runs differ:\n%+v\n%+v", r1, r2)
	}
}

// --- hermetic cache.Cache decorators (package-local) ---

// countingCache wraps a real cache.Cache and counts Get/Put calls, proving
// the cache-before-execute flow and the no-re-store-on-hit property.
type countingCache struct {
	cache.Cache
	mu   sync.Mutex
	gets int
	puts int
}

func (c *countingCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.Cache.Get(ctx, key)
}

func (c *countingCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	c.mu.Lock()
	c.puts++
	c.mu.Unlock()
	return c.Cache.Put(ctx, key, record)
}

func (c *countingCache) getCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets
}

func (c *countingCache) putCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}
