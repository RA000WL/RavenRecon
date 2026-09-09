package detect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// NEW-145 Slice 2 — engine parity + migration tests for the Slice 1
// SchemaVersion 3→4 change (fingerprintPriorFindings folds the full sorted
// prior metadata map and confidence alongside the finding identity).
//
// Harness: a level-0 producer P with a fixed-identity finding
// (slice2.producer @ the fixture subject) whose Metadata["signal"] is driven
// by a shared atomic, plus a consumer C (Deps:[P]) whose output branches on
// the prior Metadata["signal"] (it echoes it as Metadata["echo"]). Between
// runs the producer's Version is bumped 1.0.0→1.0.1 — a documented harness
// necessity, not a behavior under test: deterministic producers cannot
// change their output otherwise, and the rule-version bump is the supported
// contract for changing a rule's output. The snapshot and every finding
// identity stay identical across runs, so only the prior metadata edit can
// move the consumer's key.

// slice2ProducerDetector emits one fixed-identity finding whose signal
// metadata tracks the shared atomic. The finding is built through
// asset.NewFinding inline (never mutated afterwards) so the canonical
// round-trip in validateFinding holds on both the fresh and decode paths.
func slice2ProducerDetector(signal *atomic.Value, execs *int32) Detector {
	return func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(execs, 1)
		sig, _ := signal.Load().(string)
		subj := asset.Identity{Kind: asset.KindURL, Value: testSubjectURL}
		ev, err := asset.NewEvidence(asset.MethodDetection, "slice2.producer",
			"slice2 producer signal", subj, asset.Provenance{Source: "slice2-test"})
		if err != nil {
			return nil, err
		}
		f, err := asset.NewFinding(asset.Finding{
			RuleID:     "slice2.producer",
			RuleName:   "Rule slice2.producer",
			Category:   CategoryInformation.String(),
			Subject:    subj,
			Confidence: 0.5,
			Evidence:   []asset.Evidence{ev},
			Metadata:   map[string]string{"signal": sig},
			Priority:   PriorityMedium.String(),
			Status:     StatusOpen.String(),
			Created:    dctx.Clock.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}
}

// slice2ConsumerDetector branches on the prior Metadata["signal"]: it echoes
// the producer's signal into its own Metadata["echo"]. A stale cache hit
// would serve the previous run's echo; a recompute emits the current one.
func slice2ConsumerDetector(execs *int32) Detector {
	return func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(execs, 1)
		sig := ""
		for _, pf := range dctx.PriorFindings {
			if pf.RuleID == "slice2.producer" {
				sig = pf.Metadata["signal"]
			}
		}
		if sig == "" {
			return nil, errors.New("slice2: consumer saw no producer signal in PriorFindings")
		}
		subj := asset.Identity{Kind: asset.KindURL, Value: testSubjectURL}
		ev, err := asset.NewEvidence(asset.MethodDetection, "slice2.consumer",
			"slice2 consumer signal", subj, asset.Provenance{Source: "slice2-test"})
		if err != nil {
			return nil, err
		}
		f, err := asset.NewFinding(asset.Finding{
			RuleID:     "slice2.consumer",
			RuleName:   "Rule slice2.consumer",
			Category:   CategoryInformation.String(),
			Subject:    subj,
			Confidence: 0.5,
			Evidence:   []asset.Evidence{ev},
			Metadata:   map[string]string{"echo": sig},
			Priority:   PriorityMedium.String(),
			Status:     StatusOpen.String(),
			Created:    dctx.Clock.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}
}

// slice2ConsumerEcho returns the consumer finding's echo metadata from a
// report (exactly one consumer finding per run by construction).
func slice2ConsumerEcho(t *testing.T, rep Report) string {
	t.Helper()
	for _, f := range rep.Findings {
		if f.RuleID == "slice2.consumer" {
			return f.Metadata["echo"]
		}
	}
	t.Fatalf("consumer finding missing from the report (%d findings)", len(rep.Findings))
	return ""
}

// TestSlice2MetadataEditRecomputesConsumer pins T1: a metadata-only prior
// edit (same snapshot, same finding identities) must invalidate the
// dependent's cached result. Pre-fix (identity-only prior digest) run 2
// would stale-hit the consumer (Cached==true, echo v1); post-fix it must
// recompute (Cached==false, echo v2).
func TestSlice2MetadataEditRecomputesConsumer(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var execP, execC int32
	var signal atomic.Value
	signal.Store("v1")
	snap := testSnapshot(t)

	prodV1 := makeRule(t, "slice2.producer", &ruleOptions{
		detector: slice2ProducerDetector(&signal, &execP),
	})
	cons := makeRule(t, "slice2.consumer", &ruleOptions{
		deps:     []string{"slice2.producer"},
		detector: slice2ConsumerDetector(&execC),
	})

	cfg1 := DefaultEngineConfig(newTestRegistry(t, prodV1, cons))
	cfg1.Cache = fs
	rep1, err := Run(context.Background(), cfg1, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	if rep1.CacheHits != 0 {
		t.Fatalf("cold run served %d cache hits, want 0", rep1.CacheHits)
	}
	if atomic.LoadInt32(&execP) != 1 || atomic.LoadInt32(&execC) != 1 {
		t.Fatalf("cold executions producer=%d consumer=%d, want 1/1",
			atomic.LoadInt32(&execP), atomic.LoadInt32(&execC))
	}
	o1 := slice2ConsumerEcho(t, rep1)
	if o1 != "v1" {
		t.Fatalf("cold consumer echo %q, want v1", o1)
	}

	// Metadata-only prior edit: the producer emits signal v2 under the same
	// finding identity and snapshot. The Version bump is the documented
	// harness necessity — a deterministic producer cannot change its output
	// without one, and the version enters the producer's own key by
	// contract — so the producer re-executes and the consumer's prior
	// digest is the only remaining variable under test.
	signal.Store("v2")
	prodV2 := makeRule(t, "slice2.producer", &ruleOptions{
		detector: slice2ProducerDetector(&signal, &execP),
		version:  "1.0.1",
	})
	cfg2 := DefaultEngineConfig(newTestRegistry(t, prodV2, cons))
	cfg2.Cache = fs
	rep2, err := Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("metadata-edit Run: %v", err)
	}

	rP := resultOf(t, rep2, "slice2.producer")
	if rP.Cached {
		t.Fatalf("bumped producer must re-execute, was served cached: %+v", rP)
	}
	rC := resultOf(t, rep2, "slice2.consumer")
	if rC.Cached {
		t.Fatalf("consumer served STALE cached output after a metadata-only prior edit: %+v (a stale hit here is the pre-fix bug)", rC)
	}
	if atomic.LoadInt32(&execP) != 2 {
		t.Fatalf("producer executions %d, want 2 (version bump must re-execute)", atomic.LoadInt32(&execP))
	}
	if atomic.LoadInt32(&execC) != 2 {
		t.Fatalf("consumer executions %d, want 2 (metadata edit must recompute, not hit)", atomic.LoadInt32(&execC))
	}
	o2 := slice2ConsumerEcho(t, rep2)
	if o2 == o1 {
		t.Fatalf("consumer output unchanged after the prior metadata edit (echo %q): stale result served", o2)
	}
	if o2 != "v2" {
		t.Fatalf("warm consumer echo %q, want v2 (the recomputed judgment)", o2)
	}
}

// TestSlice2IdenticalRunsHit pins T2: two identical P+C runs share every
// cache result — run 2 serves CacheHits==attempted with zero executions.
func TestSlice2IdenticalRunsHit(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var execP, execC int32
	var signal atomic.Value
	signal.Store("v1")
	snap := testSnapshot(t)
	reg := newTestRegistry(t,
		makeRule(t, "slice2.producer", &ruleOptions{
			detector: slice2ProducerDetector(&signal, &execP),
		}),
		makeRule(t, "slice2.consumer", &ruleOptions{
			deps:     []string{"slice2.producer"},
			detector: slice2ConsumerDetector(&execC),
		}),
	)
	run := func() Report {
		cfg := DefaultEngineConfig(reg)
		cfg.Cache = fs
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	rep1 := run()
	if rep1.CacheHits != 0 {
		t.Fatalf("cold run served %d cache hits, want 0", rep1.CacheHits)
	}
	rep2 := run()
	attempted := len(rep2.Rules) - rep2.Skipped
	if attempted != 2 {
		t.Fatalf("attempted %d, want 2 (no rule may skip in this harness)", attempted)
	}
	if rep2.CacheHits != attempted {
		t.Fatalf("warm cache hits %d, want %d (every attempted rule)", rep2.CacheHits, attempted)
	}
	if atomic.LoadInt32(&execP) != 1 || atomic.LoadInt32(&execC) != 1 {
		t.Fatalf("warm run executed: producer=%d consumer=%d, want 1/1 (zero warm executions)",
			atomic.LoadInt32(&execP), atomic.LoadInt32(&execC))
	}
	for _, id := range []string{"slice2.producer", "slice2.consumer"} {
		if r := resultOf(t, rep2, id); !r.Cached || r.Status != RuleStatusCompleted {
			t.Fatalf("warm rule %q must be cache-served completed: %+v", id, r)
		}
	}
	if len(rep2.Findings) != len(rep1.Findings) {
		t.Fatalf("warm findings %d vs cold %d", len(rep2.Findings), len(rep1.Findings))
	}
	for i := range rep2.Findings {
		if rep2.Findings[i].ID() != rep1.Findings[i].ID() {
			t.Fatalf("finding %d ID drift: warm %s cold %s", i, rep2.Findings[i].ID(), rep1.Findings[i].ID())
		}
	}
}

// TestSlice2OldPayloadVersionEvicted pins T5: a hand-crafted version-3
// payload stored under the CURRENT (version-4) key shape must be
// decode-rejected, evicted, and recomputed in the same run — never served.
// The stale payload carries zero findings while a fresh execution emits
// one, so serving it would be observable as a missing finding.
func TestSlice2OldPayloadVersionEvicted(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	rule := makeRule(t, "slice2.migrated", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "slice2.migrated", "Rule slice2.migrated", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg := newTestRegistry(t, rule)
	snap := testSnapshot(t)

	// Compute the current key shape exactly as the engine does (mirroring
	// TestRunTamperedCacheRecordRecomputed): snapshot fingerprint plus the
	// level-0 graph digest (no priors yet).
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fp, err := fingerprintSnapshot(corpus)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	key, err := ruleKey(rule, fp, fingerprintGraph(corpus.context.Relationships), nil)
	if err != nil {
		t.Fatalf("ruleKey: %v", err)
	}

	// Hand-crafted version-3 payload under the new key shape: the envelope
	// is valid (cache.SchemaVersion, completed, this operation/target) so
	// the cache reports a hit, but the detect payload version predates
	// SchemaVersion 4 and must be rejected at decode. Empty findings make
	// serving observable: a fresh execution emits one finding.
	stale := cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        "rule:slice2.migrated",
		Status:        cache.StatusCompleted,
		CreatedAt:     time.Now().UTC(),
		Data:          json.RawMessage(`{"version":3,"findings":[]}`),
	}
	if err := fs.Put(context.Background(), key, stale); err != nil {
		t.Fatalf("seed stale v3 record: %v", err)
	}

	cfg := DefaultEngineConfig(reg)
	cfg.Cache = fs
	rep, err := Run(context.Background(), cfg, snap)
	if err == nil || !strings.Contains(err.Error(), "cache hit rejected") {
		t.Fatalf("old-version record must surface as a cache-hit-rejected diagnostic: %v", err)
	}
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("old-version record must be evicted and recomputed: %d executions", executions)
	}
	r := resultOf(t, rep, "slice2.migrated")
	if r.Cached || r.Status != RuleStatusCompleted || r.Findings != 1 {
		t.Fatalf("recomputed result wrong (stale v3 payload must never serve): %+v", r)
	}
	if rep.CacheHits != 0 {
		t.Fatalf("cache hits %d, want 0 (the v3 record is a miss by version)", rep.CacheHits)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings %d, want 1 (the stale empty payload must not be served)", len(rep.Findings))
	}

	// The old record is gone: the key now holds the freshly stored
	// version-4 record, decodable through the strict decode path.
	out := fs.Get(context.Background(), key)
	if out.State != cache.StateHit || out.Record == nil {
		t.Fatalf("post-run Get state %s (want a hit on the fresh record)", out.State)
	}
	var payload struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(out.Record.Data, &payload); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	if payload.Version != SchemaVersion {
		t.Fatalf("stored payload version %d, want %d (the v3 record must be evicted, never retained)",
			payload.Version, SchemaVersion)
	}
	if _, err := decodeStoredFindings(*out.Record, rule, corpus.observed); err != nil {
		t.Fatalf("fresh record must decode strictly: %v", err)
	}
}
