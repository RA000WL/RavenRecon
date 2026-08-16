package priority

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// engineClockFake is the deterministic runtime.Clock seam for engine runs.
type engineClockFake struct {
	mu  sync.Mutex
	now time.Time
}

func newEngineClock() *engineClockFake {
	return &engineClockFake{now: time.Unix(1700000000, 0).UTC()}
}

func (c *engineClockFake) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *engineClockFake) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	t := c.now.Add(d)
	c.mu.Unlock()
	ch <- t
	return ch
}

func openEngineCache(t *testing.T) *cache.FS {
	t.Helper()
	c, err := cache.Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

func engineCfg() EngineConfig {
	return EngineConfig{Concurrency: 4, QueueSize: 64}
}

// feedSignals feeds signals into a channel and closes it.
func feedSignals(sigs []Signal) chan Signal {
	ch := make(chan Signal, len(sigs))
	for _, s := range sigs {
		ch <- s
	}
	close(ch)
	return ch
}

func engineSignals() []Signal {
	base := func(i int) Signal {
		return Signal{
			Identity: asset.Identity{
				Kind:  asset.KindURL,
				Value: fmt.Sprintf("https://www.example.com/api/v2/admin/item%03d", i),
			},
			Kind:     asset.KindURL,
			Path:     "/api/v2/admin",
			Hostname: "www.example.com",
			ScoredAt: fixedTime(30),
		}
	}
	out := make([]Signal, 0, 6)
	for i := 0; i < 6; i++ {
		s := base(i)
		switch i % 3 {
		case 0:
			s.Technologies = []TechSignal{{Name: "auth0", Category: "authentication", Confidence: 0.9, Identity: "authentication/auth0"}}
		case 1:
			s.Secrets = []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: 0.85, Identity: "secret_candidate:aws/x/y"}}
		}
		out = append(out, s)
	}
	return out
}

func TestEngineFreshRun(t *testing.T) {
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	rep, err := Score(context.Background(), cfg, feedSignals(engineSignals()))
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Errorf("outcome = %s, want completed", rep.Outcome)
	}
	if rep.Completed != 6 || rep.Failed != 0 || rep.Cancelled != 0 {
		t.Errorf("counts = %d/%d/%d", rep.Completed, rep.Failed, rep.Cancelled)
	}
	if len(rep.Assets) != 6 {
		t.Fatalf("assets = %d, want 6", len(rep.Assets))
	}
	for i := 1; i < len(rep.Assets); i++ {
		if rep.Assets[i-1].Identity.String() >= rep.Assets[i].Identity.String() {
			t.Errorf("results not sorted by identity: %q >= %q", rep.Assets[i-1].Identity, rep.Assets[i].Identity)
		}
	}
	for _, r := range rep.Assets {
		if r.Status != StatusCompleted || r.Surface == nil || r.Cached {
			t.Errorf("result %+v is not a fresh completed surface", r)
		}
		if r.Surface.ScoredAt != fixedTime(30) {
			t.Errorf("explicit ScoredAt must be echoed, got %v", r.Surface.ScoredAt)
		}
	}
}

func TestEngineDeterministicAcrossRuns(t *testing.T) {
	run := func() string {
		cfg := engineCfg()
		cfg.Clock = newEngineClock()
		rep, err := Score(context.Background(), cfg, feedSignals(engineSignals()))
		if err != nil {
			t.Fatal(err)
		}
		buf, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf)
	}
	if run() != run() {
		t.Error("two identical engine runs must produce identical report bytes")
	}
}

// TestEngineCacheRoundTrip pins the warm-cache contract: a cold run stores
// every completed record; a warm run over the same signals serves every
// surface from validated cache hits (ZERO scorings) with bit-identical
// results.
func TestEngineCacheRoundTrip(t *testing.T) {
	fs := openEngineCache(t)
	ic, rc := mustCatalogs(t)
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	cfg.Cache = fs
	cfg.Interesting, cfg.Risk = ic, rc

	var coldMetrics Metrics
	coldCfg := cfg
	coldCfg.Metrics = &coldMetrics
	cold, err := Score(context.Background(), coldCfg, feedSignals(engineSignals()))
	if err != nil {
		t.Fatal(err)
	}
	if m := coldMetrics.Snapshot(); m.Scored != 6 || m.CacheStores != 6 || m.CacheHits != 0 {
		t.Errorf("cold metrics = %+v, want 6 scored/stored, 0 hits", m)
	}

	var warmMetrics Metrics
	warmCfg := cfg
	warmCfg.Metrics = &warmMetrics
	warm, err := Score(context.Background(), warmCfg, feedSignals(engineSignals()))
	if err != nil {
		t.Fatal(err)
	}
	if m := warmMetrics.Snapshot(); m.Scored != 0 || m.CacheHits != 6 {
		t.Errorf("warm metrics = %+v, want 0 scored, 6 hits", m)
	}
	if len(warm.Assets) != len(cold.Assets) {
		t.Fatalf("warm assets = %d, cold = %d", len(warm.Assets), len(cold.Assets))
	}
	for i := range warm.Assets {
		if !warm.Assets[i].Cached {
			t.Errorf("warm result %d was not served from cache", i)
		}
		if !reflect.DeepEqual(warm.Assets[i].Surface, cold.Assets[i].Surface) {
			t.Errorf("warm surface %d differs from cold:\n%+v\n%+v", i, warm.Assets[i].Surface, cold.Assets[i].Surface)
		}
	}
	// Determinism includes the warm path: two warm runs are byte-identical.
	warm2, _ := Score(context.Background(), cfg, feedSignals(engineSignals()))
	a, _ := json.Marshal(warm)
	b, _ := json.Marshal(warm2)
	if string(a) != string(b) {
		t.Error("two warm runs must produce identical report bytes")
	}
}

// tamper writes a corrupted-but-wellformed record under the exact key the
// engine computes for sig, simulating an on-disk tamper or corruption.
func tamper(t *testing.T, fs *cache.FS, sig Signal, mutate func(*storedSurface)) cache.Key {
	t.Helper()
	ic, rc := mustCatalogs(t)
	digest := CatalogsDigest(ic, rc)
	key, err := priorityKey(sig, digest)
	if err != nil {
		t.Fatal(err)
	}
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	cfg.Interesting, cfg.Risk = ic, rc
	surface, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	st := storedSurface{Version: SchemaVersion, Surface: surface}
	mutate(&st)
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Put(context.Background(), key, cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        sig.Identity.String(),
		Status:        cache.StatusCompleted,
		CreatedAt:     time.Now().UTC(),
		Data:          data,
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestEngineTamperedCacheRowsEvicted pins the strict decode contract: a
// completed record that fails ANY re-validation check is treated as a
// miss, EVICTED, and recomputed in the same run — never served, never a
// panic (the eviction surfaces as a bounded run diagnostic). Corruption
// shapes: an unparseable level, an out-of-range factor weight (the
// JSON-encodable sibling of the NaN-weight shape — encoding/json refuses
// to serialize NaN, so a NaN payload is classified corrupt by the cache
// layer before the engine ever decodes it; the NaN guard itself is pinned
// in TestValidateSurfaceInvariants), a truncated factor list contradicting
// the stored score, and a record whose identity does not match the signal
// it was keyed for.
func TestEngineTamperedCacheRowsEvicted(t *testing.T) {
	base := engineSignals()[0]
	shapes := []struct {
		name   string
		mutate func(*storedSurface)
	}{
		{"bad level", func(st *storedSurface) {
			st.Surface.Level = PriorityLevel("critical")
		}},
		{"out-of-range factor weight", func(st *storedSurface) {
			st.Surface.Factors[0].Weight = 5
		}},
		{"truncated factor list", func(st *storedSurface) {
			st.Surface.Factors = st.Surface.Factors[:1]
		}},
		{"record identity mismatch", func(st *storedSurface) {
			st.Surface.Identity = asset.Identity{Kind: asset.KindURL, Value: "https://other.example.com/x"}
			st.Surface.Kind = asset.KindURL
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			fs := openEngineCache(t)
			key := tamper(t, fs, base, shape.mutate)

			var metrics Metrics
			cfg := engineCfg()
			cfg.Clock = newEngineClock()
			cfg.Cache = fs
			cfg.Metrics = &metrics
			rep, err := Score(context.Background(), cfg, feedSignals([]Signal{base}))
			if err == nil || !strings.Contains(err.Error(), "hit rejected") {
				t.Fatalf("the eviction must surface as a run diagnostic, got %v", err)
			}
			if rep.Outcome != OutcomeCompleted || len(rep.Assets) != 1 {
				t.Fatalf("report = %+v", rep)
			}
			r := rep.Assets[0]
			if r.Status != StatusCompleted || r.Cached {
				t.Errorf("tampered row must be recomputed fresh, got %+v", r)
			}
			if m := metrics.Snapshot(); m.Scored != 1 || m.Evictions != 1 {
				t.Errorf("metrics = %+v, want one fresh score and one eviction", m)
			}
			// The tampered row is gone: whatever is under the key now is
			// the recomputed record, which decodes cleanly.
			out := fs.Get(context.Background(), key)
			if !out.IsHit() {
				t.Fatalf("post-run record state = %s, want a re-stored hit", out.State)
			}
			if _, err := decodeStoredSurface(*out.Record, base); err != nil {
				t.Errorf("re-stored record must decode cleanly: %v", err)
			}
		})
	}
}

// TestEngineInvalidSignals pin the per-asset structured errors: an invalid
// signal produces a failed result carrying its error (never a panic), a
// mixed run reports incomplete, and an all-failed run reports failed.
func TestEngineInvalidSignals(t *testing.T) {
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	bad := Signal{Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/x"}, Kind: asset.KindURL, Port: 70000}
	good := engineSignals()[0]
	rep, err := Score(context.Background(), cfg, feedSignals([]Signal{bad, good}))
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if rep.Outcome != OutcomeIncomplete {
		t.Errorf("mixed outcome = %s, want incomplete", rep.Outcome)
	}
	if rep.Completed != 1 || rep.Failed != 1 {
		t.Errorf("counts = %d/%d", rep.Completed, rep.Failed)
	}
	var failed *AssetResult
	for i := range rep.Assets {
		if rep.Assets[i].Status == StatusFailed {
			failed = &rep.Assets[i]
		}
	}
	if failed == nil || failed.Err == nil || !strings.Contains(failed.Err.Error(), "port") {
		t.Errorf("failed result must carry a structured error naming the field: %+v", failed)
	}

	allBad, err := Score(context.Background(), cfg, feedSignals([]Signal{bad}))
	if err != nil {
		t.Fatal(err)
	}
	if allBad.Outcome != OutcomeFailed {
		t.Errorf("all-failed outcome = %s, want failed", allBad.Outcome)
	}

	empty, err := Score(context.Background(), cfg, feedSignals(nil))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Outcome != OutcomeCompleted || len(empty.Assets) != 0 {
		t.Errorf("empty run = %+v, want completed with no assets", empty)
	}
}

// blockingProducer feeds its signals, then holds the channel open without
// sending (a stalled upstream) until the run context is cancelled.
type blockingProducer struct {
	sigs []Signal
	ctx  context.Context
}

func (p *blockingProducer) run(ch chan Signal) {
	for _, s := range p.sigs {
		select {
		case ch <- s:
		case <-p.ctx.Done():
			return
		}
	}
	<-p.ctx.Done() // stall: channel open, nothing more arriving
}

// TestEngineCancellation pins honest cancellation: with a rate-gated pool
// (work provably still queued at cancellation time) and a stalled
// producer, the engine unwinds, reports cancelled work, and leaves no
// goroutines behind.
func TestEngineCancellation(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 600 distinct signals; the pool's central limiter (2000 starts/s)
	// guarantees most jobs are still queued when the context is cancelled
	// ~10 ms in — the cancellation lands mid-run by construction.
	var sigs []Signal
	for i := 0; i < 600; i++ {
		sigs = append(sigs, Signal{
			Identity: asset.Identity{
				Kind:  asset.KindURL,
				Value: fmt.Sprintf("https://www.example.com/item%04d", i),
			},
			Kind:     asset.KindURL,
			Path:     "/api/v2/admin",
			Hostname: "www.example.com",
			ScoredAt: fixedTime(30),
		})
	}
	prod := &blockingProducer{sigs: sigs, ctx: ctx}
	ch := make(chan Signal, 8)
	go prod.run(ch)
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	cfg := EngineConfig{Concurrency: 4, QueueSize: 128, Rate: 2000, Burst: 1}
	rep, err := Score(ctx, cfg, ch)
	if err != nil {
		t.Fatalf("Score with cancelled context: %v", err)
	}
	if rep.Outcome != OutcomeCancelled {
		t.Errorf("outcome = %s, want cancelled", rep.Outcome)
	}
	if rep.Cancelled < 1 {
		t.Errorf("cancelled = %d, want >= 1 (work provably queued at cancellation)", rep.Cancelled)
	}
	if total := rep.Completed + rep.Cancelled + rep.Failed; total < 1 || total > len(sigs) {
		t.Errorf("honest accounting: total %d out of bounds", total)
	}

	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine leak after cancellation: before %d, after %d", before, after)
	}
}

func TestEngineNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	_, _ = Score(context.Background(), cfg, feedSignals(engineSignals()))
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine leak: before %d, after %d", before, after)
	}
}

// TestEngineConcurrentRaceRun is the engine-level race surface: a large
// mixed batch through bounded workers with a shared cache, metrics, and
// duplicate identities — meaningful under -race.
func TestEngineConcurrentRaceRun(t *testing.T) {
	fs := openEngineCache(t)
	cfg := EngineConfig{Concurrency: 8, QueueSize: 128, Clock: newEngineClock(), Cache: fs}
	var sigs []Signal
	for i := 0; i < 200; i++ {
		s := engineSignals()[i%len(engineSignals())]
		if i%7 == 0 {
			// Duplicate identities with DIFFERENT signals exercise the
			// deterministic merge under concurrency.
			s.ParameterNames = []string{"query"}
		}
		sigs = append(sigs, s)
	}
	rep, err := Score(context.Background(), cfg, feedSignals(sigs))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Completed+rep.Failed+rep.Cancelled != len(rep.Assets) {
		t.Errorf("accounting mismatch: %+v", rep)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Errorf("outcome = %s, want completed", rep.Outcome)
	}
}

// TestEngineDuplicateIdentityMergesDeterministically pins the merge rule:
// the same identity scored twice with different signals keeps exactly one
// result — the higher-scoring surface, ties by serialized bytes — and the
// choice is identical across runs regardless of processing order.
func TestEngineDuplicateIdentityMergesDeterministically(t *testing.T) {
	id := asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/admin"}
	weak := Signal{Identity: id, Kind: asset.KindURL, Path: "/admin", ScoredAt: fixedTime(1)}
	strong := Signal{
		Identity: id, Kind: asset.KindURL, Path: "/admin",
		Secrets:  []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: 0.9, Identity: "secret_candidate:aws/x/y"}},
		ScoredAt: fixedTime(1),
	}
	run := func(order []Signal) SurfaceAsset {
		cfg := engineCfg()
		cfg.Clock = newEngineClock()
		rep, err := Score(context.Background(), cfg, feedSignals(order))
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Assets) != 1 || rep.Assets[0].Status != StatusCompleted {
			t.Fatalf("duplicate identity must yield one completed result: %+v", rep.Assets)
		}
		return *rep.Assets[0].Surface
	}
	a := run([]Signal{weak, strong})
	b := run([]Signal{strong, weak})
	if !reflect.DeepEqual(a, b) {
		t.Error("merge result must not depend on submission order")
	}
	if a.Score <= 0 {
		t.Errorf("merged score = %v, want the stronger surface's score > 0", a.Score)
	}
}

// TestEngineCacheBypassForNonCanonicalIdentity pins the documented bypass:
// a signal whose identity does not re-parse canonically is still scored
// (the Round-1 contract), but the engine performs no cache read and no
// store for it.
func TestEngineCacheBypassForNonCanonicalIdentity(t *testing.T) {
	fs := openEngineCache(t)
	sig := Signal{
		Identity: asset.Identity{Kind: asset.KindURL, Value: "not a url"},
		Kind:     asset.KindURL,
		ScoredAt: fixedTime(1),
	}
	var metrics Metrics
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	cfg.Cache = fs
	cfg.Metrics = &metrics
	rep, err := Score(context.Background(), cfg, feedSignals([]Signal{sig}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != OutcomeCompleted || rep.Assets[0].Status != StatusCompleted {
		t.Fatalf("non-canonical signal must still score: %+v", rep)
	}
	if m := metrics.Snapshot(); m.CacheReads != 0 || m.CacheStores != 0 || m.Scored != 1 {
		t.Errorf("non-canonical identity must bypass the cache entirely: %+v", m)
	}
}

// TestEngineEmitHook pins the emit-hook contract: every completed surface
// is emitted exactly once, and a PANICKING hook is contained — the run
// completes with every asset accounted for, the panic surfaces as a
// bounded run diagnostic, and nothing crashes the process.
//
// The panic branch is made genuinely reachable by a canonical sentinel
// identity: the hook panics on that one value, and the run feeds it
// alongside the healthy fixtures (validateSignal rejects empty-value
// identities, so the sentinel must be — and is — a real canonical asset).
func TestEngineEmitHook(t *testing.T) {
	const panicValue = "https://www.example.com/emit-panic"
	var mu sync.Mutex
	var emitted []SurfaceAsset
	hook := func(_ context.Context, s SurfaceAsset) error {
		if s.Identity.Value == panicValue {
			panic("emit hook panic path")
		}
		mu.Lock()
		emitted = append(emitted, s)
		mu.Unlock()
		return nil
	}

	// Healthy path: every completed surface is emitted exactly once.
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	cfg.Emit = hook
	rep, err := Score(context.Background(), cfg, feedSignals(engineSignals()))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(emitted) != rep.Completed {
		t.Errorf("emitted %d surfaces, want %d", len(emitted), rep.Completed)
	}
	mu.Unlock()

	// Panic containment: one canonical sentinel surface whose emit path
	// panics, alongside the healthy ones.
	sentinel := Signal{
		Identity: asset.Identity{Kind: asset.KindURL, Value: panicValue},
		Kind:     asset.KindURL, Path: "/emit-panic",
		ScoredAt: fixedTime(30),
	}
	sigs := append(engineSignals(), sentinel)
	mu.Lock()
	emitted = nil
	mu.Unlock()
	rep, err = Score(context.Background(), cfg, feedSignals(sigs))
	if err == nil || !strings.Contains(err.Error(), "emit hook panicked: emit hook panic path") {
		t.Fatalf("contained panic must surface as a run diagnostic, got %v", err)
	}
	if n := strings.Count(err.Error(), "emit hook panicked"); n != 1 {
		t.Errorf("panic diagnostic must be bounded: %d occurrences in %q", n, err)
	}
	if rep.Outcome != OutcomeCompleted || rep.Completed != len(sigs) {
		t.Errorf("a contained emit panic must not fail the assets: outcome %s, completed %d (want %d)",
			rep.Outcome, rep.Completed, len(sigs))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != rep.Completed-1 {
		t.Errorf("emitted %d surfaces, want %d (the panicking one contained)", len(emitted), rep.Completed-1)
	}
}

func TestEngineConfigValidation(t *testing.T) {
	if _, err := Score(context.Background(), EngineConfig{}, feedSignals(nil)); err == nil || !strings.Contains(err.Error(), "Concurrency") {
		t.Errorf("zero concurrency must fail: %v", err)
	}
	if _, err := Score(context.Background(), EngineConfig{Concurrency: 4}, feedSignals(nil)); err == nil || !strings.Contains(err.Error(), "QueueSize") {
		t.Errorf("zero queue must fail: %v", err)
	}
	cfg := engineCfg()
	cfg.Timeout = -1
	if _, err := Score(context.Background(), cfg, feedSignals(nil)); err == nil || !strings.Contains(err.Error(), "Timeout") {
		t.Errorf("negative timeout must fail: %v", err)
	}
	if _, err := Score(context.Background(), engineCfg(), nil); err == nil || !strings.Contains(err.Error(), "nil signal channel") {
		t.Errorf("nil channel must fail: %v", err)
	}
}
