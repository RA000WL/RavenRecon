package priority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Engine defaults and bounds (fixed constants).
const (
	// defaultEngineConcurrency is the default worker count.
	defaultEngineConcurrency = 8
	// defaultEngineQueueSize is the default bounded queue size.
	defaultEngineQueueSize = 256
	// maxEngineDiagnostics bounds the run-level diagnostics the engine
	// retains.
	maxEngineDiagnostics = 32
)

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a completed score). Mirrors the
// convention shared by the other cache-consuming stages.
const storeTimeout = 5 * time.Second

// shutdownGrace / shutdownForceBudget bound Shutdown's drain, mirroring
// the convention shared by the other runtime consumers.
const (
	shutdownGrace       = 15 * time.Second
	shutdownForceBudget = 30 * time.Second
)

// Status is the per-asset outcome of one engine run. It uses the house
// outcome vocabulary; a scored asset is completed (fresh or cache-served),
// an unscorable asset is failed (its structured error is attached), and an
// asset whose work never executed is cancelled. The vocabulary's
// "partial"/"incomplete" members surface at RUN level (see Outcome): a run
// with both completed and failed assets is incomplete — truncated work is
// never reported completed.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Outcome is the aggregate outcome of one engine run, derived from the
// per-asset statuses in fixed priority order: any cancelled asset →
// cancelled; any failed asset alongside completed ones → incomplete
// (partial — the successes are kept and reported, the run is not
// completed); every attempted asset failed → failed; otherwise completed.
// An empty run is completed (zero assets, nothing attempted).
type Outcome string

const (
	OutcomeCompleted  Outcome = "completed"
	OutcomeIncomplete Outcome = "incomplete"
	OutcomeFailed     Outcome = "failed"
	OutcomeCancelled  Outcome = "cancelled"
)

// AssetResult is one scored asset's honest outcome.
type AssetResult struct {
	// Identity is the canonical identity of the scored asset.
	Identity asset.Identity `json:"identity"`

	// Status is the per-asset outcome.
	Status Status `json:"status"`

	// Surface is the scored surface; nil unless Status is completed.
	Surface *SurfaceAsset `json:"surface,omitempty"`

	// Cached reports that the surface was served from a validated cache
	// hit (zero scoring performed).
	Cached bool `json:"cached,omitempty"`

	// Err carries the structured per-asset error for failed assets.
	Err error `json:"-"`
}

// Report is the deterministic result of one engine run: every asset's
// outcome sorted by identity, the counts, and the aggregate outcome.
type Report struct {
	// Outcome is the aggregate run outcome (see Outcome).
	Outcome Outcome `json:"outcome"`

	// Assets holds one result per distinct input identity, sorted by
	// identity string.
	Assets []AssetResult `json:"assets"`

	// Completed, Failed, and Cancelled count the per-asset statuses.
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`

	// Scored counts fresh scorings performed; CacheHits counts validated
	// cache hits served.
	Scored    int `json:"scored"`
	CacheHits int `json:"cache_hits"`
}

// Metrics accumulates the run's work counters. It is safe for concurrent
// use; a nil *Metrics is a no-op.
type Metrics struct {
	mu        sync.Mutex
	signals   int
	scored    int
	reads     int
	stores    int
	hits      int
	evictions int
}

// MetricsSnapshot is a consistent point-in-time copy of the counters.
type MetricsSnapshot struct {
	Signals     int
	Scored      int
	CacheReads  int
	CacheStores int
	CacheHits   int
	Evictions   int
}

func (m *Metrics) add(f func(*MetricsSnapshot)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snapshotLocked()
	f(&s)
	m.signals, m.scored, m.reads, m.stores = s.Signals, s.Scored, s.CacheReads, s.CacheStores
	m.hits, m.evictions = s.CacheHits, s.Evictions
}

func (m *Metrics) snapshotLocked() MetricsSnapshot {
	return MetricsSnapshot{
		Signals: m.signals, Scored: m.scored, CacheReads: m.reads,
		CacheStores: m.stores, CacheHits: m.hits, Evictions: m.evictions,
	}
}

// Snapshot returns a consistent copy of the counters. A nil Metrics
// snapshots as all zeros.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

// EngineConfig configures one engine run. Numeric fields are validated;
// invalid values are rejected with an error rather than silently
// normalized (mirroring the other runtime consumers).
type EngineConfig struct {
	// Concurrency is the exact worker count. Must be > 0; default 8.
	Concurrency int
	// QueueSize is the bounded reader→worker queue. Must be > 0; the
	// reader blocks on a full queue (backpressure, never unbounded
	// memory). Default 256.
	QueueSize int
	// Timeout is the per-signal deadline; 0 means no deadline.
	Timeout time.Duration
	// Rate is the optional per-job start rate limit (jobs/sec) honored
	// through the pool's central limiter; 0 disables.
	Rate float64
	// Burst is the rate limiter burst size; values below 1 normalize to 1.
	Burst int
	// Clock is the injectable time seam (score timestamps and cache record
	// stamps); nil uses the wall clock.
	Clock runtime.Clock
	// Cache is the Phase 3 cache. When nil, cache-before-execute is
	// disabled and every signal is scored fresh.
	Cache cache.Cache
	// Interesting and Risk are the compiled catalogs. When nil, Score
	// loads the production tables (the compile-once contract: the engine
	// NEVER compiles its own regular expressions).
	Interesting, Risk *Catalog
	// Emit, when non-nil, is called once per PROCESSED surface (fresh or
	// cache-served). Panics inside Emit are contained and reported as run
	// diagnostics.
	Emit func(context.Context, SurfaceAsset) error
	// Metrics, when non-nil, accumulates the run's work counters.
	Metrics *Metrics
}

// DefaultEngineConfig returns the documented default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Concurrency: defaultEngineConcurrency,
		QueueSize:   defaultEngineQueueSize,
	}
}

func (c EngineConfig) validateAndDefault() (*EngineConfig, error) {
	if c.Concurrency <= 0 {
		return nil, fmt.Errorf("priority: Concurrency must be > 0")
	}
	if c.QueueSize <= 0 {
		return nil, fmt.Errorf("priority: QueueSize must be > 0")
	}
	if c.Timeout < 0 {
		return nil, fmt.Errorf("priority: Timeout must be >= 0")
	}
	d := c
	if d.Clock == nil {
		d.Clock = engineClock{}
	}
	if d.Interesting == nil {
		ic, err := LoadInterestingness()
		if err != nil {
			return nil, fmt.Errorf("priority: load interestingness catalog: %w", err)
		}
		d.Interesting = ic
	}
	if d.Risk == nil {
		rc, err := LoadRisk()
		if err != nil {
			return nil, fmt.Errorf("priority: load risk catalog: %w", err)
		}
		d.Risk = rc
	}
	return &d, nil
}

// env is the immutable per-run environment shared by the reader and every
// worker.
type env struct {
	interesting *Catalog
	risk        *Catalog
	digest      string
	cache       cache.Cache
	clock       runtime.Clock
	metrics     *Metrics

	errMu  sync.Mutex
	diags  []error
	excess int
}

func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < maxEngineDiagnostics {
		e.diags = append(e.diags, err)
	} else {
		e.excess++
	}
}

func (e *env) runError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) == 0 && e.excess == 0 {
		return nil
	}
	msgs := make([]string, 0, len(e.diags)+1)
	for _, d := range e.diags {
		msgs = append(msgs, d.Error())
	}
	if e.excess > 0 {
		msgs = append(msgs, fmt.Sprintf("... and %d more diagnostics suppressed", e.excess))
	}
	return errors.New("priority: " + joinStrings(msgs, "; "))
}

func joinStrings(msgs []string, sep string) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += sep
		}
		out += m
	}
	return out
}

func (e *env) recordCacheDiagnostic(op string, err error) {
	if err == nil {
		return
	}
	e.recordErr(fmt.Errorf("priority: cache %s: %w", op, err))
}

// Score runs one prioritization pass over the signal channel: for each
// signal — validate → cache-before-execute (a validated hit serves the
// stored surface with ZERO scoring) → score → store → report. The engine
// is the cache-composing consumer stage per the architecture rule: the
// runtime pool stays cache-independent, and THIS stage performs the
// lookup → score → store sequencing around pool jobs.
//
// Signals whose identity is not canonically parseable (see
// validateCanonicalIdentity) are still scored — the Round-1 ScoreSurface
// contract is unchanged — but bypass the cache entirely (no read, no
// write), mirroring the discovery layer's unknown-tool rule: a record the
// decode seam would refuse is never stored in the first place.
//
// Duplicate identities merge deterministically: completed beats failed
// beats cancelled; among completed results the higher score wins, ties by
// the lexicographically smaller serialized surface — the kept result never
// depends on processing order.
//
// Cancellation is honest: assets whose work never executed report
// cancelled, the aggregate outcome reports cancelled, and no worker
// goroutine outlives the run. The returned error joins the bounded run
// diagnostics; per-asset errors ride on their results.
func Score(ctx context.Context, cfg EngineConfig, signals <-chan Signal) (Report, error) {
	c, err := cfg.validateAndDefault()
	if err != nil {
		return Report{}, err
	}
	if signals == nil {
		return Report{}, errors.New("priority: nil signal channel")
	}
	digest := CatalogsDigest(c.Interesting, c.Risk)
	if digest == "" {
		return Report{}, errors.New("priority: catalog digest is empty")
	}
	// The engine always counts into its own metrics so the report's
	// counters are true regardless of whether the caller injected any; a
	// caller-provided Metrics is folded into after the run.
	internal := &Metrics{}
	e := &env{
		interesting: c.Interesting,
		risk:        c.Risk,
		digest:      digest,
		cache:       c.Cache,
		clock:       c.Clock,
		metrics:     internal,
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: c.Concurrency,
		QueueSize:   c.QueueSize,
		Timeout:     c.Timeout,
		Rate:        c.Rate,
		Burst:       c.Burst,
		Clock:       c.Clock,
	})
	if err != nil {
		return Report{}, fmt.Errorf("priority: pool: %w", err)
	}

	acc := newAccumulator()

	// Reader: validate at ingest, pre-register a cancelled placeholder
	// (a job dropped by a forced shutdown still appears in the report),
	// submit one bounded job per valid signal. The receive selects on the
	// run context, so a producer that stops feeding while holding the
	// channel open cannot wedge the run.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			var sig Signal
			var ok bool
			select {
			case <-ctx.Done():
				return
			case sig, ok = <-signals:
				if !ok {
					return
				}
			}
			e.metrics.add(func(s *MetricsSnapshot) { s.Signals++ })
			if err := validateSignal(sig); err != nil {
				acc.merge(AssetResult{
					Identity: sig.Identity,
					Status:   StatusFailed,
					Err:      fmt.Errorf("priority: invalid signal: %w", err),
				})
				continue
			}
			acc.preRegister(sig.Identity.String(), AssetResult{
				Identity: sig.Identity,
				Status:   StatusCancelled,
			})
			s := sig
			if _, err := pool.Submit(ctx, runtime.Job{
				Func: func(ctx context.Context) (any, error) {
					result := processSignal(ctx, s, e)
					acc.merge(result)
					if c.Emit != nil && result.Status == StatusCompleted {
						if err := callEmit(ctx, c.Emit, *result.Surface); err != nil {
							e.recordErr(fmt.Errorf("priority: emit: %w", err))
						}
					}
					return nil, nil
				},
			}); err != nil {
				if errors.Is(err, runtime.ErrPoolClosed) || ctx.Err() != nil {
					return // shutting down; the placeholder covers it
				}
				e.recordErr(fmt.Errorf("priority: submit: %w", err))
				return
			}
		}
	}()

	<-readDone

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(c.Timeout))
	err = pool.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		e.recordErr(fmt.Errorf("priority: shutdown: %w", err))
	}

	// Fold the run's counters into a caller-provided Metrics.
	if c.Metrics != nil {
		s := internal.Snapshot()
		c.Metrics.add(func(dst *MetricsSnapshot) {
			dst.Signals += s.Signals
			dst.Scored += s.Scored
			dst.CacheReads += s.CacheReads
			dst.CacheStores += s.CacheStores
			dst.CacheHits += s.CacheHits
			dst.Evictions += s.Evictions
		})
	}

	return buildReport(acc.snapshot(), e), e.runError()
}

// shutdownTimeout derives the bounded drain budget.
func shutdownTimeout(jobTimeout time.Duration) time.Duration {
	if jobTimeout <= 0 {
		return shutdownForceBudget
	}
	return jobTimeout + shutdownGrace
}

// callEmit runs the optional emit hook, containing panics.
func callEmit(ctx context.Context, fn func(context.Context, SurfaceAsset) error, s SurfaceAsset) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return fn(ctx, s)
}

// processSignal runs one signal through cache-before-execute: a validated
// cache hit serves the stored surface (ZERO scoring); a miss scores fresh
// and stores. A tampered or contradictory record is evicted and recomputed
// in the same run, never served.
func processSignal(ctx context.Context, sig Signal, e *env) AssetResult {
	cacheable := e.cache != nil && validateCanonicalIdentity(sig.Identity) == nil
	if !cacheable {
		return scoreFresh(ctx, sig, e, cache.Key(""), false)
	}
	key, err := priorityKey(sig, e.digest)
	if err != nil {
		e.recordErr(fmt.Errorf("priority: cache key: %w", err))
		return failedResult(sig.Identity, err)
	}
	if served := lookupSurface(ctx, key, sig, e); served != nil {
		return AssetResult{Identity: sig.Identity, Status: StatusCompleted, Surface: served, Cached: true}
	}
	return scoreFresh(ctx, sig, e, key, true)
}

// scoreFresh scores a signal (honoring cancellation), stores the completed
// record when the key was computed, and returns the honest result.
func scoreFresh(ctx context.Context, sig Signal, e *env, key cache.Key, cacheable bool) AssetResult {
	if err := ctx.Err(); err != nil {
		return AssetResult{Identity: sig.Identity, Status: StatusCancelled}
	}

	scoredSig := sig
	if scoredSig.ScoredAt.IsZero() {
		scoredSig.ScoredAt = e.clock.Now().UTC()
	}
	surface, err := ScoreSurface(scoredSig, e.interesting, e.risk)
	if err != nil {
		return failedResult(sig.Identity, err)
	}
	e.metrics.add(func(s *MetricsSnapshot) { s.Scored++ })

	if cacheable {
		// The encode-side gate mirrors the decode checks: only surfaces
		// that would re-validate are stored.
		if err := validateSurfaceInvariants(surface, sig); err != nil {
			e.recordErr(fmt.Errorf("priority: fresh surface failed its own cache invariants (store skipped): %w", err))
		} else {
			storeSurface(ctx, key, surface, e)
		}
	}
	return AssetResult{Identity: sig.Identity, Status: StatusCompleted, Surface: &surface}
}

func failedResult(id asset.Identity, err error) AssetResult {
	return AssetResult{Identity: id, Status: StatusFailed, Err: err}
}

// lookupSurface performs cache-before-execute. Any non-hit outcome falls
// through to a fresh score; a completed hit is decoded with strict
// re-validation and a rejected record is deleted (evicted) and recomputed.
func lookupSurface(ctx context.Context, key cache.Key, sig Signal, e *env) *SurfaceAsset {
	e.metrics.add(func(s *MetricsSnapshot) { s.CacheReads++ })
	out := e.cache.Get(ctx, key)
	switch out.State {
	case cache.StateHit:
		surface, err := decodeStoredSurface(*out.Record, sig)
		if err != nil {
			e.recordCacheDiagnostic("hit rejected", err)
			e.metrics.add(func(s *MetricsSnapshot) { s.Evictions++ })
			e.recordCacheDiagnostic("delete", e.cache.Delete(ctx, key))
			return nil
		}
		e.metrics.add(func(s *MetricsSnapshot) { s.CacheHits++ })
		return surface
	case cache.StateCorrupt, cache.StateSchemaIncompatible, cache.StateIncomplete:
		if out.Err != nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateError:
		if out.Err != nil && ctx.Err() == nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateMiss, cache.StateExpired:
		return nil
	}
	return nil
}

// storeSurface persists one completed score. When the run context was
// already cancelled, the write runs under a fresh short budget (a
// completed result deserves persistence even during teardown).
func storeSurface(ctx context.Context, key cache.Key, surface SurfaceAsset, e *env) {
	storeCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		storeCtx, cancel = context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
	}
	rec, err := encodeStoredSurface(surface, e.clock.Now())
	if err != nil {
		e.recordCacheDiagnostic("encode", err)
		return
	}
	if err := e.cache.Put(storeCtx, key, rec); err != nil {
		e.recordCacheDiagnostic("put", err)
		return
	}
	e.metrics.add(func(s *MetricsSnapshot) { s.CacheStores++ })
}

// accumulator merges per-asset results keyed by identity string.
type accumulator struct {
	mu      sync.Mutex
	results map[string]*AssetResult
}

func newAccumulator() *accumulator {
	return &accumulator{results: make(map[string]*AssetResult)}
}

// preRegister installs a placeholder only when no result exists yet, so a
// duplicate identity never clobbers an already-processed result.
func (a *accumulator) preRegister(id string, r AssetResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.results[id]; !ok {
		a.results[id] = &r
	}
}

// merge installs a real result: it replaces placeholders and loses only
// to an existing result that beats it under the deterministic total order
// (see betterResult).
func (a *accumulator) merge(r AssetResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := r.Identity.String()
	if prev, ok := a.results[id]; ok && betterResult(*prev, r) {
		return
	}
	cp := r
	a.results[id] = &cp
}

func (a *accumulator) snapshot() []AssetResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AssetResult, 0, len(a.results))
	for _, r := range a.results {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Identity.String() < out[j].Identity.String()
	})
	return out
}

// betterResult reports whether a strictly beats b under the deterministic
// merge order: completed > failed > cancelled; among completed results,
// higher score, then the lexicographically smaller serialized surface —
// the winner never depends on processing order.
func betterResult(a, b AssetResult) bool {
	rank := func(s Status) int {
		switch s {
		case StatusCompleted:
			return 2
		case StatusFailed:
			return 1
		}
		return 0
	}
	if rank(a.Status) != rank(b.Status) {
		return rank(a.Status) > rank(b.Status)
	}
	switch a.Status {
	case StatusCompleted:
		if a.Surface == nil || b.Surface == nil {
			return a.Surface != nil
		}
		if a.Surface.Score != b.Surface.Score {
			return a.Surface.Score > b.Surface.Score
		}
		ab, bb := marshalSurface(a.Surface), marshalSurface(b.Surface)
		if ab != bb {
			return ab < bb
		}
		return false
	case StatusFailed:
		ae, be := "", ""
		if a.Err != nil {
			ae = a.Err.Error()
		}
		if b.Err != nil {
			be = b.Err.Error()
		}
		if ae != be {
			return ae < be
		}
	}
	return false
}

func marshalSurface(s *SurfaceAsset) string {
	buf, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(buf)
}

// buildReport assembles the deterministic run report and derives the
// aggregate outcome in the fixed priority order.
func buildReport(results []AssetResult, e *env) Report {
	rep := Report{Assets: results}
	for _, r := range results {
		switch r.Status {
		case StatusCompleted:
			rep.Completed++
		case StatusFailed:
			rep.Failed++
		case StatusCancelled:
			rep.Cancelled++
		}
	}
	m := e.metrics.Snapshot()
	rep.Scored = m.Scored
	rep.CacheHits = m.CacheHits
	switch {
	case rep.Cancelled > 0:
		rep.Outcome = OutcomeCancelled
	case rep.Failed > 0 && rep.Completed > 0:
		rep.Outcome = OutcomeIncomplete
	case rep.Failed > 0:
		rep.Outcome = OutcomeFailed
	default:
		rep.Outcome = OutcomeCompleted
	}
	return rep
}

// engineClock is the production runtime.Clock (local twin, mirroring the
// other consumer stages).
type engineClock struct{}

func (engineClock) Now() time.Time                         { return time.Now() }
func (engineClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
