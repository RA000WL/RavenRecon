package techintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a completed record). Cache writes are
// small atomic files; this budget only exists so a cancelled run cannot wedge
// shutdown on a pathological filesystem. Mirrors the Phase 4 convention.
const storeTimeout = 5 * time.Second

// shutdownGrace is added to the pool timeout to bound Shutdown's drain:
// jobs already respect their per-job deadline, so a clean drain needs at most
// the timeout plus one grace period. Mirrors the Phase 4 convention.
const shutdownGrace = 15 * time.Second

// shutdownForceBudget bounds Shutdown's drain when the pool per-job timeout
// is disabled (0). Mirrors the Phase 4 convention.
const shutdownForceBudget = 30 * time.Second

// maxRunDiagnostics bounds how many run-level error messages Ingest retains.
const maxRunDiagnostics = 32

// Config configures one Ingest run. All numeric fields are validated by
// Ingest; invalid values are rejected with an error rather than silently
// normalized (mirroring urlintel).
type Config struct {
	// Concurrency is the worker count. Must be > 0.
	Concurrency int
	// QueueSize is the bounded reader->worker queue. Must be > 0; the reader
	// blocks on a full queue (backpressure, never unbounded memory).
	QueueSize int
	// Timeout is the per-observation processing deadline; 0 means no deadline.
	Timeout time.Duration
	// Rate is the optional per-job start rate limit (jobs/sec); 0 disables.
	Rate float64
	// Burst is the rate limiter burst size; values below 1 normalize to 1.
	Burst int
	// Clock is the injectable time seam; nil uses the wall clock.
	Clock runtime.Clock
	// Cache is the Phase 3 cache. When nil, cache-before-execute is disabled
	// and every observation is analyzed fresh (still merged and reported).
	Cache cache.Cache
	// DB is the compiled fingerprint database. When nil, Ingest loads it via
	// fingerprints.Load() (the compile-once contract: the engine NEVER
	// compiles regular expressions itself). Tests may inject the loaded DB.
	DB *fingerprints.DB
	// MaxTechnologiesPerObservation bounds how many technologies one
	// observation may report. Default 128.
	MaxTechnologiesPerObservation int
	// MaxIndicatorsPerObservation bounds how many evidence records (indicator
	// matches plus cookie-flag evidence) one observation may retain. Default
	// 512.
	MaxIndicatorsPerObservation int
	// Emit, when non-nil, is called once per PROCESSED observation (fresh or
	// cache-served) with the observation and its merged entry. Panics inside
	// Emit are contained and reported as run diagnostics, never fatal.
	Emit func(context.Context, Observation, ReportEntry) error
	// Metrics, when non-nil, accumulates the run's work counters (see
	// Metrics.Snapshot).
	Metrics *Metrics
}

// DefaultConfig returns the documented default Ingest configuration.
func DefaultConfig() Config {
	return Config{
		Concurrency:                   8,
		QueueSize:                     256,
		Timeout:                       30 * time.Second,
		Rate:                          0,
		Burst:                         1,
		MaxTechnologiesPerObservation: 128,
		MaxIndicatorsPerObservation:   512,
	}
}

// validateAndDefault validates a Config copy, fills defaults, and loads the
// fingerprint DB when none was injected.
func (c *Config) validateAndDefault() (*Config, error) {
	if c.Concurrency <= 0 {
		return nil, fmt.Errorf("config: Concurrency must be > 0")
	}
	if c.QueueSize <= 0 {
		return nil, fmt.Errorf("config: QueueSize must be > 0")
	}
	if c.Timeout < 0 {
		return nil, fmt.Errorf("config: Timeout must be >= 0")
	}
	if c.MaxTechnologiesPerObservation < 0 {
		return nil, fmt.Errorf("config: MaxTechnologiesPerObservation must be >= 0")
	}
	if c.MaxIndicatorsPerObservation < 0 {
		return nil, fmt.Errorf("config: MaxIndicatorsPerObservation must be >= 0")
	}

	d := *c
	if d.Clock == nil {
		d.Clock = wallClock{}
	}
	if d.DB == nil {
		db, err := fingerprints.Load()
		if err != nil {
			return nil, fmt.Errorf("load fingerprint database: %w", err)
		}
		d.DB = db
	}

	// The cap defaults let a caller create a partial Config literally:
	//   cfg := Config{Concurrency: 4, QueueSize: 64}
	// and still get documented bounds.
	if d.MaxTechnologiesPerObservation == 0 {
		d.MaxTechnologiesPerObservation = 128
	}
	if d.MaxIndicatorsPerObservation == 0 {
		d.MaxIndicatorsPerObservation = 512
	}
	return &d, nil
}

// ObservationSource is the ingest seam: a stream of typed observations. Next
// returns io.EOF at end of stream and must honor ctx cancellation (the
// reader stops promptly when ctx is done).
type ObservationSource interface {
	Next(ctx context.Context) (Observation, error)
}

// SliceObservationSource wraps a fixed slice of observations for tests and
// static input.
type SliceObservationSource []Observation

// Next implements ObservationSource.
func (s *SliceObservationSource) Next(ctx context.Context) (Observation, error) {
	if len(*s) == 0 {
		return Observation{}, io.EOF
	}
	o := (*s)[0]
	*s = (*s)[1:]
	return o, nil
}

// Metrics accumulates the run's work counters. It is safe for concurrent
// use.
type Metrics struct {
	mu           sync.Mutex
	observations int
	analyzed     int
	stored       int
	reads        int
	malformed    int
}

// Snapshot is a consistent point-in-time copy of the metrics counters.
type MetricsSnapshot struct {
	// Observations is the number of observations read from the source
	// (valid observations; malformed ones are counted separately).
	Observations int
	// Analyzed is the number of analysis passes performed (cache misses
	// only). A cache hit performs ZERO analysis and never increments it.
	Analyzed int
	// Stored is the number of completed records persisted to the cache.
	Stored int
	// Reads is the number of cache lookups performed.
	Reads int
	// Malformed is the number of observations rejected at ingest.
	Malformed int
}

// addObservations and the other add methods are nil-safe: a nil *Metrics
// (no instrumentation) is a no-op, mirroring Snapshot's documented behavior.
func (m *Metrics) addObservations() {
	if m == nil {
		return
	}
	m.add(&m.observations, 1)
}

func (m *Metrics) addAnalyzed() {
	if m == nil {
		return
	}
	m.add(&m.analyzed, 1)
}

func (m *Metrics) addStored() {
	if m == nil {
		return
	}
	m.add(&m.stored, 1)
}

func (m *Metrics) addReads() {
	if m == nil {
		return
	}
	m.add(&m.reads, 1)
}

func (m *Metrics) addMalformed() {
	if m == nil {
		return
	}
	m.add(&m.malformed, 1)
}

func (m *Metrics) add(p *int, v int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	*p += v
	m.mu.Unlock()
}

// Snapshot returns a consistent copy of the counters. A nil Metrics (no
// instrumentation) snapshots as all zeros.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return MetricsSnapshot{
		Observations: m.observations,
		Analyzed:     m.analyzed,
		Stored:       m.stored,
		Reads:        m.reads,
		Malformed:    m.malformed,
	}
}

// env is the immutable per-run environment shared by the reader and every
// worker.
type env struct {
	fingerprints []fingerprints.Fingerprint
	cache        cache.Cache
	clock        runtime.Clock
	capTech      int
	capInd       int
	schema       int

	metrics *Metrics

	errMu  sync.Mutex
	diags  []error
	excess int
}

// recordErr appends one run diagnostic, bounded. Callers must not treat
// recorded diagnostics as fatal: the run continues unless the context is
// done.
func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < maxRunDiagnostics {
		e.diags = append(e.diags, err)
	} else {
		e.excess++
	}
}

// runError joins all recorded diagnostics into one error for Ingest's
// return value.
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
	return errors.New("techintel: " + joinStrings(msgs, "; "))
}

// recordCacheDiagnostic surfaces a cache.Get outcome problem as a run
// diagnostic; cancellation/expiry/corrupt states are never fatal and the
// observation falls through to a fresh analysis (mirroring urlintel).
func (e *env) recordCacheDiagnostic(op string, err error) {
	if err == nil {
		return
	}
	e.recordErr(fmt.Errorf("techintel: cache %s: %w", op, err))
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

// Ingest runs one technology-detection pass over the observation source:
// for each observation: validate at ingest -> cache-before-execute (a hit
// serves the stored result with ZERO analysis) -> analyze (cache miss) ->
// store -> merge at emit -> report. Cancellation performs a bounded drain
// (honest cancelled statuses) and never leaks workers.
//
// The returned Report is deterministic: entries sorted by identity, every
// collection inside sorted. The returned error is nil on a clean run, or the
// joined bounded run diagnostics (source errors, cache errors, emit errors);
// cancellation is surfaced through entry statuses, never as an error.
func Ingest(ctx context.Context, cfg Config, src ObservationSource) (Report, error) {
	c, err := cfg.validateAndDefault()
	if err != nil {
		return Report{}, err
	}
	if src == nil {
		return Report{}, errors.New("techintel: nil observation source")
	}

	e := &env{
		fingerprints: c.DB.Fingerprints(),
		cache:        c.Cache,
		clock:        c.Clock,
		capTech:      c.MaxTechnologiesPerObservation,
		capInd:       c.MaxIndicatorsPerObservation,
		schema:       fingerprints.SchemaVersion,
		metrics:      c.Metrics,
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: c.Concurrency,
		QueueSize:   c.QueueSize,
		Timeout:     c.Timeout,
		Rate:        c.Rate,
		Burst:       c.Burst,
	})
	if err != nil {
		return Report{}, fmt.Errorf("techintel: pool: %w", err)
	}

	acc := newAccumulator()

	// Reader goroutine: read observations, validate at ingest, pre-register
	// cancelled placeholders, submit one bounded job per observation.
	readDone := make(chan struct{})
	var sourceErr error
	go func() {
		defer close(readDone)
		for {
			if ctx.Err() != nil {
				sourceErr = ctx.Err()
				return
			}
			o, err := src.Next(ctx)
			if err != nil {
				if err == io.EOF {
					return
				}
				if ctx.Err() != nil {
					sourceErr = ctx.Err()
					return
				}
				sourceErr = err
				return
			}

			now := e.clock.Now().UTC()
			prepared, truncated, err := prepareObservation(o, now)
			if err != nil {
				acc.addMalformed()
				e.metrics.addMalformed()
				e.recordErr(fmt.Errorf("techintel: malformed observation: %w", err))
				continue
			}
			e.metrics.addObservations()
			acc.preRegister(prepared)
			obs := prepared
			obsTrunc := truncated
			if _, err := pool.Submit(ctx, runtime.Job{
				Func: func(ctx context.Context) (any, error) {
					entry := processObservation(ctx, obs, obsTrunc, e)
					normalizeEntry(&entry)
					acc.merge(obs.identity().String(), &entry)
					if c.Emit != nil {
						if err := callEmit(ctx, c.Emit, obs, entry); err != nil {
							e.recordErr(fmt.Errorf("techintel: emit: %w", err))
						}
					}
					return nil, nil
				},
			}); err != nil {
				if errors.Is(err, runtime.ErrPoolClosed) || ctx.Err() != nil {
					return // run is shutting down; the pre-registered placeholder covers it
				}
				e.recordErr(fmt.Errorf("techintel: submit: %w", err))
				return
			}
		}
	}()

	<-readDone

	// Bounded drain with honest statuses.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(c.Timeout))
	err = pool.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		e.recordErr(fmt.Errorf("techintel: shutdown: %w", err))
	}

	if sourceErr != nil && ctx.Err() == nil {
		e.recordErr(fmt.Errorf("techintel: source: %w", sourceErr))
	}

	entries, malformed := acc.snapshot()
	rep := buildReport(entries, malformed, c.Metrics.Snapshot())
	return rep, e.runError()
}

// shutdownTimeout derives the bounded drain budget, mirroring urlintel:
// one grace period on top of the pool's per-job timeout, or the force budget
// when timeouts are disabled.
func shutdownTimeout(jobTimeout time.Duration) time.Duration {
	if jobTimeout <= 0 {
		return shutdownForceBudget
	}
	return jobTimeout + shutdownGrace
}

// callEmit runs the optional emit hook, containing panics so a misbehaving
// consumer hook can never kill a run.
func callEmit(ctx context.Context, fn func(context.Context, Observation, ReportEntry) error, o Observation, e ReportEntry) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return fn(ctx, o, e)
}

// processObservation runs one observation through cache-before-execute:
// a completed cache hit rebuilds and returns the stored result (ZERO
// analysis); a miss analyzes, stores the completed record, and returns the
// fresh result. Failed and Cancelled observations are never stored.
func processObservation(ctx context.Context, o Observation, truncated bool, e *env) ReportEntry {
	prov := asset.Provenance{Source: o.Source, DiscoveredAt: o.ObservedAt}

	if e.cache != nil {
		key, err := techKey(o, e.schema)
		if err != nil {
			e.recordErr(fmt.Errorf("techintel: cache key: %w", err))
			return failedEntry(o, err)
		}
		if out := lookupTech(ctx, key, o, e); out != nil {
			return *out
		}
	}

	if err := ctx.Err(); err != nil {
		return cancelledEntry(o)
	}

	outcome := analyze(o, e.fingerprints, e.capTech, e.capInd, prov)
	outcome.truncated = outcome.truncated || truncated
	e.metrics.addAnalyzed()

	entry := completedEntry(o, outcome, prov)

	if e.cache != nil {
		key, err := techKey(o, e.schema)
		if err != nil {
			return entry // analysis succeeded; key failure only skips the store
		}
		storeTechDetached(ctx, key, o, entry, e)
	}
	return entry
}

// completedEntry assembles the completed ReportEntry for a fresh analysis.
func completedEntry(o Observation, out analysisOutcome, prov asset.Provenance) ReportEntry {
	now := o.ObservedAt
	entry := ReportEntry{
		ID:           o.identity(),
		URL:          o.URL,
		StatusCode:   o.StatusCode,
		Status:       StatusCompleted,
		Technologies: out.technologies,
		Evidence:     out.evidence,
		Conflicts:    out.conflicts,
		Truncated:    out.truncated,
		Overflow:     out.overflow,
		FirstSeen:    now,
		LastSeen:     now,
		source:       o.Source,
		techEvidence: out.techEvidence,
	}
	if o.Endpoint != nil {
		ep := *o.Endpoint
		entry.Endpoint = &ep
	}
	entry.Relationships = graphOf(o, out.technologies, out.techEvidence)
	return entry
}

// cancelledEntry is the honest outcome for an observation whose work never
// executed. FirstSeen carries the observation's own ObservedAt (it IS the
// observation time): the failed/cancelled Err and status tie-breaks depend
// on it, and an honest report can still say when a cancelled observation
// was made.
func cancelledEntry(o Observation) ReportEntry {
	e := ReportEntry{
		ID:         o.identity(),
		URL:        o.URL,
		StatusCode: o.StatusCode,
		Status:     StatusCancelled,
		FirstSeen:  o.ObservedAt,
		source:     o.Source,
	}
	if o.Endpoint != nil {
		ep := *o.Endpoint
		e.Endpoint = &ep
	}
	return e
}

// failedEntry is the honest outcome for an observation that could not be
// processed (cache-key failure). The Err is bounded.
func failedEntry(o Observation, err error) ReportEntry {
	e := cancelledEntry(o)
	e.Status = StatusFailed
	e.Err = err
	return e
}

// lookupTech performs cache-before-execute. It returns nil on any non-hit
// outcome (miss, expired, corrupt, incomplete, schema-incompatible, error):
// the caller falls through to a fresh analysis. A completed hit is decoded
// with strict re-validation; a tampered record is deleted and falls through.
func lookupTech(ctx context.Context, key cache.Key, o Observation, e *env) *ReportEntry {
	e.metrics.addReads()
	out := e.cache.Get(ctx, key)
	switch out.State {
	case cache.StateHit:
		s, err := decodeStoredTech(*out.Record, o, sourcesMask(o), e.capTech, e.capInd)
		if err != nil {
			// Tampered, corrupt, or contradictory: never serve; delete so the
			// next observation recomputes, and fall through to fresh analysis.
			e.recordCacheDiagnostic("hit rejected", err)
			e.recordCacheDiagnostic("delete", e.cache.Delete(ctx, key))
			return nil
		}
		entry := entryFromStored(o, s)
		return &entry
	case cache.StateExpired:
		// Expired entries are never served; the caller recomputes and stores.
		return nil
	case cache.StateCorrupt, cache.StateSchemaIncompatible, cache.StateIncomplete:
		// Corrupt / schema-incompatible / incomplete: never served; corrupt
		// entries are deleted by the cache itself. Fall through to analysis.
		if out.Err != nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateError:
		if out.Err != nil && ctx.Err() == nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateMiss:
		return nil
	}
	return nil
}

// entryFromStored rebuilds a completed ReportEntry from a decoded cache
// record: zero analysis, zero fingerprint matching. Relationships are
// rebuilt deterministically from the stored technologies, evidence, and
// tech->evidence links.
func entryFromStored(o Observation, s *storedTech) ReportEntry {
	entry := ReportEntry{
		ID:           o.identity(),
		URL:          o.URL,
		StatusCode:   s.StatusCode,
		Status:       StatusCompleted,
		Cached:       true,
		Conflicts:    s.Conflicts,
		Truncated:    s.Truncated,
		Overflow:     s.Overflow,
		FirstSeen:    s.FirstSeen,
		LastSeen:     s.LastSeen,
		techEvidence: s.TechEvidence,
	}
	if o.Endpoint != nil {
		ep := *o.Endpoint
		entry.Endpoint = &ep
	}
	entry.Technologies = make([]TechnologyResult, 0, len(s.Technologies))
	for i, t := range s.Technologies {
		lv := LevelUnknown
		if i < len(s.Levels) {
			if parsed, err := ParseConfidenceLevel(s.Levels[i]); err == nil {
				lv = parsed
			}
		}
		tr := TechnologyResult{
			Technology: t,
			Score:      t.Prov.Confidence,
			Level:      lv,
		}
		if i < len(s.VersionOrdinals) {
			tr.versionOrdinal = s.VersionOrdinals[i]
		}
		entry.Technologies = append(entry.Technologies, tr)
	}
	entry.Evidence = s.Evidence
	entry.Relationships = graphOf(o, entry.Technologies, entry.techEvidence)
	return entry
}

// storeTechDetached persists one completed observation's record. On a clean
// run the store uses the job context; when the run is already cancelled the
// store runs under a bounded detached context (storeTimeout) so a completed
// result is still persisted without wedging shutdown. Failed/cancelled
// observations never reach this function.
func storeTechDetached(ctx context.Context, key cache.Key, o Observation, entry ReportEntry, e *env) {
	storeCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		storeCtx, cancel = context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
	}
	mask := sourcesMask(o)
	// The record's CreatedAt is the STORE time (the run clock), never the
	// observation's ObservedAt: TTL is measured from CreatedAt, and an
	// observation with a stale or future ObservedAt must not produce an
	// instantly-expired or immortal record.
	rec, err := encodeStoredTech(o, entry, mask, e.clock.Now())
	if err != nil {
		e.recordCacheDiagnostic("encode", err)
		return
	}
	if err := e.cache.Put(storeCtx, key, rec); err != nil {
		e.recordCacheDiagnostic("put", err)
		return
	}
	e.metrics.addStored()
}

// wallClock is the production runtime.Clock used when no clock is injected.
// The runtime package keeps its own unexported implementation; this local
// twin keeps the engine's dependency surface unchanged.
type wallClock struct{}

// Now implements runtime.Clock.
func (wallClock) Now() time.Time { return time.Now() }

// After implements runtime.Clock.
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
