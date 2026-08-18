package urlintel

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
)

// maxRawURLLen is the ingest-boundary line cap: a raw line longer than this
// is rejected as malformed without ever being parsed. It bounds the URL
// parser's input (the parser is linear, but a hostile multi-megabyte line
// would still waste cycles and memory) and is a fixed constant, deliberately
// NOT configuration, and must never enter cache keys.
const maxRawURLLen = 32 << 10 // 32 KiB

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

// LineSource is the ingest seam: a stream of raw URL lines. Raw strings
// exist only at this boundary — a line is parsed into a canonical Phase 2
// URL asset immediately and never travels beyond the parse stage, and
// userinfo credentials carried by a raw line are dropped at that same parse
// point (see parseRawURL), so no credential-bearing string ever flows past
// the boundary. URL assets and typed observations flow through the pipeline
// from there on.
//
// Next returns io.EOF at end of stream. It must honor ctx cancellation and
// may return ctx.Err() when cancelled. Tool adapters (roadmap 6C) implement
// LineSource over external command output; tests and static input use
// SliceSource.
type LineSource interface {
	Next(ctx context.Context) (string, error)
}

// sliceSource is a fixed []string-backed LineSource for tests and static
// input. Not safe for concurrent use (the pipeline reads a source
// sequentially by design).
type sliceSource struct {
	lines []string
	i     int
}

// SliceSource returns a LineSource over the given lines, in order. The
// slice is not copied; callers must not mutate it after construction.
func SliceSource(lines []string) LineSource {
	return &sliceSource{lines: lines}
}

// Next implements LineSource.
func (s *sliceSource) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.i >= len(s.lines) {
		return "", io.EOF
	}
	line := s.lines[s.i]
	s.i++
	return line, nil
}

// Config configures one URL ingest run. ValidateAndDefault normalizes it;
// all fields are optional except Adapter (which must identify the source of
// the lines — it enters the cache key).
type Config struct {
	// Concurrency is the exact number of worker goroutines of the run's
	// single runtime pool (> 0; DefaultConfig sets 8). One job is submitted
	// per raw line into the bounded queue; the pool never creates a
	// goroutine per line.
	Concurrency int

	// QueueSize is the capacity of the pool's bounded submission queue
	// (> 0; DefaultConfig sets 256). The line reader blocks (backpressure)
	// while the queue is full, so memory stays bounded regardless of source
	// size.
	QueueSize int

	// Timeout is the per-job deadline at pool level (0 disables it;
	// DefaultConfig sets 30 s). The deadline covers the rate-limit wait and
	// the per-line work.
	Timeout time.Duration

	// Rate and Burst configure the pool's job-start rate limiter (0
	// disables pacing; DefaultConfig disables it — URL parsing and
	// extraction are local work, and any pacing a 6C adapter needs belongs
	// to the adapter's own execution layer). When enabled, Burst < 1 means 1.
	Rate  float64
	Burst int

	// Adapter identifies the source of the lines. It enters the cache key
	// (per-adapter records) and the provenance of every asset. Must be
	// non-empty and at most 128 bytes (the Phase 2 source bound).
	Adapter string

	// ParseParameters enables query-parameter extraction. It is
	// result-relevant and therefore enters the cache key: records written
	// with extraction enabled are never served to a run that disabled it.
	ParseParameters bool

	// Cache, when non-nil, enables cache-before-execute per (URL, adapter):
	// each observation first derives the Phase 3 key and merges the stored
	// result on a usable hit (a hit performs ZERO extraction work); on a
	// miss it extracts and stores a completed record. Nil disables caching.
	Cache cache.Cache

	// Clock is the run's single time source: provenance and observation
	// timestamps AND the pool's job-start rate limiter (the pool receives
	// this clock, so pacing is deterministic under an injected fake clock
	// and always agrees with the timestamps the run records). Nil means the
	// wall clock; tests inject a fake clock for deterministic assertions.
	Clock runtime.Clock

	// Emit, when non-nil, is the incremental emit hook: it is called once
	// per processed URL observation (fresh extraction or cache hit), from a
	// worker goroutine, so consumers can process per-URL results without
	// accumulating. Ordering is not guaranteed under concurrency; consumers
	// needing the deterministic merged view use the Report. An Emit error is
	// recorded on the run's returned error but does not abort the pipeline;
	// a panicking hook is contained and likewise surfaced as a diagnostic
	// (the observation is merged into the report before the hook runs).
	Emit func(context.Context, URLEntry) error

	// Metrics, when non-nil, collects run counters (parse/extract/store
	// work). Tests and benchmarks use it to assert zero work on cache hits.
	Metrics *Metrics
}

// DefaultConfig returns a Config with documented defaults. Concurrency and
// the per-job timeout are consistent with the Phase 4 conventions; job-start
// rate limiting is disabled by default (URL work is local; see Config.Rate).
func DefaultConfig() Config {
	return Config{
		Concurrency:     8,
		QueueSize:       256,
		Timeout:         30 * time.Second,
		Adapter:         "urlintel",
		ParseParameters: true,
	}
}

// validateAndDefault validates cfg and applies defaults, returning the
// normalized configuration. Config is validated per run; it is never
// mutated globally.
func validateAndDefault(cfg Config) (Config, error) {
	if cfg.Concurrency <= 0 {
		return Config{}, fmt.Errorf("urlintel: concurrency must be positive, got %d", cfg.Concurrency)
	}
	if cfg.QueueSize <= 0 {
		return Config{}, fmt.Errorf("urlintel: queue size must be positive, got %d", cfg.QueueSize)
	}
	if cfg.Timeout < 0 {
		return Config{}, fmt.Errorf("urlintel: timeout must not be negative, got %s", cfg.Timeout)
	}
	if cfg.Adapter == "" {
		return Config{}, fmt.Errorf("urlintel: adapter must not be empty (it identifies the observation source)")
	}
	if len(cfg.Adapter) > 128 {
		return Config{}, fmt.Errorf("urlintel: adapter is longer than 128 bytes")
	}
	if cfg.Clock == nil {
		cfg.Clock = wallClock{}
	}
	return cfg, nil
}

// Metrics collects run-level work counters. All methods are safe for
// concurrent use (the line reader and pool workers increment them).
type Metrics struct {
	mu            sync.Mutex
	lines         int
	canonicalized int
	extracted     int
	stored        int
	reads         int
	malformed     int
}

// Snapshot is a consistent point-in-time view of a Metrics.
type Snapshot struct {
	Lines         int // raw lines consumed from the source
	Canonicalized int // raw lines canonicalized to a valid URL (key derivation)
	Extracted     int // extraction passes performed (cache misses only)
	Stored        int // cache records written
	Reads         int // cache reads performed
	Malformed     int // raw lines rejected
}

// Snapshot returns a consistent point-in-time view of the counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		Lines:         m.lines,
		Canonicalized: m.canonicalized,
		Extracted:     m.extracted,
		Stored:        m.stored,
		Reads:         m.reads,
		Malformed:     m.malformed,
	}
}

func (m *Metrics) addLine() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.lines++
	m.mu.Unlock()
}

func (m *Metrics) addCanonicalized() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.canonicalized++
	m.mu.Unlock()
}

func (m *Metrics) addExtracted() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.extracted++
	m.mu.Unlock()
}

func (m *Metrics) addStored() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.stored++
	m.mu.Unlock()
}

func (m *Metrics) addRead() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.reads++
	m.mu.Unlock()
}

func (m *Metrics) addMalformed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.malformed++
	m.mu.Unlock()
}

// maxRunDiagnostics bounds how many individual diagnostics the run's error
// summary retains. Beyond the cap, further diagnostics are only counted
// (the total is appended once at runError), so a persistently failing cache
// or Emit hook can never grow the run error without bound.
const maxRunDiagnostics = 32

// env is the per-run plumbing shared by every job. It is immutable after
// construction except errMu/diags (the bounded diagnostic summary) and the
// metrics counters; the cache is internally synchronized. It is always used
// as a pointer (*env): the errMu mutex forbids copying.
type env struct {
	cache       cache.Cache
	adapter     string
	parseParams bool
	clock       runtime.Clock
	metrics     *Metrics

	errMu  sync.Mutex
	diags  []error // first maxRunDiagnostics diagnostics, in arrival order
	excess int     // count of diagnostics recorded beyond the cap
}

// recordErr joins a diagnostic (cache read/write warning, emit failure)
// into the run's error summary. It never aborts the pipeline.
//
// The summary is bounded: at most maxRunDiagnostics individual diagnostics
// are retained; every further diagnostic is only counted, and the count is
// appended at read time by runError. A persistently failing cache can
// therefore never grow the run error without bound.
func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < maxRunDiagnostics {
		e.diags = append(e.diags, err)
		return
	}
	e.excess++
}

// runError assembles the bounded diagnostic summary: the first
// maxRunDiagnostics diagnostics joined in arrival order, plus a single
// count line when more were recorded. It returns nil when no diagnostic was
// recorded.
func (e *env) runError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if e.excess > 0 {
		tail := fmt.Errorf("... and %d more diagnostic(s) (the first %d are shown)", e.excess, maxRunDiagnostics)
		return errors.Join(append(append([]error(nil), e.diags...), tail)...)
	}
	return errors.Join(e.diags...)
}

func (e *env) metricsRead() {
	if e.metrics != nil {
		e.metrics.addRead()
	}
}

func (e *env) metricsStored() {
	if e.metrics != nil {
		e.metrics.addStored()
	}
}

// Ingest runs one ingest over src with cfg's adapter and returns the merged
// report: one entry per distinct canonical URL, merged across every
// observation of that URL in the run (cache-backed per (URL, adapter)).
//
// It is a convenience wrapper over IngestInto with a fresh accumulator; use
// IngestInto with a shared accumulator to merge multiple adapters (or
// multiple runs) into one report.
func Ingest(ctx context.Context, cfg Config, src LineSource) (Report, error) {
	acc := NewAccumulator()
	err := IngestInto(ctx, cfg, src, acc)
	return acc.Report(), err
}

// IngestInto processes one source into the shared accumulator. The same
// accumulator may be passed to successive IngestInto calls — one per
// adapter — producing the cross-adapter merged view: one report entry per
// canonical URL with unioned sources, min/max timestamps, merged parameters,
// and deduplicated endpoints and relationships (the two-level design:
// cache stores per (URL, adapter), emit merges per URL).
//
// Pipeline per line: read -> canonicalize (raw strings never go further) ->
// malformed accounting -> cache-before-execute -> extraction on miss ->
// statused store -> merge at emit -> report.
//
// Cancellation: IngestInto honors ctx throughout. When the run is cancelled
// mid-stream, the line reader stops, already-submitted jobs are cancelled by
// the pool (their pre-registered entries keep an honest cancelled status),
// and the pool's bounded shutdown budgets bound the drain. Lines not yet
// read from the source are not represented — they were never consumed.
func IngestInto(ctx context.Context, cfg Config, src LineSource, acc *Accumulator) error {
	if ctx == nil {
		return fmt.Errorf("urlintel: context must not be nil")
	}
	if src == nil {
		return fmt.Errorf("urlintel: source must not be nil")
	}
	if acc == nil {
		return fmt.Errorf("urlintel: accumulator must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("urlintel: %w", err)
	}
	cfg, err := validateAndDefault(cfg)
	if err != nil {
		return err
	}

	e := &env{
		cache:       cfg.Cache,
		adapter:     cfg.Adapter,
		parseParams: cfg.ParseParameters,
		clock:       cfg.Clock,
		metrics:     cfg.Metrics,
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        cfg.Rate,
		Burst:       cfg.Burst,
		// The run's clock drives the pool's rate limiter too, so job-start
		// pacing is deterministic under an injected clock and always agrees
		// with the observation timestamps the run records.
		Clock: cfg.Clock,
	})
	if err != nil {
		return fmt.Errorf("urlintel: create worker pool: %w", err)
	}

	var sourceErr error
	lineNo := 0
	for {
		if err := ctx.Err(); err != nil {
			// The run is being cancelled: stop reading. Lines already
			// submitted keep their pre-registered entries (cancelled until
			// a worker overwrites them); lines not yet read are never
			// consumed and are not represented (see the doc comment).
			break
		}
		line, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sourceErr = fmt.Errorf("urlintel: read line %d: %w", lineNo+1, err)
			break
		}
		lineNo++
		if cfg.Metrics != nil {
			cfg.Metrics.addLine()
		}

		// Ingest-boundary protections and canonicalization. A raw line is
		// handled here — in the reader goroutine — so malformed lines are
		// counted and rejected before any job exists, the canonical URL is
		// available for the cache key, and a pre-registered cancelled entry
		// guarantees that a job dropped by forced shutdown still appears in
		// the report with an honest status.
		if len(line) > maxRawURLLen {
			acc.addMalformed()
			if cfg.Metrics != nil {
				cfg.Metrics.addMalformed()
			}
			continue
		}
		u, perr := parseRawURL(line, cfg.Adapter, e.clock)
		if perr != nil {
			acc.addMalformed()
			if cfg.Metrics != nil {
				cfg.Metrics.addMalformed()
			}
			continue
		}
		if cfg.Metrics != nil {
			cfg.Metrics.addCanonicalized()
		}

		// Pre-register the URL as cancelled: the entry exists from the start
		// (one per distinct URL — bounded by the run's distinct-URL count),
		// and the worker's real observation replaces or unions into it.
		acc.merge(URLEntry{URL: u, Status: StatusCancelled})

		if _, serr := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			entry := processURL(jctx, u, e)
			acc.merge(entry)
			if cfg.Emit != nil {
				// The emit hook runs AFTER the entry was merged, so a
				// panicking or failing consumer can never lose the merged
				// observation. A panic is contained here (mirroring adapt's
				// detectSafe containment style) and converted into a run
				// diagnostic; it never propagates as a job error.
				if eerr := callEmit(jctx, entry, cfg.Emit); eerr != nil {
					e.recordErr(fmt.Errorf("urlintel: emit %s: %w", u.String(), eerr))
				}
			}
			return nil, nil
		}}); serr != nil {
			// The run context is done or the pool is closing: the current
			// line keeps its pre-registered cancelled entry (it was never
			// executed), and reading stops.
			break
		}
	}

	// Shutdown is the join point: it drains every queued and in-flight job
	// before returning (bounded, so a job that ignores cancellation cannot
	// wedge the run forever).
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()

	runErr := e.runError()
	if shutdownErr != nil {
		return fmt.Errorf("urlintel: pool shutdown: %w", shutdownErr)
	}
	return errors.Join(sourceErr, runErr)
}

// callEmit invokes the Config.Emit hook with panic containment: a panicking
// hook is converted into an error (reported through recordErr by the caller)
// instead of crashing the worker goroutine or aborting the run. Containment
// style mirrors adapt's detectSafe. The wrapping diagnostic that names the
// URL is applied by the caller, which owns the URL asset.
func callEmit(ctx context.Context, entry URLEntry, emit func(context.Context, URLEntry) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return emit(ctx, entry)
}

// shutdownContext derives the bounded drain context for pool shutdown,
// mirroring the Phase 4 budget: timeout + shutdownGrace, or
// shutdownForceBudget when per-job deadlines are disabled.
func shutdownContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	budget := timeout + shutdownGrace
	if timeout <= 0 {
		budget = shutdownForceBudget
	}
	return context.WithTimeout(context.Background(), budget)
}

// wallClock is the production runtime.Clock backed by the wall clock,
// mirroring the runtime package's own production clock (which is
// unexported).
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// parseRawURL canonicalizes one raw line into a Phase 2 URL asset at the
// ingest boundary. This is the ONLY place raw strings enter the asset model;
// everything downstream works with the canonical URL asset.
//
// Credential redaction: asset.URL.Original preserves userinfo by design
// (asset/url.go), and the stored observation marshals Original into the
// cache record AND the report/export — so a raw line like
// http://user:pass@example.com/p must never survive. When the parsed URL's
// Original differs from its canonical string (the raw line carries
// non-canonical surface, userinfo included), the asset is rebuilt through
// the canonical string, so Original equals the canonical form and the
// userinfo is gone everywhere downstream (records, reports, exports,
// merges). A line already in canonical form is untouched. This is the single
// construction point where a raw line becomes an asset.URL, so redacting
// here redacts every observation path (mirrors the httpprobe scope-layer
// construction-point redaction).
func parseRawURL(raw, adapter string, clock runtime.Clock) (asset.URL, error) {
	prov := asset.Provenance{Source: adapter, DiscoveredAt: clock.Now().UTC()}
	u, err := asset.ParseURL(raw, prov)
	if err != nil {
		return asset.URL{}, err
	}
	if u.Original != u.String() {
		// Rebuild through the canonical string: Original becomes the
		// canonical form and any userinfo the raw line carried is dropped.
		u, err = asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			// Cannot happen for a canonical asset URL; keep the defensive
			// path so a malformed line is still rejected.
			return asset.URL{}, err
		}
	}
	return u, nil
}

// processURL runs the cache-before-execute per-line work: serve the stored
// observation on a usable cache hit (zero extraction work — asserted by the
// benchmark harness), otherwise extract the endpoint/parameters/graph and
// store a completed record. Failed and cancelled observations are never
// cached: a second run must re-work them.
func processURL(ctx context.Context, u asset.URL, e *env) URLEntry {
	if e.cache != nil {
		entry := lookupURL(ctx, u, e)
		if entry.Status != "" {
			// A completed cache hit, a key-build failure, or a discarded
			// unusable record that already classified the entry; no
			// extraction work happens on any of these paths.
			return entry
		}
		// Fall through to execution on a miss.
	}
	if err := ctx.Err(); err != nil {
		// Cancelled before the work could run: report cancelled, never
		// success, and never extract.
		return URLEntry{URL: u, Status: StatusCancelled, Err: err}
	}
	entry := extractURL(u, e.adapter, e.parseParams, e.clock.Now())
	if e.metrics != nil {
		e.metrics.addExtracted()
	}
	if e.cache != nil {
		entry = storeURL(ctx, u, entry, e)
	}
	return entry
}
