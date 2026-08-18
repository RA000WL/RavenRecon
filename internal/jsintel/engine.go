// The discovery + processing pipeline: a typed Source seam feeds a bounded
// worker pool; every candidate URL runs cache-before-execute fetch →
// classify → parse → extract → merge → emit → bounded expansion. Mirrors
// urlintel/engine.go in structure and guarantees.
package jsintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Engine constants. StoreTimeout mirrors the fetch layer's detached-store
// budget (storeTimeout in fetch.go — storeFetch owns the post-cancellation
// write context; the engine's budget chain is request ⊆ job ⊆ shutdown).
const (
	// StoreTimeout bounds a single cache write performed after the run
	// context was already cancelled (persisting a completed record). The
	// store path in storeFetch applies this budget itself; the constant is
	// the engine-level documentation of the convention.
	StoreTimeout = 5 * time.Second
	// ShutdownGrace is added to the pool timeout to bound Shutdown's
	// drain: jobs already respect their per-job deadline, so a clean drain
	// needs at most the timeout plus one grace period.
	ShutdownGrace = 15 * time.Second
	// ShutdownForceBudget bounds Shutdown's drain when the pool per-job
	// timeout is disabled (0).
	ShutdownForceBudget = 30 * time.Second
	// MaxRunDiagnostics bounds how many individual diagnostics the run's
	// error summary retains; beyond the cap only a count is kept.
	MaxRunDiagnostics = 32
	// MaxHTMLBody is the per-HTML-observation body cap. The engine
	// truncates an oversized body at ingest (and counts the truncation);
	// parseHTML re-enforces the cap defensively.
	MaxHTMLBody = 1 << 20 // 1 MiB
	// maxLineSecretURLs bounds the distinct current-URL contexts (one per
	// "[ + ] URL:" progress line) for which the line seam retains pending
	// line-secrets. A secret line for a 33rd distinct URL context is
	// counted (Skipped) and dropped — deterministic arrival-order
	// accounting; the D2 line-secret ingestion contract.
	maxLineSecretURLs = 32
	// maxLineSecretsPerURL bounds the pending line-secrets retained for ONE
	// URL context. The 65th secret line for one URL is counted (Skipped)
	// and dropped.
	maxLineSecretsPerURL = 64
)

// ItemKind discriminates the two Source item forms.
type ItemKind int

const (
	// ItemLine is a raw input line (a URL, the "[ + ] URL: <u>" progress
	// form, or a secretfinder "name\t->\tvalue" line — recognized, typed,
	// and ingested against the current progress-URL context by the line
	// seam; see parseLine in discover.go).
	ItemLine ItemKind = iota
	// ItemHTML is a page observation with a canonical page URL, response
	// headers, and a body bounded to MaxHTMLBody.
	ItemHTML
)

// HeaderEntry is one captured response header of an ItemHTML observation.
type HeaderEntry struct {
	Name  string
	Value string
}

// Item is one typed input to the pipeline. Raw strings exist only in
// Item.Line at this boundary — everything downstream works with canonical
// URL assets and typed observations.
type Item struct {
	Kind ItemKind
	// Line is the raw line for ItemLine.
	Line string
	// URL is the canonical page URL for ItemHTML (the resolution base).
	URL asset.URL
	// Headers are the response headers for ItemHTML (Link header
	// candidates are extracted from them).
	Headers []HeaderEntry
	// Body is the page body for ItemHTML, bounded at ingest to MaxHTMLBody
	// (oversized bodies are truncated and counted — honestly).
	Body string
}

// Source is the ingest seam: a stream of typed items. Next returns io.EOF
// at end of stream; it must honor ctx cancellation and may return ctx.Err()
// when cancelled. Tool adapters implement Source over external command
// output; tests and static input use SliceSource.
type Source interface {
	Next(ctx context.Context) (Item, error)
}

// sliceSource is a fixed []Item-backed Source for tests and static input.
// Not safe for concurrent use (the pipeline reads a source sequentially by
// design).
type sliceSource struct {
	items []Item
	i     int
}

// SliceSource returns a Source over the given items, in order. The slice is
// not copied; callers must not mutate it after construction.
func SliceSource(items []Item) Source {
	return &sliceSource{items: items}
}

// Next implements Source.
func (s *sliceSource) Next(ctx context.Context) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	if s.i >= len(s.items) {
		return Item{}, io.EOF
	}
	it := s.items[s.i]
	s.i++
	return it, nil
}

// Config configures one discovery + processing run. Validate via
// DefaultConfig or the validated method; zero values fall back to the
// documented defaults (except Concurrency and QueueSize, which must be
// positive — the pool requires them).
type Config struct {
	// Concurrency is the exact number of worker goroutines of the run's
	// single runtime pool (> 0; DefaultConfig sets 8). One job is
	// submitted per candidate URL into the bounded queue; the pool never
	// creates a goroutine per candidate.
	Concurrency int

	// QueueSize is the capacity of the pool's bounded submission queue
	// (> 0; DefaultConfig sets 256). The reader blocks (backpressure)
	// while the queue is full, so memory stays bounded regardless of
	// source size.
	QueueSize int

	// Timeout is the per-job deadline at pool level (0 disables it;
	// DefaultConfig sets 30 s). The deadline covers the whole job: fetch,
	// parse, extract, merge, and expansion.
	Timeout time.Duration

	// Rate is the central outbound fetch rate in tokens per second
	// (DefaultConfig sets 20). The limiter is passed to Fetch, where every
	// dispatched request — initial and redirect hops — waits for a token.
	// The pool itself is NOT paced: cache-before-execute means a cache hit
	// performs zero token waits, and the token wait belongs inside Fetch.
	// 0 disables pacing; negative, NaN, and infinite values are rejected.
	Rate float64

	// Burst is the token-bucket burst capacity of the fetch limiter
	// (DefaultConfig sets 1; values below 1 normalize to 1).
	Burst int

	// Source identifies the discovery source. It enters the provenance of
	// every observed asset and the sources of every fetch-record and
	// report entry. Must be non-empty (default "jsintel") and at most 128
	// bytes.
	Source string

	// Base is the optional base URL for resolving RELATIVE line items
	// ("./x.js", "../x.js", "/x.js", "//h/p"). The zero URL means relative
	// lines are malformed.
	Base asset.URL

	// Cache, when non-nil, enables cache-before-execute per canonical URL:
	// each candidate first derives the js.fetch key and is served from a
	// completed record on a usable hit (a hit performs ZERO network
	// requests and ZERO limiter token waits — the fetch is still parsed
	// and analyzed from the restored content: this pass caches fetches,
	// not analyses). Nil disables caching.
	Cache cache.Cache

	// Clock is the run's single time source: provenance and observation
	// timestamps AND the fetch limiter (deterministic under an injected
	// fake clock). Nil means the wall clock.
	Clock runtime.Clock

	// Emit, when non-nil, is the incremental emit hook: called once per
	// processed candidate observation, from a worker goroutine, AFTER the
	// observation was merged. Ordering is not guaranteed under
	// concurrency; consumers needing the deterministic merged view use the
	// Report. An Emit error is recorded on the run's returned error but
	// does not abort the pipeline; a panicking hook is contained and
	// likewise surfaced as a diagnostic.
	Emit func(context.Context, JSEntry) error

	// Metrics, when non-nil, collects run counters. Tests and benchmarks
	// use it to assert zero work on cache hits.
	Metrics *Metrics

	// Transport is the fetch seam. Nil means the bounded production
	// transport (see FetchConfig.Transport).
	Transport http.RoundTripper

	// RequestTimeout is the per-attempt fetch deadline (0 means the 10 s
	// default). It is clamped to the job deadline when the job deadline is
	// shorter, so the budget chain request ⊆ job always holds.
	RequestTimeout time.Duration

	// MaxJSBytes is the retained-content cap per fetch (0 means the 2 MiB
	// default; clamped to [64 KiB, 8 MiB]).
	MaxJSBytes int64

	// Retries is the number of immediate retries for failed fetch attempts
	// (0 means the default 1; clamped to at most 3).
	Retries int

	// MaxScripts bounds the total number of JS candidates processed per
	// run (DefaultConfig sets 500). Candidates beyond the cap are dropped
	// and counted Skipped — import edges are still recorded.
	MaxScripts int

	// MaxImportDepth bounds import expansion depth (DefaultConfig sets 4):
	// imports beyond this depth are recorded as edges only, never fetched,
	// and counted Skipped.
	MaxImportDepth int

	// MaxImportsPerFile bounds the resolved-import retention per file
	// (DefaultConfig sets 256): imports beyond the cap are dropped and
	// counted Skipped. The same cap bounds the bare-import (External)
	// list.
	MaxImportsPerFile int

	// MaxSourceMapsPerFile bounds the source map assets detected per file
	// (DefaultConfig sets 8); beyond the cap maps are dropped and counted
	// Skipped.
	MaxSourceMapsPerFile int

	// MaxHTMLScripts bounds the candidates extracted from ONE HTML
	// observation (DefaultConfig sets 128); beyond the cap they are
	// dropped and counted Skipped.
	MaxHTMLScripts int

	// MaxEndpointsPerFile bounds the endpoint candidates retained from
	// ONE parsed file (DefaultConfig sets 64); candidates beyond the cap
	// are dropped and counted Skipped. The cap also bounds the
	// different-host URL observations of the same file: every URL asset
	// accompanies an endpoint, so the URL list can never exceed the
	// endpoint list.
	MaxEndpointsPerFile int

	// MaxSecretsPerFile bounds the secret candidates retained from ONE
	// parsed file (DefaultConfig sets 32); candidates beyond the cap are
	// dropped and counted Skipped.
	MaxSecretsPerFile int

	// MaxTechPerFile bounds the technologies retained from ONE parsed
	// file (DefaultConfig sets 32 — the fixed detection table has 19
	// entries, so the default retains the full table); technologies
	// beyond the cap are dropped and counted Skipped.
	MaxTechPerFile int

	// MaxEvidencePerFile bounds the per-marker evidence records retained
	// from ONE parsed file (DefaultConfig sets 64 — the detection table
	// has fewer than 60 markers); evidence beyond the cap is dropped and
	// counted Skipped.
	MaxEvidencePerFile int
}

// DefaultConfig returns a Config with documented defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency:          8,
		QueueSize:            256,
		Timeout:              30 * time.Second,
		Rate:                 20,
		Burst:                1,
		Source:               "jsintel",
		RequestTimeout:       10 * time.Second,
		MaxJSBytes:           2 << 20,
		Retries:              1,
		MaxScripts:           500,
		MaxImportDepth:       4,
		MaxImportsPerFile:    256,
		MaxSourceMapsPerFile: 8,
		MaxHTMLScripts:       128,
		MaxEndpointsPerFile:  64,
		MaxSecretsPerFile:    32,
		MaxTechPerFile:       32,
		MaxEvidencePerFile:   64,
	}
}

// validated normalizes cfg: defaults, clamps, and rejection of negative
// values. Config is validated per run; it is never mutated globally.
func (c Config) validated() (Config, error) {
	if c.Concurrency <= 0 {
		return Config{}, fmt.Errorf("jsintel: concurrency must be positive, got %d", c.Concurrency)
	}
	if c.QueueSize <= 0 {
		return Config{}, fmt.Errorf("jsintel: queue size must be positive, got %d", c.QueueSize)
	}
	if c.Timeout < 0 {
		return Config{}, fmt.Errorf("jsintel: timeout must not be negative, got %s", c.Timeout)
	}
	if c.Rate < 0 || math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) {
		return Config{}, fmt.Errorf("jsintel: rate must be zero (disabled) or a positive finite number, got %v", c.Rate)
	}
	if c.Burst < 1 {
		c.Burst = 1
	}
	if c.Source == "" {
		c.Source = "jsintel"
	}
	if len(c.Source) > 128 {
		return Config{}, fmt.Errorf("jsintel: source is longer than 128 bytes")
	}
	if c.RequestTimeout < 0 {
		return Config{}, fmt.Errorf("jsintel: request timeout must not be negative, got %s", c.RequestTimeout)
	}
	if c.MaxJSBytes < 0 {
		return Config{}, fmt.Errorf("jsintel: max js bytes must not be negative, got %d", c.MaxJSBytes)
	}
	if c.Retries < 0 {
		return Config{}, fmt.Errorf("jsintel: retries must not be negative, got %d", c.Retries)
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = requestTimeoutDefault
	}
	if c.MaxJSBytes == 0 {
		c.MaxJSBytes = defaultMaxJSBytes
	}
	if c.MaxJSBytes < minMaxJSBytes {
		c.MaxJSBytes = minMaxJSBytes
	}
	if c.MaxJSBytes > maxMaxJSBytes {
		c.MaxJSBytes = maxMaxJSBytes
	}
	if c.Retries == 0 {
		c.Retries = defaultRetries
	}
	if c.Retries > maxRetries {
		c.Retries = maxRetries
	}
	// Budget chain: the per-attempt fetch deadline never exceeds the job
	// deadline, so a request cannot outlive the job that owns it.
	if c.Timeout > 0 && c.RequestTimeout > c.Timeout {
		c.RequestTimeout = c.Timeout
	}
	if c.Clock == nil {
		c.Clock = wallClock{}
	}
	return normalizeCaps(c), nil
}

// normalizeCaps applies the per-run analysis cap defaults. Zero means
// default (mirroring the other zero-means-default fields); negatives are
// rejected by validated before this point. Shared with the accumulator so
// a directly constructed Accumulator applies the same caps at merge time.
func normalizeCaps(c Config) Config {
	if c.MaxScripts <= 0 {
		c.MaxScripts = 500
	}
	if c.MaxImportDepth <= 0 {
		c.MaxImportDepth = 4
	}
	if c.MaxImportsPerFile <= 0 {
		c.MaxImportsPerFile = 256
	}
	if c.MaxSourceMapsPerFile <= 0 {
		c.MaxSourceMapsPerFile = 8
	}
	if c.MaxHTMLScripts <= 0 {
		c.MaxHTMLScripts = 128
	}
	if c.MaxEndpointsPerFile <= 0 {
		c.MaxEndpointsPerFile = 64
	}
	if c.MaxSecretsPerFile <= 0 {
		c.MaxSecretsPerFile = 32
	}
	if c.MaxTechPerFile <= 0 {
		c.MaxTechPerFile = 32
	}
	if c.MaxEvidencePerFile <= 0 {
		c.MaxEvidencePerFile = 64
	}
	return c
}

// env is the per-run plumbing shared by every job. It is immutable after
// construction except errMu/diags (the bounded diagnostic summary) and the
// metrics counters. It is always used as a pointer (*env): the errMu mutex
// forbids copying.
type env struct {
	parser   Parser
	cache    cache.Cache
	source   string
	clock    runtime.Clock
	metrics  *Metrics
	cfg      Config
	fetchCfg FetchConfig

	errMu  sync.Mutex
	diags  []error // first MaxRunDiagnostics diagnostics, in arrival order
	excess int     // count of diagnostics recorded beyond the cap
}

// recordErr joins a diagnostic (cache read/write warning, emit failure)
// into the run's error summary. It never aborts the pipeline. The summary
// is bounded: at most MaxRunDiagnostics individual diagnostics are
// retained; every further diagnostic is only counted and the count is
// appended at read time by runError.
func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < MaxRunDiagnostics {
		e.diags = append(e.diags, err)
		return
	}
	e.excess++
}

// runError assembles the bounded diagnostic summary: the first
// MaxRunDiagnostics diagnostics joined in arrival order, plus a single
// count line when more were recorded. It returns nil when no diagnostic was
// recorded.
func (e *env) runError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if e.excess > 0 {
		tail := fmt.Errorf("... and %d more diagnostic(s) (the first %d are shown)", e.excess, MaxRunDiagnostics)
		return errors.Join(append(append([]error(nil), e.diags...), tail)...)
	}
	return errors.Join(e.diags...)
}

// The env metric helpers no-op on a nil Metrics.

func (e *env) metricsLine()      { e.metrics.addLine() }
func (e *env) metricsCandidate() { e.metrics.addCandidate() }
func (e *env) metricsFetch()     { e.metrics.addFetch() }
func (e *env) metricsRead()      { e.metrics.addRead() }
func (e *env) metricsStore()     { e.metrics.addStore() }
func (e *env) metricsParse()     { e.metrics.addParse() }
func (e *env) metricsMalformed(n int) {
	if n > 0 {
		e.metrics.addMalformed(n)
	}
}
func (e *env) metricsTruncated() { e.metrics.addTruncated() }
func (e *env) metricsSkipped(n int) {
	if n > 0 {
		e.metrics.addSkipped(n)
	}
}
func (e *env) metricsSecretLine() { e.metrics.addSecretLine() }

// Run performs one discovery + processing run over src and returns the
// merged report: one entry per distinct candidate URL. It is a convenience
// wrapper over RunInto with a fresh accumulator and Metrics (the report
// therefore always carries the run's counters).
func Run(ctx context.Context, cfg Config, src Source) (Report, error) {
	m := &Metrics{}
	cfg.Metrics = m
	acc := NewAccumulator(cfg)
	err := RunInto(ctx, cfg, src, acc)
	return acc.Report(), err
}

// RunInto processes one source into the shared accumulator. The same
// accumulator may be passed to successive RunInto calls (one per source),
// producing the merged view: one report entry per canonical URL with
// unioned sources and min/max timestamps (the two-level design: the cache
// stores per-URL fetch records, emit merges per URL).
//
// Pipeline per candidate: read -> normalize (lines and HTML flattened into
// canonical candidate URLs; raw strings never go further) -> malformed
// accounting -> visited/cap admission (every URL is processed at most once
// per run) -> pre-registration (cancelled placeholder + sources) -> pool
// job: cache-before-execute fetch -> classification (the JS asset rule) ->
// parse -> extraction (imports, source maps, endpoints, secrets,
// technologies, evidence) -> merge -> emit -> bounded expansion (resolved
// imports become new candidates at depth+1, bounded by MaxImportDepth and
// MaxScripts).
//
// Cancellation: RunInto honors ctx throughout. When the run is cancelled
// mid-stream, the reader stops, already-submitted jobs are cancelled by the
// pool (their pre-registered entries keep an honest cancelled status), and
// the pool's bounded shutdown budgets bound the drain. Items not yet read
// from the source are not represented — they were never consumed. In-flight
// cache stores on a cancelled run use the detached bounded context inside
// storeFetch, so a cancelled run cannot wedge shutdown on a pathological
// filesystem.
func RunInto(ctx context.Context, cfg Config, src Source, acc *Accumulator) error {
	if ctx == nil {
		return fmt.Errorf("jsintel: context must not be nil")
	}
	if src == nil {
		return fmt.Errorf("jsintel: source must not be nil")
	}
	if acc == nil {
		return fmt.Errorf("jsintel: accumulator must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("jsintel: %w", err)
	}
	cfg, err := cfg.validated()
	if err != nil {
		return err
	}
	// The accumulator applies the validated caps to its merges.
	acc.adopt(cfg)

	var limiter *runtime.Limiter
	if cfg.Rate > 0 {
		limiter, err = runtime.NewLimiter(cfg.Rate, float64(cfg.Burst), runtime.WithClock(cfg.Clock))
		if err != nil {
			return fmt.Errorf("jsintel: create fetch rate limiter: %w", err)
		}
	}
	e := &env{
		parser:  NewParser(),
		cache:   cfg.Cache,
		source:  cfg.Source,
		clock:   cfg.Clock,
		metrics: cfg.Metrics,
		cfg:     cfg,
		fetchCfg: FetchConfig{
			Transport:      cfg.Transport,
			RequestTimeout: cfg.RequestTimeout,
			MaxJSBytes:     cfg.MaxJSBytes,
			Retries:        cfg.Retries,
			Limiter:        limiter,
			Clock:          cfg.Clock,
		},
	}

	// The pool is NOT paced: job-start pacing would double the rate limit
	// (every fetch already waits on the central limiter inside Fetch) and
	// would pace cache-hit jobs that perform zero network work.
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Clock:       cfg.Clock,
	})
	if err != nil {
		return fmt.Errorf("jsintel: create worker pool: %w", err)
	}
	rs := &runState{
		acc:         acc,
		pool:        pool,
		cfg:         cfg,
		env:         e,
		visited:     make(map[asset.Identity]struct{}),
		claimed:     make(map[asset.Identity]struct{}),
		pend:        &pending{},
		lineSecrets: make(map[asset.Identity]*lineSecretBucket),
	}

	var sourceErr error
	for {
		if err := ctx.Err(); err != nil {
			// The run is being cancelled: stop reading. Candidates already
			// submitted keep their pre-registered entries (cancelled until
			// a worker overwrites them); items not yet read are never
			// consumed and are not represented.
			break
		}
		item, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sourceErr = fmt.Errorf("jsintel: read item: %w", err)
			break
		}
		switch item.Kind {
		case ItemLine:
			e.metricsLine()
			candidates, malformed, secret, progress := parseLine(cfg, item.Line)
			if secret != nil {
				// Every recognized secret line counts as a raw line
				// (SecretLines), whether or not it is ingested.
				e.metricsSecretLine()
				if secret.dropped {
					// Empty or overlong value: counted and dropped.
					e.metricsSkipped(1)
				} else {
					secret.at = e.clock.Now().UTC()
					rs.addLineSecret(*secret)
				}
			}
			if !progress.IsZero() {
				// The "[ + ] URL: <u>" form sets the current URL context
				// for the line-secrets that follow.
				rs.lineCurrent = progress
			}
			acc.addMalformed(malformed)
			e.metricsMalformed(malformed)
			for _, u := range candidates {
				rs.offer(ctx, u)
			}
		case ItemHTML:
			// Ingest-boundary body truncation: an oversized body is cut to
			// MaxHTMLBody and the truncation is counted honestly.
			if len(item.Body) > MaxHTMLBody {
				item.Body = item.Body[:MaxHTMLBody]
				e.metricsTruncated()
			}
			candidates, malformed, dropped := parseHTML(item, e.parser, cfg.MaxHTMLScripts)
			acc.addMalformed(malformed)
			e.metricsMalformed(malformed)
			e.metricsSkipped(dropped)
			for _, u := range candidates {
				rs.offer(ctx, u)
			}
		default:
			sourceErr = fmt.Errorf("jsintel: item with unknown kind %d", item.Kind)
		}
		if sourceErr != nil {
			break
		}
	}

	// Quiescence before shutdown: a running job may still submit expansion
	// jobs (resolved imports become new candidates), and the pool stops
	// accepting work the moment Shutdown starts. Wait until the last job
	// finished — only then can no new expansion arrive — or until the run
	// is cancelled (a cancelled run wants no further expansions; the forced
	// shutdown cancels whatever remains).
	rs.pend.waitIdle(ctx)

	// Shutdown is the join point: it drains every queued and in-flight job
	// before returning (bounded, so a job that ignores cancellation cannot
	// wedge the run forever).
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()

	// Attach the run's pending line-secrets to their entries (deduped with
	// the content-derived candidates at merge). Runs after the drain so the
	// attachment order is deterministic.
	rs.flushLineSecrets()

	if ctx.Err() != nil {
		// A cancelled run drops not-yet-started jobs before their work
		// could run: their pre-registered entries keep the cancelled status
		// — stamp the cause so every one reports WHY it was never
		// processed.
		acc.finalizeCancelled(ctx.Err())
	}

	runErr := e.runError()
	if shutdownErr != nil {
		return fmt.Errorf("jsintel: pool shutdown: %w", shutdownErr)
	}
	return errors.Join(sourceErr, runErr)
}

// shutdownContext derives the bounded drain context for pool shutdown,
// mirroring the Phase 4 budget: timeout + ShutdownGrace, or
// ShutdownForceBudget when per-job deadlines are disabled.
func shutdownContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	budget := timeout + ShutdownGrace
	if timeout <= 0 {
		budget = ShutdownForceBudget
	}
	return context.WithTimeout(context.Background(), budget)
}

// callEmit invokes the Config.Emit hook with panic containment: a panicking
// hook is converted into an error (reported through recordErr by the
// caller) instead of crashing the worker goroutine or aborting the run. The
// wrapping diagnostic that names the URL is applied by the caller, which
// owns the URL asset.
func callEmit(ctx context.Context, entry JSEntry, emit func(context.Context, JSEntry) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return emit(ctx, entry)
}

// pending tracks the run's in-flight pool jobs so the reader can wait for
// quiescence before shutting the pool down: a running job may submit
// expansion jobs (resolved imports become new candidates), so the pool must
// keep accepting work until the LAST job finished — only then can no new
// expansion arrive. waitIdle also ends on run cancellation: a cancelled run
// wants no further expansions, and Shutdown force-cancels whatever remains.
type pending struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n drops to 0; recreated on add
}

// add registers one in-flight job. Must be balanced by exactly one done.
func (p *pending) add() {
	p.mu.Lock()
	if p.n == 0 {
		p.idle = make(chan struct{})
	}
	p.n++
	p.mu.Unlock()
}

// done unregisters one in-flight job, closing the idle channel when the
// count reaches zero.
func (p *pending) done() {
	p.mu.Lock()
	p.n--
	if p.n == 0 {
		close(p.idle)
	}
	p.mu.Unlock()
}

// waitIdle blocks until no job is in flight, or until ctx is cancelled.
func (p *pending) waitIdle(ctx context.Context) {
	for {
		p.mu.Lock()
		n := p.n
		ch := p.idle
		p.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}
}

// runState is the per-run orchestration state shared by the reader and the
// pool workers: the admission set (visited + total cap), the accumulator,
// the in-flight job count, and the pool.
type runState struct {
	acc  *Accumulator
	pool *runtime.Pool
	cfg  Config
	env  *env

	visitMu   sync.Mutex
	visited   map[asset.Identity]struct{}
	claimed   map[asset.Identity]struct{} // admitted URLs (subset of visited), under visitMu
	submitted int                         // distinct candidates claimed, under visitMu

	pend *pending // in-flight pool jobs, for the pre-shutdown quiescence wait

	// Reader-owned D2 line-secret state: the current "[ + ] URL:" context
	// and the pending line-secrets accumulated against it (bounded by
	// maxLineSecretURLs contexts × maxLineSecretsPerURL secrets). Only the
	// reader writes these; flushLineSecrets reads them after the pool
	// drained, so no lock is needed.
	lineCurrent asset.URL
	lineSecrets map[asset.Identity]*lineSecretBucket
}

// lineSecretBucket is the pending line-secret accumulation for ONE URL
// context, bounded by maxLineSecretsPerURL.
type lineSecretBucket struct {
	u    asset.URL
	secs []lineSecret
}

// addLineSecret accumulates one recognized line-secret against the current
// progress-URL context. Every drop is counted through the Skipped metric
// and nothing is silently lost:
//
//   - no current context (the line arrived before any "[ + ] URL:" line)
//     → counted and dropped;
//   - the context URL was already refused admission (its progress line's
//     offer hit the MaxScripts cap) → counted and dropped — the URL can
//     never be processed, so its secrets can never be ingested;
//   - a 33rd distinct URL context → counted and dropped;
//   - a 65th secret for one context → counted and dropped.
//
// The admission outcome is final by the time a secret line is read (the
// progress line's offer ran synchronously before it), so this is
// deterministic.
func (rs *runState) addLineSecret(sec lineSecret) {
	if rs.lineCurrent.IsZero() {
		rs.env.metricsSkipped(1)
		return
	}
	id := rs.lineCurrent.Identity()
	rs.visitMu.Lock()
	_, admitted := rs.claimed[id]
	rs.visitMu.Unlock()
	if !admitted {
		rs.env.metricsSkipped(1)
		return
	}
	b := rs.lineSecrets[id]
	if b == nil {
		if len(rs.lineSecrets) >= maxLineSecretURLs {
			rs.env.metricsSkipped(1)
			return
		}
		b = &lineSecretBucket{u: rs.lineCurrent}
		rs.lineSecrets[id] = b
	}
	if len(b.secs) >= maxLineSecretsPerURL {
		rs.env.metricsSkipped(1)
		return
	}
	b.secs = append(b.secs, sec)
}

// flushLineSecrets attaches every pending line-secret to its URL's entry:
// the entry's Secrets become the content-derived candidates PLUS the
// URL's pending line-secrets, deduplicated by candidate identity at merge
// (mergeSecrets — the identity is type/value/source, with the source the
// JavaScript identity of the URL, so a line-secret and a content-derived
// candidate with the same type and value are ONE candidate).
//
// It runs AFTER the pool drained (all processed merges already happened, so
// the attachment order is deterministic regardless of map iteration order —
// each bucket belongs to a different entry, and entries are sorted at
// report time). The flushed entry is a line-secrets-only observation: the
// cancelled status never overrides a real outcome (rank 1), the sources
// union (first-seen order), and FirstSeen/LastSeen widen to the secret
// lines' arrival window — the lines ARE observations of the URL. Nothing
// is dropped here: buckets exist only for admitted URLs, and every other
// drop already happened at line time in addLineSecret.
func (rs *runState) flushLineSecrets() {
	for _, b := range rs.lineSecrets {
		if len(b.secs) == 0 {
			continue
		}
		first, last := b.secs[0].at, b.secs[0].at
		secs := make([]asset.SecretCandidate, 0, len(b.secs))
		for _, s := range b.secs {
			if s.at.Before(first) {
				first = s.at
			}
			if s.at.After(last) {
				last = s.at
			}
			c, err := asset.NewSecretCandidate(s.typ, s.value, jsIdentity(b.u),
				asset.Provenance{Source: rs.cfg.Source, DiscoveredAt: s.at})
			if err != nil {
				// Defensive (parseLine bounds the value and the mapping
				// table only yields valid types): counted and dropped.
				rs.env.metricsSkipped(1)
				continue
			}
			secs = append(secs, c)
		}
		if len(secs) == 0 {
			continue
		}
		rs.acc.merge(JSEntry{
			URL:       b.u,
			Status:    StatusCancelled,
			Sources:   []string{rs.cfg.Source},
			Secrets:   secs,
			FirstSeen: first,
			LastSeen:  last,
		})
	}
}

// jsIdentity is the JavaScript asset identity of a URL: the source identity
// every secret candidate observed in that URL's content carries, and the
// source identity line-secrets are attributed to — so both streams dedup by
// the same identity.
func jsIdentity(u asset.URL) asset.Identity {
	return asset.Identity{Kind: asset.KindJavaScript, Value: u.String()}
}

// reserve claims u for a job when it is the run's first observation of the
// URL AND the total candidate cap (MaxScripts) allows. Returns (true,
// false) when a job was claimed, (false, true) when the URL was already
// claimed or capped (a duplicate observation of an earlier URL), and
// (false, false) when the cap blocked a NEW URL (the URL is marked seen —
// it was processed and dropped — and the caller counts Skipped).
//
// The mutex makes admission atomic, so concurrent duplicate candidates
// (reader vs. import expansion) can never double-claim a URL. Claimed URLs
// are tracked in rs.claimed (the admission subset) so re-offers can union
// their sources without ever creating an entry for a cap-dropped URL.
func (rs *runState) reserve(u asset.URL) (claimed, dup bool) {
	rs.visitMu.Lock()
	defer rs.visitMu.Unlock()
	if _, ok := rs.visited[u.Identity()]; ok {
		return false, true
	}
	rs.visited[u.Identity()] = struct{}{}
	if rs.submitted >= rs.cfg.MaxScripts {
		return false, false
	}
	rs.submitted++
	rs.claimed[u.Identity()] = struct{}{}
	rs.env.metricsCandidate()
	return true, false
}

// offer is the reader-side admission: claim the candidate and submit a
// depth-0 job, or account the drop.
func (rs *runState) offer(ctx context.Context, u asset.URL) {
	claimed, dup := rs.reserve(u)
	switch {
	case claimed:
		rs.submitJob(ctx, u, 0)
	case dup:
		// A re-observation of an ADMITTED URL: union the source into its
		// entry (append + dedup, first-seen order — the D1 sources-union
		// contract). Everything else stays first-wins. A cap-dropped URL
		// has no entry and must never get one, so only admitted URLs merge.
		rs.visitMu.Lock()
		_, admitted := rs.claimed[u.Identity()]
		rs.visitMu.Unlock()
		if admitted {
			rs.acc.merge(JSEntry{URL: u, Status: StatusCancelled, Sources: []string{rs.cfg.Source}})
		}
	default:
		rs.env.metricsSkipped(1)
	}
}

// submitJob pre-registers the candidate in the accumulator (a cancelled
// placeholder carrying its source) and submits the processing job. The job
// is counted in-flight from BEFORE submission until it finished (or until
// it is dropped), so the reader's pre-shutdown quiescence wait cannot miss
// it. A submission failure (run cancelled or pool closing) leaves the
// honest pre-registered entry in place and balances the in-flight count —
// the job never queued.
func (rs *runState) submitJob(ctx context.Context, u asset.URL, depth int) {
	rs.acc.merge(JSEntry{URL: u, Status: StatusCancelled, Sources: []string{rs.cfg.Source}})
	rs.pend.add()
	if _, serr := rs.pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
		defer rs.pend.done()
		rs.processJob(jctx, u, depth)
		return nil, nil
	}}); serr != nil {
		// The run context is done or the pool is closing: the candidate
		// keeps its pre-registered cancelled entry (it was never executed).
		rs.pend.done()
	}
}

// processJob runs one candidate through the pipeline: fetch (cache-first)
// → classify → parse → extract → merge → emit → bounded expansion. The job
// never panics (the pool contains panics anyway) and never recurses:
// expansion submits NEW jobs, it does not chain calls.
func (rs *runState) processJob(ctx context.Context, u asset.URL, depth int) {
	entry, resolved := rs.env.process(ctx, u)
	rs.acc.merge(entry)
	if rs.cfg.Emit != nil {
		// The emit hook runs AFTER the entry was merged, so a panicking or
		// failing consumer can never lose the merged observation.
		if eerr := callEmit(ctx, entry, rs.cfg.Emit); eerr != nil {
			rs.env.recordErr(fmt.Errorf("jsintel: emit %s: %w", u.String(), eerr))
		}
	}
	// Bounded expansion: resolved imports at depth+1 become new jobs while
	// depth+1 <= MaxImportDepth AND the total cap allows; every other
	// resolved import stays an edge-only observation (its edge was already
	// recorded during extraction) and counts Skipped. Depth-capped imports
	// are NOT admitted to the visited set: a shallower path to the same
	// URL must still be able to fetch it.
	if depth >= rs.cfg.MaxImportDepth {
		rs.env.metricsSkipped(len(resolved))
		return
	}
	for _, child := range resolved {
		claimed, dup := rs.reserve(child)
		switch {
		case claimed:
			rs.submitJob(ctx, child, depth+1)
		case dup:
			// The URL was already claimed (or capped): the edge stands; no
			// second job. Cycle protection: circular imports terminate
			// because a URL is admitted at most once per run.
		default:
			rs.env.metricsSkipped(1)
		}
	}
}

// process runs the per-candidate work and returns the merged entry plus the
// resolved import URLs (the expansion candidates). The work order is fixed:
// cache-before-execute lookup (zero network on a hit) → fetch on a miss →
// classification → JS asset build → parse → extraction.
func (e *env) process(ctx context.Context, u asset.URL) (JSEntry, []asset.URL) {
	if e.cache != nil {
		lookup := lookupFetch(ctx, u, e.fetchCfg, e.cache, e.clock, e.source)
		e.metricsRead()
		if lookup.Err != nil {
			e.recordErr(fmt.Errorf("jsintel: %s: %w", u.String(), lookup.Err))
		}
		if lookup.Hit {
			// A completed, validated, unexpired record: zero network
			// requests and zero token waits; the fetch is still parsed and
			// analyzed from the restored content.
			return e.classify(ctx, u, lookup.Result, true, lookup.FirstSeen, lookup.LastSeen)
		}
	}
	if err := ctx.Err(); err != nil {
		// Cancelled before the work could run: report cancelled, never
		// success, and never fetch.
		return JSEntry{URL: u, Status: StatusCancelled, Sources: []string{e.source}, Err: err}, nil
	}
	res := Fetch(ctx, e.fetchCfg, u)
	e.metricsFetch()
	now := e.clock.Now().UTC()
	entry, resolved := e.classify(ctx, u, res, false, now, now)
	if e.cache != nil {
		// Completed and truncated observations are stored (truncated as
		// incomplete — never served as a hit); failed and cancelled
		// observations are never stored: a later run re-works them.
		if serr := storeFetch(ctx, e.fetchCfg, e.cache, e.clock, res, entry.Sources, entry.FirstSeen, entry.LastSeen); serr != nil {
			e.recordErr(serr)
		} else {
			e.metricsStore()
		}
	}
	return entry, resolved
}

// classify maps one fetch result to a typed entry and runs the analysis
// (parse + extraction) on completed JS observations. Classification rules:
//
//   - truncated fetch → StatusIncomplete, no JS asset (no content was
//     retained — an honest partial observation);
//   - completed negative (conn_refused / tls) → StatusCompleted, no JS
//     asset (a legitimate negative observation);
//   - failed fetch → StatusFailed, no JS asset;
//   - cancelled fetch → StatusCancelled, no JS asset;
//   - completed positive → the JS classification rule decides the asset:
//     the content is a JS asset when the final Content-Type is a JS media
//     type (application/javascript, text/javascript, application/x-
//     javascript, application/ecmascript, text/ecmascript,
//     application/x-ecmascript) OR the canonical URL path ends with
//     .js/.mjs/.cjs (case-insensitive). No content sniffing. A completed
//     positive that is not a JS asset (HTML, images, ...) is a completed
//     observation with NO JS asset. A JS-classified observation builds the
//     asset, runs the cache-before-execute analysis (a usable js.analyze
//     hit skips parsing entirely), parses on a miss, and extracts imports,
//     source maps, endpoints, secrets, technologies, and evidence; a
//     parser hard error (the 8 MiB defense cap — unreachable through the
//     fetch content cap) → StatusFailed; a parser cap hit → the entry is
//     StatusIncomplete but the JS asset is still recorded — the file IS a
//     JS file, the analysis is partial.
func (e *env) classify(ctx context.Context, u asset.URL, res FetchResult, cached bool, firstSeen, lastSeen time.Time) (JSEntry, []asset.URL) {
	entry := JSEntry{
		URL:       u,
		Status:    StatusCompleted,
		Sources:   []string{e.source},
		Cached:    cached,
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
	}
	switch res.Status {
	case FetchTruncated:
		entry.Status = StatusIncomplete
		entry.Err = res.Err
		e.metricsTruncated()
		return entry, nil
	case FetchCancelled:
		entry.Status = StatusCancelled
		entry.Err = res.Err
		return entry, nil
	case FetchFailed:
		entry.Status = StatusFailed
		entry.Err = res.Err
		return entry, nil
	case FetchCompleted:
		if res.Reason != ReasonNone {
			// Completed negative: conn_refused / tls.
			return entry, nil
		}
	default:
		entry.Status = StatusFailed
		entry.Err = fmt.Errorf("jsintel: %s: unknown fetch status %q", u.String(), res.Status)
		return entry, nil
	}
	// Completed positive. The fixed JS classification rule decides whether
	// a JS asset exists; everything else is a completed observation with
	// no JS asset.
	if !isJSAsset(res, u) {
		return entry, nil
	}
	js, jerr := buildJSAsset(u, res, e.source, e.clock.Now().UTC())
	if jerr != nil {
		entry.Status = StatusFailed
		entry.Err = fmt.Errorf("jsintel: build asset %s: %w", u.String(), jerr)
		return entry, nil
	}
	entry.JS = &js

	// Analysis: cache-before-execute. A usable js.analyze record serves
	// the stored payload — zero parse — and the entry is built through the
	// same applyAnalysis as the fresh path, so a cache-served entry is
	// byte-identical in payload to a freshly analyzed one. The lookup is
	// cross-validated against the CURRENT content's hash (js.ContentHash,
	// the SHA-256 of the fetched bytes): a record derived from different
	// content is deleted and never served — a refreshed fetch with NEW
	// content always falls through to a fresh analysis, and the fresh
	// store overwrites the same key bound to the new hash. A content
	// mismatch is a routine lifecycle event (fetch and analyze records
	// have independent lifecycles), so it falls through as a silent miss;
	// only a discarded unusable record (identity contradiction or decode
	// failure — tampering or corruption) surfaces a diagnostic. A miss
	// falls through to a fresh analysis, which is stored for the next run
	// — completed records as hits, truncated records as incomplete (never
	// served). Analysis is only ever stored for completed-positive JS
	// observations, so the store side needs no further status guard.
	if e.cache != nil {
		lookup := lookupAnalyze(ctx, u, js.ContentHash, e.cfg, e.cache, e.clock)
		e.metricsRead()
		if lookup.Err != nil {
			e.recordErr(fmt.Errorf("jsintel: %s: %w", u.String(), lookup.Err))
		}
		if lookup.Hit {
			data := lookup.Result
			return applyAnalysis(entry, js, data, e.cfg), analysisResolved(data)
		}
	}

	parsed, perr := e.parser.Parse(res.Content)
	e.metricsParse()
	if perr != nil {
		// The only Parse error is the hard 8 MiB input cap; the fetch
		// content cap (max 8 MiB) makes this unreachable in practice, but
		// the classification stays honest.
		entry.Status = StatusFailed
		entry.Err = fmt.Errorf("jsintel: parse %s: %w", u.String(), perr)
		return entry, nil
	}
	if parsed.Truncated {
		// A parser cap hit: the analysis is a partial prefix. The asset is
		// still recorded — the file IS a JS file.
		entry.Status = StatusIncomplete
		e.metricsTruncated()
	}
	ie := extractImports(js, parsed, e.cfg)
	e.metricsMalformed(ie.skipped)
	e.metricsSkipped(ie.dropped)
	sm := extractSourceMaps(js, res, parsed, e.cfg)
	e.metricsMalformed(sm.skipped)
	e.metricsSkipped(sm.dropped)
	ep := extractEndpoints(js, parsed, e.cfg)
	e.metricsMalformed(ep.skipped)
	e.metricsSkipped(ep.dropped)
	sc := extractSecrets(js, parsed, e.cfg)
	e.metricsMalformed(sc.skipped)
	e.metricsSkipped(sc.dropped)
	td := detectTechnologies(js, res.Content, e.cfg)
	e.metricsSkipped(td.dropped)
	data := analysisData{
		Imports:      ie.imports,
		BareImports:  ie.external,
		Exports:      parsed.Exports,
		SourceMaps:   sm.maps,
		Endpoints:    ep.endpoints,
		URLs:         ep.urls,
		Secrets:      sc.secrets,
		Technologies: td.techs,
		Evidence:     td.evidence,
	}
	entry = applyAnalysis(entry, js, data, e.cfg)
	if e.cache != nil {
		if serr := storeAnalyze(ctx, e.cfg, e.cache, e.clock, u, js.ContentHash, data, parsed.Truncated, entry.Sources, entry.FirstSeen, entry.LastSeen); serr != nil {
			e.recordErr(serr)
		} else {
			e.metricsStore()
		}
	}
	return entry, ie.resolved
}

// isJSAsset applies the fixed JS classification rule: a completed positive
// observation is a JS asset when the final Content-Type is a JS media type
// or the canonical URL path ends with .js/.mjs/.cjs (case-insensitive).
// There is NO content sniffing: a text/plain body at /app.js IS a JS asset
// (the URL says so), and an application/javascript body at /page IS one
// too. Anything else is a completed observation with no JS asset.
func isJSAsset(res FetchResult, u asset.URL) bool {
	if isJSContentType(res.ContentType) {
		return true
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs")
}

// isJSContentType reports whether a final Content-Type is a JS media type.
func isJSContentType(ct string) bool {
	mime, _, _ := strings.Cut(ct, ";")
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "application/javascript", "text/javascript",
		"application/x-javascript", "application/ecmascript",
		"text/ecmascript", "application/x-ecmascript":
		return true
	}
	return false
}

// buildJSAsset assembles the JavaScript asset observation for a
// JS-classified completed positive. Every observed field passes through the
// asset layer's setters (bounds enforced, canonical forms required). The
// host observation is the bare hostname — IP-literal hosts have no host
// asset in the Phase 2 model, mirroring the URL pipeline; a canonical
// URL's host either forms a valid hostname or is an IP literal, so a
// setter failure leaves the observation unset.
func buildJSAsset(u asset.URL, res FetchResult, source string, now time.Time) (asset.JavaScript, error) {
	js := asset.JavaScript{
		URL:  u,
		Prov: asset.Provenance{Source: source, DiscoveredAt: now},
	}
	var err error
	if js, err = asset.WithSize(js, res.Size); err != nil {
		return js, err
	}
	if js, err = asset.WithContentHash(js, res.Hash); err != nil {
		return js, err
	}
	if js, err = asset.WithContentType(js, res.ContentType); err != nil {
		return js, err
	}
	if js, err = asset.WithETag(js, res.ETag); err != nil {
		return js, err
	}
	if js, err = asset.WithLastModified(js, res.LastModified); err != nil {
		return js, err
	}
	if js, err = asset.WithDiscoverySource(js, source); err != nil {
		return js, err
	}
	if js, err = asset.WithStatusCode(js, res.StatusCode); err != nil {
		return js, err
	}
	if !res.FinalURL.IsZero() {
		if js, err = asset.WithFinalURL(js, res.FinalURL.String()); err != nil {
			return js, err
		}
	}
	name := u.HostPort
	if !strings.HasPrefix(name, "[") {
		if h, _, ok := strings.Cut(name, ":"); ok {
			name = h // strip a non-default port; the host asset is the bare hostname
		}
	}
	if js2, herr := asset.WithHost(js, name); herr == nil {
		js = js2
	}
	return js, nil
}
