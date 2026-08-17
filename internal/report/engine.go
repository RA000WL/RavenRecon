package report

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Engine defaults and bounds (fixed constants).
const (
	defaultEngineConcurrency = 4
	defaultEngineQueueSize   = 64
	defaultEngineTimeout     = 5 * time.Minute
	// shutdownGrace / shutdownForceBudget bound Shutdown's drain,
	// mirroring the convention shared by the other runtime consumers.
	shutdownGrace       = 15 * time.Second
	shutdownForceBudget = 30 * time.Second
	// storeTimeout bounds a single cache write performed after the run
	// context was already cancelled (persisting a completed render).
	storeTimeout = 5 * time.Second
)

// ReportStatus is the per-report outcome of one engine run, in the house
// outcome vocabulary: completed (rendered or cache-served, validated, and
// committed), failed (render, validation, or commit error), cancelled (run
// teardown), or skipped (disabled or not selected — never an error).
type ReportStatus string

// Report statuses.
const (
	ReportStatusCompleted ReportStatus = "completed"
	ReportStatusFailed    ReportStatus = "failed"
	ReportStatusCancelled ReportStatus = "cancelled"
	ReportStatusSkipped   ReportStatus = "skipped"
)

// Outcome is the aggregate outcome of one engine run, derived from the
// per-report statuses in fixed priority order: any cancelled report →
// cancelled; any failed report alongside completed ones → incomplete (the
// successes are kept, the run is not completed); every attempted report
// failed → failed; otherwise completed. A run with no active reporters is
// completed (nothing was attempted). Skipped reports never force a
// non-completed outcome.
type Outcome string

// Run outcomes.
const (
	OutcomeCompleted  Outcome = "completed"
	OutcomeIncomplete Outcome = "incomplete"
	OutcomeFailed     Outcome = "failed"
	OutcomeCancelled  Outcome = "cancelled"
)

// EngineConfig configures one engine run. Invalid values are rejected with
// an error rather than silently normalized (mirroring the other runtime
// consumers); only Timeout defaults (0 becomes the default deadline).
type EngineConfig struct {
	// Registry is the report registry (required).
	Registry *Registry

	// OutputDir is the directory reports are written to (required; created
	// as needed).
	OutputDir string

	// BaseName optionally overrides the deterministic file base name
	// (sanitized; the default derives from the run's target).
	BaseName string

	// Reports optionally restricts the run to specific reporter IDs.
	// An unknown ID is rejected. Empty means every registered reporter.
	Reports []string

	// Compress gzip-compresses the outputs of reporters that support it.
	Compress bool

	// Cache optionally composes cache-before-execute around renders
	// (operation "report.render"). Nil disables caching entirely.
	Cache cache.Cache

	// Concurrency is the exact worker count for render jobs.
	Concurrency int

	// QueueSize is the bounded submission queue size.
	QueueSize int

	// Timeout is the per-render deadline (0 selects the default).
	Timeout time.Duration

	// Clock is the time seam for cache record timestamps (nil = wall
	// clock). It never enters report content — report bytes are
	// deterministic regardless.
	Clock runtime.Clock
}

// DefaultEngineConfig returns the default configuration for a registry and
// output directory.
func DefaultEngineConfig(registry *Registry, outputDir string) EngineConfig {
	return EngineConfig{
		Registry:    registry,
		OutputDir:   outputDir,
		Concurrency: defaultEngineConcurrency,
		QueueSize:   defaultEngineQueueSize,
		Timeout:     defaultEngineTimeout,
	}
}

// validateAndDefault checks the configuration and applies defaults.
func (c EngineConfig) validateAndDefault() (*EngineConfig, error) {
	if c.Registry == nil {
		return nil, fmt.Errorf("report: registry must not be nil")
	}
	if strings.TrimSpace(c.OutputDir) == "" {
		return nil, fmt.Errorf("report: output directory must not be empty")
	}
	out := c
	if out.Concurrency <= 0 {
		out.Concurrency = defaultEngineConcurrency
	}
	if out.QueueSize <= 0 {
		out.QueueSize = defaultEngineQueueSize
	}
	if out.Timeout < 0 {
		return nil, fmt.Errorf("report: timeout %s is negative", c.Timeout)
	}
	if out.Timeout == 0 {
		out.Timeout = defaultEngineTimeout
	}
	if out.Clock == nil {
		out.Clock = wallClock{}
	}
	return &out, nil
}

// wallClock is the production runtime.Clock (local twin, mirroring the
// other consumer stages).
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ReportResult is one reporter's honest outcome.
type ReportResult struct {
	// ReporterID and ReporterVersion identify the report.
	ReporterID      string `json:"reporter_id"`
	ReporterVersion string `json:"reporter_version"`

	// Format is the output format.
	Format Format `json:"format"`

	// Status is the per-report outcome.
	Status ReportStatus `json:"status"`

	// SkipReason explains a skipped report (empty otherwise).
	SkipReason string `json:"skip_reason,omitempty"`

	// Files lists the committed file paths (completed reports only),
	// sorted by part name.
	Files []string `json:"files,omitempty"`

	// Bytes is the total rendered size. On a fresh render it is the
	// uncompressed byte count the renderer wrote through its writers; on
	// a cache-served run it is the stored byte count of the final files
	// (compressed for gzip reporters) — for compressed reports the two
	// can differ.
	Bytes int64 `json:"bytes,omitempty"`

	// Cached reports that the output was served from a validated
	// render-cache hit (zero rendering).
	Cached bool `json:"cached,omitempty"`

	// Compressed reports that the files are gzip-compressed.
	Compressed bool `json:"compressed,omitempty"`

	// RenderTime is how long the (fresh) render took. It is run metadata
	// only — it never enters the report files.
	RenderTime time.Duration `json:"-"`

	// Err carries the structured error for failed reports.
	Err error `json:"-"`
}

// RunResult is the deterministic result of one engine run: the aggregate
// outcome, the model digest, the sanitized base name, and one result per
// registered reporter (sorted by reporter ID).
type RunResult struct {
	Outcome  Outcome        `json:"outcome"`
	Digest   string         `json:"digest"`
	BaseName string         `json:"base_name"`
	Reports  []ReportResult `json:"reports"`
}

// reportPlan is one active reporter's file plan.
type reportPlan struct {
	rep          Reporter
	dir          string
	base         string
	ext          string
	disambiguate bool
	compress     bool
}

// pathFor derives a part's deterministic final path: base, the reporter ID
// when the format is ambiguous, the part name, the format extension, and
// the .gz suffix when compressed. Every component is sanitized (the base
// name through sanitizeBaseName; the part and extension are framework
// vocabulary), so no untrusted string reaches a filesystem path.
func (p reportPlan) pathFor(part string) string {
	name := p.base
	if p.disambiguate {
		name += "." + p.rep.ID
	}
	if part != "" {
		name += "." + part
	}
	name += "." + p.ext
	if p.compress {
		name += ".gz"
	}
	return filepath.Join(p.dir, name)
}

// Run builds the canonical model from input once and renders every active
// registered report on one bounded runtime pool — exactly one job per
// report, no new scheduler. Every job renders (or cache-serves) into
// temporary files, validates them, and only then atomically renames them
// into place: a cancelled, failed, or invalid render never leaves a file,
// and a failed render never overwrites the previous good one. Model
// construction and normalization happen exactly once, before any pool job.
func Run(ctx context.Context, cfg EngineConfig, input Context) (RunResult, error) {
	c, err := cfg.validateAndDefault()
	if err != nil {
		return RunResult{}, err
	}
	if ctx == nil {
		return RunResult{}, fmt.Errorf("report: context must not be nil")
	}

	model, err := NewModel(input)
	if err != nil {
		return RunResult{}, err
	}

	base := c.BaseName
	if base == "" {
		derived := "ravenrecon-report"
		if model.Target != "" {
			derived += "-" + model.Target
		}
		base = derived
	}
	base, err = sanitizeBaseName(base)
	if err != nil {
		return RunResult{}, err
	}

	// Selection: every registered reporter appears in the result. Disabled
	// reporters and unselected reporters are skipped with honest reasons.
	selected := map[string]bool{}
	for _, id := range c.Reports {
		if _, ok := c.Registry.Get(id); !ok {
			return RunResult{}, fmt.Errorf("report: unknown reporter id %q", id)
		}
		selected[id] = true
	}
	all := c.Registry.Reports()
	active := make([]reportPlan, 0, len(all))
	formatCount := make(map[Format]int)
	for _, rep := range all {
		if !rep.Enabled || (len(selected) > 0 && !selected[rep.ID]) {
			continue
		}
		formatCount[rep.Format]++
	}
	for _, rep := range all {
		if !rep.Enabled {
			continue
		}
		if len(selected) > 0 && !selected[rep.ID] {
			continue
		}
		active = append(active, reportPlan{
			rep:          rep,
			dir:          c.OutputDir,
			base:         base,
			ext:          rep.Format.extension(),
			disambiguate: formatCount[rep.Format] > 1,
			compress:     c.Compress && rep.SupportsCompression,
		})
	}

	var mu sync.Mutex
	results := make([]ReportResult, 0, len(all))
	var shutdownFailure error
	install := func(res ReportResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, res)
	}
	for _, rep := range all {
		if rep.Enabled && (len(selected) == 0 || selected[rep.ID]) {
			continue
		}
		reason := "reporter disabled"
		if rep.Enabled && len(selected) > 0 && !selected[rep.ID] {
			reason = "reporter not selected"
		}
		install(ReportResult{
			ReporterID: rep.ID, ReporterVersion: rep.Version, Format: rep.Format,
			Status: ReportStatusSkipped, SkipReason: reason,
		})
	}

	if len(active) > 0 {
		pool, err := runtime.NewPool(ctx, runtime.Config{
			Concurrency: c.Concurrency,
			QueueSize:   c.QueueSize,
			Timeout:     c.Timeout,
			Clock:       c.Clock,
		})
		if err != nil {
			return RunResult{}, fmt.Errorf("report: pool: %w", err)
		}

		done := make(chan struct{}, len(active))
		submitted := 0
		for i := range active {
			plan := active[i]
			if _, err := pool.Submit(ctx, runtime.Job{
				Func: func(jctx context.Context) (any, error) {
					defer func() { done <- struct{}{} }()
					install(processReport(jctx, c, model, plan))
					return nil, nil
				},
			}); err != nil {
				if errors.Is(err, runtime.ErrPoolClosed) || ctx.Err() != nil {
					install(cancelledResult(plan))
					continue
				}
				install(failedResult(plan, fmt.Errorf("report: submit %q: %w", plan.rep.ID, err)))
				continue
			}
			submitted++
		}
		for i := 0; i < submitted; i++ {
			select {
			case <-done:
			case <-ctx.Done():
				// Teardown: Shutdown below drains or cancels the remaining
				// jobs; their own paths install honest results.
			}
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(c.Timeout))
		shutdownErr := pool.Shutdown(shutdownCtx)
		cancel()
		// A shutdown error does not discard the installed results: every
		// pool-owned goroutine has terminated by the time Shutdown
		// returns, so the honest per-report outcomes survive alongside
		// the surfaced error.
		if shutdownErr != nil {
			shutdownFailure = fmt.Errorf("report: shutdown: %w", shutdownErr)
		}
	}

	// Every active reporter must appear exactly once. A job dropped by a
	// forced shutdown (no terminal event) installs its cancelled
	// placeholder here.
	seen := make(map[string]int, len(active))
	mu.Lock()
	for _, res := range results {
		seen[res.ReporterID]++
	}
	mu.Unlock()
	for _, plan := range active {
		if seen[plan.rep.ID] == 0 {
			install(cancelledResult(plan))
		}
	}

	mu.Lock()
	sort.Slice(results, func(i, j int) bool { return results[i].ReporterID < results[j].ReporterID })
	outcome := deriveOutcome(results)
	result := RunResult{
		Outcome:  outcome,
		Digest:   model.Digest,
		BaseName: base,
		Reports:  results,
	}
	mu.Unlock()
	return result, shutdownFailure
}

// processReport is one render job: cache lookup (when configured), render,
// validate, atomic commit, and cache store. It returns the honest result
// for the reporter. One deferred recovery covers the WHOLE job body — the
// render, the validation, the commit, and the cache store: a panic anywhere
// inside becomes a structured failed result (the sink is aborted, its temp
// files removed, and the panic value surfaced in the error), never a
// cancelled report, which the framework reserves for run teardown. The
// pool's own recovery remains the last-resort net for panics outside this
// function.
func processReport(jctx context.Context, cfg *EngineConfig, m *Model, plan reportPlan) (res ReportResult) {
	// The sink is created up front and aborted by the recovery on ANY
	// panic, so no temp file can survive a panic on any path — including
	// the cache-hit commit, which streams through this same sink.
	var sink *fileSink
	defer func() {
		if r := recover(); r != nil {
			if sink != nil {
				// Defensive note: Abort takes fileSink.mu. The recovery
				// cannot deadlock today — every stdlib-only call site
				// inside the lock returns its error instead of panicking,
				// and user Render/Validate code runs lock-free — but a
				// future locked call that panicked would deadlock here.
				sink.Abort()
			}
			res = failedResult(plan, fmt.Errorf("report: reporter %q panicked: %v", plan.rep.ID, r))
		}
	}()

	sink, err := newFileSink(plan.dir, plan.compress, plan.pathFor)
	if err != nil {
		return failedOrCancelled(jctx, plan, err)
	}

	// Cache-before-execute: a validated hit serves the exact bytes with
	// zero rendering. A tampered or contradictory record is evicted and
	// re-rendered in the same run, never served.
	if cfg.Cache != nil {
		key, err := renderCacheKey(m, plan.rep, plan.compress)
		if err == nil {
			outcome := cfg.Cache.Get(jctx, key)
			if !outcome.IsMiss() {
				if parts, ok := decodeRender(outcome, m, plan.rep, plan.compress); ok {
					files, bytes, cerr := commitCachedRender(jctx, plan, sink, parts)
					if cerr == nil {
						return ReportResult{
							ReporterID: plan.rep.ID, ReporterVersion: plan.rep.Version,
							Format: plan.rep.Format, Status: ReportStatusCompleted,
							Files: files, Bytes: bytes, Cached: true, Compressed: plan.compress,
						}
					}
					return failedOrCancelled(jctx, plan, cerr)
				}
				// A record existed but failed validation: evict it, never
				// serve it. The delete is bounded like the store path — a
				// stuck cache backend must not wedge a pool worker past
				// the run.
				evictCtx, cancel := context.WithTimeout(context.Background(), storeTimeout)
				cfg.Cache.Delete(evictCtx, key)
				cancel()
			}
		}
	}

	start := cfg.Clock.Now()
	if rerr := plan.rep.Render(jctx, m, sink); rerr != nil {
		sink.Abort()
		return failedOrCancelled(jctx, plan, rerr)
	}
	parts, err := sink.Parts()
	if err != nil {
		sink.Abort()
		return failedOrCancelled(jctx, plan, err)
	}
	files, bytes, cerr := validateAndCommit(plan, sink, parts)
	if cerr != nil {
		return failedOrCancelled(jctx, plan, cerr)
	}
	elapsed := cfg.Clock.Now().Sub(start)

	if cfg.Cache != nil {
		key, kerr := renderCacheKey(m, plan.rep, plan.compress)
		if kerr == nil {
			storeCtx := jctx
			if storeCtx.Err() != nil {
				var cancel context.CancelFunc
				storeCtx, cancel = context.WithTimeout(context.Background(), storeTimeout)
				defer cancel()
			}
			// A failed store never fails the render: the committed output
			// is already correct, so the store error is deliberately
			// dropped here.
			_ = storeRender(storeCtx, cfg.Cache, key, m, plan.rep, plan.compress, parts, cfg.Clock.Now())
		}
	}

	return ReportResult{
		ReporterID: plan.rep.ID, ReporterVersion: plan.rep.Version,
		Format: plan.rep.Format, Status: ReportStatusCompleted,
		Files: files, Bytes: bytes, Compressed: plan.compress,
		RenderTime: elapsed,
	}
}

// commitCachedRender writes a validated cached render's parts into the
// caller's sink and exposes them through the same validate-and-commit
// pipeline as a fresh render (temp file, fsync, validate, rename). The sink
// is owned by processReport so its single deferred panic recovery always
// aborts this path's temp files too (a panicking custom validator must not
// leak).
func commitCachedRender(ctx context.Context, plan reportPlan, sink *fileSink, parts []renderPart) ([]string, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	for _, part := range parts {
		// The stored part bytes ARE the final file bytes (already
		// gzip-compressed for compressed reporters) — write them raw, or
		// the committed file would carry a second gzip layer that every
		// builtin validator, which decompresses exactly once, rejects.
		w, err := sink.RawWriter(part.Part)
		if err != nil {
			sink.Abort()
			return nil, 0, err
		}
		if _, err := w.Write(part.Data); err != nil {
			w.Close()
			sink.Abort()
			return nil, 0, err
		}
		if err := w.Close(); err != nil {
			sink.Abort()
			return nil, 0, err
		}
	}
	infos, err := sink.Parts()
	if err != nil {
		sink.Abort()
		return nil, 0, err
	}
	return validateAndCommit(plan, sink, infos)
}

// validateAndCommit validates the sink's closed parts and atomically
// commits them; on the first failure the sink is aborted and nothing is
// exposed (a failed render never overwrites the previous good file).
// Returns the committed file paths (sorted by part name) and the total
// written bytes.
func validateAndCommit(plan reportPlan, sink *fileSink, parts []sinkPartInfo) ([]string, int64, error) {
	validate := plan.rep.Validate
	if validate == nil {
		validate = validateNonEmpty
	}
	for _, info := range parts {
		if verr := validate(info.Tmp, info.Compressed); verr != nil {
			sink.Abort()
			return nil, 0, verr
		}
	}
	if err := sink.Commit(); err != nil {
		sink.Abort()
		return nil, 0, err
	}
	files := make([]string, 0, len(parts))
	var total int64
	for _, info := range parts {
		files = append(files, info.Final)
		total += info.Bytes
	}
	sort.Strings(files)
	return files, total, nil
}

// failedOrCancelled classifies an error path: context cancellation (of the
// run or the job) is a cancelled report; anything else is a failure with
// the structured error attached.
func failedOrCancelled(ctx context.Context, plan reportPlan, err error) ReportResult {
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return cancelledResult(plan)
	}
	return failedResult(plan, err)
}

func cancelledResult(plan reportPlan) ReportResult {
	return ReportResult{
		ReporterID: plan.rep.ID, ReporterVersion: plan.rep.Version,
		Format: plan.rep.Format, Status: ReportStatusCancelled,
	}
}

func failedResult(plan reportPlan, err error) ReportResult {
	return ReportResult{
		ReporterID: plan.rep.ID, ReporterVersion: plan.rep.Version,
		Format: plan.rep.Format, Status: ReportStatusFailed, Err: err,
	}
}

// deriveOutcome folds the per-report statuses into the aggregate outcome
// (see Outcome). Skipped reports never force a non-completed outcome. A
// run with no attempted reports is completed.
func deriveOutcome(results []ReportResult) Outcome {
	anyCancelled, anyFailed, anyCompleted := false, false, false
	for _, res := range results {
		switch res.Status {
		case ReportStatusCancelled:
			anyCancelled = true
		case ReportStatusFailed:
			anyFailed = true
		case ReportStatusCompleted:
			anyCompleted = true
		}
	}
	switch {
	case anyCancelled:
		return OutcomeCancelled
	case anyFailed && anyCompleted:
		return OutcomeIncomplete
	case anyFailed:
		return OutcomeFailed
	default:
		return OutcomeCompleted
	}
}

// shutdownTimeout derives the bounded drain budget.
func shutdownTimeout(jobTimeout time.Duration) time.Duration {
	if jobTimeout <= 0 {
		return shutdownForceBudget
	}
	return jobTimeout + shutdownGrace
}
