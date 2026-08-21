package adapt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/urlintel"
)

// shutdownGrace is added to the pool timeout to bound Shutdown's drain: jobs
// already respect their per-job deadline, so a clean drain needs at most the
// timeout plus one grace period. Mirrors the Phase 4 convention.
const shutdownGrace = 15 * time.Second

// shutdownForceBudget bounds Shutdown's drain when the pool per-job timeout
// is disabled (0). Mirrors the Phase 4 convention.
const shutdownForceBudget = 30 * time.Second

// Config configures one historical-URL adapter run.
//
// Zero values are normalized where documented (Tools, MaxOutputSize,
// DetectTimeout). Concurrency, QueueSize, and IngestWorkers must be positive;
// they are validated here with clear errors.
type Config struct {
	// Tools selects the tools to run, in order. Nil or empty means every
	// built-in tool (Builtins). Duplicate names are deduplicated preserving
	// selection order; unknown or nameless tools are an error.
	Tools []Tool

	// Targets are the canonical target hosts to query, in input order. At
	// least one is required; every target is re-validated through
	// asset.NewHost at the Run boundary (a hand-built non-canonical Host is
	// refused), so target-derived strings reach argv only as canonical
	// single elements.
	Targets []asset.Host

	// Concurrency and QueueSize configure the single outer runtime pool
	// that owns all scheduling: exactly one job per (tool, target), and the
	// pool owns concurrency, cancellation, per-job deadlines, and job-start
	// rate limiting.
	Concurrency int
	QueueSize   int

	// Timeout is the per-job deadline at pool level (0 disables it). The
	// deadline bounds the tool execution AND the ingest of its lines.
	Timeout time.Duration

	// Rate and Burst configure the pool's central token-bucket limiter,
	// which gates job STARTS only (tool-internal network traffic is the
	// tool's own responsibility — RavenRecon never fakes per-request limits
	// for external processes). Rate <= 0 disables job-start rate limiting;
	// Burst < 1 means 1.
	Rate  float64
	Burst int

	// IngestWorkers is the per-job inner ingest pool concurrency (> 0; the
	// DefaultConfig sets 4). The composite bound is Concurrency x
	// IngestWorkers ingest workers plus Concurrency tool processes, all
	// bounded.
	IngestWorkers int

	// ParseParameters enables query-parameter extraction in the ingest
	// engine. It is result-relevant and therefore enters cache keys:
	// records written with extraction enabled are never served to a run
	// that disabled it.
	ParseParameters bool

	// Cache, when non-nil, enables cache-before-execute per (URL, adapter)
	// inside each ingest: on a usable hit the stored observation is served
	// and zero extraction work happens. Nil disables caching.
	Cache cache.Cache

	// Clock is the run's single time source: provenance and observation
	// timestamps AND the pool's job-start rate limiter. Nil means the wall
	// clock; tests inject a fake clock for deterministic assertions.
	Clock runtime.Clock

	// Metrics, when non-nil, collects engine-level work counters (lines
	// consumed, extractions, stores, cache reads, malformed).
	Metrics *urlintel.Metrics

	// Bin optionally overrides the executable path per tool name. Empty
	// means PATH lookup of the tool's default name.
	Bin map[string]string

	// MaxOutputSize caps each captured stdout/stderr stream in bytes. Zero
	// means discovery.DefaultMaxOutput (4 MiB per stream). Output beyond the
	// cap is discarded and diagnosed (the slot is reported partial), never
	// buffered without bound.
	MaxOutputSize int64

	// DetectTimeout bounds each tool detection invocation. Zero means
	// DefaultDetectTimeout.
	DetectTimeout time.Duration

	// Runner executes tool commands. Nil means discovery.ExecRunner (real
	// execution); tests inject fakes through this seam. Detection and
	// execution share it.
	Runner discovery.Runner

	// LookPath resolves tool executables. Nil means exec.LookPath; tests
	// inject fakes.
	LookPath discovery.LookupFunc

	// PerToolTimeout overrides the per-tool execution timeout for the named
	// tool. Zero means ToolTimeoutDefault or the built-in default (2m) —
	// the timeout is mandatory and cannot be disabled, 0 means “use the
	// default”. Negative values are rejected by validation. The timeout
	// encloses the runner only — ingest has its own pool deadline (Timeout)
	// and is never bounded by the per-tool timeout.
	PerToolTimeout map[string]time.Duration

	// ToolTimeoutDefault is the default per-tool execution timeout (0 means
	// the built-in default 2m — the timeout is mandatory and cannot be
	// disabled, 0 means “use the default”). It is the StageParams
	// "tool_timeout_default" surface. Negative values are rejected. Zero
	// per-tool entries fall back to this default, and when both are zero
	// the built-in default applies.
	ToolTimeoutDefault time.Duration
}

// DefaultToolTimeout is the built-in default per-tool execution timeout
// (StageParams "tool_timeout_default" when absent). It encloses the runner
// only — ingest has its own pool deadline.
//
// The per-tool timeout is mandatory and always on (cannot be disabled):
// the built-in 2m is intentional, bounding external tool execution even
// when the operator supplies no duration (AGENTS §0.6: truncated results
// are never silently completed — the timeout is the outermost per-tool
// bound). Supplying 0 (or omitting the key) means “use the default”, not
// “no deadline”; a per-tool timeout that fires is reported as partial with
// the captured prefix ingested.
const DefaultToolTimeout = 2 * time.Minute

// ToolTimeout returns the effective per-tool execution timeout for the named
// tool: PerToolTimeout[tool] when positive, otherwise ToolTimeoutDefault
// when positive, otherwise DefaultToolTimeout (2m). Zero per-tool entries
// fall back to the default. Negative values are never returned — they are
// rejected by validation.
func (c Config) ToolTimeout(tool string) time.Duration {
	if c.PerToolTimeout != nil {
		if d, ok := c.PerToolTimeout[tool]; ok && d > 0 {
			return d
		}
	}
	if c.ToolTimeoutDefault > 0 {
		return c.ToolTimeoutDefault
	}
	return DefaultToolTimeout
}

// DefaultConfig returns a Config with documented defaults: the three
// built-in tools, pool bounds consistent with the passive-discovery stage
// (Concurrency 2, QueueSize 8, job-start rate 2/s burst 1, 30 s per-job
// deadline), a small inner ingest pool (IngestWorkers 4), parameter
// extraction enabled, and the 4 MiB per-stream capture cap.
func DefaultConfig() Config {
	return Config{
		Concurrency:        2,
		QueueSize:          8,
		Timeout:            30 * time.Second,
		Rate:               2,
		Burst:              1,
		IngestWorkers:      4,
		ParseParameters:    true,
		MaxOutputSize:      discovery.DefaultMaxOutput,
		DetectTimeout:      DefaultDetectTimeout,
		ToolTimeoutDefault: DefaultToolTimeout,
	}
}

// env builds the execution environment from cfg. Zero seams are normalized
// by env.sanitized at use time.
func (cfg Config) env() env {
	return env{
		runner:        cfg.Runner,
		lookup:        cfg.LookPath,
		limits:        discovery.Limits{MaxOutput: cfg.MaxOutputSize},
		detectTimeout: cfg.DetectTimeout,
		bins:          cfg.Bin,
	}
}

// validateAndDefault validates cfg and applies defaults: the tool selection
// (nil/empty means every built-in, duplicates collapsed preserving order;
// empty names refused — they would collide on the engine's adapter key) and
// every pool bound. It never mutates global state.
func validateAndDefault(cfg Config) (Config, error) {
	if len(cfg.Tools) == 0 {
		cfg.Tools = Builtins()
	}
	seen := make(map[string]bool, len(cfg.Tools))
	tools := make([]Tool, 0, len(cfg.Tools))
	for _, t := range cfg.Tools {
		if t.Name == "" {
			return Config{}, fmt.Errorf("adapt: selected tool has an empty name")
		}
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		tools = append(tools, t)
	}
	cfg.Tools = tools
	if len(cfg.Targets) == 0 {
		return Config{}, fmt.Errorf("adapt: at least one target is required")
	}
	if cfg.Concurrency <= 0 {
		return Config{}, fmt.Errorf("adapt: concurrency must be positive, got %d", cfg.Concurrency)
	}
	if cfg.QueueSize <= 0 {
		return Config{}, fmt.Errorf("adapt: queue size must be positive, got %d", cfg.QueueSize)
	}
	if cfg.IngestWorkers <= 0 {
		return Config{}, fmt.Errorf("adapt: ingest workers must be positive, got %d", cfg.IngestWorkers)
	}
	if cfg.Timeout < 0 {
		return Config{}, fmt.Errorf("adapt: timeout must not be negative, got %s", cfg.Timeout)
	}
	if cfg.ToolTimeoutDefault < 0 {
		return Config{}, fmt.Errorf("adapt: tool timeout default must not be negative, got %s", cfg.ToolTimeoutDefault)
	}
	for tool, d := range cfg.PerToolTimeout {
		if d < 0 {
			return Config{}, fmt.Errorf("adapt: per-tool timeout for %q must not be negative, got %s", tool, d)
		}
	}
	return cfg, nil
}

// validateTarget re-validates the target at the Run boundary. Run receives
// assets normally produced by asset.NewHost, but a hand-built struct literal
// could bypass its normalization rules and reach argv construction; this
// check refuses such values up front. Defense-in-depth: callers are expected
// to normalize before calling Run.
func validateTarget(target asset.Host) error {
	got, err := asset.NewHost(target.Name, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("adapt: invalid target %q: %w", target.Name, err)
	}
	if got.Name != target.Name {
		return fmt.Errorf("adapt: target %q is not in canonical form (normalized %q)", target.Name, got.Name)
	}
	return nil
}

// detectSafe runs a tool's detection with panic containment, matching the
// containment style used for pool jobs: a panicking detection becomes a WARN
// with a reason (never a MISSING and never a crash), so one broken
// descriptor or runner cannot take down the whole run.
func detectSafe(ctx context.Context, e env, t Tool) (d discovery.Detection) {
	defer func() {
		if r := recover(); r != nil {
			d = discovery.Detection{
				Source: t.Name,
				Status: discovery.StatusWarn,
				Reason: fmt.Sprintf("detection panicked: %v", r),
			}
		}
	}()
	return t.detect(ctx, e)
}

// DetectTools runs detection for every selected tool in selection order
// (nil or empty selection means every built-in tool), sequentially, each
// bounded by the environment's detection timeout (zero means
// DefaultDetectTimeout). It shares exactly the detection implementation Run
// uses — there is no second detection path — and is the seam for a future
// doctor-style command. Nameless tools and duplicates are skipped (Run
// itself validates strictly).
func DetectTools(ctx context.Context, cfg Config) []discovery.Detection {
	e := cfg.env()
	names := make(map[string]bool)
	var tools []Tool
	for _, t := range cfg.Tools {
		if t.Name == "" || names[t.Name] {
			continue
		}
		names[t.Name] = true
		tools = append(tools, t)
	}
	if len(tools) == 0 {
		tools = Builtins()
	}
	dets := make([]discovery.Detection, 0, len(tools))
	for _, t := range tools {
		dets = append(dets, detectSafe(ctx, e, t))
	}
	return dets
}

// ResultStatus classifies one (tool, target) execution slot.
type ResultStatus string

const (
	// ResultSkipped: detection reported the tool MISSING; the slot never
	// executed — never an error, never an execution attempt.
	ResultSkipped ResultStatus = "skipped"
	// ResultCompleted: the tool ran cleanly (exit 0, stdout within the
	// capture cap) and its lines were fully ingested.
	ResultCompleted ResultStatus = "completed"
	// ResultPartial: non-zero exit with usable output, or stdout truncated
	// at the capture cap: the captured URL set is incomplete by definition.
	ResultPartial ResultStatus = "partial"
	// ResultFailed: the tool produced no usable output (clean failure with
	// empty stdout, missing executable, execution error).
	ResultFailed ResultStatus = "failed"
	// ResultCancelled: the run context was cancelled; the lines consumed
	// before cancellation are still represented in the report. A slot that
	// never started (forced shutdown or a submission failure) is also
	// cancelled — the honest label for "cancelled or dropped before its job
	// ran", mirroring the discovery layer's OutCancelled.
	ResultCancelled ResultStatus = "cancelled"
	// ResultTimedOut: the outer per-job deadline elapsed during execution
	// or ingest.
	ResultTimedOut ResultStatus = "timed-out"
)

// String returns the stable status label.
func (s ResultStatus) String() string { return string(s) }

// ToolResult is the honest outcome of one (tool, target) slot.
type ToolResult struct {
	// Tool is the tool name (the engine's adapter identity).
	Tool string

	// Target is the canonical target host of the slot.
	Target asset.Host

	// Status classifies the slot (see ResultStatus).
	Status ResultStatus

	// Lines is the number of non-blank URL lines streamed into the engine
	// (blank lines are skipped by the adapter; malformed lines are counted
	// run-level by the engine's accumulator).
	Lines int

	// Err carries the summary diagnostic: the skipped reason, the
	// partial/failure cause (exit code, truncation, execution error), the
	// cancellation cause, or joined non-fatal ingest warnings. It is nil
	// for a clean completed slot.
	Err error
}

// RunReport is the complete outcome of one Run: the merged URL-intelligence
// report plus one ToolResult per (tool, target).
type RunReport struct {
	// Report is the cross-tool, cross-target merged view of every
	// observation (URLs, endpoints, parameters, relationships, malformed
	// count).
	Report urlintel.Report

	// Results holds one ToolResult per (tool, target) in deterministic
	// order: tools in selection order, targets in input order. It is safe
	// to read after Run returns; Run's Shutdown is the join point.
	Results []ToolResult

	// Metrics is the engine-level work snapshot (zero when cfg.Metrics is
	// nil).
	Metrics urlintel.Snapshot
}

// Run executes the selected historical-URL tools against the given targets
// and returns the merged report. One bounded runtime.Pool owns all
// scheduling: exactly one job per (tool, target); detection runs first,
// sequentially, once per tool. A failing tool never aborts the run — every
// slot reports an honest ToolResult, and non-fatal diagnostics plus shutdown
// failures are joined on the returned error.
//
// Cancellation: Run honors ctx throughout. Cancelled mid-run, in-flight
// jobs are cancelled (their consumed lines stay in the report), the pool
// drains within bounded budgets, and Run returns only after every pool-owned
// goroutine has terminated.
func Run(ctx context.Context, cfg Config) (RunReport, error) {
	if ctx == nil {
		return RunReport{}, fmt.Errorf("adapt: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return RunReport{}, fmt.Errorf("adapt: %w", err)
	}
	cfg, err := validateAndDefault(cfg)
	if err != nil {
		return RunReport{}, err
	}
	for _, t := range cfg.Targets {
		if err := validateTarget(t); err != nil {
			return RunReport{}, err
		}
	}
	e := cfg.env()

	// Detection phase: sequential, once per selected tool, each bounded by
	// the detection timeout. Missing tools are skipped (never executed);
	// warn tools still run — the executable exists and may work.
	dets := make(map[string]discovery.Detection, len(cfg.Tools))
	for _, t := range cfg.Tools {
		dets[t.Name] = detectSafe(ctx, e, t)
	}

	// One outer pool owns every job of the run's execution phase.
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        cfg.Rate,
		Burst:       cfg.Burst,
		Clock:       cfg.Clock,
	})
	if err != nil {
		return RunReport{}, fmt.Errorf("adapt: create worker pool: %w", err)
	}

	// One shared accumulator merges every tool's observations at emit time
	// (it is internally synchronized; each inner ingest pre-registers its
	// own URLs).
	acc := urlintel.NewAccumulator()

	var (
		diagMu sync.Mutex
		diag   error
	)

	// One slot per (tool, target), tool-major: tools in selection order,
	// targets in input order — the same deterministic order the submit loop
	// below uses. Slots are initialized cancelled WITH their tool and target
	// identity filled in: a slot whose job never started (forced shutdown,
	// pool close mid-submit) keeps an honest cancelled status and is never a
	// zero-valued placeholder.
	results := make([]ToolResult, len(cfg.Tools)*len(cfg.Targets))
	i := 0
	for _, t := range cfg.Tools {
		for _, target := range cfg.Targets {
			results[i] = ToolResult{Tool: t.Name, Target: target, Status: ResultCancelled}
			i++
		}
	}

	slot := 0
submitLoop:
	for _, t := range cfg.Tools {
		det := dets[t.Name]
		for _, target := range cfg.Targets {
			i := slot
			slot++
			if det.Status == discovery.StatusMissing {
				// Skipped: never an execution attempt.
				results[i] = ToolResult{
					Tool:   t.Name,
					Target: target,
					Status: ResultSkipped,
					Err:    fmt.Errorf("adapt: %s: %s", t.Name, det.Reason),
				}
				continue
			}
			t, target := t, target
			if _, serr := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
				defer func() {
					if r := recover(); r != nil {
						// A panicking job body (for example a hostile custom
						// descriptor's args func) must fail its slot, never
						// the run. The pool also contains the panic; this
						// records the outcome.
						results[i] = ToolResult{
							Tool:   t.Name,
							Target: target,
							Status: ResultFailed,
							Err:    fmt.Errorf("adapt: %s %s panicked during execution: %v", t.Name, target.Name, r),
						}
					}
				}()
				res, d := runOne(jctx, cfg, e, t, target, acc)
				results[i] = res
				if d != nil {
					diagMu.Lock()
					diag = errors.Join(diag, d)
					diagMu.Unlock()
				}
				return nil, nil
			}}); serr != nil {
				// The run context is done or the pool is closing: the
				// current slot is cancelled with its cause, and the
				// remaining slots keep their initialized cancelled status.
				results[i] = ToolResult{
					Tool:   t.Name,
					Target: target,
					Status: ResultCancelled,
					Err:    fmt.Errorf("adapt: submit %s %s: %w", t.Name, target.Name, serr),
				}
				break submitLoop
			}
		}
	}

	// Shutdown is the join point: it drains every queued and in-flight job
	// before returning. The drain is bounded so a job that ignores
	// cancellation cannot wedge the run forever (the inner ingest shutdowns
	// use the same Phase 4 budget chain).
	budget := cfg.Timeout + shutdownGrace
	if cfg.Timeout <= 0 {
		budget = shutdownForceBudget
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), budget)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()

	var ms urlintel.Snapshot
	if cfg.Metrics != nil {
		ms = cfg.Metrics.Snapshot()
	}
	report := RunReport{Report: acc.Report(), Results: results, Metrics: ms}

	diagMu.Lock()
	joined := diag
	diagMu.Unlock()
	if shutdownErr != nil {
		return report, errors.Join(joined, fmt.Errorf("adapt: pool shutdown: %w", shutdownErr))
	}
	return report, joined
}

// runOne is one (tool, target) job body: it executes the tool through the
// hardened runner with the typed argv, streams the bounded stdout capture
// through the engine's per-(URL, adapter) ingest, and classifies the slot.
//
// The returned error is nil unless the INGEST surfaced non-fatal diagnostics
// (for example cache read/write warnings) that are not accounted for by the
// slot's classification; Run joins those at run level. Cancellation,
// deadline-elapse, and tool failures never reach that return — they are
// classified into the ToolResult.
func runOne(ctx context.Context, cfg Config, e env, t Tool, target asset.Host, acc *urlintel.Accumulator) (ToolResult, error) {
	e = e.sanitized() // nil seams mean production defaults (lookup, runner, limits)
	res := ToolResult{Tool: t.Name, Target: target}

	// Tool existence is checked again at execution time: detection and
	// execution are separate moments, and the executable may have vanished
	// (or a Bin override may point nowhere).
	bin := e.binOf(t)
	path, err := e.lookup(bin)
	if err != nil {
		res.Status = ResultFailed
		res.Err = fmt.Errorf("adapt: %s %s: executable %q not found", t.Name, target.Name, bin)
		return res, nil
	}

	timeout := cfg.ToolTimeout(t.Name)
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	rres, err := e.runner.Run(runCtx, discovery.Cmd{Path: path, Args: t.Args(target)}, e.limits)
	isPerToolTimeout := false
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			isPerToolTimeout = true
		} else {
			// The process never ran to completion. Context classification
			// takes priority: cancellation and deadline-elapse are never tool
			// failures.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return classifyContextSlot(res, ctxErr)
			}
			if errors.Is(err, discovery.ErrExecutableNotFound) {
				res.Status = ResultFailed
				res.Err = fmt.Errorf("adapt: %s %s: %w (%s)", t.Name, target.Name, discovery.ErrExecutableNotFound, bin)
				return res, nil
			}
			res.Status = ResultFailed
			res.Err = fmt.Errorf("adapt: %s %s could not be executed: %w", t.Name, target.Name, err)
			return res, nil
		}
	}

	// The process executed and exited; its bounded stdout capture is valid
	// regardless of the exit code. On a per-tool timeout the captured prefix
	// is still valid — ingest it and report partial. Stream it through the
	// engine (raw lines exist only at the ingest boundary), then classify.
	src := newToolSource(rres.Stdout)
	ierr := urlintel.IngestInto(ctx, urlintel.Config{
		Concurrency:     cfg.IngestWorkers,
		QueueSize:       cfg.QueueSize,
		Timeout:         cfg.Timeout,
		Adapter:         t.Name,
		ParseParameters: cfg.ParseParameters,
		Cache:           cfg.Cache,
		Clock:           cfg.Clock,
		Metrics:         cfg.Metrics,
	}, src, acc)
	res.Lines = src.lineCount()

	if ctxErr := ctx.Err(); ctxErr != nil {
		// Run teardown mid-ingest (outer deadline or run cancellation): the
		// consumed lines are already represented in the report.
		return classifyContextSlot(res, ctxErr)
	}

	if isPerToolTimeout {
		res.Status = ResultPartial
		res.Err = fmt.Errorf("adapt: %s %s: per-tool timeout %s exceeded", t.Name, target.Name, timeout)
		if ierr != nil {
			dw := fmt.Errorf("adapt: %s %s: ingest: %w", t.Name, target.Name, ierr)
			res.Err = errors.Join(res.Err, dw)
			return res, dw
		}
		return res, nil
	}

	switch {
	case rres.ExitCode != 0 && res.Lines == 0 && !rres.StdoutTruncated:
		// Clean failure with no usable output.
		res.Status = ResultFailed
		res.Err = fmt.Errorf("adapt: %s %s: exited with code %d and produced no usable output", t.Name, target.Name, rres.ExitCode)
	case rres.ExitCode != 0 || rres.StdoutTruncated:
		// Partial: non-zero exit with usable output, or stdout cut at the
		// capture cap — the captured URL set is incomplete by definition.
		res.Status = ResultPartial
		res.Err = fmt.Errorf("adapt: %s %s: %s", t.Name, target.Name, partialReason(rres))
	default:
		res.Status = ResultCompleted
	}

	if ierr != nil {
		// Non-fatal ingest diagnostics (cache warnings etc.), joined into
		// the slot summary AND returned for run-level joining. A clean
		// ingest returns nil here.
		dw := fmt.Errorf("adapt: %s %s: ingest: %w", t.Name, target.Name, ierr)
		res.Err = errors.Join(res.Err, dw)
		return res, dw
	}
	return res, nil
}

// classifyContextSlot classifies a slot whose context fired: deadline
// exceeded is timed-out, any other cancellation is cancelled. Lines consumed
// before the fire stay in the report (the caller already streamed them).
func classifyContextSlot(res ToolResult, ctxErr error) (ToolResult, error) {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		res.Status = ResultTimedOut
	} else {
		res.Status = ResultCancelled
	}
	res.Err = fmt.Errorf("adapt: %s %s: %w", res.Tool, res.Target.Name, ctxErr)
	return res, nil
}

// partialReason summarizes why a slot is partial: a non-zero exit code
// and/or stdout truncation at the capture cap.
func partialReason(r discovery.RunResult) string {
	var parts []string
	if r.ExitCode != 0 {
		parts = append(parts, fmt.Sprintf("exited with code %d", r.ExitCode))
	}
	if r.StdoutTruncated {
		parts = append(parts, "stdout exceeded the capture cap; the captured set is incomplete")
	}
	return strings.Join(parts, "; ")
}

// toolSource is the urlintel.LineSource over one tool's bounded stdout
// capture. The adapter stream is raw: lines are trimmed (CRLF and
// surrounding whitespace stripped), blank lines are skipped, and EVERYTHING
// else passes through unchanged. Canonical-boundary rejection (non-URLs,
// oversized lines, control-character garbage) is the engine's Malformed
// accounting — never the adapter's — so garbage from a noisy tool is
// counted, never fatal and never silently dropped. Tool output is never
// trusted as a URL until asset.ParseURL has canonicalized it.
//
// The underlying capture is already bounded by the runner (Limits.MaxOutput),
// so the stream is bounded by construction. Not safe for concurrent use: the
// engine reads a source sequentially by design.
type toolSource struct {
	data  []byte
	pos   int
	lines int
}

// newToolSource wraps a bounded stdout capture.
func newToolSource(stdout []byte) *toolSource {
	return &toolSource{data: stdout}
}

// Next implements urlintel.LineSource. It returns io.EOF at end of stream
// and honors ctx cancellation (returning ctx.Err()).
func (s *toolSource) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for s.pos < len(s.data) {
		start := s.pos
		if nl := bytes.IndexByte(s.data[start:], '\n'); nl >= 0 {
			s.pos = start + nl + 1
		} else {
			s.pos = len(s.data)
		}
		line := strings.TrimSpace(string(s.data[start:s.pos]))
		if line == "" {
			continue
		}
		s.lines++
		return line, nil
	}
	return "", io.EOF
}

// lineCount reports how many non-blank lines were streamed. It is final once
// the source is exhausted (the engine reads to EOF or to cancellation).
func (s *toolSource) lineCount() int {
	return s.lines
}
