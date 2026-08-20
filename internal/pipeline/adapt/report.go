package adapt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// reportStage adapts internal/report (report.Run) into a pipeline.Stage.
//
// Construction is explicit — there is no registry: NewReportStage returns
// the stage and callers pass it to pipeline.Run as part of the stages slice.
type reportStage struct {
	// registry is the engine's reporter-registry seam
	// (report.EngineConfig.Registry). nil means the engine's production
	// default registry (report.NewDefaultRegistry — the four builtin
	// reporters: json, csv, markdown, html).
	registry *report.Registry
}

var _ pipeline.Stage = (*reportStage)(nil)

// NewReportStage returns the report pipeline stage wrapping
// internal/report.
//
// registry is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine's default registry with the builtin reporters),
// or a hermetic registry built with report.NewRegistry + Register in
// tests. It is never read from StageParams — params are operator
// configuration, not test plumbing.
func NewReportStage(registry *report.Registry) pipeline.Stage {
	return &reportStage{registry: registry}
}

// Name implements pipeline.Stage.
func (s *reportStage) Name() pipeline.StageName { return pipeline.StageReport }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Registry    ← the constructor seam   (nil = the engine's default
//	                                      registry: json, csv, markdown,
//	                                      html)
//	OutputDir   ← in.OutputDir           (required by the engine; created
//	                                      as needed)
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = the engine's own default
//	                                      deadline — the report engine
//	                                      DEFAULTS 0, it never disables)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//
// The report engine has no Rate/Burst configuration, so those stage bounds
// are deliberately not passed (documented; they are unused by this stage).
// Zero Concurrency/QueueSize are DEFAULTED by the engine (not rejected,
// unlike the other engines), and a negative Timeout is the engine's
// config-validation error path (mapped to Outcome failed below).
//
// StageParams: none. in.Config is never read — the stage has no documented
// parameter keys, and unknown keys are ignored by construction.
//
// Context: the report Context is composed from the StageInput —
//
//	Target    ← in.Target.Name (display metadata; the engine derives and
//	                            sanitizes the report base name from it)
//	StartedAt ← in.Clock.Now()  (EndedAt equals it: the pipeline tracks no
//	                            run bracket yet, so both timestamps are the
//	                            stage's single honest "now"; equal values
//	                            are valid — the engine rejects only an
//	                            EndedAt BEFORE StartedAt)
//	EndedAt   ← in.Clock.Now()
//	Domains/Hosts/URLs ← the in-scope filtered corpus
//	every other data channel ← the results channel as the earlier stages
//	                            produced it (T3d): IPs, Ports, Services,
//	                            Endpoints, JavaScript, Parameters,
//	                            Technologies, Secrets, Evidence, Findings,
//	                            TLSCertificates, SourceMaps, Relationships,
//	                            Surfaces, Groups, AttackPaths — copied
//	                            whole, never rebuilt (the engine's
//	                            NewModel re-normalizes, deduplicates, and
//	                            sorts everything)
//
// The error/runtime/cache/execution stats channels stay empty: the report
// stage has no pipeline counterparts for them (the runner's own bookkeeping
// is not exposed on the report Context). Results channels get NO additional
// scope filtering here: they are pipeline-composed (each producer filtered
// its own inputs), and relationship edges cannot be meaningfully
// scope-filtered without corrupting the graph (adapt/doc.go T3d). The zero
// corpus is valid — an empty report renders honestly.
//
// Boundary (mandatory, both sides): input corpus entries are pre-filtered
// with pipeline.InDomain/FilterHosts and filterURLs (canonical names only —
// the single normalization point stays in internal/asset), so no
// out-of-domain entry ever reaches the report. The report engine produces
// no corpus assets (it writes files), so the stage produces NO corpus
// additions — Additions stay empty by construction.
//
// No empty-input short-circuit: rendering the report IS this stage's work
// — an empty corpus still renders a valid (empty) report, so the engine
// always runs. The non-canonical-target gate of the sibling adapters does
// not apply here either: there is no filtered-empty short-circuit to gate;
// an unsound scope filter yields an empty in-scope corpus, and the engine
// renders the honest empty report for it.
//
// Outcome mapping (engine report outcome → pipeline outcome; the engine
// folds its per-report statuses into RunResult.Outcome itself):
//
//	RunResult.Outcome.Completed  -> completed
//	RunResult.Outcome.Incomplete -> partial    (completed mixed with failed
//	                                           reports — the successes are
//	                                           kept, the run is not
//	                                           completed)
//	RunResult.Outcome.Failed     -> failed     (every attempted report
//	                                           failed)
//	RunResult.Outcome.Cancelled  -> cancelled  (render work never executed)
//
// Cancellation is mapped exactly as the sibling adapters do: an engine
// error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail; a clean engine
// drain followed by a fired stage context reports cancelled with the
// context error; per-report cancellations with a still-live stage context
// (the engine's own teardown) report cancelled with a nil Err — the
// outcome, not the error field, carries cancellation. A pre-cancelled
// context is handled honestly on every path: the engine returns cancelled
// per-report statuses for it, and the stage's own context check drives the
// cancelled outcome. A cancelled or failed render never leaves a file
// (the engine commits only validated renders atomically).
//
// Counters: ItemsProcessed is the engine run's Completed + Failed +
// Cancelled report count (every report the engine attempted);
// ItemsFailed is Failed. Skipped reports are NOT counted as processed —
// the engine explicitly did not attempt them (disabled or unselected).
//
// Truncation: the report engine reports NO truncation or overflow signals
// (its renderer has no retention caps; a run with no active reporters is a
// valid empty run), so this adapter never sets Truncated or a sticky flag.
// The absence is deliberate and documented (adapt/doc.go T2d); a future
// engine cap must surface here.
func (s *reportStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}

	// The production default is the engine's default registry with the
	// four builtin reporters. The seam's nil never reaches the engine —
	// the engine rejects a nil Registry. NewDefaultRegistry cannot fail
	// (the builtin IDs are unique and valid), but the error is surfaced
	// honestly if it ever does.
	reg := s.registry
	if reg == nil {
		var err error
		reg, err = report.NewDefaultRegistry()
		if err != nil {
			wrapped := fmt.Errorf("stage %s: default registry: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
		}
	}

	// Boundary filter, input side (adapt/doc.go): the corpus may carry
	// entries outside the declared scope. Filtering operates on canonical
	// names only. The report engine re-derives every identity through the
	// Phase 2 builders (NewModel) and rejects a non-canonical entry — the
	// filtered corpus is canonical by construction.
	domains := filterDomains(in.Target, in.Domains)
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)
	urls := filterURLs(in.Target, in.URLs)

	// The run bracket: the pipeline tracks no per-run timestamps yet, so
	// the stage's single honest "now" fills both ends (equal values are
	// valid). The injected clock keeps the result deterministic through
	// the runner; a nil clock (direct caller) falls back to the wall
	// clock — the report content itself never carries these timestamps.
	now := time.Now()
	if in.Clock != nil {
		now = in.Clock.Now()
	}
	rctx := report.Context{
		Target:          in.Target.Name,
		StartedAt:       now,
		EndedAt:         now,
		Domains:         domains,
		Hosts:           hosts,
		URLs:            urls,
		IPs:             in.Results.IPs,
		Ports:           in.Results.Ports,
		Services:        in.Results.Services,
		Endpoints:       in.Results.Endpoints,
		JavaScript:      in.Results.JavaScript,
		Parameters:      in.Results.Parameters,
		Technologies:    in.Results.Technologies,
		Secrets:         in.Results.Secrets,
		Evidence:        in.Results.Evidence,
		Findings:        in.Results.Findings,
		TLSCertificates: in.Results.TLSCertificates,
		SourceMaps:      in.Results.SourceMaps,
		Relationships:   in.Results.Relationships,
		Surfaces:        in.Results.Surfaces,
		Groups:          in.Results.Groups,
		AttackPaths:     in.Results.AttackPaths,
	}

	return s.runReport(ctx, in, reg, rctx)
}

// runReport derives the engine config from the StageInput, calls
// report.Run, and maps the engine's result and error onto the pipeline's
// StageResult shape.
func (s *reportStage) runReport(ctx context.Context, in pipeline.StageInput, reg *report.Registry, rctx report.Context) (pipeline.StageResult, error) {
	cfg := report.EngineConfig{
		// Bounds pass-through: 0 = engine default per the ENGINE's own
		// documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Unlike the other engines the report engine
		// DEFAULTS zero Concurrency/QueueSize (positive defaults) and zero
		// Timeout (its own default deadline) instead of rejecting them; a
		// negative Timeout is its config-validation error path. Rate/Burst
		// have no engine counterpart and are not passed (documented on
		// Run).
		Registry:    reg,
		OutputDir:   in.OutputDir,
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Clock: in.Clock,
		Cache: in.Cache,
	}

	res, engineErr := report.Run(ctx, cfg, rctx)

	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal (pipeline contract); the engine's
	// detail is joined so nothing is lost. The result's honest per-report
	// statuses are still reflected in the mapped result.
	if engineErr != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
		return s.buildReportResult(res, pipeline.OutcomeCancelled, joined), nil
	}
	if engineErr != nil {
		// Any other engine error (invalid config — nil registry, empty
		// OutputDir, negative Timeout, unknown reporter ID — model
		// normalization, pool failure, shutdown failure): failed, wrapped
		// with context.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		return s.buildReportResult(res, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight
		// (including a pre-cancelled context): the stage outcome is
		// cancelled, with the context error attached and a nil Go error
		// return — the outcome, not the error field, carries cancellation.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return s.buildReportResult(res, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Aggregate-outcome mapping (the engine folds per-report statuses
	// itself; mapping table documented on Run).
	r := s.buildReportResult(res, foldReportRunOutcome(res.Outcome), nil)
	if r.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Per-report cancellations with a still-live stage context report
		// cancelled with a nil Err (documented on Run). If the stage
		// context fired in the window between the check above and the fold,
		// attach it so the cancellation is unambiguous.
		r.Err = fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
	}
	return r, nil
}

// buildReportResult maps one engine run result onto the pipeline's
// StageResult shape: the honest counters and empty Additions (report
// produces no corpus additions — T2d). No truncation mapping exists — the
// report engine reports no truncation signals (documented on Run).
func (s *reportStage) buildReportResult(res report.RunResult, outcome pipeline.Outcome, err error) pipeline.StageResult {
	return pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: reportProcessed(res),
		ItemsFailed:    reportFailed(res),
	}
}

// foldReportRunOutcome maps the engine's aggregate outcome onto the
// pipeline's five-value vocabulary (mapping table documented on
// reportStage.Run). An unrecognized engine outcome is a contract violation
// and folds to failed — it must never be masked as completed. (The name is
// foldReportRunOutcome, not foldReportOutcome — that name belongs to the
// discovery adapter's per-source fold.)
func foldReportRunOutcome(o report.Outcome) pipeline.Outcome {
	switch o {
	case report.OutcomeCompleted:
		return pipeline.OutcomeCompleted
	case report.OutcomeIncomplete:
		return pipeline.OutcomePartial
	case report.OutcomeFailed:
		return pipeline.OutcomeFailed
	case report.OutcomeCancelled:
		return pipeline.OutcomeCancelled
	default:
		return pipeline.OutcomeFailed
	}
}

// reportProcessed returns the engine run's honest processed count: every
// report the engine attempted, including cancelled and failed ones.
// Skipped reports are excluded — the engine explicitly did not attempt
// them (documented on Run).
func reportProcessed(res report.RunResult) int {
	n := 0
	for _, r := range res.Reports {
		switch r.Status {
		case report.ReportStatusCompleted, report.ReportStatusFailed, report.ReportStatusCancelled:
			n++
		}
	}
	return n
}

// reportFailed returns the engine run's honest "could not be processed"
// count: every report that failed to render or commit.
func reportFailed(res report.RunResult) int {
	n := 0
	for _, r := range res.Reports {
		if r.Status == report.ReportStatusFailed {
			n++
		}
	}
	return n
}
