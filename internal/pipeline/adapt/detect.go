package adapt

import (
	"context"
	"errors"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// detectFindingsTruncatedFlag is the sticky flag this adapter records when
// the engine report carries its retention-cap signal
// (detect.Report.FindingsTruncated — findings cut at the engine's fixed
// maxFindingsPerRun). It is preserved end-to-end (result → RunReport →
// report), never swallowed (AGENTS §0.6 names the detect engine's
// findings cap as a truncation signal).
//
// The name follows the package convention (adapt/doc.go): a sticky flag is
// <engine>_<what>_truncated — never a bare generic like "truncated", which
// could collide across engines in the report's StickyFlags map. "findings"
// is the engine's canonical term for the retained set the cap cuts.
const detectFindingsTruncatedFlag = "detect_findings_truncated"

// detectStage adapts internal/detect (detect.Run) into a pipeline.Stage.
//
// Construction is explicit — there is no registry: NewDetectStage returns
// the stage and callers pass it to pipeline.Run as part of the stages slice.
type detectStage struct {
	// registry is the engine's rule-registry seam (detect.EngineConfig.
	// Registry). nil means the engine's EMPTY registry (detect.NewRegistry)
	// — the v1.3 default: no rules ship with the framework
	// (internal/detect/examples is the only pack, explicitly loaded, never
	// auto-loaded; AGENTS §5 / ROADMAP D2).
	registry *detect.Registry
}

var _ pipeline.Stage = (*detectStage)(nil)

// NewDetectStage returns the detect pipeline stage wrapping
// internal/detect.
//
// registry is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine's empty registry — D2), or a hermetic registry
// built with detect.NewRegistry + Register in tests. It is never read from
// StageParams — params are operator configuration, not test plumbing.
func NewDetectStage(registry *detect.Registry) pipeline.Stage {
	return &detectStage{registry: registry}
}

// Name implements pipeline.Stage.
func (s *detectStage) Name() pipeline.StageName { return pipeline.StageDetect }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Registry    ← the constructor seam   (nil = the EMPTY registry, D2)
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = engine: no default job deadline)
//	Rate        ← in.Bounds.Rate         (0 = engine: pacing disabled; a
//	                                      negative Rate is the engine's
//	                                      config-validation error)
//	Burst       ← in.Bounds.Burst        (< 1 = engine: normalized to 1)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//
// Zero bounds are passed through verbatim and mean "engine default/disabled"
// per the ENGINE's documented semantics (adapt/doc.go), NOT pre-resolved
// pipeline defaults (the pipeline runner has already resolved 0 to positive
// defaults; a direct caller passing 0 gets the engine's own
// config-validation error, mapped to Outcome failed below).
//
// StageParams: none. in.Config is never read — the stage has no documented
// parameter keys, and unknown keys are ignored by construction.
//
// Snapshot: the detection Snapshot carries the core-graph asset identities
// derived from the in-scope corpus (in.Domains, in.Hosts, in.URLs — one
// identity each, canonical by construction) PLUS the results channel's
// Phase 2 values the earlier stages produced (T3d): relationships,
// evidence, technologies, secrets, JavaScript, and endpoints are copied
// into the snapshot channels as-is — the engine's own normalization
// deduplicates and sorts them. Findings are NOT inputs (the engine's own
// output, never re-consumed); the remaining results channels
// (IPs/ports/services/URLs/parameters/TLS certificates/source maps/
// surfaces/groups/attack paths) have no snapshot counterpart. The adapter
// never fabricates snapshot entries.
//
// Boundary (mandatory, both sides): input corpus entries are pre-filtered
// with pipeline.InDomain/FilterHosts and filterURLs (canonical names only —
// the single normalization point stays in internal/asset), so no
// out-of-domain identity ever enters the snapshot. The engine cannot
// produce out-of-domain assets through this adapter: findings are named by
// the rules over the snapshot's in-scope identities, and the engine emits
// no corpus additions. Consequently the stage produces NO corpus additions:
// findings are results, propagated by the results channel (T3d —
// buildDetectResult). Additions stay empty by construction.
//
// Empty-input short-circuit: an empty filtered corpus with an EMPTY
// registry is observationally identical to calling the engine (zero rules,
// nothing attempted → vacuous completed), so the stage short-circuits —
// but only when ALL THREE hold: no corpus assets, no snapshot-feeding
// results channels (relationships, evidence, technologies, secrets,
// JavaScript, endpoints — see Run), and an empty registry. A non-empty
// registry may contain rules without RequiredAssetTypes that genuinely
// EXECUTE against an empty corpus (and can fail or emit findings), and a
// non-empty results channel is a non-empty corpus to such rules, so an
// empty corpus alone never skips the engine. The canonicality gate is kept
// for shape-consistency with the sibling adapters: with a non-canonical
// target the scope filter is unsound, so the stage falls through to the
// engine with an empty snapshot and lets the engine produce its own honest
// vacuous (or rule-driven) outcome. Note the declared target itself is NOT
// added to the snapshot: the engine runs over the corpus as the earlier
// stages produced it — the target domain is detected only when the corpus
// carries it.
//
// Outcome mapping (engine report outcome → pipeline outcome; the engine
// folds its per-rule statuses into Report.Outcome itself):
//
//	Report.Outcome.Completed  -> completed
//	Report.Outcome.Incomplete -> partial    (completed mixed with failed
//	                                         rules, or findings cut at
//	                                         maxFindingsPerRun — the
//	                                         retained set is never silently
//	                                         completed, AGENTS §0.6)
//	Report.Outcome.Failed     -> failed     (every attempted rule failed)
//	Report.Outcome.Cancelled  -> cancelled  (work never executed)
//
// Cancellation is mapped exactly as the sibling adapters do: an engine
// error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail; a clean engine
// drain followed by a fired stage context reports cancelled with the
// context error; per-rule cancellations with a still-live stage context
// (the engine's own teardown, e.g. a rule deadline) report cancelled with
// a nil Err — the outcome, not the error field, carries cancellation. A
// pre-cancelled context is handled honestly on every path: the engine
// itself returns cancelled rule statuses for it, and the stage's own
// context check drives the cancelled outcome.
//
// Counters: ItemsProcessed is the engine report's Completed + Failed +
// Cancelled rule count (every rule the engine attempted); ItemsFailed is
// Failed. Skipped rules are NOT counted as processed — the framework
// explicitly did not attempt them (disabled, required kind absent, or a
// failed dependency).
//
// Truncation (Report.FindingsTruncated — findings cut at the engine's
// fixed maxFindingsPerRun): sets Truncated=true and
// StickyFlags[detectFindingsTruncatedFlag]=true, never swallowed. The
// engine reports the truncated run's outcome as incomplete, so the mapped
// stage outcome is partial with the flag set — the flag, never the outcome
// alone, marks the retained set incomplete (AGENTS §0.6).
func (s *detectStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	// Boundary filter, input side (adapt/doc.go): the corpus may carry
	// assets outside the declared scope. Filtering operates on canonical
	// names only.
	domains := filterDomains(in.Target, in.Domains)
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)
	urls := filterURLs(in.Target, in.URLs)

	// The production default is the EMPTY registry (D2): no rules ship
	// with the framework. The seam's nil never reaches the engine — the
	// engine rejects a nil Registry.
	reg := s.registry
	if reg == nil {
		reg = detect.NewRegistry()
	}

	// Empty filtered input short-circuit — only when observationally
	// identical to calling the engine: an empty corpus (including the
	// snapshot-feeding results channels) AND an empty registry (see Run).
	// A non-canonical target makes the scope filter unsound, so the stage
	// falls through to the engine with an empty snapshot (the engine never
	// validates the target, so this yields the engine's own honest outcome,
	// never a fabricated error).
	if len(domains)+len(hosts)+len(urls) == 0 && resultsSnapshotEmpty(in.Results) && reg.Len() == 0 {
		if !targetCanonical(in.Target) {
			return s.runDetect(ctx, in, reg, detect.Snapshot{})
		}
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// The core-graph identities plus the results channel's snapshot values
	// (see Run). Findings are not inputs; the remaining results channels
	// have no snapshot counterpart.
	snap := detect.Snapshot{
		Assets:        buildSnapshotAssets(domains, hosts, urls),
		Relationships: in.Results.Relationships,
		Evidence:      in.Results.Evidence,
		Technologies:  in.Results.Technologies,
		Secrets:       in.Results.Secrets,
		JavaScript:    in.Results.JavaScript,
		Endpoints:     in.Results.Endpoints,
	}
	return s.runDetect(ctx, in, reg, snap)
}

// resultsSnapshotEmpty reports whether every results channel that feeds the
// detection snapshot is empty. The short-circuit must not fire when an
// earlier stage produced snapshot values: rules without RequiredAssetTypes
// genuinely execute against them (see Run).
func resultsSnapshotEmpty(r pipeline.Results) bool {
	return len(r.Relationships) == 0 &&
		len(r.Evidence) == 0 &&
		len(r.Technologies) == 0 &&
		len(r.Secrets) == 0 &&
		len(r.JavaScript) == 0 &&
		len(r.Endpoints) == 0
}

// runDetect derives the engine config from the StageInput, calls
// detect.Run, and maps the engine's report and error onto the pipeline's
// StageResult shape. It is shared by the normal path and the
// non-canonical-target fall-through so both honor the identical error and
// cancellation mapping.
func (s *detectStage) runDetect(ctx context.Context, in pipeline.StageInput, reg *detect.Registry, snap detect.Snapshot) (pipeline.StageResult, error) {
	cfg := detect.EngineConfig{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so
		// through the runner they are never 0); Timeout 0 disables the
		// default per-job deadline (rules carry their own declared
		// deadlines); Rate 0 disables pacing (a negative Rate is the engine's
		// config-validation error); Burst < 1 means 1.
		Registry:    reg,
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Clock: in.Clock,
		Cache: in.Cache,
	}

	rep, engineErr := detect.Run(ctx, cfg, snap)

	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal (pipeline contract); the engine's
	// detail is joined so nothing is lost. The report's honest per-rule
	// statuses are still reflected in the mapped result.
	if engineErr != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
		return s.buildDetectResult(rep, pipeline.OutcomeCancelled, joined), nil
	}
	if engineErr != nil {
		// Any other engine error (invalid config, snapshot normalization,
		// pool failure, shutdown failure): failed, wrapped with context.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		return s.buildDetectResult(rep, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight
		// (including a pre-cancelled context): the stage outcome is
		// cancelled, with the context error attached and a nil Go error
		// return — the outcome, not the error field, carries cancellation.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return s.buildDetectResult(rep, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Aggregate-outcome mapping (the engine folds per-rule statuses itself;
	// mapping table documented on Run).
	res := s.buildDetectResult(rep, foldDetectOutcome(rep.Outcome), nil)
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Per-rule cancellations with a still-live stage context report
		// cancelled with a nil Err (documented on Run). If the stage
		// context fired in the window between the check above and the fold,
		// attach it so the cancellation is unambiguous.
		res.Err = fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
	}
	return res, nil
}

// buildDetectResult maps one engine report onto the pipeline's StageResult
// shape: the honest counters, the truncation flag (never swallowed), the
// results-channel additions (the engine's canonical findings, copied —
// never rebuilt — per the one-normalization-point rule), and empty
// Additions (detect produces no corpus additions — T2d). It is used on
// every path: the success path and both engine-error branches.
func (s *detectStage) buildDetectResult(rep detect.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: detectProcessed(rep),
		ItemsFailed:    detectFailed(rep),
	}
	// Findings are results, never corpus additions. They are copied whole:
	// the rules emitted them over the in-scope snapshot, and findings carry
	// no scope-boundary semantics of their own (adapt/doc.go T3d).
	res.Results.Findings = rep.Findings
	if rep.FindingsTruncated {
		res.Truncated = true
		res.StickyFlags = map[string]bool{detectFindingsTruncatedFlag: true}
	}
	return res
}

// foldDetectOutcome maps the engine's aggregate outcome onto the pipeline's
// five-value vocabulary (mapping table documented on detectStage.Run). An
// unrecognized engine outcome is a contract violation and folds to failed —
// it must never be masked as completed.
func foldDetectOutcome(o detect.Outcome) pipeline.Outcome {
	switch o {
	case detect.OutcomeCompleted:
		return pipeline.OutcomeCompleted
	case detect.OutcomeIncomplete:
		return pipeline.OutcomePartial
	case detect.OutcomeFailed:
		return pipeline.OutcomeFailed
	case detect.OutcomeCancelled:
		return pipeline.OutcomeCancelled
	default:
		return pipeline.OutcomeFailed
	}
}

// detectProcessed returns the engine report's honest processed count: every
// rule the engine attempted, including cancelled and failed ones. Skipped
// rules are excluded — the framework explicitly did not attempt them
// (documented on Run).
func detectProcessed(rep detect.Report) int {
	return rep.Completed + rep.Failed + rep.Cancelled
}

// detectFailed returns the engine report's honest "could not be processed"
// count: every rule that failed to execute.
func detectFailed(rep detect.Report) int {
	return rep.Failed
}

// buildSnapshotAssets derives the detection snapshot's core-graph asset
// identities from the in-scope corpus, in deterministic corpus order
// (domains, then hosts, then URLs). Identities are canonical by
// construction — the corpus is canonical and the assets' own Identity()
// methods are the single normalization point's output.
func buildSnapshotAssets(domains []asset.Domain, hosts []asset.Host, urls []asset.URL) []asset.Identity {
	assets := make([]asset.Identity, 0, len(domains)+len(hosts)+len(urls))
	for _, d := range domains {
		assets = append(assets, d.Identity())
	}
	for _, h := range hosts {
		assets = append(assets, h.Identity())
	}
	for _, u := range urls {
		assets = append(assets, u.Identity())
	}
	return assets
}
