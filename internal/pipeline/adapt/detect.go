package adapt

import (
	"context"
	"errors"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/apis"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/cloud"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/js"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/takeover"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/triage"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/web"
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

// detectFindingListsTruncatedFlag is the sticky flag this adapter records
// when any finding it returns carries the asset model's Truncated marker
// (asset.Finding.Truncated — a MergeFindings union was cut at one of the
// model's per-list bounds: evidence, related assets, relationships, or
// metadata). It is preserved end-to-end (result → RunReport → report),
// never swallowed (AGENTS §0.6).
//
// The name follows the package convention (adapt/doc.go): a sticky flag is
// <engine>_<what>_truncated. "finding_lists" names exactly what was cut —
// the bounded lists INSIDE merged findings — and is kept distinct from
// detectFindingsTruncatedFlag (the run-level maxFindingsPerRun cap on the
// number of findings), which can fire alongside it.
const detectFindingListsTruncatedFlag = "detect_finding_lists_truncated"

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

// NewDetectStageWithPacks returns a detect stage pre-loaded with the web
// pack (v2.0 Batch 2). If registry is nil a fresh registry is created;
// otherwise the provided registry is reused. Web pack rules are loaded via
// web.Rules() → ValidateRule → Registry.Register (deep copy) → Validate
// graph → Seal (startup confinement), matching the Batch 1 loader story.
// The original NewDetectStage(nil) empty-registry behavior is unchanged;
// callers that want the web pack use this constructor or LoadWebPack.
//
// The registry is sealed before returning, confining further registration
// to startup (the Q1 lock). AllStages is unchanged — the pack is an
// explicit opt-in, never auto-discovered.
func NewDetectStageWithPacks(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := web.Rules()
	if err != nil {
		return nil, fmt.Errorf("web pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("web pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// LoadWebPack loads the web pack into registry through the SDK's
// ValidateRule → Register → Validate → Seal path. It is the wiring helper
// for callers that already own a registry and want explicit control.
func LoadWebPack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("web pack: registry must not be nil")
	}
	rules, err := web.Rules()
	if err != nil {
		return fmt.Errorf("web pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("web pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// LoadJsPack loads the JS pack (v2.0 Batch 3) into registry through the
// same SDK path as LoadWebPack: ValidateRule → Register → Validate → Seal.
// It is the wiring helper for callers that want explicit control over the
// JS pack. The registry is sealed before returning.
func LoadJsPack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("js pack: registry must not be nil")
	}
	rules, err := js.Rules()
	if err != nil {
		return fmt.Errorf("js pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("js pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// LoadApisPack loads the APIs pack (v2.0 Batch 4) into registry through the
// same SDK path as LoadWebPack/LoadJsPack: ValidateRule → Register → Validate → Seal.
// It is the wiring helper for callers that want explicit control over the
// APIs pack. The registry is sealed before returning.
func LoadApisPack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("apis pack: registry must not be nil")
	}
	rules, err := apis.Rules()
	if err != nil {
		return fmt.Errorf("apis pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("apis pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// LoadCloudPack loads the cloud pack (v2.0 Batch 5) into registry through the
// same SDK path as LoadWebPack/LoadJsPack/LoadApisPack: ValidateRule →
// Register → Validate → Seal. It is the wiring helper for callers that want
// explicit control over the cloud pack. The registry is sealed before returning.
func LoadCloudPack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("cloud pack: registry must not be nil")
	}
	rules, err := cloud.Rules()
	if err != nil {
		return fmt.Errorf("cloud pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("cloud pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// LoadTriagePack loads the triage pack (v2.0 Batch 6) into registry through
// the same SDK path as LoadWebPack/LoadJsPack/LoadApisPack/LoadCloudPack:
// ValidateRule → Register → Validate → Seal. It is the wiring helper for
// callers that want explicit control over the triage pack. The registry is
// sealed before returning.
func LoadTriagePack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("triage pack: registry must not be nil")
	}
	rules, err := triage.Rules()
	if err != nil {
		return fmt.Errorf("triage pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("triage pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// LoadTakeoverPack loads the takeover pack (v2.1 Batch 1) into registry
// through the same SDK path as LoadWebPack/LoadJsPack/LoadApisPack/
// LoadCloudPack/LoadTriagePack: ValidateRule → Register → Validate → Seal.
// It is the wiring helper for callers that want explicit control over the
// takeover pack. The registry is sealed before returning.
func LoadTakeoverPack(registry *detect.Registry) error {
	if registry == nil {
		return fmt.Errorf("takeover pack: registry must not be nil")
	}
	rules, err := takeover.Rules()
	if err != nil {
		return fmt.Errorf("takeover pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return fmt.Errorf("takeover pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return err
	}
	registry.Seal()
	return nil
}

// NewDetectStageWithJsPack returns a detect stage pre-loaded with the JS
// pack (v2.0 Batch 3). It mirrors NewDetectStageWithPacks but for the JS
// pack. If registry is nil a fresh registry is created. The registry is
// sealed before returning. AllStages is unchanged — the pack is explicit
// opt-in, never auto-discovered.
func NewDetectStageWithJsPack(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := js.Rules()
	if err != nil {
		return nil, fmt.Errorf("js pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("js pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// NewDetectStageWithApisPack returns a detect stage pre-loaded with the APIs
// pack (v2.0 Batch 4). It mirrors NewDetectStageWithJsPack but for the APIs
// pack. If registry is nil a fresh registry is created. The registry is
// sealed before returning. AllStages is unchanged — the pack is explicit
// opt-in, never auto-discovered.
func NewDetectStageWithApisPack(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := apis.Rules()
	if err != nil {
		return nil, fmt.Errorf("apis pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("apis pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// NewDetectStageWithCloudPack returns a detect stage pre-loaded with the
// cloud pack (v2.0 Batch 5). It mirrors NewDetectStageWithApisPack but for
// the cloud pack. If registry is nil a fresh registry is created. The
// registry is sealed before returning. AllStages is unchanged — the pack is
// explicit opt-in, never auto-discovered.
func NewDetectStageWithCloudPack(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := cloud.Rules()
	if err != nil {
		return nil, fmt.Errorf("cloud pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("cloud pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// NewDetectStageWithTriagePack returns a detect stage pre-loaded with the
// triage pack (v2.0 Batch 6). It mirrors NewDetectStageWithCloudPack but for
// the triage pack. If registry is nil a fresh registry is created. The
// registry is sealed before returning. AllStages is unchanged — the pack is
// explicit opt-in, never auto-discovered.
func NewDetectStageWithTriagePack(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := triage.Rules()
	if err != nil {
		return nil, fmt.Errorf("triage pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("triage pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// NewDetectStageWithTakeoverPack returns a detect stage pre-loaded with the
// takeover pack (v2.1 Batch 1). It mirrors NewDetectStageWithTriagePack but
// for the takeover pack. If registry is nil a fresh registry is created. The
// registry is sealed before returning. AllStages is unchanged — the pack is
// explicit opt-in, never auto-discovered.
func NewDetectStageWithTakeoverPack(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	rules, err := takeover.Rules()
	if err != nil {
		return nil, fmt.Errorf("takeover pack: %w", err)
	}
	for _, r := range rules {
		if err := registry.Register(r); err != nil {
			return nil, fmt.Errorf("takeover pack register %q: %w", r.ID, err)
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
}

// NewDetectStageWithAllPacks returns a detect stage pre-loaded with the web
// pack (Batch 2), the JS pack (Batch 3), the APIs pack (Batch 4), the cloud
// pack (Batch 5), the triage pack (Batch 6), and the takeover pack (Batch
// v2.1). If registry is nil a fresh registry is created; otherwise the
// provided registry is reused. All packs are loaded via ValidateRule →
// Register → Validate → Seal (startup confinement). AllStages is unchanged —
// packs are explicit opt-in. The original NewDetectStageWithPacks (web-only),
// NewDetectStageWithJsPack (js-only), NewDetectStageWithApisPack
// (apis-only), NewDetectStageWithCloudPack (cloud-only),
// NewDetectStageWithTriagePack (triage-only), and
// NewDetectStageWithTakeoverPack (takeover-only) remain available for callers
// that want a single pack.
func NewDetectStageWithAllPacks(registry *detect.Registry) (pipeline.Stage, error) {
	if registry == nil {
		registry = detect.NewRegistry()
	}
	for _, load := range []func() ([]detect.Rule, error){web.Rules, js.Rules, apis.Rules, cloud.Rules, triage.Rules, takeover.Rules} {
		rules, err := load()
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if err := registry.Register(r); err != nil {
				return nil, fmt.Errorf("pack register %q: %w", r.ID, err)
			}
		}
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	registry.Seal()
	return NewDetectStage(registry), nil
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
// alone, marks the retained set incomplete (AGENTS §0.6). A second,
// asset-level signal exists: a returned finding carrying Finding.Truncated
// (a MergeFindings union cut at one of the model's per-list bounds) sets
// Truncated=true and StickyFlags[detectFindingListsTruncatedFlag]=true
// while the outcome stays whatever the rules earned — completed + flag is
// the legal §0.6 carve-out for a retained set cut at a cap, because the
// marker is recomputed from the returned/replayed findings on every path
// (success AND cache replay). Both signals can fire together; their flags
// accumulate.
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
	// Truncation markers are never swallowed (AGENTS §0.6): the engine's
	// run-level FindingsTruncated cap and the asset-level Finding.Truncated
	// merge marker on any returned finding each set Truncated and their own
	// named sticky flag. Both are computed from the returned/replayed
	// findings on EVERY path — success, engine error, and cache replay
	// alike — because a cache hit serves stored findings as decoded assets:
	// the marker rides the record and the flag is recomputed from whatever
	// the stage returns, so the §0.6 chain holds trivially.
	flags := map[string]bool{}
	if rep.FindingsTruncated {
		res.Truncated = true
		flags[detectFindingsTruncatedFlag] = true
	}
	for _, f := range rep.Findings {
		if f.Truncated {
			res.Truncated = true
			flags[detectFindingListsTruncatedFlag] = true
			break
		}
	}
	if len(flags) > 0 {
		res.StickyFlags = flags
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
