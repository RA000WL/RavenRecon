package pipeline

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// RunReport is the deterministic, ordered report of one Run.
type RunReport struct {
	// Target is the validated canonical target.
	Target asset.Domain

	// Stages holds one entry per configured stage, in config order. A
	// stage that never ran (the run context was cancelled before its
	// turn) is recorded with Outcome cancelled and Err = the context
	// error.
	Stages []StageRecord

	// Outcome is the pipeline-level fold of the per-stage outcomes (see
	// foldOutcome for the exact precedence).
	Outcome Outcome

	// StartAt and EndAt are stamped by the injected clock.
	StartAt time.Time
	EndAt   time.Time

	// ItemsProcessed and ItemsFailed are the sums of the per-stage
	// counters.
	ItemsProcessed int
	ItemsFailed    int

	// Truncated reports whether any stage cut its retained set at a cap,
	// including a runner-side corpus cap. Consumers must treat a
	// truncated run as an incomplete retained set (never a silent
	// completed result).
	Truncated bool

	// Domains, Hosts, URLs are the final merged corpus after all stages
	// (first-seen dedup, deterministic order). Domains are the discovered
	// scope — the declared target itself lives in Target. Hosts+URLs are
	// bounded by the per-stage MaxCorpusSize caps (hosts kept first,
	// URLs tail-dropped).
	Domains []asset.Domain
	Hosts   []asset.Host
	URLs    []asset.URL

	// Results is the final merged results channel after all stages
	// (first-seen dedup, deterministic order; per-channel MaxOutput caps
	// at each merge). Every channel mirrors one report.Context data
	// channel 1:1 (internal/report/context.go) — the report stage will
	// consume the full Context from this struct in a later milestone. A
	// channel cut by a cap carries its <channel>_truncated sticky flag
	// below, marking the retained set incomplete (never silently
	// completed).
	Results Results

	// StickyFlags names the runner-level cuts — "corpus_capped" when a
	// per-stage MaxCorpusSize cut the corpus at a merge, plus one
	// "<channel>_truncated" flag per results channel a per-stage
	// MaxOutput cap cut (ips_truncated, attack_paths_truncated, ...; see
	// mergeResults for the full vocabulary). Preserved end-to-end (result
	// → RunReport → report stage): consumers must treat a flagged run as
	// an incomplete retained set (AGENTS §0.6 carve-out — a completed
	// run may carry the flags, never silence them).
	StickyFlags map[string]bool
}

// StageRecord is one stage's recorded outcome in run order.
type StageRecord struct {
	Name    StageName
	Outcome Outcome

	// Truncated reports that the stage cut its retained set at a cap.
	Truncated bool

	// StickyFlags is a defensive copy of the stage's StickyFlags.
	StickyFlags map[string]bool

	// ItemsProcessed and ItemsFailed are the stage's counters, always
	// >= 0: negative counters are a contract violation and are clamped to
	// 0 (the stage is recorded failed — see normalizeResult), so a
	// recorded record and its mirrored stage_finished event always
	// validate.
	ItemsProcessed int
	ItemsFailed    int

	// Err carries the failure detail for Outcome failed, or the context
	// error for a stage that never ran.
	Err error

	// Duration is measured with the injected clock.
	Duration time.Duration
}

// Run validates cfg, resolves every selected stage name against the
// provided stages slice, and runs the stages strictly in cfg.Stages
// order.
//
// Stage resolution: a provided stage is used if and only if its Name
// appears in cfg.Stages — provided stages whose name is not in the
// selection are skipped (never run). A selected name with no matching
// provided stage is a run error: nothing runs, and the error is returned
// with a zero RunReport. Duplicate names among the provided stages are
// also a run error (the mapping would be ambiguous). Resolution happens
// before any stage runs, so a run is all-or-nothing at start — with one
// exception: a provided stage whose Name() panics cannot be identified,
// so a selection entry it was needed for is recorded failed (never
// invoked) and the run continues (panic isolation covers Name()).
//
// Failure semantics: fail-continue. A failed stage records its outcome
// and error in the report and the runner proceeds with the next stage
// unless the run context is cancelled. Cancellation stops new stages:
// once ctx is cancelled, every remaining stage is recorded with Outcome
// cancelled (Err = ctx.Err()) without being invoked. A per-stage Timeout
// cancels only that stage's context; the run itself continues with the
// next stage.
//
// Errors: Run returns an error only for configuration or resolution
// problems (nil clock, invalid config, unresolvable stage). Run-level
// outcomes — including cancellation — are carried in the report, never
// as an error.
//
// Stage events: when cfg.Observer is non-nil, the runner emits exactly
// one stage_started event immediately before each stage entry is invoked
// or recorded, and exactly one stage_finished event after its StageRecord
// is finalized — including entries that never run (recorded cancelled
// because the run context was already cancelled, or failed because the
// provided stage could not be resolved). Emission is synchronous, in stage
// order, before Run returns: no goroutines, no buffering. At is the
// injected clock's Now() at emission time, Identity is the stage name,
// Phase is "stage", Severity is the default (info), and Sequence stays 0
// — the bus assigns sequence numbers at publish time. The finished
// payload mirrors the recorded StageRecord (outcome, truncation,
// counters, duration) and carries the record's error text bounded by the
// event package (empty when the record has none). A hostile observer that
// panics is contained: the event is dropped and the run continues.
//
// The explicit cache and clock parameters are the operative values; a
// nil cache disables caching for the run, and a nil clock is rejected
// (an injected clock is required for determinism).
func Run(ctx context.Context, cfg ScanConfig, cache cache.Cache, clock runtime.Clock, stages []Stage) (RunReport, error) {
	if clock == nil {
		return RunReport{}, ConfigError{Field: "clock", Problem: "nil runtime.Clock: an injected clock is required for determinism"}
	}
	if err := cfg.Validate(); err != nil {
		return RunReport{}, err
	}
	byName, namePanicked, err := indexStages(stages)
	if err != nil {
		return RunReport{}, err
	}
	type stageEntry struct {
		stage   Stage
		nameErr error
	}
	entries := make([]stageEntry, len(cfg.Stages))
	for i, name := range cfg.Stages {
		s, ok := byName[name]
		if !ok {
			if namePanicked {
				// A provided stage could not be identified (its Name()
				// panicked), so this selection entry cannot be
				// resolved: record it failed and continue.
				entries[i] = stageEntry{nameErr: fmt.Errorf("stage %q: could not resolve: no matching stage provided (note: a provided stage's Name() panicked during resolution)", name)}
				continue
			}
			return RunReport{}, ConfigError{
				Field:   fmt.Sprintf("stages[%d]", i),
				Problem: fmt.Sprintf("stage %q: no matching stage provided", name),
			}
		}
		entries[i] = stageEntry{stage: s}
	}

	report := RunReport{Target: cfg.Target, StartAt: clock.Now()}
	var domains []asset.Domain
	var hosts []asset.Host
	var urls []asset.URL
	var results Results
	seen := make(map[asset.Identity]struct{})
	resultsSeen := make(map[string]struct{})

	for i, entry := range entries {
		name := cfg.Stages[i]
		sr := StageRecord{Name: name}
		emitStageStarted(cfg.Observer, clock, name)
		if ctx.Err() != nil {
			// The run is cancelled: this stage and every remaining
			// stage is recorded cancelled without being invoked.
			sr.Outcome = OutcomeCancelled
			sr.Err = ctx.Err()
			report.Stages = append(report.Stages, sr)
			emitStageFinished(cfg.Observer, clock, sr)
			continue
		}
		if entry.nameErr != nil {
			// Unresolvable (Name() panicked during resolution): recorded
			// failed without being invoked.
			sr.Outcome = OutcomeFailed
			sr.Err = entry.nameErr
			report.Stages = append(report.Stages, sr)
			emitStageFinished(cfg.Observer, clock, sr)
			continue
		}
		eff := effectiveConfig(cfg, name)
		input := StageInput{
			Target:    cfg.Target,
			Domains:   domains,
			Hosts:     hosts,
			URLs:      urls,
			Results:   results,
			Bounds:    eff,
			Config:    effectiveStageParams(cfg, name),
			Clock:     clock,
			Cache:     cache,
			OutputDir: cfg.OutputDir,
		}
		stageCtx := ctx
		cancel := func() {}
		if eff.Timeout > 0 {
			stageCtx, cancel = context.WithTimeout(ctx, eff.Timeout)
		}
		t0 := clock.Now()
		res, err := runStage(entry.stage, stageCtx, input)
		t1 := clock.Now()
		cancel()
		sr = normalizeResult(sr, res, err)
		sr.Duration = t1.Sub(t0)
		report.Stages = append(report.Stages, sr)
		emitStageFinished(cfg.Observer, clock, sr)
		// Corpus propagation: merge this stage's additions into the
		// shared corpus handed to the remaining stages (first-seen dedup,
		// deterministic order), then enforce this stage's MaxCorpusSize
		// cap. Runner-side capping records the corpus_capped sticky flag
		// at the report level (AGENTS §0.6 carve-out): the stage's own
		// outcome is untouched, but the flag and Truncated mark the
		// retained set incomplete.
		domains = mergeCorpus(domains, res.Additions.Domains, seen)
		hosts = mergeCorpus(hosts, res.Additions.Hosts, seen)
		urls = mergeCorpus(urls, res.Additions.URLs, seen)
		var capped bool
		hosts, urls, capped = capCorpus(eff.MaxCorpusSize, hosts, urls)
		if capped {
			report.Truncated = true
			if report.StickyFlags == nil {
				report.StickyFlags = make(map[string]bool)
			}
			report.StickyFlags["corpus_capped"] = true
		}
		// Results propagation: merge this stage's result-channel additions
		// into the shared channel handed to the remaining stages (first-seen
		// dedup, deterministic order), then enforce this stage's MaxOutput
		// cap per channel. The merge runs regardless of the stage's outcome
		// — a failed stage's retained results are still merged (mirroring
		// the corpus Additions semantics above). Runner-side capping records
		// one <channel>_truncated sticky flag per cut channel at the report
		// level (AGENTS §0.6 carve-out, mirroring corpus_capped): the
		// stage's own outcome is untouched, but the flags and Truncated mark
		// the retained set incomplete. A stage never sees its own additions:
		// StageInput.Results is the merged state before this stage's turn.
		for _, ch := range mergeResults(&results, res.Results, resultsSeen, eff.MaxOutput) {
			report.Truncated = true
			if report.StickyFlags == nil {
				report.StickyFlags = make(map[string]bool)
			}
			report.StickyFlags[ch+"_truncated"] = true
		}
	}

	report.EndAt = clock.Now()
	report.Outcome = foldOutcome(report.Stages)
	if len(report.Stages) == 0 && ctx.Err() != nil {
		// Pre-cancelled with no stages configured: cancelled beats the
		// vacuous completed of the empty fold (more honest).
		report.Outcome = OutcomeCancelled
	}
	report.Domains = domains
	report.Hosts = hosts
	report.URLs = urls
	report.Results = results
	for _, sr := range report.Stages {
		report.ItemsProcessed += sr.ItemsProcessed
		report.ItemsFailed += sr.ItemsFailed
		report.Truncated = report.Truncated || sr.Truncated
	}
	return report, nil
}

// emitStageStarted publishes one stage_started event immediately before a
// stage entry is invoked or recorded. A nil observer is the off switch: a
// single nil check, nothing else. The event is canonical and pre-bus: At
// is the injected clock's Now() at emission, Identity is the stage name,
// Phase is "stage", Severity is the default, and Sequence stays 0 (the
// bus assigns sequence numbers at publish time).
func emitStageStarted(obs event.Observer, clock runtime.Clock, name StageName) {
	if obs == nil {
		return
	}
	observeStageEvent(obs, event.New(event.KindStageStarted, clock.Now(), event.StageStarted{Name: string(name)}).
		WithPhase("stage").
		WithIdentity(string(name)))
}

// emitStageFinished publishes one stage_finished event after a stage
// entry's StageRecord is finalized, mirroring the record exactly: Outcome,
// Truncated, ItemsProcessed, ItemsFailed, Duration, and Err (the record's
// error message, empty when none, bounded by the event package's message
// bound). Emission rules match emitStageStarted.
func emitStageFinished(obs event.Observer, clock runtime.Clock, sr StageRecord) {
	if obs == nil {
		return
	}
	errMsg := ""
	if sr.Err != nil {
		errMsg = sr.Err.Error()
	}
	observeStageEvent(obs, event.New(event.KindStageFinished, clock.Now(),
		event.NewStageFinished(string(sr.Name), string(sr.Outcome), sr.Truncated,
			sr.ItemsProcessed, sr.ItemsFailed, sr.Duration, errMsg)).
		WithPhase("stage").
		WithIdentity(string(sr.Name)))
}

// observeStageEvent delivers ev to the observer under panic containment,
// recovering in the same goroutine as the Observe call — the same
// containment shape as the event package's deriveSafe and the pipeline's
// runStage recovery. A panicking or hostile observer must never crash the
// run: the event is dropped and the run continues unchanged. A nil
// observer is a no-op.
func observeStageEvent(obs event.Observer, ev event.Event) {
	if obs == nil {
		return
	}
	defer func() {
		_ = recover() // contained: drop the event, keep the run alive
	}()
	obs.Observe(ev)
}

// indexStages maps the provided stages by name, rejecting nil stages and
// duplicate names. A provided stage whose Name() panics cannot be
// identified: it is skipped from the map and reported through the
// returned namePanicked flag so the runner can attribute unresolvable
// selection entries honestly instead of crashing.
func indexStages(stages []Stage) (byName map[StageName]Stage, namePanicked bool, err error) {
	byName = make(map[StageName]Stage, len(stages))
	for i, s := range stages {
		if s == nil {
			return nil, false, ConfigError{
				Field:   fmt.Sprintf("stages[%d]", i),
				Problem: "nil stage provided",
			}
		}
		name, nameErr := safeStageName(s)
		if nameErr != nil {
			namePanicked = true
			continue
		}
		if _, dup := byName[name]; dup {
			return nil, false, ConfigError{
				Field:   fmt.Sprintf("stages[%d]", i),
				Problem: fmt.Sprintf("duplicate stage %q provided; each stage name may appear at most once", name),
			}
		}
		byName[name] = s
	}
	return byName, namePanicked, nil
}

// safeStageName calls s.Name() under panic recovery. A panicking Name()
// returns an error instead of crashing the run.
func safeStageName(s Stage) (name StageName, err error) {
	defer func() {
		if r := recover(); r != nil {
			name = ""
			err = fmt.Errorf("stage Name() panicked: %v", r)
		}
	}()
	return s.Name(), nil
}

// effectiveConfig resolves the per-stage bounds: defaults, overridden
// field-wise by the StageBounds entry for name (non-zero fields only).
func effectiveConfig(cfg ScanConfig, name StageName) StageConfig {
	eff := DefaultStageConfig()
	b, ok := cfg.StageBounds[name]
	if !ok {
		return eff
	}
	if b.MaxConcurrency != 0 {
		eff.MaxConcurrency = b.MaxConcurrency
	}
	if b.QueueSize != 0 {
		eff.QueueSize = b.QueueSize
	}
	if b.Timeout != 0 {
		eff.Timeout = b.Timeout
	}
	if b.Rate != 0 {
		eff.Rate = b.Rate
	}
	if b.Burst != 0 {
		eff.Burst = b.Burst
	}
	if b.MaxCorpusSize != 0 {
		eff.MaxCorpusSize = b.MaxCorpusSize
	}
	if b.MaxOutput != 0 {
		eff.MaxOutput = b.MaxOutput
	}
	return eff
}

// effectiveStageParams resolves the per-stage parameters: the StageParams
// entry for name, defensively copied so a stage can never mutate the
// caller's config (nil when the stage has none).
func effectiveStageParams(cfg ScanConfig, name StageName) map[string]string {
	p, ok := cfg.StageParams[name]
	if !ok || p == nil {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// runStage invokes one stage, isolating panics: a panicking stage is
// recorded as failed with a structured error and the run continues. The
// stage name in the error is read under the same recovery, so a stage
// whose Name() also panics cannot crash the process.
func runStage(s Stage, ctx context.Context, in StageInput) (res StageResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = StageResult{}
			name := "<unnamed>"
			if n, nameErr := safeStageName(s); nameErr == nil {
				name = string(n)
			}
			err = fmt.Errorf("stage %s panicked: %v", name, r)
		}
	}()
	return s.Run(ctx, in)
}

// normalizeResult applies the runner's stage-contract rules:
//
//   - a claimed Outcome cancelled with a context error — returned or
//     attached, context.Canceled or context.DeadlineExceeded — stays
//     cancelled and the error is recorded: a stage whose context fired
//     may surface ctx.Err() and must not be punished for it;
//   - any other non-nil error return forces Outcome failed, whatever the
//     stage claimed, and is recorded as Err;
//   - any other non-failed outcome with an attached Err is a contract
//     violation and is recorded as failed with that error;
//   - an empty or unknown Outcome is a contract violation and is
//     recorded as failed;
//   - negative ItemsProcessed/ItemsFailed are a contract violation and
//     are recorded as failed with a structured error (the counters are
//     impossible: the event layer rejects negative counts by design, so
//     a record could never be mirrored into a valid stage_finished
//     event). Counters are clamped to >= 0 on EVERY path below — the
//     error-return and cancellation paths keep their truthful outcomes
//     but must still never carry a negative count into the record or
//     the emitted event;
//   - StickyFlags is defensively copied into the report (never aliased);
//   - Truncated=true with Outcome completed and an empty StickyFlags set
//     is downgraded to Outcome incomplete — exactly one behavior, pinned
//     here and documented on StageResult.
func normalizeResult(sr StageRecord, res StageResult, err error) StageRecord {
	switch {
	case err != nil && res.Outcome == OutcomeCancelled && isContextError(err):
		sr.Outcome = OutcomeCancelled
		sr.Err = err
	case err != nil:
		sr.Outcome = OutcomeFailed
		sr.Err = err
	case res.Outcome == OutcomeCancelled && res.Err != nil && isContextError(res.Err):
		sr.Outcome = OutcomeCancelled
		sr.Err = res.Err
	case res.Err != nil && res.Outcome != OutcomeFailed:
		sr.Outcome = OutcomeFailed
		sr.Err = fmt.Errorf("stage %s: outcome %q with error: %w", sr.Name, res.Outcome, res.Err)
	case !ValidOutcome(res.Outcome):
		sr.Outcome = OutcomeFailed
		sr.Err = fmt.Errorf("stage %s: invalid outcome %q (vocabulary: completed/partial/failed/cancelled/incomplete)", sr.Name, res.Outcome)
	case res.ItemsProcessed < 0 || res.ItemsFailed < 0:
		sr.Outcome = OutcomeFailed
		sr.Err = fmt.Errorf("stage %s: negative counters (processed=%d failed=%d): counters must be >= 0", sr.Name, res.ItemsProcessed, res.ItemsFailed)
	default:
		sr.Outcome = res.Outcome
		sr.Err = res.Err
	}
	sr.Truncated = res.Truncated
	if len(res.StickyFlags) > 0 {
		sr.StickyFlags = make(map[string]bool, len(res.StickyFlags))
		for k, v := range res.StickyFlags {
			sr.StickyFlags[k] = v
		}
	}
	// Clamp counters to >= 0 unconditionally: whatever outcome path fired
	// above, a negative count in the record would make the mirrored
	// stage_finished event invalid (the event layer rejects negative
	// counts by design), so the record must never carry one.
	if res.ItemsProcessed < 0 {
		sr.ItemsProcessed = 0
	} else {
		sr.ItemsProcessed = res.ItemsProcessed
	}
	if res.ItemsFailed < 0 {
		sr.ItemsFailed = 0
	} else {
		sr.ItemsFailed = res.ItemsFailed
	}
	if sr.Outcome == OutcomeCompleted && sr.Truncated && len(sr.StickyFlags) == 0 {
		sr.Outcome = OutcomeIncomplete
	}
	return sr
}

// isContextError reports whether err is the context package's own
// cancellation or deadline signal.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// foldOutcome reduces the per-stage outcomes to one pipeline outcome in
// this exact precedence, top rule first:
//
//  1. cancelled   — if any stage outcome is cancelled;
//  2. failed      — else if at least one stage failed and no stage
//     completed;
//  3. incomplete  — else if any stage outcome is incomplete (a stage's
//     honest incomplete, or the runner's truncation
//     downgrade: completed + Truncated with empty
//     StickyFlags);
//  4. completed   — else if every stage outcome is completed (vacuously
//     true for an empty stage list);
//  5. partial     — otherwise (some completed together with any partial
//     or failed outcomes).
//
// The per-stage truncation downgrade happens before the fold, so
// "truncation without flags" is already an incomplete outcome here; the
// fold never inspects Truncated or StickyFlags itself. Run overrides the
// vacuous completed of an empty stage list to cancelled when the run
// context was already cancelled before any stage ran.
func foldOutcome(stages []StageRecord) Outcome {
	anyCancelled, anyFailed, anyIncomplete, anyCompleted := false, false, false, false
	allCompleted := true
	for _, s := range stages {
		switch s.Outcome {
		case OutcomeCompleted:
			anyCompleted = true
		case OutcomePartial:
			allCompleted = false
		case OutcomeFailed:
			anyFailed = true
			allCompleted = false
		case OutcomeCancelled:
			anyCancelled = true
			allCompleted = false
		case OutcomeIncomplete:
			anyIncomplete = true
			allCompleted = false
		}
	}
	switch {
	case anyCancelled:
		return OutcomeCancelled
	case anyFailed && !anyCompleted:
		return OutcomeFailed
	case anyIncomplete:
		return OutcomeIncomplete
	case allCompleted:
		return OutcomeCompleted
	default:
		return OutcomePartial
	}
}
