package pipeline

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Outcome is the fixed run-outcome vocabulary (AGENTS.md §0.6). Truncated
// results are never silently completed: a completed outcome with
// Truncated=true is only legal through the documented sticky-flag
// carve-out below, and every other truncation is recorded as incomplete
// or partial.
type Outcome string

const (
	OutcomeCompleted  Outcome = "completed"
	OutcomePartial    Outcome = "partial"
	OutcomeFailed     Outcome = "failed"
	OutcomeCancelled  Outcome = "cancelled"
	OutcomeIncomplete Outcome = "incomplete"
)

// ValidOutcome reports whether o is one of the five vocabulary values.
func ValidOutcome(o Outcome) bool {
	switch o {
	case OutcomeCompleted, OutcomePartial, OutcomeFailed, OutcomeCancelled, OutcomeIncomplete:
		return true
	}
	return false
}

// Stage is one pipeline engine: a unit of work that consumes the shared
// corpus and reports a fixed-vocabulary outcome.
type Stage interface {
	// Name returns the stage's identity; it must be one of the ten
	// StageName constants.
	Name() StageName

	// Run executes the stage against the shared corpus with the resolved
	// per-stage bounds. It must honor ctx cancellation (returning
	// Outcome cancelled) and must never swallow a truncation flag (see
	// StageResult).
	Run(ctx context.Context, in StageInput) (StageResult, error)
}

// StageInput is the shared, read-only input every stage receives.
type StageInput struct {
	// Target is the canonical declared domain (cfg.Target).
	Target asset.Domain

	// Domains, Hosts, URLs are the shared corpus accumulated by the
	// earlier stages (first-seen dedup, deterministic order). Stages must
	// treat the slices as read-only — the runner passes its live slices,
	// so an in-place write corrupts the corpus handed to later stages and
	// the final report; the runner only copies at the merge.
	Domains []asset.Domain
	Hosts   []asset.Host
	URLs    []asset.URL

	// Bounds is the resolved per-stage bound set (defaults applied).
	Bounds StageConfig

	// Config is the per-stage parameter map resolved from
	// ScanConfig.StageParams (nil when the stage has none; never aliased
	// — the runner copies the caller's map).
	Config map[string]string

	// Clock is the injected clock, shared by every stage of the run.
	Clock runtime.Clock

	// Cache is the caller-owned cache; nil means caching is disabled for
	// the run and stages must treat it as a no-op.
	Cache cache.Cache

	// OutputDir is the configured output directory (report stage).
	OutputDir string
}

// StageResult is what one stage run reports.
//
// Stage contract — pinned by the runner (normalizeResult):
//
//   - A non-nil error return forces Outcome failed, whatever the stage
//     claimed. A stage cancelled by its context returns Outcome
//     cancelled, either with a nil error or with the context's own
//     error (context.Canceled / context.DeadlineExceeded — both are
//     kept as cancelled): the outcome, not the error field, carries
//     cancellation.
//   - An empty or unknown Outcome is a contract violation and is
//     recorded as failed.
//   - Truncated must be set whenever the stage cut its retained set at a
//     cap — adapters never swallow truncation flags. A completed outcome
//     with Truncated=true is only legal through the documented
//     carve-out: the stage must name the cut in StickyFlags (for example
//     "corpus_capped") and must preserve that flag end-to-end (result →
//     RunReport → report). completed + Truncated with an empty
//     StickyFlags set is downgraded to Outcome incomplete by the runner —
//     exactly one behavior.
//   - StickyFlags is a map for lookups; the runner copies it into the
//     report and never aliases the stage's map.
type StageResult struct {
	// Outcome is the fixed-vocabulary outcome.
	Outcome Outcome

	// Truncated reports that the stage cut its retained set at a cap.
	Truncated bool

	// StickyFlags names the cuts the stage made (the completed-with-
	// truncation carve-out) and is preserved end-to-end.
	StickyFlags map[string]bool

	// ItemsProcessed and ItemsFailed are the stage's honest counters.
	// Both must be >= 0: a negative counter is a stage-contract
	// violation — the runner records the stage failed with a structured
	// error and clamps the counters to 0 (the event layer rejects
	// negative counts by design, so a record and its mirrored
	// stage_finished event can never carry them). See normalizeResult.
	ItemsProcessed int
	ItemsFailed    int

	// Additions are the corpus entries this stage produced (what it
	// discovered, resolved, or enriched). The runner merges them into
	// the shared corpus handed to the remaining stages (first-seen dedup,
	// deterministic order). Additions are merged even from a failed or
	// partial stage: they are the stage's honest retained output, and the
	// outcome vocabulary already carries the honesty signal. The runner
	// never aliases these slices.
	Additions StageAdditions

	// Err is the failure detail for Outcome failed. For cancelled,
	// return a nil Err: the outcome, not the error field, carries
	// cancellation.
	Err error
}

// StageAdditions is the corpus output of one stage: the canonical assets
// the stage produced, in deterministic order. The runner copies the
// slices at the merge and never aliases them.
type StageAdditions struct {
	Domains []asset.Domain
	Hosts   []asset.Host
	URLs    []asset.URL
}
