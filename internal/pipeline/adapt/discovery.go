package adapt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// discoveryTruncatedFlag is the sticky-flag name this adapter sets when the
// discovery engine reports a truncation. It is the adapter's mapping of the
// engine's own truncation marker — the Truncated field on
// DiscoverResult/SourceResult (and the storedResult JSON key "truncated"),
// which the engine sets when a captured stream hit the capture cap — the
// retained set is incomplete by definition (discovery/doc.go "Partial result
// semantics"). The flag is preserved end-to-end (result → RunReport →
// report) and never swallowed (AGENTS §0.6 carve-out).
//
// The flag name follows the package convention (adapt/doc.go): a sticky flag
// is <engine>_<what>_truncated — never a bare generic like "truncated",
// which could collide across engines in the report's StickyFlags map
// (LOW-3 review finding).
const discoveryTruncatedFlag = "discovery_truncated"

// discoveryQualityFlag is the sticky-flag name this adapter sets when the
// discovery data-quality gate fires (NEW-22). It mirrors the
// priority_groups_truncated flag's chain: the engine's applied gate writes the
// issues into the cache record (quality_issues), a warm cache hit replays them
// verbatim (sticky), the adapter maps any issue to this flag (flagged≠failed),
// and the runner/exposers preserve it (stage flags → summary → JSON). The
// completed-with-flag carve-out is legal per AGENTS §0.6.
//
// discovery_quality_flagged is a stage-level sticky flag (like priority_groups_truncated) — it lives in StageRecord.StickyFlags, survives cache replay, and is not auto-merged to RunReport.StickyFlags; consumers must check stage flags.
const discoveryQualityFlag = "discovery_quality_flagged"

// discoveryStage adapts the passive-subdomain-discovery engine
// (internal/discovery) to the pipeline Stage contract.
//
// Config derivation (engine Config from StageInput only — no pre-resolved
// pipeline defaults):
//
//   - Concurrency/QueueSize/Timeout/Rate/Burst come from in.Bounds verbatim.
//     0 means "engine default/disabled" per the discovery engine's own
//     semantics (discovery.Config): Concurrency/QueueSize must be positive
//     (the worker pool validates them), Timeout 0 disables per-job
//     deadlines, Rate <= 0 disables job-start rate limiting, Burst < 1
//     means 1. The pipeline runner resolves the per-stage defaults before
//     invoking the stage, so values reached here are already resolved; the
//     adapter deliberately does not apply pipeline.WithDefaults itself.
//   - Cache passes through (nil = caching disabled, which the engine
//     supports).
//   - Now bridges the pipeline clock: the discovery engine's time seam is
//     func() time.Time, so Now returns in.Clock.Now(). Every discovered
//     host's provenance timestamp therefore comes from the injected clock.
//   - Sources comes from the "sources" StageParams key (comma-separated
//     tool names; absent/empty/all-empty = engine default = every built-in
//     source). Unknown params are ignored. An unknown source name is passed
//     through and rejected by the engine (surfaced as a failed outcome).
//
// StageParams keys:
//
//	"sources"  comma-separated tool names ("subfinder,amass"). Absent,
//	           empty, or all-whitespace/comma values select the engine
//	           default (every built-in source). Whitespace around each
//	           name is trimmed; empty elements are dropped.
//
// Boundary filtering: the adapter filters every host the engine reports
// through pipeline.FilterHosts(in.Target, ...) before returning it as an
// Additions.Host, so an out-of-domain host produced by a tool (a noise line,
// a cross-domain CNAME-style record, ...) never propagates into the shared
// corpus. Filtering uses pipeline.InDomain on canonical names only — the
// normalization point stays in internal/asset. The input boundary is
// vacuous for this adapter: the discovery engine consumes only the declared
// target (it never receives the corpus host list), so there is no input
// host list to pre-filter. The engine reports no domains (only hosts), so
// Additions.Domains is always empty here: the declared target itself lives
// in StageInput.Target, never in Additions.Domains, and the engine never
// discovers additional domains.
//
// Outcome mapping (engine status → pipeline outcome):
//
//	OutCompleted  → completed   (trustworthy complete result, executed or
//	                             served from cache; an empty-but-successful
//	                             source is still completed)
//	OutPartial    → partial     (non-zero exit with usable output, or a
//	                             capture-cap truncation; the engine stores
//	                             these as StatusIncomplete). When the
//	                             engine's Truncated marker is set the
//	                             result also carries Truncated=true and the
//	                             sticky flag "discovery_truncated" (never
//	                             swallowed; LOW-3 review finding).
//	OutFailed     → failed      (no usable output)
//	OutCancelled  → cancelled   (cancelled or timed out, or the job never
//	                             started)
//	OutSkipped    → incomplete  (the source was not run — tool MISSING).
//	                             The pipeline has no "skipped" value, and
//	                             claiming completed would hide that a source
//	                             never ran; the retained set is incomplete
//	                             by definition, so the honest value is
//	                             incomplete.
//
// The stage outcome folds the per-source mappings with exactly the
// pipeline's own precedence (run.go foldOutcome): cancelled if any source
// was cancelled; else failed if any source failed and none completed; else
// incomplete if any source was skipped; else completed if every source
// completed; else partial. A failed source among completed ones is
// therefore partial (never completed, never failed) — the same fold the
// runner applies to stages.
//
// Counts: ItemsProcessed is the total hosts the engine report carries (the
// sum over the per-source host lists — a host seen via two sources counts
// twice, matching the engine's per-source report). ItemsFailed is the total
// malformed input lines the report carries (lines that did not normalize to
// a valid host; diagnostics that never poison results).
//
// Errors: an engine error is wrapped with context ("stage %s: %w") and
// returned; the outcome is failed. Cancellation is reported through Outcome
// cancelled with the context error attached, exactly as the pipeline
// contract documents: when the stage context has fired, cancellation wins
// over any engine error detail — the engine error is joined into the wrapped
// context error (isContextError traverses the join, so the cancelled
// classification is preserved) instead of being replaced by it, and the Go
// error return is nil, because returning a non-context error would force the
// runner's failed classification (run.go normalizeResult). The engine
// report's per-source statuses already reflect the cancellation honestly.
// Every error path still merges the engine report's honest retained
// observations into Additions (LOW-2 review finding): the forced-pool-
// shutdown path returns a populated report alongside its error, and the
// runner merges a failed stage's additions.
type discoveryStage struct {
	// runner is the engine's Runner seam (nil = ExecRunner, production).
	runner discovery.Runner
	// lookPath is the engine's LookupFunc seam (nil = exec.LookPath,
	// production).
	lookPath discovery.LookupFunc
}

var _ pipeline.Stage = (*discoveryStage)(nil)

// NewDiscoveryStage constructs the discovery pipeline stage. The hooks are
// constructor test seams only — nil means production behavior (the engine's
// own defaults: ExecRunner and exec.LookPath). Tests inject hermetic fakes
// through these, never through StageParams (params are operator
// configuration, not test plumbing).
func NewDiscoveryStage(runner discovery.Runner, lookPath discovery.LookupFunc) pipeline.Stage {
	return &discoveryStage{runner: runner, lookPath: lookPath}
}

// Name implements pipeline.Stage.
func (s *discoveryStage) Name() pipeline.StageName { return pipeline.StageDiscover }

// Run implements pipeline.Stage.
func (s *discoveryStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	cfg := discovery.Config{
		Sources:     sourcesParam(in.Config),
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		Cache:       in.Cache,
		Runner:      s.runner,
		LookPath:    s.lookPath,
		Now: func() time.Time {
			return in.Clock.Now()
		},
		Quality: qualityConfigFromParams(in.Config),
	}

	report, err := discovery.Run(ctx, in.Target, cfg)
	if err != nil {
		// Every error path still merges the engine report's honest retained
		// observations into Additions (LOW-2 review finding): the only
		// populated-report+error path is a forced pool shutdown, whose report
		// carries the sources that did run, and the runner merges a failed
		// stage's additions anyway. The quality flag is preserved even on
		// error paths: a gate abort (qualityGateError) returns a populated
		// report with QualityIssues alongside the error.
		additions := discoveryAdditions(in, report)
		var qflags map[string]bool
		if len(report.QualityIssues) > 0 {
			qflags = map[string]bool{discoveryQualityFlag: true}
			if anyTruncated(report.Results) {
				qflags[discoveryTruncatedFlag] = true
			}
		} else if anyTruncated(report.Results) {
			qflags = map[string]bool{discoveryTruncatedFlag: true}
		}
		if ctx.Err() != nil {
			// The stage context fired (the engine surfaces it as a wrapped
			// context error, or the pool was forced down after cancellation).
			// Cancellation is carried by the outcome, with the context's own
			// error attached and the engine's shutdown detail joined in so
			// nothing is lost — the runner's isContextError traverses the
			// join and keeps the cancelled classification (INFO-1 review
			// finding, mirroring the httpprobe adapter).
			joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), err))
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: joined, Additions: additions, StickyFlags: qflags, Truncated: len(qflags) > 0 && qflags[discoveryTruncatedFlag]}, nil
		}
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped, Additions: additions, StickyFlags: qflags, Truncated: len(qflags) > 0 && qflags[discoveryTruncatedFlag]}, wrapped
	}

	truncated := anyTruncated(report.Results)
	qualityFlagged := len(report.QualityIssues) > 0
	var flags map[string]bool
	if truncated || qualityFlagged {
		flags = make(map[string]bool)
		if truncated {
			flags[discoveryTruncatedFlag] = true
		}
		if qualityFlagged {
			flags[discoveryQualityFlag] = true
		}
	}
	res := pipeline.StageResult{
		Outcome:        foldReportOutcome(report.Results),
		Truncated:      truncated,
		StickyFlags:    flags,
		ItemsProcessed: reportItemCount(report.Results),
		ItemsFailed:    reportMalformedCount(report.Results),
		Additions:      discoveryAdditions(in, report),
	}
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// A report can carry OutCancelled statuses with a nil engine error
		// (clean drain after mid-run cancellation or a per-job deadline):
		// attach the context error so the outcome's cancellation is
		// unambiguous.
		res.Err = ctx.Err()
	}
	return res, nil
}

// discoveryAdditions builds the stage's Additions from the engine report.
// The discovery engine reports hosts only — the declared target lives in
// in.Target, never in Additions.Domains, and the engine never discovers
// URLs — so Domains and URLs are always nil. Every reported host is
// boundary-filtered through pipeline.FilterHosts before it can enter the
// shared corpus. It is used on every path: the success path and both engine
// error branches (LOW-2 review finding: a forced pool shutdown returns a
// populated report alongside its error, and those honest retained
// observations must still propagate).
func discoveryAdditions(in pipeline.StageInput, report discovery.Report) pipeline.StageAdditions {
	return pipeline.StageAdditions{
		Domains: nil,
		Hosts:   pipeline.FilterHosts(in.Target, report.All()),
		URLs:    nil,
	}
}

// sourcesParam reads the "sources" StageParams key defensively:
// comma-separated tool names with surrounding whitespace trimmed and empty
// elements dropped. Absent, empty, or all-empty values select the engine
// default (nil = every built-in source). Unknown source names are passed
// through unchanged — the engine validates them and its error surfaces as a
// failed outcome.
func sourcesParam(params map[string]string) []string {
	v, ok := params["sources"]
	if !ok {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil // empty selection: engine default, every built-in source
	}
	return out
}

// qualityConfigFromParams reads the data-quality gate StageParams keys
// defensively (NEW-22). Recognized keys (all optional, unknown keys ignored):
//
//	quality_max_per_source        int   (>0)
//	quality_divergence_ratio      float (>0)
//	quality_divergence_min_count  int   (>0)
//	quality_abort_on_flag         bool  ("1", "true", "yes" — case-insensitive)
//
// Zero or absent values normalize to DefaultQualityConfig via
// NormalizeQualityConfig; parse failures are ignored (the default wins).
func qualityConfigFromParams(params map[string]string) discovery.QualityConfig {
	var qc discovery.QualityConfig
	if v, ok := params["quality_max_per_source"]; ok {
		if iv, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			qc.MaxPerSource = iv
		}
	}
	if v, ok := params["quality_divergence_ratio"]; ok {
		if fv, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			qc.DivergenceRatio = fv
		}
	}
	if v, ok := params["quality_divergence_min_count"]; ok {
		if iv, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			qc.DivergenceMinCount = iv
		}
	}
	if v, ok := params["quality_abort_on_flag"]; ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			qc.AbortOnFlag = true
		}
	}
	return discovery.NormalizeQualityConfig(qc)
}

// foldReportOutcome reduces the per-source report statuses to one pipeline
// outcome with exactly the pipeline's own fold precedence (run.go
// foldOutcome), using the documented per-status mapping.
func foldReportOutcome(results []discovery.SourceResult) pipeline.Outcome {
	anyCancelled, anyFailed, anyIncomplete, anyCompleted := false, false, false, false
	allCompleted := true
	for _, r := range results {
		switch r.Status {
		case discovery.OutCompleted:
			anyCompleted = true
		case discovery.OutPartial:
			allCompleted = false
		case discovery.OutFailed:
			anyFailed = true
			allCompleted = false
		case discovery.OutCancelled:
			anyCancelled = true
			allCompleted = false
		case discovery.OutSkipped:
			anyIncomplete = true
			allCompleted = false
		}
	}
	switch {
	case anyCancelled:
		return pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		return pipeline.OutcomeFailed
	case anyIncomplete:
		return pipeline.OutcomeIncomplete
	case allCompleted:
		return pipeline.OutcomeCompleted
	default:
		return pipeline.OutcomePartial
	}
}

// anyTruncated reports whether any source result carries the engine's
// truncation marker (the Truncated field — captured output hit the capture
// cap, so the retained set is incomplete by definition). The flag is
// propagated to Truncated=true and the sticky "discovery_truncated" flag
// (LOW-3 review finding: named flags never collide across engines), never
// swallowed.
func anyTruncated(results []discovery.SourceResult) bool {
	for _, r := range results {
		if r.Truncated {
			return true
		}
	}
	return false
}

// reportItemCount is the report's honest processed count: the total hosts
// the per-source result lists carry (a host seen via two sources counts
// twice, matching the engine's own per-source report).
func reportItemCount(results []discovery.SourceResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Hosts)
	}
	return n
}

// reportMalformedCount is the report's honest failed count: the total
// malformed input lines the per-source results carry (lines that did not
// normalize to a valid host).
func reportMalformedCount(results []discovery.SourceResult) int {
	n := 0
	for _, r := range results {
		n += r.Malformed
	}
	return n
}
