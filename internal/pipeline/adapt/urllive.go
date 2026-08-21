package adapt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// UrlliveStickyFlag is the sticky-flag name the urllive adapter records
// when any URL liveness probe hit a hard cap (header block or entry cap) or
// the retained set was otherwise cut. It follows the <engine>_<what>_truncated
// convention and is preserved end-to-end (result → RunReport → report), never
// swallowed (AGENTS §0.6).
const UrlliveStickyFlag = "urllive_truncated"

// urlliveStage adapts the httpprobe URL liveness engine (ProbeURLs) to the
// pipeline.Stage contract.
type urlliveStage struct {
	transport http.RoundTripper
}

var _ pipeline.Stage = (*urlliveStage)(nil)

// NewUrlliveStage constructs the urllive pipeline stage wrapping
// internal/httpprobe ProbeURLs.
//
// transport is the constructor test-seam hook: pass nil for production (the
// engine uses its bounded default transport), or a hermetic fake in tests. It
// is never read from StageParams.
func NewUrlliveStage(transport http.RoundTripper) pipeline.Stage {
	return &urlliveStage{transport: transport}
}

// Name implements pipeline.Stage.
func (s *urlliveStage) Name() pipeline.StageName { return pipeline.StageURLLive }

// Run implements pipeline.Stage.
func (s *urlliveStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	// Input URLs: historical + JS-fed + crawl (already merged by runner).
	// Filter to in-domain canonical URLs only. The engine validates the whole
	// list against the target and rejects the call on any out-of-domain URL,
	// so every out-of-domain corpus URL is filtered out before the engine sees
	// it. IP literals and zero URLs are never in scope.
	urls := filterURLs(in.Target, in.URLs)

	// Empty filtered input: short-circuit with completed and zero work — but
	// only for a canonical target. The engine tolerates an empty list (empty
	// report, no pool), so this is a pure optimization; a non-canonical
	// target falls through so the engine's own honesty is not masked. The
	// context is still honored first, exactly as the engine checks ctx.Err()
	// before its own work.
	if len(urls) == 0 && targetCanonical(in.Target) {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, nil
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// Config derivation: bounds pass-through, StageParams override.
	cfg := httpprobe.Config{
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		Cache:       in.Cache,
		Clock:       in.Clock,
		Transport:   s.transport,
	}
	// StageParams overrides: urllive_concurrency, urllive_timeout,
	// urllive_rate_limit. Unknown keys ignored.
	if v, ok := in.Config["urllive_concurrency"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			cfg.Concurrency = n
		}
	}
	if v, ok := in.Config["urllive_timeout"]; ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			cfg.Timeout = d
			cfg.RequestTimeout = d
		} else if err == nil && d == 0 {
			cfg.RequestTimeout = 0
		}
	}
	if v, ok := in.Config["urllive_rate_limit"]; ok {
		if n, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && n >= 0 {
			cfg.Rate = n
		}
	}
	// Also handle generic request_timeout alias for consistency with httpprobe stage.
	if v, ok := in.Config["request_timeout"]; ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			cfg.RequestTimeout = d
		}
	}

	// Non-canonical target fallback: let the engine return its scope error
	// rather than masking it with a completed outcome. We still need to ensure
	// the engine is called for non-canonical targets even when urls is empty
	// after filtering? The empty short-circuit above already gated on
	// targetCanonical, so non-canonical falls through to here even with empty
	// filtered list — but we have already handled empty+canonical case. For
	// non-canonical, we must still call ProbeURLs to get its validation error.
	// However ProbeURLs requires at least one URL to validate domain? It
	// validates domain first, so empty list after domain validation would just
	// return empty report. To preserve honest error for non-canonical, we
	// check targetCanonical before calling and surface failed if not canonical.
	if !targetCanonical(in.Target) {
		// Let the engine's own validateScope produce the error for honesty,
		// but we must call it. If urls is empty, the engine would return
		// empty without error, masking the non-canonical. So we synthesize
		// the same error the engine would for probe.
		_, err := httpprobe.ProbeURLs(ctx, in.Target, urls, cfg)
		if err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
		}
		// If engine unexpectedly succeeded (should not for non-canonical),
		// fall through to normal handling — but we already know target is
		// non-canonical, so treat as failed.
		wrapped := fmt.Errorf("stage %s: target %q is not canonical", s.Name(), in.Target.Name)
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
	}

	report, err := httpprobe.ProbeURLs(ctx, in.Target, urls, cfg)

	if err != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), err))
		return buildUrlliveResult(report, pipeline.OutcomeCancelled, joined), nil
	}
	if err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return buildUrlliveResult(report, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return buildUrlliveResult(report, pipeline.OutcomeCancelled, wrapped), nil
	}

	return buildUrlliveResult(report, foldUrlliveOutcomes(report), nil), nil
}

// buildUrlliveResult maps one engine live report onto the pipeline's
// StageResult shape: honest counters, truncation flag, and the results-channel
// addition (LiveRecords). No corpus additions. The Cached flag is stripped
// for pipeline determinism: a cache-hit and a fresh execution produce
// identical Results after the merge (the cache is an optimization, not a
// semantic difference), mirroring how the dns/httpprobe results channels
// carry no Cached marker.
func buildUrlliveResult(report httpprobe.LiveReport, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		ItemsProcessed: len(report.Records),
		ItemsFailed:    urlliveFailedCount(report),
		Err:            err,
	}
	if urlliveTruncated(report) {
		res.Truncated = true
		res.StickyFlags = map[string]bool{UrlliveStickyFlag: true}
	}
	// Results channel: LiveRecords are the liveness observations.
	// Copy and strip the Cached marker so that a cache-hit and a fresh
	// execution DeepEqual (cache-hit parity, T4).
	clean := make([]httpprobe.LiveRecord, len(report.Records))
	for i, r := range report.Records {
		r.Cached = false
		clean[i] = r
	}
	res.Results = pipeline.Results{
		LiveRecords: clean,
	}
	return res
}

// foldUrlliveOutcomes reduces the engine's per-URL outcomes to one stage
// outcome. Mapping: cancelled > failed > completed (spec simplified). Any
// record whose Err is context.Canceled (run cancellation) folds to
// cancelled; any other Err (timeout, refused, dns, etc.) folds to failed
// when no completed record exists; otherwise completed. Truncated records
// are considered completed for outcome purposes — the flag, not the
// outcome, marks the set incomplete (AGENTS §0.6 carve-out).
func foldUrlliveOutcomes(report httpprobe.LiveReport) pipeline.Outcome {
	if len(report.Records) == 0 {
		return pipeline.OutcomeCompleted
	}
	anyCompleted, anyFailed, anyCancelled := false, false, false
	for _, r := range report.Records {
		if r.Truncated {
			anyCompleted = true
			continue
		}
		if r.Err != nil && isContextError(r.Err) {
			anyCancelled = true
			continue
		}
		if r.Err != nil {
			anyFailed = true
			continue
		}
		anyCompleted = true
	}
	switch {
	case anyCancelled:
		return pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		return pipeline.OutcomeFailed
	default:
		return pipeline.OutcomeCompleted
	}
}

// urlliveFailedCount is the honest failed count: records with a transport
// error (non-nil Err) that are not truncated and not cancelled? But for
// pipeline counters, ItemsFailed should count failed observations (timeout,
// refused with error, etc.), not truncated. We count any record with Err
// non-nil that is not a truncated observation (truncated's headers-truncated
// error is not a failure, it is a completed-with-flag carve-out per AGENTS
// §0.6).
func urlliveFailedCount(report httpprobe.LiveReport) int {
	n := 0
	for _, r := range report.Records {
		if r.Truncated {
			continue
		}
		if r.Err != nil {
			n++
		}
	}
	return n
}

// urlliveTruncated reports whether any live record hit a cap.
func urlliveTruncated(report httpprobe.LiveReport) bool {
	for _, r := range report.Records {
		if r.Truncated {
			return true
		}
	}
	return false
}
