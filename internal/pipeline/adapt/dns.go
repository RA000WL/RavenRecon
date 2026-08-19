package adapt

import (
	"context"
	"errors"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// dnsAnswersTruncated is the sticky flag this adapter sets when the engine
// capped an answer set at dns.MaxAnswersPerType. It is the adapter's mapping
// of the engine's own truncation marker (TypeResult.Truncated / the stored
// record's Truncated field, documented in internal/dns as "retained and
// reported (and stored) as incomplete, never as complete"). The flag is set
// whenever any retained type is truncated and is preserved end-to-end
// (result → RunReport → report), never swallowed (AGENTS §0.6).
const dnsAnswersTruncated = "dns_answers_truncated"

// dnsStage adapts internal/dns (dns.Resolve) into a pipeline.Stage.
//
// Construction is explicit — there is no registry: NewDNSStage returns the
// stage and callers pass it to pipeline.Run as part of the stages slice.
type dnsStage struct {
	// resolver is the engine's Resolver seam. nil means the engine's
	// production default (dns.NewNetResolver, the stdlib pure-Go resolver),
	// exactly as dns.Config.Resolver documents. The adapter never
	// substitutes a resolver of its own.
	resolver dns.Resolver
}

var _ pipeline.Stage = (*dnsStage)(nil)

// NewDNSStage returns the DNS pipeline stage wrapping internal/dns.
//
// resolver is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine uses its default resolver), or a hermetic fake in
// tests. It is never read from StageParams — params are operator
// configuration, not test plumbing.
func NewDNSStage(resolver dns.Resolver) pipeline.Stage {
	return &dnsStage{resolver: resolver}
}

// Name implements pipeline.Stage.
func (s *dnsStage) Name() pipeline.StageName { return pipeline.StageDNS }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = engine: no per-job deadline)
//	Rate        ← in.Bounds.Rate         (<= 0 = engine: pacing disabled)
//	Burst       ← in.Bounds.Burst        (< 1 = engine: normalized to 1)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Resolver    ← the constructor seam   (nil = engine: NewNetResolver)
//
// Zero bounds are passed through verbatim and mean "engine default/disabled"
// per the ENGINE's documented semantics (adapt/doc.go), NOT pre-resolved
// pipeline defaults: the pipeline runner has already resolved 0 to the
// pipeline defaults (Concurrency/QueueSize/Burst are positive by then), while
// a direct caller may deliberately pass Timeout 0 / Rate 0 to disable the
// engine's per-job deadline and query pacing. The engine requires a positive
// Concurrency and QueueSize; a direct caller passing 0 for either gets the
// engine's own pool-creation error (mapped to Outcome failed below).
//
// StageParams: none. in.Config is never read — the stage has no documented
// parameter keys, and unknown keys are ignored by construction.
//
// Run never panics on engine errors: every error return of dns.Resolve is
// wrapped with context ("stage %s: %w") and returned; a non-nil error return
// additionally forces Outcome failed or cancelled (never anything else), so
// the runner's normalizeResult contract is honored.
func (s *dnsStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	// Boundary filter, input side (adapt/doc.go): the engine validates the
	// WHOLE host list against the target and rejects the entire call on any
	// out-of-domain host (dns.validateInputHost), so in-domain hosts are
	// pre-filtered here — the engine never sees an out-of-domain input. The
	// filter is label-aware and operates on canonical names only
	// (pipeline.InDomain/FilterHosts); the single normalization point stays
	// in internal/asset.
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)

	// Empty filtered input short-circuit. dns.Resolve treats an empty host
	// list as VALID input (it returns an empty report without starting a
	// pool), so short-circuiting here is observationally identical to
	// calling the engine — but only when the engine would actually accept
	// the call: a non-canonical target is rejected by the engine's own
	// boundary (dns.validateScope) even with zero hosts, so for such a
	// target the adapter falls through to the engine instead of masking the
	// engine's honest error with a completed outcome. The canonicality
	// re-check goes through asset.NewDomain — the single normalization
	// point, exactly as the engine's own scope validation does.
	if len(hosts) == 0 && targetCanonical(in.Target) {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	cfg := dns.Config{
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		Cache:       in.Cache,
		Clock:       in.Clock,
		Resolver:    s.resolver,
	}

	rep, engineErr := dns.Resolve(ctx, in.Target, hosts, cfg)
	return s.mapResult(ctx, in, rep, engineErr)
}

// mapResult translates the engine's report and error into the pipeline's
// fixed outcome vocabulary, additions, counters, and truncation flags.
func (s *dnsStage) mapResult(ctx context.Context, in pipeline.StageInput, rep dns.Report, engineErr error) (pipeline.StageResult, error) {
	// Boundary filter, output side: the engine's report can carry
	// out-of-domain hosts — a queried host's CNAME target is a legitimate
	// DNS observation that may point anywhere (dns doc.go), and the engine
	// resolves the direct target's addresses at depth exactly 1. Cross-domain
	// CNAME targets must never enter the corpus, so every host the engine
	// reported (input hosts plus CNAME targets, merged and sorted by
	// dns.Report.AllHosts) is re-filtered through pipeline.FilterHosts
	// before it can become an Addition. Input hosts re-enter harmlessly: the
	// runner deduplicates by identity (first-seen wins).
	additions := pipeline.StageAdditions{
		Hosts: pipeline.FilterHosts(in.Target, rep.AllHosts()),
	}

	// Engine error paths. Errors are wrapped with context and returned;
	// cancellation is reported through Outcome cancelled with the context
	// error, exactly as the pipeline contract documents.
	if engineErr != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		switch {
		case isContextError(engineErr):
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped, Additions: additions}, wrapped
		case ctx.Err() != nil:
			// The engine failed on teardown (for example a forced pool
			// shutdown) while the stage context was also firing: the
			// cancellation is the dominant, more honest signal.
			wrappedCtx := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrappedCtx, Additions: additions}, wrappedCtx
		default:
			return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped, Additions: additions}, wrapped
		}
	}

	// Honest counters: the engine report's own counts. ItemsProcessed is
	// every host the engine processed (one Report result per input host,
	// including cancelled, failed, and incomplete ones); ItemsFailed is the
	// count of hosts with no usable observation (dns.StatusFailed).
	processed := len(rep.Results)
	failed := 0
	var anyCompleted, anyFailed, anyIncomplete, anyCancelled, anyTruncated bool
	for _, hr := range rep.Results {
		switch hr.Status {
		case dns.StatusCompleted:
			anyCompleted = true
		case dns.StatusFailed:
			anyFailed = true
			failed++
		case dns.StatusIncomplete:
			anyIncomplete = true
		case dns.StatusCancelled:
			anyCancelled = true
		}
		for _, tr := range hr.Types {
			if tr.Truncated {
				anyTruncated = true
			}
		}
	}

	// The stage context fired while the engine ran (cancellation or the
	// pipeline's per-stage deadline): the report already carries the engine's
	// honest per-host statuses, but the stage itself was cancelled — report
	// Outcome cancelled with the context error.
	if err := ctx.Err(); err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		res := pipeline.StageResult{
			Outcome:        pipeline.OutcomeCancelled,
			Err:            wrapped,
			ItemsProcessed: processed,
			ItemsFailed:    failed,
			Additions:      additions,
		}
		return applyTruncation(res, anyTruncated), wrapped
	}

	// Per-host outcome fold over the engine's statuses, with exactly the
	// unified adapter shape (adapt/doc.go "Unified outcome mapping",
	// MEDIUM-1 review unification): cancelled > failed&&!completed >
	// completed > partial.
	//
	//   dns.StatusCompleted  -> a completed host
	//   dns.StatusIncomplete -> an incomplete host (partial results retained:
	//                           some types failed/timed out while others
	//                           completed, or an answer set hit the retention
	//                           cap — never a completed result); folds into
	//                           the partial bucket — the adapters themselves
	//                           never emit OutcomeIncomplete (that bucket is
	//                           reserved for discovery's OutSkipped and the
	//                           runner's truncation downgrade)
	//   dns.StatusFailed     -> a failed host (no usable observation)
	//   dns.StatusCancelled  -> a cancelled host (run teardown, or the job
	//                           timed out as a whole — the engine's own
	//                           StatusCancelled semantics)
	//
	// The fold applies the unified rule in order:
	//   1. any cancelled host                              -> cancelled
	//   2. any failed host and no completed host           -> failed
	//   3. every host completed (vacuous for zero hosts)   -> completed
	//   4. otherwise (completed mixed with failed, or any
	//      incomplete host)                                -> partial
	//
	// Cancellation note: per-host cancellations with a still-live stage
	// context mean the ENGINE's own teardown cut the host's resolution (for
	// example the engine's per-job deadline fired while the stage deadline is
	// disabled), so the stage reports cancelled with a nil Err — the outcome,
	// not the error field, carries cancellation. When the stage context fired
	// instead, the branch above reports the context error.
	outcome := pipeline.OutcomeCompleted
	switch {
	case anyCancelled:
		outcome = pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		outcome = pipeline.OutcomeFailed
	case !anyFailed && !anyIncomplete && !anyCancelled:
		// Every host completed (vacuously true for zero hosts).
		outcome = pipeline.OutcomeCompleted
	default:
		// Completed mixed with failed hosts, or any engine-incomplete host
		// (which folds into the partial bucket).
		outcome = pipeline.OutcomePartial
	}
	res := pipeline.StageResult{
		Outcome:        outcome,
		ItemsProcessed: processed,
		ItemsFailed:    failed,
		Additions:      additions,
	}
	return applyTruncation(res, anyTruncated), nil
}

// applyTruncation attaches the stage's truncation marker: any type the
// engine capped at dns.MaxAnswersPerType (dns.TypeResult.Truncated) sets
// Truncated=true plus the dnsAnswersTruncated sticky flag, never swallowed.
// A truncated host is engine-incomplete by definition, so this outcome is
// never completed-with-truncation — the carve-out downgrade in the runner
// never fires for this adapter.
func applyTruncation(res pipeline.StageResult, anyTruncated bool) pipeline.StageResult {
	if anyTruncated {
		res.Truncated = true
		res.StickyFlags = map[string]bool{dnsAnswersTruncated: true}
	}
	return res
}

// targetCanonical reports whether d is the canonical form asset.NewDomain
// produces — the same boundary check the engine applies (dns.validateScope)
// and the pipeline runner applies (ScanConfig.Validate). It uses the single
// normalization point in internal/asset; it never normalizes itself.
func targetCanonical(d asset.Domain) bool {
	got, err := asset.NewDomain(d.Name, asset.Provenance{})
	return err == nil && got.Name == d.Name
}

// isContextError reports whether err is the context package's own
// cancellation or deadline signal (through any wrapping).
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
