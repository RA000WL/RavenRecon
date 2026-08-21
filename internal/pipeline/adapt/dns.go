package adapt

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// dnsBruteWildcardFlag is the sticky flag this adapter sets when the
// wildcard probe detected a wildcard DNS zone and brute was aborted to
// prevent *.example.com inflation. The flag is the opt-in brute's
// diagnostic surface — the stage remains completed but no brute hosts are
// emitted.
const dnsBruteWildcardFlag = "dns_brute_wildcard"

// dnsBruteTruncatedFlag is the sticky flag set when the brute wordlist
// exceeded MaxBruteWordlistEntries or the candidate set exceeded
// MaxBruteHostsPerDomain and was capped. The retained set is incomplete.
const dnsBruteTruncatedFlag = "dns_brute_truncated"

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
// StageParams: the dns stage is opt-in brute via dnsx-compatible keys
// (all other keys are ignored — the adapter reads defensively):
//
//	dnsx_brute     bool   "true"/"1"/"yes"/"on" (case-insensitive) enables
//	                       brute. Absent/false = zero cost, exactly as before.
//	dnsx_wordlist  string comma-separated prefixes ("www,api,dev"); empty or
//	                       absent uses the embedded 10-item default wordlist.
//	                       Capped at 5000 entries and 5000 hosts.
//	dnsx_resolvers string comma-separated IPs; parsed but unused (reserved;
//	                       native resolver is used — hermetic without binary).
//
// When enabled, after the normal dns resolution the stage probes wildcard
// (random-uuid subdomain), aborts on positive with the dns_brute_wildcard
// sticky flag, otherwise generates wordlist×domain candidates, deduplicates,
// caps, and resolves them via the same bounded engine (central limiter
// 20/s, per-domain brute timeout 60s, MaxBruteHostsPerDomain 5000). Brute
// hosts are emitted as corpus Hosts additions (like discovery), no new
// results channel. Brute candidates are not separately cached — per
// (host,type) DNS cache already exists.
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

	bruteEnabled := dnsBruteEnabled(in.Config)

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
	//
	// When brute is enabled, the empty-host short-circuit is intentionally
	// disabled: brute operates on the domain itself (wordlist×domain) even
	// with no corpus hosts, so the stage must still run the engine (and
	// the brute path) rather than returning a vacuous completed result.
	if len(hosts) == 0 && targetCanonical(in.Target) && !bruteEnabled {
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
	baseRes, baseErr := s.mapResult(ctx, in, rep, engineErr)
	// Opt-in brute: zero cost when disabled. When enabled, attempt brute
	// after the normal resolution, merging brute hosts into the corpus.
	if !bruteEnabled {
		return baseRes, baseErr
	}
	// Brute is not attempted when the base run failed or was cancelled, or
	// the stage context is already done — the base outcome already carries
	// the honesty signal.
	if engineErr != nil || ctx.Err() != nil {
		return baseRes, baseErr
	}
	// Non-canonical target: the engine would have already rejected it;
	// brute must not hide that error behind a wildcard probe.
	if !targetCanonical(in.Target) {
		return baseRes, baseErr
	}
	bruteRes, bruteTruncated, bruteWildcard := s.runBrute(ctx, in, cfg, baseRes)
	if bruteWildcard {
		// Wildcard detected: abort brute, surface diagnostic via sticky flag.
		// The stage outcome stays that of the base run; the flag marks the
		// retained set as honestly without brute hosts.
		if baseRes.StickyFlags == nil {
			baseRes.StickyFlags = make(map[string]bool)
		}
		baseRes.StickyFlags[dnsBruteWildcardFlag] = true
		return baseRes, baseErr
	}
	// If brute produced no new hosts, we may still need to propagate
	// truncation, counters and a downgraded outcome (timeout case).
	// Historic path returned baseRes unchanged except for the wordlist cap
	// flag; the new path also propagates a timeout-truncated brute that
	// carried no resolving hosts (all cancelled).
	hasBruteHosts := len(bruteRes.Additions.Hosts) > 0 || len(bruteRes.Results.IPs) > 0
	if !hasBruteHosts {
		needsPropagation := bruteRes.Truncated || len(bruteRes.StickyFlags) > 0 || bruteRes.ItemsProcessed > 0 || (bruteRes.Outcome != "" && bruteRes.Outcome != pipeline.OutcomeCompleted)
		if bruteTruncated {
			needsPropagation = true
		}
		if !needsPropagation {
			return baseRes, baseErr
		}
		merged := baseRes
		if len(bruteRes.StickyFlags) > 0 {
			if merged.StickyFlags == nil {
				merged.StickyFlags = make(map[string]bool)
			}
			for k, v := range bruteRes.StickyFlags {
				merged.StickyFlags[k] = v
			}
		}
		if bruteTruncated {
			if merged.StickyFlags == nil {
				merged.StickyFlags = make(map[string]bool)
			}
			merged.StickyFlags[dnsBruteTruncatedFlag] = true
			merged.Truncated = true
		}
		if bruteRes.Truncated {
			merged.Truncated = true
		}
		merged.ItemsProcessed = baseRes.ItemsProcessed + bruteRes.ItemsProcessed
		merged.ItemsFailed = baseRes.ItemsFailed + bruteRes.ItemsFailed
		if bruteRes.Outcome != "" && bruteRes.Outcome != pipeline.OutcomeCompleted {
			switch bruteRes.Outcome {
			case pipeline.OutcomeCancelled:
				merged.Outcome = pipeline.OutcomeCancelled
			case pipeline.OutcomePartial, pipeline.OutcomeIncomplete:
				if merged.Outcome == pipeline.OutcomeCompleted {
					merged.Outcome = pipeline.OutcomePartial
				}
			case pipeline.OutcomeFailed:
				if merged.Outcome == pipeline.OutcomeCompleted {
					merged.Outcome = pipeline.OutcomePartial
				}
			default:
				if merged.Outcome == pipeline.OutcomeCompleted {
					merged.Outcome = bruteRes.Outcome
				}
			}
		}
		return merged, baseErr
	}
	// Merge brute hosts into the base result's corpus additions and results.
	merged := mergeBruteAdditions(baseRes, bruteRes, in.Target)
	if bruteTruncated {
		if merged.StickyFlags == nil {
			merged.StickyFlags = make(map[string]bool)
		}
		merged.StickyFlags[dnsBruteTruncatedFlag] = true
		merged.Truncated = true
	}
	// Preserve base counters: add brute attempted-only counts.
	merged.ItemsProcessed = baseRes.ItemsProcessed + bruteRes.ItemsProcessed
	merged.ItemsFailed = baseRes.ItemsFailed + bruteRes.ItemsFailed
	if bruteRes.Outcome != "" && bruteRes.Outcome != pipeline.OutcomeCompleted {
		switch bruteRes.Outcome {
		case pipeline.OutcomeCancelled:
			merged.Outcome = pipeline.OutcomeCancelled
		case pipeline.OutcomePartial, pipeline.OutcomeIncomplete:
			if merged.Outcome == pipeline.OutcomeCompleted {
				merged.Outcome = pipeline.OutcomePartial
			}
		case pipeline.OutcomeFailed:
			if merged.Outcome == pipeline.OutcomeCompleted {
				merged.Outcome = pipeline.OutcomePartial
			}
		default:
			if merged.Outcome == pipeline.OutcomeCompleted {
				merged.Outcome = bruteRes.Outcome
			}
		}
	}
	return merged, baseErr
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

	// Results: the engine report's canonical resolved addresses are copied
	// into the results channel, never rebuilt (the one-normalization-point
	// rule, AGENTS §0.5). IPs need no scope filtering: they are the answers
	// of the in-scope hosts this stage resolved, and an address is not
	// "in-domain" or "out-of-domain" — an out-of-domain address (CDN, ...)
	// is a legitimate observation of an in-scope host (mirrors how the
	// engine records them; the stage produces no IP corpus additions, so
	// the corpus scope boundary is unaffected).
	results := pipeline.Results{IPs: rep.AllIPs()}

	// Engine error paths. Errors are wrapped with context and returned;
	// cancellation is reported through Outcome cancelled with the context
	// error, exactly as the pipeline contract documents.
	if engineErr != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		switch {
		case isContextError(engineErr):
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped, Additions: additions, Results: results}, wrapped
		case ctx.Err() != nil:
			// The engine failed on teardown (for example a forced pool
			// shutdown) while the stage context was also firing: the
			// cancellation is the dominant, more honest signal.
			wrappedCtx := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrappedCtx, Additions: additions, Results: results}, wrappedCtx
		default:
			return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped, Additions: additions, Results: results}, wrapped
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
			Results:        results,
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
		Results:        results,
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

// dnsBruteEnabled reports whether brute is enabled via StageParams.
func dnsBruteEnabled(params map[string]string) bool {
	if params == nil {
		return false
	}
	v, ok := params["dnsx_brute"]
	if !ok {
		return false
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "true" || v == "1" || v == "yes" || v == "on"
}

// dnsBruteWordlist parses the dnsx_wordlist StageParam. Absent, empty, or
// whitespace-only values select the embedded default wordlist; otherwise the
// comma-separated prefixes are trimmed and empty elements dropped. The result
// is capped at dns.MaxBruteWordlistEntries; an over-long wordlist sets the
// caller-observed truncation flag. Unknown params are ignored.
func dnsBruteWordlist(params map[string]string) ([]string, bool) {
	v, ok := params["dnsx_wordlist"]
	if !ok {
		return dns.DefaultBruteWordlist, false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return dns.DefaultBruteWordlist, false
	}
	parts := strings.Split(v, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return dns.DefaultBruteWordlist, false
	}
	truncated := false
	if len(out) > dns.MaxBruteWordlistEntries {
		out = out[:dns.MaxBruteWordlistEntries]
		truncated = true
	}
	return out, truncated
}

// dnsBruteResolvers parses the optional dnsx_resolvers StageParam
// (comma-separated IPs). It is accepted but unused — the native resolver is
// used (hermetic without binary). Parsing validates shape but never errors;
// unknown values are ignored.
func dnsBruteResolvers(params map[string]string) []string {
	v, ok := params["dnsx_resolvers"]
	if !ok {
		return nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// runBrute executes the opt-in brute path: wildcard probe, candidate
// generation, bounded resolution, and filtering to resolving hosts. It
// returns the brute StageResult (additions + results), whether the wordlist
// or candidate set was truncated, and whether a wildcard was detected. The
// candidate resolution is bounded by BruteTimeout and the stage's own
// context, with the same bounded pool and limiter as the normal path.
func (s *dnsStage) runBrute(ctx context.Context, in pipeline.StageInput, cfg dns.Config, base pipeline.StageResult) (pipeline.StageResult, bool, bool) {
	// Wildcard probe before any brute work.
	// Use the stage's resolver seam (nil = production). IsWildcard handles nil.
	wildcard, err := dns.IsWildcard(ctx, in.Target, s.resolver)
	if err != nil {
		// Cancellation/deadline during probe: abort brute, propagate no
		// wildcard flag — the stage context already carries cancellation.
		if isContextError(err) {
			return pipeline.StageResult{}, false, false
		}
		wildcard = false
	}
	if wildcard {
		return pipeline.StageResult{}, false, true
	}

	wordlist, wordlistTruncated := dnsBruteWordlist(in.Config)
	// Reserving parsing of resolvers (unused, but defensive).
	_ = dnsBruteResolvers(in.Config)

	candidates := dns.GenerateBruteCandidates(in.Target, wordlist)
	if len(candidates) == 0 {
		return pipeline.StageResult{}, wordlistTruncated, false
	}
	// Dedup candidates against hosts already in the base report (input
	// hosts plus CNAME targets) to avoid redundant queries.
	seen := make(map[string]bool, len(base.Additions.Hosts)+len(candidates))
	for _, h := range base.Additions.Hosts {
		seen[h.Name] = true
	}
	// Also dedup against the input hosts that were filtered before the
	// base resolve (in case base had no report due to empty input).
	for _, h := range in.Hosts {
		seen[h.Name] = true
	}
	var filtered []asset.Host
	for _, h := range candidates {
		if seen[h.Name] {
			continue
		}
		seen[h.Name] = true
		filtered = append(filtered, h)
	}
	if len(filtered) == 0 {
		return pipeline.StageResult{}, wordlistTruncated, false
	}
	candidateTruncated := len(candidates) >= dns.MaxBruteHostsPerDomain || wordlistTruncated
	// Brute candidates are already capped by GenerateBruteCandidates, but
	// filtering may have reduced them; the truncation flag reflects the
	// generation cap, not the filtered size.

	// Bounded per-domain brute timeout. The stage context already bounds the
	// run; this additional deadline ensures a single domain cannot wedge the
	// stage indefinitely. If the context already has a tighter deadline, it
	// wins (WithTimeout respects the parent's deadline).
	bruteCtx, cancel := context.WithTimeout(ctx, dns.BruteTimeout)
	defer cancel()

	rep, err := dns.Resolve(bruteCtx, in.Target, filtered, cfg)
	if err != nil {
		if isContextError(err) {
			return pipeline.StageResult{}, candidateTruncated, false
		}
		// Engine error on brute: treat as failed brute with no additions.
		return pipeline.StageResult{}, candidateTruncated, false
	}
	// Inspect the raw resolve report for cancellation/timeout. When
	// BruteTimeout fires mid-resolution dns.Resolve returns nil error but
	// hosts remain with StatusCancelled (or Types with cancelled/timedOut);
	// the resolving filter would otherwise silently drop them and the
	// adapter would record a completed result with no truncation flag
	// (AGENTS §0.6 violation). Detect any cancelled host and treat the
	// brute as truncated.
	var anyCancelled, anyCompleted, anyFailedHR, anyIncomplete bool
	var attempted, failed int
	var anyAnswersTruncated bool
	for _, hr := range rep.Results {
		wasAttempted := len(hr.Types) > 0
		if wasAttempted {
			attempted++
		}
		switch hr.Status {
		case dns.StatusCompleted:
			anyCompleted = true
		case dns.StatusFailed:
			anyFailedHR = true
			if wasAttempted {
				failed++
			}
		case dns.StatusIncomplete:
			anyIncomplete = true
		case dns.StatusCancelled:
			anyCancelled = true
		}
		for _, tr := range hr.Types {
			if tr.Truncated {
				anyAnswersTruncated = true
			}
		}
	}
	bruteTimeout := anyCancelled
	if !bruteTimeout && bruteCtx.Err() != nil {
		if isContextError(bruteCtx.Err()) {
			bruteTimeout = true
		}
	}
	if !bruteTimeout && bruteCtx.Err() != nil {
		for _, hr := range rep.Results {
			for _, tr := range hr.Types {
				if tr.Status == dns.TypeCancelled || tr.Status == dns.TypeTimedOut {
					bruteTimeout = true
					break
				}
			}
			if bruteTimeout {
				break
			}
		}
	}

	// Filter brute hosts to only those that actually resolved (have at least
	// one address or CNAME observation). NXDOMAIN / NODATA hosts are not
	// useful brute discoveries and must not pollute the corpus.
	var resolving []asset.Host
	for _, hr := range rep.Results {
		if len(hr.IPs) > 0 || len(hr.Targets) > 0 {
			// Host resolved to at least one IP or CNAME target.
			resolving = append(resolving, hr.Host)
			// Also include the CNAME targets themselves if they are in-domain
			// (the adapter's output filter will enforce in-domain again).
			resolving = append(resolving, hr.Targets...)
		}
	}
	// Helper to build a truncated result for the empty-host case (timeout
	// or cap) that still carries honest counters, flags and a downgraded
	// outcome. This preserves AGENTS §0.6: a truncated retained set is
	// never silently completed.
	buildEmptyResult := func() (pipeline.StageResult, bool, bool) {
		if !bruteTimeout && !anyAnswersTruncated && !candidateTruncated {
			return pipeline.StageResult{}, candidateTruncated, false
		}
		res := pipeline.StageResult{
			ItemsProcessed: attempted,
			ItemsFailed:    failed,
		}
		if bruteTimeout {
			if anyCompleted || anyIncomplete {
				res.Outcome = pipeline.OutcomePartial
			} else if anyFailedHR && !anyCompleted && !anyIncomplete {
				res.Outcome = pipeline.OutcomeFailed
			} else {
				res.Outcome = pipeline.OutcomeCancelled
			}
			res.Truncated = true
			if res.StickyFlags == nil {
				res.StickyFlags = make(map[string]bool)
			}
			res.StickyFlags[dnsBruteTruncatedFlag] = true
		} else {
			res.Outcome = pipeline.OutcomeCompleted
		}
		if anyAnswersTruncated {
			res.Truncated = true
			if res.StickyFlags == nil {
				res.StickyFlags = make(map[string]bool)
			}
			res.StickyFlags[dnsAnswersTruncated] = true
		}
		if candidateTruncated {
			res.Truncated = true
			if res.StickyFlags == nil {
				res.StickyFlags = make(map[string]bool)
			}
			res.StickyFlags[dnsBruteTruncatedFlag] = true
		}
		return res, candidateTruncated, false
	}

	if len(resolving) == 0 {
		return buildEmptyResult()
	}
	// Deduplicate resolving hosts by identity and filter to in-domain.
	resolving = dedupeHosts(resolving)
	resolving = pipeline.FilterHosts(in.Target, resolving)
	if len(resolving) == 0 {
		return buildEmptyResult()
	}
	// Collect IPs for the results channel (only for resolving hosts) —
	// use the report's merged IPs filtered to resolving hosts' contributions.
	// Simplest: use rep.AllIPs which already contains only resolving hosts'
	// IPs (non-resolving hosts have none).
	resolvingIPs := pipelineFilterIPs(resolving, rep.AllIPs())

	bruteResult := pipeline.StageResult{
		Outcome:        pipeline.OutcomeCompleted,
		ItemsProcessed: attempted,
		ItemsFailed:    failed,
		Additions:      pipeline.StageAdditions{Hosts: resolving},
		Results:        pipeline.Results{IPs: resolvingIPs},
	}
	if anyAnswersTruncated {
		bruteResult.Truncated = true
		if bruteResult.StickyFlags == nil {
			bruteResult.StickyFlags = make(map[string]bool)
		}
		bruteResult.StickyFlags[dnsAnswersTruncated] = true
	}
	if bruteTimeout {
		bruteResult.Truncated = true
		if bruteResult.StickyFlags == nil {
			bruteResult.StickyFlags = make(map[string]bool)
		}
		bruteResult.StickyFlags[dnsBruteTruncatedFlag] = true
		if len(resolving) > 0 || anyCompleted || anyIncomplete {
			bruteResult.Outcome = pipeline.OutcomePartial
		} else {
			bruteResult.Outcome = pipeline.OutcomeCancelled
		}
	} else if candidateTruncated {
		bruteResult.Truncated = true
		if bruteResult.StickyFlags == nil {
			bruteResult.StickyFlags = make(map[string]bool)
		}
		bruteResult.StickyFlags[dnsBruteTruncatedFlag] = true
	}
	return bruteResult, candidateTruncated, false
}

// dedupeHosts deduplicates hosts by Phase 2 identity, keeping first-seen,
// then sorting by canonical name — deterministic.
func dedupeHosts(hosts []asset.Host) []asset.Host {
	seen := make(map[string]bool, len(hosts))
	var out []asset.Host
	for _, h := range hosts {
		if seen[h.Name] {
			continue
		}
		seen[h.Name] = true
		out = append(out, h)
	}
	// Sorting is already done by GenerateBruteCandidates and by the
	// report's AllHosts, but deduping may have mixed order; sort for
	// determinism.
	sortHosts(out)
	return out
}

// sortHosts sorts hosts by canonical name.
func sortHosts(hosts []asset.Host) {
	// Use a simple sort to keep hermetic and avoid extra imports beyond
	// what the file already has; time is already imported for BruteTimeout.
	for i := 1; i < len(hosts); i++ {
		for j := i; j > 0 && hosts[j].Name < hosts[j-1].Name; j-- {
			hosts[j], hosts[j-1] = hosts[j-1], hosts[j]
		}
	}
}

// pipelineFilterIPs keeps only IPs that belong to resolving hosts.
// Since rep.AllIPs is already filtered to resolving hosts' IPs (non-resolving
// hosts contribute none), this is effectively a pass-through, but we keep the
// helper for explicitness and future scope filtering.
func pipelineFilterIPs(resolvingHosts []asset.Host, ips []asset.IP) []asset.IP {
	// No host-to-IP filtering is required: IPs are observations of
	// in-scope hosts, and an address is not in- or out-of-domain.
	// Return the IPs sorted and deduplicated (AllIPs already is).
	return ips
}

// mergeBruteAdditions merges brute hosts and results into the base stage
// result, deduplicating by identity and sorting deterministically.
func mergeBruteAdditions(base, brute pipeline.StageResult, target asset.Domain) pipeline.StageResult {
	merged := base
	// Merge Hosts additions.
	hostSet := make(map[string]bool, len(base.Additions.Hosts)+len(brute.Additions.Hosts))
	for _, h := range base.Additions.Hosts {
		hostSet[h.Name] = true
	}
	var mergedHosts []asset.Host
	mergedHosts = append(mergedHosts, base.Additions.Hosts...)
	for _, h := range brute.Additions.Hosts {
		if hostSet[h.Name] {
			continue
		}
		hostSet[h.Name] = true
		mergedHosts = append(mergedHosts, h)
	}
	sortHosts(mergedHosts)
	merged.Additions.Hosts = pipeline.FilterHosts(target, mergedHosts)

	// Merge IPs results.
	ipSet := make(map[string]bool, len(base.Results.IPs)+len(brute.Results.IPs))
	for _, ip := range base.Results.IPs {
		ipSet[ip.String()] = true
	}
	var mergedIPs []asset.IP
	mergedIPs = append(mergedIPs, base.Results.IPs...)
	for _, ip := range brute.Results.IPs {
		if ipSet[ip.String()] {
			continue
		}
		ipSet[ip.String()] = true
		mergedIPs = append(mergedIPs, ip)
	}
	// IPs are already sorted by AllIPs; sort deterministically if merged.
	sortIPs(mergedIPs)
	merged.Results.IPs = mergedIPs

	// Merge sticky flags.
	if len(brute.StickyFlags) > 0 {
		if merged.StickyFlags == nil {
			merged.StickyFlags = make(map[string]bool)
		}
		for k, v := range brute.StickyFlags {
			merged.StickyFlags[k] = v
		}
	}
	if brute.Truncated {
		merged.Truncated = true
	}
	return merged
}

// sortIPs sorts IPs by canonical string.
func sortIPs(ips []asset.IP) {
	for i := 1; i < len(ips); i++ {
		for j := i; j > 0 && ips[j].String() < ips[j-1].String(); j-- {
			ips[j], ips[j-1] = ips[j-1], ips[j]
		}
	}
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
