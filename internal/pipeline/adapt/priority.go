package adapt

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// priorityStage adapts internal/priority (priority.Score) into a
// pipeline.Stage.
//
// Construction is explicit — there is no registry: NewPriorityStage returns
// the stage and callers pass it to pipeline.Run as part of the stages slice.
type priorityStage struct {
	// interesting and risk are the engine's compiled catalog seams
	// (priority.EngineConfig.Interesting/Risk). nil/nil means the engine's
	// production tables (the compile-once contract); any provided catalog
	// is never mixed with a production one — the missing counterpart is an
	// explicit EMPTY catalog (see NewPriorityStage).
	interesting, risk *priority.Catalog
}

var _ pipeline.Stage = (*priorityStage)(nil)

// NewPriorityStage returns the priority pipeline stage wrapping
// internal/priority.
//
// interesting and risk are the constructor test-seam hooks (adapt/doc.go):
// pass nil for BOTH to use the engine's production tables (compiled-in,
// hermetic), or a pair of hermetic catalogs built with
// priority.CompileForTest in tests. The priority engine requires BOTH
// catalogs to be non-nil (its cache key digests the pair — an empty catalog
// is legal and yields a valid digest; a NIL catalog fails the digest
// check), so a single provided catalog is completed with an explicit empty
// counterpart: a provided seam never silently mixes with a production
// table. The seam is never read from StageParams — params are operator
// configuration, not test plumbing.
func NewPriorityStage(interesting, risk *priority.Catalog) pipeline.Stage {
	if interesting == nil && risk != nil {
		// An explicit empty interestingness catalog: nothing is
		// interesting, but the risk catalog still fires. Cannot fail
		// (no entries to validate).
		interesting, _ = priority.CompileForTest("interestingness", nil)
	}
	if risk == nil && interesting != nil {
		risk, _ = priority.CompileForTest("risk", nil)
	}
	return &priorityStage{interesting: interesting, risk: risk}
}

// Name implements pipeline.Stage.
func (s *priorityStage) Name() pipeline.StageName { return pipeline.StagePriority }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = engine: no per-job deadline)
//	Rate        ← in.Bounds.Rate         (0 = engine: pacing disabled; a
//	                                      negative Rate is the engine's
//	                                      config-validation error)
//	Burst       ← in.Bounds.Burst        (< 1 = engine: normalized to 1)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//	Catalogs    ← the constructor seam   (nil/nil = production tables)
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
// Signals: one priority.Signal per in-scope corpus asset — domains carry
// their name as the hostname, hosts carry their name, URLs carry their
// canonical path, hostname, and the parameter names derived from their
// canonical query string (the URL asset itself carries the query; the
// adapter derives the names deterministically — the canonical query has
// sorted keys, so the parameter-name list is deterministic by
// construction). All other signal fields (port, service, headers,
// technologies, secrets, bundle sizes, first-seen, ...) stay zero: the
// pipeline corpus does not carry those observation channels yet (results
// propagation is a separate milestone). The adapter never fabricates
// observations.
//
// Boundary (mandatory, both sides): input corpus entries are pre-filtered
// with pipeline.InDomain/FilterHosts and filterURLs (canonical names only —
// the single normalization point stays in internal/asset), so no
// out-of-domain asset is ever scored. The engine cannot produce
// out-of-domain assets through this adapter: its report carries scored
// surfaces only, never corpus additions, and no corpus asset can leave the
// adapter's input side. Consequently the stage produces NO corpus
// additions: surfaces, groups, and attack paths are results, propagated by
// the results channel in a later milestone. Additions stay empty by
// construction.
//
// Empty-input short-circuit: an empty filtered corpus yields a vacuous
// completed run — the priority engine treats an empty signal channel as a
// valid empty run ("zero assets, nothing attempted" → completed), so
// short-circuiting is observationally identical to calling the engine —
// but only when the target is canonical: with a non-canonical target the
// scope filter is unsound, so the stage falls through to the engine with
// an empty (closed) signal channel and lets the engine produce its own
// honest vacuous completed (mirroring the techintel adapter's gate). Note
// the target itself is NOT added to the signals: the engine scores the
// corpus as the earlier stages produced it — the declared domain is scored
// only when the corpus carries it.
//
// Outcome mapping (engine report outcome → pipeline outcome; the engine
// folds its per-asset statuses into Report.Outcome itself):
//
//	Report.Outcome.Completed  -> completed
//	Report.Outcome.Incomplete -> partial    (completed mixed with failed
//	                                         assets — the successes are
//	                                         kept, the run is not completed)
//	Report.Outcome.Failed     -> failed     (every attempted asset failed)
//	Report.Outcome.Cancelled  -> cancelled  (work never executed)
//
// Cancellation is mapped exactly as the sibling adapters do: an engine
// error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail; a clean engine
// drain followed by a fired stage context reports cancelled with the
// context error; per-asset cancellations with a still-live stage context
// (the engine's own teardown, e.g. a per-job deadline) report cancelled
// with a nil Err — the outcome, not the error field, carries cancellation.
// A pre-cancelled context is handled honestly on every path: the engine
// may return a vacuous completed report for it, and the stage's own
// context check drives the cancelled outcome.
//
// Counters: ItemsProcessed is the engine report's Completed + Failed +
// Cancelled asset count (every asset the engine processed); ItemsFailed is
// Failed (every asset that could not be scored).
//
// Truncation: the priority engine reports NO truncation or overflow
// signals through this adapter's input path (its retention model has no
// caps on the asset count it reports), so this adapter never sets
// Truncated or a sticky flag. The absence is deliberate and documented
// (adapt/doc.go T2d); a future engine cap must surface here.
func (s *priorityStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	// Boundary filter, input side (adapt/doc.go): the corpus may carry
	// assets outside the declared scope (other root domains, IP-literal
	// URLs). Filtering operates on canonical names only.
	domains := filterDomains(in.Target, in.Domains)
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)
	urls := filterURLs(in.Target, in.URLs)

	// Empty filtered input short-circuit. priority.Score treats an empty
	// signal channel as a valid empty run (vacuous completed), so
	// short-circuiting is observationally identical — but only when the
	// scope filter is sound: the engine never validates the target (it
	// consumes signals only), so a non-canonical target with no in-scope
	// assets yields an empty report (vacuously completed), never a
	// fabricated error. The canonicality gate is kept for
	// shape-consistency with the sibling adapters (dns, httpprobe,
	// techintel) and so that a future engine-side target validation would
	// surface honestly instead of being masked by a completed
	// short-circuit. The re-check goes through asset.NewDomain — the
	// single normalization point.
	if len(domains)+len(hosts)+len(urls) == 0 {
		if !targetCanonical(in.Target) {
			return s.runScore(ctx, in, nil)
		}
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// One signal per in-scope corpus asset, carrying only what the corpus
	// assets canonically carry (see Run).
	return s.runScore(ctx, in, buildPrioritySignals(domains, hosts, urls))
}

// runScore derives the engine config from the StageInput, calls
// priority.Score, and maps the engine's report and error onto the
// pipeline's StageResult shape. It is shared by the normal path and the
// non-canonical-target fall-through so both honor the identical error and
// cancellation mapping.
func (s *priorityStage) runScore(ctx context.Context, in pipeline.StageInput, sigs []priority.Signal) (pipeline.StageResult, error) {
	cfg := priority.EngineConfig{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so
		// through the runner they are never 0); Timeout 0 disables the
		// per-job deadline; Rate 0 disables pacing (a negative Rate is the
		// engine's config-validation error); Burst < 1 means 1.
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
		// Constructor test seam: nil/nil = the engine's production tables.
		Interesting: s.interesting,
		Risk:        s.risk,
	}

	// The engine rejects a nil signal channel; an empty closed channel is
	// the honest "no signals" input (also used by the non-canonical-target
	// fall-through). The channel is fully buffered and filled synchronously
	// — no feeder goroutine, so no goroutine can leak or wedge the run (the
	// engine's reader additionally selects on the run context).
	signals := make(chan priority.Signal, len(sigs))
	for _, sig := range sigs {
		signals <- sig
	}
	close(signals)

	rep, engineErr := priority.Score(ctx, cfg, signals)

	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal (pipeline contract); the engine's
	// detail is joined so nothing is lost. The report's honest per-asset
	// statuses are still reflected in the mapped result.
	if engineErr != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
		return s.buildPriorityResult(rep, pipeline.OutcomeCancelled, joined), nil
	}
	if engineErr != nil {
		// Any other engine error (invalid config, pool failure, shutdown
		// failure): failed, wrapped with context.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		return s.buildPriorityResult(rep, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight
		// (including a pre-cancelled context, for which the engine returns
		// a vacuous completed report): the stage outcome is cancelled, with
		// the context error attached and a nil Go error return — the
		// outcome, not the error field, carries cancellation.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return s.buildPriorityResult(rep, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Aggregate-outcome mapping (the engine folds per-asset statuses itself;
	// mapping table documented on Run).
	res := s.buildPriorityResult(rep, foldPriorityOutcome(rep.Outcome), nil)
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Per-asset cancellations with a still-live stage context report
		// cancelled with a nil Err (documented on Run). If the stage
		// context fired in the window between the check above and the fold,
		// attach it so the cancellation is unambiguous.
		res.Err = fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
	}
	return res, nil
}

// buildPriorityResult maps one engine report onto the pipeline's
// StageResult shape: the honest counters and empty Additions (priority
// produces no corpus additions — T2d). No truncation mapping exists — the
// priority engine reports no truncation signals (documented on Run).
func (s *priorityStage) buildPriorityResult(rep priority.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	return pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: priorityProcessed(rep),
		ItemsFailed:    priorityFailed(rep),
	}
}

// foldPriorityOutcome maps the engine's aggregate outcome onto the
// pipeline's five-value vocabulary (mapping table documented on
// priorityStage.Run). An unrecognized engine outcome is a contract
// violation and folds to failed — it must never be masked as completed.
func foldPriorityOutcome(o priority.Outcome) pipeline.Outcome {
	switch o {
	case priority.OutcomeCompleted:
		return pipeline.OutcomeCompleted
	case priority.OutcomeIncomplete:
		return pipeline.OutcomePartial
	case priority.OutcomeFailed:
		return pipeline.OutcomeFailed
	case priority.OutcomeCancelled:
		return pipeline.OutcomeCancelled
	default:
		return pipeline.OutcomeFailed
	}
}

// priorityProcessed returns the engine report's honest processed count:
// every asset the engine processed, including cancelled and failed ones.
func priorityProcessed(rep priority.Report) int {
	return rep.Completed + rep.Failed + rep.Cancelled
}

// priorityFailed returns the engine report's honest "could not be
// processed" count: every asset that failed to score.
func priorityFailed(rep priority.Report) int {
	return rep.Failed
}

// filterDomains returns the domains in domains that are in-domain, in
// input order (stable, deterministic). Domains are compared through the
// same label-aware scope rule as hosts (pipeline.InDomain) — the declared
// domain itself and its subdomains — on canonical names only.
func filterDomains(declared asset.Domain, domains []asset.Domain) []asset.Domain {
	out := make([]asset.Domain, 0, len(domains))
	for _, d := range domains {
		if pipeline.InDomain(declared, asset.Host{Name: d.Name}) {
			out = append(out, d)
		}
	}
	return out
}

// buildPrioritySignals maps the in-scope corpus assets onto one
// priority.Signal each, carrying only what the corpus assets canonically
// carry (see priorityStage.Run): domains and hosts contribute their
// canonical names as the hostname field; URLs contribute their canonical
// path, hostname, and the parameter names derived from the canonical query
// string. The order is deterministic (the filtered slices are in corpus
// order: domains, then hosts, then URLs).
func buildPrioritySignals(domains []asset.Domain, hosts []asset.Host, urls []asset.URL) []priority.Signal {
	sigs := make([]priority.Signal, 0, len(domains)+len(hosts)+len(urls))
	for _, d := range domains {
		sigs = append(sigs, priority.Signal{
			Identity: d.Identity(),
			Kind:     asset.KindDomain,
			Hostname: d.Name,
		})
	}
	for _, h := range hosts {
		sigs = append(sigs, priority.Signal{
			Identity: h.Identity(),
			Kind:     asset.KindHost,
			Hostname: h.Name,
		})
	}
	for _, u := range urls {
		h, ok := urlHost(u)
		if !ok {
			// filterURLs already dropped IP-literal URLs; this is
			// defensive — an unparseable host is never a scorable signal.
			continue
		}
		sigs = append(sigs, priority.Signal{
			Identity:       u.Identity(),
			Kind:           asset.KindURL,
			Path:           u.Path,
			Hostname:       h.Name,
			ParameterNames: queryParamNames(u.Query),
		})
	}
	return sigs
}

// queryParamNames derives the sorted parameter-name list from a canonical
// query string ("a=1&b=2", keys sorted, no leading "?"). The canonical
// query's keys are already sorted, so the derived list is deterministic by
// construction. Empty keys are skipped; a query with no parameters yields
// nil.
func queryParamNames(query string) []string {
	if query == "" {
		return nil
	}
	var names []string
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}
