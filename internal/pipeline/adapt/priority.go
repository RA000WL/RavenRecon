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

// priorityGroupsTruncated is the sticky flag this adapter records when the
// priority engine's correlation cut retained groups (Correlate's run-level
// truncation signal — groups beyond the engine's fixed maxCorrelationGroups
// are dropped and counted). The name follows the package convention
// (adapt/doc.go): a sticky flag is <engine>_<what>_truncated. Group-level
// member truncation (Group.Truncated) rides on the group values only — it
// never sets this flag.
const priorityGroupsTruncated = "priority_groups_truncated"

// priorityPathsTruncated is the sticky flag this adapter records when the
// priority engine's attack-path cut retained paths (AttackPaths' run-level
// truncation signal — paths beyond the engine's fixed maxPathsPerRun are
// dropped after ranking; M-6). It fires independently of
// priorityGroupsTruncated: more qualifying groups than maxPathsPerRun cuts
// paths even when every group was retained.
const priorityPathsTruncated = "priority_paths_truncated"

// priorityParamsTruncated is the sticky flag this adapter records when a
// URL's canonical query carries MORE parameter names than the engine's
// fixed per-signal bound (priority.MaxParamsPerSignal): the derivation
// retains the first bound-many names in canonical (sorted) order and marks
// the retained set incomplete instead of handing the engine an input its
// validation rejects — a pathological URL degrades to an explicit
// truncation signal, never a failed asset (NEW-14).
const priorityParamsTruncated = "priority_params_truncated"

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
// pipeline corpus does not carry those observation channels yet. The
// adapter never fabricates observations.
//
// Boundary (mandatory, both sides): input corpus entries are pre-filtered
// with pipeline.InDomain/FilterHosts and filterURLs (canonical names only —
// the single normalization point stays in internal/asset), so no
// out-of-domain asset is ever scored. The engine cannot produce
// out-of-domain assets through this adapter: its report carries scored
// surfaces only, never corpus additions, and no corpus asset can leave the
// adapter's input side. Consequently the stage produces NO corpus
// additions: surfaces, groups, and attack paths are results, propagated
// through the results channel (T3d, adapt/doc.go). Additions stay empty by
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
// Truncation: the scoring engine reports NO truncation or overflow
// signals through this adapter's input path (its retention model has no
// caps on the asset count it reports). The signals this adapter can
// observe are (a) the correlation cut — Correlate's run-level truncation
// (groups beyond the engine's fixed maxCorrelationGroups), mapped to
// Truncated + the priority_groups_truncated sticky flag, and (b) the
// adapter-side parameter-name derivation cut (NEW-14): a URL whose
// canonical query yields more names than priority.MaxParamsPerSignal
// retains the first bound-many and maps to Truncated +
// priority_params_truncated instead of a failed asset. Neither cut is ever
// swallowed (AGENTS §0.6). Group-level member truncation (Group.Truncated)
// rides on the group values only.
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
			return s.runScore(ctx, in, nil, false)
		}
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// One signal per in-scope corpus asset, carrying only what the corpus
	// assets canonically carry (see Run). A URL whose query yields more
	// parameter names than the engine's bound truncates the derivation and
	// reports it (NEW-14).
	sigs, paramsTruncated := buildPrioritySignals(domains, hosts, urls)
	return s.runScore(ctx, in, sigs, paramsTruncated)
}

// runScore derives the engine config from the StageInput, calls
// priority.Score, and maps the engine's report and error onto the
// pipeline's StageResult shape. It is shared by the normal path and the
// non-canonical-target fall-through so both honor the identical error and
// cancellation mapping. paramsTruncated (NEW-14) applies the parameter-name
// truncation signal to every returned result — on any outcome path: a cut
// input set is never silently completed, even when the engine itself fails.
func (s *priorityStage) runScore(ctx context.Context, in pipeline.StageInput, sigs []priority.Signal, paramsTruncated bool) (res pipeline.StageResult, _ error) {
	defer func() {
		if paramsTruncated {
			// The derivation retained only the first
			// priority.MaxParamsPerSignal names of at least one URL:
			// mark the retained set incomplete (AGENTS §0.6).
			res.Truncated = true
			if res.StickyFlags == nil {
				res.StickyFlags = make(map[string]bool)
			}
			res.StickyFlags[priorityParamsTruncated] = true
		}
	}()
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
	res = s.buildPriorityResult(rep, foldPriorityOutcome(rep.Outcome), nil)
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
// StageResult shape: the honest counters, the results-channel additions
// (scored surfaces, correlated groups, and attack-path hypotheses), the
// correlation-cut and attack-path-cut truncation flags (never swallowed),
// and empty Additions (priority produces no corpus additions — T2d). It is
// used on every path:
// the success path and both engine-error branches — the report's honest
// completed assets still merge through Correlate and AttackPaths (both
// pure, deterministic, and bounded by the engine's fixed caps).
func (s *priorityStage) buildPriorityResult(rep priority.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: priorityProcessed(rep),
		ItemsFailed:    priorityFailed(rep),
	}
	// Results: one surface per completed asset result (the engine's
	// canonical scored values, copied — never rebuilt), then the
	// deterministic correlation groups and attack paths derived from those
	// retained surfaces. Correlate and AttackPaths run on every path —
	// even an engine-error path merges its honest completed assets —
	// mirroring how the secrentel adapter derives its report's results.
	surfaces := make([]priority.SurfaceAsset, 0, rep.Completed)
	for _, ar := range rep.Assets {
		if ar.Status == priority.StatusCompleted && ar.Surface != nil {
			surfaces = append(surfaces, *ar.Surface)
		}
	}
	groups, groupsTruncated := priority.Correlate(surfaces)
	res.Results.Surfaces = surfaces
	res.Results.Groups = groups
	paths, pathsTruncated := priority.AttackPaths(groups)
	res.Results.AttackPaths = paths
	if groupsTruncated || pathsTruncated {
		// Run-level cuts in the priority engine: groups beyond the engine's
		// fixed maxCorrelationGroups and/or paths beyond maxPathsPerRun were
		// dropped. The flags, never the outcome alone, mark the retained set
		// incomplete (AGENTS §0.6); each cut carries its own sticky flag.
		res.Truncated = true
		flags := make(map[string]bool, 2)
		if groupsTruncated {
			flags[priorityGroupsTruncated] = true
		}
		if pathsTruncated {
			flags[priorityPathsTruncated] = true
		}
		res.StickyFlags = flags
	}
	return res
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
// order: domains, then hosts, then URLs). The second return reports whether
// any URL's parameter-name derivation was cut at the engine's bound
// (NEW-14).
func buildPrioritySignals(domains []asset.Domain, hosts []asset.Host, urls []asset.URL) ([]priority.Signal, bool) {
	sigs := make([]priority.Signal, 0, len(domains)+len(hosts)+len(urls))
	paramsTruncated := false
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
		names, truncated := queryParamNames(u.Query)
		paramsTruncated = paramsTruncated || truncated
		sigs = append(sigs, priority.Signal{
			Identity:       u.Identity(),
			Kind:           asset.KindURL,
			Path:           u.Path,
			Hostname:       h.Name,
			ParameterNames: names,
		})
	}
	return sigs, paramsTruncated
}

// queryParamNames derives the parameter-name list from a canonical query
// string ("a=1&b=2", keys sorted, no leading "?"), aligned with urlintel's
// extraction semantics (internal/urlintel extractParams): a pair carrying
// NO observed value ("?flag" or "?flag=") yields no name — the same rule
// that keeps value-less keys out of the Parameter channel. The canonical
// query's keys are already sorted, so the derived list is deterministic by
// construction; duplicate keys keep every occurrence (urlintel merges
// them into one Parameter — a residual divergence, deliberately out of
// NEW-14 scope). A query with no eligible parameters yields nil.
//
// When more than priority.MaxParamsPerSignal names would be handed to the
// engine, the list retains exactly the first bound-many names and the
// second return reports the cut (NEW-14): the adapter surfaces an explicit
// truncation signal instead of letting the whole asset fail engine
// validation.
func queryParamNames(query string) (names []string, truncated bool) {
	if query == "" {
		return nil, false
	}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if name == "" || value == "" {
			// "?flag" / "?flag=" / "=value": no observed (name, value)
			// pair — skipped by design, mirroring urlintel.
			continue
		}
		if len(names) >= priority.MaxParamsPerSignal {
			truncated = true // keep scanning: later names only confirm the cut
			continue
		}
		names = append(names, name)
	}
	return names, truncated
}
