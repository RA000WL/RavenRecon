package adapt

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/techintel"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// techIndicatorsTruncatedFlag is the sticky flag this adapter records when
// the engine report carries ANY of its truncation/overflow signals
// (techintel.Report.Truncated, or any field of Report.Overflow). It names the
// engine's retention-cap family — indicator matches (evidence records) cut at
// MaxIndicatorsPerObservation, fired technologies cut at
// MaxTechnologiesPerObservation, and cookie entries cut at the cookie cap —
// and is preserved end-to-end (result → RunReport → report), never swallowed
// (AGENTS §0.6 names techintel's Truncated/Overflow signals explicitly).
//
// The name follows the package convention (adapt/doc.go): a sticky flag is
// <engine>_<what>_truncated — never a bare generic like "truncated", which
// could collide across engines in the report's StickyFlags map. "indicators"
// is the engine's canonical term for the analysis-channel family that
// produces the evidence records. Through the v1.3 pipeline the observations
// carry URL identity only (see techIntelStage), so the indicator and
// technology caps are the signals that can genuinely fire; the cookie and
// ingest-truncation signals are mapped anyway so no engine signal is ever
// swallowed.
const techIndicatorsTruncatedFlag = "tech_indicators_truncated"

// techIntelStage adapts internal/techintel (techintel.Ingest) into a
// pipeline.Stage.
//
// Construction is explicit — there is no registry: NewTechIntelStage returns
// the stage and callers pass it to pipeline.Run as part of the stages slice.
type techIntelStage struct {
	// db is the engine's fingerprint database seam. nil means the engine's
	// production default (fingerprints.Load, the compile-once database),
	// exactly as techintel.Config.DB documents. The adapter never
	// substitutes a database of its own.
	db *fingerprints.DB
}

var _ pipeline.Stage = (*techIntelStage)(nil)

// NewTechIntelStage returns the techintel pipeline stage wrapping
// internal/techintel.
//
// db is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine loads the compiled-in fingerprint database via
// fingerprints.Load), or a hermetic synthetic database in tests
// (fingerprints.CompileForTest). It is never read from StageParams — params
// are operator configuration, not test plumbing.
func NewTechIntelStage(db *fingerprints.DB) pipeline.Stage {
	return &techIntelStage{db: db}
}

// Name implements pipeline.Stage.
func (s *techIntelStage) Name() pipeline.StageName { return pipeline.StageTechIntel }

// Level implements pipeline.LeveledStage: fingerprints need the post-crawl corpus.
func (s *techIntelStage) Level() int { return 4 }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = engine: no per-job deadline)
//	Rate        ← in.Bounds.Rate         (<= 0 = engine: pacing disabled)
//	Burst       ← in.Bounds.Burst        (< 1 = engine: normalized to 1)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//	DB          ← the constructor seam   (nil = engine: fingerprints.Load)
//
// The engine's analysis caps (MaxTechnologiesPerObservation,
// MaxIndicatorsPerObservation) are deliberately NOT configurable here: they
// are fixed engine constants (internal/techintel/observation.go — "fixed
// constant, deliberately NOT configuration"), so the adapter leaves them at
// their engine defaults and there is no StageParams surface for them.
//
// Zero bounds are passed through verbatim and mean "engine default/disabled"
// per the ENGINE's documented semantics (adapt/doc.go), NOT pre-resolved
// pipeline defaults: the pipeline runner has already resolved 0 to the
// pipeline defaults (Concurrency/QueueSize/Burst are positive by then), while
// a direct caller may deliberately pass Timeout 0 / Rate 0 to disable the
// engine's per-job deadline and pacing. The engine requires a positive
// Concurrency and QueueSize; a direct caller passing 0 for either gets the
// engine's own config-validation error (mapped to Outcome failed below).
//
// StageParams: none. in.Config is never read — the stage has no documented
// parameter keys, and unknown keys are ignored by construction.
//
// Observations: each in-scope URL becomes exactly one
// techintel.Observation carrying its URL identity plus the host-level TLS
// observation resolved from the results channel (NEW-119): the httpprobe
// stage reports leaf certificates (Results.TLSCertificates) linked to
// hosts (host_to_tls_certificate relationships), and the adapter attaches
// the certificate's issuer, subject CN, and SAN DNS names as the
// observation's TLSInfo. ALPN is honestly absent — it is handshake-level
// data the certificate channel does not carry — so tls_alpn indicators
// stay silent through this adapter. Headers, bodies, cookies, and DNS
// observations have no results-channel carrier at this stage position
// (headers/status live in urllive LiveRecords, which run later; DNS CNAME
// edges are not published by the dns stage), so those fields stay zero
// ("not observed", legal) and their indicator families stay silent here.
// The adapter never fabricates observations: a URL whose host carries no
// certificate is analyzed URL-only, exactly as before.
//
// Boundary (mandatory, both sides): input URLs are pre-filtered with
// filterURLs (in-domain canonical hosts; IP literals and zero URLs dropped)
// so the engine never sees an out-of-domain input. The engine's cache key is
// derived from the observation's URL identity only, so the engine cannot
// produce out-of-domain assets through this adapter: Report.Technologies are
// named from the fingerprint database, and every url_to_technology
// relationship's source is an observation's URL identity, which entered
// through the input filter. There is consequently no output-side URL filter
// (nothing new can leave the scope) and, per T2c (adapt/doc.go), techintel
// produces NO corpus additions — technologies, evidence, and relationships
// are results, propagated by the results channel (T3d).
// Additions stay empty by construction.
//
// Malformed observations (non-canonical URLs that survive the input filter —
// for example an uppercase hostname, which canonicalizes in asset.NewHost
// but not in the URL's own identity) are NOT silently dropped: they reach the
// engine, which counts them as Malformed in its report and records a bounded
// diagnostic. The adapter reflects them in ItemsFailed (the pipeline's
// honest "could not be processed" counter) without folding them into the
// outcome (a malformed observation is a diagnostic, exactly as the discovery
// adapter treats malformed lines). This is pinned by a unit test.
//
// Note on the stage level: the engine surfaces its bounded malformed
// diagnostic as a joined run error, so a run that CONTAINS a malformed
// observation reports failed through the adapter's error path (the outcome
// the stage-level test pins) — the "never folded" claim above applies to the
// pure fold over the report's counts (foldTechOutcome), not to the error
// path. The engine's own behavior never changes either way: the observation
// is counted, never analyzed.
//
// Outcome mapping (engine observation status → pipeline outcome; the engine
// folds its per-observation statuses into Report.Observations counts):
//
//	Report.Observations.Completed -> a completed entry
//	Report.Observations.Cancelled -> a cancelled entry (run teardown, or the
//	                                engine's per-job deadline fired)
//	Report.Observations.Failed    -> a failed entry (no usable observation)
//	Report.Observations.Malformed -> a rejected observation: counted in
//	                                ItemsFailed, never folded into the outcome
//
// The stage fold over those counts is deterministic, in the unified adapter
// precedence (adapt/doc.go "Unified outcome mapping", MEDIUM-1 review
// unification): cancelled > failed&&!completed > completed > partial —
//
//  1. any cancelled entry                                -> cancelled
//  2. any failed entry and no completed entry            -> failed
//  3. no failed and no cancelled entry                   -> completed
//     (vacuously true for an empty report)
//  4. otherwise (completed mixed with failed entries)    -> partial
//
// Cancellation note: per-entry cancellations with a still-live stage context
// mean the ENGINE's own teardown cut the entries (for example the engine's
// per-job deadline fired while the stage deadline is disabled), so the stage
// reports cancelled with a nil Err — the outcome, not the error field, carries
// cancellation. When the stage context fired instead, the context error is
// attached (see below).
//
// Engine error paths. Errors are wrapped with context ("stage %s: %w") and
// returned; a non-nil error return additionally forces Outcome failed or
// cancelled (never anything else), so the runner's normalizeResult contract
// is honored. When the engine returns an error while the stage context is
// also firing, cancellation is the dominant signal and the engine's shutdown
// detail is errors.Join-ed so nothing is lost. A clean engine drain followed
// by a fired stage context reports cancelled with the context error. A
// pre-cancelled context is handled honestly on every path (the engine itself
// returns an empty report with a nil error for a pre-cancelled context, so
// the stage's own context checks drive the cancelled outcome).
//
// Counters: ItemsProcessed is the engine report's Completed + Cancelled +
// Failed entry count (every entry the engine processed); ItemsFailed is
// Failed + Malformed (everything that could not be processed — engine-failed
// entries and rejected observations).
//
// Truncation (Report.Truncated, or any Report.Overflow field — indicator /
// technology / cookie retention caps): sets Truncated=true and
// StickyFlags[techIndicatorsTruncatedFlag]=true, never swallowed. The engine
// itself retains truncated entries as StatusCompleted entries with the
// overflow flagged in the report, so completed+Truncated+flag is the AGENTS
// §0.6-legal combination for this adapter's retained set — the flag, never
// the outcome alone, marks the set incomplete. The runner's completed+
// Truncated+empty-flags downgrade never fires because the flag is always set
// alongside Truncated.
func (s *techIntelStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	// Boundary filter, input side (adapt/doc.go): the corpus may carry URLs
	// outside the declared scope (other root domains, IP literals, zero
	// URLs). filterURLs operates on canonical hostnames only — the single
	// normalization point stays in internal/asset.
	urls := filterURLs(in.Target, in.URLs)

	// Empty filtered input short-circuit. techintel.Ingest treats an empty
	// observation source as VALID input (it returns an empty report without
	// starting a pool), so short-circuiting here is observationally identical
	// to calling the engine — but only when the engine would actually accept
	// the call: the techintel engine never validates the target (it consumes
	// observations only), so a non-canonical target with no in-scope URLs
	// yields an empty report (vacuously completed), never a fabricated error.
	// The canonicality gate is still kept for shape-consistency with the dns
	// and httpprobe adapters and so that a future engine-side target
	// validation would surface honestly instead of being masked by a
	// completed short-circuit. The re-check goes through asset.NewDomain —
	// the single normalization point, exactly as the sibling adapters do.
	if len(urls) == 0 {
		if !targetCanonical(in.Target) {
			return s.runIngest(ctx, in, techintel.SliceObservationSource{})
		}
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// One observation per in-scope URL: the URL identity plus the
	// host-level TLS observation resolved from the results channel
	// (NEW-119). URLs whose host carries no certificate stay URL-only —
	// the adapter never fabricates data.
	tlsIdx := newTLSCertIndex(in.Results.TLSCertificates, in.Results.Relationships)
	obs := make(techintel.SliceObservationSource, 0, len(urls))
	for _, u := range urls {
		o := techintel.Observation{URL: u}
		if h, ok := urlHost(u); ok {
			o.TLS = tlsIdx.infoForHost(h)
		}
		obs = append(obs, o)
	}
	return s.runIngest(ctx, in, obs)
}

// tlsCertIndex resolves host-level TLS observations from the results
// channel: leaf certificates by identity plus host_to_tls_certificate
// edges by host identity, both deterministically ordered. It is built
// once per stage run; per-URL lookups are map reads.
type tlsCertIndex struct {
	byID   map[string]asset.TLSCertificate
	byHost map[string][]string
}

// newTLSCertIndex builds the index. Edges pointing at certificates absent
// from the set are ignored (no observation can be composed for them).
func newTLSCertIndex(certs []asset.TLSCertificate, rels []asset.Relationship) *tlsCertIndex {
	idx := &tlsCertIndex{
		byID:   make(map[string]asset.TLSCertificate, len(certs)),
		byHost: make(map[string][]string),
	}
	for _, c := range certs {
		idx.byID[c.Identity().String()] = c
	}
	for _, r := range rels {
		if r.Kind != asset.RelationshipHostToTLSCertificate {
			continue
		}
		id := r.To.String()
		if _, ok := idx.byID[id]; !ok {
			continue
		}
		h := r.From.String()
		idx.byHost[h] = append(idx.byHost[h], id)
	}
	for h := range idx.byHost {
		sort.Strings(idx.byHost[h])
	}
	return idx
}

// infoForHost returns the TLS observation for one host: the sorted-first
// certificate's issuer, subject CN, and SAN DNS names. It returns nil
// when the host carries no certificate — or no usable certificate
// fields — so the observation stays honestly URL-only.
//
// Multi-certificate hosts (more than one host_to_tls_certificate edge):
// sorted-first wins and the rest are ignored by design. Host→certificate
// edges are normally 1:1 (one leaf per host per run); a multi-cert set is
// ambiguous (which handshake's issuer describes the host?), and merging
// distinct issuers/subjects into one TLSInfo would fabricate an
// observation no handshake produced. The deterministic sorted-first pick
// keeps the signal honest and reproducible; pinned by
// TestTLSInfoForHostDeterministic.
func (x *tlsCertIndex) infoForHost(host asset.Host) *techintel.TLSInfo {
	if x == nil {
		return nil
	}
	ids := x.byHost[host.Identity().String()]
	if len(ids) == 0 {
		return nil
	}
	c := x.byID[ids[0]]
	if c.Issuer == "" && c.Subject == "" && len(c.DNSNames) == 0 {
		return nil
	}
	return &techintel.TLSInfo{
		Issuer:   c.Issuer,
		Subject:  c.Subject,
		DNSNames: append([]string(nil), c.DNSNames...),
	}
}

// runIngest derives the engine config from the StageInput, calls
// techintel.Ingest, and maps the engine's report and error onto the
// pipeline's StageResult shape. It is shared by the normal path and the
// non-canonical-target fall-through so both honor the identical error and
// cancellation mapping.
func (s *techIntelStage) runIngest(ctx context.Context, in pipeline.StageInput, obs techintel.SliceObservationSource) (pipeline.StageResult, error) {
	cfg := techintel.Config{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so through
		// the runner they are never 0); Timeout 0 disables the per-job
		// deadline; Rate <= 0 disables pacing; Burst < 1 means 1.
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
		// Observer passes through: nil = pool instrumentation off (zero
		// behavior change); the runner's StageInput.Observer carries the
		// run's shared sink.
		Observer: in.Observer,
		// Constructor test seam: nil = the engine's production database
		// (fingerprints.Load). The analysis caps stay at their engine
		// defaults (128 technologies, 512 indicators) — deliberately NOT
		// configurable (see Run).
		DB: s.db,
	}

	rep, engineErr := techintel.Ingest(ctx, cfg, &obs)

	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal (pipeline contract); the engine's
	// shutdown detail is joined so nothing is lost. The report's honest
	// per-observation statuses are still reflected in the mapped result.
	if engineErr != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
		return s.buildTechResult(rep, pipeline.OutcomeCancelled, joined), nil
	}
	if engineErr != nil {
		// Any other engine error (invalid config, pool failure, shutdown
		// failure): failed, wrapped with context. This is the only path that
		// can surface a failed outcome through this adapter — the engine's
		// cache key cannot fail on a canonical observation (internal/
		// techintel/record.go), so per-entry StatusFailed is effectively
		// unreachable; the failed/partial folds are still pinned by the
		// foldTechOutcome table test below.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		return s.buildTechResult(rep, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight: the
		// report's per-entry statuses are honest cancelled entries and the
		// stage outcome is cancelled, with the context error attached.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return s.buildTechResult(rep, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Per-entry outcome fold over the engine's report counts (mapping table
	// documented on Run).
	res := s.buildTechResult(rep, foldTechOutcome(rep.Observations), nil)
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Per-entry cancellations with a still-live stage context report
		// cancelled with a nil Err (documented on Run). If the stage context
		// fired in the window between the check above and the fold, attach it
		// so the cancellation is unambiguous.
		res.Err = fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
	}
	return res, nil
}

// buildTechResult maps one engine report onto the pipeline's StageResult
// shape: the honest counters, the truncation flag (never swallowed), the
// results-channel additions (the engine report's canonical assets, copied —
// never rebuilt — per the one-normalization-point rule), and empty Additions
// (techintel produces no corpus additions — T2c). It is used on every path:
// the success path and both engine-error branches.
func (s *techIntelStage) buildTechResult(rep techintel.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: techProcessed(rep),
		ItemsFailed:    techFailed(rep),
	}
	// Results: technologies, evidence, and relationships are not corpus
	// values — the results channel carries them. They are copied whole:
	// the engine derived them from the in-scope URLs this stage consumed
	// (header/TLS/DNS metadata observations), and relationship edges cannot
	// be meaningfully scope-filtered without corrupting the graph
	// (adapt/doc.go T3d).
	res.Results = pipeline.Results{
		Technologies:  rep.Technologies,
		Evidence:      rep.Evidence,
		Relationships: rep.Relationships,
	}
	if techTruncated(rep) {
		res.Truncated = true
		res.StickyFlags = map[string]bool{techIndicatorsTruncatedFlag: true}
	}
	return res
}

// foldTechOutcome reduces the engine report's observation counts to one stage
// outcome (mapping table documented on techIntelStage.Run). Malformed is a
// diagnostic, never folded (mirrors the discovery adapter's malformed lines).
func foldTechOutcome(obs techintel.ReportObservations) pipeline.Outcome {
	switch {
	case obs.Cancelled > 0:
		return pipeline.OutcomeCancelled
	case obs.Failed > 0 && obs.Completed == 0:
		return pipeline.OutcomeFailed
	case obs.Failed == 0 && obs.Cancelled == 0:
		// Every entry completed (vacuously true for an empty report).
		return pipeline.OutcomeCompleted
	default:
		// Completed mixed with failed entries.
		return pipeline.OutcomePartial
	}
}

// techProcessed returns the engine report's honest processed count: every
// entry the engine processed, including cancelled and failed ones.
func techProcessed(rep techintel.Report) int {
	return rep.Observations.Completed + rep.Observations.Cancelled + rep.Observations.Failed
}

// techFailed returns the engine report's honest "could not be processed"
// count: engine-failed entries plus rejected (malformed) observations.
func techFailed(rep techintel.Report) int {
	return rep.Observations.Failed + rep.Observations.Malformed
}

// techTruncated reports whether the engine report carries ANY truncation or
// overflow signal (the ingest/analysis Truncated marker, or an Overflow flag
// for technologies, indicators, or cookies). The marker is never swallowed:
// the caller sets Truncated and the sticky flag from it.
func techTruncated(rep techintel.Report) bool {
	return rep.Truncated ||
		rep.Overflow.Technologies ||
		rep.Overflow.Indicators ||
		rep.Overflow.Cookies
}
