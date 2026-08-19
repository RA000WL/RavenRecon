package adapt

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/RA000WL/RavenRecon/internal/jsintel"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// jsFetchTruncated is the sticky-flag name this adapter records in
// StageResult.StickyFlags when the jsintel engine cut any retained content at
// a cap. It follows the package convention (adapt/doc.go): a truncation flag
// is <engine>_<what>_truncated — here "js" (the engine's short name, matching
// its js.fetch cache operation and FetchTruncated status) and "fetch" (the
// per-URL fetch→analyze pipeline the cut happens inside).
//
// The signal it maps is the engine's own truncation/overflow surface
// (jsintel/report.go): the run's truncation-event counter
// (Report.Metrics().Snapshot().Truncated — "oversized fetch, capped parse,
// oversized HTML body") and the per-observation StatusIncomplete entries,
// which the engine creates ONLY for truncation (a fetch whose content could
// not be fully retained at MaxJSBytes, or a parse that hit a parser cap). The
// ItemHTML body cap is unreachable through this adapter — the corpus supplies
// ItemLine candidates only — so every truncation the adapter can observe is
// a cut inside the per-URL fetch→analyze pipeline. The flag is never
// swallowed (AGENTS §0.6): a truncated observation is engine-incomplete by
// definition and folds the stage to partial, so this adapter never records
// completed-with-truncation.
const jsFetchTruncated = "js_fetch_truncated"

// jsIntelStage adapts the JavaScript intelligence engine (internal/jsintel)
// to the pipeline.Stage contract (internal/pipeline/adapt/doc.go).
//
// Config derivation (engine Config from StageInput only — no pre-resolved
// pipeline defaults):
//
//	Concurrency ← in.Bounds.MaxConcurrency  (> 0; the engine's pool
//	                                           requires it — 0 is rejected
//	                                           by the engine's own
//	                                           validation)
//	QueueSize   ← in.Bounds.QueueSize       (> 0, same)
//	Timeout     ← in.Bounds.Timeout         (0 = engine: no per-job deadline)
//	Rate        ← in.Bounds.Rate            (0 = engine: fetch pacing
//	                                           disabled — the pool is never
//	                                           paced, the central fetch
//	                                           limiter is)
//	Burst       ← in.Bounds.Burst           (< 1 = engine: normalized to 1)
//	Source      ← pipeline.StageJSIntel     ("jsintel", non-empty, ≤ 128
//	                                           bytes; enters the provenance
//	                                           of every observed asset)
//	Cache       ← in.Cache                  (nil = engine: caching disabled)
//	Clock       ← in.Clock                  (nil = engine: wall clock)
//	Transport   ← the constructor seam       (nil = the engine's bounded
//	                                           production transport)
//	RequestTimeout ← the "request_timeout" StageParam (absent/unparseable/
//	                                           zero/negative = 0 = the
//	                                           engine's 10 s default)
//
// Zero bounds are passed through verbatim and mean "engine default/disabled"
// per the ENGINE's documented semantics (adapt/doc.go), never pre-resolved
// pipeline defaults. MaxJSBytes, Retries, and the analysis caps are
// deliberately NOT configurable through the stage: the engine's own defaults
// (2 MiB retained-content cap, 1 retry, 500-script cap, ...) apply, and the
// bounded-fetch truncation at MaxJSBytes is reported honestly.
//
// StageParams keys (all others are ignored — the adapter reads defensively):
//
//	"request_timeout" — a Go duration string (time.ParseDuration) naming
//	the per-attempt fetch deadline the engine applies around every outbound
//	request (slowloris protection; jsintel.Config.RequestTimeout). The
//	parsing is the shared httpprobe helper (httpprobe.go) — absent,
//	unparseable, zero, and negative values resolve to 0, which the engine
//	treats as its 10 s default; the key name is consistent with the
//	httpprobe stage.
//
// Input (in.URLs → Source of candidate Items): every corpus URL maps to ONE
// Item of kind ItemLine with Line = the URL's canonical string. ItemHTML is
// not constructible from the corpus: it requires a resolved page URL plus
// response headers and a body (Item.URL/Headers/Body — engine.go), and the
// corpus carries none of those; ItemLine is the honest mapping, and
// parseLine resolves an absolute http(s) line to exactly that canonical
// candidate (jsintel/doc.go). A corpus URL with a non-http(s) scheme
// (ftp:, ...) is a legitimate input line that the engine classifies
// malformed at its ingest boundary — the adapter does not second-guess the
// engine (a thin translation layer), and the malformed count is surfaced
// through ItemsFailed.
//
// Boundary filtering (mandatory input side): the engine has NO declared-
// scope concept and fetches whatever candidate it is given (jsintel/doc.go:
// "jsintel has no declared-scope concept, fetch targets come from the
// operator's own corpus"), so out-of-domain corpus URLs — a CDN or
// cross-domain observation an earlier stage retained — are pre-filtered with
// the shared URL filter (filterURLs: canonical host via the asset model, IP
// literals and zero URLs dropped — IPs are never in scope and are not yet in
// the corpus). The output side is vacuous: this adapter produces NO corpus
// additions — scripts, endpoints, and secret candidates are results,
// propagated by the results channel (separate milestone, adapt/doc.go).
//
// Empty filtered input short-circuits to completed with zero work (honest
// no-op) — but only for a canonical target (targetCanonical, the dns/httpprobe
// guard). A non-canonical target falls through to the engine: the jsintel
// engine performs no scope validation of its own, so nothing is masked — the
// engine processes the filtered remainder (possibly empty, yielding an empty
// report) and reports it honestly. Cancellation is still honored on the
// short-circuit path, mirroring the engine's own pre-run ctx check.
//
// Outcome mapping (engine entry status → pipeline outcome), per the unified
// adapter table (adapt/doc.go):
//
//	StatusCompleted  → completed
//	StatusIncomplete → partial   (the engine's own definition: a truncated
//	                             fetch retains no content, a capped parse a
//	                             partial analysis — never a completed
//	                             observation) + Truncated + the
//	                             js_fetch_truncated sticky flag
//	StatusFailed     → failed
//	StatusCancelled  → cancelled
//
// The stage fold over the report's entries is deterministic, in the unified
// precedence: (1) any cancelled entry, or a fired run context, folds to
// cancelled; (2) every entry failed with no completed entry folds to failed;
// (3) every entry completed folds to completed; (4) otherwise (any mix)
// folds to partial. Truncated observations are engine-incomplete and fold to
// partial — never completed — so the runner's completed+Truncated+empty-
// flags downgrade never fires on this adapter's truncation path.
//
// Counters: ItemsProcessed is the number of report entries (one per distinct
// candidate URL processed, including cancelled and failed ones — the
// engine's honest processed set). ItemsFailed is the number of StatusFailed
// entries plus the report's Malformed count (input lines the engine rejected
// at ingest — a non-http(s)-scheme corpus URL — mirroring how the discovery
// adapter counts malformed input lines as failed).
//
// Errors: engine errors are wrapped with context ("stage %s: %w") and
// returned; cancellation is reported through Outcome cancelled with the
// context error joined with the engine's shutdown detail, exactly as the
// pipeline contract documents (the runner's isContextError traverses the
// join, so the cancelled classification is preserved; the Go error return is
// nil because returning a non-context error would force the runner's failed
// classification).
type jsIntelStage struct {
	// transport is the constructor test seam: nil means the engine's bounded
	// production transport (a clone of http.DefaultTransport with a
	// response-header byte cap, a response-header timeout, and proxy
	// support disabled). Tests inject hermetic transports.
	transport http.RoundTripper
}

var _ pipeline.Stage = (*jsIntelStage)(nil)

// NewJSIntelStage constructs the jsintel pipeline stage wrapping
// internal/jsintel.
//
// transport is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine uses its bounded default transport), or a hermetic
// fake in tests. It is never read from StageParams — params are operator
// configuration, not test plumbing.
func NewJSIntelStage(transport http.RoundTripper) pipeline.Stage {
	return &jsIntelStage{transport: transport}
}

// Name implements pipeline.Stage.
func (s *jsIntelStage) Name() pipeline.StageName { return pipeline.StageJSIntel }

// Run implements pipeline.Stage.
func (s *jsIntelStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	// Boundary filter, input side (adapt/doc.go): the engine has no scope
	// concept and would fetch any candidate it is given, so out-of-domain
	// corpus URLs (and IP-literal / zero URLs, which are never in scope)
	// are filtered out before the engine sees them. The filter is
	// label-aware and operates on canonical names only (pipeline.InDomain);
	// the single normalization point stays in internal/asset.
	urls := filterURLs(in.Target, in.URLs)

	// Empty filtered input: short-circuit with completed and zero work — but
	// only for a canonical target. The engine tolerates an empty source
	// (empty report, no pool), so this is a pure optimization; a
	// non-canonical target falls through so the engine's own honest behavior
	// decides (the jsintel engine performs no scope validation, so its empty
	// report is itself honest — nothing is masked). The context is honored
	// first, exactly as the engine checks ctx.Err() before its own work.
	if len(urls) == 0 && targetCanonical(in.Target) {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, nil
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// Corpus URLs become ItemLine candidates: the canonical string of each
	// surviving URL, in corpus order (deterministic; the engine resolves
	// each absolute http(s) line back to that exact canonical candidate).
	items := make([]jsintel.Item, 0, len(urls))
	for _, u := range urls {
		items = append(items, jsintel.Item{Kind: jsintel.ItemLine, Line: u.String()})
	}

	cfg := jsintel.Config{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so
		// through the runner they are never 0); Timeout 0 disables the
		// per-job deadline; Rate 0 disables the central fetch limiter;
		// Burst < 1 normalizes to 1.
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		// The stage identity enters the provenance of every observed asset
		// (non-empty, ≤ 128 bytes — "jsintel").
		Source: string(pipeline.StageJSIntel),
		// Cache and Clock pass through: nil cache = caching disabled (the
		// engine's cache-before-execute then performs zero lookups); nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Cache: in.Cache,
		Clock: in.Clock,
		// The single StageParam (documented on the type): invalid or absent
		// resolves to 0 = the engine's 10 s per-attempt default. Parsing is
		// the shared httpprobe helper — the key name and semantics are
		// consistent with the httpprobe stage.
		RequestTimeout: requestTimeoutFromParams(in.Config),
		// Constructor test seam: nil = the engine's bounded production
		// transport. MaxJSBytes stays 0 = the engine's 2 MiB default (the
		// adapter never configures the content cap; its bounded-fetch
		// truncation is reported, not tuned).
		Transport: s.transport,
	}

	report, engineErr := jsintel.Run(ctx, cfg, jsintel.SliceSource(items))
	return s.mapResult(ctx, report, engineErr)
}

// mapResult translates the engine's report and error into the pipeline's
// fixed outcome vocabulary, counters, and truncation flags. Additions are
// always empty: scripts, endpoints, and secret candidates are results,
// propagated by the results channel (separate milestone, adapt/doc.go).
func (s *jsIntelStage) mapResult(ctx context.Context, report jsintel.Report, engineErr error) (pipeline.StageResult, error) {
	// Engine error paths. Errors are wrapped with context and returned;
	// cancellation is reported through Outcome cancelled with the context
	// error, exactly as the pipeline contract documents.
	if engineErr != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		if ctx.Err() != nil {
			// The stage context fired (the engine surfaces it as a wrapped
			// context error, or the pool was forced down after
			// cancellation): the outcome, not the error field, carries
			// cancellation — the context's own error is attached with the
			// engine's shutdown detail joined in so nothing is lost (the
			// runner's isContextError traverses the join and keeps the
			// cancelled classification). The Go error return is nil: a
			// non-context error return would force the runner's failed
			// classification.
			joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: joined}, nil
		}
		// Any other engine error (invalid config — e.g. a direct caller
		// passing zero Concurrency — pool failure, shutdown failure):
		// failed, wrapped with context.
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
	}

	// The engine drained cleanly but the run was cancelled in flight: the
	// per-URL statuses are cancelled (or the reader stopped early) and the
	// stage outcome is cancelled, with the context error attached.
	if ctx.Err() != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return buildJSResult(report, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Outcome fold over the engine's per-entry statuses (mapping table
	// documented on the type).
	return buildJSResult(report, foldJSEntries(report), nil), nil
}

// buildJSResult maps one engine report onto the pipeline's StageResult
// shape: the honest counters, the truncation flag (never swallowed), and the
// outcome. Additions stay empty (results are a separate milestone). It is
// used on every path: the success path and both engine error branches.
func buildJSResult(report jsintel.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		ItemsProcessed: len(report.Entries),
		ItemsFailed:    jsFailedCount(report),
		Err:            err,
	}
	if jsTruncated(report) {
		res.Truncated = true
		res.StickyFlags = map[string]bool{jsFetchTruncated: true}
	}
	return res
}

// foldJSEntries reduces the engine report's per-entry statuses to one stage
// outcome, with exactly the unified adapter shape (adapt/doc.go
// "Unified outcome mapping"): cancelled > failed&&!completed > completed >
// partial.
//
//	jsintel.StatusCompleted  -> a completed entry
//	jsintel.StatusIncomplete -> an engine-incomplete entry (a truncated
//	                            fetch or capped parse — partial results
//	                            retained, never completed); folds into the
//	                            partial bucket — the adapters themselves
//	                            never emit OutcomeIncomplete
//	jsintel.StatusFailed     -> a failed entry (no usable observation)
//	jsintel.StatusCancelled  -> a cancelled entry (run teardown, or the
//	                            engine's per-job deadline fired while the
//	                            stage context is live — the outcome, not
//	                            the error field, carries that cancellation)
//
// Cancellation note: per-entry cancellations with a still-live stage context
// mean the ENGINE's own teardown or a per-job deadline cut the entry's work
// (for example a job-level Timeout while the stage deadline is disabled), so
// the stage reports cancelled with a nil Err, exactly as the dns adapter
// documents for its per-host cancellations.
func foldJSEntries(report jsintel.Report) pipeline.Outcome {
	if len(report.Entries) == 0 {
		// Defensive: the adapter short-circuits empty inputs, so an empty
		// report through normal operation means a non-canonical target fell
		// through with everything filtered out; a vacuous empty report folds
		// to completed, mirroring the engine's own empty-source behavior.
		return pipeline.OutcomeCompleted
	}
	anyCompleted, anyFailed, anyCancelled := false, false, false
	allCompleted := true
	for _, e := range report.Entries {
		switch e.Status {
		case jsintel.StatusCompleted:
			anyCompleted = true
		case jsintel.StatusFailed:
			anyFailed = true
			allCompleted = false
		case jsintel.StatusCancelled:
			anyCancelled = true
			allCompleted = false
		case jsintel.StatusIncomplete:
			// Engine-incomplete (truncated): not completed, and it folds
			// into the partial bucket below.
			allCompleted = false
		}
	}
	switch {
	case anyCancelled:
		return pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		return pipeline.OutcomeFailed
	case allCompleted:
		return pipeline.OutcomeCompleted
	default:
		return pipeline.OutcomePartial
	}
}

// jsFailedCount is the report's honest failed count: the number of entries
// with StatusFailed (processing produced no usable observation) plus the
// report's Malformed count (input lines the engine rejected at its ingest
// boundary — for this adapter, corpus URLs with a non-http(s) scheme). A
// truncated entry (StatusIncomplete) is partial, not failed.
func jsFailedCount(report jsintel.Report) int {
	failed := report.Malformed
	for _, e := range report.Entries {
		if e.Status == jsintel.StatusFailed {
			failed++
		}
	}
	return failed
}

// jsTruncated reports whether the engine cut any retained content at a cap:
// the run's truncation-event counter (bounded-fetch truncation at MaxJSBytes,
// capped parses — the ItemHTML body cap is unreachable through this
// ItemLine-only adapter) or, equivalently, any StatusIncomplete entry (the
// engine creates those ONLY for truncation). The marker is never swallowed:
// the caller sets Truncated and the sticky flag from it.
func jsTruncated(report jsintel.Report) bool {
	if report.Metrics().Truncated > 0 {
		return true
	}
	for _, e := range report.Entries {
		if e.Status == jsintel.StatusIncomplete {
			return true
		}
	}
	return false
}
