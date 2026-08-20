package adapt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
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

// jsURLOverflowFlag is the sticky-flag name this adapter records when the
// analyzer-derived URL feedback loop hit its per-run cap. Flag is
// jsintel_url_overflow (overflow, not truncated) per spec — intentional
// _overflow exception to the <engine>_<what>_truncated convention
// (adapt/doc.go); distinct from the probe_truncated family; still sets
// Truncated=true for the honest incomplete carve-out (AGENTS §0.6).
// Preserved end-to-end (result → RunReport → report), never swallowed.
// The flag maps the bounded per-run cap on URLs derived from the jsintel
// analyzer output (endpoints and external URL observations); excess beyond
// the cap is truncated to the cap deterministically (sorted by canonical
// URL), Truncated is set, and the stage outcome stays completed (the flag,
// not the outcome, marks the retained set incomplete).
const jsURLOverflowFlag = "jsintel_url_overflow"

// jsURLCapDefault is the default per-run cap for analyzer-derived URL
// additions (endpoint URLs that become corpus URLs). Zero in StageParams
// means this default (mirroring other adapters' zero-means-default).
const jsURLCapDefault = 500

// jsURLCap parses the "jsintel_url_cap" StageParam. Absent, empty,
// unparseable, zero, or negative values resolve to the default (500),
// mirroring other adapters' zero-means-default normalization.
func jsURLCap(params map[string]string) int {
	v, ok := params["jsintel_url_cap"]
	if !ok {
		return jsURLCapDefault
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return jsURLCapDefault
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return jsURLCapDefault
	}
	return n
}

// jsCollectURLs derives the in-domain corpus URL additions from the
// jsintel analyzer output (endpoints and external URL observations).
// It is the JS → URL feedback loop (OPT-P0-2): endpoint URLs that survive
// the in-domain filter become corpus URLs for urlintel/urllive/priority.
//
// Steps (locked design):
//
//  1. Parse via asset.ParseURL (single normalization point) — drop
//     unparseable (endpoints are already canonical via NewEndpoint, so this
//     is a re-validation).
//  2. Keep only in-domain: host is subdomain of target domain (via
//     filterURLs which uses pipeline.InDomain) — drop evil.com, IP literals,
//     zero URLs.
//  3. Dedup against incoming corpus URLs (in.URLs) and within the new set.
//  4. Bounded per-run cap (configurable via StageParams "jsintel_url_cap",
//     default 500). Excess beyond cap triggers honest overflow: truncate to
//     cap, set overflow flag and Truncated.
//
// Determinism: dedup keeps first-seen (incoming first), then the survivors
// are sorted by canonical URL string (deterministic regardless of observation
// order), then capped deterministically. No new cache operation — URLs are
// derived from already-cached fetch+analysis. No mutation of input corpus.
//
// The source fields are the report's endpoint URLs and external URL
// observations (the same output at record_analyze.go:176 — analysisData.URLs
// and JSEntry.Endpoints/URLs). Both are collected so a same-host relative
// endpoint (e.g. /api/v1/users resolved to http://www.example.com/api/v1/users)
// and a different-host in-domain endpoint (https://other.example.com/x) are
// covered. Out-of-domain candidates are dropped by the in-domain filter.
func jsCollectURLs(report jsintel.Report, target asset.Domain, incoming []asset.URL, cap int) ([]asset.URL, bool) {
	if cap <= 0 {
		cap = jsURLCapDefault
	}
	if len(report.Entries) == 0 {
		return nil, false
	}
	var candidates []asset.URL
	for _, e := range report.Entries {
		for _, ep := range e.Endpoints {
			if ep.URL.IsZero() {
				continue
			}
			u, err := asset.ParseURL(ep.URL.String(), ep.URL.Prov)
			if err != nil {
				continue
			}
			candidates = append(candidates, u)
		}
		for _, u := range e.URLs {
			if u.IsZero() {
				continue
			}
			pu, err := asset.ParseURL(u.String(), u.Prov)
			if err != nil {
				continue
			}
			candidates = append(candidates, pu)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}
	filtered := filterURLs(target, candidates)
	if len(filtered) == 0 {
		return nil, false
	}
	// Dedup against incoming corpus and within the new set.
	incomingSeen := make(map[asset.Identity]struct{}, len(incoming))
	for _, u := range incoming {
		incomingSeen[u.Identity()] = struct{}{}
	}
	seen := make(map[asset.Identity]struct{}, len(filtered))
	var deduped []asset.URL
	for _, u := range filtered {
		id := u.Identity()
		if _, ok := incomingSeen[id]; ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		deduped = append(deduped, u)
	}
	if len(deduped) == 0 {
		return nil, false
	}
	sort.Slice(deduped, func(i, j int) bool { return deduped[i].String() < deduped[j].String() })
	overflow := false
	if len(deduped) > cap {
		overflow = true
		deduped = deduped[:cap]
	}
	if len(deduped) == 0 {
		return nil, overflow
	}
	return deduped, overflow
}

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
//	"jsintel_url_cap" — decimal integer naming the per-run cap for
//	analyzer-derived URL additions (the JS → URL feedback loop, OPT-P0-2).
//	Absent, empty, unparseable, zero, and negative values resolve to 500
//	(the default per-run cap). The cap is enforced after in-domain
//	filtering, dedup, and sorting; excess beyond the cap is truncated and
//	reported with Truncated=true and the jsintel_url_overflow sticky flag.
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
// the corpus). The output side: the adapter IS the pipeline's document-channel
// producer (Config.RetainContent is always enabled here — the engine's
// retained bodies become pipeline.Documents (jsDocuments)) and the URL corpus
// feedback producer (analyzer-derived endpoint URLs that survive the in-domain
// filter become corpus URL additions via Additions.URLs, bounded by the
// jsintel_url_cap StageParam, sorted deterministically; see jsCollectURLs).
// Scripts, endpoints, and secret candidates remain results-channel additions
// (T3d, adapt/doc.go).
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
		// Content retention is always enabled: this stage is the pipeline's
		// document-channel producer (T3d) — the engine's retained bodies
		// become pipeline.Documents (jsDocuments). The retained content is
		// bounded per entry by the engine's 2 MiB default MaxJSBytes, equal
		// to pipeline.MaxDocumentBytes, so the pipeline's hostile-producer
		// guard never fires on engine output.
		RetainContent: true,
	}

	report, engineErr := jsintel.Run(ctx, cfg, jsintel.SliceSource(items))
	cap := jsURLCap(in.Config)
	urlAdds, urlOverflow := jsCollectURLs(report, in.Target, in.URLs, cap)
	res, err := s.mapResult(ctx, report, engineErr)
	// Merge analyzer-derived URL corpus additions (JS → URL feedback loop,
	// OPT-P0-2): URLs are derived from already-cached fetch+analysis, so no
	// new cache operation; they are corpus additions (Additions.URLs) and flow
	// through the same merge path as the corpus (mergeCorpus), deterministic
	// and deduped. Only report-present paths (success and cancelled-in-flight)
	// carry additions — engine-error branches return a bare failed/cancelled
	// result with no usable report (T2c documented), so they carry none.
	if engineErr == nil {
		if len(urlAdds) > 0 {
			res.Additions.URLs = urlAdds
		}
		if urlOverflow {
			res.Truncated = true
			if res.StickyFlags == nil {
				res.StickyFlags = map[string]bool{}
			}
			res.StickyFlags[jsURLOverflowFlag] = true
		}
	}
	return res, err
}

// mapResult translates the engine's report and error into the pipeline's
// fixed outcome vocabulary, counters, and truncation flags. Results-channel
// additions (scripts, endpoints, secrets) are results, propagated through the
// results channel; retained bodies flow through the document channel
// (T3d, adapt/doc.go); analyzer-derived URL additions (the JS → URL feedback
// loop) flow through Additions.URLs (corpus) and are merged in Run after
// mapResult — mapResult itself handles only the fetch-truncation flag
// (js_fetch_truncated); the url-overflow flag is layered in Run.
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
// shape: the honest counters, the truncation flag (never swallowed), the
// document-channel additions (the engine's retained bodies — the stage is
// the pipeline's document producer, T3d), the results-channel additions
// (the engine report's canonical assets, copied — never rebuilt — per the
// one-normalization-point rule), and the outcome. Corpus URL additions
// (the JS → URL feedback loop) are layered in Run after this function —
// buildJSResult handles only the fetch-truncation flag (js_fetch_truncated);
// the url-overflow flag is added in Run. It is used on the paths where a
// report exists to merge: the success path and the cancelled-in-flight path
// (the report's honest retained entries still merge). The engine-error
// branches return early with a bare failed/cancelled StageResult (T2c
// behavior — the engine returned no usable report on those paths).
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
	res.Documents = jsDocuments(report)
	res.Results = jsResults(report)
	return res
}

// jsResults builds the stage's results-channel additions from the engine
// report: the canonical JavaScript assets, source maps, and relationships
// through the report's own merged, sorted accessors, plus the endpoint,
// secret, technology, and evidence candidates derived from the per-entry
// lists (the report exposes no merged accessors for those — the adapter
// derives them from the sorted entries, deduplicating by canonical identity
// and sorting, so the additions are deterministic). External (different-
// host) URL observations are NOT propagated: the corpus URL channel belongs
// to the urlintel stage's producer and the report exposes no merged URL
// accessor for them (documented). Nothing is rebuilt — every value is the
// engine's canonical Phase 2 asset, copied.
func jsResults(report jsintel.Report) pipeline.Results {
	res := pipeline.Results{
		JavaScript:    report.AllJavaScript(),
		SourceMaps:    report.AllSourceMaps(),
		Relationships: report.AllRelationships(),
	}
	var eps []asset.Endpoint
	var secretsList []asset.SecretCandidate
	var techList []asset.Technology
	var evList []asset.Evidence
	for _, e := range report.Entries {
		eps = append(eps, e.Endpoints...)
		secretsList = append(secretsList, e.Secrets...)
		techList = append(techList, e.Technologies...)
		evList = append(evList, e.Evidence...)
	}
	res.Endpoints = dedupeByIdentity(eps, func(a asset.Endpoint) asset.Identity { return a.Identity() })
	res.Secrets = dedupeByIdentity(secretsList, func(a asset.SecretCandidate) asset.Identity { return a.Identity() })
	res.Technologies = dedupeByIdentity(techList, func(a asset.Technology) asset.Identity { return a.Identity() })
	res.Evidence = dedupeByIdentity(evList, func(a asset.Evidence) asset.Identity { return a.Identity() })
	return res
}

// jsDocuments builds the stage's document-channel additions from the engine
// report's retained bodies: one pipeline.Document per fully retained body,
// in canonical-URL order (Report.RetainedContent is already sorted and
// deduplicated by URL). The document identity is the canonical JavaScript
// asset identity of the URL — asset.Identity{Kind: KindJavaScript, Value:
// the canonical URL string}, exactly what the engine's JS asset Identity()
// produces — so a document and its JavaScript asset share one identity by
// construction. The identity is keyed to the URL, not to the retained
// body's classification: the engine keeps the bytes of every completed
// positive observation (engine.go classify), so a fully-retained body that
// is not itself JS-classified (e.g. fetched HTML) still yields a document
// carrying the JavaScript-kind identity of its URL — a document identity
// without a corresponding Results.JavaScript asset (the engine records JS
// assets only for JS-classified observations) is therefore a documented
// contract, not a surprise. Truncated is always false: retention only ever
// carries complete bodies (jsintel/doc.go), and the pipeline's
// hostile-producer guard re-binds over-cap content at the merge anyway.
// Content is passed by reference — the report owns the bytes (pipeline
// document-merge semantics).
func jsDocuments(report jsintel.Report) []pipeline.Document {
	ret := report.RetainedContent()
	if len(ret) == 0 {
		return nil
	}
	out := make([]pipeline.Document, 0, len(ret))
	for _, rc := range ret {
		u := rc.URL
		out = append(out, pipeline.Document{
			Identity: asset.Identity{Kind: asset.KindJavaScript, Value: u.String()},
			URL:      &u,
			Content:  rc.Content,
		})
	}
	return out
}

// dedupeByIdentity deduplicates a slice by canonical asset identity,
// keeping first-seen order, and sorts the survivors by identity string
// (deterministic regardless of observation order — the report's per-entry
// lists are sorted within an entry, but the same candidate may be observed
// in several files, and the adapter's additions must be deterministic).
func dedupeByIdentity[T any](in []T, key func(T) asset.Identity) []T {
	seen := make(map[asset.Identity]struct{}, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		id := key(v)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]).String() < key(out[j]).String() })
	return out
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
