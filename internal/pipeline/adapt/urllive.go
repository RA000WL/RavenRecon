package adapt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// UrlliveStickyFlag is the sticky-flag name the urllive adapter records
// when any URL liveness probe hit a hard cap (header block or entry cap) or
// the retained set was otherwise cut. It follows the <engine>_<what>_truncated
// convention and is preserved end-to-end (result → RunReport → report), never
// swallowed (AGENTS §0.6).
const UrlliveStickyFlag = "urllive_truncated"

// Reflection sticky flags (NEW-120): canary-reflection evidence is additive
// — capping it never poisons the liveness outcome — so cuts ride flags on a
// completed result (the §0.6 carve-out), never the outcome.
const (
	// UrlliveReflectOverflowFlag marks a run whose parameterized-URL set
	// exceeded urllive_reflect_max_urls: only the sorted head was
	// reflected.
	UrlliveReflectOverflowFlag = "urllive_reflect_overflow"
	// UrlliveReflectTruncatedFlag marks a run where any reflection body
	// hit the engine's body cap (its undecided verdicts are unknown) or
	// the reflection pass itself ended cut short (error/cancellation):
	// the retained evidence is an incomplete set.
	UrlliveReflectTruncatedFlag = "urllive_reflect_truncated"
)

// urlliveReflectMaxURLsDefault bounds how many parameterized corpus URLs
// per run undergo canary reflection (one extra GET each). Override with
// StageParams "urllive_reflect_max_urls".
const urlliveReflectMaxURLsDefault = 512

// urlliveStage adapts the httpprobe URL liveness engine (ProbeURLs) to the
// pipeline.Stage contract.
type urlliveStage struct {
	transport http.RoundTripper
}

var _ pipeline.Stage = (*urlliveStage)(nil)

// Level implements pipeline.LeveledStage: liveness needs the full URL corpus.
func (s *urlliveStage) Level() int { return 5 }

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

	// Operator session headers (NEW-125): resolved before the
	// short-circuit below so a broken session file fails the stage even
	// on an empty corpus — fail-closed, never scan anonymously when
	// authentication was asked for (mirrors the httpprobe stage).
	sessionHeaders, err := sessionHeadersFromParams(in.Config)
	if err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
	}

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
	// Operator session headers (NEW-125): resolved above (fail-closed).
	cfg := httpprobe.Config{
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Clock:       in.Clock,
		Transport:   s.transport,
		Cache:       in.Cache,
		// Operator session headers (nil = anonymous liveness).
		RequestHeaders: sessionHeaders,
		// Forward the run observer into the engine pool; nil disables events.
		Observer: in.Observer,
	}
	// StageParams overrides: urllive_concurrency, urllive_timeout,
	// urllive_rate_limit, session_headers (filesystem path to operator
	// session headers; default absent = anonymous, NEW-125 — read
	// fail-closed above). Unknown keys ignored.
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
		res := buildUrlliveResult(report, pipeline.OutcomeCancelled, joined)
		// The stage budget fired mid-triage: the retained records are an
		// incomplete set. Mark truncation honestly (flag + Truncated) so
		// consumers never treat a cancelled triage as complete (AGENTS §0.6).
		markUrlliveCutShort(&res)
		return res, nil
	}
	if err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return buildUrlliveResult(report, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		res := buildUrlliveResult(report, pipeline.OutcomeCancelled, wrapped)
		markUrlliveCutShort(&res)
		return res, nil
	}

	res := buildUrlliveResult(report, foldUrlliveOutcomes(report), nil)
	// Canary reflection (NEW-120): additive evidence over the live corpus.
	// It runs only when liveness completed or partially completed — a
	// failed or cancelled liveness observation leaves no corpus to
	// reflect — and never changes the liveness outcome: cuts ride the
	// reflection flags on the completed/partial result.
	if res.Outcome == pipeline.OutcomeCompleted || res.Outcome == pipeline.OutcomePartial {
		res = s.addReflection(ctx, in, urls, cfg, res)
	}
	return res, nil
}

// urlliveReflectionEnabled reports whether canary reflection runs: ON
// unless StageParams carries an explicit "false" (case/space-insensitive).
// Reflection doubles requests for parameterized URLs (one extra GET each),
// so operators on tight budgets can disable it without affecting liveness.
func urlliveReflectionEnabled(params map[string]string) bool {
	if params == nil {
		return true
	}
	v, ok := params["urllive_reflection"]
	if !ok {
		return true
	}
	return !strings.EqualFold(strings.TrimSpace(v), "false")
}

// urlliveReflectMaxURLs resolves the per-run reflection URL budget.
func urlliveReflectMaxURLs(params map[string]string) int {
	if params != nil {
		if v, ok := params["urllive_reflect_max_urls"]; ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
				return n
			}
		}
	}
	return urlliveReflectMaxURLsDefault
}

// addReflection runs canary reflection over the parameterized head of the
// live corpus and appends decided verdicts as evidence to the result.
// Unknown verdicts are fail-open downstream (kept findings) and carry no
// evidence — emitting them would spend channel budget for zero decision
// value — while body-cap truncations, per-URL transport/cancel/submit
// errors, and budget cuts set UrlliveReflectTruncatedFlag /
// UrlliveReflectOverflowFlag honestly: any URL without a complete
// verdict set makes the retained evidence set incomplete. Only
// liveness-completed URLs (Status != 0 && Err == nil) are reflected:
// dead URLs never carried a live response, so reflecting them would only
// burn requests for verdicts that prove nothing. Any flag set here also
// sets Truncated (AGENTS §0.6: the flag, never swallowed, marks the
// retained set incomplete on a completed result).
//
// POST body reflection (NEW-127) follows the same rules through
// reflectPostProbes: URLs in the GET-budgeted head whose liveness response
// advertises form/JSON acceptance get one POST per advertised body kind,
// verdict-ed with the same taxonomy and merged as scope-stamped evidence.
// Budget split policy is GET-first: the urllive_reflect_max_urls budget
// selects URLs for GET probing exactly as before POST existed (same
// sorted-head cut, same overflow flag); POST probes never widen the URL
// set, they only add body-kind probes for already-selected URLs. Every
// verdict carries its reflection_scope (query-get-only for GET,
// post-form/post-json for POST) so a GET-clean observation is never
// mistaken for a POST-clean one.
func (s *urlliveStage) addReflection(ctx context.Context, in pipeline.StageInput, urls []asset.URL, cfg httpprobe.Config, res pipeline.StageResult) pipeline.StageResult {
	if !urlliveReflectionEnabled(in.Config) {
		return res
	}
	liveOK := make(map[string]bool, len(res.Results.LiveRecords))
	for _, r := range res.Results.LiveRecords {
		if r.Status != 0 && r.Err == nil {
			liveOK[r.URL.Identity().String()] = true
		}
	}
	var cands []asset.URL
	for _, u := range urls {
		if u.Query == "" {
			continue
		}
		if !liveOK[u.Identity().String()] {
			continue
		}
		cands = append(cands, u)
	}
	if len(cands) == 0 {
		return res
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].String() < cands[j].String() })
	maxURLs := urlliveReflectMaxURLs(in.Config)
	overflow := false
	if len(cands) > maxURLs {
		cands = cands[:maxURLs]
		overflow = true
	}
	rep, err := httpprobe.ReflectURLs(ctx, in.Target, cands, cfg)
	if err != nil {
		// The reflection pass ended cut short (error/cancellation): the
		// liveness result stands, downgraded to partial when it was
		// completed, with the truncation flag marking the evidence set
		// incomplete.
		if res.Outcome == pipeline.OutcomeCompleted {
			res.Outcome = pipeline.OutcomePartial
		}
		if res.StickyFlags == nil {
			res.StickyFlags = map[string]bool{}
		}
		res.StickyFlags[UrlliveReflectTruncatedFlag] = true
		res.Truncated = true
		if res.Err == nil {
			res.Err = fmt.Errorf("stage %s: reflection: %w", s.Name(), err)
		}
		if overflow {
			res.StickyFlags[UrlliveReflectOverflowFlag] = true
		}
		return res
	}
	var evs []asset.Evidence
	truncated := false
	for _, rec := range rep.Records {
		if rec.Truncated || rec.Err != nil {
			// A body-cap hit OR a per-URL transport/cancel/submit
			// failure: the verdict set for this URL is incomplete
			// (unknown verdicts, or no verdicts at all on submit
			// failure), so the retained evidence set is incomplete —
			// flagged, never silent (review wave 2026-09-03).
			truncated = true
		}
		for _, pv := range rec.Verdicts {
			if pv.Verdict == httpprobe.ReflectUnknown {
				continue
			}
			ev, everr := httpprobe.ReflectEvidence(rec.URL.Identity(), pv.Param, pv.Verdict)
			if everr != nil {
				continue
			}
			evs = append(evs, ev)
		}
	}
	// POST body reflection over the GET-budgeted head (cands is already
	// the sorted, budget-cut head: GET-first, POST never widens it).
	// A cut-short POST pass marks the evidence set truncated exactly like
	// the GET pass; decided POST verdicts merge as scope-stamped
	// evidence alongside the GET verdicts.
	postEvs, postTruncated, postErr := s.reflectPostProbes(ctx, in, cands, cfg, res)
	if postErr != nil {
		if res.Outcome == pipeline.OutcomeCompleted {
			res.Outcome = pipeline.OutcomePartial
		}
		if res.StickyFlags == nil {
			res.StickyFlags = map[string]bool{}
		}
		res.StickyFlags[UrlliveReflectTruncatedFlag] = true
		res.Truncated = true
		if res.Err == nil {
			res.Err = fmt.Errorf("stage %s: post reflection: %w", s.Name(), postErr)
		}
	}
	evs = append(evs, postEvs...)
	truncated = truncated || postTruncated
	sort.Slice(evs, func(i, j int) bool { return evs[i].ID() < evs[j].ID() })
	if len(evs) > 0 {
		if res.Results.Evidence == nil {
			res.Results.Evidence = evs
		} else {
			res.Results.Evidence = append(res.Results.Evidence, evs...)
		}
		// The merged evidence list is sorted by evidence ID so the
		// result is deterministic regardless of the pre-existing order.
		sort.Slice(res.Results.Evidence, func(i, j int) bool { return res.Results.Evidence[i].ID() < res.Results.Evidence[j].ID() })
	}
	if res.StickyFlags == nil && (overflow || truncated) {
		res.StickyFlags = map[string]bool{}
	}
	if overflow {
		res.StickyFlags[UrlliveReflectOverflowFlag] = true
		res.Truncated = true
	}
	if truncated {
		res.StickyFlags[UrlliveReflectTruncatedFlag] = true
		res.Truncated = true
	}
	return res
}

// reflectPostKind is the POST discovery rule (NEW-127, deterministic):
// a liveness-completed URL is POST-probed only when its liveness response
// Content-Type looks like body acceptance — form-urlencoded re-sends as a
// form, JSON (including +json suffixes) re-sends as JSON. The response
// Content-Type is a heuristic, NOT acceptance proof: it hints the endpoint
// may read a body but proves nothing about POST acceptance. Anything else
// (HTML pages, images, missing or unparsable types) gets no POST probe:
// without even a heuristic hint a POST would invent an interaction the
// endpoint never offered. The media type is lowercased with parameters
// stripped, so "Application/JSON; charset=utf-8" still matches. Residual:
// a single benign POST may still reach state-changing endpoints, and it
// runs authenticated under the configured session headers.
func reflectPostKind(contentType string) (httpprobe.ReflectScope, bool) {
	media := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(media, ';'); i >= 0 {
		media = strings.TrimSpace(media[:i])
	}
	switch {
	case media == "application/x-www-form-urlencoded":
		return httpprobe.ReflectScopePostForm, true
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		return httpprobe.ReflectScopePostJSON, true
	default:
		return "", false
	}
}

// reflectPostProbes runs POST body reflection over head — the
// GET-budgeted, sorted head selected by addReflection — and returns
// scope-stamped evidence for decided verdicts. Discovery joins each head
// URL against the liveness result: only liveness-completed URLs whose
// response Content-Type heuristically suggests form/JSON acceptance are
// probed (a hint, not acceptance proof), at most one POST per (URL,
// body-kind). Unknown verdicts carry no evidence (fail-open, mirroring
// GET); any body-cap truncation, per-URL transport/cancel/submit failure,
// or cut-short engine call reports truncated, and the first engine error
// returns as err for the caller's partial-downgrade. Residual: a single
// benign POST may reach state-changing endpoints and runs authenticated
// under the configured session headers. All scheduling stays inside the
// engine's bounded pool; no new concurrency is introduced here.
func (s *urlliveStage) reflectPostProbes(ctx context.Context, in pipeline.StageInput, head []asset.URL, cfg httpprobe.Config, res pipeline.StageResult) (evs []asset.Evidence, truncated bool, err error) {
	liveCT := make(map[string]string, len(res.Results.LiveRecords))
	for _, r := range res.Results.LiveRecords {
		if r.Status != 0 && r.Err == nil {
			liveCT[r.URL.Identity().String()] = r.Headers.Get("Content-Type")
		}
	}
	var formURLs, jsonURLs []asset.URL
	for _, u := range head {
		ct, ok := liveCT[u.Identity().String()]
		if !ok {
			continue
		}
		kind, ok := reflectPostKind(ct)
		if !ok {
			continue
		}
		switch kind {
		case httpprobe.ReflectScopePostForm:
			formURLs = append(formURLs, u)
		case httpprobe.ReflectScopePostJSON:
			jsonURLs = append(jsonURLs, u)
		}
	}
	groups := []struct {
		kind httpprobe.ReflectScope
		urls []asset.URL
	}{
		{httpprobe.ReflectScopePostForm, formURLs},
		{httpprobe.ReflectScopePostJSON, jsonURLs},
	}
	for _, g := range groups {
		if len(g.urls) == 0 {
			continue
		}
		rep, rerr := httpprobe.ReflectPOSTURLs(ctx, in.Target, g.urls, g.kind, cfg)
		if rerr != nil {
			// Cut short (error/cancellation): keep whatever the
			// other group decided, flag the set incomplete.
			truncated = true
			if err == nil {
				err = rerr
			}
			continue
		}
		for _, rec := range rep.Records {
			if rec.Truncated || rec.Err != nil {
				truncated = true
			}
			for _, pv := range rec.Verdicts {
				if pv.Verdict == httpprobe.ReflectUnknown {
					continue
				}
				ev, everr := httpprobe.ReflectPostEvidence(rec.URL.Identity(), pv.Param, pv.Verdict, rec.Scope)
				if everr != nil {
					continue
				}
				evs = append(evs, ev)
			}
		}
	}
	return evs, truncated, err
}

// markUrlliveCutShort flags a triage that ended before every URL was probed
// (stage deadline / cancellation): Truncated + urllive_truncated, preserving
// any flags buildUrlliveResult already set.
func markUrlliveCutShort(res *pipeline.StageResult) {
	res.Truncated = true
	if res.StickyFlags == nil {
		res.StickyFlags = map[string]bool{}
	}
	res.StickyFlags[UrlliveStickyFlag] = true
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
// outcome using the unified mapping table (adapt/doc.go): cancelled >
// failed&&none-completed > all-completed > partial. Any record whose Err is
// a context error (run cancellation) folds to cancelled; any other Err
// (timeout, refused, dns, etc.) folds to failed only when NO completed
// record exists — a mixed success/failure report is PARTIAL (M-9 / NEW-72:
// the old fold collapsed mixed reports into completed). All-completed
// reports are completed; anything else is partial. Truncated records are
// considered completed for outcome purposes — the flag, not the outcome,
// marks the set incomplete (AGENTS §0.6 carve-out).
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
	case !anyFailed:
		return pipeline.OutcomeCompleted
	default:
		return pipeline.OutcomePartial
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
