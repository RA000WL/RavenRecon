package httpprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Reflection probing (canary reflection): for corpus URLs carrying query
// parameters, one GET is issued with every targeted parameter substituted by
// a deterministic per-(URL, param) canary, and the bounded response body is
// searched for each canary — raw (reflected-unencoded), percent-encoded
// (reflected-encoded), or absent after a complete read (not-reflected).
// Transport errors, timeouts, and body-cap truncations without an observed
// canary yield unknown: absence under a truncated read proves nothing, so it
// is never reported as not-reflected (AGENTS §0.6).
//
// POST body reflection (NEW-127) runs the same scheme through POST bodies:
// one POST per (URL, body-kind) re-sends the targeted query parameters as
// body fields carrying their canaries — form-urlencoded or JSON, mirroring
// the advertised type — with the same 128 KiB cap, verdict taxonomy, and
// cache honesty. Discovery (which URLs are POST-probed) lives in the
// caller: the engine probes exactly the URLs and kinds it is given.
//
// This is liveness observation, not exploitation: no payload is sent — only
// a benign, deterministic canary token substituted for existing parameter
// values — and redirects are observed, never followed. POST residual
// (NEW-127): POST can change server state; probes are constrained to benign
// canary values on already-parameterized endpoints, one request per (URL,
// body-kind), mirroring the observed Content-Type — the residual is that a
// state-changing endpoint still receives one benign POST. Triage rules
// consume the verdicts as evidence to separate reflected inputs from inert
// ones; unknown or missing verdicts keep the finding (fail-open), so
// behavior without enrichment is unchanged.

const (
	// ReflectOperation is the cache operation for canary reflection probes.
	ReflectOperation = "url.reflect"
	// reflectCanaryScheme versions the canary derivation: a future canary
	// change derives different keys (and verdicts) by construction. It is
	// part of every reflect cache key.
	reflectCanaryScheme = "ravenrecon-reflect-v1"
	// maxReflectParams bounds how many query parameters of one URL are
	// substituted and verdict-ed. Further parameters are counted Skipped
	// on the record — never silently dropped.
	maxReflectParams = 16
	// maxReflectParamNameBytes bounds one decoded, lowercased parameter
	// name accepted for substitution. Longer names are counted Skipped:
	// evidence indicators embed the name under a 128-byte bound, so an
	// unbounded name could never be attributed downstream.
	maxReflectParamNameBytes = 64
	// reflectMaxBodyBytes bounds how many response body bytes one
	// reflection probe reads for canary search. A body exceeding the cap
	// without an observed canary ends the read as unknown (honest
	// truncation); a canary observed before the cap is still a solid
	// reflected verdict, flagged Truncated.
	reflectMaxBodyBytes = 128 << 10
)

// ReflectVerdict is the per-parameter canary verdict.
type ReflectVerdict string

const (
	// ReflectUnencoded reports the raw canary observed in the body.
	ReflectUnencoded ReflectVerdict = "reflected-unencoded"
	// ReflectEncoded reports only the percent-encoded canary observed:
	// the value flows into output through an encoder (weaker signal).
	ReflectEncoded ReflectVerdict = "reflected-encoded"
	// ReflectAbsent reports a complete body read with neither canary
	// form observed.
	ReflectAbsent ReflectVerdict = "not-reflected"
	// ReflectUnknown reports that no verdict was reachable (transport
	// error, timeout, or truncated read without an observed canary).
	ReflectUnknown ReflectVerdict = "unknown"
)

// validReflectVerdict reports whether v is a canonical verdict value.
func validReflectVerdict(v ReflectVerdict) bool {
	switch v {
	case ReflectUnencoded, ReflectEncoded, ReflectAbsent, ReflectUnknown:
		return true
	}
	return false
}

// ReflectScope names the input channel a reflection probe covered. Every
// record and evidence entry carries one so a hunter never reads a
// query-get-only observation as a statement about POST bodies, headers, or
// fragments (NEW-127).
type ReflectScope string

const (
	// ReflectScopeQueryGET marks GET query-parameter reflection (NEW-120).
	ReflectScopeQueryGET ReflectScope = "query-get-only"
	// ReflectScopePostForm marks POST form-urlencoded body reflection.
	ReflectScopePostForm ReflectScope = "post-form"
	// ReflectScopePostJSON marks POST JSON body reflection.
	ReflectScopePostJSON ReflectScope = "post-json"
)

// validReflectScope reports whether s is a canonical scope value.
func validReflectScope(s ReflectScope) bool {
	switch s {
	case ReflectScopeQueryGET, ReflectScopePostForm, ReflectScopePostJSON:
		return true
	}
	return false
}

// validPostScope reports whether s is a POST body scope: only body kinds
// are valid probe targets for ReflectPOSTURLs.
func validPostScope(s ReflectScope) bool {
	return s == ReflectScopePostForm || s == ReflectScopePostJSON
}

// ParamVerdict is one parameter's canary verdict.
type ParamVerdict struct {
	Param   string         `json:"param"`
	Verdict ReflectVerdict `json:"verdict"`
}

// ReflectRecord is the reflection observation for one URL.
type ReflectRecord struct {
	URL asset.URL `json:"url"`
	// Params are the targeted parameter names (decoded, lowercased,
	// sorted, capped) this record verdicts.
	Params []string `json:"params,omitempty"`
	// Verdicts carries one verdict per targeted parameter, sorted by
	// parameter name.
	Verdicts []ParamVerdict `json:"verdicts,omitempty"`
	// Scope names the input channel this record probed: query-get-only
	// for GET query reflection, post-form / post-json for POST body
	// reflection. A query-get-only record says nothing about POST
	// bodies, headers, or fragments.
	Scope ReflectScope `json:"scope,omitempty"`
	// Status is the HTTP status code; 0 when no response was received.
	Status int `json:"status"`
	// Truncated marks a body-cap hit: verdicts of unknown on this record
	// rest on a partial read.
	Truncated bool `json:"truncated,omitempty"`
	// Skipped counts parameters dropped by the per-URL cap or the name
	// bound — honestly counted, never silent.
	Skipped int `json:"skipped,omitempty"`
	// Err carries the transport error for failed probes. Nil for probes
	// that received an HTTP response.
	Err error `json:"-"`
	// ErrMsg is the serialized form of Err (for cache persistence).
	ErrMsg string `json:"error,omitempty"`
	// Cached reports that the record was served from a validated cache
	// hit.
	Cached bool `json:"-"`
}

// ReflectReport is the complete outcome of a ReflectURLs run.
type ReflectReport struct {
	Target  asset.Domain    `json:"target"`
	Records []ReflectRecord `json:"records"`
}

// reflectCanary derives the deterministic canary for one (URL, param)
// pair. The output is lowercase hex plus one ':' separator, so it is safe
// as a raw query value while its percent-encoded form always differs —
// the unencoded/encoded distinction is decidable by construction.
func reflectCanary(urlID, param string) string {
	sum := sha256.Sum256([]byte(reflectCanaryScheme + "\x00" + urlID + "\x00" + param))
	h := hex.EncodeToString(sum[:])
	return "rr" + h[:8] + "x" + h[8:12] + ":q"
}

// extractReflectParams derives the targeted parameter names from a
// canonical URL's query string: decoded, lowercased, deduplicated, sorted,
// capped at maxReflectParams with the remainder counted skipped. Overlong
// names are skipped (they could never be attributed downstream). Bare
// parameters without "=" (e.g. "?q") are counted Skipped, never targeted:
// substitution only rewrites k=<canary> pairs, so a bare parameter would
// never carry its canary and would otherwise verdict a false-absent
// not-reflected (AGENTS §0.6). It mirrors
// the triage pack's extractParamNames normalization so verdicts correlate
// by name without a second normalizer downstream.
func extractReflectParams(target asset.URL) (params []string, skipped int) {
	q := target.Query
	if q == "" {
		return nil, 0
	}
	seen := make(map[string]struct{})
	var names []string
	for _, p := range strings.Split(q, "&") {
		if p == "" {
			continue
		}
		k, _, hasValue := strings.Cut(p, "=")
		if k == "" {
			continue
		}
		if !hasValue {
			// Bare "?q" (no "="): never substituted, so never
			// targeted — counted Skipped, never verdict-ed.
			skipped++
			continue
		}
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if len(k) > maxReflectParamNameBytes {
			skipped++
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) > maxReflectParams {
		skipped += len(names) - maxReflectParams
		names = names[:maxReflectParams]
	}
	return names, skipped
}

// extractReflectParamsWithOriginals derives the targeted parameter names
// plus the first-seen original field spelling per canonical name: decoded
// and trimmed but case-preserved, for POST body rendering. Verdict
// attribution stays on the lowercased canonical; only the body field name
// uses the original. Deduplication, sorting, and caps mirror
// extractReflectParams exactly so keys stay aligned.
func extractReflectParamsWithOriginals(target asset.URL) (params []string, originals map[string]string, skipped int) {
	originals = make(map[string]string)
	q := target.Query
	if q == "" {
		return nil, originals, 0
	}
	seen := make(map[string]struct{})
	var names []string
	for _, p := range strings.Split(q, "&") {
		if p == "" {
			continue
		}
		k, _, hasValue := strings.Cut(p, "=")
		if k == "" {
			continue
		}
		if !hasValue {
			skipped++
			continue
		}
		decoded := k
		if d, err := url.QueryUnescape(k); err == nil {
			decoded = d
		}
		orig := strings.TrimSpace(decoded)
		canon := strings.ToLower(orig)
		if canon == "" {
			continue
		}
		if len(canon) > maxReflectParamNameBytes {
			skipped++
			continue
		}
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		names = append(names, canon)
		originals[canon] = orig
	}
	sort.Strings(names)
	if len(names) > maxReflectParams {
		skipped += len(names) - maxReflectParams
		for _, drop := range names[maxReflectParams:] {
			delete(originals, drop)
		}
		names = names[:maxReflectParams]
	}
	return names, originals, skipped
}

// substituteCanaries rewrites rawQuery with every targeted parameter's
// value(s) replaced by its canary. Non-targeted pairs pass through
// byte-identical; matching is on the decoded-lowercased key, so encoded
// key spellings are substituted too. The output is deterministic.
func substituteCanaries(rawQuery string, canaries map[string]string) string {
	if rawQuery == "" || len(canaries) == 0 {
		return rawQuery
	}
	pairs := strings.Split(rawQuery, "&")
	for i, p := range pairs {
		if p == "" {
			continue
		}
		k, _, hasValue := strings.Cut(p, "=")
		if k == "" || !hasValue {
			continue
		}
		key := k
		if decoded, err := url.QueryUnescape(k); err == nil {
			key = decoded
		}
		key = strings.ToLower(strings.TrimSpace(key))
		canary, ok := canaries[key]
		if !ok {
			continue
		}
		pairs[i] = k + "=" + url.QueryEscape(canary)
	}
	return strings.Join(pairs, "&")
}

// ReflectURLs probes canary reflection for the given URLs within the
// declared target domain: one GET per parameterized URL with every
// targeted parameter substituted, redirects observed never followed, body
// read bounded by reflectMaxBodyBytes. URLs without query parameters
// complete with zero verdicts and zero requests. Results are sorted
// deterministically by canonical URL string. One bounded runtime.Pool owns
// all scheduling; cache-before-execute (operation url.reflect) applies per
// URL when cfg.Cache is non-nil.
func ReflectURLs(ctx context.Context, domain asset.Domain, urls []asset.URL, cfg Config) (ReflectReport, error) {
	return runReflect(ctx, domain, urls, cfg, func(jctx context.Context, u asset.URL, e env) ReflectRecord {
		return reflectOneURL(jctx, u, domain, e)
	})
}

// ReflectPOSTURLs probes canary reflection through POST bodies for the
// given URLs within the declared target domain: one POST per parameterized
// URL with every targeted query parameter re-sent as a body field carrying
// its deterministic per-(URL, param) canary — the same canary scheme as
// the GET path. kind selects the body encoding (post-form or post-json)
// and is stamped on every record; any other scope is rejected before any
// request. Redirects are observed, never followed; the body read is
// bounded by reflectMaxBodyBytes; the verdict taxonomy and unknown-on-error
// semantics match the GET path exactly. URLs without query parameters
// complete with zero verdicts and zero requests. Results are sorted
// deterministically by canonical URL string. One bounded runtime.Pool owns
// all scheduling; cache-before-execute (operation url.reflect, POST-bound
// keys) applies per URL when cfg.Cache is non-nil.
//
// POST residual (NEW-127, AGENTS §0): POST can change server state. Probes
// are constrained to benign canary values substituted for existing
// parameter values on already-parameterized endpoints — never new attack
// payloads, no auth/session mutation beyond the configured session headers
// shared with the GET path — one request per (URL, body-kind), mirroring
// the advertised Content-Type. The residual is that a state-changing
// endpoint still receives one benign POST; callers gate discovery (which
// URLs advertise body acceptance) so probes never invent endpoints.
func ReflectPOSTURLs(ctx context.Context, domain asset.Domain, urls []asset.URL, kind ReflectScope, cfg Config) (ReflectReport, error) {
	if !validPostScope(kind) {
		return ReflectReport{}, fmt.Errorf("httpprobe: reflect POST needs a body scope (post-form or post-json), got %q", kind)
	}
	return runReflect(ctx, domain, urls, cfg, func(jctx context.Context, u asset.URL, e env) ReflectRecord {
		return reflectOnePostURL(jctx, u, domain, kind, e)
	})
}

// runReflect owns the bounded pool shared by the GET and POST reflection
// probes: scope validation, input normalization, pool defaults, submit
// loop, clean shutdown, deterministic sort. The per-URL probe (including
// its cache-before-execute semantics) is injected so both channels share
// one scheduling envelope.
func runReflect(ctx context.Context, domain asset.Domain, urls []asset.URL, cfg Config, probe func(jctx context.Context, u asset.URL, e env) ReflectRecord) (ReflectReport, error) {
	if ctx == nil {
		return ReflectReport{}, fmt.Errorf("httpprobe: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return ReflectReport{}, fmt.Errorf("httpprobe: %w", err)
	}
	if err := validateScope(domain); err != nil {
		return ReflectReport{}, err
	}
	norm, err := normalizeInputURLs(urls, domain)
	if err != nil {
		return ReflectReport{}, err
	}
	if len(norm) == 0 {
		return ReflectReport{Target: domain}, nil
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = liveRequestTimeoutDefault
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = liveConcurrencyDefault
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = cfg.Concurrency
	}
	e, err := buildEnv(cfg, map[string]asset.IP{})
	if err != nil {
		return ReflectReport{}, err
	}
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        0,
		Burst:       0,
		// Forward the instrumentation sink; nil disables pool events.
		// The stateless Deriver converts completed job results into
		// canonical derived events at the pool-job boundary.
		Observer: cfg.Observer,
		Deriver:  Deriver{},
	})
	if err != nil {
		return ReflectReport{}, fmt.Errorf("httpprobe: create worker pool: %w", err)
	}
	results := make([]ReflectRecord, len(norm))
	for i, u := range norm {
		results[i] = ReflectRecord{URL: u, Err: context.Canceled}
	}
	for i, u := range norm {
		i := i
		u := u
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			results[i] = probe(jctx, u, e)
			return results[i], nil
		}}); err != nil {
			results[i] = ReflectRecord{URL: u, Err: fmt.Errorf("httpprobe: submit %s: %w", u.String(), err)}
			for j := i + 1; j < len(norm); j++ {
				results[j] = ReflectRecord{URL: norm[j], Err: fmt.Errorf("httpprobe: not submitted: %w", ctx.Err())}
			}
			break
		}
	}
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()
	sort.Slice(results, func(i, j int) bool { return results[i].URL.String() < results[j].URL.String() })
	report := ReflectReport{Target: domain, Records: results}
	if shutdownErr != nil {
		return report, fmt.Errorf("httpprobe: pool shutdown: %w", shutdownErr)
	}
	return report, nil
}

// reflectOneURL reflects one URL with cache-before-execute semantics.
// Parameter extraction runs before the lookup because the cache key binds
// the targeted parameter list.
func reflectOneURL(ctx context.Context, target asset.URL, domain asset.Domain, e env) ReflectRecord {
	rec := ReflectRecord{URL: target, Scope: ReflectScopeQueryGET}
	params, skipped := extractReflectParams(target)
	rec.Skipped = skipped
	if e.cache != nil {
		if hit, ok := lookupReflect(ctx, target, domain, params, ReflectScopeQueryGET, e); ok {
			hit.Skipped = skipped
			return hit
		}
	}
	if ctx.Err() != nil {
		rec.Err = ctx.Err()
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	if len(params) == 0 {
		// Nothing to reflect (no query, or every name skipped): a
		// completed observation with zero verdicts and zero requests.
		return rec
	}
	rec.Params = params
	rec = doReflectProbe(ctx, target, params, e, rec)
	if e.cache != nil {
		rec = storeReflect(ctx, target, domain, params, ReflectScopeQueryGET, rec, e)
	}
	return rec
}

// reflectOnePostURL reflects one URL through a POST body with
// cache-before-execute semantics under a POST-bound key. Parameter
// extraction mirrors the GET path: the targeted query parameters are
// re-sent as body fields, so a URL without substitutable params completes
// with zero verdicts and zero requests.
func reflectOnePostURL(ctx context.Context, target asset.URL, domain asset.Domain, kind ReflectScope, e env) ReflectRecord {
	rec := ReflectRecord{URL: target, Scope: kind}
	params, originals, skipped := extractReflectParamsWithOriginals(target)
	rec.Skipped = skipped
	if e.cache != nil {
		if hit, ok := lookupReflect(ctx, target, domain, params, kind, e); ok {
			hit.Skipped = skipped
			return hit
		}
	}
	if ctx.Err() != nil {
		rec.Err = ctx.Err()
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	if len(params) == 0 {
		// Nothing to reflect (no query, or every name skipped): a
		// completed observation with zero verdicts and zero requests.
		return rec
	}
	rec.Params = params
	rec = doReflectPostProbe(ctx, target, params, originals, kind, e, rec)
	if e.cache != nil {
		rec = storeReflect(ctx, target, domain, params, kind, rec, e)
	}
	return rec
}

// reflectKey derives the Phase 3 cache key for one GET reflection probe. The
// key binds the operation, the canonical URL identity, the declared
// domain, the sorted targeted parameter list, and the canary scheme: any
// of them changing the observable verdicts misses by construction. Fixed
// constants (body cap, verdict vocabulary) never enter the key — a
// completed entry stays valid under caps that only retain more, and
// truncated entries are stored incomplete (never served) under every cap.
// POST probes never use this key (see reflectPostKey): the same (URL,
// params) under GET and POST must never share an entry.
func reflectKey(target asset.URL, domain asset.Domain, params []string, session string) (cache.Key, error) {
	cp := append([]string(nil), params...)
	sort.Strings(cp)
	sum := sha256.Sum256([]byte(strings.Join(cp, "\x00")))
	cfg := map[string]string{
		"domain":  domain.Name,
		"reflect": reflectCanaryScheme,
		"params":  hex.EncodeToString(sum[:]),
	}
	if session != "" {
		cfg["session"] = session
	}
	return cache.NewKey(cache.KeyParts{
		Operation: ReflectOperation,
		Target:    target.Identity().String(),
		Config:    cfg,
	})
}

// reflectKeyForScope resolves the cache key for one reflection probe by
// channel: GET probes use the original reflectKey byte-identically (old
// entries stay valid); POST probes use a channel-bound key.
func reflectKeyForScope(target asset.URL, domain asset.Domain, params []string, session string, scope ReflectScope) (cache.Key, error) {
	if validPostScope(scope) {
		return reflectPostKey(target, domain, params, session, scope)
	}
	return reflectKey(target, domain, params, session)
}

// reflectPostKey derives the Phase 3 cache key for one POST reflection
// probe. It binds everything reflectKey binds plus the probe channel: the
// method marker ("POST") is folded into the hashed params material and the
// method/body-kind ride as structural config entries, so the same (URL,
// params) under GET and POST — or under post-form and post-json — never
// share an entry by construction (a GET verdict served for a POST probe
// would be a scope lie, AGENTS §0.6).
func reflectPostKey(target asset.URL, domain asset.Domain, params []string, session string, kind ReflectScope) (cache.Key, error) {
	cp := append([]string(nil), params...)
	sort.Strings(cp)
	sum := sha256.Sum256([]byte("POST\x00" + string(kind) + "\x00" + strings.Join(cp, "\x00")))
	cfg := map[string]string{
		"domain":  domain.Name,
		"method":  http.MethodPost,
		"body":    string(kind),
		"reflect": reflectCanaryScheme,
		"params":  hex.EncodeToString(sum[:]),
	}
	if session != "" {
		cfg["session"] = session
	}
	return cache.NewKey(cache.KeyParts{
		Operation: ReflectOperation,
		Target:    target.Identity().String(),
		Config:    cfg,
	})
}

// doReflectProbe executes one bounded reflection probe: limiter wait,
// single GET with substituted canaries (redirects never followed —
// RoundTrip is direct), body read bounded by reflectMaxBodyBytes.
func doReflectProbe(ctx context.Context, target asset.URL, params []string, e env, rec ReflectRecord) ReflectRecord {
	if err := waitForToken(ctx, e); err != nil {
		rec.Err = err
		rec.ErrMsg = err.Error()
		return rec
	}
	reqCtx := ctx
	if e.requestTimeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, e.requestTimeout)
		defer cancel()
	}
	canaries := make(map[string]string, len(params))
	for _, p := range params {
		canaries[p] = reflectCanary(target.Identity().String(), p)
	}
	parsed, err := url.Parse(target.String())
	if err != nil {
		rec.Err = fmt.Errorf("httpprobe: reflect %s: parse target: %w", target.String(), err)
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	parsed.RawQuery = substituteCanaries(parsed.RawQuery, canaries)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		rec.Err = fmt.Errorf("httpprobe: reflect %s: build request: %w", target.String(), err)
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	req.Header.Set("User-Agent", userAgent)
	applySessionHeaders(req, e.reqHeaders)
	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		rec.Err = err
		rec.ErrMsg = err.Error()
		return verdictsUnknown(rec, params)
	}
	defer resp.Body.Close()
	rec.Status = resp.StatusCode
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, reflectMaxBodyBytes+1))
	if rerr != nil {
		rec.Err = rerr
		rec.ErrMsg = rerr.Error()
		// A body-read failure may have delivered a partial prefix before
		// failing: absence over that prefix proves nothing (§0.6), so the
		// record is truncated (stored incomplete, never served) and its
		// verdicts stay unknown.
		rec.Truncated = true
		return verdictsUnknown(rec, params)
	}
	if int64(len(body)) > reflectMaxBodyBytes {
		rec.Truncated = true
		body = body[:reflectMaxBodyBytes]
	}
	rec.Verdicts = classifyReflectBody(body, canaries, params, rec.Truncated)
	return rec
}

// POST body content types mirrored from the advertised type.
const (
	// reflectPostFormContentType is the body type for post-form probes.
	reflectPostFormContentType = "application/x-www-form-urlencoded"
	// reflectPostJSONContentType is the body type for post-json probes.
	reflectPostJSONContentType = "application/json"
)

// reflectPostBody builds the deterministic POST body for one probe: every
// targeted parameter re-sent as a body field carrying its canary. Field
// names render the first-seen ORIGINAL spelling (originals maps canonical
// → original); verdict attribution stays on the lowercased canonical, so
// only the wire spelling uses the original. Form bodies join
// QueryEscape-d pairs with "&" in sorted canonical order; JSON bodies
// render a param→canary object in sorted canonical order (keys marshaled
// individually, so the rendering is deterministic regardless of case).
// Only existing parameter values are substituted — no new fields, no
// attack payloads.
func reflectPostBody(params []string, originals map[string]string, canaries map[string]string, kind ReflectScope) (body, contentType string, err error) {
	switch kind {
	case ReflectScopePostForm:
		pairs := make([]string, 0, len(params))
		for _, p := range params {
			field := p
			if orig, ok := originals[p]; ok && orig != "" {
				field = orig
			}
			pairs = append(pairs, url.QueryEscape(field)+"="+url.QueryEscape(canaries[p]))
		}
		return strings.Join(pairs, "&"), reflectPostFormContentType, nil
	case ReflectScopePostJSON:
		var sb strings.Builder
		sb.WriteByte('{')
		for i, p := range params {
			field := p
			if orig, ok := originals[p]; ok && orig != "" {
				field = orig
			}
			kb, merr := json.Marshal(field)
			if merr != nil {
				return "", "", fmt.Errorf("httpprobe: reflect POST JSON body: %w", merr)
			}
			vb, merr := json.Marshal(canaries[p])
			if merr != nil {
				return "", "", fmt.Errorf("httpprobe: reflect POST JSON body: %w", merr)
			}
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.Write(kb)
			sb.WriteByte(':')
			sb.Write(vb)
		}
		sb.WriteByte('}')
		return sb.String(), reflectPostJSONContentType, nil
	default:
		return "", "", fmt.Errorf("httpprobe: unknown reflect POST scope %q", kind)
	}
}

// doReflectPostProbe executes one bounded POST reflection probe: limiter
// wait, single POST with canary-substituted body fields (redirects never
// followed — RoundTrip is direct), body read bounded by
// reflectMaxBodyBytes. The POST URL keeps the original query string intact:
// canaries travel in the body only, so query-echo and body-echo never mix.
// Body field names render the first-seen original spelling; canaries and
// verdicts stay keyed by the lowercased canonical.
func doReflectPostProbe(ctx context.Context, target asset.URL, params []string, originals map[string]string, kind ReflectScope, e env, rec ReflectRecord) ReflectRecord {
	if err := waitForToken(ctx, e); err != nil {
		rec.Err = err
		rec.ErrMsg = err.Error()
		return rec
	}
	reqCtx := ctx
	if e.requestTimeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, e.requestTimeout)
		defer cancel()
	}
	canaries := make(map[string]string, len(params))
	for _, p := range params {
		canaries[p] = reflectCanary(target.Identity().String(), p)
	}
	postBody, contentType, err := reflectPostBody(params, originals, canaries, kind)
	if err != nil {
		rec.Err = err
		rec.ErrMsg = err.Error()
		return verdictsUnknown(rec, params)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.String(), strings.NewReader(postBody))
	if err != nil {
		rec.Err = fmt.Errorf("httpprobe: reflect POST %s: build request: %w", target.String(), err)
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", contentType)
	applySessionHeaders(req, e.reqHeaders)
	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		rec.Err = err
		rec.ErrMsg = err.Error()
		return verdictsUnknown(rec, params)
	}
	defer resp.Body.Close()
	rec.Status = resp.StatusCode
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, reflectMaxBodyBytes+1))
	if rerr != nil {
		rec.Err = rerr
		rec.ErrMsg = rerr.Error()
		// A body-read failure may have delivered a partial prefix before
		// failing: absence over that prefix proves nothing (§0.6), so the
		// record is truncated (stored incomplete, never served) and its
		// verdicts stay unknown.
		rec.Truncated = true
		return verdictsUnknown(rec, params)
	}
	if int64(len(body)) > reflectMaxBodyBytes {
		rec.Truncated = true
		body = body[:reflectMaxBodyBytes]
	}
	rec.Verdicts = classifyReflectBody(body, canaries, params, rec.Truncated)
	return rec
}

// classifyReflectBody verdicts every targeted parameter over one bounded
// response body: raw canary present → reflected-unencoded; else the
// percent-encoded canary (percent-hex matched case-insensitively —
// %3A vs %3a — while the raw search stays exact) → reflected-encoded;
// else unknown under a truncated read (absence under a partial read proves
// nothing, AGENTS §0.6) or not-reflected after a complete read. The GET and
// POST probes share this classifier so both channels speak one verdict
// taxonomy over the same canary scheme.
func classifyReflectBody(body []byte, canaries map[string]string, params []string, truncated bool) []ParamVerdict {
	text := string(body)
	lower := strings.ToLower(text)
	out := make([]ParamVerdict, 0, len(params))
	for _, p := range params {
		raw := canaries[p]
		switch {
		case strings.Contains(text, raw):
			out = append(out, ParamVerdict{Param: p, Verdict: ReflectUnencoded})
		case strings.Contains(lower, strings.ToLower(url.QueryEscape(raw))):
			out = append(out, ParamVerdict{Param: p, Verdict: ReflectEncoded})
		case truncated:
			out = append(out, ParamVerdict{Param: p, Verdict: ReflectUnknown})
		default:
			out = append(out, ParamVerdict{Param: p, Verdict: ReflectAbsent})
		}
	}
	return out
}

// verdictsUnknown marks every targeted parameter unknown (transport error,
// timeout, or body-read failure): no verdict was reachable.
func verdictsUnknown(rec ReflectRecord, params []string) ReflectRecord {
	rec.Verdicts = make([]ParamVerdict, 0, len(params))
	for _, p := range params {
		rec.Verdicts = append(rec.Verdicts, ParamVerdict{Param: p, Verdict: ReflectUnknown})
	}
	return rec
}

// storedReflect is the persisted payload for one reflection record.
type storedReflect struct {
	Target     string         `json:"target"`
	Params     []string       `json:"params,omitempty"`
	Verdicts   []ParamVerdict `json:"verdicts,omitempty"`
	Scope      ReflectScope   `json:"scope,omitempty"`
	StatusCode int            `json:"status_code"`
	Truncated  bool           `json:"truncated,omitempty"`
	Skipped    int            `json:"skipped,omitempty"`
	ErrMsg     string         `json:"error,omitempty"`
}

// decodeStoredReflect validates a stored payload before serving it as a
// hit: canonical target match, exact parameter-list match (order-sensitive
// — both sides store sorted), per-verdict vocabulary and param-membership
// checks, probe-channel match (a GET verdict is never served for a POST
// probe and vice versa — the keys already separate channels, this is
// defense in depth), status range, and the truncated contradiction (a
// completed record never carries Truncated). Any violation evicts and
// recomputes. Legacy GET entries stored without a scope read as
// query-get-only.
func decodeStoredReflect(raw json.RawMessage, target asset.URL, params []string, scope ReflectScope) (storedReflect, error) {
	var s storedReflect
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored reflect result: %w", err)
	}
	if s.Target != target.String() {
		return s, fmt.Errorf("stored reflect target %q does not match %q", s.Target, target.String())
	}
	if len(s.Params) != len(params) {
		return s, fmt.Errorf("stored reflect params %d do not match %d", len(s.Params), len(params))
	}
	for i := range params {
		if s.Params[i] != params[i] {
			return s, fmt.Errorf("stored reflect param %d %q does not match %q", i, s.Params[i], params[i])
		}
	}
	if len(s.Verdicts) != len(params) {
		return s, fmt.Errorf("stored reflect verdicts %d do not match params %d", len(s.Verdicts), len(params))
	}
	for i, pv := range s.Verdicts {
		if pv.Param != params[i] {
			return s, fmt.Errorf("stored reflect verdict %d param %q does not match %q", i, pv.Param, params[i])
		}
		if !validReflectVerdict(pv.Verdict) {
			return s, fmt.Errorf("stored reflect verdict %q is not a canonical verdict", pv.Verdict)
		}
	}
	if s.StatusCode < 0 || s.StatusCode > 599 {
		return s, fmt.Errorf("stored reflect has invalid status code %d", s.StatusCode)
	}
	switch {
	case validPostScope(scope):
		if s.Scope != scope {
			return s, fmt.Errorf("stored reflect scope %q does not match %q", s.Scope, scope)
		}
	case scope == ReflectScopeQueryGET || scope == "":
		if s.Scope != "" && s.Scope != ReflectScopeQueryGET {
			return s, fmt.Errorf("stored reflect scope %q is not a GET scope", s.Scope)
		}
	default:
		return s, fmt.Errorf("stored reflect lookup needs a canonical scope, got %q", scope)
	}
	if s.Truncated {
		return s, fmt.Errorf("stored reflect is marked truncated")
	}
	if s.Skipped < 0 {
		return s, fmt.Errorf("stored reflect has negative skipped %d", s.Skipped)
	}
	return s, nil
}

// reflectRecordFromStored rebuilds a ReflectRecord from validated payload.
// A legacy payload stored without a scope normalizes to the lookup scope.
func reflectRecordFromStored(s storedReflect, target asset.URL, params []string, scope ReflectScope) ReflectRecord {
	rec := ReflectRecord{
		URL:      target,
		Params:   append([]string(nil), params...),
		Verdicts: append([]ParamVerdict(nil), s.Verdicts...),
		Scope:    s.Scope,
		Status:   s.StatusCode,
		Skipped:  s.Skipped,
		Cached:   true,
	}
	if rec.Scope == "" {
		rec.Scope = scope
	}
	if s.ErrMsg != "" {
		rec.Err = errors.New(s.ErrMsg)
		rec.ErrMsg = s.ErrMsg
	}
	return rec
}

// lookupReflect is the cache-before-execute read side for one reflection
// target. The key binds the targeted parameter list, so extraction runs
// before the lookup. scope selects the channel key (GET keys stay
// byte-identical to the pre-scope layout). A key-construction failure is a
// cache miss, never an observation error: the returned record is discarded
// by the caller on a miss, so it carries no diagnostic Err.
func lookupReflect(ctx context.Context, target asset.URL, domain asset.Domain, params []string, scope ReflectScope, e env) (ReflectRecord, bool) {
	key, err := reflectKeyForScope(target, domain, params, e.session, scope)
	if err != nil {
		return ReflectRecord{}, false
	}
	out := e.cache.Get(ctx, key)
	if !out.IsHit() {
		return ReflectRecord{}, false
	}
	if out.Record.Operation != ReflectOperation || out.Record.Target != target.Identity().String() {
		_ = e.cache.Delete(ctx, key)
		return ReflectRecord{}, false
	}
	st, derr := decodeStoredReflect(out.Record.Data, target, params, scope)
	if derr != nil {
		_ = e.cache.Delete(ctx, key)
		return ReflectRecord{}, false
	}
	return reflectRecordFromStored(st, target, params, scope), true
}

// storeReflect is the cache write side for one reflection target.
// Cache diagnostics (key, encode, or put failures) never join the
// observation Err: a cache failure must not corrupt a completed
// observation into a failed one. Failures return the record unchanged.
func storeReflect(ctx context.Context, target asset.URL, domain asset.Domain, params []string, scope ReflectScope, rec ReflectRecord, e env) ReflectRecord {
	key, err := reflectKeyForScope(target, domain, params, e.session, scope)
	if err != nil {
		return rec
	}
	st := storedReflect{
		Target:     target.String(),
		Params:     append([]string(nil), params...),
		Verdicts:   append([]ParamVerdict(nil), rec.Verdicts...),
		Scope:      scope,
		StatusCode: rec.Status,
		Truncated:  rec.Truncated,
		Skipped:    rec.Skipped,
		ErrMsg:     rec.ErrMsg,
	}
	data, err := json.Marshal(st)
	if err != nil {
		return rec
	}
	recCache := cache.Record{
		Operation: ReflectOperation,
		Target:    target.Identity().String(),
		Status:    reflectStatusToCache(rec),
		Meta:      map[string]string{"scheme": target.Scheme},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	// A put failure is a cache diagnostic, never an observation error.
	_ = e.cache.Put(storeCtx, key, recCache)
	return rec
}

// ReflectEvidenceIndicatorPrefix namespaces reflection indicators inside
// the shared evidence channel (MethodEndpoint): "reflect:<param>".
const ReflectEvidenceIndicatorPrefix = "reflect:"

// ReflectEvidenceIndicator returns the evidence indicator for one
// parameter's reflection verdict.
func ReflectEvidenceIndicator(param string) string {
	return ReflectEvidenceIndicatorPrefix + param
}

// ReflectEvidence builds the evidence record for one decided parameter
// verdict: MethodEndpoint (observed by probing the endpoint), the
// namespaced indicator, the verdict value, sourced at the probed URL's
// identity. Unknown verdicts are never built — unknown is fail-open at
// the reader, and emitting it would spend channel budget for zero
// decision value.
func ReflectEvidence(source asset.Identity, param string, v ReflectVerdict) (asset.Evidence, error) {
	if v != ReflectUnencoded && v != ReflectEncoded && v != ReflectAbsent {
		return asset.Evidence{}, fmt.Errorf("httpprobe: reflect evidence needs a decided verdict, got %q", v)
	}
	return asset.NewEvidence(asset.MethodEndpoint, ReflectEvidenceIndicator(param), string(v), source, asset.Provenance{Source: "urllive"})
}

// ParseReflectEvidence reads the writer contract back: it reports the
// parameter and verdict for reflection evidence records and refuses
// everything else (other methods, other indicators, non-vocabulary
// values), so foreign evidence sharing the snapshot channel can never
// influence a reflection consumer.
func ParseReflectEvidence(ev asset.Evidence) (string, ReflectVerdict, bool) {
	if ev.Method != asset.MethodEndpoint {
		return "", "", false
	}
	param, ok := strings.CutPrefix(ev.Indicator, ReflectEvidenceIndicatorPrefix)
	if !ok || param == "" {
		return "", "", false
	}
	v := ReflectVerdict(ev.Value)
	if !validReflectVerdict(v) || v == ReflectUnknown {
		return "", "", false
	}
	return param, v, true
}

// POST reflection indicator prefixes (NEW-127). They deliberately avoid
// the "reflect:" prefix so the GET-only reader above — and every triage
// gate built on it — never parses a POST verdict as a query verdict:
// GET gating flows exactly as before POST existed, while POST verdicts
// stay visible to hunters carrying their own scope.
const (
	// ReflectPostFormIndicatorPrefix namespaces post-form verdicts.
	ReflectPostFormIndicatorPrefix = "reflect-post-form:"
	// ReflectPostJSONIndicatorPrefix namespaces post-json verdicts.
	ReflectPostJSONIndicatorPrefix = "reflect-post-json:"
)

// ReflectPostEvidenceIndicator returns the evidence indicator for one
// POST parameter verdict under the given body scope.
func ReflectPostEvidenceIndicator(scope ReflectScope, param string) (string, error) {
	switch scope {
	case ReflectScopePostForm:
		return ReflectPostFormIndicatorPrefix + param, nil
	case ReflectScopePostJSON:
		return ReflectPostJSONIndicatorPrefix + param, nil
	default:
		return "", fmt.Errorf("httpprobe: reflect POST evidence needs a body scope (post-form or post-json), got %q", scope)
	}
}

// ReflectPostEvidence builds the evidence record for one decided POST
// parameter verdict: MethodEndpoint, the scope-namespaced indicator, the
// verdict value, sourced at the probed URL's identity. Unknown verdicts
// are never built — unknown is fail-open at the reader, and emitting it
// would spend channel budget for zero decision value.
func ReflectPostEvidence(source asset.Identity, param string, v ReflectVerdict, scope ReflectScope) (asset.Evidence, error) {
	if v != ReflectUnencoded && v != ReflectEncoded && v != ReflectAbsent {
		return asset.Evidence{}, fmt.Errorf("httpprobe: reflect POST evidence needs a decided verdict, got %q", v)
	}
	ind, err := ReflectPostEvidenceIndicator(scope, param)
	if err != nil {
		return asset.Evidence{}, err
	}
	return asset.NewEvidence(asset.MethodEndpoint, ind, string(v), source, asset.Provenance{Source: "urllive"})
}

// ReflectEvidenceScope reports the probed input channel for a reflection
// evidence record: query-get-only for GET query verdicts, post-form /
// post-json for POST body verdicts. It accepts decided verdicts only —
// unknown carries no channel claim (builders never emit it, and a
// hand-crafted unknown must not gate or cite) — and refuses everything
// else, mirroring the ParseReflectEvidence boundaries so foreign evidence
// never claims a scope.
func ReflectEvidenceScope(ev asset.Evidence) (ReflectScope, bool) {
	if ev.Method != asset.MethodEndpoint {
		return "", false
	}
	if param, ok := strings.CutPrefix(ev.Indicator, ReflectPostFormIndicatorPrefix); ok && param != "" {
		if v := ReflectVerdict(ev.Value); validReflectVerdict(v) && v != ReflectUnknown {
			return ReflectScopePostForm, true
		}
		return "", false
	}
	if param, ok := strings.CutPrefix(ev.Indicator, ReflectPostJSONIndicatorPrefix); ok && param != "" {
		if v := ReflectVerdict(ev.Value); validReflectVerdict(v) && v != ReflectUnknown {
			return ReflectScopePostJSON, true
		}
		return "", false
	}
	if param, ok := strings.CutPrefix(ev.Indicator, ReflectEvidenceIndicatorPrefix); ok && param != "" {
		if v := ReflectVerdict(ev.Value); validReflectVerdict(v) && v != ReflectUnknown {
			return ReflectScopeQueryGET, true
		}
	}
	return "", false
}

// reflectStatusToCache maps a reflection record onto a cache status:
// truncated is incomplete (never served); a received response — any
// status — is a completed observation; transport failures are failed;
// cancellation is cancelled.
func reflectStatusToCache(rec ReflectRecord) cache.Status {
	if rec.Truncated {
		return cache.StatusIncomplete
	}
	if rec.Status != 0 {
		return cache.StatusCompleted
	}
	if rec.Err != nil {
		if errors.Is(rec.Err, context.Canceled) {
			return cache.StatusCancelled
		}
		return cache.StatusFailed
	}
	return cache.StatusCompleted
}
