package httpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Operation is the stable cache operation name for the HTTP probing
// pipeline. It is part of the Phase 3 cache key payload; changing it
// invalidates every previously stored probe record by construction.
const Operation = "http.probe"

// probeKey derives the Phase 3 cache key for one probe target.
//
// The key contains every input that materially changes the result: the
// operation ("http.probe"), the canonical Phase 2 URL identity of the probe
// target ("url:http://example.com" — raw input never reaches a key, and the
// scheme is part of the identity, so the http and https probes of one host
// are distinct keys), AND the canonical declared domain. The domain is a key
// input because the redirect scope boundary is part of the walk semantics:
// recordHop decides follow-vs-observe against the declared domain, so two
// runs of the same target under different declared domains can legitimately
// produce different walks. A narrow-scope run stores a completed record
// whose out-of-scope hops were observed but never followed; a later
// broader-scope run must never be served that scope-truncated walk as
// complete — under the old key shape it was, because the record decodes
// cleanly (its stored hops are all in-scope for the broader domain).
//
// The request shape is fixed (GET, no body, a fixed RavenRecon user agent)
// and the redirect policy and the caps (MaxRedirects, MaxHeaderBytes,
// MaxHeaders, MaxBodyBytes) are fixed constants, not configuration — so,
// like the DNS pipeline's answer cap, they must never enter the key: a
// completed entry written under the current caps stays valid under any
// future caps that only retain more, and truncated entries are stored
// incomplete (never served) under every cap. Timings, timeouts,
// concurrency, rate limits, and the transport (trust roots, dial routing)
// never enter the key either — exactly like the DNS pipeline, which never
// hashes the resolver.
//
// The domain entered the key in the M-2 release; records written by earlier
// builds (keyed on operation + target only) are unreachable under the new
// key shape and are simply re-probed. That is acceptable at release: stale
// scope-truncated records must never be served, and a re-probe is the safe
// outcome.
func probeKey(target asset.URL, domain asset.Domain) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    target.Identity().String(),
		Config:    map[string]string{"domain": domain.Name},
	})
}

// storedProbe is the structured Data payload of one probe-target cache
// record. It is never terminal output: URLs are stored as the typed Phase 2
// assets (with provenance) exactly as they will be served back, and the
// observation fields mirror ProbeResult.
type storedProbe struct {
	// Target is the canonical probe-target URL string.
	Target string `json:"target"`
	// Scheme is the probe scheme, "http" or "https".
	Scheme string `json:"scheme"`
	// StatusCode is the final response's status code (0 when no HTTP
	// response was received).
	StatusCode int `json:"status_code"`
	// FinalURL is the last URL actually requested, as a typed Phase 2 URL
	// asset.
	FinalURL asset.URL `json:"final_url"`
	// Headers are the final response's bounded, sorted header entries.
	Headers []HeaderEntry `json:"headers,omitempty"`
	// ResponseSize is the counted body size of the final response.
	ResponseSize int64 `json:"response_size"`
	// TLS reports that the https probe completed a TLS handshake.
	TLS bool `json:"tls,omitempty"`
	// TLSMeta is the stored typed TLS observation (5C): nil when the probe
	// completed no handshake. It may only appear on a completed https probe
	// with TLS=true, and it is re-validated field by field on decode
	// (validateStoredTLS) — bounds, the completed-handshake consistency
	// rules, and the embedded certificate asset through the Phase 2 model.
	TLSMeta *TLSMetadata `json:"tls_meta,omitempty"`
	// Truncated marks a probe that hit a hard cap; such records are stored
	// StatusIncomplete and never served as hits.
	Truncated bool `json:"truncated,omitempty"`
	// FailureReason is the typed cause of a completed probe without an HTTP
	// response (conn_refused / tls), or the redirect-cap reason.
	FailureReason FailureReason `json:"failure_reason,omitempty"`
	// Redirects are the observed Location targets in order.
	Redirects []RedirectHop `json:"redirects,omitempty"`
}

// decodeStoredProbe validates and decodes a stored probe payload before it
// may be served as a hit. It re-validates every URL through the Phase 2
// asset model (canonical form required), refuses payloads whose target or
// scheme does not match the probe, whose redirect chain is internally
// inconsistent, whose final URL does not match the chain, whose header
// entries are not canonical, whose URLs carry credentials in their original
// form, and whose outcome flags contradict each other (a completed record
// with a truncated flag, a failed reason, a missing status code, a redirect
// status with a followed chain and a Location header, ...) — so a corrupt,
// tampered, or legacy completed record can never produce bogus observations.
// On any error the caller deletes the record and falls through to a fresh
// probe (self-healing), never serving it as a hit.
func decodeStoredProbe(raw json.RawMessage, target asset.URL, scheme string, domain asset.Domain) (storedProbe, error) {
	var s storedProbe
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored result: %w", err)
	}
	if s.Target != target.String() {
		return s, fmt.Errorf("stored result target %q does not match %q", s.Target, target.String())
	}
	if s.Scheme != scheme {
		return s, fmt.Errorf("stored result scheme %q does not match %q", s.Scheme, scheme)
	}
	if s.StatusCode < 0 || s.StatusCode > 599 {
		return s, fmt.Errorf("stored result has invalid status code %d", s.StatusCode)
	}
	if s.ResponseSize < 0 {
		return s, fmt.Errorf("stored result has negative response size %d", s.ResponseSize)
	}
	if s.ResponseSize > MaxBodyBytes {
		return s, fmt.Errorf("stored result response size %d exceeds the body cap", s.ResponseSize)
	}
	if s.Truncated {
		// A truncated payload can only have been stored as StatusIncomplete,
		// which the cache never serves as a hit; reaching decode on a
		// completed record means the record was tampered with. Refuse it.
		return s, fmt.Errorf("stored result is marked truncated")
	}
	if !validFailureReason(s.FailureReason) {
		return s, fmt.Errorf("stored result has invalid failure reason %q", s.FailureReason)
	}
	switch s.FailureReason {
	case ReasonNone:
		if s.StatusCode == 0 {
			return s, fmt.Errorf("stored result is complete with no status code and no reason")
		}
	case ReasonConnRefused, ReasonTLS:
		if s.StatusCode != 0 {
			return s, fmt.Errorf("stored result has reason %s but status code %d", s.FailureReason, s.StatusCode)
		}
		if s.FailureReason == ReasonTLS && s.Scheme != "https" {
			return s, fmt.Errorf("stored result has TLS failure reason on an %s probe", s.Scheme)
		}
		if s.TLS {
			return s, fmt.Errorf("stored result has reason %s but a completed TLS handshake", s.FailureReason)
		}
	default: // failed / cancelled / redirect-cap reasons can never be stored completed
		return s, fmt.Errorf("stored result has non-completed reason %q", s.FailureReason)
	}
	// The stored TLS observation must satisfy the completed-handshake
	// consistency rules and the retention bounds (validateStoredTLS): TLS
	// metadata may only appear on a completed https probe with TLS=true,
	// every bounded field must be within its cap, and the embedded
	// certificate asset — when present — must re-validate through the Phase
	// 2 asset model. A payload failing any check refuses the whole record,
	// which the caller deletes and recomputes (never served).
	if err := validateStoredTLS(s.TLSMeta, s.Scheme, s.TLS); err != nil {
		return s, err
	}
	if err := validateStoredURL(s.FinalURL, domain, "final url"); err != nil {
		return s, err
	}
	for _, h := range s.Headers {
		if h.Key == "" || http.CanonicalHeaderKey(h.Key) != h.Key {
			return s, fmt.Errorf("stored result header %q is not in canonical form", h.Key)
		}
		if len(h.Values) == 0 {
			return s, fmt.Errorf("stored result header %q has no values", h.Key)
		}
	}
	if len(s.Headers) > MaxHeaders {
		return s, fmt.Errorf("stored result retains %d headers (cap %d)", len(s.Headers), MaxHeaders)
	}
	if len(s.Redirects) > MaxRedirects+1 {
		return s, fmt.Errorf("stored result redirect chain has %d hops (cap %d)", len(s.Redirects), MaxRedirects+1)
	}
	for i, hop := range s.Redirects {
		if hop.InScope {
			if err := validateStoredURL(hop.URL, domain, fmt.Sprintf("redirect hop %d", i)); err != nil {
				return s, err
			}
			if hop.Target != hop.URL.String() {
				return s, fmt.Errorf("stored redirect hop %d target %q does not match its URL %q", i, hop.Target, hop.URL.String())
			}
		} else {
			if hop.URL.Scheme != "" || hop.URL.HostPort != "" {
				return s, fmt.Errorf("stored out-of-scope redirect hop %d carries a typed URL", i)
			}
			if strings.TrimSpace(hop.Target) == "" {
				return s, fmt.Errorf("stored out-of-scope redirect hop %d has an empty target", i)
			}
		}
		if !hop.Followed && i != len(s.Redirects)-1 {
			return s, fmt.Errorf("stored redirect hop %d is not followed but is not the last hop", i)
		}
	}
	// The redirect chain and the final URL must agree: the final URL is the
	// last FOLLOWED URL (or the probe target when nothing was followed), and
	// a not-followed last hop means the final response is the redirect
	// response that carried it.
	expectedFinal := target
	for _, hop := range s.Redirects {
		if hop.Followed {
			expectedFinal = hop.URL
		}
	}
	if s.FinalURL.Identity() != expectedFinal.Identity() {
		return s, fmt.Errorf("stored result final url %q does not match the redirect chain (%q)", s.FinalURL.String(), expectedFinal.String())
	}
	if len(s.Redirects) > 0 && !s.Redirects[len(s.Redirects)-1].Followed && !isRedirectCode(s.StatusCode) {
		return s, fmt.Errorf("stored result has an unfollowed last hop but status %d", s.StatusCode)
	}
	// A terminal 3xx with a followed chain is a legitimate completed probe
	// exactly when the terminal response carried NO Location header: Go
	// client semantics make a 3xx without Location terminal, so the probe
	// ended on the followed hop's redirect response. Conversely, any
	// 3xx WITH a Location either gets followed (in-scope; the chain
	// continues) or is recorded as the unfollowed final hop (out-of-scope
	// or cap) — so a completed record with a redirect status, a followed
	// chain, AND a Location on the stored final response is contradictory
	// and refused. The chain/finalURL agreement check above already
	// constrains the same invariants; this rule only keeps the status field
	// honest.
	if isRedirectCode(s.StatusCode) && len(s.Redirects) > 0 && s.Redirects[len(s.Redirects)-1].Followed {
		if loc := storedLocation(s.Headers); loc != "" {
			return s, fmt.Errorf("stored result has status %d with a Location header but a followed redirect chain", s.StatusCode)
		}
	}
	return s, nil
}

// storedLocation returns the non-empty Location header value of a stored
// final response, or "" when absent. A completed record's header retention
// is complete (truncated records are stored incomplete and never decoded),
// so the absence of a Location entry is trustworthy.
func storedLocation(headers []HeaderEntry) string {
	for _, h := range headers {
		if h.Key == "Location" && len(h.Values) > 0 && strings.TrimSpace(h.Values[0]) != "" {
			return h.Values[0]
		}
	}
	return ""
}

// validateStoredURL re-validates a stored URL asset: it must be canonical
// Phase 2 form (asset.ParseURL must reproduce it exactly), non-zero, and
// inside the target domain — a stored observation must never carry a URL
// the probe could not have requested.
func validateStoredURL(u asset.URL, domain asset.Domain, what string) error {
	if u.Scheme == "" || u.HostPort == "" {
		return fmt.Errorf("stored %s is not a URL", what)
	}
	got, err := asset.ParseURL(u.String(), u.Prov)
	if err != nil {
		return fmt.Errorf("stored %s %q does not parse: %w", what, u.String(), err)
	}
	if got.String() != u.String() {
		return fmt.Errorf("stored %s %q is not in canonical form (normalized %q)", what, u.String(), got.String())
	}
	parsed, err := url.Parse(u.String())
	if err != nil {
		return fmt.Errorf("stored %s %q does not parse: %w", what, u.String(), err)
	}
	if host := canonicalScopeHost(parsed.Hostname()); host == "" || !inDomain(host, domain.Name) {
		return fmt.Errorf("stored %s %q is outside target domain %q", what, u.String(), domain.Name)
	}
	// Credential defense at decode time: asset.URL.Original preserves
	// userinfo by design, and a stored record whose Original carries
	// credentials (for example one written by a pre-redaction build of this
	// pipeline) must never be served as a hit — it is refused, deleted, and
	// recomputed by the self-healing path. Fresh records never trip this:
	// the probe redacts userinfo at the observation boundary (recordHop).
	if u.Original != "" {
		if orig, oerr := url.Parse(u.Original); oerr == nil && orig.User != nil {
			return fmt.Errorf("stored %s carries credentials in its original form", what)
		}
	}
	return nil
}

// probeStatusToCache maps a probe outcome to the Phase 3 record status,
// mirroring the Phase 4 conventions:
//
//   - completed (HTTP responses of any code, plus the legitimate negative
//     observations conn_refused / tls) -> StatusCompleted
//   - truncated capture -> StatusIncomplete (the captured observation is
//     incomplete by definition, exactly like Phase 4's truncated capture)
//   - failure -> StatusFailed
//   - cancellation -> StatusCancelled
//
// A failed, cancelled, or truncated probe is never stored as completed, so
// no later run can ever be served a partial or failed probe as success.
func probeStatusToCache(ps ProbeStatus) cache.Status {
	switch ps {
	case ProbeCompleted:
		return cache.StatusCompleted
	case ProbeFailed:
		return cache.StatusFailed
	case ProbeCancelled:
		return cache.StatusCancelled
	default: // ProbeTruncated
		return cache.StatusIncomplete
	}
}

// probeResultFromStored rebuilds a completed ProbeResult from a validated
// stored payload (always with completed semantics: only completed records
// are ever served as hits, and decodeStoredProbe guarantees the payload is
// a consistent completed observation). The probe is reported as executed —
// the observation exists, and a cached hit reproduces the typed assets and
// relationships exactly as the original run would have.
func probeResultFromStored(s storedProbe, host asset.Host, target asset.URL, scheme string) ProbeResult {
	return ProbeResult{
		Host:          host,
		URL:           target,
		Scheme:        scheme,
		Status:        ProbeCompleted,
		Cached:        true,
		Executed:      true,
		StatusCode:    s.StatusCode,
		FinalURL:      s.FinalURL,
		RedirectChain: s.Redirects,
		Headers:       s.Headers,
		ResponseSize:  s.ResponseSize,
		TLS:           s.TLS,
		TLSMeta:       s.TLSMeta,
		FailureReason: s.FailureReason,
	}
}

// lookupProbe is the cache-before-execute read side for one probe target.
// It returns the probe either served from a completed, validated, unexpired
// record (Status ProbeCompleted, Cached true), or with an empty Status to
// fall through to execution (miss, expired, incomplete, or discarded
// unusable records — any diagnosis is joined into Err), or already
// classified failed when the key cannot be built.
func lookupProbe(ctx context.Context, host asset.Host, target asset.URL, domain asset.Domain, pr ProbeResult, e env) ProbeResult {
	key, err := probeKey(target, domain)
	if err != nil {
		pr.Status = ProbeFailed
		pr.FailureReason = ReasonOther
		pr.Err = fmt.Errorf("httpprobe: %s %s: build cache key: %w", host.Name, target, err)
		return pr
	}
	out := e.cache.Get(ctx, key)
	if !out.IsHit() {
		// Miss / expired / incomplete / corrupt / schema-incompatible are
		// all "execute" outcomes; only a Get that carries a diagnosis
		// (StateError — the state payloads carry no Err) is surfaced, as a
		// warning, never as a failure: the run falls through to a fresh
		// probe.
		if out.Err != nil {
			pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: cache get: %w", host.Name, target, out.Err))
		}
		return pr
	}

	// Only a completed, unexpired record for the exact key is a hit (the
	// cache enforces that). The record's own identity fields must also match
	// the probe — a record found under this key with different operation or
	// target fields could only be tampered with — and the payload is
	// cross-checked by decodeStoredProbe. A record failing either check is
	// deleted and recomputed in this same run (self-healing), so it is never
	// served as a hit and never wedges the probe into repeated failures.
	if out.Record.Operation != Operation || out.Record.Target != target.Identity().String() {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: delete mismatched cached record: %w", host.Name, target, delerr))
		}
		pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: discarded cached record with mismatched identity %q/%q",
			host.Name, target, out.Record.Operation, out.Record.Target))
		return pr
	}
	st, derr := decodeStoredProbe(out.Record.Data, target, pr.Scheme, domain)
	if derr != nil {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: delete unusable cached record: %w", host.Name, target, delerr))
		}
		pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: discarded unusable cached result: %w", host.Name, target, derr))
		return pr
	}
	return probeResultFromStored(st, host, target, pr.Scheme)
}

// storeProbe is the cache write side: it persists the probe's terminal
// classification as a statused Phase 3 record (completed incl. the
// legitimate negative observations / failed / cancelled / incomplete-for-
// truncated), so a failed or cancelled probe is never stored as success and
// a later run can inspect the partial state. A cancelled run still persists
// its terminal record using a detached, bounded context so the write cannot
// wedge shutdown (Phase 4 convention).
func storeProbe(ctx context.Context, host asset.Host, target asset.URL, domain asset.Domain, pr ProbeResult, e env) ProbeResult {
	key, err := probeKey(target, domain)
	if err != nil {
		pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: build cache key: %w", host.Name, target, err))
		return pr
	}
	st := storedProbe{
		Target:        pr.URL.String(),
		Scheme:        pr.Scheme,
		StatusCode:    pr.StatusCode,
		FinalURL:      pr.FinalURL,
		Headers:       pr.Headers,
		ResponseSize:  pr.ResponseSize,
		TLS:           pr.TLS,
		TLSMeta:       pr.TLSMeta,
		Truncated:     pr.Truncated,
		FailureReason: pr.FailureReason,
		Redirects:     pr.RedirectChain,
	}
	data, err := json.Marshal(st)
	if err != nil {
		pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: encode result: %w", host.Name, target, err))
		return pr
	}
	rec := cache.Record{
		Operation: Operation,
		Target:    target.Identity().String(),
		Status:    probeStatusToCache(pr.Status),
		Meta:      map[string]string{"scheme": pr.Scheme},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := e.cache.Put(storeCtx, key, rec); perr != nil {
		pr.Err = errors.Join(pr.Err, fmt.Errorf("httpprobe: %s %s: cache put: %w", host.Name, target, perr))
	}
	return pr
}
