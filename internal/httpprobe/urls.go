package httpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// LiveOperation is the cache operation for URL liveness triage.

const (
	// liveRequestTimeoutDefault is the per-URL deadline for ProbeURLs when
	// the caller leaves RequestTimeout unset: triage semantics favor
	// coverage over patience (a dead host costs 5 s, not the 10 s host-probe
	// default). Explicit Config values always win.
	liveRequestTimeoutDefault = 5 * time.Second
	// liveConcurrencyDefault widens the probe pool for large URL corpora
	// when the caller leaves Concurrency unset.
	liveConcurrencyDefault = 20
)
const LiveOperation = "urllive.probe"

// LiveRecord is the liveness observation for one URL. It is the Results
// channel entity for the urllive stage — not a field on asset.URL (avoids a
// schema bump per OPTIMIZATION.md:115). The URL is the canonical Phase 2
// identity; Status is the HTTP status code (0 when no HTTP response was
// received); Headers are the bounded final response headers; RedirectObserved
// with RedirectLocation captures a 3xx Location without following it (M-6
// consistency jsintel/fetch.go:448); TLS is the leaf certificate when an
// https probe completed a handshake (nil for http or no handshake); Err
// carries the transport error for timeout/refused/tls-handshake failures;
// Truncated marks a header-cap hit.
type LiveRecord struct {
	URL asset.URL `json:"url"`
	// Status is the HTTP status code; 0 when no response was received.
	Status int `json:"status"`
	// Headers are the bounded final response headers (sorted, entry-capped).
	Headers http.Header `json:"headers,omitempty"`
	// RedirectObserved reports that the final response was a redirect with a
	// Location header. The hop was observed, never followed.
	RedirectObserved bool `json:"redirect_observed,omitempty"`
	// RedirectLocation is the observed Location value (userinfo stripped,
	// control bytes stripped) when RedirectObserved is true.
	RedirectLocation string `json:"redirect_location,omitempty"`
	// TLS is the leaf certificate observed on a completed https handshake.
	// Nil for http, for a failed handshake, or when no handshake completed.
	TLS *asset.TLSCertificate `json:"tls,omitempty"`
	// TLSMeta is the full TLS metadata observation (ALPN, issuer, subject,
	// DNS names) when a handshake completed. It is kept for cache
	// persistence and for callers that need richer data than the leaf
	// certificate alone. JSON serialized but not part of the public
	// identity.
	TLSMeta *TLSMetadata `json:"tls_meta,omitempty"`
	// Err carries the transport error for failed probes (timeout, refused,
	// dns, tls handshake tagging, header-cap abort). Nil for probes that
	// received an HTTP response.
	Err error `json:"-"`
	// ErrMsg is the serialized form of Err (for cache persistence).
	ErrMsg string `json:"error,omitempty"`
	// Truncated marks a probe that hit a hard cap (header block or entry cap).
	Truncated bool `json:"truncated,omitempty"`
	// Cached reports that the record was served from a validated cache hit.
	Cached bool `json:"-"`
}

// MarshalJSON implements custom marshaling to serialize Err as a string.
func (r LiveRecord) MarshalJSON() ([]byte, error) {
	type alias LiveRecord
	a := struct {
		alias
		Error string `json:"error,omitempty"`
	}{
		alias: alias(r),
	}
	if r.Err != nil {
		a.Error = r.Err.Error()
	}
	// Ensure ErrMsg is honored when Err is nil but ErrMsg is set (store path).
	if r.Err == nil && r.ErrMsg != "" {
		a.Error = r.ErrMsg
	}
	// Hide the raw Err field (json:"-") and ErrMsg duplicate.
	a.alias.Err = nil
	a.alias.ErrMsg = ""
	return json.Marshal(a)
}

// UnmarshalJSON implements custom unmarshaling to restore Err from string.
func (r *LiveRecord) UnmarshalJSON(data []byte) error {
	type alias LiveRecord
	aux := struct {
		alias
		Error string `json:"error,omitempty"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*r = LiveRecord(aux.alias)
	if aux.Error != "" {
		r.Err = errors.New(aux.Error)
		r.ErrMsg = aux.Error
	}
	return nil
}

// LiveReport is the complete outcome of a ProbeURLs run.
type LiveReport struct {
	Target  asset.Domain `json:"target"`
	Records []LiveRecord `json:"records"`
}

// ProbeURLs probes the liveness of the given URLs within the declared target
// domain. For each URL it performs a single GET with headers/status only,
// observes (never follows) redirects, captures TLS metadata via the existing
// DialTLSContext sentinel, and enforces per-URL timeouts via
// context.WithTimeout. The results are sorted deterministically by canonical URL
// string. The pool Concurrency/QueueSize/Burst and the central rate limiter
// (Rate/Burst) bound the run; no unbounded goroutine per URL is created.
// Cache-before-execute is composed around each URL when cfg.Cache is non-nil
// (operation urllive.probe, keyed by canonical URL identity and declared
// domain).
func ProbeURLs(ctx context.Context, domain asset.Domain, urls []asset.URL, cfg Config) (LiveReport, error) {
	if ctx == nil {
		return LiveReport{}, fmt.Errorf("httpprobe: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return LiveReport{}, fmt.Errorf("httpprobe: %w", err)
	}
	if err := validateScope(domain); err != nil {
		return LiveReport{}, err
	}
	norm, err := normalizeInputURLs(urls, domain)
	if err != nil {
		return LiveReport{}, err
	}
	if len(norm) == 0 {
		return LiveReport{Target: domain}, nil
	}
	// Triage defaults: ProbeURLs is a liveness triage pass over potentially
	// thousands of URLs, not a deep host probe. When the caller leaves the
	// knobs unset, use a shorter per-URL deadline and a wider pool than the
	// host-probe defaults so a large corpus fits inside a shared stage
	// budget (field trial 3: 8,254 URLs — 10 s per dead host starved the
	// stage deadline). Explicit caller values always win.
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
		return LiveReport{}, err
	}
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        0,
		Burst:       0,
	})
	if err != nil {
		return LiveReport{}, fmt.Errorf("httpprobe: create worker pool: %w", err)
	}
	results := make([]LiveRecord, len(norm))
	for i, u := range norm {
		// Pre-initialize as cancelled so a dropped job keeps an honest
		// cancelled status (mirrors Probe's HostResult initialization).
		results[i] = LiveRecord{URL: u, Err: context.Canceled, Truncated: false}
	}
	for i, u := range norm {
		i := i
		u := u
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			results[i] = probeOneURL(jctx, u, domain, e)
			return nil, nil
		}}); err != nil {
			results[i] = LiveRecord{URL: u, Err: fmt.Errorf("httpprobe: submit %s: %w", u.String(), err)}
			for j := i + 1; j < len(norm); j++ {
				results[j] = LiveRecord{URL: norm[j], Err: fmt.Errorf("httpprobe: not submitted: %w", ctx.Err())}
			}
			break
		}
	}
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()
	// Sort deterministically by canonical URL string regardless of pool order.
	sort.Slice(results, func(i, j int) bool { return results[i].URL.String() < results[j].URL.String() })
	report := LiveReport{Target: domain, Records: results}
	if shutdownErr != nil {
		return report, fmt.Errorf("httpprobe: pool shutdown: %w", shutdownErr)
	}
	return report, nil
}

// normalizeInputURLs validates, deduplicates, and sorts the input URL list.
func normalizeInputURLs(urls []asset.URL, domain asset.Domain) ([]asset.URL, error) {
	seen := make(map[asset.Identity]bool, len(urls))
	out := make([]asset.URL, 0, len(urls))
	for _, u := range urls {
		if u.IsZero() {
			return nil, fmt.Errorf("httpprobe: url is zero")
		}
		reparsed, err := asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			return nil, fmt.Errorf("httpprobe: invalid url %q: %w", u.String(), err)
		}
		if reparsed.Identity() != u.Identity() {
			return nil, fmt.Errorf("httpprobe: url %q is not in canonical form (normalized %q)", u.String(), reparsed.String())
		}
		parsed, err := url.Parse(u.String())
		if err != nil {
			return nil, fmt.Errorf("httpprobe: invalid url %q: %w", u.String(), err)
		}
		host := canonicalScopeHost(parsed.Hostname())
		if host == "" || !inDomain(host, domain.Name) {
			return nil, fmt.Errorf("httpprobe: url %q is outside target domain %q", u.String(), domain.Name)
		}
		if seen[u.Identity()] {
			continue
		}
		seen[u.Identity()] = true
		// Normalize provenance through asset model.
		nu, err := asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			return nil, fmt.Errorf("httpprobe: invalid url %q: %w", u.String(), err)
		}
		out = append(out, nu)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// probeOneURL probes one URL with cache-before-execute semantics.
func probeOneURL(ctx context.Context, target asset.URL, domain asset.Domain, e env) LiveRecord {
	rec := LiveRecord{URL: target}
	if e.cache != nil {
		if hit, ok := lookupLive(ctx, target, domain, e); ok {
			return hit
		}
	}
	if ctx.Err() != nil {
		rec.Err = ctx.Err()
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	rec = doLiveProbe(ctx, target, domain, e, rec)
	if e.cache != nil {
		rec = storeLive(ctx, target, domain, rec, e)
	}
	return rec
}

// doLiveProbe executes one bounded live probe: a GET that never follows
// redirects, with bounded header retention and typed failure classification.
// Every outbound request waits on the central limiter first.
func doLiveProbe(ctx context.Context, target asset.URL, domain asset.Domain, e env, rec LiveRecord) LiveRecord {
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
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		rec.Err = fmt.Errorf("httpprobe: build request for %s: %w", target, err)
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		st, _ := classifyProbeError(reqCtx, err)
		rec.Truncated = st == ProbeTruncated
		rec.Err = err
		rec.ErrMsg = err.Error()
		return rec
	}
	// Success: capture bounded headers, status, redirect observation, TLS.
	statusCode := resp.StatusCode
	headers, hdrTrunc := boundedHeaders(resp.Header)
	hdrMap := make(http.Header, len(headers))
	for _, he := range headers {
		hdrMap[he.Key] = he.Values
	}
	rec.Status = statusCode
	rec.Headers = hdrMap
	if isRedirectCode(statusCode) && resp.Header.Get("Location") != "" {
		rec.RedirectObserved = true
		// Location header already redacted in boundedHeaders, but also ensure
		// userinfo stripped for direct observation.
		loc := resp.Header.Get("Location")
		// boundedHeaders redacts Location values; use the redacted form from hdrMap
		if vals := hdrMap["Location"]; len(vals) > 0 && vals[0] != "" {
			rec.RedirectLocation = vals[0]
		} else {
			rec.RedirectLocation = stripLocationUserinfo(loc)
		}
	}
	// TLS metadata capture for https probes that completed a handshake.
	if target.Scheme == "https" && resp.TLS != nil {
		meta, cerr := captureTLS(resp.TLS, e.clock)
		if meta != nil {
			rec.TLSMeta = meta
			if meta.Certificate.Fingerprint != "" {
				c := meta.Certificate
				rec.TLS = &c
			}
		}
		if cerr != nil {
			rec.Err = errors.Join(rec.Err, cerr)
			if rec.Err != nil {
				rec.ErrMsg = rec.Err.Error()
			}
		}
	}
	rec.Truncated = hdrTrunc
	if hdrTrunc {
		rec.Err = errors.Join(rec.Err, fmt.Errorf("httpprobe: headers truncated"))
		if rec.Err != nil {
			rec.ErrMsg = rec.Err.Error()
		}
	}
	// Body handling: MaxBody 0 — drain and close without retention.
	// Ensure body is closed to reuse connections (even though keep-alives
	// are disabled in tests, production transport may keep them).
	_ = resp.Body.Close()
	return rec
}

// liveKey derives the cache key for one live URL.
func liveKey(target asset.URL, domain asset.Domain) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: LiveOperation,
		Target:    target.Identity().String(),
		Config:    map[string]string{"domain": domain.Name},
	})
}

// storedLive is the persisted payload for one live record.
type storedLive struct {
	Target           string        `json:"target"`
	StatusCode       int           `json:"status_code"`
	Headers          []HeaderEntry `json:"headers,omitempty"`
	RedirectObserved bool          `json:"redirect_observed,omitempty"`
	RedirectLocation string        `json:"redirect_location,omitempty"`
	TLSMeta          *TLSMetadata  `json:"tls_meta,omitempty"`
	Truncated        bool          `json:"truncated,omitempty"`
	FailureReason    FailureReason `json:"failure_reason,omitempty"`
	ErrMsg           string        `json:"error,omitempty"`
}

// decodeStoredLive validates a stored payload before serving it as a hit.
func decodeStoredLive(raw json.RawMessage, target asset.URL, domain asset.Domain) (storedLive, error) {
	var s storedLive
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored live result: %w", err)
	}
	if s.Target != target.String() {
		return s, fmt.Errorf("stored live target %q does not match %q", s.Target, target.String())
	}
	if s.StatusCode < 0 || s.StatusCode > 599 {
		return s, fmt.Errorf("stored live has invalid status code %d", s.StatusCode)
	}
	if s.Truncated {
		return s, fmt.Errorf("stored live is marked truncated")
	}
	if !validFailureReason(s.FailureReason) && s.FailureReason != "" {
		return s, fmt.Errorf("stored live has invalid failure reason %q", s.FailureReason)
	}
	if s.TLSMeta != nil {
		if err := validateStoredTLS(s.TLSMeta, target.Scheme, true); err != nil {
			return s, err
		}
		// Also validate that TLSMeta itself is well-formed; the helper checks
		// scheme/tls consistency. For stored live, we stored with tls=true
		// only when handshake completed, but we persist even when handshake
		// didn't? We treat same as probe: tls true only on https.
	}
	for _, h := range s.Headers {
		if h.Key == "" || http.CanonicalHeaderKey(h.Key) != h.Key {
			return s, fmt.Errorf("stored live header %q is not canonical", h.Key)
		}
		if len(h.Values) == 0 {
			return s, fmt.Errorf("stored live header %q has no values", h.Key)
		}
	}
	if len(s.Headers) > MaxHeaders {
		return s, fmt.Errorf("stored live retains %d headers (cap %d)", len(s.Headers), MaxHeaders)
	}
	// RedirectLocation validation: if observed, location must be non-empty
	// and have userinfo stripped (best-effort). We do not re-validate URL
	// parsing because out-of-scope locations are stored as display strings.
	if s.RedirectObserved && s.RedirectLocation == "" {
		return s, fmt.Errorf("stored live redirect observed but location empty")
	}
	if !s.RedirectObserved && s.RedirectLocation != "" {
		return s, fmt.Errorf("stored live redirect location without observed flag")
	}
	// Credential self-heal for redirect locations: pre-redaction cached
	// records could carry https://user:pass@host. The probe redacts at the
	// observation boundary (stripLocationUserinfo), so a stored location
	// that still carries userinfo must be refused and recomputed. Host
	// cache does the same via validateStoredURL's Original check; the live
	// cache's RedirectLocation is the string counterpart.
	if s.RedirectLocation != "" && strings.Contains(s.RedirectLocation, "@") {
		if u, err := url.Parse(s.RedirectLocation); err == nil && u.User != nil {
			return s, fmt.Errorf("stored live redirect location carries credentials")
		}
		if stripLocationUserinfo(s.RedirectLocation) != s.RedirectLocation {
			return s, fmt.Errorf("stored live redirect location carries credentials")
		}
	}
	return s, nil
}

// liveRecordFromStored rebuilds a LiveRecord from a validated stored payload.
func liveRecordFromStored(s storedLive, target asset.URL) LiveRecord {
	hdrMap := make(http.Header, len(s.Headers))
	for _, he := range s.Headers {
		hdrMap[he.Key] = he.Values
	}
	rec := LiveRecord{
		URL:              target,
		Status:           s.StatusCode,
		Headers:          hdrMap,
		RedirectObserved: s.RedirectObserved,
		RedirectLocation: s.RedirectLocation,
		Truncated:        false,
		Cached:           true,
	}
	if s.TLSMeta != nil {
		rec.TLSMeta = s.TLSMeta
		if s.TLSMeta.Certificate.Fingerprint != "" {
			c := s.TLSMeta.Certificate
			rec.TLS = &c
		}
	}
	if s.ErrMsg != "" {
		rec.Err = errors.New(s.ErrMsg)
		rec.ErrMsg = s.ErrMsg
	}
	return rec
}

// lookupLive is the cache-before-execute read side for one live URL.
func lookupLive(ctx context.Context, target asset.URL, domain asset.Domain, e env) (LiveRecord, bool) {
	key, err := liveKey(target, domain)
	if err != nil {
		return LiveRecord{URL: target, Err: fmt.Errorf("httpprobe: build cache key: %w", err)}, false
	}
	out := e.cache.Get(ctx, key)
	if !out.IsHit() {
		return LiveRecord{}, false
	}
	if out.Record.Operation != LiveOperation || out.Record.Target != target.Identity().String() {
		_ = e.cache.Delete(ctx, key)
		return LiveRecord{}, false
	}
	st, derr := decodeStoredLive(out.Record.Data, target, domain)
	if derr != nil {
		_ = e.cache.Delete(ctx, key)
		return LiveRecord{}, false
	}
	return liveRecordFromStored(st, target), true
}

// storeLive is the cache write side for one live URL.
func storeLive(ctx context.Context, target asset.URL, domain asset.Domain, rec LiveRecord, e env) LiveRecord {
	key, err := liveKey(target, domain)
	if err != nil {
		rec.Err = errors.Join(rec.Err, fmt.Errorf("httpprobe: build cache key for %s: %w", target.String(), err))
		if rec.Err != nil {
			rec.ErrMsg = rec.Err.Error()
		}
		return rec
	}
	// Convert Headers http.Header to []HeaderEntry for storage.
	var headers []HeaderEntry
	if len(rec.Headers) > 0 {
		// Use boundedHeaders to ensure sorting and canonical form? But rec.Headers
		// already came from boundedHeaders, so just convert.
		keys := make([]string, 0, len(rec.Headers))
		for k := range rec.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			headers = append(headers, HeaderEntry{Key: k, Values: rec.Headers[k]})
		}
	}
	st := storedLive{
		Target:           target.String(),
		StatusCode:       rec.Status,
		Headers:          headers,
		RedirectObserved: rec.RedirectObserved,
		RedirectLocation: rec.RedirectLocation,
		TLSMeta:          rec.TLSMeta,
		Truncated:        rec.Truncated,
		ErrMsg:           rec.ErrMsg,
	}
	// FailureReason is derived for validation purposes: map Err to reason.
	if rec.Err != nil {
		// Use classifyProbeError to derive reason if possible.
		_, fr := classifyProbeError(ctx, rec.Err)
		// For truncated, reason is none; for others, use derived.
		if rec.Truncated {
			st.FailureReason = ReasonNone
		} else {
			st.FailureReason = fr
		}
	}
	data, err := json.Marshal(st)
	if err != nil {
		rec.Err = errors.Join(rec.Err, fmt.Errorf("httpprobe: encode live result: %w", err))
		if rec.Err != nil {
			rec.ErrMsg = rec.Err.Error()
		}
		return rec
	}
	status := liveStatusToCache(rec)
	recCache := cache.Record{
		Operation: LiveOperation,
		Target:    target.Identity().String(),
		Status:    status,
		Meta:      map[string]string{"scheme": target.Scheme},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := e.cache.Put(storeCtx, key, recCache); perr != nil {
		rec.Err = errors.Join(rec.Err, fmt.Errorf("httpprobe: cache put: %w", perr))
		if rec.Err != nil {
			rec.ErrMsg = rec.Err.Error()
		}
	}
	return rec
}

func liveStatusToCache(rec LiveRecord) cache.Status {
	if rec.Truncated {
		return cache.StatusIncomplete
	}
	if rec.Err != nil {
		if errors.Is(rec.Err, context.Canceled) {
			return cache.StatusCancelled
		}
		if errors.Is(rec.Err, context.DeadlineExceeded) {
			return cache.StatusFailed
		}
		var dnsErr *net.DNSError
		if errors.As(rec.Err, &dnsErr) {
			if dnsErr.IsTimeout {
				return cache.StatusFailed
			}
			return cache.StatusFailed
		}
		var netErr net.Error
		if errors.As(rec.Err, &netErr) && netErr.Timeout() {
			return cache.StatusFailed
		}
		if errors.Is(rec.Err, syscall.ECONNREFUSED) {
			return cache.StatusCompleted
		}
		if isTLSError(rec.Err) {
			return cache.StatusCompleted
		}
		if isHeaderCapAbort(rec.Err) {
			return cache.StatusIncomplete
		}
		return cache.StatusFailed
	}
	return cache.StatusCompleted
}

// AllLiveRecords merges live records across a report (deduplicated by URL identity).
func (r LiveReport) AllLiveRecords() []LiveRecord {
	byID := make(map[asset.Identity]int)
	var out []LiveRecord
	for _, rec := range r.Records {
		if idx, ok := byID[rec.URL.Identity()]; ok {
			// Merge? Keep first-seen.
			_ = idx
			continue
		}
		byID[rec.URL.Identity()] = len(out)
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL.String() < out[j].URL.String() })
	return out
}
