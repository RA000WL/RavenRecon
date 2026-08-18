// Package-level documentation lives in doc.go.
package jsintel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/version"
)

// FetchOperation is the stable cache operation name for the JS fetch
// pipeline. It is part of the Phase 3 cache key payload; changing it
// invalidates every previously stored fetch record by construction.
const FetchOperation = "js.fetch"

// Fixed fetch caps. These are constants, deliberately NOT configuration:
// they bound what the pipeline retains, so a hostile or misbehaving server
// can never grow memory or cache records without bound. The redirect cap and
// the header-block cap never enter cache keys; the content cap is
// configurable (FetchConfig.MaxJSBytes) but is clamped to a fixed window and
// never enters a cache key either (see fetchKey in record_fetch.go).
const (
	// MaxRedirects bounds how many redirect hops one fetch attempt follows
	// (GET semantics, Location resolved against the current URL). A
	// redirect beyond the cap is observed but never requested: the walk
	// stops and the terminal 3xx response IS the final observation
	// (completed, Redirects == MaxRedirects). A redirect to a NON-http(s)
	// scheme is likewise observed but never requested (see
	// resolveRedirect). The redirect cap is NOT a content truncation: the
	// terminal 3xx record is a complete observation of the chain prefix
	// and is stored completed.
	MaxRedirects = 5

	// MaxHeaderBytes bounds the size of one response's header block. The
	// production transport enforces it via http.Transport's
	// MaxResponseHeaderBytes; a server that exceeds it aborts the response
	// and the attempt is classified failed/other (and therefore retried).
	MaxHeaderBytes = 64 << 10 // 64 KiB
)

// requestTimeoutDefault is the per-attempt deadline applied around every
// fetch attempt when FetchConfig.RequestTimeout is zero (slowloris
// protection). The deadline covers the whole attempt: every request in the
// redirect walk and the terminal body read. The engine clamps it to the
// caller's job deadline later, so the budget chain request ⊆ job always
// holds (this layer has no job deadline to clamp against).
const requestTimeoutDefault = 10 * time.Second

// Content retention bounds. FetchConfig.MaxJSBytes is clamped to this window
// at validation: below the minimum it is raised, above the maximum it is
// lowered. maxMaxJSBytes also bounds what a stored record may carry
// (maxStoredContent in record_fetch.go is the same value, re-checked at
// decode as defense).
const (
	defaultMaxJSBytes = 2 << 20 // 2 MiB
	minMaxJSBytes     = 64 << 10
	maxMaxJSBytes     = 8 << 20
	defaultRetries    = 1 // zero in FetchConfig means this default
	maxRetries        = 3
)

// Bounded captured-header limits: response header values are sanitized to
// printable ASCII and truncated to these caps at capture time, so a captured
// value always passes the stored-record decode validation (printable ASCII,
// same caps) and a record we store can never be rejected by our own decode.
const (
	maxContentTypeBytes = 128
	maxETagBytes        = 256
	maxSourceMapBytes   = 4096
)

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a terminal completed record). Cache
// writes are small atomic files; this budget only exists so a cancelled run
// cannot wedge shutdown on a pathological filesystem. Mirrors the Phase 4
// convention.
const storeTimeout = 5 * time.Second

// userAgent identifies RavenRecon's fetches to the serving server. It
// mirrors the httpprobe pipeline's user agent exactly, so both pipelines
// present the same identity to the probed server.
var userAgent = "RavenRecon/" + version.Version

// provenanceSource is the discovery source attached to URLs derived from
// redirect Locations.
const provenanceSource = "js-fetch"

// wallClock is the production runtime.Clock backed by the wall clock,
// mirroring the runtime package's own production clock (which is
// unexported) and the httpprobe convention.
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// FetchStatus classifies one fetch outcome. The values are the same strings
// the cache layer stores (record_fetch.go), so a stored status round-trips
// unchanged.
type FetchStatus string

const (
	// FetchCompleted marks a response observed (any HTTP status, including
	// the completed-negative observations conn_refused and tls) with the
	// full body retained, or a completed negative. Cacheable.
	FetchCompleted FetchStatus = "completed"
	// FetchFailed marks an attempt that errored before a response (timeout,
	// DNS, transport failure). Never cached; retried per FetchConfig.
	FetchFailed FetchStatus = "failed"
	// FetchCancelled marks work interrupted by context cancellation before
	// completion. Never cached, never retried.
	FetchCancelled FetchStatus = "cancelled"
	// FetchTruncated marks a response observed whose content could not be
	// fully retained (content cap hit, or a read failure mid-body). The
	// retained content is deliberately nil. Stored incomplete — never
	// served as a cache hit; a later run re-fetches.
	FetchTruncated FetchStatus = "incomplete"
)

// FetchReason is the fine-grained cause of a non-completed fetch or of a
// completed negative observation. It is part of the stored record and of
// FetchResult.
type FetchReason string

const (
	ReasonNone        FetchReason = ""
	ReasonConnRefused FetchReason = "conn_refused" // completed negative: service absent on the port
	ReasonTimeout     FetchReason = "timeout"      // failed: a deadline or net-level timeout fired
	ReasonDNS         FetchReason = "dns"          // failed: the dial could not resolve the hostname
	ReasonTLS         FetchReason = "tls"          // completed negative: TLS handshake failed (https not served)
	ReasonOther       FetchReason = "other"        // failed: anything else
)

// FetchResult is the complete observation of one fetch operation. It is the
// pipeline's internal currency: the cache layer (record_fetch.go) persists
// completed observations as records and restores byte-identical results on a
// hit, and the later analysis passes consume it.
type FetchResult struct {
	// URL is the requested canonical URL — the fetch's identity.
	URL asset.URL
	// FinalURL is the last URL targeted by a request: the requested URL
	// when no redirect was followed, the last followed hop's URL otherwise.
	// Zero only when no request was ever dispatched (cancelled before
	// dispatch, or a configuration failure).
	FinalURL asset.URL
	// StatusCode is the final response's status; 0 for negative
	// observations (conn_refused, tls, failed, cancelled).
	StatusCode int
	// ContentType is the final Content-Type header (trimmed, printable
	// ASCII, at most 128 bytes).
	ContentType string
	// ETag is the final ETag header (at most 256 bytes).
	ETag string
	// LastModified is the final Last-Modified header parsed with the HTTP
	// date format; zero when absent or unparseable.
	LastModified time.Time
	// XSourceMap is the X-SourceMap header (at most 4096 bytes).
	XSourceMap string
	// ContentLength is the server-declared Content-Length of the final
	// response; -1 when unknown (for example when the transport
	// decompressed a gzip body).
	ContentLength int64
	// Size is the retained content size in bytes; 0 when nothing was
	// retained (empty body, truncated, or negative observation).
	Size int64
	// Hash is the lowercase hex SHA-256 of Content; empty when Size is 0 or
	// the fetch is truncated.
	Hash string
	// Content is the retained body bytes, bounded by MaxJSBytes; nil when
	// no body was retained (empty body, truncated, or negative
	// observation). A truncated fetch NEVER retains a partial prefix: the
	// honest record has no content at all (see doc.go).
	Content []byte
	// Truncated reports that the content could not be fully retained
	// (content cap hit, or a read failure mid-body). Never true together
	// with non-nil Content.
	Truncated bool
	// Redirects is the number of redirect hops FOLLOWED. An observed but
	// un-followed redirect (the cap-exceeding hop, an unparseable
	// Location, or a non-http(s) target) ends the walk with the redirect
	// response itself as the final observation and is not counted here.
	Redirects int
	// Status classifies the outcome (see FetchStatus).
	Status FetchStatus
	// Reason is the fine-grained cause (see FetchReason). Completed
	// positive observations carry ReasonNone.
	Reason FetchReason
	// Err carries the underlying error for failed/cancelled fetches, and a
	// body-read diagnostic for truncated fetches. Nil for completed
	// observations with fully retained content.
	Err error
}

// FetchConfig configures one fetch operation.
type FetchConfig struct {
	// Transport performs the HTTP round trips. Nil means a bounded
	// production transport: a clone of http.DefaultTransport with
	// MaxResponseHeaderBytes set to MaxHeaderBytes, a 30 s
	// response-header timeout, proxy support disabled (fetches always go
	// direct; a stray environment proxy must never silently reroute a
	// recon run), and transparent gzip decompression ENABLED
	// (DisableCompression false) — the stored content is the DECOMPRESSED
	// bytes the transport hands over.
	//
	// An injected transport is used exactly as given — the caller owns its
	// timeouts and header caps. Tests inject hermetic loopback transports.
	Transport http.RoundTripper

	// RequestTimeout is the per-attempt deadline: it covers the whole
	// attempt, every request in the redirect walk and the terminal body
	// read (slowloris protection). Zero means the 10 s default. The engine
	// clamps it to the caller's job deadline later so the budget chain
	// request ⊆ job always holds. A timeout is a failed attempt and is
	// retried like any other failure.
	RequestTimeout time.Duration

	// MaxJSBytes is the retained-content cap. Zero means the 2 MiB
	// default; validation clamps to [64 KiB, 8 MiB]. A response whose
	// content exceeds the cap is truncated: nothing is retained, and the
	// observation is stored incomplete (never served as a hit). Cap
	// changes NEVER invalidate cache entries — the key does not contain
	// the cap (see fetchKey); a lowered cap simply means the re-fetch path
	// truncates again.
	MaxJSBytes int64

	// Retries is the number of IMMEDIATE retries (no sleep, deterministic)
	// for attempts classified failed (timeout, dns, other — any failed
	// reason). Completed observations — including the completed negatives
	// conn_refused and tls — and cancelled attempts are never retried. A
	// failed attempt is not retried once the caller's context is done.
	// Zero means the default (1); values above 3 are clamped to 3.
	Retries int

	// Limiter is the central outbound-dispatch limiter. Every dispatched
	// request — the initial request and each followed redirect hop — waits
	// for a token before dispatch. Nil disables pacing. The cache-before-
	// execute order (lookup first, limiter wait only on a miss) is the
	// CALLER's concern; inside Fetch every attempt starts with a token
	// wait.
	Limiter *runtime.Limiter

	// Clock is the time source for provenance timestamps of URLs derived
	// from redirect Locations. Nil means the wall clock.
	Clock runtime.Clock
}

// validated applies defaults and clamps, rejecting negatives. The result is
// the FetchConfig every fetch attempt actually honors. Negative values are
// configuration errors; small positive values are clamped into the fixed
// windows (caps clamp, negatives reject).
func (c FetchConfig) validated() (FetchConfig, error) {
	if c.RequestTimeout < 0 {
		return c, fmt.Errorf("jsintel: request timeout must not be negative")
	}
	if c.MaxJSBytes < 0 {
		return c, fmt.Errorf("jsintel: max js bytes must not be negative")
	}
	if c.Retries < 0 {
		return c, fmt.Errorf("jsintel: retries must not be negative")
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = requestTimeoutDefault
	}
	if c.MaxJSBytes == 0 {
		c.MaxJSBytes = defaultMaxJSBytes
	}
	if c.MaxJSBytes < minMaxJSBytes {
		c.MaxJSBytes = minMaxJSBytes
	}
	if c.MaxJSBytes > maxMaxJSBytes {
		c.MaxJSBytes = maxMaxJSBytes
	}
	if c.Retries == 0 {
		c.Retries = defaultRetries
	}
	if c.Retries > maxRetries {
		c.Retries = maxRetries
	}
	return c, nil
}

// Fetch performs one bounded fetch of the canonical URL u: a GET with no
// body, a fixed RavenRecon user agent, and no cookies or custom headers,
// built from the canonical asset URL form (userinfo and fragment never reach
// the wire). It follows up to MaxRedirects redirects — cross-host http(s)
// redirects included, since jsintel has no declared-scope concept — but a
// redirect to a NON-http(s) scheme is observed, never requested: the walk
// ends with the redirect response as the final observation. It streams the
// terminal body under the MaxJSBytes content cap (truncating honestly,
// never retaining a partial prefix), and classifies every outcome with a
// typed FetchStatus and FetchReason.
//
// Retries are immediate and deterministic: an attempt classified failed
// (any failed reason) is retried up to cfg.Retries times while the caller's
// context stays alive; completed observations (including the completed
// negatives conn_refused and tls) and cancelled attempts are never retried.
// Every dispatched request — the initial request and each redirect hop —
// waits on the central limiter first.
//
// Fetch is safe for concurrent use: it keeps no shared state. It never
// panics; every failure is reported through FetchResult.
func Fetch(ctx context.Context, cfg FetchConfig, u asset.URL) FetchResult {
	if ctx == nil {
		return FetchResult{Status: FetchFailed, Reason: ReasonOther,
			Err: fmt.Errorf("jsintel: fetch: context must not be nil")}
	}
	vcfg, err := cfg.validated()
	if err != nil {
		return FetchResult{URL: u, Status: FetchFailed, Reason: ReasonOther,
			Err: fmt.Errorf("jsintel: fetch %s: invalid config: %w", u.String(), err)}
	}
	if vcfg.Transport == nil {
		vcfg.Transport = newTransport()
	}
	if vcfg.Clock == nil {
		vcfg.Clock = wallClock{}
	}

	// The retry loop: each iteration is one full attempt (token wait,
	// request, redirect walk, terminal read). Failed attempts are retried
	// immediately; the loop stops on any other outcome, or once the
	// caller's context is done (a retry could only fail again), or after
	// cfg.Retries retries.
	var last FetchResult
	for attempt := 0; ; attempt++ {
		res := attemptFetch(ctx, u, vcfg)
		if res.Status != FetchFailed || ctx.Err() != nil {
			return res
		}
		last = res
		if attempt >= vcfg.Retries {
			return last
		}
	}
}

// attemptFetch is one full fetch attempt. It performs the limiter wait, the
// request, and the redirect walk, and returns the classified observation.
func attemptFetch(ctx context.Context, u asset.URL, cfg FetchConfig) FetchResult {
	if err := ctx.Err(); err != nil {
		// Cancelled before dispatch: the request was never built, so no
		// URL was targeted (FinalURL stays zero).
		return FetchResult{URL: u, Status: FetchCancelled, Reason: ReasonOther, Err: err}
	}
	// The per-attempt deadline covers the whole attempt — every request in
	// the redirect walk and the terminal body read: cancelling the request
	// context before the body is fully read aborts the read, so the
	// deadline context must outlive the body read. The deferred cancel
	// fires when the attempt ends; at most Retries+1 such contexts can be
	// pending, each firing at its own deadline or at attemptFetch's return
	// — bounded, no leak.
	reqCtx := ctx
	var cancel context.CancelFunc
	if cfg.RequestTimeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, cfg.RequestTimeout)
		defer cancel()
	}

	cur := u
	hops := 0
	for {
		// Token wait before EVERY dispatch: the initial request and each
		// followed redirect hop. The wait runs on ctx — the JOB context,
		// bounded by the job deadline that owns the whole attempt — NOT on
		// reqCtx, so a stalled limiter can hold a dispatch beyond
		// RequestTimeout and only the job deadline bounds it. This is
		// deliberate: the limiter is the pipeline's central pace, and the
		// per-attempt deadline still covers everything after the token is
		// granted (the request itself and the body read).
		if cfg.Limiter != nil {
			if werr := cfg.Limiter.Wait(ctx); werr != nil {
				st, reason := classifyContextError(werr)
				return FetchResult{URL: u, FinalURL: cur, Redirects: hops, Status: st, Reason: reason,
					Err: fmt.Errorf("jsintel: fetch %s: limiter wait: %w", u.String(), werr)}
			}
		}

		// finalURL is the URL targeted by this dispatch: assign it before
		// the round trip so a failed request still records the URL it
		// targeted, and a completed negative (conn_refused / tls) carries
		// the targeted URL as its final URL — required for stored
		// completed observations to be re-validated and served as cache
		// hits.
		finalURL := cur
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, cur.String(), nil)
		if err != nil {
			// A canonical asset URL always builds; keep the defensive path.
			return FetchResult{URL: u, FinalURL: finalURL, Redirects: hops, Status: FetchFailed, Reason: ReasonOther,
				Err: fmt.Errorf("jsintel: fetch %s: build request: %w", u.String(), err)}
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := cfg.Transport.RoundTrip(req)
		if err != nil {
			st, reason := classifyFetchError(ctx, err)
			return FetchResult{URL: u, FinalURL: finalURL, Redirects: hops, Status: st, Reason: reason, Err: err}
		}

		if isRedirectCode(resp.StatusCode) && resp.Header.Get("Location") != "" && hops < MaxRedirects {
			next, ok := resolveRedirect(resp, cfg.Clock)
			if !ok {
				// An unparseable Location — or a Location whose target is
				// NOT http(s) — ends the walk: the redirect response
				// itself is the final observation (completed, FinalURL =
				// the URL it was received from), observed but never
				// followed.
				return readTerminal(u, cur, resp, hops, cfg)
			}
			// Intermediate redirect bodies are never read — only closed.
			resp.Body.Close()
			cur = next
			hops++
			continue
		}
		// Terminal response: any non-redirect status, a redirect without a
		// Location header, or the cap-exceeding redirect (hops ==
		// MaxRedirects): the response IS the final observation.
		return readTerminal(u, cur, resp, hops, cfg)
	}
}

// resolveRedirect resolves a response's Location against the request URL and
// canonicalizes it through the asset model. ok is false when the Location is
// absent, unparseable, fails canonicalization, or points at a NON-http(s)
// scheme — the caller then ends the walk with the current response as the
// final observation (observed, not followed).
//
// Redirect scheme policy: cross-host http(s) redirect targets ARE followed —
// jsintel has no declared-scope concept, fetch targets come from the
// operator's own corpus, and asset.ParseURL accepts any syntactically valid
// scheme (ftp:, file:, ws:, ...), so an explicit gate is required here. A
// non-http(s) target is NEVER requested: the walk ends with the redirect
// response as the final observation, exactly like the unparseable-Location
// path. That keeps one scheme-incompatible redirect from turning the whole
// observation into a permanently failed record (an unsupported scheme can
// never be fetched, so a "failed" classification would retry forever).
func resolveRedirect(resp *http.Response, clock runtime.Clock) (asset.URL, bool) {
	loc, err := resp.Location()
	if err != nil {
		return asset.URL{}, false
	}
	next, err := asset.ParseURL(loc.String(), asset.Provenance{
		Source:       provenanceSource,
		DiscoveredAt: clock.Now().UTC(),
	})
	if err != nil {
		return asset.URL{}, false
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return asset.URL{}, false
	}
	return next, true
}

// readTerminal retains the bounded metadata and content of the terminal
// response. Content bounds run in two stages:
//
//  1. Declared bound: a server-declared Content-Length above the cap means
//     the body is larger than we will ever retain — close it WITHOUT reading
//     a byte.
//  2. Streamed bound: otherwise stream up to MaxJSBytes+1 bytes; reading
//     more than MaxJSBytes means the body exceeds the cap.
//
// On either cap hit — or on a read failure mid-body — the retained content
// is nil and the fetch is truncated (FetchTruncated): a partial prefix is
// never stored or served as if it were the file (see doc.go). A truncated
// observation still carries its honest metadata: status, headers, and the
// declared/observed ContentLength.
func readTerminal(u, finalURL asset.URL, resp *http.Response, hops int, cfg FetchConfig) FetchResult {
	defer resp.Body.Close()
	res := FetchResult{
		URL:           u,
		FinalURL:      finalURL,
		StatusCode:    resp.StatusCode,
		ContentType:   sanitizeHeader(resp.Header.Get("Content-Type"), maxContentTypeBytes),
		ETag:          sanitizeHeader(resp.Header.Get("ETag"), maxETagBytes),
		XSourceMap:    sanitizeHeader(resp.Header.Get("X-SourceMap"), maxSourceMapBytes),
		ContentLength: resp.ContentLength,
		Redirects:     hops,
		Status:        FetchCompleted,
		Reason:        ReasonNone,
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := time.Parse(http.TimeFormat, lm); err == nil {
			res.LastModified = t
		}
	}
	if resp.ContentLength > cfg.MaxJSBytes {
		res.Truncated = true
		res.Status = FetchTruncated
		return res
	}
	body, exceeded, rerr := readBounded(resp.Body, cfg.MaxJSBytes)
	if rerr != nil {
		res.Err = fmt.Errorf("jsintel: fetch %s: read body: %w", u.String(), rerr)
		res.Truncated = true
		res.Status = FetchTruncated
		return res
	}
	if exceeded {
		res.Truncated = true
		res.Status = FetchTruncated
		return res
	}
	if len(body) > 0 {
		res.Content = body
		res.Size = int64(len(body))
		sum := sha256.Sum256(body)
		res.Hash = hex.EncodeToString(sum[:])
	}
	return res
}

// readBounded streams r up to cap+1 bytes. A body larger than cap reports
// exceeded (the retained bytes are dropped by the caller); the streamed read
// is bounded to cap+1 bytes of memory regardless of the true body size, so a
// gzip-decompressing transport (ContentLength -1) cannot grow memory without
// bound either.
func readBounded(r io.Reader, capBytes int64) (data []byte, exceeded bool, err error) {
	n, rerr := io.ReadAll(io.LimitReader(r, capBytes+1))
	if rerr != nil {
		return nil, false, rerr
	}
	if int64(len(n)) > capBytes {
		return nil, true, nil
	}
	return n, false, nil
}

// sanitizeHeader bounds one captured response header value to at most max
// bytes of printable ASCII (after trimming surrounding whitespace).
// Non-printable bytes — control characters and multi-byte UTF-8 — are
// dropped, so a captured value always passes the stored-record decode
// validation (printable ASCII, same caps) and never carries bytes that could
// corrupt a JSON payload or a log line.
func sanitizeHeader(v string, max int) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v) && b.Len() < max; i++ {
		if c := v[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// newTransport returns the bounded production transport: a clone of
// http.DefaultTransport with an explicit response-header byte cap, a
// response-header timeout, and direct connection only (environment proxies
// are never consulted). Transparent gzip decompression stays ENABLED: the
// transport hands over the decompressed body, which is what Fetch retains
// and stores.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxResponseHeaderBytes = MaxHeaderBytes
	t.ResponseHeaderTimeout = 30 * time.Second
	t.Proxy = nil // direct only: a stray environment proxy must never silently reroute fetching
	return t
}

// isRedirectCode reports whether status is a followable redirect status.
func isRedirectCode(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// classifyContextError maps a limiter-wait error to a fetch outcome: a
// deadline is a failed timed-out attempt, any other cancellation is a
// cancelled fetch.
func classifyContextError(err error) (FetchStatus, FetchReason) {
	if errors.Is(err, context.DeadlineExceeded) {
		return FetchFailed, ReasonTimeout
	}
	return FetchCancelled, ReasonOther
}

// classifyFetchError maps a round-trip error to a fetch outcome, in a fixed
// priority order:
//
//   - context cancellation -> cancelled (our own teardown)
//   - deadline -> failed, timeout (the per-attempt deadline, the caller's
//     job deadline, or the transport's response-header timeout fired)
//   - DNS resolution failure -> failed, dns (the dial could not resolve the
//     hostname; a DNS timeout is a timeout)
//   - net-level timeout -> failed, timeout
//   - connection refused -> COMPLETED, conn_refused: a legitimate negative
//     observation, the service is absent on this port
//   - TLS handshake failure (including certificate verification failures) ->
//     COMPLETED, tls: a legitimate negative observation, https is not served
//     on this endpoint from RavenRecon's trust perspective
//   - response-header block over the transport cap, and anything else ->
//     failed, other
//
// Completed negatives are never retried; failed outcomes are retried per
// FetchConfig.Retries.
func classifyFetchError(ctx context.Context, err error) (FetchStatus, FetchReason) {
	if errors.Is(err, context.Canceled) {
		return FetchCancelled, ReasonOther
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FetchFailed, ReasonTimeout
	}
	if ctx.Err() != nil {
		// The caller's context fired while the request was in flight; the
		// surfaced error may not wrap the context error directly.
		return classifyContextError(ctx.Err())
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return FetchFailed, ReasonTimeout
		}
		return FetchFailed, ReasonDNS
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return FetchFailed, ReasonTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return FetchCompleted, ReasonConnRefused
	}
	if isTLSError(err) {
		return FetchCompleted, ReasonTLS
	}
	return FetchFailed, ReasonOther
}

// isTLSError reports whether err stems from a TLS handshake failure:
// protocol alerts, certificate verification failures, or the crypto/tls
// text errors ("tls: first record does not look like a TLS handshake").
// The text check is a last resort because crypto/tls surfaces some
// handshake failures as plain errors; the texts are stdlib-fixed and never
// server-controlled.
func isTLSError(err error) bool {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return true
	}
	var invalidErr *x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return true
	}
	var unknownErr *x509.UnknownAuthorityError
	if errors.As(err, &unknownErr) {
		return true
	}
	var hostnameErr *x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var rootsErr *x509.SystemRootsError
	if errors.As(err, &rootsErr) {
		return true
	}
	return strings.Contains(err.Error(), "tls:")
}
