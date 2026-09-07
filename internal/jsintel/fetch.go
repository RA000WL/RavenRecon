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
	"net/netip"
	"net/textproto"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

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

// Truncation causes for a FetchTruncated observation. The cause decides the
// manifest contract: a cap truncation carries a well-formed window manifest,
// a read-error truncation carries none.
const (
	// truncCauseCap marks content-cap truncation (body exceeded MaxJSBytes
	// while streaming): windows + manifest retained, content nil.
	truncCauseCap = "cap"
	// truncCauseRead marks a mid-body read failure: nothing retained, no
	// manifest.
	truncCauseRead = "read"
)

// ChunkInfo is one window's manifest entry: the deterministic byte span in
// the retained prefix plus the full SHA-256 of the window bytes. The chunk
// identity cites the first 8 hex digits (ph) of SHA256Hex.
type ChunkInfo struct {
	// Index is the window index in tiling order.
	Index int
	// Start is the byte offset of the window in the retained prefix.
	Start int64
	// End is the exclusive end offset (Start < End <= PrefixLen).
	End int64
	// SHA256Hex is the lowercase hex SHA-256 of the window bytes (64 hex).
	SHA256Hex string
}

// FetchManifest describes the retained windows of a cap-truncated fetch: the
// tiling tag that produced them, the retained prefix length, the cause, and
// the per-window entries in index order. Read-error truncations carry a nil
// manifest; completed fetches never carry one.
type FetchManifest struct {
	// TilingTag names the tiling that produced the windows (fetchTilingTag).
	TilingTag string
	// PrefixLen is the retained prefix length (== MaxJSBytes at cap time).
	PrefixLen int64
	// Cause is truncCauseCap for every manifest-bearing result.
	Cause string
	// Chunks holds one entry per window in index order.
	Chunks []ChunkInfo
}

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
	// Windows are the deterministic overlapped tilings of the retained
	// prefix for over-cap bodies discovered while streaming (NEW-124
	// Phase 1): window i covers
	// [i*(maxFetchWindowBytes-fetchWindowOverlapBytes),
	//  i*(...)+maxFetchWindowBytes), so every prefix byte appears in at
	// least one window and any token shorter than the overlap appears
	// whole in one. Empty unless the body exceeded the cap while
	// streaming. Windows alias the
	// retained prefix (read-only downstream) and never exceed MaxJSBytes
	// total — the same memory ceiling as today.
	Windows [][]byte
	// Manifest describes the retained windows of a cap-truncated fetch
	// (NEW-129 Slice 1): tiling tag, prefix length, per-window spans and
	// hashes, and the truncation cause. Nil for completed fetches and for
	// read-error truncations (which carry no manifest).
	Manifest *FetchManifest
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

	// RequestHeaders carries operator-supplied session headers (NEW-125):
	// added to requests on the fetch target's own host. Nil or empty
	// means anonymous fetching. Cross-host redirect hops NEVER inherit
	// them (fail-closed direction). Values never enter logs, errors,
	// reports, or cache records — only the session digest enters cache
	// keys. Validated at the engine layer (fail-closed); direct Fetch
	// callers pass already-validated headers.
	RequestHeaders http.Header

	// ResolveIP resolves redirect-target hostnames for the dial-safety
	// gate (see redirectDialSafe). Nil means the system default resolver.
	// Tests inject a hermetic stub; the engine leaves it nil (production
	// resolution). It is consulted ONLY for cross-host redirect hops —
	// same-host hops and the initial URL never resolve through it.
	ResolveIP func(ctx context.Context, host string) ([]net.IP, error)
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
	if len(c.RequestHeaders) > 0 {
		// Fail-closed validation + canonicalization before any dispatch
		// (mirrors the engine layer and httpprobe buildEnv): direct Fetch
		// callers get the same whole-call rejection as pipeline runs — a
		// half-authed fetch is worse than none.
		normalized, _, err := normalizeRequestHeaders(c.RequestHeaders)
		if err != nil {
			return c, err
		}
		c.RequestHeaders = normalized
	}
	return c, nil
}

// Fetch performs one bounded fetch of the canonical URL u: a GET with no
// body, a fixed RavenRecon user agent, and no cookies or custom headers,
// built from the canonical asset URL form (userinfo and fragment never reach
// the wire). It follows up to MaxRedirects redirects — cross-host http(s)
// redirects included, since jsintel has no declared-scope concept — but a
// redirect to a NON-http(s) scheme is observed, never requested: the walk
// ends with the redirect response as the final observation. Cross-host
// IP-literal targets are likewise refused at the string layer, and
// cross-host DNS-name hops pass a dial-time gate (redirectDialSafe):
// the target must resolve to all-public addresses or the hop is
// observed, never followed. It streams the
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
		// Session headers ride only same-host dispatches (NEW-125):
		// the initial request targets u itself (always same-host);
		// redirect hops to other hosts never inherit credentials.
		if hostPart(cur.HostPort) == hostPart(u.HostPort) {
			applySessionHeaders(req, cfg.RequestHeaders)
		}
		resp, err := cfg.Transport.RoundTrip(req)
		if err != nil {
			st, reason := classifyFetchError(ctx, err)
			return FetchResult{URL: u, FinalURL: finalURL, Redirects: hops, Status: st, Reason: reason, Err: err}
		}

		if isRedirectCode(resp.StatusCode) && resp.Header.Get("Location") != "" && hops < MaxRedirects {
			next, ok := resolveRedirect(resp, cur, cfg.Clock)
			if !ok {
				// An unparseable Location — a non-http(s) target — or a
				// cross-host IP-literal target ends the walk: the redirect
				// response itself is the final observation (completed,
				// FinalURL = the URL it was received from), observed but
				// never followed.
				return readTerminal(u, cur, resp, hops, cfg)
			}
			if !redirectDialSafe(reqCtx, cfg, cur, next) {
				// Cross-host hop resolving to non-public addresses (or
				// unresolvable at all): observed, never followed.
				// Fail-closed — a hostile target controlling its DNS can
				// only deny fetches, never steer them onto internal
				// infrastructure (review wave 2026-09-03).
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

// Session header bounds (NEW-125, mirroring httpprobe's run.go — same
// values, same fail-closed semantics; the two engines stay independent
// with no shared dependency).
const (
	maxSessionHeaderCount      = 32
	maxSessionHeaderNameBytes  = 256
	maxSessionHeaderValueBytes = 8 << 10
	// maxSessionHeaderValues bounds the total number of header values
	// across all keys (a single key may carry many values).
	maxSessionHeaderValues = 64
	// maxSessionHeaderTotalBytes bounds the total session header value
	// bytes across all keys (Σ len(values)).
	maxSessionHeaderTotalBytes = 64 << 10
)

// forbiddenSessionHeader reports whether the canonical header name must
// never arrive via session headers: Host (the transport would ignore
// it — silent confusion), the framing headers Content-Length /
// Transfer-Encoding / Connection (the transport owns framing), and
// User-Agent (Fetch sets its own fixed identifier; a session override
// would silently impersonate a different client).
func forbiddenSessionHeader(canon string) bool {
	switch canon {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "User-Agent":
		return true
	}
	return false
}

// normalizeRequestHeaders validates session headers (fail-closed) and
// returns the canonical form (net/textproto MIME form, sorted keys,
// duplicate values merged in order) plus its cache-key digest. Mirrors
// httpprobe.normalizeRequestHeaders exactly — same bounds, same
// rejections (empty map, bad tokens, Host / framing / User-Agent
// headers, empty/over-long values, control bytes, over-count keys,
// over-count total values, over-budget total value bytes).
func normalizeRequestHeaders(h http.Header) (http.Header, string, error) {
	if len(h) == 0 {
		return nil, "", fmt.Errorf("jsintel: no session headers")
	}
	if len(h) > maxSessionHeaderCount {
		return nil, "", fmt.Errorf("jsintel: %d session headers over bound %d", len(h), maxSessionHeaderCount)
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(http.Header, len(h))
	totalValues := 0
	totalBytes := 0
	for _, k := range keys {
		if !validSessionHeaderToken(k) {
			return nil, "", fmt.Errorf("jsintel: invalid session header name %q", k)
		}
		canon := textproto.CanonicalMIMEHeaderKey(k)
		if len(canon) > maxSessionHeaderNameBytes {
			return nil, "", fmt.Errorf("jsintel: session header name over bound %d", maxSessionHeaderNameBytes)
		}
		if forbiddenSessionHeader(canon) {
			return nil, "", fmt.Errorf("jsintel: session headers must not set %s", canon)
		}
		for _, v := range h[k] {
			if v == "" {
				return nil, "", fmt.Errorf("jsintel: session header %q has an empty value", k)
			}
			if len(v) > maxSessionHeaderValueBytes {
				return nil, "", fmt.Errorf("jsintel: session header %q value over bound %d", k, maxSessionHeaderValueBytes)
			}
			for i := 0; i < len(v); i++ {
				if v[i] < 0x20 || v[i] > 0x7e {
					return nil, "", fmt.Errorf("jsintel: session header %q value carries control bytes", k)
				}
			}
			totalValues++
			totalBytes += len(v)
		}
		out[canon] = append(out[canon], h[k]...)
	}
	if totalValues > maxSessionHeaderValues {
		return nil, "", fmt.Errorf("jsintel: %d session header values over bound %d", totalValues, maxSessionHeaderValues)
	}
	if totalBytes > maxSessionHeaderTotalBytes {
		return nil, "", fmt.Errorf("jsintel: session header values total %d bytes over bound %d", totalBytes, maxSessionHeaderTotalBytes)
	}
	return out, sessionDigest(out), nil
}

// validSessionHeaderToken reports whether name is an HTTP token.
func validSessionHeaderToken(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// sessionDigest binds session headers into cache keys without carrying
// values (mirrors httpprobe.sessionDigest): hex SHA-256 over sorted
// "name\x00value" lines; empty digests to "" (callers omit the key
// component then, keeping anonymous keys byte-identical).
func sessionDigest(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteByte(0)
			b.WriteString(v)
			b.WriteByte(0)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// applySessionHeaders sets validated session headers on an outbound
// request. Callers gate scope themselves (same-host only for redirect
// walks); single-URL observations call it directly.
func applySessionHeaders(req *http.Request, headers http.Header) {
	for k, vs := range headers {
		req.Header[k] = append([]string(nil), vs...)
	}
}

// resolveRedirect resolves a response's Location against the request URL and
// canonicalizes it through the asset model. ok is false when the Location is
// absent, unparseable, fails canonicalization, points at a NON-http(s)
// scheme, or points at an IP literal on a DIFFERENT host than the current
// request — the caller then ends the walk with the current response as the
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
//
// Redirect address policy (mirrors httpprobe canonicalScopeHost): a
// cross-host IP-literal target is NEVER requested — observed, never
// followed. Otherwise a hostile target could drive the fetcher onto
// link-local/loopback addresses (e.g. cloud instance metadata) via a 302
// and retain the body into cache/reports. Same-host redirects (relative
// hops and absolute URLs on the request's own host, including IP-literal
// bases such as loopback test servers and operator-supplied IP targets)
// are still followed; hostname targets (including cross-host DNS names)
// are still followed. The initial dial follows whatever the target's DNS
// returns at request time (see doc.go DNS-following contract).
func resolveRedirect(resp *http.Response, cur asset.URL, clock runtime.Clock) (asset.URL, bool) {
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
	if isIPLiteralHostPort(next.HostPort) && hostPart(next.HostPort) != hostPart(cur.HostPort) {
		return asset.URL{}, false
	}
	return next, true
}

// redirectDialSafe reports whether a resolved cross-host redirect hop
// may be requested: the target hostname must resolve (through the
// configured resolver, production DNS by default) to at least one
// address, and every resolved address must be public. Same-host hops
// always pass — the operator's own surface, including IP-literal bases
// and loopback test servers, is never gated. Anything else (resolver
// error, empty answer, or any loopback/link-local/private/multicast/
// unspecified address) refuses the hop: observed, never followed.
//
// Fail-closed is deliberate: an attacker commanding the target's DNS
// can only deny fetches, never steer them onto metadata endpoints,
// loopback services, or RFC 1918 infrastructure. Residual risk remains
// for DNS rebinding between this check and the transport's own dial
// (short TTLs can swap answers) — operators scanning hostile domains
// must still run behind egress that denies non-public destinations,
// documented in doc.go.
func redirectDialSafe(ctx context.Context, cfg FetchConfig, cur, next asset.URL) bool {
	if hostPart(next.HostPort) == hostPart(cur.HostPort) {
		return true
	}
	addrs, err := cfg.resolveIP(ctx, hostPart(next.HostPort))
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, ip := range addrs {
		if !isPublicDialIP(ip) {
			return false
		}
	}
	return true
}

// resolveIP resolves a hostname to addresses for the dial-safety gate,
// via the injected stub in tests or the system resolver in production.
func (c FetchConfig) resolveIP(ctx context.Context, host string) ([]net.IP, error) {
	if c.ResolveIP != nil {
		return c.ResolveIP(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// isPublicDialIP reports whether ip is a public routable address: not
// loopback, link-local (v4 or v6), multicast, unspecified, or private
// (RFC 1918 / RFC 4193, including IPv4-mapped forms). Anything else is
// internal infrastructure a hostile redirect must never reach.
func isPublicDialIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	return true
}

// hostPart returns the host without port or IPv6 brackets for same-host
// comparison (canonical HostPorts are already lowercase).
func hostPart(hostPort string) string {
	hp := hostPort
	if host, _, err := net.SplitHostPort(hp); err == nil {
		hp = host
	}
	hp = strings.TrimPrefix(hp, "[")
	hp = strings.TrimSuffix(hp, "]")
	return hp
}

// isIPLiteralHostPort reports whether a canonical asset HostPort names an IP
// literal (never a fetchable redirect target). The canonical HostPort may
// carry a non-default port ("host:8080" or a bracketed IPv6 literal), which
// is stripped before the check; the parse uses netip.ParseAddr so the
// verdict matches the asset model's own IP/host routing (including the
// leading-zero-octet asymmetry documented in normalizeHost).
//
// The check is deliberately broader than ParseAddr: a trailing root dot is
// stripped, and classic non-canonical IP spellings — dotted quads with
// leading-zero octets ("010.0.0.1"), pure decimal ("2130706433"), and
// 0x-hex ("0x7f000001"), all of which ParseAddr rejects but some
// resolvers interpret as addresses — are refused via isNumericHost.
// Mixed-alphanumeric ("db2", "cafe01") and pure-hex-alpha ("dead")
// names are real hostname shapes and still pass through to DNS. The
// initial fetch URL (the operator's explicit target) is never gated.
func isIPLiteralHostPort(hostPort string) bool {
	hp := hostPort
	if host, _, err := net.SplitHostPort(hp); err == nil {
		hp = host
	}
	hp = strings.TrimPrefix(hp, "[")
	hp = strings.TrimSuffix(hp, "]")
	hp = strings.ToLower(strings.TrimSuffix(hp, "."))
	if isNumericHost(hp) {
		return true
	}
	_, err := netip.ParseAddr(hp)
	return err == nil
}

// isNumericHost reports whether h is an IP-address spelling no DNS
// name needs: pure decimal ("2130706433"), 0x-hex ("0x7f000001"), or
// dotted numerics ("10.0.0.1" including leading-zero octets like
// "010.0.0.1" — which ParseAddr rejects but some resolvers interpret
// as addresses). Mixed-alphanumeric names ("db2", "a1", "cafe01",
// "123abc") and pure-hex-alpha names ("dead", "cafe") are real
// hostname shapes and pass through to DNS.
func isNumericHost(hp string) bool {
	if hp == "" {
		return false
	}
	if isDecimal(hp) || isHexIP(hp) || isDottedNumeric(hp) {
		return true
	}
	return false
}

// isDecimal reports an all-digit host (a decimal IP spelling).
func isDecimal(hp string) bool {
	for i := 0; i < len(hp); i++ {
		if hp[i] < '0' || hp[i] > '9' {
			return false
		}
	}
	return true
}

// isHexIP reports a 0x/0X-prefixed hex IP spelling.
func isHexIP(hp string) bool {
	if len(hp) < 3 || (hp[:2] != "0x" && hp[:2] != "0X") {
		return false
	}
	for i := 2; i < len(hp); i++ {
		c := hp[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// isDottedNumeric reports dot-separated all-digit groups ("10.0.0.1",
// "010.0.0.1", "1.2.3.4.5"). Empty groups and non-digit bytes fail.
func isDottedNumeric(hp string) bool {
	if !strings.Contains(hp, ".") {
		return false
	}
	for _, part := range strings.Split(hp, ".") {
		if part == "" || !isDecimal(part) {
			return false
		}
	}
	return true
}

// readTerminal retains the bounded metadata and content of the terminal
// response. The declared Content-Length is never trusted: every body is
// streamed up to MaxJSBytes+1 bytes, and reading more than MaxJSBytes
// means the body exceeds the cap (the bound is kept, the trust is
// dropped — a lying Content-Length can neither truncate a small body
// nor retain a huge one).
//
// On a cap hit — or on a read failure mid-body — the fetch is
// truncated (FetchTruncated): Content stays nil and Size/Hash stay zero
// (a partial prefix is never stored or served as if it were the file,
// see doc.go). The over-cap path additionally retains deterministic
// overlapped windows over the bounded prefix (NEW-124 Phase 1,
// splitWindows) for analysis — same memory ceiling, same
// truncated/incomplete honesty. A truncated observation
// still carries its honest metadata: status, headers, and the
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
	body, exceeded, rerr := readBounded(resp.Body, cfg.MaxJSBytes)
	if rerr != nil {
		res.Err = fmt.Errorf("jsintel: fetch %s: read body: %w", u.String(), rerr)
		res.Truncated = true
		res.Status = FetchTruncated
		return res
	}
	if exceeded {
		// Over-cap body discovered while streaming: retain deterministic
		// overlapped windows over the bounded prefix for analysis
		// (NEW-124 Phase 1) — same memory ceiling as today (cap+1 read),
		// same truncated/incomplete honesty, Content still nil.
		// Accepted waste: windows are tiled before JS classification, so
		// an over-cap non-JS body retains a prefix that analysis
		// discards — bounded by MaxJSBytes either way, and gating on
		// Content-Type/extension here would duplicate the engine's
		// isJSAsset rule (a second classifier for the same concept).
		res.Windows = splitWindows(body, maxFetchWindowBytes, fetchWindowOverlapBytes)
		res.Manifest = buildFetchManifest(body, res.Windows)
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
// exceeded with the first cap bytes retained (the analysis prefix —
// callers tile it into windows, never serve it as the file); the streamed
// read is bounded to cap+1 bytes of memory regardless of the true body
// size, so a gzip-decompressing transport (ContentLength -1) cannot grow
// memory without bound either.
func readBounded(r io.Reader, capBytes int64) (data []byte, exceeded bool, err error) {
	n, rerr := io.ReadAll(io.LimitReader(r, capBytes+1))
	if rerr != nil {
		return nil, false, rerr
	}
	if int64(len(n)) > capBytes {
		return n[:capBytes], true, nil
	}
	return n, false, nil
}

// Fetch window bounds (NEW-124 Phase 1, tiling tag NEW-129 Slice 1).
// Fixed constants, deliberately NOT configuration: they bound retained
// memory exactly like MaxJSBytes, so they must never enter cache keys. The
// overlap covers the parser's longest atomic token (maxParserStringBytes
// 4 KiB) with margin, so any literal or specifier split by a window
// boundary still appears whole in a neighbor window. OD-4 measurement
// (NEW-129): the secrentel engine's longest retained candidate value is
// 800 bytes (aws session token, MaxLen 800; max Trail 120 is already
// bounded by its own MaxLen), so the 8 KiB overlap covers it with a ~7 KiB
// margin (10x) — no resize; the tag below stays "w512-o8-v1".
const (
	// maxFetchWindowBytes bounds one analysis window.
	maxFetchWindowBytes = 512 << 10
	// fetchWindowOverlapBytes bounds the overlap between consecutive
	// windows (stride = window - overlap).
	fetchWindowOverlapBytes = 8 << 10
	// fetchTilingTag names the tiling that produced a window set. It enters
	// chunk identities and fetch manifests (never cache keys — the constants
	// above never enter keys either); a tag mismatch means the windows were
	// tiled differently and the manifest must be recomputed.
	fetchTilingTag = "w512-o8-v1"
	// maxWindowedChunks bounds how many windows one fetch may retain. The
	// default 2 MiB prefix tiles to 5 windows; the 8 MiB maximum tiles to
	// 17 in the worst case, so the bound keeps margin at 32 and the
	// manifest decode rejects counts above this bound so a tampered
	// record cannot smuggle unbounded windows. No per-file chunk cut is
	// applied below the produced windows: jsDocuments emits every
	// produced window.
	maxWindowedChunks = 32
)

// snapToRuneStart backs off to the nearest UTF-8 rune boundary at or before
// off (a deterministic pure function of bytes): while off points at a UTF-8
// continuation byte it moves one byte earlier. Offsets 0 and len(data) are
// fixed points. Mirrors secrentel's Trail rune-boundary backup so a window
// boundary never splits a multi-byte rune into invalid UTF-8 at its edges.
func snapToRuneStart(data []byte, off int) int {
	if off <= 0 || off >= len(data) {
		return off
	}
	for off > 0 && off < len(data) && !utf8.RuneStart(data[off]) {
		off--
	}
	return off
}

// splitWindows tiles data into deterministic overlapped windows:
// window i covers [i*stride, i*stride+size), the last window ending
// exactly at len(data). Every byte appears in at least one window.
// Windows alias data (read-only downstream); no bytes are copied.
// Window boundaries (except 0 and len(data)) snap to UTF-8 rune
// boundaries via snapToRuneStart — a deterministic pure function of the
// bytes, at most 3 bytes of shift against the 8 KiB overlap, so coverage
// and overlap guarantees are unchanged.
func splitWindows(data []byte, size, overlap int) [][]byte {
	if len(data) <= size {
		return [][]byte{data}
	}
	stride := size - overlap
	if stride <= 0 {
		return [][]byte{data}
	}
	var out [][]byte
	for start := 0; start < len(data); start += stride {
		s := snapToRuneStart(data, start)
		end := start + size
		if end > len(data) {
			end = len(data)
		} else {
			end = snapToRuneStart(data, end)
			if end <= s {
				// Degenerate snap (a >512 KiB rune run, unreachable for
				// valid UTF-8): fall back to the raw end so no byte is
				// ever dropped.
				end = start + size
				if end > len(data) {
					end = len(data)
				}
			}
		}
		out = append(out, data[s:end])
		if end == len(data) {
			break
		}
	}
	return out
}

// buildFetchManifest describes windows tiled from prefix: the tiling tag,
// the prefix length, and one entry per window in index order with byte
// spans and full SHA-256 hex. It replays the exact tiling math of
// splitWindows (including rune snapping) so spans always agree with the
// retained windows by construction. The manifest copies no window bytes.
func buildFetchManifest(prefix []byte, windows [][]byte) *FetchManifest {
	if len(windows) == 0 {
		return nil
	}
	size, overlap := maxFetchWindowBytes, fetchWindowOverlapBytes
	stride := size - overlap
	m := &FetchManifest{
		TilingTag: fetchTilingTag,
		PrefixLen: int64(len(prefix)),
		Cause:     truncCauseCap,
		Chunks:    make([]ChunkInfo, 0, len(windows)),
	}
	wi := 0
	for start := 0; start < len(prefix) && wi < len(windows); start += stride {
		s := snapToRuneStart(prefix, start)
		end := start + size
		if end > len(prefix) {
			end = len(prefix)
		} else {
			end = snapToRuneStart(prefix, end)
			if end <= s {
				end = start + size
				if end > len(prefix) {
					end = len(prefix)
				}
			}
		}
		sum := sha256.Sum256(windows[wi])
		m.Chunks = append(m.Chunks, ChunkInfo{
			Index:     wi,
			Start:     int64(s),
			End:       int64(s + len(windows[wi])),
			SHA256Hex: hex.EncodeToString(sum[:]),
		})
		wi++
		if end == len(prefix) {
			break
		}
	}
	return m
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
//
// TLS handshake failures are tagged at the dial boundary: DialTLSContext
// performs the handshake and wraps ANY handshake error in the typed
// tlsHandshakeError sentinel, so classification never depends on matching
// error text (server-controlled bytes can reach error strings via
// textproto.ProtocolError and net/http's badStringError, so text matching
// is spoofable). Dial-level failures — connection refused, DNS failures,
// dial timeouts — happen in DialContext BEFORE the handshake and pass
// through untagged, keeping their own classification. Mirrors the
// httpprobe production transport.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxResponseHeaderBytes = MaxHeaderBytes
	t.ResponseHeaderTimeout = 30 * time.Second
	t.Proxy = nil // direct only: a stray environment proxy must never silently reroute fetching
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Dial through the transport's own DialContext so dial-level
		// failures (refused, DNS, timeout) keep the classification the
		// default TLS path gives them; only the handshake itself is
		// tagged.
		plain, err := t.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The transport normally derives ServerName from the request host
		// (addTLS); with a custom dialer the address is all we have.
		// Mirroring httpprobe's dialer (NEW-50), ServerName is set
		// UNCONDITIONALLY
		// when empty — including for IP literals, exactly like net/http's
		// addTLS does: crypto/tls rejects a verifying config with an empty
		// ServerName outright ("either ServerName or InsecureSkipVerify"),
		// so skipping IPs here would turn every https://IP/ fetch into an
		// instant handshake failure instead of a real verification against
		// the certificate's IP SANs.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg := t.TLSClientConfig.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		// The transport applies TLSHandshakeTimeout only on its own TLS
		// path (addTLS); the custom dialer must bound the handshake
		// itself. A timeout surfaces as context.DeadlineExceeded wrapped
		// in the sentinel and classifies failed/timeout, exactly like the
		// default path's handshake-timeout error (the context checks run
		// before the TLS checks in classifyFetchError).
		hsCtx := ctx
		var cancel context.CancelFunc
		if d := t.TLSHandshakeTimeout; d > 0 {
			hsCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
		tlsConn := tls.Client(plain, cfg)
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			plain.Close()
			return nil, &tlsHandshakeError{err: err}
		}
		return tlsConn, nil
	}
	return t
}

// tlsHandshakeError tags an error as a TLS handshake failure observed at the
// dial boundary (the production transport's DialTLSContext). Classification
// matches this type structurally — never error text — so a hostile server
// that embeds "tls:"-looking text in a malformed response cannot fabricate
// a TLS observation (a cached completed negative). Unwrap keeps the
// underlying stdlib error reachable for the typed checks (tls.AlertError,
// tls.RecordHeaderError, tls.CertificateVerificationError, the x509 set)
// and for context-error classification (cancellation and deadline checks
// run before the TLS checks, so a cancelled or timed-out handshake keeps
// its own outcome). Mirrors the httpprobe sentinel.
type tlsHandshakeError struct{ err error }

func (e *tlsHandshakeError) Error() string {
	return "jsintel: tls handshake failed: " + e.err.Error()
}
func (e *tlsHandshakeError) Unwrap() error { return e.err }

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
// the dial-boundary sentinel (the production transport's DialTLSContext
// tags every handshake error), protocol alerts, record-header failures
// ("first record does not look like a TLS handshake"), certificate
// verification failures, or the x509 error set. Classification is strictly
// structural — there is deliberately NO error-text fallback: the stdlib
// embeds raw server bytes in some error strings (textproto.ProtocolError,
// net/http's badStringError), so matching "tls:" text would let a hostile
// server fabricate a TLS observation (and with it a completed cache
// record). The typed checks also cover errors from caller-injected
// transports, whose handshake failures never cross our dial boundary.
// Mirrors the httpprobe classifier.
func isTLSError(err error) bool {
	var hsErr *tlsHandshakeError
	if errors.As(err, &hsErr) {
		return true
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
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
	return false
}
