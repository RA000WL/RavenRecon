package techintel

import (
	"fmt"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Observation-shaped input bounds. The engine NEVER fetches anything: a
// caller composes an Observation from its own probes (HTTP probing, TLS
// metadata 5C, DNS resolution 5A) and feeds it to Ingest. Every cap below is
// a fixed constant, deliberately NOT configuration, and never enters cache
// keys: the caps are ingest/analysis bounds, not result semantics.
const (
	// maxObservationBody bounds the retained response body. A longer body is
	// truncated at ingest with the observation's Truncated flag set — the
	// analysis result is honest (the body it saw is incomplete).
	maxObservationBody = 1 << 20 // 1 MiB

	// maxObservationHeaders bounds the header entry count. A caller-provided
	// observation with more entries than this is REJECTED as malformed at
	// ingest (counted, never analyzed): the header analysis contract covers
	// at most 128 entries, and a larger set cannot be honestly analyzed.
	maxObservationHeaders = 128

	// maxHeaderValueBytes bounds one retained header value. Longer values
	// are truncated at ingest (Truncated flag). Header MATCHING runs on the
	// full retained line, so this bounds the matching work per entry.
	maxHeaderValueBytes = 64 << 10 // 64 KiB

	// maxCookieNameBytes and maxCookieValueBytes bound one caller-provided
	// cookie entry. Longer values are truncated at ingest (Truncated flag).
	maxCookieNameBytes  = 2 << 10 // 2 KiB
	maxCookieValueBytes = 4 << 10 // 4 KiB

	// maxObservationCookies bounds how many cookie entries the cookie
	// analyzer retains per observation (caller-provided plus headers-parsed,
	// combined). Beyond the cap entries are dropped in deterministic order
	// and Overflow.Cookies is set (the record stays completed but the
	// observed cookie set is incomplete).
	maxObservationCookies = 256

	// maxCanonicalURLLen is the ingest-boundary cap on the observation
	// URL's CANONICAL string, mirroring urlintel's raw-line cap
	// (maxRawURLLen, 32 KiB): the URL identity feeds cache keys, evidence
	// source identities, and report entries, so a caller-composed
	// observation whose canonical URL exceeds this is REJECTED as malformed
	// at ingest (counted, never analyzed). It is a fixed constant,
	// deliberately NOT configuration, and never enters cache keys; the
	// check runs before any re-parse, so a hostile oversized URL never
	// reaches the parser.
	maxCanonicalURLLen = 32 << 10 // 32 KiB

	// maxTLSEntries bounds the TLSInfo ALPN and DNSNames lists and
	// maxCNAMEChain bounds the DNSInfo CNAME chain. Longer lists are
	// truncated at ingest (Truncated flag). None of the lists are analyzed
	// beyond these bounds.
	maxTLSEntries = 32
	maxCNAMEChain = 16

	// defaultSourceName is the provenance source used when an observation
	// carries no Source name.
	defaultSourceName = "techintel"
)

// HeaderEntry is one response header of the final response, as observed. A
// header that occurred multiple times is represented by multiple entries
// (one per occurrence), so every occurrence is considered by the header
// analyzer.
type HeaderEntry struct {
	// Name is the header name as observed, e.g. "Server".
	Name string `json:"name"`
	// Value is the header value as observed, e.g. "nginx/1.25.3".
	Value string `json:"value"`
}

// CookieEntry is one cookie as observed, either caller-parsed or parsed by
// the cookie analyzer from Cookie / Set-Cookie headers.
type CookieEntry struct {
	// Name is the cookie name as observed.
	Name string `json:"name"`
	// Value is the cookie value as observed. Values are never secrets to the
	// engine: only bounded matching and bounded evidence values consume them.
	Value string `json:"value"`
}

// TLSInfo is the typed TLS observation seam (the 5C metadata shape): the
// certificate issuer, the certificate subject (CN), and the ALPN protocols
// offered during the handshake. It is nil when TLS metadata is unknown (for
// example an http observation), in which case no TLS indicators can fire.
type TLSInfo struct {
	// ALPN lists the ALPN protocols offered during the handshake (e.g.
	// "h3"), in handshake order.
	ALPN []string `json:"alpn,omitempty"`
	// Issuer is the certificate issuer string as observed.
	Issuer string `json:"issuer,omitempty"`
	// Subject is the certificate subject CN string as observed.
	Subject string `json:"subject,omitempty"`
	// DNSNames lists the certificate DNS SANs. Retained for fidelity; no
	// fingerprint indicator analyzes them today.
	DNSNames []string `json:"dns_names,omitempty"`
}

// DNSInfo is the typed DNS observation seam (the 5A shape): the CNAME chain
// observed for the host. It is nil when DNS metadata is unknown.
type DNSInfo struct {
	// CNAMEChain lists the CNAME targets observed, in chain order.
	CNAMEChain []string `json:"cname_chain,omitempty"`
}

// Observation is one typed technology-detection input: everything the
// analyzers may consume, composed by the CALLER. The engine never fetches:
// it validates, analyzes, caches, and reports the typed inputs it is given.
//
// The observation's IDENTITY — the cache-key target and report-merge key —
// is the endpoint identity when Endpoint is present, otherwise the canonical
// URL identity. Everything else (status code, headers, body, cookies, TLS,
// DNS) is observation material that feeds the analyzers; the status code is
// retained for the report and record but is deliberately NOT analyzed by any
// current indicator kind, so it never enters a cache key.
type Observation struct {
	// URL is the canonical Phase 2 URL asset the observation is about. It
	// must be a canonical asset (re-parseable to its own identity); a
	// hand-built or non-canonical URL is rejected as malformed at ingest.
	URL asset.URL

	// Endpoint, when present, narrows the observation's identity to one
	// request shape. Its URL must equal Observation.URL's identity.
	Endpoint *asset.Endpoint

	// StatusCode is the HTTP response status code, when observed.
	StatusCode int

	// Headers are the response headers as observed, at most
	// maxObservationHeaders entries (more is malformed at ingest).
	Headers []HeaderEntry

	// Body is the response body, truncated to maxObservationBody bytes at
	// ingest with the Truncated flag set when longer.
	Body string

	// Cookies are the caller-parsed cookies. The cookie analyzer ALSO parses
	// Cookie / Set-Cookie headers, so cookies may arrive from either side;
	// the combined set is capped at maxObservationCookies entries.
	Cookies []CookieEntry

	// TLS is the typed TLS observation; nil when unknown.
	TLS *TLSInfo

	// DNS is the typed DNS observation; nil when unknown.
	DNS *DNSInfo

	// Source names the provenance of this observation (the capability that
	// composed it). It becomes the Provenance.Source of every asset this
	// observation produces. Empty defaults to "techintel".
	Source string

	// ObservedAt is when the observation was made; zero means the run's
	// clock at processing time. It becomes the Provenance.DiscoveredAt of
	// every asset this observation produces.
	ObservedAt time.Time
}

// identity returns the observation's canonical identity: the endpoint
// identity when an endpoint is attached, otherwise the URL identity. This is
// the cache-key target AND the report-merge key, mirroring the design
// contract ("target = canonical URL identity, else endpoint identity").
func (o Observation) identity() asset.Identity {
	if o.Endpoint != nil {
		return o.Endpoint.Identity()
	}
	return o.URL.Identity()
}

// prepareObservation validates and bounds one caller-composed observation at
// the ingest boundary.
//
// It returns a normalized copy (body/header-value/cookie/TLS/DNS truncation
// applied, timestamps filled, source defaulted) and whether any truncation
// happened (the observation's Truncated flag), or an error for input that is
// MALFORMED and must be counted, never analyzed:
//
//   - the URL does not re-parse to its own canonical identity (zero, broken,
//     or hand-built non-canonical structs);
//   - the URL's canonical string exceeds maxCanonicalURLLen (32 KiB);
//   - an attached endpoint does not re-validate, or its URL identity differs
//     from the observation URL's;
//   - more than maxObservationHeaders header entries.
//
// Malformed input never panics and never stops the run: the caller counts it
// (see Ingest).
func prepareObservation(o Observation, now time.Time) (Observation, bool, error) {
	if err := validateObservationURL(o.URL); err != nil {
		return Observation{}, false, err
	}
	if o.Endpoint != nil {
		if err := validateObservationEndpoint(*o.Endpoint, o.URL); err != nil {
			return Observation{}, false, err
		}
	}
	if len(o.Headers) > maxObservationHeaders {
		return Observation{}, false, fmt.Errorf(
			"observation carries %d headers (cap %d)", len(o.Headers), maxObservationHeaders)
	}

	truncated := false
	out := o

	// Body bound: truncate, never reject — the analysis result stays honest
	// via the Truncated flag.
	if len(out.Body) > maxObservationBody {
		out.Body = out.Body[:maxObservationBody]
		truncated = true
	}

	// Header value bound: truncate (the retained line is what gets matched).
	for i := range out.Headers {
		if len(out.Headers[i].Value) > maxHeaderValueBytes {
			out.Headers[i].Value = out.Headers[i].Value[:maxHeaderValueBytes]
			truncated = true
		}
	}

	// Cookie name/value bounds: truncate.
	for i := range out.Cookies {
		if len(out.Cookies[i].Name) > maxCookieNameBytes {
			out.Cookies[i].Name = out.Cookies[i].Name[:maxCookieNameBytes]
			truncated = true
		}
		if len(out.Cookies[i].Value) > maxCookieValueBytes {
			out.Cookies[i].Value = out.Cookies[i].Value[:maxCookieValueBytes]
			truncated = true
		}
	}

	// TLS / DNS list bounds: truncate.
	if out.TLS != nil {
		t := *out.TLS
		if len(t.ALPN) > maxTLSEntries {
			t.ALPN = t.ALPN[:maxTLSEntries]
			truncated = true
		}
		if len(t.DNSNames) > maxTLSEntries {
			t.DNSNames = t.DNSNames[:maxTLSEntries]
			truncated = true
		}
		out.TLS = &t
	}
	if out.DNS != nil {
		d := *out.DNS
		if len(d.CNAMEChain) > maxCNAMEChain {
			d.CNAMEChain = d.CNAMEChain[:maxCNAMEChain]
			truncated = true
		}
		out.DNS = &d
	}

	if out.Source == "" {
		out.Source = defaultSourceName
	}
	if out.ObservedAt.IsZero() {
		out.ObservedAt = now
	}
	out.ObservedAt = out.ObservedAt.UTC()
	return out, truncated, nil
}

// validateObservationURL re-validates a caller-composed URL asset: it must
// re-parse through the Phase 2 model to EXACTLY its own identity. A zero or
// hand-built non-canonical URL is malformed, never analyzed. The canonical
// string is bounded at maxCanonicalURLLen BEFORE the re-parse, so an
// oversized canonical URL is rejected without parser work.
func validateObservationURL(u asset.URL) error {
	if n := len(u.String()); n > maxCanonicalURLLen {
		return fmt.Errorf("observation canonical URL is %d bytes, exceeding cap %d", n, maxCanonicalURLLen)
	}
	parsed, err := asset.ParseURL(u.String(), u.Prov)
	if err != nil {
		return fmt.Errorf("observation URL %q does not parse: %w", u.String(), err)
	}
	if parsed.String() != u.String() {
		return fmt.Errorf("observation URL %q is not in canonical form (normalized to %q)", u.String(), parsed.String())
	}
	if parsed.Identity() != u.Identity() {
		return fmt.Errorf("observation URL identity %q does not match its canonical form %q",
			u.Identity().String(), parsed.Identity().String())
	}
	return nil
}

// validateObservationEndpoint re-validates a caller-composed endpoint: it
// must re-parse canonically (method charset, URL identity) and its URL must
// be the observation's URL — an endpoint for a different URL is malformed.
func validateObservationEndpoint(ep asset.Endpoint, u asset.URL) error {
	parsed, err := asset.NewEndpoint(ep.Method, ep.URL.String(), ep.Prov)
	if err != nil {
		return fmt.Errorf("observation endpoint %s %s does not validate: %w", ep.Method, ep.URL.String(), err)
	}
	if parsed.Identity() != ep.Identity() {
		return fmt.Errorf("observation endpoint is not in canonical form")
	}
	if ep.URL.Identity() != u.Identity() {
		return fmt.Errorf("observation endpoint URL %q differs from the observation URL %q",
			ep.URL.Identity().String(), u.Identity().String())
	}
	return nil
}

// sourcesMask derives the result-relevant sources bitmask for one
// observation: the sorted letters of the observation families that were
// present. The mask enters the cache key, so a body-ful observation and a
// headers-only observation of the same target are never served each other's
// results. Letters are sorted, so equivalent observations always produce the
// same mask:
//
//	'c' cookies observed   'd' DNS observed   'e' endpoint attached
//	'h' headers observed   'b' body observed  't' TLS observed
//
// The status code is deliberately NOT part of the mask: no indicator kind
// analyzes it, so it cannot change a result.
func sourcesMask(o Observation) string {
	mask := make([]byte, 0, 6)
	if len(o.Headers) > 0 {
		mask = append(mask, 'h')
	}
	if o.Body != "" {
		mask = append(mask, 'b')
	}
	if len(o.Cookies) > 0 {
		mask = append(mask, 'c')
	}
	if o.TLS != nil {
		mask = append(mask, 't')
	}
	if o.DNS != nil {
		mask = append(mask, 'd')
	}
	if o.Endpoint != nil {
		mask = append(mask, 'e')
	}
	// The append order above is NOT sorted (h, b, c, t, d, e); the insertion
	// sort below is the guarantee of the deterministic order ('b' < 'c' <
	// 'd' < 'e' < 'h' < 't'), so equivalent observations always produce the
	// same mask regardless of how the appends are ordered.
	for i := 1; i < len(mask); i++ {
		for j := i; j > 0 && mask[j] < mask[j-1]; j-- {
			mask[j], mask[j-1] = mask[j-1], mask[j]
		}
	}
	return string(mask)
}

func maskHas(mask string, c byte) bool { return strings.IndexByte(mask, c) >= 0 }
