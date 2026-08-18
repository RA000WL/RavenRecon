package httpprobe

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// validateScope re-validates the declared target domain at the pipeline
// boundary. Probe receives an asset.Domain that is normally produced by
// asset.NewDomain, but a hand-built struct literal could bypass normalization
// and reach validation or cache keys; this check refuses such values up front.
// Defense-in-depth: the caller is expected to normalize before calling.
func validateScope(domain asset.Domain) error {
	got, err := asset.NewDomain(domain.Name, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("httpprobe: invalid target domain %q: %w", domain.Name, err)
	}
	if got.Name != domain.Name {
		return fmt.Errorf("httpprobe: target domain %q is not in canonical form (normalized %q)", domain.Name, got.Name)
	}
	return nil
}

// validateInputHost re-validates one input host: it must be a canonical Phase
// 2 host (asset.NewHost must accept it and its Name must already be the
// canonical form — raw user input, uppercase, trailing dots, IP literals, and
// hand-built struct literals are all rejected) and it must be the target
// domain itself or a subdomain of it. This is the probing boundary: the
// package probes exactly the validated in-scope inputs, never arbitrary host
// lists. The whole input list is rejected before a single request is issued.
func validateInputHost(h asset.Host, domain asset.Domain) error {
	got, err := asset.NewHost(h.Name, h.Prov)
	if err != nil {
		return fmt.Errorf("httpprobe: invalid host %q: %w", h.Name, err)
	}
	if got.Name != h.Name {
		return fmt.Errorf("httpprobe: host %q is not in canonical form (normalized %q)", h.Name, got.Name)
	}
	if got.Name != domain.Name && !strings.HasSuffix(got.Name, "."+domain.Name) {
		return fmt.Errorf("httpprobe: host %q is outside target domain %q", got.Name, domain.Name)
	}
	return nil
}

// inDomain reports whether name is the domain itself or a subdomain of it.
// Both arguments must already be canonical.
func inDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// RedirectHop is one observed Location target in a probe's redirect chain.
//
// In-scope targets (the Location host is the declared domain or a subdomain
// of it) are normalized through the Phase 2 asset model and recorded as typed
// URLs; they may be followed, up to MaxRedirects hops. Out-of-scope targets
// are recorded as canonicalized strings and NEVER requested. A hop with
// InScope true and Followed false is the hop that exceeded the redirect cap:
// it was observed from the last response's Location header but never
// requested.
type RedirectHop struct {
	// Target is the hop target: the canonical URL string for in-scope hops
	// (identical to URL.String()), or the canonicalized target string for
	// out-of-scope hops (best-effort display form: lowercase scheme/host,
	// default port removed, IPv6 literals unmapped, fragment and userinfo
	// dropped — never parsed back into the asset model and never requested).
	Target string `json:"target"`

	// URL is the typed Phase 2 URL asset for in-scope hops; zero for
	// out-of-scope hops.
	URL asset.URL `json:"url,omitempty"`

	// InScope reports whether the target stayed inside the target domain.
	InScope bool `json:"in_scope,omitempty"`

	// Followed reports whether the hop was actually requested. It is true
	// for in-scope hops under the redirect cap and false for the final
	// observed hop (out-of-scope, or the cap-exceeding hop).
	Followed bool `json:"followed,omitempty"`
}

// recordHop resolves a Location header value against the URL it came from
// (cur) and classifies the target: in-scope targets are normalized through
// asset.ParseURL and may be followed; everything else is recorded as a
// canonicalized string and never requested. It returns the hop and whether
// the target is in-scope.
func recordHop(cur asset.URL, loc string, domain asset.Domain, clock runtime.Clock) (RedirectHop, bool) {
	base, err := url.Parse(cur.String())
	if err != nil {
		// A canonical asset URL always parses; keep the defensive path.
		// Never echo the raw Location: url.Parse rejects control bytes, so
		// a raw string that fails here is sanitized (userinfo and control
		// bytes stripped) and never followed.
		return RedirectHop{Target: sanitizeLocation(loc), InScope: false}, false
	}
	ref, err := url.Parse(loc)
	if err != nil {
		// Unparseable Location — for example an out-of-range port with
		// embedded userinfo (http://user:supersecret@evil.net:99999/x):
		// observed in sanitized form, never requested, and NEVER echoed
		// verbatim into observations, reports, or cache records.
		return RedirectHop{Target: sanitizeLocation(loc), InScope: false}, false
	}
	resolved := base.ResolveReference(ref)

	// Scope check on the canonical host: a trailing root dot is stripped
	// (asset.ParseURL normalizes it away for the followed URL) and IP
	// literals are never in scope — a redirect into an address is an
	// out-of-scope observation by construction, which also prevents
	// redirect-driven rebinding to arbitrary addresses.
	if host := canonicalScopeHost(resolved.Hostname()); host != "" && inDomain(host, domain.Name) {
		u, err := asset.ParseURL(resolved.String(), asset.Provenance{
			Source:       "http-probe",
			DiscoveredAt: clock.Now().UTC(),
		})
		if err != nil {
			// In-domain per hostname but not canonicalizable (for example an
			// out-of-range port in the Location): observed, never followed.
			return RedirectHop{Target: canonicalizeTarget(resolved), InScope: false}, false
		}
		// Credential redaction at the observation boundary: asset.URL.Original
		// preserves userinfo by design, and stored observations marshal
		// Original into the report AND the on-disk cache record — so a
		// hostile in-scope Location like
		// http://user:supersecret@www.example.com/b must never survive.
		// Rebuilding through the canonical string drops the userinfo: the
		// resulting asset's Original equals its canonical form. This is the
		// single construction point where a Location-derived string becomes
		// an asset.URL (FinalURL and every followed hop derive from this
		// value), so redacting here redacts every observation path.
		u, err = asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			// Cannot happen for a canonical asset URL; keep the defensive
			// path: observe without following.
			return RedirectHop{Target: u.String(), InScope: false}, false
		}
		return RedirectHop{Target: u.String(), URL: u, InScope: true}, true
	}
	return RedirectHop{Target: canonicalizeTarget(resolved), InScope: false}, false
}

// canonicalScopeHost returns the canonical form of a Location host for the
// scope check: lowercase (url.Parse already lowercases), one trailing root
// dot stripped, IP literals rejected (empty). The empty string means "never
// in scope".
func canonicalScopeHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "" // IP literals are never in scope
	}
	return host
}

// isDefaultPort reports whether port is the default port for scheme
// ("http":80, "https":443). Mirrors the asset model's own default-port rule
// for the display-form canonicalizer.
func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	}
	return false
}

// canonicalizeTarget renders a resolved out-of-scope redirect target in a
// best-effort canonical display form: lowercase scheme and host, default port
// removed, IPv6 literals unmapped (IPv4-mapped IPv6 rewritten to IPv4), path
// preserved verbatim, query preserved verbatim, fragment dropped. Userinfo is
// deliberately dropped so credentials in a hostile Location header can never
// be echoed into observations or logs. The string is display data only: it is
// never parsed back into the asset model and never requested.
func canonicalizeTarget(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	port := u.Port()
	if isDefaultPort(scheme, port) {
		port = ""
	}
	hostport := host
	if port != "" {
		hostport += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + hostport + path
	if q := u.RawQuery; q != "" {
		out += "?" + q
	}
	return out
}

// sanitizeLocation renders an UNPARSEABLE Location header value as a safe
// observation string. The raw header is never returned as a target: control
// bytes are stripped, userinfo is stripped (credentials in a hostile
// Location must never be echoed), and when the sanitized result parses it is
// canonicalized through canonicalizeTarget (the same display form used for
// parseable out-of-scope hops). When even the sanitized string does not
// parse — for example an out-of-range port — the sanitized string itself is
// the best-effort display form. The result is display data only: it is never
// parsed back into the asset model and never requested.
func sanitizeLocation(loc string) string {
	// Strip control bytes first so no raw server byte can survive into an
	// observation, a report, or a cache record.
	var b strings.Builder
	b.Grow(len(loc))
	for i := 0; i < len(loc); i++ {
		if c := loc[i]; c >= 0x20 && c != 0x7f {
			b.WriteByte(c)
		}
	}
	clean := stripLocationUserinfo(b.String())
	if u, err := url.Parse(clean); err == nil {
		return canonicalizeTarget(u)
	}
	return clean
}

// stripLocationUserinfo removes the userinfo part of a URL string: anything
// between the scheme separator "://" and the last '@' that precedes the
// first '/', '?' or '#'. The '@' separator itself is removed with it, so
// credentials (user and password) can never be echoed. A string without
// "://" has no authority to carry userinfo and is returned unchanged, as is
// a string whose only '@' characters sit in the path, query, or fragment.
func stripLocationUserinfo(s string) string {
	schemeEnd := strings.Index(s, "://")
	if schemeEnd < 0 {
		return s
	}
	// The authority runs from after "://" to the first '/', '?' or '#'.
	authStart := schemeEnd + 3
	authEnd := len(s)
	for _, c := range []byte{'/', '?', '#'} {
		if i := strings.IndexByte(s[authStart:], c); i >= 0 && authStart+i < authEnd {
			authEnd = authStart + i
		}
	}
	at := strings.LastIndexByte(s[authStart:authEnd], '@')
	if at < 0 {
		return s
	}
	return s[:authStart] + s[authStart+at+1:]
}
