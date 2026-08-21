package asset

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// URL is a normalized absolute URL with a scheme and a host.
//
// The canonical identity keeps everything that is security-relevant while
// discarding detail the destination server cannot or does not distinguish:
//
//   - the scheme is lowercased
//   - the host is lowercased, a trailing root dot is removed, and IP literals
//     are rewritten in canonical form
//   - a default port for the scheme is removed; a non-default port is kept.
//     Ports are canonicalized as numbers, so ":080" and ":80" are equal
//   - an empty path is treated as "/"
//   - dot segments use server-style root-clamped resolution: "." and ".."
//     are removed, ".." never escapes the root, and "//" is never collapsed
//   - query parameters are preserved but sorted by decoded key
//   - the fragment is excluded from the identity but preserved for inspection
//   - userinfo is excluded from the identity but preserved in Original
//
// Query values are value-preserving by design: "?x=a%20b" and "?x=a+b" remain
// distinct identities even though many servers treat them identically, and a
// present-but-empty value keeps its '=' ("?x=" stays "?x=", never merged with
// the bare key "?x"). The one exception is a literal raw space, which cannot
// appear in a canonical query string and is escaped to "%20", so "?x=a b" and
// "?x=a%20b" share an identity. This errs toward splitting observations
// rather than merging distinct raw forms.
//
// Original preserves the URL exactly as first observed and may contain
// userinfo credentials (e.g. "https://user:pass@example.com/"). Consuming
// phases must redact Original before logging it or returning it in errors.
type URL struct {
	// Original preserves the URL exactly as it was first observed.
	Original string `json:"original,omitempty"`

	// Scheme is the lowercased scheme, e.g. "http".
	Scheme string `json:"scheme"`

	// HostPort is the canonical host, including a non-default port when one is
	// present, e.g. "example.com", "example.com:8080", "[2001:db8::1]".
	HostPort string `json:"hostport"`

	// Path is the canonical path. It is always non-empty ("/" for the root).
	Path string `json:"path"`

	// Query is the canonical query string with keys sorted, without a leading "?".
	Query string `json:"query,omitempty"`

	// Fragment is preserved for inspection but excluded from the identity.
	Fragment string `json:"fragment,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// ParseURL parses and canonicalizes raw into a URL asset.
func ParseURL(raw string, p Provenance) (URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URL{}, fmt.Errorf("URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return URL{}, fmt.Errorf("invalid URL %q: missing scheme", raw)
	}
	if !validScheme(u.Scheme) {
		return URL{}, fmt.Errorf("invalid URL %q: invalid scheme %q", raw, u.Scheme)
	}
	if u.Host == "" {
		return URL{}, fmt.Errorf("invalid URL %q: missing host", raw)
	}

	canonical, err := canonicalURL(u)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	canonical.Original = raw
	canonical.Prov = p
	return canonical, nil
}

// Identity returns the deterministic identity used for deduplication.
func (u URL) Identity() Identity {
	return Identity{Kind: KindURL, Value: u.canonicalString()}
}

// IsZero reports whether the URL asset is unset. The zero URL is never a
// valid observation — ParseURL always yields a scheme and a canonical host —
// so a zero URL reliably means "not observed" (for example a fetch's
// FinalURL before any request was dispatched).
func (u URL) IsZero() bool { return u == (URL{}) }

// ID returns the canonical identity string.
func (u URL) ID() string { return u.Identity().String() }

// String returns the canonical identity form of the URL.
//
// The fragment and userinfo are not part of the canonical form, matching
// what the destination server actually receives.
func (u URL) String() string { return u.canonicalString() }

func (u URL) canonicalString() string {
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(u.HostPort)
	b.WriteString(u.Path)
	if u.Query != "" {
		b.WriteByte('?')
		b.WriteString(u.Query)
	}
	return b.String()
}

func validScheme(s string) bool {
	if s == "" {
		return false
	}
	if !(s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "http", "ws":
		// ws shares http's default port (RFC 6455 section 3).
		return port == "80"
	case "https", "wss":
		// wss shares https's default port (RFC 6455 section 3).
		return port == "443"
	}
	return false
}

// canonicalURL rewrites a parsed *url.URL into canonical asset fields.
func canonicalURL(u *url.URL) (URL, error) {
	canonical := URL{Scheme: strings.ToLower(u.Scheme)}

	host := u.Hostname()
	if host == "" {
		return URL{}, fmt.Errorf("host must not be empty")
	}
	if strings.Contains(u.Host, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return URL{}, fmt.Errorf("invalid IPv6 literal host %q", u.Host)
		}
		host = addr.Unmap().String()
	} else {
		host = strings.ToLower(host)
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return URL{}, fmt.Errorf("host must not be empty")
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.Unmap().String()
		} else if err := validateHostname(host); err != nil {
			return URL{}, fmt.Errorf("invalid host: %w", err)
		}
	}

	_, ipErr := netip.ParseAddr(host)
	isIP := ipErr == nil

	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return URL{}, fmt.Errorf("invalid port %q", p)
		}
		// Canonicalize the port to its decimal form so leading zeros
		// ("080") equal the same numeric port ("80").
		port := strconv.Itoa(n)
		if !isDefaultPort(canonical.Scheme, port) {
			if isIP && strings.Contains(host, ":") {
				canonical.HostPort = "[" + host + "]:" + port
			} else {
				canonical.HostPort = host + ":" + port
			}
		}
	}
	if canonical.HostPort == "" {
		if isIP && strings.Contains(host, ":") {
			canonical.HostPort = "[" + host + "]"
		} else {
			canonical.HostPort = host
		}
	}

	canonical.Path = removeDotSegments(u.EscapedPath())
	if canonical.Path == "" {
		canonical.Path = "/"
	}
	canonical.Query = sortQuery(u.RawQuery)
	canonical.Fragment = u.Fragment

	return canonical, nil
}

// removeDotSegments applies server-style root-clamped resolution: "." and
// ".." segments are removed, ".." never escapes the root, and "//" is never
// collapsed. This intentionally differs from RFC 3986 section 5.2.4
// remove_dot_segments, which is a full state machine over the whole path
// buffer; preserving "//" is the recon-relevant property here, and path.Clean
// must not be used because it collapses "//".
func removeDotSegments(path string) string {
	var out []string
	start := 0
	if strings.HasPrefix(path, "/") {
		out = append(out, "")
		start = 1
	}
	for _, seg := range strings.Split(path[start:], "/") {
		switch seg {
		case ".":
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "/")
}

// sortQuery returns a canonical query string with parameters ordered by
// their decoded key while emitting each key and value in its original raw
// form.
//
// Sorting by the decoded key keeps the ordering deterministic and matches how
// servers typically interpret the query. Emitting the raw forms guarantees
// that distinct raw forms never collapse into the same identity ("a%26b" is a
// single key, "a&b" splits into two, and "?x=a%20b" stays distinct from
// "?x=a+b"), and that the identity never contains raw characters (such as
// '#', ' ', '&', '=') that would alter how the query is parsed: escapeRawQuery
// percent-encodes exactly those four raw bytes at emission time. Because a
// raw space is escaped to "%20", "?x=a b" and "?x=a%20b" share an identity.
//
// The '=' separator is part of the raw form: a pair that contained '=' keeps
// it even when its value is empty ("?x=" canonicalizes to "x="), so a
// present-but-empty value never collapses into the bare key ("?x" -> "x").
func sortQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type param struct {
		rawKey   string // original raw key, emitted with corrupting raw bytes escaped
		key      string // decoded key, used for ordering
		value    string
		hasValue bool // the raw pair contained '=' (a present-but-empty value)
	}
	params := make([]param, 0, 8)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, found := strings.Cut(pair, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		params = append(params, param{rawKey: k, key: dk, value: v, hasValue: found})
	}
	sort.SliceStable(params, func(i, j int) bool { return params[i].key < params[j].key })
	var b strings.Builder
	for i, prm := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(escapeRawQuery(prm.rawKey))
		if prm.hasValue {
			b.WriteByte('=')
			b.WriteString(escapeRawQuery(prm.value))
		}
	}
	return b.String()
}

// escapeRawQuery percent-encodes the literal raw bytes that would corrupt a
// canonical query string: ' ' -> "%20", '#' -> "%23", '&' -> "%26",
// '=' -> "%3D". Everything else is emitted verbatim, so already-escaped forms
// such as "%26" or "%20" are never double-escaped.
func escapeRawQuery(s string) string {
	if !strings.ContainsAny(s, " #&=") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			b.WriteString("%20")
		case '#':
			b.WriteString("%23")
		case '&':
			b.WriteString("%26")
		case '=':
			b.WriteString("%3D")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
