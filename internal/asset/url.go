package asset

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// URL is a normalized absolute URL with a scheme and a host.
//
// The canonical identity keeps everything that is security-relevant while
// discarding detail the destination server cannot or does not distinguish:
//
//   - the scheme is lowercased
//   - the host is lowercased, a trailing root dot is removed, and IP literals
//     are rewritten in canonical form
//   - IPv6 zone identifiers are stripped ("fe80::1%eth0" canonicalizes to
//     "fe80::1"): a zone is link-local scope metadata naming the observing
//     interface, not part of the remote endpoint's identity
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

// maxRawURLBytes bounds the raw input ParseURL accepts, mirroring the
// identity-bounding discipline of the sibling types (parameter.go's name
// bound, evidence.go's indicator bound): without it, an unbounded Path or
// RawQuery would flow into Identity().Value and every downstream consumer
// of that identity. 8 KiB is far above any legitimate observed request
// target while keeping canonical identities bounded.
const maxRawURLBytes = 8 * 1024

// ParseURL parses and canonicalizes raw into a URL asset.
func ParseURL(raw string, p Provenance) (URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URL{}, fmt.Errorf("URL must not be empty")
	}
	if len(raw) > maxRawURLBytes {
		return URL{}, fmt.Errorf("URL exceeds %d bytes (got %d)", maxRawURLBytes, len(raw))
	}
	if !utf8.ValidString(raw) {
		return URL{}, fmt.Errorf("invalid URL %q: must be valid UTF-8", redactURLForError(raw))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL %q: %w", redactURLForError(raw), err)
	}
	if u.Scheme == "" {
		return URL{}, fmt.Errorf("invalid URL %q: missing scheme", redactURLForError(raw))
	}
	if !validScheme(u.Scheme) {
		return URL{}, fmt.Errorf("invalid URL %q: invalid scheme %q", redactURLForError(raw), u.Scheme)
	}
	if u.Host == "" {
		return URL{}, fmt.Errorf("invalid URL %q: missing host", redactURLForError(raw))
	}

	canonical, err := canonicalURL(u)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL %q: %w", redactURLForError(raw), err)
	}
	canonical.Original = raw
	canonical.Prov = p
	return canonical, nil
}

// redactURLForError returns a redacted form of raw suitable for error messages.
// It parses raw with url.Parse, clears any userinfo, and returns scheme+host
// or a redacted fallback. This prevents credentials from leaking in errors.
func redactURLForError(raw string) string {
	u, err := url.Parse(raw)
	if err == nil {
		u.User = nil
		if u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
		if u.Host != "" {
			return u.Host
		}
		s := u.String()
		if s != "" {
			return s
		}
	}
	// Fallback: strip userinfo manually.
	if idx := strings.Index(raw, "://"); idx >= 0 {
		rest := raw[idx+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			return raw[:idx+3] + rest[at+1:]
		}
	}
	if idx := strings.Index(raw, "@"); idx >= 0 {
		return "[redacted]@" + raw[idx+1:]
	}
	if len(raw) > 256 {
		return raw[:256] + "…"
	}
	return raw
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

// validScheme reports whether s is a syntactically valid RFC 3986 scheme:
// one leading ASCII letter, then letters, digits, '+', '-', or '.'. It is a
// deliberately open policy: there is no scheme allowlist, so any
// well-formed scheme token — http, https, ws, wss, gopher, ftp, ... — is
// accepted. The real policy gate is the host requirement enforced by
// ParseURL immediately after this check: every URL asset must carry a
// host, so hostless schemes such as data: and javascript: are rejected
// downstream by the empty-host error even though their scheme tokens are
// valid here. Default-port knowledge lives in isDefaultPort; unknown
// schemes simply never have a default port.
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
	// IPv6 zone identifiers ("%25eth0" in a URL) are stripped deliberately:
	// a zone names the local interface that observed the link-local address,
	// so keeping it would make the asset identity environment-dependent
	// ("[fe80::1%eth0]" on one machine vs "[fe80::1%wlan0]" on another).
	// The remote endpoint's identity is the address alone.
	if strings.Contains(u.Host, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return URL{}, fmt.Errorf("invalid IPv6 literal host %q", u.Host)
		}
		host = addr.WithZone("").Unmap().String()
	} else {
		host = strings.ToLower(host)
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return URL{}, fmt.Errorf("host must not be empty")
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.WithZone("").Unmap().String()
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
	// Validate raw query key/value are valid UTF-8 before canonicalization.
	// Invalid UTF-8 would cause json.Marshal to emit U+FFFD drift, breaking
	// ID stability across JSON round-trips.
	if u.RawQuery != "" {
		for _, pair := range strings.Split(u.RawQuery, "&") {
			if pair == "" {
				continue
			}
			k, v, _ := strings.Cut(pair, "=")
			if !utf8.ValidString(k) {
				return URL{}, fmt.Errorf("query key contains invalid UTF-8")
			}
			if !utf8.ValidString(v) {
				return URL{}, fmt.Errorf("query value contains invalid UTF-8")
			}
		}
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
		// Sort by the decode of the EMITTED key form, not of the raw key:
		// emission (escapeRawQuery) rewrites ' ', '#', '&', '=' to their
		// %XX forms, and every later parse sees the emitted form, so
		// decoding exactly that form keeps each pair's sort key identical
		// across re-canonicalization and makes the canonical query a fixed
		// point. Sorting by the raw key's decode instead let a key with an
		// invalid percent escape (e.g. " %0") decode differently after
		// emission, flipping its order against other keys and changing the
		// URL identity on re-parse (found by FuzzParseURL). For keys without
		// invalid escapes this is value-identical to decoding the raw key:
		// escapeRawQuery only rewrites the four bytes that QueryUnescape
		// decodes back to themselves ("%20"/"%23"/"%26"/"%3D").
		emittedKey := escapeRawQuery(k)
		dk, err := url.QueryUnescape(emittedKey)
		if err != nil {
			dk = emittedKey
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
// '=' -> "%3D", and any byte >=0x80 (non-ASCII). Everything else is emitted
// verbatim, so already-escaped forms such as "%26" or "%20" are never
// double-escaped. Encoding bytes >=0x80 ensures the canonical query never
// contains raw non-ASCII bytes, preserving valid UTF-8 for JSON stability.
func escapeRawQuery(s string) string {
	needEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '#' || c == '&' || c == '=' || c >= 0x80 {
			needEscape = true
			break
		}
	}
	if !needEscape {
		return s
	}
	const hexDigit = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ':
			b.WriteString("%20")
		case '#':
			b.WriteString("%23")
		case '&':
			b.WriteString("%26")
		case '=':
			b.WriteString("%3D")
		default:
			if c >= 0x80 {
				b.WriteByte('%')
				b.WriteByte(hexDigit[c>>4])
				b.WriteByte(hexDigit[c&0x0f])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
