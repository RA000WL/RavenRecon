package httpprobe

import "strings"

// redactedCookieValue is the placeholder every Set-Cookie pair value is
// replaced with at header retention time.
const redactedCookieValue = "[redacted]"

// setCookieHeader is the canonical http.Header key whose values carry cookie
// pairs; only these values are value-redacted by boundedHeaders.
const setCookieHeader = "Set-Cookie"

// redactSetCookieValues returns a copy of vals with every Set-Cookie value
// passed through redactSetCookieValue. The observed header map is never
// mutated.
func redactSetCookieValues(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = redactSetCookieValue(v)
	}
	return out
}

// redactSetCookieValue masks the secret-bearing part of one Set-Cookie
// header value while preserving everything technology detection keys on:
//
//   - every "name=value" segment keeps its name (byte-for-byte, including
//     surrounding whitespace) and has its whole value replaced with
//     "[redacted]" — this covers the real cookie AND valued attributes,
//   - bare attributes ("HttpOnly", "Secure") are kept verbatim,
//   - empty values stay empty ("sid=" remains "sid=").
//
// Worked example:
//
//	sessionid=SECRET123; HttpOnly; Path=/; SameSite=Lax
//	→ sessionid=[redacted]; HttpOnly; Path=[redacted]; SameSite=[redacted]
//
// Segments are split at ';' boundaries OUTSIDE quoted values (mirroring the
// techintel analyzer's Set-Cookie parser), so a quoted ';' never tears a
// segment and a quoted value — including any ';' it contains — is swallowed
// whole into the placeholder. Quote characters are part of the value and are
// redacted with it ("tok=\"a;b\"" → "tok=[redacted]").
//
// Cookie NAMES must survive because technology fingerprints match cookies by
// name (__cf_bm, cf_clearance, PHPSESSID, sessionid, ...): destroying names
// would regress detection, while retaining values would retain session
// credentials.
func redactSetCookieValue(v string) string {
	segs := splitSetCookieSegments(v)
	out := make([]string, len(segs))
	for i, seg := range segs {
		out[i] = redactCookieSegment(seg)
	}
	return strings.Join(out, ";")
}

// redactCookieSegment transforms one Set-Cookie segment: everything from the
// first '=' on becomes the placeholder unless the segment carries no '=' (a
// bare attribute, kept verbatim) or the value is empty (kept empty).
func redactCookieSegment(seg string) string {
	i := strings.IndexByte(seg, '=')
	if i < 0 {
		return seg // bare attribute: no value to redact
	}
	if seg[i+1:] == "" {
		return seg // empty value stays empty
	}
	return seg[:i+1] + redactedCookieValue
}

// splitSetCookieSegments splits a Set-Cookie value at ';' boundaries outside
// quoted values: quotes toggle on every '"' byte (cookie attribute values
// have no escape mechanism), so a ';' inside quotes stays inside its
// segment. This mirrors the techintel analyzer's Set-Cookie segmentation so
// that a redacted header re-parses into exactly the segments the writer saw.
func splitSetCookieSegments(v string) []string {
	var parts []string
	start := 0
	inQuote := false
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				parts = append(parts, v[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, v[start:])
}

// storedSetCookieValuesRedacted reports whether every Set-Cookie value in
// vals is exactly what redactSetCookieValue would have retained: every
// "name=value" segment carries either an empty or a "[redacted]" value,
// under the same quote-aware segmentation. It is the read-side self-heal
// predicate: a cached record written before redaction (or tampered with)
// still carries verbatim pair values and must be refused and recomputed
// instead of served.
func storedSetCookieValuesRedacted(vals []string) bool {
	for _, v := range vals {
		for _, seg := range splitSetCookieSegments(v) {
			i := strings.IndexByte(seg, '=')
			if i < 0 {
				continue // bare attribute
			}
			switch seg[i+1:] {
			case "", redactedCookieValue:
				// compliant: nothing retained beyond the placeholder
			default:
				return false
			}
		}
	}
	return true
}
