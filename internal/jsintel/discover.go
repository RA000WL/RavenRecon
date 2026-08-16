// Input normalization: raw lines and HTML observations become canonical
// candidate URLs. Everything here is bounded (attribute caps, tag/header
// entry caps, body truncation), deterministic, and never panics.
package jsintel

import (
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// maxAttrValueBytes bounds ONE scanned attribute value in an HTML tag and
// the inline scan for the matching quote. Longer values are cut at the cap
// (the remainder of the tag is scanned as further attributes), so a hostile
// page can never force unbounded scanning work.
const maxAttrValueBytes = 4096

// maxLinkHeaderEntries bounds how many Link header entries one header value
// contributes. Entries beyond the cap are ignored.
const maxLinkHeaderEntries = 32

// maxLinkHeaderEntryBytes bounds one Link header entry. Entries longer than
// the cap are skipped (bounded scanning work on hostile headers).
const maxLinkHeaderEntryBytes = 4096

// maxLineSecretValueBytes bounds ONE line-secret value (the right side of a
// secretfinder "name\t->\tvalue" line) — the same 4096 the parser applies to
// every retained literal and import specifier (maxParserStringBytes), so no
// observation can smuggle a longer value past the seam. A line whose value
// exceeds the cap is dropped and counted, never ingested.
const maxLineSecretValueBytes = 4096

// secretLineTypes maps secretfinder's match-line NAME (the left side of
// "name\t->\tvalue", matched lowercased and trimmed) to the asset
// SecretType. This is the documented D2 type-mapping table; a name outside
// the table maps to generic (secretLineType), so a recognized secret line
// ALWAYS yields a typed candidate — the seam never drops a line for an
// unknown name.
var secretLineTypes = map[string]asset.SecretType{
	"google_api":               asset.SecretTypeGoogle,
	"google_api_key":           asset.SecretTypeGoogle,
	"json_web_token":           asset.SecretTypeJWT,
	"amazon_aws_access_key_id": asset.SecretTypeAWS,
	"aws_access_key_id":        asset.SecretTypeAWS,
	"aws_secret_access_key":    asset.SecretTypeAWS,
	"firebase":                 asset.SecretTypeFirebase,
	"firebase_api_key":         asset.SecretTypeFirebase,
	"stripe":                   asset.SecretTypeStripe,
	"stripe_secret_key":        asset.SecretTypeStripe,
	"github":                   asset.SecretTypeGitHub,
	"github_token":             asset.SecretTypeGitHub,
	"private_key":              asset.SecretTypePrivateKey,
	"bearer":                   asset.SecretTypeBearer,
	"possible_creds":           asset.SecretTypeGeneric,
	"custom_regex":             asset.SecretTypeGeneric,
	"default":                  asset.SecretTypeGeneric,
}

// secretLineType maps a match-line name to its SecretType via
// secretLineTypes; every name outside the table maps to generic.
func secretLineType(name string) asset.SecretType {
	if t, ok := secretLineTypes[strings.ToLower(name)]; ok {
		return t
	}
	return asset.SecretTypeGeneric
}

// lineSecret is the typed payload of ONE secretfinder "name\t->\tvalue"
// line. The value is the bounded right side; an empty or overlong value
// marks the line DROPPED (counted by the caller, never ingested) — the
// recognition itself is still reported so the raw-line (SecretLines) count
// stays exact.
type lineSecret struct {
	typ     asset.SecretType
	value   string
	at      time.Time // arrival time (run clock): observation window + provenance
	dropped bool      // empty or overlong value: counted, never ingested
}

// parseLine normalizes ONE raw input line into candidate URLs.
//
// Forms, in order:
//
//   - empty (after trimming) → nothing;
//   - a secretfinder "name\t->\tvalue" line (contains "\t->\t", detected
//     on the raw line BEFORE trimming so an empty value is still
//     recognized) → a typed lineSecret: the name maps through
//     secretLineTypes (names outside the table map to generic) and the
//     value is the bounded right side (a line whose value is empty or
//     longer than maxLineSecretValueBytes is DROPPED inside the returned
//     secret — counted by the caller, never ingested). A secret line
//     never produces a candidate URL: its payload is ingested against
//     the current "[ + ] URL:" context by the engine;
//   - the "[ + ] URL: <u>" progress form → the <u> part (a trailing
//     missing-bracket form tolerates the bare remainder) resolves like any
//     other URL candidate, and the resolved URL is ALSO surfaced as the
//     `progress` value: the caller tracks it as the current URL context for
//     later line-secrets;
//   - the remaining text is a URL candidate when it resolves through the
//     shared resolver: an absolute http(s) URL always resolves; a
//     protocol-relative, root-relative, or relative reference resolves only
//     when cfg.Base is set (relative line items need a base to resolve
//     against — zero Base means such lines are malformed). Bare text
//     ("react") has no URL meaning on a line and counts malformed.
//
// Returns the resolved candidates, the malformed count, the line's secret
// payload (nil for non-secret lines), and the surfaced progress URL (the
// zero URL for non-progress lines). (The secret and progress returns are
// extensions of the documented two-value shape: the metric count and the
// current-URL context must be observable by the caller, and duplicating the
// detection logic in the caller would let the sites drift.)
func parseLine(cfg Config, line string) (candidates []asset.URL, malformed int, secret *lineSecret, progress asset.URL) {
	// Secret lines are detected on the RAW line, before TrimSpace: the
	// separator is "\t->\t", and a line whose value is empty
	// ("name\t->\t" — trimmed to "name\t->" by TrimSpace) must still be
	// recognized so it is counted as a secret and dropped, never
	// mistaken for a URL candidate.
	if i := strings.Index(line, "\t->\t"); i >= 0 {
		name := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+len("\t->\t"):])
		sec := &lineSecret{typ: secretLineType(name), value: value}
		if value == "" || len(value) > maxLineSecretValueBytes {
			sec.dropped = true
		}
		return nil, 0, sec, asset.URL{}
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, 0, nil, asset.URL{}
	}
	isProgress := false
	if strings.HasPrefix(line, "[ + ] URL: ") {
		rest := strings.TrimPrefix(line, "[ + ] URL: ")
		if strings.HasPrefix(rest, "<") && strings.HasSuffix(rest, ">") && len(rest) >= 2 {
			line = rest[1 : len(rest)-1]
		} else {
			line = rest
		}
		line = strings.TrimSpace(line)
		isProgress = true
	}
	u, resolved, _ := resolveRef(cfg.Base, line)
	if !resolved {
		return nil, 1, nil, asset.URL{}
	}
	if isProgress {
		progress = u
	}
	return []asset.URL{u}, 0, nil, progress
}

// parseHTML normalizes ONE HTML observation into candidate URLs: script
// src attributes, qualifying link hrefs, qualifying Link response headers,
// and the static/dynamic imports of inline (src-less) script blocks. The
// body is truncated to MaxHTMLBody if a caller constructed an oversized
// Item directly (defense; the engine truncates at ingest and counts).
// item.URL is the page the observation came from: the resolution base.
//
// Returns the resolved candidates, the malformed count (references that
// could not resolve), and the count of candidates dropped by the
// MaxHTMLScripts per-observation cap. (The drop count is an extension of
// the documented two-value shape so the engine can report caps through the
// Skipped metric.)
func parseHTML(item Item, parser Parser, maxScripts int) (candidates []asset.URL, malformed int, dropped int) {
	if item.URL.Scheme == "" {
		// No page URL: nothing can resolve. The observation is unusable.
		return nil, 0, 0
	}
	body := item.Body
	if len(body) > MaxHTMLBody {
		body = body[:MaxHTMLBody]
	}
	lower := strings.ToLower(body)

	pos := 0
	for {
		tagAt, isScript, ok := findNextTag(lower, pos)
		if !ok {
			break
		}
		nameLen := len("<link")
		if isScript {
			nameLen = len("<script")
		}
		nameEnd := tagAt + nameLen
		// A tag-name boundary: "<scriptx" is not a script tag. The char
		// after the name must be whitespace, '/', '>', or end-of-body.
		if nameEnd < len(lower) {
			c := lower[nameEnd]
			if !isSpace(c) && c != '/' && c != '>' {
				pos = tagAt + 1
				continue
			}
		}
		attrs, end, closed := scanTagAttrs(body, nameEnd)
		if !closed {
			// No '>' anywhere: nothing more can be scanned.
			break
		}
		tagEnd := end + 1

		if isScript {
			src, hasSrc := attrs["src"]
			if hasSrc {
				if u, ok := resolveHTMLRef(item.URL, src); ok {
					candidates, dropped = addCandidate(candidates, u, maxScripts, dropped)
				} else {
					malformed++
				}
				// An external script carries no markup body: continue
				// scanning from the tag end. When the src value was cut by
				// the attribute cap (hostile input), the region between
				// '>' and the eventual "</script>" may contain further
				// real tags — skipping straight to "</script>" would
				// swallow them.
				pos = tagEnd
				continue
			}
			// Inline script without src: its body is not markup — advance
			// past the closing </script> (or to the end when the block is
			// unterminated) so script text is never tag-scanned.
			closeAt := strings.Index(lower[tagEnd:], "</script")
			var inline string
			if closeAt >= 0 {
				inline = body[tagEnd : tagEnd+closeAt]
				pos = tagEnd + closeAt + len("</script")
			} else {
				inline = body[tagEnd:]
				pos = len(body)
			}
			// The inline body's imports are candidates resolved against
			// the page URL (import specifier semantics: bare specifiers
			// are dropped — they have no page-relative meaning — and
			// unsupported schemes count malformed).
			parsed, perr := parser.Parse([]byte(inline))
			if perr == nil {
				for _, imp := range parsed.Imports {
					if imp.Specifier == "" {
						continue
					}
					u, resolved, bare := resolveImport(item.URL, imp.Specifier)
					if !resolved {
						if !bare {
							malformed++
						}
						continue
					}
					candidates, dropped = addCandidate(candidates, u, maxScripts, dropped)
				}
			}
			continue
		}

		// Link tag: qualifying rel (modulepreload, or preload/prefetch
		// with as=script) turns href into a candidate. Non-qualifying
		// links are legitimate observations, skipped without counting.
		pos = tagEnd
		if href, has := attrs["href"]; has && linkQualifies(strings.Fields(attrs["rel"]), attrs["as"]) {
			if u, ok := resolveHTMLRef(item.URL, href); ok {
				candidates, dropped = addCandidate(candidates, u, maxScripts, dropped)
			} else {
				malformed++
			}
		}
	}

	for _, h := range item.Headers {
		if !strings.EqualFold(h.Name, "Link") {
			continue
		}
		for _, href := range parseLinkHeader(h.Value) {
			if u, ok := resolveHTMLRef(item.URL, href); ok {
				candidates, dropped = addCandidate(candidates, u, maxScripts, dropped)
			} else {
				malformed++
			}
		}
	}
	return candidates, malformed, dropped
}

// findNextTag locates the next "<script" or "<link" at or after pos,
// returning the earlier one. A "<script" hit is reported as a script tag
// only when the name is properly bounded (the char after "script" is
// whitespace, '/', '>', or end-of-body): "<scriptx" is not a script tag and
// is reported with isScript=false so the caller's boundary re-check skips
// it. ok is false when neither prefix occurs.
func findNextTag(lower string, pos int) (tagAt int, isScript bool, ok bool) {
	si := strings.Index(lower[pos:], "<script")
	li := strings.Index(lower[pos:], "<link")
	switch {
	case si < 0 && li < 0:
		return 0, false, false
	case si < 0:
		return pos + li, false, true
	case li < 0 || si < li:
		at := pos + si
		// Tag-name boundary: "script" must be followed by whitespace, '/',
		// '>', or end-of-body — "<scriptx" is not a script tag.
		nameEnd := at + len("<script")
		if nameEnd < len(lower) {
			c := lower[nameEnd]
			if !isSpace(c) && c != '/' && c != '>' {
				return at, false, true
			}
		}
		return at, true, true
	default:
		return pos + li, false, true
	}
}

// scanTagAttrs parses the attributes of the tag body starting at nameEnd
// (just past the tag name) up to the closing '>'. Attribute names are
// lowercased; values are single-, double-, or unquoted and bounded to
// maxAttrValueBytes. Returns the attribute map, the index of the closing
// '>' (len(body) when unterminated), and whether the tag terminated.
func scanTagAttrs(body string, nameEnd int) (attrs map[string]string, end int, ok bool) {
	attrs = make(map[string]string)
	i := nameEnd
	for i < len(body) {
		for i < len(body) && isSpace(body[i]) {
			i++
		}
		if i >= len(body) {
			return attrs, len(body), false
		}
		if body[i] == '>' {
			return attrs, i, true
		}
		if body[i] == '/' && i+1 < len(body) && body[i+1] == '>' {
			return attrs, i + 1, true
		}
		start := i
		for i < len(body) && !isSpace(body[i]) && body[i] != '>' && body[i] != '=' && body[i] != '/' {
			i++
		}
		name := strings.ToLower(body[start:i])
		j := i
		for j < len(body) && isSpace(body[j]) {
			j++
		}
		if j < len(body) && body[j] == '=' {
			j++
			for j < len(body) && isSpace(body[j]) {
				j++
			}
			if j < len(body) && (body[j] == '"' || body[j] == '\'') {
				q := body[j]
				j++
				vstart := j
				for j < len(body) && body[j] != q && j-vstart < maxAttrValueBytes {
					j++
				}
				value := body[vstart:j]
				if j < len(body) && body[j] == q {
					j++
				}
				if name != "" {
					attrs[name] = value
				}
				i = j
			} else {
				vstart := j
				for j < len(body) && !isSpace(body[j]) && body[j] != '>' && j-vstart < maxAttrValueBytes {
					j++
				}
				if name != "" {
					attrs[name] = body[vstart:j]
				}
				i = j
			}
		} else {
			if name != "" {
				attrs[name] = ""
			}
			i = j
		}
	}
	return attrs, len(body), false
}

// linkQualifies reports whether a link's rel tokens qualify as a script
// candidate: modulepreload always qualifies; preload and prefetch qualify
// only when as=script.
func linkQualifies(relTokens []string, as string) bool {
	for _, tok := range relTokens {
		switch strings.ToLower(tok) {
		case "modulepreload":
			return true
		case "preload", "prefetch":
			for _, a := range strings.Fields(strings.ToLower(as)) {
				if a == "script" {
					return true
				}
			}
		}
	}
	return false
}

// parseLinkHeader extracts the URLs of Link header entries whose rel
// qualifies (modulepreload, or preload/prefetch with as=script). Entries
// are <url>; param=value pairs separated by commas OUTSIDE angle brackets —
// a URL may itself contain a comma (<https://example.com/x,y.js>), so naive
// comma splitting would tear entries apart. Each entry's parameter segment
// runs from its '>' to the entry's end, so rel/as values never carry a
// trailing delimiter. At most maxLinkHeaderEntries entries contribute;
// entries longer than maxLinkHeaderEntryBytes are skipped; a dangling '<'
// ends the scan.
func parseLinkHeader(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var hrefs []string
	pos := 0
	entries := 0
	for pos < len(v) {
		if entries >= maxLinkHeaderEntries {
			break
		}
		end := linkEntryEnd(v, pos)
		entry := strings.TrimSpace(v[pos:end])
		entries++
		pos = end + 1 // skip the delimiter comma (or move past the end)
		if len(entry) > maxLinkHeaderEntryBytes {
			continue
		}
		lt := strings.IndexByte(entry, '<')
		if lt < 0 {
			continue
		}
		gt := strings.IndexByte(entry[lt+1:], '>')
		if gt < 0 {
			continue // dangling '<': this entry has no URL
		}
		gt += lt + 1
		url := entry[lt+1 : gt]
		rel, as := parseLinkParams(entry[gt+1:])
		if url != "" && linkQualifies(rel, as) {
			hrefs = append(hrefs, url)
		}
	}
	return hrefs
}

// linkEntryEnd returns the index of the comma ending the Link header entry
// starting at pos, or len(v) when the entry runs to the end of the value.
// Commas inside <...> (a URL may contain one) never end an entry.
func linkEntryEnd(v string, pos int) int {
	depth := 0
	for i := pos; i < len(v); i++ {
		switch v[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return len(v)
}

// parseLinkParams extracts the rel and as values from the parameter
// segment of one Link header entry (" rel=preload; as=script").
func parseLinkParams(s string) (relTokens []string, as string) {
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "rel":
			relTokens = strings.Fields(strings.ToLower(v))
		case "as":
			as = v
		}
	}
	return relTokens, as
}

// addCandidate appends u to the observation's candidates unless the
// MaxHTMLScripts per-observation cap was reached, in which case it counts a
// drop instead.
func addCandidate(candidates []asset.URL, u asset.URL, maxScripts, dropped int) ([]asset.URL, int) {
	if len(candidates) >= maxScripts {
		return candidates, dropped + 1
	}
	return append(candidates, u), dropped
}

// isSpace reports whether b is HTML whitespace.
func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}
