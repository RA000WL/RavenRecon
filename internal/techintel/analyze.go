package techintel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// HTML candidate caps bound one body pass. They are the "huge page" security
// bound on the mark-up side: a hostile page cannot make the analyzers retain
// unbounded candidate lists. Candidates beyond a cap are dropped in document
// order and the observation is flagged Truncated (the analysis is honest but
// the page is too dense to fully extract).
const (
	maxHTMLScripts    = 128
	maxHTMLCSS        = 128
	maxHTMLMetas      = 128
	maxHTMLAttributes = 256
	maxHTMLSourceMaps = 32
	maxHTMLGenerators = 16
)

// cookie flag labels for evidence-only session-flag records. The values
// follow the canonical "kind:name" indicator-key form so a consumer can
// recognize them symmetrically.
const (
	cookieFlagIndicatorHTTPOnly = "cookie_flag:httponly"
	cookieFlagIndicatorSecure   = "cookie_flag:secure"
	cookieFlagIndicatorSameSite = "cookie_flag:samesite"
)

// Overflow records which hard caps an observation hit. The observation is
// still Completed (its result is honest), but the retained set is
// incomplete: the report and records flag it so consumers never mistake a
// capped set for a full one.
type Overflow struct {
	// Technologies is set when more fingerprints fired than
	// MaxTechnologiesPerObservation: the retained set was cut to the cap in
	// deterministic order (score desc, then name).
	Technologies bool `json:"technologies,omitempty"`
	// Indicators is set when more indicator matches (evidence records,
	// including cookie-flag evidence) fired than
	// MaxIndicatorsPerObservation: the retained set was cut to the cap in
	// deterministic order (DB order, then slot order).
	Indicators bool `json:"indicators,omitempty"`
	// Cookies is set when the cookie analyzer dropped cookie entries beyond
	// maxObservationCookies.
	Cookies bool `json:"cookies,omitempty"`
}

// methodFor maps an IndicatorKind to its asset.DetectionMethod. The mapping
// is the engine-side half of the fingerprint contract; the methods are
// documented on asset.DetectionMethod.
func methodFor(k fingerprints.IndicatorKind) asset.DetectionMethod {
	switch k {
	case fingerprints.IndicatorHeader:
		return asset.MethodHeader
	case fingerprints.IndicatorCookie:
		return asset.MethodCookie
	case fingerprints.IndicatorHTMLRegex, fingerprints.IndicatorHTMLSubstring:
		return asset.MethodHTML
	case fingerprints.IndicatorGenerator:
		return asset.MethodGenerator
	case fingerprints.IndicatorMetaName:
		return asset.MethodMeta
	case fingerprints.IndicatorScriptName, fingerprints.IndicatorScriptPath:
		return asset.MethodScript
	case fingerprints.IndicatorCSSPath:
		return asset.MethodCSS
	case fingerprints.IndicatorAttribute:
		return asset.MethodAttribute
	case fingerprints.IndicatorEndpointPath:
		return asset.MethodEndpoint
	case fingerprints.IndicatorTLSIssuer, fingerprints.IndicatorTLSCN, fingerprints.IndicatorTLSALPN:
		return asset.MethodTLS
	case fingerprints.IndicatorDNSCNAME:
		return asset.MethodDNS
	case fingerprints.IndicatorSourceMapPath:
		return asset.MethodSourceMap
	}
	return ""
}

// indicatorKey is the canonical evidence indicator key for one fingerprint
// indicator: "kind:match" exactly (for example "header:server: nginx" or
// "cookie_flag:httponly"). It is part of the evidence identity.
func indicatorKey(k fingerprints.IndicatorKind, match string) string {
	return string(k) + ":" + match
}

// headerLine is one retained header entry in matchable form.
type headerLine struct {
	name  string
	value string
	line  string // "Name: value", as observed
	lower string // lowercase of line, for case-insensitive matching
}

// cookieEntry is one cookie in matchable form.
type cookieEntry struct {
	name  string
	value string
}

// cookieFlagObs records one Set-Cookie session flag observed on a cookie.
type cookieFlagObs struct {
	cookieName string
	flagMethod asset.DetectionMethod
	indicator  string
}

// metaEntry is one meta tag's name/content pair.
type metaEntry struct {
	name    string
	content string
}

// attrEntry is one HTML attribute name/value pair observed in a tag.
type attrEntry struct {
	name  string
	value string
}

// obsCorpus is everything the analyzers match against, extracted ONCE per
// observation: headers in matchable form, cookies (caller-provided plus
// header-parsed), one HTML body pass, and the typed TLS/DNS/endpoint seams.
type obsCorpus struct {
	headers     []headerLine
	cookies     []cookieEntry
	cookieFlags []cookieFlagObs
	scripts     []string
	css         []string
	metas       []metaEntry
	attrs       []attrEntry
	sourcemaps  []string
	generators  []string
	body        string
	bodyLower   string // single lowercase copy, reused by every case-insensitive matcher
	path        string // canonical URL path (endpoint_path target)
	tls         *TLSInfo
	dns         *DNSInfo
	truncated   bool // a candidate cap dropped extracted material
	overflow    Overflow
}

// buildCorpus extracts the match corpus from one observation. It performs
// exactly ONE pass over the body (tag scanning) and ONE lowercase copy; the
// cookie analyzer combines caller-provided cookies with Cookie/Set-Cookie
// header parsing, capped at maxObservationCookies entries.
func buildCorpus(o Observation) obsCorpus {
	c := obsCorpus{
		body:      o.Body,
		bodyLower: strings.ToLower(o.Body),
		path:      o.URL.Path,
		tls:       o.TLS,
		dns:       o.DNS,
	}

	c.headers = make([]headerLine, 0, len(o.Headers))
	for _, h := range o.Headers {
		line := h.Name + ": " + h.Value
		c.headers = append(c.headers, headerLine{name: h.Name, value: h.Value, line: line, lower: strings.ToLower(line)})
	}

	// Cookies: caller-provided first, then header-parsed, capped in order.
	c.cookies = make([]cookieEntry, 0, len(o.Cookies))
	appendCookie := func(name, value string) {
		if len(c.cookies) >= maxObservationCookies {
			c.overflow.Cookies = true
			return
		}
		c.cookies = append(c.cookies, cookieEntry{name: name, value: value})
	}
	for _, ck := range o.Cookies {
		appendCookie(ck.Name, ck.Value)
	}
	for _, h := range o.Headers {
		switch strings.ToLower(h.Name) {
		case "cookie":
			for _, part := range strings.Split(h.Value, ";") {
				name, value, ok := splitCookiePair(part)
				if ok {
					appendCookie(name, value)
				}
			}
		case "set-cookie":
			// Set-Cookie syntax: the FIRST pair is the real cookie; every
			// later pair is an ATTRIBUTE of that cookie. Only real
			// attributes are deliberate observations, so only allow-listed
			// attribute pairs are ingested as entries; unknown directives
			// (stale or hostile "attributes") are dropped.
			parts := splitSetCookie(h.Value)
			for i, part := range parts {
				name, value, ok := splitCookiePair(part)
				if !ok {
					continue
				}
				if i > 0 && !isCookieAttribute(part) {
					continue
				}
				appendCookie(name, value)
			}
			// Session flags are evidence-only observations on the Set-Cookie
			// directive set: an EXACT attribute-name match on the
			// out-of-quote segments (case-insensitive, no space requirement
			// after ';', so both ";secure" and "; Secure" fire) — a
			// "; Secure" inside a quoted value is data, never a directive.
			// Value-less flag attributes ("HttpOnly", "Secure") carry no '=',
			// so the extractor must accept bare names too.
			cookieName := firstCookieName(h.Value)
			if cookieName == "" {
				continue
			}
			for _, part := range parts[1:] {
				switch segmentName(part) {
				case "httponly":
					c.cookieFlags = append(c.cookieFlags, cookieFlagObs{cookieName: cookieName, flagMethod: asset.MethodCookie, indicator: cookieFlagIndicatorHTTPOnly})
				case "secure":
					c.cookieFlags = append(c.cookieFlags, cookieFlagObs{cookieName: cookieName, flagMethod: asset.MethodCookie, indicator: cookieFlagIndicatorSecure})
				case "samesite":
					c.cookieFlags = append(c.cookieFlags, cookieFlagObs{cookieName: cookieName, flagMethod: asset.MethodCookie, indicator: cookieFlagIndicatorSameSite})
				}
			}
		}
	}
	c.truncated = c.overflow.Cookies

	if o.Body != "" {
		h := scanHTML(o.Body)
		c.scripts = h.scripts
		c.css = h.css
		c.metas = h.metas
		c.attrs = h.attrs
		c.sourcemaps = h.sourcemaps
		c.generators = h.generators
		c.truncated = c.truncated || h.truncated
	}
	return c
}

// splitCookiePair splits one "name=value" cookie pair. A pair without '=' is
// not a cookie.
func splitCookiePair(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// firstCookieName returns the name of the first cookie in a Set-Cookie value
// (the segment before the first ';').
func firstCookieName(v string) string {
	i := strings.IndexByte(v, ';')
	if i >= 0 {
		v = v[:i]
	}
	name, _, ok := splitCookiePair(v)
	if !ok {
		return ""
	}
	return name
}

// splitSetCookie splits a Set-Cookie directive set at ';' boundaries OUTSIDE
// quoted values. A quoted attribute value may legally contain ';' (for
// example Expires="Thu, 01 Jan 1970 00:00:00 GMT; Secure" is ONE segment);
// naive splitting would tear the value AND let the flag scanner false-fire
// inside it. Quotes toggle on every '"' (cookie attribute values have no
// escape mechanism; a quote is a plain byte).
func splitSetCookie(v string) []string {
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

// attrName returns the trimmed, lowercased attribute name of one Set-Cookie
// segment (the text before the first '='), or "" when the segment is not a
// "name=value" pair.
func attrName(part string) string {
	i := strings.IndexByte(part, '=')
	if i <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(part[:i]))
}

// segmentName is the flag-scanner variant of attrName: it also recognizes
// value-less flag attributes (" HttpOnly", ";secure"). The trimmed,
// lowercased name is the text before the first '=' when the segment is a
// "name=value" pair, otherwise the whole trimmed segment. Quoted junk
// ("\"HttpOnly\"") keeps its quotes, so it never matches; a quote-wrapped
// value containing ';' stays one segment for splitSetCookie, and its name
// (e.g. "expires") never matches a flag.
func segmentName(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	if i := strings.IndexByte(part, '='); i > 0 {
		return strings.ToLower(part[:i])
	}
	return strings.ToLower(part)
}

// isCookieAttribute reports whether a Set-Cookie pair beyond the first is a
// REAL cookie attribute (RFC 6265 attributes plus Partitioned). Only these
// are deliberate observations; anything else is dropped at ingest.
func isCookieAttribute(name string) bool {
	switch attrName(name) {
	case "path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "partitioned":
		return true
	}
	return false
}

// htmlExtract is the bounded result of one body pass.
type htmlExtract struct {
	scripts    []string
	css        []string
	metas      []metaEntry
	attrs      []attrEntry
	sourcemaps []string
	generators []string
	truncated  bool
}

// scanHTML performs ONE bounded pass over the body: it scans tags, extracts
// script src values, stylesheet href values, meta name/content pairs, all
// attribute name/value pairs, and sourceMappingURL tokens. Everything is
// bounded by the caps above; document order is preserved; exceeding a cap
// sets truncated.
func scanHTML(body string) htmlExtract {
	var out htmlExtract

	appendAttr := func(name, value string) {
		if len(out.attrs) >= maxHTMLAttributes {
			out.truncated = true
			return
		}
		out.attrs = append(out.attrs, attrEntry{name: name, value: value})
	}

	i := 0
	for i < len(body) {
		lt := strings.IndexByte(body[i:], '<')
		if lt < 0 {
			break
		}
		start := i + lt
		gt := strings.IndexByte(body[start:], '>')
		if gt < 0 {
			break
		}
		tag := body[start+1 : start+gt]
		name, attrs := parseTag(tag)
		switch name {
		case "script":
			if src := attrValue(attrs, "src"); src != "" {
				if len(out.scripts) < maxHTMLScripts {
					out.scripts = append(out.scripts, src)
				} else {
					out.truncated = true
				}
			}
		case "link":
			rel := strings.ToLower(attrValue(attrs, "rel"))
			if strings.Contains(rel, "stylesheet") {
				if href := attrValue(attrs, "href"); href != "" {
					if len(out.css) < maxHTMLCSS {
						out.css = append(out.css, href)
					} else {
						out.truncated = true
					}
				}
			}
		case "meta":
			nameAttr := attrValue(attrs, "name")
			if nameAttr != "" {
				if len(out.metas) < maxHTMLMetas {
					out.metas = append(out.metas, metaEntry{name: nameAttr, content: attrValue(attrs, "content")})
				} else {
					out.truncated = true
				}
				if strings.EqualFold(nameAttr, "generator") {
					if gen := attrValue(attrs, "content"); gen != "" {
						if len(out.generators) < maxHTMLGenerators {
							out.generators = append(out.generators, gen)
						} else {
							out.truncated = true
						}
					}
				}
			}
		}
		// Every tag's attributes feed the attribute analyzer (framework
		// attributes live on divs, app roots, and script tags alike).
		for _, a := range attrs {
			appendAttr(a.name, a.value)
		}

		i = start + gt + 1
	}

	// sourceMappingURL tokens: presence-only extraction, bounded.
	j := 0
	for j < len(body) {
		k := strings.Index(body[j:], "sourceMappingURL=")
		if k < 0 {
			break
		}
		pos := j + k + len("sourceMappingURL=")
		end := pos
		for end < len(body) && body[end] != ' ' && body[end] != '\n' && body[end] != '\r' && body[end] != '\t' && body[end] != '*' && body[end] != '-' {
			end++
		}
		if end > pos {
			if len(out.sourcemaps) < maxHTMLSourceMaps {
				out.sourcemaps = append(out.sourcemaps, body[pos:end])
			} else {
				out.truncated = true
			}
		}
		j = end
	}
	return out
}

// tagAttr is a parsed attribute in document order.
type tagAttr struct {
	name  string
	value string
}

// parseTag parses one tag's content (the text between '<' and '>') into its
// lowercase tag name and its attributes in document order.
func parseTag(s string) (string, []tagAttr) {
	attrs := []tagAttr{}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", attrs
	}
	if s[0] == '/' || s[0] == '!' {
		// closing tag or comment/declaration: no attributes
		return strings.ToLower(strings.TrimSpace(strings.TrimLeft(s, "/!"))), attrs
	}
	i := 0
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	name := strings.ToLower(s[:i])
	for i < len(s) {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '/' {
			break // self-closing slash
		}
		if s[i] == '>' {
			break
		}
		start := i
		for i < len(s) && !isSpace(s[i]) && s[i] != '=' && s[i] != '/' && s[i] != '>' {
			i++
		}
		attrName := s[start:i]
		if attrName == "" {
			// stray punctuation: skip one byte
			i++
			continue
		}
		// Skip whitespace before '=', if any.
		j := i
		for j < len(s) && isSpace(s[j]) {
			j++
		}
		attrVal := ""
		if j < len(s) && s[j] == '=' {
			j++
			for j < len(s) && isSpace(s[j]) {
				j++
			}
			var v string
			if j < len(s) && (s[j] == '"' || s[j] == '\'') {
				quote := s[j]
				j++
				end := j
				for end < len(s) && s[end] != quote {
					end++
				}
				v = s[j:end]
				j = end
				if j < len(s) {
					j++ // closing quote
				}
			} else {
				end := j
				for end < len(s) && !isSpace(s[end]) && s[end] != '>' {
					end++
				}
				v = s[j:end]
				j = end
			}
			attrVal = v
		}
		attrs = append(attrs, tagAttr{name: attrName, value: attrVal})
		i = j
		if i < len(s) && s[i] == '/' {
			break
		}
	}
	return name, attrs
}

// attrValue returns the value of the named attribute (case-insensitive), or
// "" when absent.
func attrValue(attrs []tagAttr, want string) string {
	for _, a := range attrs {
		if strings.EqualFold(a.name, want) {
			return a.value
		}
	}
	return ""
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// match is ONE matched indicator in one slot of the observation.
type match struct {
	kind      fingerprints.IndicatorKind
	slot      int
	value     string // the observed value the indicator matched against
	attrValue string // for attribute-kind indicators: the attribute VALUE (the version target)
}

// techMatch is one retained indicator match for one fingerprint.
type techMatch struct {
	fp     fingerprints.Fingerprint
	ind    fingerprints.Indicator
	m      match
	indIdx int // the indicator's index within its fingerprint (DB order)
}

// matchIndicator runs one indicator against the corpus and returns every
// match slot. Slots are deterministic: header index, cookie index, script
// index, meta index, attribute index, ALPN index, CNAME-chain index, or 0
// for the single-slot kinds (html regex/substring, endpoint path, TLS
// issuer/CN). An indicator matches at most once per slot.
func matchIndicator(ind fingerprints.Indicator, c *obsCorpus) []match {
	matchStr := strings.ToLower(ind.Match)
	var out []match
	add := func(slot int, value, attrValue string) {
		out = append(out, match{kind: ind.Kind, slot: slot, value: value, attrValue: attrValue})
	}

	switch ind.Kind {
	case fingerprints.IndicatorHeader:
		for i, h := range c.headers {
			if containsFold(h.lower, matchStr) {
				add(i, h.line, "")
			}
		}
	case fingerprints.IndicatorCookie:
		for i, ck := range c.cookies {
			if containsFold(strings.ToLower(ck.name), matchStr) {
				add(i, ck.name, "")
			} else if containsFold(strings.ToLower(ck.value), matchStr) {
				add(i, ck.value, "")
			}
		}
	case fingerprints.IndicatorHTMLSubstring:
		if idx := indexFold(c.bodyLower, matchStr); idx >= 0 {
			// The index is a byte offset into the FOLDED copy; evidence
			// values must come from the ORIGINAL body (folding shrinks
			// multi-byte runes, so folded offsets are not original
			// offsets). originalSpan maps the folded span back to the
			// original span — linear, allocation-free.
			start, end := originalSpan(c.body, idx, len(matchStr))
			add(0, c.body[start:end], "")
		}
	case fingerprints.IndicatorHTMLRegex:
		re := ind.MatchRe()
		if re == nil {
			return nil // compile-once contract violation; never matches
		}
		if loc := re.FindStringIndex(c.body); loc != nil {
			add(0, c.body[loc[0]:loc[1]], "")
		}
	case fingerprints.IndicatorGenerator:
		re := ind.MatchRe()
		if re == nil {
			return nil
		}
		for i, g := range c.generators {
			if re.MatchString(g) {
				add(i, g, "")
			}
		}
	case fingerprints.IndicatorMetaName:
		for i, m := range c.metas {
			if containsFold(strings.ToLower(m.name), matchStr) {
				add(i, m.name, "")
			}
		}
	case fingerprints.IndicatorScriptName:
		for i, s := range c.scripts {
			base := scriptBase(s)
			if containsFold(strings.ToLower(base), matchStr) {
				add(i, base, "")
			}
		}
	case fingerprints.IndicatorScriptPath:
		for i, s := range c.scripts {
			if containsFold(strings.ToLower(s), matchStr) {
				add(i, s, "")
			}
		}
	case fingerprints.IndicatorCSSPath:
		for i, s := range c.css {
			if containsFold(strings.ToLower(s), matchStr) {
				add(i, s, "")
			}
		}
	case fingerprints.IndicatorAttribute:
		for i, a := range c.attrs {
			if containsFold(strings.ToLower(a.name), matchStr) {
				add(i, a.name, a.value)
			}
		}
	case fingerprints.IndicatorEndpointPath:
		if containsFold(strings.ToLower(c.path), matchStr) {
			add(0, c.path, "")
		}
	case fingerprints.IndicatorTLSIssuer:
		if c.tls != nil && containsFold(strings.ToLower(c.tls.Issuer), matchStr) {
			add(0, c.tls.Issuer, "")
		}
	case fingerprints.IndicatorTLSCN:
		if c.tls != nil && containsFold(strings.ToLower(c.tls.Subject), matchStr) {
			add(0, c.tls.Subject, "")
		}
	case fingerprints.IndicatorTLSALPN:
		if c.tls != nil {
			for i, p := range c.tls.ALPN {
				if containsFold(strings.ToLower(p), matchStr) {
					add(i, p, "")
				}
			}
		}
	case fingerprints.IndicatorDNSCNAME:
		if c.dns != nil {
			for i, cn := range c.dns.CNAMEChain {
				if containsFold(strings.ToLower(cn), matchStr) {
					add(i, cn, "")
				}
			}
		}
	case fingerprints.IndicatorSourceMapPath:
		for i, s := range c.sourcemaps {
			if containsFold(strings.ToLower(s), matchStr) {
				add(i, s, "")
			}
		}
	}
	return out
}

// scriptBase returns the basename of a script src value: the last path
// segment of its URL path (query and fragment stripped).
func scriptBase(src string) string {
	if i := strings.IndexAny(src, "?#"); i >= 0 {
		src = src[:i]
	}
	if i := strings.LastIndex(src, "/"); i >= 0 {
		src = src[i+1:]
	}
	return src
}

// analysisOutcome is everything the analyzers produced for one observation.
// It is the unit stored in cache records and reconstructed on hits.
type analysisOutcome struct {
	technologies []TechnologyResult
	evidence     []asset.Evidence
	techEvidence map[string][]string // technology ID -> evidence IDs that fired it (for tech->evidence edges)
	conflicts    int
	truncated    bool
	overflow     Overflow
}

// analyze runs every fingerprint indicator over the observation's corpus.
// It never compiles regular expressions: all matching uses the compile-once
// DB accessors (MatchRe/VersionRe).
//
// Bounds: matches are collected in deterministic DB order (then slot order)
// and cut at capIndicators (Overflow.Indicators); fired technologies are cut
// at capTechnologies (Overflow.Technologies) in deterministic order (score
// desc, then name asc). Evidence records (indicator matches plus cookie-flag
// evidence) are deduplicated by identity and cut at capIndicators in
// deterministic order — all in one bounded pass.
func analyze(o Observation, fps []fingerprints.Fingerprint, capTechnologies, capIndicators int, prov asset.Provenance) analysisOutcome {
	out := analysisOutcome{
		techEvidence: make(map[string][]string),
	}

	// Prepare the corpus ONCE per observation.
	corpus := buildCorpus(o)
	out.truncated = corpus.truncated
	out.overflow = corpus.overflow

	source := o.identity()
	evidenceByID := make(map[string]asset.Evidence)
	var evidenceOrder []string

	// Retained match list per fired fingerprint, in deterministic DB order.
	type fpMatches struct {
		fpIdx int // the fingerprint's index in the DB's fingerprint order
		fp    fingerprints.Fingerprint
		ms    []techMatch
	}
	var fired []fpMatches
	matchBudget := capIndicators

	// versionOrdinalBase[i] is the flat DB position offset of fingerprint
	// i's first indicator; ordinals are 1-based (the DB's first indicator
	// is 1; 0 means "no version carried"). The ordinal of the
	// version-bearing indicator is the deterministic third key of the
	// equal-score merge tie-break ("first-in-DB-order of the version-bearing
	// indicator") and is persisted in cache records so cache-served
	// contributors tie-break identically.
	versionOrdinalBase := make([]int, len(fps)+1)
	for i := range fps {
		versionOrdinalBase[i+1] = versionOrdinalBase[i] + len(fps[i].Indicators)
	}

	for fi, fp := range fps {
		if matchBudget <= 0 {
			out.overflow.Indicators = true
			break
		}
		var ms []techMatch
		for ii, ind := range fp.Indicators {
			if matchBudget <= 0 {
				out.overflow.Indicators = true
				break
			}
			for _, m := range matchIndicator(ind, &corpus) {
				if matchBudget <= 0 {
					out.overflow.Indicators = true
					break
				}
				ms = append(ms, techMatch{fp: fp, ind: ind, m: m, indIdx: ii})
				matchBudget--
			}
		}
		if len(ms) > 0 {
			fired = append(fired, fpMatches{fpIdx: fi, fp: fp, ms: ms})
		}
	}

	// Slot fingerprint sets for conflict counting: (kind,slot) -> fingerprint
	// names, deduplicated later. The count is fingerprint-level: it includes
	// fingerprints whose technologies are later dropped by the technology
	// cap (conflicts describe observed disagreement, not retention).
	slotFPs := make(map[string][]string)

	// Score and build each fired technology.
	type scoredTech struct {
		result TechnologyResult
		evIDs  []string
	}
	var scoredList []scoredTech

	for _, fm := range fired {
		fp := fm.fp
		groups := make([]indicatorGroup, 0, len(fm.ms))
		var versionInd *fingerprints.Indicator
		var versionMatch *match
		versionOrd := 0 // DB ordinal of the version-bearing indicator (0 = none)
		versionWeight := -1.0

		for _, tm := range fm.ms {
			groups = append(groups, indicatorGroup{kind: tm.ind.Kind, slot: tm.m.slot, weight: tm.ind.Weight})
			slotKey := string(tm.ind.Kind) + ":" + fmt.Sprintf("%d", tm.m.slot)
			slotFPs[slotKey] = append(slotFPs[slotKey], fp.Name)

			if tm.ind.Version != nil && tm.ind.Weight > versionWeight {
				v := tm.ind
				m := tm.m
				versionInd = &v
				versionMatch = &m
				versionWeight = tm.ind.Weight
				versionOrd = versionOrdinalBase[fm.fpIdx] + tm.indIdx + 1
			}
		}

		score, level := deriveConfidence(groups)

		tech, err := asset.NewTechnology(fp.Name, fp.Category, prov)
		if err != nil {
			continue
		}
		tech.Prov.Confidence = score

		// Version: from the highest-weight version-bearing matched indicator;
		// ties resolve to the first in DB (table) order. The version pattern
		// applies to the matched value AS OBSERVED; for attribute-kind
		// indicators it applies to the attribute VALUE. The indicator's DB
		// ordinal rides along only when the version actually landed, so a
		// version-less result never claims a version-bearing origin.
		versionLanded := false
		if versionInd != nil && versionInd.VersionRe() != nil && versionMatch != nil {
			value := versionMatch.value
			if versionInd.Kind == fingerprints.IndicatorAttribute {
				value = versionMatch.attrValue
			}
			if m := versionInd.VersionRe().FindStringSubmatch(value); m != nil {
				g := versionInd.Version.Group
				if g >= 0 && g < len(m) {
					if v := m[g]; v != "" {
						if t, err := asset.WithVersion(tech, v); err == nil {
							tech = t
							versionLanded = true
						}
					}
				}
			}
		}
		if !versionLanded {
			versionOrd = 0
		}

		// Evidence for every retained match.
		var evIDs []string
		for _, tm := range fm.ms {
			ev, err := asset.NewEvidence(methodFor(tm.ind.Kind), indicatorKey(tm.ind.Kind, tm.ind.Match), tm.m.value, source, prov)
			if err != nil {
				continue
			}
			id := ev.ID()
			if _, dup := evidenceByID[id]; !dup {
				evidenceByID[id] = ev
				evidenceOrder = append(evidenceOrder, id)
			}
			evIDs = append(evIDs, id)
		}

		scoredList = append(scoredList, scoredTech{
			result: TechnologyResult{
				Technology:     tech,
				Score:          score,
				Level:          level,
				versionOrdinal: versionOrd,
			},
			evIDs: evIDs,
		})
	}

	// Cookie-flag evidence (evidence-only; no technology edges).
	for _, f := range corpus.cookieFlags {
		ev, err := asset.NewEvidence(f.flagMethod, f.indicator, f.cookieName, source, prov)
		if err != nil {
			continue
		}
		id := ev.ID()
		if _, dup := evidenceByID[id]; !dup {
			evidenceByID[id] = ev
			evidenceOrder = append(evidenceOrder, id)
		}
	}

	// Deterministic selection of retained technologies: score desc, then
	// name asc (the DB is name-sorted, so ties are stable in DB order).
	sort.SliceStable(scoredList, func(i, j int) bool {
		if scoredList[i].result.Score != scoredList[j].result.Score {
			return scoredList[i].result.Score > scoredList[j].result.Score
		}
		return scoredList[i].result.Technology.Name < scoredList[j].result.Technology.Name
	})
	if len(scoredList) > capTechnologies {
		scoredList = scoredList[:capTechnologies]
		out.overflow.Technologies = true
	}

	for _, s := range scoredList {
		out.technologies = append(out.technologies, s.result)
		// Only retained technologies contribute technology->evidence edges;
		// evidence records whose technology was dropped past the cap are
		// still reported as observed evidence (they are real observations),
		// but they have no technology edge.
		for _, id := range s.evIDs {
			out.techEvidence[s.result.Technology.ID()] = appendUnique(out.techEvidence[s.result.Technology.ID()], id)
		}
	}

	// Evidence: deduplicate by identity; cut at capIndicators in
	// deterministic order (matches in DB/slot order, then cookie-flag
	// records in cookie order).
	out.evidence = make([]asset.Evidence, 0, len(evidenceOrder))
	budget := capIndicators
	for _, id := range evidenceOrder {
		if budget <= 0 {
			out.overflow.Indicators = true
			break
		}
		out.evidence = append(out.evidence, evidenceByID[id])
		budget--
	}

	// Conflict count per (kind, slot): n distinct fingerprints -> n-1
	// conflicts, deterministic (deduplicated, order-free).
	for _, fps := range slotFPs {
		uniq := uniqueSorted(fps)
		if len(uniq) > 1 {
			out.conflicts += len(uniq) - 1
		}
	}
	return out
}

// appendUnique appends id to list if not already present.
func appendUnique(list []string, id string) []string {
	for _, x := range list {
		if x == id {
			return list
		}
	}
	return append(list, id)
}

// uniqueSorted returns the sorted unique values of list.
func uniqueSorted(list []string) []string {
	sort.Strings(list)
	out := list[:0]
	for i, s := range list {
		if i == 0 || s != list[i-1] {
			out = append(out, s)
		}
	}
	return out
}
