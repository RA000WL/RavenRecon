package secrentel

import (
	"bytes"
	"sort"
	"strings"
)

// Context is the extracted surrounding evidence of one candidate match: the
// assignment variable name, the nearest JSON key, comment containment,
// matched positive indicators in the surrounding window, and whether a
// pattern hint or the provider name appears in the name. Context influences
// confidence; it never classifies alone.
type Context struct {
	// Variable is the assignment name the match sits in the value position
	// of ("awsAccessKey = <match>" → "awsAccessKey"), when one is found.
	Variable string `json:"variable,omitempty"`
	// JSONKey is the nearest preceding JSON object key ("{\"apiKey\":
	// \"<match>\"}" → "apiKey"), when one is found.
	JSONKey string `json:"json_key,omitempty"`
	// InComment reports that the match sits inside a //, #, or /* … */
	// comment. String-aware: comment markers inside string literals do not
	// count (a quoted "//" is data, not a comment).
	InComment bool `json:"in_comment,omitempty"`
	// Nearby lists the pattern's positive indicators matched in the
	// surrounding window (bounded).
	Nearby []string `json:"nearby,omitempty"`
	// NameHint reports that Variable/JSONKey contains one of the pattern's
	// hints or the provider name — the strong context signal.
	NameHint string `json:"name_hint,omitempty"`
}

// Location is the candidate's position in the scanned document. Line is
// 1-based (0 = beyond the tracked-line cap); Column is the 1-based byte
// column; Offset is the byte offset of the match start.
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset"`
}

// Context extraction bounds (fixed constants).
const (
	// contextWindowBytes bounds the surrounding window each side of a match.
	contextWindowBytes = 256
	// maxNearby bounds the retained nearby-indicator list.
	maxNearby = 4
	// maxNameBytes bounds the extracted Variable/JSONKey strings.
	maxNameBytes = 128
	// maxTrackedLines bounds the line-start index (a hostile 2 MiB file of
	// bare newlines cannot grow it without bound; matches beyond the cap
	// report Line 0 — honest, bounded, deterministic).
	maxTrackedLines = 65536
	// maxTrackedIntervals bounds the state index of one document: the
	// string-literal, block-comment, and line-comment interval lists SHARE
	// this per-list bound. Beyond the cap, comment detection falls back to
	// the legacy line-based scan (bounded, deterministic, but
	// string-unaware); intervals are dropped deterministically as the cap
	// trips (drop-new).
	maxTrackedIntervals = 4096
	// maxIdentifierRun bounds backward/forward identifier scans.
	maxIdentifierRun = 256
)

// stateIndex is the bounded string/comment state of one document: the byte
// intervals covered by string literals ('…', "…", `…`), by /* … */ block
// comments, and by // and # line comments (each region runs from its marker
// to the end of its line). Built ONCE per scan in a single forward pass;
// lookups are binary searches over the sorted, non-overlapping interval
// lists. Comment regions (line and block) never overlap string intervals: a
// marker or quote inside the other kind is comment/string material and is
// consumed by the kind that opened first.
type stateIndex struct {
	str    [][2]int // [start, end) string-literal intervals
	blk    [][2]int // [start, end) block-comment intervals
	ln     [][2]int // [start, end) line-comment regions (marker to newline)
	capped bool     // more intervals than maxTrackedIntervals
}

// buildStateIndex scans the document once, recording string-literal,
// block-comment, and line-comment intervals. Escape sequences (\" \' \`
// \\ and line continuations) are respected; an unterminated single-line
// string closes at end-of-line; backtick strings may span lines; an
// unterminated block comment runs to the end of the document. A // or #
// marker seen at top level (outside strings and block comments, which the
// pass consumes as it goes) opens a line-comment region running to the end
// of its line — the region wins over any quote-shaped text inside it, so a
// quote in a line comment never opens a string interval, while markers
// inside string intervals remain data ("https://…" never starts a comment).
// Intervals never overlap within one list, and comment regions always win
// over string intervals (inside a comment, quote-shaped text is comment
// material).
func buildStateIndex(content []byte) stateIndex {
	idx := stateIndex{}
	n := len(content)
	addInterval := func(list [][2]int, iv [2]int) [][2]int {
		if !idx.capped {
			if len(list) >= maxTrackedIntervals {
				idx.capped = true
				return list
			}
			list = append(list, iv)
		}
		return list
	}
	for i := 0; i < n; {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '*':
			// Block comment: record the interval and skip past the close.
			start := i
			closeOff := bytes.Index(content[i+2:], []byte("*/"))
			if closeOff < 0 {
				// Unterminated: the comment runs to the end of the document.
				idx.blk = addInterval(idx.blk, [2]int{start, n})
				return idx
			}
			end := i + 2 + closeOff + 2
			idx.blk = addInterval(idx.blk, [2]int{start, end})
			i = end
		case c == '\'' || c == '"' || c == '`':
			quote := c
			start := i
			i++
			for i < n {
				if content[i] == '\\' {
					i += 2 // escape (+ possible line continuation) stays in the string
					continue
				}
				if content[i] == quote {
					i++
					break
				}
				if content[i] == '\n' && quote != '`' {
					break // unterminated single-line string closes at the newline
				}
				i++
			}
			idx.str = addInterval(idx.str, [2]int{start, i})
		case c == '#' || (c == '/' && i+1 < n && content[i+1] == '/'):
			// Line comment: this byte is at top level (strings and block
			// comments were consumed above), so the marker is real comment
			// material. The region runs from the marker to the newline and
			// swallows every quote on the rest of the line.
			start := i
			end := n
			if nl := bytes.IndexByte(content[i:], '\n'); nl >= 0 {
				end = i + nl
			}
			idx.ln = addInterval(idx.ln, [2]int{start, end})
			i = end
		default:
			i++
		}
	}
	return idx
}

// insideIntervals reports whether offset falls inside one of the sorted
// [start, end) intervals. Binary search: find the first interval whose end
// is beyond the offset, then check its start.
func insideIntervals(iv [][2]int, offset int) bool {
	i := sort.Search(len(iv), func(i int) bool { return iv[i][1] > offset })
	return i < len(iv) && iv[i][0] <= offset
}

// firstUnquotedMarker returns the document-relative byte offset of the first
// // or # line-comment marker in the line that is NOT inside a string
// literal or a block comment, or -1 when the line has none. String- and
// block-comment-aware: a marker inside quotes is quoted material, and a
// marker inside a /* … */ region is comment material — the forward pass
// consumed that region, so it left no line interval and its markers must
// not be re-read as comment openers. Later unquoted markers still count.
func firstUnquotedMarker(line []byte, idx stateIndex, lineStart int) int {
	for i := 0; i < len(line); i++ {
		pos := lineStart + i
		switch {
		case line[i] == '#':
			if !insideIntervals(idx.str, pos) && !insideIntervals(idx.blk, pos) {
				return pos
			}
		case line[i] == '/' && i+1 < len(line) && line[i+1] == '/':
			if !insideIntervals(idx.str, pos) && !insideIntervals(idx.blk, pos) {
				return pos
			}
		}
	}
	return -1
}

// lineIndex is the bounded line-start offset index of one document. Built
// once per scan; line lookups are binary searches.
type lineIndex struct {
	starts []int // byte offsets of line starts, first line always 0
	capped bool  // document had more lines than maxTrackedLines
}

// buildLineIndex collects at most maxTrackedLines line starts.
func buildLineIndex(content []byte) lineIndex {
	idx := lineIndex{starts: []int{0}}
	for i, b := range content {
		if b == '\n' {
			if len(idx.starts) >= maxTrackedLines {
				idx.capped = true
				break
			}
			idx.starts = append(idx.starts, i+1)
		}
	}
	return idx
}

// locate maps a byte offset to its 1-based line and column. Beyond the
// tracked cap the line is 0 (unknown) and the column is measured from the
// last tracked line start.
func (li lineIndex) locate(offset int) Location {
	// First line start strictly greater than offset: SearchInts over
	// offset+1 gives the insertion point AFTER the containing line's start.
	i := sort.SearchInts(li.starts, offset+1)
	start := 0
	if i > 0 {
		start = li.starts[i-1]
	}
	line := i // 1-based: starts[0]=0 covers line 1
	if i >= len(li.starts) && li.capped {
		line = 0
	}
	return Location{Line: line, Column: offset - start + 1, Offset: offset}
}

// extractContext builds the context of one match. All scans are bounded by
// the window and identifier-run constants; nothing beyond the document is
// read, and no large windows are retained. idx is the document's string
// state index (built once per scan); comment detection is string-aware
// through it.
func extractContext(content []byte, matchStart, matchEnd int, provider string, hints, positives []string, idx stateIndex) Context {
	var ctx Context

	winStart := matchStart - contextWindowBytes
	if winStart < 0 {
		winStart = 0
	}
	winEnd := matchEnd + contextWindowBytes
	if winEnd > len(content) {
		winEnd = len(content)
	}
	window := content[winStart:winEnd]

	ctx.Variable, ctx.JSONKey = extractName(content, matchStart)
	ctx.InComment = inComment(content, matchStart, idx)
	ctx.Nearby = matchNearby(window, positives)

	// NameHint: the strong signal — hint or provider name inside the
	// variable/JSON key, compared with separators normalized away so
	// camelCase names match snake_case hints (accessKey ~ access_key).
	name := ctx.Variable
	if name == "" {
		name = ctx.JSONKey
	}
	if name != "" {
		if provider != "" && nameContains(name, provider) {
			ctx.NameHint = "provider"
		} else {
			for _, h := range hints {
				if nameContains(name, h) {
					ctx.NameHint = "hint:" + h
					break
				}
			}
		}
	}
	return ctx
}

// nameContains reports whether name contains marker, both normalized to
// lowercase with separator bytes (_ - .) removed.
func nameContains(name, marker string) bool {
	return strings.Contains(normalizeName(name), normalizeName(marker))
}

// normalizeName lowercases and strips separator bytes.
func normalizeName(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b = append(b, c+('a'-'A'))
		case c == '_' || c == '-' || c == '.':
			// drop separators
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// extractName walks backward from the match start over the assignment shape:
//   - <spaces> ["] <ident> ["] <spaces>? [:=]  (JS/YAML/env/config)
//   - <spaces> ":" <spaces> ["] <key> ["]     (JSON)
//
// It returns (variable, jsonKey); both are "" when no shape is found. The
// scan is bounded by maxIdentifierRun bytes.
func extractName(content []byte, matchStart int) (variable, jsonKey string) {
	i := matchStart
	// Skip spaces and an optional closing quote directly before the value.
	for i > 0 && (content[i-1] == ' ' || content[i-1] == '\t') {
		i--
	}
	if i > 0 && (content[i-1] == '"' || content[i-1] == '\'') {
		i--
		for i > 0 && (content[i-1] == ' ' || content[i-1] == '\t') {
			i--
		}
	}
	// Expect the separator.
	if i == 0 {
		return "", ""
	}
	switch content[i-1] {
	case ':', '=':
		i--
	default:
		return "", ""
	}
	for i > 0 && (content[i-1] == ' ' || content[i-1] == '\t') {
		i--
	}
	// JSON form: the name is itself quoted.
	isJSON := false
	if i > 0 && content[i-1] == '"' {
		i--
		isJSON = true
	}
	// Collect the identifier run backward.
	end := i
	start := i
	limit := i - maxIdentifierRun
	if limit < 0 {
		limit = 0
	}
	for start > limit && isNameByte(content[start-1]) {
		start--
	}
	if start == end {
		return "", ""
	}
	name := string(content[start:end])
	if len(name) > maxNameBytes {
		name = name[:maxNameBytes]
	}
	if isJSON {
		return "", name
	}
	return name, ""
}

// isNameByte: identifier-ish characters of JS/env/YAML/JSON key names.
func isNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '_' || b == '-' || b == '$' || b == '.'
}

// inComment reports whether offset sits inside a comment: inside a // or #
// line-comment region or a /* … */ block-comment region (both recorded by
// the state index), or — for positions no region covers — on a line whose
// first // or # marker is unquoted (markers inside string literals do NOT
// count — the string-state index knows where quotes are — and markers
// inside block comments do NOT count either, for the same reason: the
// forward pass consumed the block region, and a closed /* … */ on the line
// must not leak its markers as comment openers; the rare fallback positions
// are those BEFORE any recorded region, e.g. document start or an offset at
// the closing newline of a marked line). Comment regions WIN over string
// intervals: quote text inside a line or block comment is comment material
// and can never open a string, so a quoted secret in a comment line is
// still "in comment". When the state index is capped (hostile documents),
// the legacy line-based scan is used: bounded, deterministic, but
// string-unaware.
func inComment(content []byte, offset int, idx stateIndex) bool {
	if idx.capped {
		return legacyInComment(content, offset)
	}
	// Comment regions first (line and block): inside a comment, quote-shaped
	// text is comment material. The forward pass records the three lists
	// without overlap, so ordering is unambiguous.
	if insideIntervals(idx.blk, offset) || insideIntervals(idx.ln, offset) {
		return true
	}
	if insideIntervals(idx.str, offset) {
		return false
	}
	// Line comments: the first // or # marker on this line that is not
	// inside a string literal or a block comment.
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	line := content[lineStart:offset]
	return firstUnquotedMarker(line, idx, lineStart) >= 0
}

// legacyInComment is the bounded line-based comment scan used when the
// string-state index is capped. It does not skip markers inside string
// literals (a quoted "//" reads as a comment opener), but it remains
// bounded, deterministic, and panic-free on any input.
func legacyInComment(content []byte, offset int) bool {
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	line := content[lineStart:offset]
	if c := bytes.Index(line, []byte("//")); c >= 0 {
		return true
	}
	if c := bytes.IndexByte(line, '#'); c >= 0 {
		return true
	}
	// Block comment: last "/*" before the offset with no "*/" after it.
	open := bytes.LastIndex(content[:offset], []byte("/*"))
	if open < 0 {
		return false
	}
	close_ := bytes.Index(content[open:offset], []byte("*/"))
	return close_ < 0
}

// matchNearby finds the pattern's positive indicators in the window
// (case-insensitive, bounded list).
func matchNearby(window []byte, positives []string) []string {
	var out []string
	w := string(window)
	for _, p := range positives {
		if len(out) >= maxNearby {
			break
		}
		if containsFold(w, p) {
			out = append(out, p)
		}
	}
	return out
}

// toLowerASCII lowercases ASCII bytes only (deterministic on any input).
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
