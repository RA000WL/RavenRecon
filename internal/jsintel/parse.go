package jsintel

import "strings"

// parse.go implements the extraction walk over the tokenizer's stream: it
// turns tokens into Parsed observations — imports, exports, string and
// template literals, and source map references — and decodes string escape
// sequences. The walk is lookahead-only: it NEVER consumes tokens, so every
// string and template token is visited exactly once and Parsed.Strings is
// complete in source order (import specifiers included — consumers filter).

// maxTemplateExprNesting bounds template-expression nesting during escape
// decoding (a second, independent pass over template text). Deeper nesting
// falls back to copying the remaining template text verbatim — bounded,
// deterministic recovery.
const maxTemplateExprNesting = 64

// maxLookaheadTokens bounds every forward/backward scan the extraction walk
// performs over the token stream around the token being processed:
// findFromSpecifier's hunt for `from "spec"` after an import keyword,
// exportList's hunt for the closing brace of `export { ... }`, the comment
// skip between a list's closing brace and a possible re-export `from`, and
// prevSig's backward hunt for the previous significant token. Without a
// window these scans make adversarial inputs quadratic in the token count —
// "import a " repeated to the token cap is ~4e11 scan steps, tens of minutes
// on one core — and Parse has no context, so pool deadlines cannot interrupt
// them: the window is the ONLY bound, and window exhaustion terminates the
// scan deterministically and cheaply.
//
// The window is sized so legitimate constructs always resolve: a single
// import/export clause spanning more than maxLookaheadTokens tokens is a
// binding list of ~250 names with `as` aliases (or ~500 plain names) — far
// beyond any real source or generated bundle, where the largest lists are a
// few hundred names. Scans that exhaust the window therefore only do so on
// adversarial input. Exhaustion semantics per scan (documented at each
// scan):
//
//   - findFromSpecifier and exportList's brace hunt mark the parse
//     Truncated: the clause may extend beyond the window, so the result is
//     an honest prefix (an incomplete analysis is never served as a cache
//     hit) — the same contract as the token cap;
//   - prevSig and the re-export comment skip report no-match/local-list:
//     only comments, which the walker deliberately ignores, lie beyond the
//     window, so the parse stays complete and the decision is a bounded
//     heuristic.
const maxLookaheadTokens = 1024

// maxTotalScanSteps caps the TOTAL number of tokens examined by all
// window scans in one parse. Per-scan maxLookaheadTokens bounds each scan to
// 1024 steps, but an adversarial input with ~500k import keywords (2 tokens
// per "import x", 1M token cap) would still drive ~512M steps
// (500k × 1024) without a global budget. The total budget makes the walk
// LINEAR overall: after budget exhaustion every remaining scan returns
// immediately with Truncated set, so adversarial corpora complete in
// milliseconds rather than minutes. Legitimate inputs stay far under the
// budget (a 1k-import bundle with typical 3-token binding lists costs ~3k
// steps), so the cap never fires on real sources — only on adversarial
// repeats. Window exhaustion and budget exhaustion share the same honesty
// contract: the result is an incomplete prefix marked Truncated, never
// served as a complete cache hit.
const maxTotalScanSteps = 100000

// Source map reference markers, matched against the TRIMMED text of a line
// or block comment (the exact forms from the source map v3 spec; no-space
// variants such as //#sourceMappingURL= are not matched).
const (
	sourceMapHashMarker = "# sourceMappingURL="
	sourceMapAtMarker   = "@ sourceMappingURL="
)

// walker extracts observations from the token stream. All state is
// per-parse.
type walker struct {
	src  []byte
	toks []token
	i    int

	out            Parsed
	seenExports    map[string]struct{}
	truncated      bool
	malformed      int
	droppedStrings int
	scanSteps      int // total tokens examined by window scans (budgeted by maxTotalScanSteps)
}

// walk processes every token exactly once.
func (w *walker) walk() {
	for w.i < len(w.toks) {
		t := w.toks[w.i]
		switch t.kind {
		case tokIdent:
			switch t.text(w.src) {
			case "import":
				w.importAt(t)
				continue
			case "export":
				w.exportAt(t)
				continue
			}
		case tokString:
			w.addString(decodeString(t.text(w.src)), int(t.line), false)
		case tokTemplate:
			w.addString(decodeTemplate(t.text(w.src)), int(t.line), true)
		case tokLineComment, tokBlockComment:
			w.sourceMapAt(t.text(w.src))
		}
		w.i++
	}
}

// prevSig returns the index of the previous SIGNIFICANT token (comments are
// skipped), or -1. The backward walk is bounded by maxLookaheadTokens: a
// comment run longer than the window hides the previous significant token,
// and the caller treats the keyword as statement-leading. This is a bounded
// heuristic — property/member access (`foo.<comment run>import(...)`) is
// misread as a statement only when the run exceeds the window — and marks
// nothing Truncated: the comments beyond the window are the only thing
// unseen, so the parse remains complete.
func (w *walker) prevSig(i int) int {
	limit := i - maxLookaheadTokens
	if limit < 0 {
		limit = 0
	}
	for j := i - 1; j >= limit; j-- {
		k := w.toks[j].kind
		if k != tokLineComment && k != tokBlockComment {
			return j
		}
	}
	return -1
}

// importAt handles an `import` keyword token at w.i (which it leaves at the
// next unprocessed token). Extraction is lookahead-only.
func (w *walker) importAt(t token) {
	start := w.i
	w.i = start + 1
	// Property access (foo.import / foo?.import) is not an import statement.
	if prev := w.prevSig(start); prev >= 0 {
		pt := w.toks[prev]
		if pt.kind == tokPunct && (pt.text(w.src) == "." || pt.text(w.src) == "?.") {
			return
		}
	}
	j := start + 1
	if j >= len(w.toks) {
		return
	}
	next := w.toks[j]
	switch {
	case next.kind == tokPunct && next.text(w.src) == "(":
		// Dynamic import: import ( <specifier?> ... )
		spec, kind := w.dynamicSpec(j + 1)
		w.addImport(spec, kind, int(t.line))
	case next.kind == tokString:
		// Side-effect import: import "spec"
		w.addImport(decodeString(next.text(w.src)), ImportStatic, int(t.line))
	default:
		// Static import with bindings: import ... from "spec"
		if spec, ok := w.findFromSpecifier(j); ok {
			w.addImport(spec, ImportStatic, int(t.line))
		}
	}
}

// dynamicSpec inspects the token after the opening paren of a dynamic import.
// A string literal yields its decoded specifier; a template literal yields
// its decoded specifier only when it has no ${...} expression; anything else
// (expressions, templates with ${...}) is unresolvable and yields "".
func (w *walker) dynamicSpec(j int) (string, ImportKind) {
	if j >= len(w.toks) {
		return "", ImportDynamic
	}
	switch t := w.toks[j]; t.kind {
	case tokString:
		return decodeString(t.text(w.src)), ImportDynamic
	case tokTemplate:
		raw := t.text(w.src)
		if templateHasExpr(raw) {
			return "", ImportDynamic
		}
		return decodeTemplate(raw), ImportDynamic
	}
	return "", ImportDynamic
}

// findFromSpecifier scans from index j (bounded by maxLookaheadTokens) for
// the pattern `from` (an identifier at brace depth 0) followed by a string
// literal, returning the decoded specifier. A depth-0 string/template before
// `from` (for example the TypeScript import-equals form
// `import x = require("m")`) stops the scan: it is not an import form we
// extract. A depth-0 `;` also stops the scan — `from` after the statement
// terminator belongs to a later statement (for example
// `import.meta.url; import x from "m"` must not report an import on the
// import.meta line). A depth-0 `import` or `export` also stops the scan:
// it is the start of the next statement, and `from` beyond it belongs to
// that statement — this makes adversarial repeats such as
// `import x import x ...` linear (2 steps per scan) instead of
// 1024 steps per scan. Window exhaustion or total-budget exhaustion marks
// the parse Truncated: an import statement whose binding list spans the
// full window may still resolve beyond it, so reporting no import without
// flagging would silently drop a true observation — the truncated result is
// an honest prefix, consistent with the token cap.
func (w *walker) findFromSpecifier(j int) (string, bool) {
	if w.scanSteps >= maxTotalScanSteps {
		w.truncated = true
		return "", false
	}
	limit := j + maxLookaheadTokens
	if limit > len(w.toks) {
		limit = len(w.toks)
	}
	depth := 0
	for j < limit {
		if w.scanSteps >= maxTotalScanSteps {
			w.truncated = true
			return "", false
		}
		w.scanSteps++
		t := w.toks[j]
		switch t.kind {
		case tokPunct:
			switch t.text(w.src) {
			case "{":
				depth++
			case "}":
				depth--
				if depth < 0 {
					return "", false
				}
			case ";":
				if depth == 0 {
					return "", false // statement boundary
				}
			}
		case tokIdent:
			if depth == 0 {
				txt := t.text(w.src)
				if txt == "import" || txt == "export" {
					return "", false // next statement — not window exhaustion
				}
				if txt == "from" {
					if j+1 < len(w.toks) && w.toks[j+1].kind == tokString {
						return decodeString(w.toks[j+1].text(w.src)), true
					}
					return "", false
				}
			}
		case tokString, tokTemplate:
			if depth == 0 {
				return "", false
			}
		}
		j++
	}
	w.truncated = true // window exhausted: the clause may continue beyond it
	return "", false
}

// exportAt handles an `export` keyword token at w.i (which it leaves at the
// next unprocessed token). Extraction is lookahead-only.
func (w *walker) exportAt(t token) {
	start := w.i
	w.i = start + 1
	if prev := w.prevSig(start); prev >= 0 {
		pt := w.toks[prev]
		if pt.kind == tokPunct && (pt.text(w.src) == "." || pt.text(w.src) == "?.") {
			return
		}
	}
	j := start + 1
	if j >= len(w.toks) {
		return
	}
	next := w.toks[j]
	switch {
	case next.kind == tokIdent && next.text(w.src) == "default":
		// export default <expr> — always the name "default", even for
		// `export default function foo() {}`.
		w.addExport("default")
	case next.kind == tokPunct && next.text(w.src) == "{":
		w.exportList(j, int(t.line))
	case next.kind == tokIdent && isDeclKeyword(next.text(w.src)):
		// export const|let|var|function|class <name>
		if j+1 < len(w.toks) && w.toks[j+1].kind == tokIdent {
			w.addExport(w.toks[j+1].text(w.src))
		} else if next.text(w.src) == "function" && j+1 < len(w.toks) &&
			w.toks[j+1].kind == tokPunct && w.toks[j+1].text(w.src) == "*" &&
			j+2 < len(w.toks) && w.toks[j+2].kind == tokIdent {
			// export function* <name>
			w.addExport(w.toks[j+2].text(w.src))
		}
	case next.kind == tokIdent && next.text(w.src) == "async":
		// export async function[*] <name>
		k := j + 1
		if k < len(w.toks) && w.toks[k].kind == tokIdent && w.toks[k].text(w.src) == "function" {
			k++
			if k < len(w.toks) && w.toks[k].kind == tokPunct && w.toks[k].text(w.src) == "*" {
				k++
			}
			if k < len(w.toks) && w.toks[k].kind == tokIdent {
				w.addExport(w.toks[k].text(w.src))
			}
		}
	case next.kind == tokPunct && next.text(w.src) == "*":
		// export * from "spec" (import only) and export * as ns from "spec"
		k := j + 1
		if k+1 < len(w.toks) && w.toks[k].kind == tokIdent && w.toks[k].text(w.src) == "as" &&
			w.toks[k+1].kind == tokIdent {
			w.addExport(w.toks[k+1].text(w.src))
		}
		if spec, ok := w.findFromSpecifier(j + 1); ok {
			w.addImport(spec, ImportStatic, int(t.line))
		}
	}
}

// isDeclKeyword reports whether the identifier is one of the declaration
// keywords whose exported name exportAt extracts.
func isDeclKeyword(text string) bool {
	switch text {
	case "const", "let", "var", "function", "class":
		return true
	}
	return false
}

// exportList handles an export list whose opening brace is at index j. A
// LOCAL list (`export {a, b as c, d as default}`) exports the re-export
// TARGET names (`b as c` exports "c"). A RE-EXPORT
// (`export {a} from "spec"` — `from` directly after the closing brace) does
// NOT export those names locally: they belong to the other module, and only
// the specifier is observed, as a static import.
func (w *walker) exportList(j, line int) {
	// First pass: find the closing brace of the list, bounded by
	// maxLookaheadTokens (an export list spanning more than the window is a
	// ~250+-name aliased binding — beyond the legitimate envelope). When the
	// window exhausts with tokens still remaining, the closing brace may
	// exist beyond it: the parse is marked Truncated (honest prefix, same
	// contract as the token cap). When the window reaches EOF without a
	// closing brace the list is genuinely unterminated: nothing to observe.
	// The scan also respects the global maxTotalScanSteps budget (see
	// findFromSpecifier): budget exhaustion also marks Truncated.
	if w.scanSteps >= maxTotalScanSteps {
		w.truncated = true
		return
	}
	depth := 0
	end := -1
	limit := j + maxLookaheadTokens
	if limit > len(w.toks) {
		limit = len(w.toks)
	}
	for k := j; k < limit; k++ {
		if w.scanSteps >= maxTotalScanSteps {
			w.truncated = true
			return
		}
		w.scanSteps++
		t := w.toks[k]
		if t.kind == tokPunct {
			switch t.text(w.src) {
			case "{":
				depth++
			case "}":
				depth--
				if depth == 0 {
					end = k
				}
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		if limit < len(w.toks) {
			w.truncated = true
		} else if w.scanSteps >= maxTotalScanSteps {
			w.truncated = true
		}
		return // unterminated list: nothing to observe
	}
	// Re-export: `export { ... } from "spec"`. `from` must be the next
	// significant token after the closing brace. The comment skip is bounded
	// by maxLookaheadTokens; a comment run longer than the window hides the
	// re-export clause and the list is read as a LOCAL export list (a
	// bounded heuristic — only comments, which the walker ignores, lie
	// beyond the window — and the parse stays complete).
	k := end + 1
	commentLimit := k + maxLookaheadTokens
	if commentLimit > len(w.toks) {
		commentLimit = len(w.toks)
	}
	for k < commentLimit {
		kk := w.toks[k].kind
		if kk == tokLineComment || kk == tokBlockComment {
			k++
			continue
		}
		break
	}
	if k+1 < len(w.toks) && w.toks[k].kind == tokIdent && w.toks[k].text(w.src) == "from" &&
		w.toks[k+1].kind == tokString {
		w.addImport(decodeString(w.toks[k+1].text(w.src)), ImportStatic, line)
		return
	}
	// Local export list: collect the exported names, keeping the re-export
	// target after `as`. Only single identifiers are collected — the walk
	// re-visits the list tokens with no further effect.
	depth = 0
	for k = j; k < end; k++ {
		t := w.toks[k]
		switch t.kind {
		case tokPunct:
			switch t.text(w.src) {
			case "{":
				depth++
			case "}":
				depth--
			}
		case tokIdent:
			if depth == 1 {
				name := t.text(w.src)
				if k+1 < end && w.toks[k+1].kind == tokIdent && w.toks[k+1].text(w.src) == "as" &&
					k+2 < end && w.toks[k+2].kind == tokIdent {
					name = w.toks[k+2].text(w.src)
					k += 2
				}
				w.addExport(name)
			}
		}
	}
}

// addImport appends an import observation, applying the import cap (a cap
// hit marks the parse truncated — the result is an honest prefix) and the
// per-specifier byte cap: a specifier longer than maxParserStringBytes
// (4096 — the same cap addString applies to every retained literal) is
// DROPPED and counted malformed, mirroring how sourceMapAt drops overlong
// references. This is the single capture point for every import form
// (findFromSpecifier, dynamicSpec, the side-effect form, and re-exports),
// so nothing longer than 4096 bytes ever enters Parsed.Imports — and since
// the engine's resolved (Imports) and bare (BareImports) observations both
// derive from Parsed.Imports, neither can carry one either. Without the
// cap, an overlong specifier (reachable via a line-continuation string)
// would be stored, rejected by the js.analyze decode (which re-validates
// specifiers against the same 4096), deleted, and re-parsed on every run —
// permanent recompute churn.
func (w *walker) addImport(spec string, kind ImportKind, line int) {
	if len(spec) > maxParserStringBytes {
		w.malformed++
		return
	}
	if len(w.out.Imports) >= maxParserImports {
		w.truncated = true
		return
	}
	w.out.Imports = append(w.out.Imports, Import{Specifier: spec, Kind: kind, Line: line})
}

// addExport appends an export name, deduplicated in first-observation order,
// applying the export cap.
func (w *walker) addExport(name string) {
	if _, ok := w.seenExports[name]; ok {
		return
	}
	if len(w.out.Exports) >= maxParserExports {
		w.truncated = true
		return
	}
	w.seenExports[name] = struct{}{}
	w.out.Exports = append(w.out.Exports, name)
}

// addString records one string/template literal, applying the string
// budget: maxParserStrings bounds the PROCESSED literals (a cap hit marks
// the parse truncated) and maxParserStringBytes bounds each retained VALUE
// (longer literals are counted toward the budget but not retained — the
// byte cap itself never marks truncated).
func (w *walker) addString(value string, line int, template bool) {
	if len(w.out.Strings)+w.droppedStrings >= maxParserStrings {
		w.truncated = true
		return
	}
	if len(value) > maxParserStringBytes {
		w.droppedStrings++
		return
	}
	w.out.Strings = append(w.out.Strings, StringLit{Value: value, Line: line, Template: template})
}

// sourceMapAt handles a comment token: when its trimmed text starts with a
// source map marker, the trimmed remainder is the reference. The LAST
// reference wins (per the source map spec). References over
// maxSourceMapRefBytes are dropped and counted malformed.
func (w *walker) sourceMapAt(text string) {
	trimmed := strings.TrimSpace(text)
	var ref string
	switch {
	case strings.HasPrefix(trimmed, sourceMapHashMarker):
		ref = strings.TrimSpace(trimmed[len(sourceMapHashMarker):])
	case strings.HasPrefix(trimmed, sourceMapAtMarker):
		ref = strings.TrimSpace(trimmed[len(sourceMapAtMarker):])
	default:
		return
	}
	if len(ref) > maxSourceMapRefBytes {
		w.malformed++
		return
	}
	w.out.SourceMapRef = ref
	w.out.HasSourceMapRef = true
}

// decodeString decodes the escape sequences of a string literal's raw text
// (the content between the quotes) into its value. Decoding mirrors the
// scanner's escape validation exactly: \n \r \t \b \f \v \0 \' \" \\ \/
// \xNN \uNNNN \u{...} (best-effort, including surrogate pairs), and line
// continuations (backslash + line terminator) are removed. Invalid \x and
// \u sequences keep their raw text; unknown escapes keep the character
// after the backslash; the scanner already counted invalid escapes as
// Malformed. Decoding never grows the output beyond the input length.
func decodeString(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '\\' {
			i = decodeEscape(raw, i, &b)
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String()
}

// decodeTemplate decodes the escape sequences of a template literal's raw
// text (the content between the backticks). Text segments decode exactly
// like string literals; ${...} expression segments are copied VERBATIM —
// escapes inside expressions are never decoded, and the expression text is
// never evaluated.
func decodeTemplate(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == '\\':
			i = decodeEscape(raw, i, &b)
		case c == '$' && i+1 < len(raw) && raw[i+1] == '{':
			i = copyTemplateExpr(raw, i, &b, 1)
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// templateHasExpr reports whether the raw text between a template's
// backticks contains a ${...} expression, honoring backslash escapes
// (\${ is an escaped dollar, not an expression start).
func templateHasExpr(raw string) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			continue
		}
		if raw[i] == '$' && raw[i+1] == '{' {
			return true
		}
	}
	return false
}

// decodeEscape decodes the escape sequence whose backslash is at raw[i],
// appends the decoded form to b, and returns the index to continue from.
// See decodeString for the rules.
func decodeEscape(raw string, i int, b *strings.Builder) int {
	if i+1 >= len(raw) {
		b.WriteByte('\\')
		return len(raw)
	}
	e := raw[i+1]
	switch e {
	case 'n':
		b.WriteByte('\n')
		return i + 2
	case 'r':
		if i+2 < len(raw) && raw[i+2] == '\n' {
			return i + 3 // \r\n line continuation: removed
		}
		return i + 2
	case '\n':
		return i + 2 // line continuation: removed
	case 't':
		b.WriteByte('\t')
		return i + 2
	case 'b':
		b.WriteByte('\b')
		return i + 2
	case 'f':
		b.WriteByte('\f')
		return i + 2
	case 'v':
		b.WriteByte('\v')
		return i + 2
	case '0':
		b.WriteByte(0)
		return i + 2
	case '\'', '"', '\\', '/':
		b.WriteByte(e)
		return i + 2
	case 'x':
		if i+3 < len(raw) && isHex(raw[i+2]) && isHex(raw[i+3]) {
			b.WriteByte(byte(hexVal(raw[i+2])<<4 | hexVal(raw[i+3])))
			return i + 4
		}
		b.WriteString(`\x`) // invalid: keep raw
		return i + 2
	case 'u':
		if i+2 < len(raw) && raw[i+2] == '{' {
			j := i + 3
			v := 0
			n := 0
			for j < len(raw) && n < 6 && isHex(raw[j]) {
				v = v<<4 | hexVal(raw[j])
				j++
				n++
			}
			if n >= 1 && j < len(raw) && raw[j] == '}' {
				b.WriteRune(rune(v)) // best-effort: out-of-range values become U+FFFD
				return j + 1
			}
			b.WriteString(`\u`) // invalid: keep raw
			return i + 2
		}
		if i+5 < len(raw) && isHex(raw[i+2]) && isHex(raw[i+3]) && isHex(raw[i+4]) && isHex(raw[i+5]) {
			hi := hexVal(raw[i+2])<<12 | hexVal(raw[i+3])<<8 | hexVal(raw[i+4])<<4 | hexVal(raw[i+5])
			if hi >= 0xD800 && hi <= 0xDBFF && i+11 < len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' &&
				isHex(raw[i+8]) && isHex(raw[i+9]) && isHex(raw[i+10]) && isHex(raw[i+11]) {
				lo := hexVal(raw[i+8])<<12 | hexVal(raw[i+9])<<8 | hexVal(raw[i+10])<<4 | hexVal(raw[i+11])
				if lo >= 0xDC00 && lo <= 0xDFFF {
					// Surrogate pair: U+10000 + ((hi-0xD800)<<10) + (lo-0xDC00),
					// always within the valid rune range (max U+10FFFF).
					b.WriteRune(rune(0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00)))
					return i + 12
				}
			}
			b.WriteRune(rune(hi)) // lone surrogates decode to U+FFFD (best-effort)
			return i + 6
		}
		b.WriteString(`\u`) // invalid: keep raw
		return i + 2
	case 0xe2:
		if i+3 < len(raw) && raw[i+2] == 0x80 && (raw[i+3] == 0xa8 || raw[i+3] == 0xa9) {
			return i + 4 // U+2028/U+2029 line continuation: removed
		}
		b.WriteByte(e) // unknown escape: keep the character after the backslash
		return i + 2
	default:
		b.WriteByte(e) // unknown escape: keep the character after the backslash
		return i + 2
	}
}

// copyTemplateExpr copies a ${...} expression segment of a template literal
// into b VERBATIM — escapes and nested constructs inside expressions are
// never decoded — and returns the index just past the closing brace. Nested
// strings, nested templates, and backslash escapes are honored so braces
// inside them cannot end the segment early; a `}` inside a regex literal or
// a line comment may end it early (documented limitation). Beyond
// maxTemplateExprNesting levels of nested templates the remaining template
// text is copied verbatim (bounded, deterministic recovery).
func copyTemplateExpr(raw string, i int, b *strings.Builder, level int) int {
	b.WriteString("${")
	depth := 1
	i += 2
	for i < len(raw) {
		c := raw[i]
		switch {
		case c == '\\':
			b.WriteByte(c)
			i++
			if i < len(raw) {
				b.WriteByte(raw[i])
				i++
			}
		case c == '\'' || c == '"':
			q := c
			b.WriteByte(c)
			i++
			for i < len(raw) && raw[i] != q {
				if raw[i] == '\\' {
					b.WriteByte(raw[i])
					i++
					if i < len(raw) {
						b.WriteByte(raw[i])
						i++
					}
					continue
				}
				b.WriteByte(raw[i])
				i++
			}
			if i < len(raw) {
				b.WriteByte(raw[i]) // closing quote
				i++
			}
		case c == '`':
			n := copyNestedTemplate(raw, i, b, level+1)
			if n < 0 {
				b.WriteString(raw[i:])
				return len(raw)
			}
			i = n
		case c == '{':
			depth++
			b.WriteByte(c)
			i++
		case c == '}':
			depth--
			b.WriteByte(c)
			i++
			if depth == 0 {
				return i
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return i
}

// copyNestedTemplate copies a nested template literal (opening backtick at
// raw[i]) verbatim into b and returns the index just past its closing
// backtick. level is the current nesting depth; exceeding
// maxTemplateExprNesting returns -1 so the caller can fall back to copying
// the remainder verbatim.
func copyNestedTemplate(raw string, i int, b *strings.Builder, level int) int {
	if level > maxTemplateExprNesting {
		return -1
	}
	b.WriteByte(raw[i]) // opening backtick
	i++
	for i < len(raw) {
		c := raw[i]
		switch {
		case c == '\\':
			b.WriteByte(c)
			i++
			if i < len(raw) {
				b.WriteByte(raw[i])
				i++
			}
		case c == '`':
			b.WriteByte(c)
			i++
			return i
		case c == '$' && i+1 < len(raw) && raw[i+1] == '{':
			i = copyTemplateExpr(raw, i, b, level+1)
		default:
			b.WriteByte(c)
			i++
		}
	}
	return i
}
