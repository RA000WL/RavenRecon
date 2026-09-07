package js

import (
	"context"
	"strings"
)

// tokenize.go implements NEW-123's token-aware precision layer for the JS
// pack's three detectors (domxss, postmessage, prototypepollution).
//
// Why a minimal local tokenizer instead of jsintel's Parsed output:
// import legality was checked first — `rg internal/detect internal/jsintel`
// finds no matches, so jsintel does not import detect and packs/js COULD
// import jsintel.NewParser without a cycle. Parsed is still the wrong
// signal here: it exposes only Imports/Exports/Strings VALUES (decoded,
// without byte spans), plus Truncated/Malformed — no code-token spans, no
// file-relative offsets, and no handler scope. The Slice 3 attribution
// contract requires citing the FIRST CODE sink at its file-relative offset
// (subject=file, evidence `signal @offset`, overlap collapse), and each
// rule needs a structural condition beyond substring (sink-LHS assignment,
// document.write call, addEventListener first-arg-is-message, statement-
// bounded proto assignment, origin-in-code). A Strings-value counting
// scheme over Parsed cannot supply offsets or scope without fragile
// re-location, and calling Parse per body per rule would double tokenizing
// cost on top of the scan below. So predicates consult THIS file's parser
// output — the per-byte code mask plus the structural finders — which is a
// real code-vs-string/comment distinction with exact original offsets.
//
// Bounds and timeout behavior (AGENTS.md §0.7, §10): inputs are snapshot
// retained bodies, pre-bounded by the engine to MaxSnapshotJSContentBodyBytes
// (2 MiB per body, 1024 bodies, 64 MiB total) and by the chunk channel to
// 512 KiB windows — both far below jsintel's 8 MiB maxParseInputBytes hard
// cap, so no input cap is needed here. codeMask is a SINGLE linear pass
// over the body (every byte visited O(1) times, no backtracking, no
// recursion): template-expression nesting is capped at 64 levels (mirroring
// jsintel's maxTemplateExprNesting) and the ${} brace stack at 64 frames,
// so hostile bundles (unterminated strings/comments/templates, megabyte
// identifiers, deep nesting) complete in linear time with O(n) mask bytes
// and no per-parse timeout beyond the rule's 2s Timeout. Finder walks over
// the mask are bounded, never naive linear-to-EOF per occurrence: each
// __proto__/constructor.prototype occurrence scans at most one 4 KiB
// statement window for its assignment (maxStmtScanBytes), each
// addEventListener occurrence scans at most one 4 KiB literal window for
// its first-argument string (maxStaticStringScanBytes, static-unknown past
// the cap), next/prev-code skips cost O(gap) to the next code byte (linear
// overall — gaps are skipped forward to code, never rescanned to EOF),
// and every finder honors ctx (checked every 128 occurrences),
// so N×`x.__proto__` reads with no terminators and single-line N×
// `x.addEventListener("` unterminated stay quiet in linear,
// interruptible time (pinned by TestJSFPProtoHostileReadsBounded's and
// TestJSFPPostMessageHostileReadsBounded's 5s guards). A 512 KiB hostile
// chunk completes with timing logged under a 5s hang guard (pinned by
// TestJSFPHostileChunkBounded — no pathological blowup vs the old
// substring scan).
//
// Fidelity limits (heuristic, informational rules): regex literals are NOT
// lexed — their contents count as code, so a `//` or `/*` inside a regex
// literal can misclassify the rest of the line/block as a comment
// (conservative: fewer fires). Bracket-notation sinks whose property name
// is a string literal (`el["innerHTML"] = x`, `obj["__proto__"] = y`) count
// as string mentions and stay quiet — only dotted property writes fire.
// `=` inside the operator scan respects `==`/`===`/`!=`/`<=`/`>=`/`=>`.

// maxTokenizerNesting bounds template-literal nesting and open ${}
// expression frames in codeMask (mirrors jsintel maxTemplateExprNesting 64).
const maxTokenizerNesting = 64

// maxStmtScanBytes caps the forward assignment search per proto occurrence
// (HIGH linear bound): hasCodeAssignInStmt never scans past from+4 KiB, so
// N occurrences cost O(N*4 KiB) worst case — linear in body size with a
// constant window — instead of O(N*n) to EOF. Statements longer than 4 KiB
// without a terminator stop scanning and stay quiet (documented FN edge,
// conservative: fewer fires; no pinned recall approaches the window).
const maxStmtScanBytes = 4096

// finderCtxCheckEvery bounds cancellation latency (AGENTS.md §10): every
// finder (including the .origin scan) checks ctx every 128 needle
// occurrences. Detectors propagate ctx.Err() so a cancelled run stops promptly.
const finderCtxCheckEvery = 128

// maxStaticStringScanBytes caps the literal scan per addEventListener
// occurrence (HIGH linear bound): parseStaticString never scans past
// j+1+4 KiB, so N occurrences cost O(N*4 KiB) worst case — linear in body
// size with a constant window — instead of O(N*n) to EOF. Literals longer
// than 4 KiB without a closing delimiter stop scanning and stay quiet
// (static-unknown, documented FN edge, conservative: fewer fires; no
// pinned recall approaches the window — "message" is 7 bytes).
const maxStaticStringScanBytes = 4096

// codeMask returns one entry per byte of src: true when the byte is
// JavaScript code, false when inside a line/block comment, a single- or
// double-quoted string literal's CONTENTS, or template TEXT (template ${...}
// expression interiors are code and scan normally, including nested
// templates). String/template DELIMITERS (quotes, backticks) count as code:
// they are code positions that open a non-code region, so code navigation
// can land on them to parse static call arguments — while comment markers
// and every comment byte count as non-code and are always skipped.
// Unterminated constructs recover at EOF (single/double strings
// additionally end at an unescaped line terminator per the JS spec) —
// recovery never fails and never loops. Callers pass the SAME case-folded
// body they search, so mask indices align with search indices by
// construction (byte-equal to original-body offsets for ASCII, a heuristic
// approximation otherwise — case folding can shift byte offsets in
// non-ASCII text — sufficient for evidence citation, never a byte-exact
// source range).
func codeMask(src string) []bool {
	n := len(src)
	mask := make([]bool, n)
	for i := range mask {
		mask[i] = true
	}
	var exprStack []int // open ${...} brace depths (capped)
	inTmpl := false     // scanning template text of the innermost template
	tmplDepth := 0      // open template levels (capped)
	i := 0
	for i < n {
		c := src[i]
		if inTmpl {
			switch {
			case c == '\\' && i+1 < n:
				mask[i] = false
				mask[i+1] = false
				i += 2
			case c == '\\':
				mask[i] = false
				i++
			case c == '$' && i+1 < n && src[i+1] == '{':
				// Past-cap fail direction: excess ${ stays template TEXT
				// (non-code, conservative — fewer fires). The brace frame
				// is dropped so nesting stays bounded.
				if len(exprStack) >= maxTokenizerNesting {
					mask[i] = false
					mask[i+1] = false
					i += 2
					continue
				}
				// ${ stays code (expression delimiters).
				exprStack = append(exprStack, 1)
				inTmpl = false
				i += 2
			case c == '`':
				// End of the current template level (a code delimiter).
				tmplDepth--
				inTmpl = false
				i++
			default:
				mask[i] = false
				i++
			}
			continue
		}
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			mask[i] = false
			mask[i+1] = false
			j := i + 2
			for j < n && src[j] != '\n' && src[j] != '\r' {
				mask[j] = false
				j++
			}
			i = j
		case c == '/' && i+1 < n && src[i+1] == '*':
			mask[i] = false
			mask[i+1] = false
			j := i + 2
			for j < n {
				if src[j] == '*' && j+1 < n && src[j+1] == '/' {
					mask[j] = false
					mask[j+1] = false
					j += 2
					break
				}
				mask[j] = false
				j++
			}
			i = j
		case c == '\'' || c == '"':
			q := c
			// Opening quote is a code delimiter; contents are non-code.
			j := i + 1
			for j < n {
				d := src[j]
				if d == '\\' {
					mask[j] = false
					if j+1 < n {
						mask[j+1] = false
						j += 2
					} else {
						j++
					}
					continue
				}
				if d == q {
					// Closing quote is a code delimiter.
					j++
					break
				}
				if d == '\n' || d == '\r' {
					break // unescaped terminator ends the string; it stays code
				}
				mask[j] = false
				j++
			}
			i = j
		case c == '`':
			// Past-cap fail direction: excess backticks stay CODE (the
			// template never opens, so following template text scans as
			// code — liberal, may fire more). Conservative would be to
			// swallow text as non-code, but that needs unbounded stack;
			// the liberal direction is documented and pinned quiet-safe
			// by the benign/hostile suites (no template-adjacent sinks).
			if tmplDepth >= maxTokenizerNesting {
				i++ // pathological nesting: treat the backtick as code text
				continue
			}
			// Opening backtick is a code delimiter.
			tmplDepth++
			inTmpl = true
			i++
		case c == '{':
			if len(exprStack) > 0 {
				exprStack[len(exprStack)-1]++
			}
			i++
		case c == '}':
			if len(exprStack) > 0 {
				top := len(exprStack) - 1
				exprStack[top]--
				if exprStack[top] == 0 {
					exprStack = exprStack[:top]
					inTmpl = true
				}
			}
			i++
		default:
			i++
		}
	}
	return mask
}

// isIdentByte reports whether c continues a JavaScript identifier.
// Bytes >= 0x80 count as identifier-continuation: UTF-8 encoded
// identifier chars (and any non-ASCII byte) never split an identifier
// boundary check, so `éwrite` cannot read as `write`.
func isIdentByte(c byte) bool {
	if c >= 0x80 {
		return true
	}
	return c == '_' || c == '$' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// isSpaceByte reports ASCII whitespace skipped around sink operators.
func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// allCode reports whether mask marks every byte in [from,to) as code.
func allCode(mask []bool, from, to int) bool {
	if from < 0 || to > len(mask) || from > to {
		return false
	}
	for k := from; k < to; k++ {
		if !mask[k] {
			return false
		}
	}
	return true
}

// prevCodeNonSpace returns the index of the previous code, non-whitespace
// byte before idx, or -1. Comment/string bytes are skipped, so
// `el /*c*/ . innerHTML` still resolves its dotted access.
func prevCodeNonSpace(s string, mask []bool, idx int) int {
	for j := idx - 1; j >= 0; j-- {
		if !mask[j] {
			continue
		}
		if isSpaceByte(s[j]) {
			continue
		}
		return j
	}
	return -1
}

// nextCodeNonSpace returns the index of the next code, non-whitespace byte
// at or after idx, or -1.
func nextCodeNonSpace(s string, mask []bool, idx int) int {
	for j := idx; j < len(s); j++ {
		if !mask[j] {
			continue
		}
		if isSpaceByte(s[j]) {
			continue
		}
		return j
	}
	return -1
}

// isAssignOpAt reports whether an assignment operator starts at s[pos]
// (pos must be code). It accepts `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`,
// `|=`, `^=`, `<<=`, `>>=`, `>>>=`, `**=`, `&&=`, `||=`, `??=` and rejects
// the comparison/arrow lookalikes `==`, `===`, `!=`, `<=`, `>=`, `=>`
// (angle-doubled `<<=`/`>>=`/`>>>=` are assignments; single `<=`/`>=` are
// not). Multi-char operators must be contiguous code.
func isAssignOpAt(s string, mask []bool, pos int) bool {
	if pos < 0 || pos >= len(s) || !mask[pos] {
		return false
	}
	if pos+4 <= len(s) && s[pos:pos+4] == ">>>=" && allCode(mask, pos, pos+4) {
		return true
	}
	if pos+3 <= len(s) && allCode(mask, pos, pos+3) {
		switch s[pos : pos+3] {
		case "<<=", ">>=", "**=", "&&=", "||=", "??=":
			return true
		}
	}
	if pos+2 <= len(s) && allCode(mask, pos, pos+2) {
		switch s[pos : pos+2] {
		case "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=":
			return true
		}
	}
	if s[pos] != '=' {
		return false
	}
	if pos+1 < len(s) && (s[pos+1] == '=' || s[pos+1] == '>') {
		return false // ==, ===, =>
	}
	if pos > 0 {
		switch p := s[pos-1]; p {
		case '=', '!':
			return false // second half of ==, ===, !=, !==
		case '<', '>':
			// <<=, >>=, >>>= carry a doubled angle; single <=, >= do not.
			if pos < 2 || (s[pos-2] != '<' && s[pos-2] != '>') {
				return false
			}
		}
	}
	return true
}

// hasCodeAssignInStmt reports whether an assignment operator occurs in code
// from `from` forward before a statement terminator (code `;`, `{`, `}`,
// `)`, `,`, `:`) or the 4 KiB statement-window cap (maxStmtScanBytes) or
// EOF. The `)` terminator keeps `if (x.__proto__ == y) z = 1;` quiet (the
// search stops at the condition's close paren before the later statement's
// `=`); `,` and `:` likewise stop cross-expression bleed (`foo(o.__proto__,
// y)` and `{__proto__: v}` stay quiet — conservative: fewer fires,
// documented). It lets `obj.__proto__.polluted = true` satisfy the sink-LHS
// check across the `.polluted` continuation while `if (x.__proto__) {}`
// stays quiet (the `{` terminates the search before any later statement's
// `=`). Comment/string `=` never counts (non-code bytes are skipped).
// `?` and `]` are deliberately NOT terminators (liberal direction: the
// search continues past ternaries and index expressions to a later `=`,
// so `x.__proto__ ? a = 1 : b` and `a[x.__proto__] = 1` fire; treating
// them as terminators would quiet such shapes — conservative — at the risk
// of missing real writes. The current choice may FP on compare-then-assign
// across `?`/`]`; documented, pinned quiet-safe by the benign suite).
func hasCodeAssignInStmt(s string, mask []bool, from int) bool {
	limit := from + maxStmtScanBytes
	if limit > len(s) {
		limit = len(s)
	}
	if from < 0 {
		from = 0
	}
	for j := from; j < limit; j++ {
		if !mask[j] {
			continue
		}
		switch c := s[j]; c {
		case ';', '{', '}', ')', ',', ':':
			return false
		case '=', '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '?':
			if isAssignOpAt(s, mask, j) {
				return true
			}
		}
	}
	return false
}

// domXSSCodeSink returns the smallest byte offset of a STRUCTURAL DOM XSS
// sink in code, or -1: `innerHTML`/`outerHTML` as dotted property access
// (previous code token `.`) followed by an assignment operator, or
// `document.write` (identifier-bounded, so `mydocument.write` does not
// match) followed by a call `(`. The `document . write` gap (spaces or
// comments between `document`, `.`, `write`) resolves through the same
// prev/nextCodeNonSpace + allCode spacing logic as innerHTML, so
// `document /*c*/.write(x)` and `document .write(x)` fire. Comment/string/
// template mentions, bare reads (`var x = el.innerHTML`), comparisons
// (`==`), and unterminated-trap words never satisfy the structure.
func domXSSCodeSink(s string, mask []bool) int {
	v, _ := domXSSCodeSinkCtx(context.Background(), s, mask)
	return v
}

// domXSSCodeSinkCtx is domXSSCodeSink with cancellation: ctx is checked
// every finderCtxCheckEvery occurrences per needle.
func domXSSCodeSinkCtx(ctx context.Context, s string, mask []bool) (int, error) {
	best := -1
	for _, needle := range []string{"innerhtml", "outerhtml"} {
		from := 0
		seen := 0
		for from <= len(s) {
			rel := strings.Index(s[from:], needle)
			if rel < 0 {
				break
			}
			idx := from + rel
			from = idx + 1
			seen++
			if seen%finderCtxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
			}
			end := idx + len(needle)
			if end < len(s) && isIdentByte(s[end]) {
				continue
			}
			if !allCode(mask, idx, end) {
				continue
			}
			if prev := prevCodeNonSpace(s, mask, idx); prev < 0 || s[prev] != '.' {
				continue
			}
			if nxt := nextCodeNonSpace(s, mask, end); nxt < 0 || !isAssignOpAt(s, mask, nxt) {
				continue
			}
			if best < 0 || idx < best {
				best = idx
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
	}
	{
		from := 0
		seen := 0
		for from <= len(s) {
			rel := strings.Index(s[from:], "document")
			if rel < 0 {
				break
			}
			idx := from + rel
			from = idx + 1
			seen++
			if seen%finderCtxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
			}
			endDoc := idx + len("document")
			if idx > 0 && isIdentByte(s[idx-1]) {
				continue
			}
			if endDoc < len(s) && isIdentByte(s[endDoc]) {
				continue
			}
			if !allCode(mask, idx, endDoc) {
				continue
			}
			dot := nextCodeNonSpace(s, mask, endDoc)
			if dot < 0 || s[dot] != '.' {
				continue
			}
			wIdx := nextCodeNonSpace(s, mask, dot+1)
			if wIdx < 0 || !strings.HasPrefix(s[wIdx:], "write") {
				continue
			}
			wEnd := wIdx + len("write")
			if wEnd < len(s) && isIdentByte(s[wEnd]) {
				continue
			}
			if !allCode(mask, wIdx, wEnd) {
				continue
			}
			if nxt := nextCodeNonSpace(s, mask, wEnd); nxt < 0 || s[nxt] != '(' || !mask[nxt] {
				continue
			}
			if best < 0 || idx < best {
				best = idx
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
	}
	return best, nil
}

// postMessageCodeHandler returns the smallest byte offset of a code
// `addEventListener` call whose first argument is the static string
// "message" (any quote style; case-folded by the caller), or -1. A
// `"message"` literal anywhere else — a variable initializer, another
// event type's sibling, a comment — does not satisfy the handler scope:
// `addEventListener("click", ...)` with `var msg = "message"` stays
// quiet. Non-static first arguments (variables, template `${...}`) stay
// quiet: the event type is statically unknown.
func postMessageCodeHandler(s string, mask []bool) int {
	v, _ := postMessageCodeHandlerCtx(context.Background(), s, mask)
	return v
}

// postMessageCodeHandlerCtx is postMessageCodeHandler with cancellation:
// ctx is checked every finderCtxCheckEvery occurrences, with a final check
// so a cancelled run stops promptly even on short bodies.
func postMessageCodeHandlerCtx(ctx context.Context, s string, mask []bool) (int, error) {
	needle := "addeventlistener"
	from := 0
	seen := 0
	for from <= len(s) {
		rel := strings.Index(s[from:], needle)
		if rel < 0 {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			return -1, nil
		}
		idx := from + rel
		from = idx + 1
		seen++
		if seen%finderCtxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
		}
		end := idx + len(needle)
		if end < len(s) && isIdentByte(s[end]) {
			continue
		}
		if idx > 0 && isIdentByte(s[idx-1]) {
			continue
		}
		if !allCode(mask, idx, end) {
			continue
		}
		open := nextCodeNonSpace(s, mask, end)
		if open < 0 || s[open] != '(' || !mask[open] {
			continue
		}
		val, ok := parseFirstStringArg(s, mask, open)
		if !ok || val != "message" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		return idx, nil
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	return -1, nil
}

// parseFirstStringArg returns the raw (caller-folded) value of the first
// call argument at openIdx when it is a static single/double-quoted string
// or a static (expression-free) template, optionally wrapped in ONE
// parenthesized layer (`("message")` unwraps; deeper nesting stays quiet).
// It returns ok=false for any other argument shape (variables and other
// var-alias shapes are statically unknown and stay quiet alongside the
// paren limit), for unterminated or over-cap literals, and — in both
// branches — unless the next code byte after the closing delimiter is `,`
// or `)` (so `"message"+x` and `("message")+suffix` stay quiet: the first
// argument is a concatenation expression, not the static event type).
func parseFirstStringArg(s string, mask []bool, openIdx int) (val string, ok bool) {
	j := nextCodeNonSpace(s, mask, openIdx+1)
	if j < 0 || !mask[j] {
		return "", false
	}
	if s[j] == '(' && mask[j] {
		inner := nextCodeNonSpace(s, mask, j+1)
		if inner < 0 || !mask[inner] {
			return "", false
		}
		v, cEnd, ok := parseStaticString(s, inner)
		if !ok {
			return "", false
		}
		close := nextCodeNonSpace(s, mask, cEnd)
		if close < 0 || s[close] != ')' || !mask[close] {
			return "", false
		}
		outer := nextCodeNonSpace(s, mask, close+1)
		if outer < 0 || (s[outer] != ',' && s[outer] != ')') || !mask[outer] {
			return "", false
		}
		return v, true
	}
	v, cEnd, ok := parseStaticString(s, j)
	if !ok {
		return "", false
	}
	nxt := nextCodeNonSpace(s, mask, cEnd)
	if nxt < 0 || (s[nxt] != ',' && s[nxt] != ')') || !mask[nxt] {
		return "", false
	}
	return v, true
}

// parseStaticString parses a static string/template literal starting at j
// (which must be a quote or backtick) and returns its raw contents plus the
// index just past the closing delimiter. The scan never runs past
// j+1+maxStaticStringScanBytes: literals longer than 4 KiB without a
// closing delimiter (or newline for '/", expression open for backticks)
// stop scanning and report static-unknown (ok=false, conservative: fewer
// fires), so no per-occurrence scan runs to EOF.
func parseStaticString(s string, j int) (string, int, bool) {
	if j < 0 || j >= len(s) {
		return "", 0, false
	}
	q := s[j]
	if q != '\'' && q != '"' && q != '`' {
		return "", 0, false
	}
	limit := j + 1 + maxStaticStringScanBytes
	if limit > len(s) {
		limit = len(s)
	}
	for k := j + 1; k < limit; k++ {
		c := s[k]
		if c == '\\' {
			k++ // skip the escaped byte (contents need no mask check)
			continue
		}
		if q == '`' && c == '$' && k+1 < len(s) && s[k+1] == '{' {
			return "", 0, false
		}
		if c == q {
			return s[j+1 : k], k + 1, true
		}
		if (q == '\'' || q == '"') && (c == '\n' || c == '\r') {
			return "", 0, false
		}
	}
	return "", 0, false
}

// hasCodeOrigin reports whether `.origin` occurs in code (trailing-
// identifier-bounded, so `.originX` does not count). No preceding check:
// `e.origin` legitimately follows an identifier. A comment-only
// `e.origin` mention never counts, so the guarded-looking-comment FN trap
// fires.
//
// Scope is deliberately FILE-GLOBAL (known-FN limitation, MEDIUM-2 choice
// B): any code `.origin` anywhere in the body suppresses the postMessage
// rule, even when it guards a different handler. A guarded handler plus an
// unguarded handler in one file therefore stays quiet (pinned by
// TestJSFPPostMessageFileGlobalOriginLimitation). Handler-scoped search
// (origin within the handler's parens/body) would fix the FN but needs
// handler-body bounds the current finders do not recover; the file-global
// direction stays conservative (fewer fires) and recall/safe gates hold.
func hasCodeOrigin(s string, mask []bool) bool {
	v, _ := hasCodeOriginCtx(context.Background(), s, mask)
	return v
}

// hasCodeOriginCtx is hasCodeOrigin with cancellation: ctx is checked
// every finderCtxCheckEvery occurrences (like every other finder) with a
// final check so a cancelled run stops promptly even on short bodies.
func hasCodeOriginCtx(ctx context.Context, s string, mask []bool) (bool, error) {
	const needle = ".origin"
	from := 0
	seen := 0
	for from <= len(s) {
		rel := strings.Index(s[from:], needle)
		if rel < 0 {
			break
		}
		idx := from + rel
		from = idx + 1
		seen++
		if seen%finderCtxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		end := idx + len(needle)
		if end < len(s) && isIdentByte(s[end]) {
			continue
		}
		if allCode(mask, idx, end) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// protoCodeSink returns the smallest byte offset of a STRUCTURAL prototype
// pollution write in code, or -1: `__proto__` or `constructor.prototype`
// as dotted property access (previous code token `.`, so `x__proto__` and
// `myconstructor.prototype` do not match) with a statement-bounded code
// assignment after it (4 KiB window, `;{}):,` terminators; see
// hasCodeAssignInStmt). The `constructor . prototype` gap (spaces or
// comments between `constructor`, `.`, `prototype`) resolves through the
// same prev/nextCodeNonSpace + allCode spacing logic as `__proto__`.
// Comment/string mentions, bare reads (`if (x.__proto__) {}`), and
// `Object.prototype` (no `constructor` qualifier) stay quiet.
func protoCodeSink(s string, mask []bool) int {
	v, _ := protoCodeSinkCtx(context.Background(), s, mask)
	return v
}

// protoCodeSinkCtx is protoCodeSink with cancellation (HIGH): a single
// forward scan per needle family where each occurrence costs at most one
// 4 KiB statement-window search — linear overall — with ctx checked every
// finderCtxCheckEvery occurrences.
func protoCodeSinkCtx(ctx context.Context, s string, mask []bool) (int, error) {
	best := -1
	{
		from := 0
		seen := 0
		for from <= len(s) {
			rel := strings.Index(s[from:], "__proto__")
			if rel < 0 {
				break
			}
			idx := from + rel
			from = idx + 1
			seen++
			if seen%finderCtxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
			}
			end := idx + len("__proto__")
			if end < len(s) && isIdentByte(s[end]) {
				continue
			}
			if !allCode(mask, idx, end) {
				continue
			}
			if prev := prevCodeNonSpace(s, mask, idx); prev < 0 || s[prev] != '.' {
				continue
			}
			if !hasCodeAssignInStmt(s, mask, end) {
				continue
			}
			if best < 0 || idx < best {
				best = idx
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
	}
	{
		from := 0
		seen := 0
		for from <= len(s) {
			rel := strings.Index(s[from:], "constructor")
			if rel < 0 {
				break
			}
			idx := from + rel
			from = idx + 1
			seen++
			if seen%finderCtxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
			}
			endCtor := idx + len("constructor")
			if idx > 0 && isIdentByte(s[idx-1]) {
				continue
			}
			if endCtor < len(s) && isIdentByte(s[endCtor]) {
				continue
			}
			if !allCode(mask, idx, endCtor) {
				continue
			}
			if prev := prevCodeNonSpace(s, mask, idx); prev < 0 || s[prev] != '.' {
				continue
			}
			dot := nextCodeNonSpace(s, mask, endCtor)
			if dot < 0 || s[dot] != '.' {
				continue
			}
			pIdx := nextCodeNonSpace(s, mask, dot+1)
			if pIdx < 0 || !strings.HasPrefix(s[pIdx:], "prototype") {
				continue
			}
			pEnd := pIdx + len("prototype")
			if pEnd < len(s) && isIdentByte(s[pEnd]) {
				continue
			}
			if !allCode(mask, pIdx, pEnd) {
				continue
			}
			if !hasCodeAssignInStmt(s, mask, pEnd) {
				continue
			}
			if best < 0 || idx < best {
				best = idx
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
	}
	return best, nil
}
