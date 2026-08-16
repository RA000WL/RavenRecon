package jsintel

import "unicode/utf8"

// lex.go implements the tokenizer half of the jsintel parser: a hand-rolled,
// error-tolerant JavaScript token scanner that runs to completion on ANY byte
// input — no panics, no infinite loops (every scan step advances or hits
// EOF/EOL). It is not a full JS lexer: it tokenizes exactly what the
// extraction walk needs and recovers from malformed constructs by stopping
// them at the nearest recoverable boundary (EOL for regexes, EOF for
// unterminated strings/comments/templates) and counting the damage on
// Parsed.Malformed.
//
// Regex-vs-division disambiguation is a deterministic state machine over the
// previous SIGNIFICANT token (comments and whitespace do not affect it): a
// `/` or `/=` starts a regex literal when the previous significant token is
// none (start of input), a punctuation token other than `)` `]` `}` `++` `--`
// (this includes multi-char operators such as `&&`, `||`, `=>` — they cannot
// end an expression), or one of the keywords return, typeof, instanceof, in,
// of, new, delete, void, case, do, else, yield, await, default. Otherwise (an
// identifier or non-listed keyword, number, string, template, regex, `)` `]`
// `}` `++` `--`) it is division. The spec's operator set lists `}` as
// regex-allowing while its division list also lists `}`; the division list
// wins here, so `}` behaves like an operand. This is a documented heuristic:
// pathological programs (for example `return\n/re/` — an ASI edge — or
// `throw /re/`, since throw is not in the keyword set) may mis-tokenize, but
// the scanner never panics and never consumes unboundedly.

// maxTemplateNesting bounds how deeply nested template literals the scanner
// follows inside ${...} expressions. Deeper nesting is recovered from (the
// backtick is treated as ordinary text) and counted malformed, so the
// scanner's internal frame stack stays trivially bounded.
const maxTemplateNesting = 256

// tokKind classifies one token.
type tokKind uint8

const (
	tokIdent        tokKind = iota // identifier or keyword (the parser distinguishes keywords by text)
	tokNumber                      // numeric literal (its text is never used by the parser)
	tokString                      // '...' or "..." — text is the raw content between the quotes
	tokTemplate                    // `...` — text is the FULL raw content between the backticks
	tokRegex                       // /.../ — text is the raw pattern between the slashes (no slashes, no flags)
	tokPunct                       // one operator/punctuation token (maximal multi-char match)
	tokLineComment                 // //... — text is the content after //
	tokBlockComment                // /*...*/ — text is the content between the delimiters
)

// String returns a short name for diagnostics and tests.
func (k tokKind) String() string {
	switch k {
	case tokIdent:
		return "ident"
	case tokNumber:
		return "number"
	case tokString:
		return "string"
	case tokTemplate:
		return "template"
	case tokRegex:
		return "regex"
	case tokPunct:
		return "punct"
	case tokLineComment:
		return "linecomment"
	case tokBlockComment:
		return "blockcomment"
	}
	return "unknown"
}

// token is one lexical token: its kind, 1-based line, and byte span into the
// source (zero-copy — token text is a substring of the input).
type token struct {
	kind  tokKind
	line  uint32
	start uint32
	end   uint32
}

// text returns the token's source text (a zero-copy substring).
func (t token) text(src []byte) string {
	return string(src[t.start:t.end])
}

// lexer scans src into a bounded token stream. All state is per-run; the
// zero value is not usable — construct with the src, line, and regexOK
// fields set.
type lexer struct {
	src       []byte
	i         int
	line      int
	toks      []token
	truncated bool // token cap hit: the stream is an honest prefix
	malformed int  // recovered-from lexical errors
	regexOK   bool // whether a / at the current position starts a regex literal
}

// run scans the whole input. It is the only entry point.
func (lx *lexer) run() {
	// Leading BOM (EF BB BF) is skipped before tokenizing.
	if len(lx.src) >= 3 && lx.src[0] == 0xEF && lx.src[1] == 0xBB && lx.src[2] == 0xBF {
		lx.i = 3
	}
	// Shebang at byte 0 is skipped to the end of the line.
	if lx.i+1 < len(lx.src) && lx.src[lx.i] == '#' && lx.src[lx.i+1] == '!' {
		i := lx.i + 2
		for i < len(lx.src) && lx.src[i] != '\n' && lx.src[i] != '\r' {
			i++
		}
		lx.i = i
	}
	for lx.i < len(lx.src) && !lx.truncated {
		c := lx.src[lx.i]
		switch {
		case c == ' ' || c == '\t' || c == '\v' || c == '\f':
			lx.i++
		case c == '\n' || c == '\r':
			lx.line++
			lx.i = lx.advanceLineTerm(lx.i)
		case c == 0xe2 && lx.i+2 < len(lx.src) && lx.src[lx.i+1] == 0x80 && (lx.src[lx.i+2] == 0xa8 || lx.src[lx.i+2] == 0xa9):
			lx.line++ // U+2028/U+2029 are line terminators
			lx.i += 3
		case c >= 0x80:
			r, sz := utf8.DecodeRune(lx.src[lx.i:])
			if r == utf8.RuneError && sz == 1 {
				// Invalid UTF-8: count malformed and skip the byte.
				lx.malformed++
				lx.i++
			} else {
				lx.scanIdent()
			}
		case isIdentStart(c):
			lx.scanIdent()
		case c >= '0' && c <= '9':
			lx.scanNumber()
		case c == '.' && lx.i+1 < len(lx.src) && lx.src[lx.i+1] >= '0' && lx.src[lx.i+1] <= '9':
			lx.scanNumber()
		case c == '\'' || c == '"':
			lx.scanString(c)
		case c == '`':
			lx.scanTemplate()
		case c == '/':
			if lx.i+1 < len(lx.src) && lx.src[lx.i+1] == '/' {
				lx.scanLineComment()
			} else if lx.i+1 < len(lx.src) && lx.src[lx.i+1] == '*' {
				lx.scanBlockComment()
			} else if lx.regexOK {
				lx.scanRegex()
			} else {
				lx.scanPunct()
			}
		case isPunctByte(c):
			lx.scanPunct()
		default:
			// Stray byte (NUL, control character, lone backslash, ...):
			// count malformed and skip — never panic, never loop.
			lx.malformed++
			lx.i++
		}
	}
}

// advanceLineTerm returns the index just past the line terminator at src[i]
// (\n, \r, \r\n counted as ONE line, U+2028, U+2029). The caller increments
// the line counter exactly once per terminator.
func (lx *lexer) advanceLineTerm(i int) int {
	switch {
	case lx.src[i] == '\n':
		return i + 1
	case lx.src[i] == '\r':
		if i+1 < len(lx.src) && lx.src[i+1] == '\n' {
			return i + 2
		}
		return i + 1
	case lx.src[i] == 0xe2 && i+2 < len(lx.src) && lx.src[i+1] == 0x80 && (lx.src[i+2] == 0xa8 || lx.src[i+2] == 0xa9):
		return i + 3
	}
	return i + 1
}

// emit appends a token with the given 1-based line and updates the
// regex/division state (comments do not affect that state). It returns
// false when the token cap was hit — the stream stops there, marked
// truncated. Callers whose token text spans newlines pass the line where
// the token STARTS (captured before scanning the body); the line counter
// keeps counting newlines consumed so the NEXT token's line stays right.
func (lx *lexer) emit(kind tokKind, line, start, end int) bool {
	if len(lx.toks) >= maxParserTokens {
		lx.truncated = true
		return false
	}
	lx.toks = append(lx.toks, token{kind: kind, line: uint32(line), start: uint32(start), end: uint32(end)})
	if kind != tokLineComment && kind != tokBlockComment {
		lx.regexOK = regexAllowsToken(kind, string(lx.src[start:end]))
	}
	return true
}

// regexAllowsToken implements the regex-vs-division state machine: whether a
// / immediately AFTER the given significant token starts a regex literal.
func regexAllowsToken(kind tokKind, text string) bool {
	switch kind {
	case tokIdent:
		switch text {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "case", "do", "else", "yield", "await", "default":
			return true
		}
		return false
	case tokNumber, tokString, tokTemplate, tokRegex:
		return false
	case tokPunct:
		switch text {
		case ")", "]", "}", "++", "--":
			return false
		}
		return true
	}
	return false
}

// scanIdent scans an identifier or keyword. Any valid non-ASCII rune counts
// as identifier content (a permissive, deterministic superset of JS's
// ID_Continue). Identifiers are capped at maxParserIdentBytes: longer ones
// are split at the cap (on a rune boundary) and counted malformed.
func (lx *lexer) scanIdent() {
	start := lx.i
	i := start
	for i < len(lx.src) {
		c := lx.src[i]
		if isIdentPart(c) {
			i++
			continue
		}
		if c >= 0x80 {
			r, sz := utf8.DecodeRune(lx.src[i:])
			if r == utf8.RuneError && sz == 1 {
				break // invalid byte ends the identifier; run() skips it
			}
			if r == 0x2028 || r == 0x2029 {
				break // U+2028/U+2029 are line terminators, not identifier content
			}
			i += sz
			continue
		}
		break
	}
	end := i
	if end-start > maxParserIdentBytes {
		end = start + maxParserIdentBytes
		for end > start && lx.src[end]&0xC0 == 0x80 {
			end-- // back up to a rune boundary
		}
		lx.malformed++
	}
	lx.emit(tokIdent, lx.line, start, end)
	lx.i = end
}

// scanNumber scans a numeric literal. Its text is never used by the parser
// (numbers only matter as token boundaries), so the scan is a simple run:
// identifier-ish characters plus dots, with +/- allowed after e/E/p/P
// (exponents).
func (lx *lexer) scanNumber() {
	start := lx.i
	i := start
	for i < len(lx.src) {
		c := lx.src[i]
		if isIdentPart(c) || c == '.' {
			i++
			continue
		}
		if (c == '+' || c == '-') && i > start && (lx.src[i-1] == 'e' || lx.src[i-1] == 'E' || lx.src[i-1] == 'p' || lx.src[i-1] == 'P') {
			i++
			continue
		}
		break
	}
	lx.emit(tokNumber, lx.line, start, i)
	lx.i = i
}

// scanString scans a '...' or "..." literal. The token text is the raw
// content between the quotes; the token's line is the line where the
// literal STARTS (line continuations inside it count toward the next
// token's line). Escape sequences are validated here (bad \x and \u forms
// count malformed — the decode pass mirrors this exactly); a partial \x or
// \u escape keeps its digits in the value and scanning continues INSIDE the
// string, so the closing quote still ends it. A backslash followed by a
// line terminator is a line continuation and keeps the string open; an
// UNescaped line terminator ends the string (JS spec behavior) and counts
// malformed; EOF leaves it unterminated (malformed).
func (lx *lexer) scanString(quote byte) {
	start := lx.i
	line := lx.line
	i := start + 1
	for i < len(lx.src) {
		c := lx.src[i]
		switch {
		case c == quote:
			lx.emit(tokString, line, start+1, i)
			lx.i = i + 1
			return
		case c == '\\':
			i++
			if i >= len(lx.src) {
				break // trailing backslash at EOF: unterminated
			}
			e := lx.src[i]
			switch {
			case e == '\n':
				lx.line++ // line continuation
				i++
			case e == '\r':
				i++
				if i < len(lx.src) && lx.src[i] == '\n' {
					i++
				}
				lx.line++
			case e == 0xe2 && i+2 < len(lx.src) && lx.src[i+1] == 0x80 && (lx.src[i+2] == 0xa8 || lx.src[i+2] == 0xa9):
				lx.line++ // U+2028/U+2029 line continuation
				i += 3
			case e == 'x':
				// Consume only the hex digits actually present: a
				// partial \x keeps its text in the value and the
				// scan continues inside the string.
				n := 0
				for n < 2 && i+1+n < len(lx.src) && isHex(lx.src[i+1+n]) {
					n++
				}
				if n < 2 {
					lx.malformed++
				}
				i += 1 + n
			case e == 'u':
				if i+1 < len(lx.src) && lx.src[i+1] == '{' {
					j := i + 2
					n := 0
					for j < len(lx.src) && n < 6 && isHex(lx.src[j]) {
						j++
						n++
					}
					if n == 0 || j >= len(lx.src) || lx.src[j] != '}' {
						lx.malformed++
					}
					i = j
				} else {
					// Consume only the hex digits actually
					// present, as for \x above.
					n := 0
					for n < 4 && i+1+n < len(lx.src) && isHex(lx.src[i+1+n]) {
						n++
					}
					if n < 4 {
						lx.malformed++
					}
					i += 1 + n
				}
			default:
				i++
			}
		case c == '\n' || c == '\r':
			// Unescaped line terminator ends the string (JS spec behavior);
			// the terminator itself is consumed by whitespace handling.
			lx.malformed++
			lx.emit(tokString, line, start+1, i)
			lx.i = i
			return
		default:
			i++
		}
	}
	// Unterminated at EOF: recover, count malformed.
	lx.malformed++
	lx.emit(tokString, line, start+1, len(lx.src))
	lx.i = len(lx.src)
}

// scanTemplate scans a backtick template literal. The token text is the FULL
// raw content between the outer backticks (${...} expression interiors
// included); the token's line is the line where the literal STARTS.
// ${...} expressions are scanned with balanced brace counting and quote,
// comment, regex, and nested-template awareness (an explicit frame stack —
// no recursion), so braces inside those constructs cannot end the template
// early; a backtick at expression depth 0 ends the current template level.
// Nested constructs contribute NO separate tokens. Newlines inside templates
// are legal and counted. EOF leaves the template unterminated (malformed).
// Nesting beyond maxTemplateNesting is recovered from and counted malformed.
func (lx *lexer) scanTemplate() {
	start := lx.i
	line := lx.line
	i := start + 1
	type frame struct {
		brace       int  // enclosing template's ${...} depth
		prevOperand bool // enclosing expression's last significant thing was an operand
	}
	stack := make([]frame, 0, 8)
	brace := 0 // current template's ${...} depth (0 = template text)
	prevOperand := false
	for i < len(lx.src) {
		c := lx.src[i]
		switch {
		case c == '\\':
			if i+1 >= len(lx.src) {
				i = len(lx.src)
				continue
			}
			e := lx.src[i+1]
			switch {
			case e == '\n':
				lx.line++ // line continuation
				i += 2
			case e == '\r':
				i += 2
				if i < len(lx.src) && lx.src[i] == '\n' {
					i++
				}
				lx.line++
			case e == 0xe2 && i+3 < len(lx.src) && lx.src[i+2] == 0x80 && (lx.src[i+3] == 0xa8 || lx.src[i+3] == 0xa9):
				lx.line++
				i += 4
			default:
				i += 2
			}
		case c == '\n' || c == '\r':
			lx.line++
			i = lx.advanceLineTerm(i)
		case c == 0xe2 && i+2 < len(lx.src) && lx.src[i+1] == 0x80 && (lx.src[i+2] == 0xa8 || lx.src[i+2] == 0xa9):
			lx.line++
			i += 3
		case c == '`':
			if brace == 0 {
				// The current template level ends.
				if len(stack) == 0 {
					lx.emit(tokTemplate, line, start+1, i)
					lx.i = i + 1
					return
				}
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				brace = f.brace
				prevOperand = true // the nested template was an operand
				i++
			} else if len(stack) >= maxTemplateNesting {
				// Pathological nesting: recover, treat the backtick as text.
				lx.malformed++
				i++
			} else {
				stack = append(stack, frame{brace: brace, prevOperand: prevOperand})
				brace = 0
				prevOperand = false
				i++
			}
		case c == '$' && i+1 < len(lx.src) && lx.src[i+1] == '{':
			if brace == 0 {
				brace = 1 // expression begins
				prevOperand = false
				i += 2
			} else {
				i += 2 // `${` inside an expression: treated as text
			}
		case c == '{' && brace > 0:
			brace++
			prevOperand = false
			i++
		case c == '}' && brace > 0:
			brace--
			if brace > 0 {
				prevOperand = true
			}
			i++
		case (c == '\'' || c == '"') && brace > 0:
			i = lx.scanTemplateString(i, c)
			prevOperand = true
		case c == '/' && brace > 0:
			if i+1 < len(lx.src) && lx.src[i+1] == '/' {
				// Line comment inside the expression: skip to the
				// terminator (the terminator's line is counted above).
				i += 2
				for i < len(lx.src) && lx.src[i] != '\n' && lx.src[i] != '\r' {
					i++
				}
			} else if i+1 < len(lx.src) && lx.src[i+1] == '*' {
				j := i + 2
				closed := false
				for j < len(lx.src) {
					if lx.src[j] == '*' && j+1 < len(lx.src) && lx.src[j+1] == '/' {
						j += 2
						closed = true
						break
					}
					if lx.src[j] == '\n' || lx.src[j] == '\r' {
						lx.line++
						j = lx.advanceLineTerm(j)
						continue
					}
					j++
				}
				if !closed {
					lx.malformed++
				}
				i = j
			} else if !prevOperand {
				// Regex literal inside the expression.
				end, ok := lx.scanRegexBody(i)
				if ok {
					i = end + 1
				} else {
					i = end
				}
				prevOperand = true
			} else {
				prevOperand = false // division
				i++
			}
		case isIdentPart(c) || c >= 0x80:
			// Identifier/number run inside the template: skip it. A `$`
			// immediately followed by `{` ends the run so that `${` is
			// recognized as an expression start (or as text inside one)
			// instead of being swallowed as identifier content.
			j := i
			for j < len(lx.src) {
				c2 := lx.src[j]
				if isIdentPart(c2) {
					if c2 == '$' && j+1 < len(lx.src) && lx.src[j+1] == '{' {
						break
					}
					j++
					continue
				}
				if c2 >= 0x80 {
					r, sz := utf8.DecodeRune(lx.src[j:])
					if r == utf8.RuneError && sz == 1 {
						lx.malformed++
						j++
						continue
					}
					if r == 0x2028 || r == 0x2029 {
						break // line terminator: counted by the template loop
					}
					j += sz
					continue
				}
				break
			}
			i = j
			prevOperand = true
		default:
			switch c {
			case '(', ',', '=', ':', '[', '!', '&', '|', '?', ';', '~', '*', '%', '<', '>', '^':
				prevOperand = false
			case ')', ']':
				prevOperand = true
			case '+':
				if i+1 < len(lx.src) && lx.src[i+1] == '+' {
					i++
					prevOperand = true
				} else {
					prevOperand = false
				}
			case '-':
				if i+1 < len(lx.src) && lx.src[i+1] == '-' {
					i++
					prevOperand = true
				} else {
					prevOperand = false
				}
			}
			i++
		}
	}
	// Unterminated at EOF: recover, count malformed.
	lx.malformed++
	lx.emit(tokTemplate, line, start+1, len(lx.src))
	lx.i = len(lx.src)
}

// scanTemplateString scans a string literal inside a ${...} expression and
// returns the index just past its closing quote. An unterminated string
// (raw line terminator or EOF) counts malformed and stops at the
// terminator/EOF, exactly like top-level strings.
func (lx *lexer) scanTemplateString(i int, quote byte) int {
	j := i + 1
	for j < len(lx.src) {
		c := lx.src[j]
		switch {
		case c == quote:
			return j + 1
		case c == '\\':
			j++
			if j >= len(lx.src) {
				break
			}
			e := lx.src[j]
			if e == '\n' {
				lx.line++
				j++
				continue
			}
			if e == '\r' {
				lx.line++
				j++
				if j < len(lx.src) && lx.src[j] == '\n' {
					j++
				}
				continue
			}
			j++
		case c == '\n' || c == '\r':
			lx.malformed++
			return j
		default:
			j++
		}
	}
	lx.malformed++
	return len(lx.src)
}

// scanRegexBody scans a regex literal whose opening '/' is at index i
// (callers only invoke it from regex-allowed positions). It returns the
// index of the closing '/' with ok=true, or the recovery point (the line
// terminator or EOF — regexes cannot contain raw line terminators) with
// ok=false, counting malformed. Character classes ([...]) and backslash
// escapes are honored, so a '/' inside a class never closes the literal.
func (lx *lexer) scanRegexBody(i int) (int, bool) {
	j := i + 1
	inClass := false
	for j < len(lx.src) {
		c := lx.src[j]
		switch {
		case c == '\\':
			j += 2
		case c == '[':
			inClass = true
			j++
		case c == ']':
			inClass = false
			j++
		case c == '/' && !inClass:
			return j, true
		case c == '\n' || c == '\r':
			lx.malformed++
			return j, false
		default:
			j++
		}
	}
	lx.malformed++
	return len(lx.src), false
}

// scanRegex emits one regex token starting at the current position (which
// must be regex-allowed). The token text is the raw pattern between the
// slashes; flags (if any) tokenize as a following identifier.
func (lx *lexer) scanRegex() {
	start := lx.i
	end, ok := lx.scanRegexBody(start)
	lx.emit(tokRegex, lx.line, start+1, end)
	if ok {
		lx.i = end + 1
	} else {
		lx.i = end // recover at the line terminator / EOF
	}
}

// scanLineComment emits a line comment token whose text is the content after
// //. The line terminator is left for whitespace handling (line counting).
func (lx *lexer) scanLineComment() {
	start := lx.i
	i := start + 2
	for i < len(lx.src) && lx.src[i] != '\n' && lx.src[i] != '\r' {
		i++
	}
	lx.emit(tokLineComment, lx.line, start+2, i)
	lx.i = i
}

// scanBlockComment emits a block comment token whose text is the content
// between /* and */. The token's line is the line where the comment STARTS.
// Newlines inside are counted (the next token's line stays right); an
// unterminated comment recovers at EOF and counts malformed.
func (lx *lexer) scanBlockComment() {
	start := lx.i
	line := lx.line
	i := start + 2
	for i+1 < len(lx.src) {
		if lx.src[i] == '*' && lx.src[i+1] == '/' {
			lx.emit(tokBlockComment, line, start+2, i)
			lx.i = i + 2
			return
		}
		if lx.src[i] == '\n' || lx.src[i] == '\r' {
			lx.line++
			i = lx.advanceLineTerm(i)
			continue
		}
		i++
	}
	// Unterminated: recover at EOF, count malformed.
	lx.malformed++
	lx.emit(tokBlockComment, line, start+2, len(lx.src))
	lx.i = len(lx.src)
}

// scanPunct emits one or more punctuation/operator tokens from the current
// position, splitting the run into maximal multi-char operators (longest
// match first). A '/' inside the run starts a regex instead when the
// run-so-far (as the previous significant token) allows one — for example
// `a && /re/` — while `a++/2` stays division.
func (lx *lexer) scanPunct() {
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		if !isPunctByte(c) {
			return
		}
		if c == '/' && lx.regexOK {
			return // the main loop scans it as a regex
		}
		m := matchOperator(lx.src, lx.i)
		if !lx.emit(tokPunct, lx.line, lx.i, lx.i+m) {
			return
		}
		lx.i += m
	}
}

// matchOperator returns the length of the longest operator/punctuation token
// at src[i]: 4, 3, 2, or 1 bytes. `?.` followed by a digit is split (the
// ternary form `a?.5:b` — `?.` would not be an optional chain there).
func matchOperator(src []byte, i int) int {
	if i+4 <= len(src) {
		switch string(src[i : i+4]) {
		case ">>>=":
			return 4
		}
	}
	if i+3 <= len(src) {
		switch string(src[i : i+3]) {
		case "===", "!==", ">>>", "**=", "<<=", ">>=", "...", "&&=", "||=", "??=":
			return 3
		}
	}
	if i+2 <= len(src) {
		s := string(src[i : i+2])
		if s == "?." && i+2 < len(src) && src[i+2] >= '0' && src[i+2] <= '9' {
			return 1
		}
		switch s {
		case "==", "!=", "<=", ">=", "&&", "||", "??", "**", "++", "--", "<<", ">>",
			"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "?.", "=>":
			return 2
		}
	}
	return 1
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

func isPunctByte(c byte) bool {
	switch c {
	case '(', ')', '{', '}', '[', ']', ';', ',', '.', ':', '?', '~',
		'+', '-', '*', '/', '%', '<', '>', '=', '!', '&', '|', '^', '@', '#':
		return true
	}
	return false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}
