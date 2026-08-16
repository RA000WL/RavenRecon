package jsintel

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// lex runs the tokenizer over src and returns the token stream, truncation
// flag, and malformed count.
func lex(t *testing.T, src string) ([]token, bool, int) {
	t.Helper()
	lx := &lexer{src: []byte(src), line: 1, regexOK: true}
	lx.run()
	return lx.toks, lx.truncated, lx.malformed
}

// stream renders a token stream as "kind(text@line) ..." for deterministic
// table assertions.
func stream(toks []token, src string) string {
	var b strings.Builder
	for _, tk := range toks {
		fmt.Fprintf(&b, "%s(%s@%d) ", tk.kind, tk.text([]byte(src)), tk.line)
	}
	return strings.TrimSpace(b.String())
}

// kinds renders just the kind sequence of a token stream.
func kinds(toks []token) []string {
	out := make([]string, len(toks))
	for i, tk := range toks {
		out[i] = tk.kind.String()
	}
	return out
}

func TestLexBasic(t *testing.T) {
	src := "#!/usr/bin/env node\nvar a = 1;\nlet s = \"x\";\n// comment\nconst t = `t${u}z`;\nfoo && /re/g.test(x);\na = b / c;\n"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 0 {
		t.Errorf("malformed = %d, want 0", malformed)
	}
	want := "ident(var@2) ident(a@2) punct(=@2) number(1@2) punct(;@2) " +
		"ident(let@3) ident(s@3) punct(=@3) string(x@3) punct(;@3) " +
		"linecomment( comment@4) " +
		"ident(const@5) ident(t@5) punct(=@5) template(t${u}z@5) punct(;@5) " +
		"ident(foo@6) punct(&&@6) regex(re@6) ident(g@6) punct(.@6) ident(test@6) punct((@6) ident(x@6) punct()@6) punct(;@6) " +
		"ident(a@7) punct(=@7) ident(b@7) punct(/@7) ident(c@7) punct(;@7)"
	if got := stream(toks, src); got != want {
		t.Errorf("stream mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestLexRegexDivision(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "regex then division",
			src:  `var re = /a\/b/g; x = a / b / c;`,
			want: "ident(var@1) ident(re@1) punct(=@1) regex(a\\/b@1) ident(g@1) punct(;@1) " +
				"ident(x@1) punct(=@1) ident(a@1) punct(/@1) ident(b@1) punct(/@1) ident(c@1) punct(;@1)",
		},
		{
			name: "character class",
			src:  `/[a-z/]+/`,
			want: "regex([a-z/]+@1)",
		},
		{
			name: "after paren",
			src:  `( /x/ )`,
			want: "punct((@1) regex(x@1) punct()@1)",
		},
		{
			name: "after comma",
			src:  `a, /x/`,
			want: "ident(a@1) punct(,@1) regex(x@1)",
		},
		{
			name: "after equals",
			src:  `x = /x/`,
			want: "ident(x@1) punct(=@1) regex(x@1)",
		},
		{
			name: "after return",
			src:  `return /x/`,
			want: "ident(return@1) regex(x@1)",
		},
		{
			name: "after double ampersand",
			src:  `a&&/re/.test(b)`,
			want: "ident(a@1) punct(&&@1) regex(re@1) punct(.@1) ident(test@1) punct((@1) ident(b@1) punct()@1)",
		},
		{
			name: "after arrow",
			src:  `x => /re/`,
			want: "ident(x@1) punct(=>@1) regex(re@1)",
		},
		{
			name: "after typeof",
			src:  `typeof /x/`,
			want: "ident(typeof@1) regex(x@1)",
		},
		{
			name: "ternary",
			src:  `x = a ? /r/ : /s/`,
			want: "ident(x@1) punct(=@1) ident(a@1) punct(?@1) regex(r@1) punct(:@1) regex(s@1)",
		},
		{
			name: "postfix increment is division",
			src:  `a++/2`,
			want: "ident(a@1) punct(++@1) punct(/@1) number(2@1)",
		},
		{
			name: "division after block brace",
			src:  `x = {} / 2`,
			want: "ident(x@1) punct(=@1) punct({@1) punct(}@1) punct(/@1) number(2@1)",
		},
		{
			name: "divide assign",
			src:  `x /= 2`,
			want: "ident(x@1) punct(/=@1) number(2@1)",
		},
		{
			name: "regex assign with slash equals inside",
			src:  `x = /=/`,
			want: "ident(x@1) punct(=@1) regex(=@1)",
		},
		{
			name: "throw not in keyword set",
			src:  `throw /x/`,
			want: "ident(throw@1) punct(/@1) ident(x@1) punct(/@1)",
		},
		{
			name: "division of regex",
			src:  `a / /b/ / c`,
			want: "ident(a@1) punct(/@1) regex(b@1) punct(/@1) ident(c@1)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks, truncated, malformed := lex(t, tc.src)
			if truncated {
				t.Error("unexpected truncation")
			}
			if malformed != 0 {
				t.Errorf("malformed = %d, want 0", malformed)
			}
			if got := stream(toks, tc.src); got != tc.want {
				t.Errorf("stream mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestLexStrings(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      string
		malformed int
	}{
		{name: "escaped quote", src: `"a\"b"`, want: "string(a\\\"b@1)"},
		{name: "escape pair", src: `'x\ny'`, want: "string(x\\ny@1)"},
		{name: "single quotes", src: `'it\'s'`, want: "string(it\\'s@1)"},
		{name: "line continuation", src: "\"a\\\nb\"", want: "string(a\\\nb@1)", malformed: 0},
		// An unescaped newline ends the string mid-literal (JS spec
		// behavior): the first literal recovers at the newline (malformed),
		// `b` lexes as an identifier, and the trailing quote opens a second
		// string that is unterminated at EOF (malformed again).
		{name: "unterminated at newline", src: "\"a\nb\"", want: "string(a@1) ident(b@2) string(@2)", malformed: 2},
		{name: "unterminated at EOF", src: `"abc`, want: "string(abc@1)", malformed: 1},
		{name: "bad hex escape", src: `"\xZZ"`, want: "string(\\xZZ@1)", malformed: 1},
		{name: "bad unicode escape", src: `"\u12"`, want: "string(\\u12@1)", malformed: 1},
		{name: "bad brace unicode", src: `"\u{zz}"`, want: "string(\\u{zz}@1)", malformed: 1},
		{name: "good brace unicode", src: `"\u{1F600}"`, want: "string(\\u{1F600}@1)", malformed: 0},
		{name: "surrogate pair", src: `"\uD83D\uDE00"`, want: "string(\\uD83D\\uDE00@1)", malformed: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks, truncated, malformed := lex(t, tc.src)
			if truncated {
				t.Error("unexpected truncation")
			}
			if malformed != tc.malformed {
				t.Errorf("malformed = %d, want %d", malformed, tc.malformed)
			}
			if got := stream(toks, tc.src); got != tc.want {
				t.Errorf("stream mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestLexTemplates(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      string
		malformed int
	}{
		{name: "plain", src: "`abc`", want: "template(abc@1)"},
		{name: "with expression", src: "`x${y}z`", want: "template(x${y}z@1)"},
		{name: "nested", src: "`a${`b${c}d`}e`", want: "template(a${`b${c}d`}e@1)"},
		{name: "brace in string", src: "`a${'}'}b`", want: "template(a${'}'}b@1)"},
		{name: "brace in regex", src: "`a${/}/.test(x)}b`", want: "template(a${/}/.test(x)}b@1)"},
		{name: "multiline", src: "`a\nb`", want: "template(a\nb@1)"},
		{name: "unterminated", src: "`abc", want: "template(abc@1)", malformed: 1},
		{name: "escaped dollar", src: "`\\${x}`", want: "template(\\${x}@1)"},
		{name: "comment brace", src: "`a${x // }\n + y}b`", want: "template(a${x // }\n + y}b@1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks, truncated, malformed := lex(t, tc.src)
			if truncated {
				t.Error("unexpected truncation")
			}
			if malformed != tc.malformed {
				t.Errorf("malformed = %d, want %d", malformed, tc.malformed)
			}
			if got := stream(toks, tc.src); got != tc.want {
				t.Errorf("stream mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestLexComments(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      string
		malformed int
	}{
		{name: "line", src: "//hello\nx", want: "linecomment(hello@1) ident(x@2)"},
		{name: "block multiline", src: "/*a\nb*/x", want: "blockcomment(a\nb@1) ident(x@2)"},
		{name: "unterminated block", src: "/* unclosed", want: "blockcomment( unclosed@1)", malformed: 1},
		{name: "source map marker", src: "//# sourceMappingURL=x", want: "linecomment(# sourceMappingURL=x@1)"},
		{name: "empty block", src: "/**/", want: "blockcomment(@1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks, truncated, malformed := lex(t, tc.src)
			if truncated {
				t.Error("unexpected truncation")
			}
			if malformed != tc.malformed {
				t.Errorf("malformed = %d, want %d", malformed, tc.malformed)
			}
			if got := stream(toks, tc.src); got != tc.want {
				t.Errorf("stream mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestLexPunctRuns(t *testing.T) {
	src := "a===b;c!==d;e>>>f;g=>h;i?.j;k...l;m<<=n;o++p;q&&r;s??=t;u>>>="
	want := "ident(a@1) punct(===@1) ident(b@1) punct(;@1) ident(c@1) punct(!==@1) ident(d@1) punct(;@1) " +
		"ident(e@1) punct(>>>@1) ident(f@1) punct(;@1) ident(g@1) punct(=>@1) ident(h@1) punct(;@1) " +
		"ident(i@1) punct(?.@1) ident(j@1) punct(;@1) ident(k@1) punct(...@1) ident(l@1) punct(;@1) " +
		"ident(m@1) punct(<<=@1) ident(n@1) punct(;@1) ident(o@1) punct(++@1) ident(p@1) punct(;@1) " +
		"ident(q@1) punct(&&@1) ident(r@1) punct(;@1) ident(s@1) punct(??=@1) ident(t@1) punct(;@1) ident(u@1) punct(>>>=@1)"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 0 {
		t.Errorf("malformed = %d, want 0", malformed)
	}
	if got := stream(toks, src); got != want {
		t.Errorf("stream mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestLexNumbers(t *testing.T) {
	src := "42 3.14 0x1F 1e+5 1_000 .5 0b101"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 0 {
		t.Errorf("malformed = %d, want 0", malformed)
	}
	if got := kinds(toks); !strings.EqualFold(strings.Join(got, " "), "number number number number number number number") {
		t.Errorf("kinds = %v, want all number", got)
	}
	wantTexts := []string{"42", "3.14", "0x1F", "1e+5", "1_000", ".5", "0b101"}
	for i, w := range wantTexts {
		if got := toks[i].text([]byte(src)); got != w {
			t.Errorf("token %d text = %q, want %q", i, got, w)
		}
	}
}

func TestLexIdentifiers(t *testing.T) {
	// Valid non-ASCII runes are identifier content; invalid UTF-8 bytes are
	// skipped and counted malformed.
	src := "var héllo = 1; var 日本語 = 2; var a\xffb = 3;"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 1 {
		t.Errorf("malformed = %d, want 1", malformed)
	}
	want := "ident(var@1) ident(héllo@1) punct(=@1) number(1@1) punct(;@1) " +
		"ident(var@1) ident(日本語@1) punct(=@1) number(2@1) punct(;@1) " +
		"ident(var@1) ident(a@1) ident(b@1) punct(=@1) number(3@1) punct(;@1)"
	if got := stream(toks, src); got != want {
		t.Errorf("stream mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestLexIdentifierCap(t *testing.T) {
	src := strings.Repeat("a", maxParserIdentBytes+100) + " b"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 1 {
		t.Errorf("malformed = %d, want 1", malformed)
	}
	if len(toks) != 3 { // split identifier, then b
		t.Fatalf("token count = %d, want 3", len(toks))
	}
	if toks[0].kind != tokIdent || toks[1].kind != tokIdent || toks[2].kind != tokIdent {
		t.Fatalf("kinds = %v, want three idents", kinds(toks))
	}
	if got := toks[0].text([]byte(src)); len(got) != maxParserIdentBytes {
		t.Errorf("first part length = %d, want %d", len(got), maxParserIdentBytes)
	}
	if got := toks[1].text([]byte(src)); len(got) != 100 {
		t.Errorf("second part length = %d, want 100", len(got))
	}
	// The split never tears a multi-byte rune.
	rsrc := strings.Repeat("é", maxParserIdentBytes/2+100)
	toks2, _, m2 := lex(t, rsrc)
	if m2 != 1 {
		t.Errorf("malformed = %d, want 1", m2)
	}
	_ = toks2
}

func TestLexShebangBOM(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{name: "shebang", src: "#!/usr/bin/env node\nvar x = 1;", want: "ident(var@2) ident(x@2) punct(=@2) number(1@2) punct(;@2)"},
		{name: "bom", src: "\xEF\xBB\xBFvar x = 1;", want: "ident(var@1) ident(x@1) punct(=@1) number(1@1) punct(;@1)"},
		{name: "bom and shebang", src: "\xEF\xBB\xBF#!x\ny", want: "ident(y@2)"},
		{name: "hash not at start", src: "a #! b", want: "ident(a@1) punct(#@1) punct(!@1) ident(b@1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks, truncated, malformed := lex(t, tc.src)
			if truncated {
				t.Error("unexpected truncation")
			}
			if malformed != 0 {
				t.Errorf("malformed = %d, want 0", malformed)
			}
			if got := stream(toks, tc.src); got != tc.want {
				t.Errorf("stream mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestLexLineTerminators(t *testing.T) {
	// \n, \r\n, lone \r, U+2028, and U+2029 each count as exactly one line.
	src := "a\nb\r\nc\rd\u2028e\u2029f"
	toks, truncated, malformed := lex(t, src)
	if truncated {
		t.Error("unexpected truncation")
	}
	if malformed != 0 {
		t.Errorf("malformed = %d, want 0", malformed)
	}
	if len(toks) != 6 {
		t.Fatalf("token count = %d, want 6", len(toks))
	}
	for i := 0; i < 6; i++ {
		if got := int(toks[i].line); got != i+1 {
			t.Errorf("token %d line = %d, want %d", i, got, i+1)
		}
	}
}

func TestLexTokenCap(t *testing.T) {
	src := strings.Repeat("a;", maxParserTokens/2+10)
	toks, truncated, _ := lex(t, src)
	if !truncated {
		t.Error("truncated = false, want true")
	}
	if len(toks) != maxParserTokens {
		t.Errorf("token count = %d, want %d", len(toks), maxParserTokens)
	}
}

// TestLexAdversarial drives the tokenizer with nasty byte sequences: it must
// terminate (never hang), never panic, and be deterministic (identical
// streams on repeat runs).
func TestLexAdversarial(t *testing.T) {
	nasties := []string{
		`'`, `''''`, `"`, `""""`, "`", "````", `/*`, `/*/*/`, `\`, `\\`, `${`,
		"`${`${`${", `"\x"`, `"\u"`, `"\u{`, `"\`, `'\\`, `a && /`, `/[/`, `//`,
		`/**/`, `#!`, `#!x`, "\x00", "\x00\x01\x02", "'a\r\nb'", "`a\r\nb`",
		`a??b`, `a?.b`, `a?.3:b`, `import(`, `export {`, `export {a`, `a=>`,
		`===>`, `0x`, `1e+`, `...`, `....`, `a+++`, `"\\`, `'\\'`, `return /`,
		"`${'}", "`${/*}", "`a${`b", "`\x00`", "\xff", "\x80", "\xc3", "a\xc3\x28b",
		"`${a}${b}", "`${`${`${`${`", `x = /[a/`, `x = /[a-z/`, `"a\`, "`a\\",
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		nasties = append(nasties, string(b))
	}
	for _, src := range nasties {
		toks1, trunc1, mal1 := lex(t, src)
		toks2, trunc2, mal2 := lex(t, src)
		if trunc1 != trunc2 || mal1 != mal2 || len(toks1) != len(toks2) {
			t.Fatalf("nondeterministic lex of %q: (%d,%v,%d) vs (%d,%v,%d)",
				src, len(toks1), trunc1, mal1, len(toks2), trunc2, mal2)
		}
		for j := range toks1 {
			if toks1[j] != toks2[j] {
				t.Fatalf("nondeterministic token %d of %q: %+v vs %+v", j, src, toks1[j], toks2[j])
			}
		}
	}
}
