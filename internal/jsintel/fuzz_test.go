package jsintel

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzParseSource drives the parser's untrusted-input boundary
// (parser.Parse → lex.go's tokenizer + parse.go's extraction walk) with
// arbitrary bytes. Parse never fails on malformed input — the only error is
// input over maxParseInputBytes — so the invariants under adversarial input
// are:
//
//   - no panic and no hang (the lexer/walk budgets — maxParserTokens,
//     maxTotalScanSteps — bound every loop);
//   - determinism: a reused Parser yields identical Parsed values for
//     identical input (a parser keeps no state between calls);
//   - truncation honesty: when Truncated is false every result cap was
//     strictly under its bound and each retained string literal is within
//     maxParserStringBytes — a complete parse never carries a silently
//     clipped set.
func FuzzParseSource(f *testing.F) {
	seeds := []string{
		"",
		";",
		`import { a, b as c } from "https://cdn.example.com/x.js";`,
		"export default class {}; export const named = 1;",
		"const tpl = `a${ `b${'c'}d` }e`; // template nesting",
		"const re = /[/]/g; const s = \"a/b/c\"; const t = a / b / c;",
		"import(`/api/${v}`); //# sourceMappingURL=app.js.map",
		"'unterminated string",
		"/* never closed",
		"`template ${ never closed",
		"\x00\x01\x02\xff\xfe raw bytes \xc3\x28 invalid utf8",
		strings.Repeat("import x ", 4096),
		`const big = "` + strings.Repeat("A", 3*maxParserStringBytes) + `";`,
		"const \u00e9\u4e2d\u6587 = \"multibyte \U0001F600\"; // \u30b3\u30e1\u30f3\u30c8\n",
		"${`${`${`${`${`}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	p := NewParser()
	f.Fuzz(func(t *testing.T, src []byte) {
		r1, err := p.Parse(src)
		if len(src) > maxParseInputBytes {
			if err == nil {
				t.Fatalf("Parse accepted %d bytes over the %d byte hard limit", len(src), maxParseInputBytes)
			}
			return
		}
		if err != nil {
			t.Fatalf("Parse(%d bytes): %v", len(src), err)
		}

		r2, err := p.Parse(src)
		if err != nil {
			t.Fatalf("second Parse of %d bytes: %v", len(src), err)
		}
		if !reflect.DeepEqual(r1, r2) {
			t.Fatalf("nondeterministic parse of %d-byte input", len(src))
		}

		if r1.Truncated {
			return
		}
		if len(r1.Imports) >= maxParserImports || len(r1.Exports) >= maxParserExports || len(r1.Strings) >= maxParserStrings {
			t.Fatalf("Truncated=false but a cap is at or over its bound: imports=%d exports=%d strings=%d",
				len(r1.Imports), len(r1.Exports), len(r1.Strings))
		}
		for i, sl := range r1.Strings {
			if len(sl.Value) > maxParserStringBytes {
				t.Fatalf("string literal %d retains %d bytes with Truncated=false (bound %d)",
					i, len(sl.Value), maxParserStringBytes)
			}
		}
	})
}
