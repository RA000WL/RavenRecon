package jsintel

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// parse parses src with a fresh parser, failing the test on error.
func parse(t *testing.T, src string) Parsed {
	t.Helper()
	r, err := NewParser().Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse(%q) error: %v", src, err)
	}
	return r
}

func importSpecs(imps []Import) []string {
	out := make([]string, len(imps))
	for i, im := range imps {
		out[i] = im.Specifier
	}
	return out
}

func TestParseSmallScript(t *testing.T) {
	src := `import { a } from "./mod.js";
import b from "mod2";
import * as ns from "ns";
import "side-effect";
export { c, d as e };
export default function main() {}
export const x = 1;
export function f() {}
export class K {}
export async function g() {}
const s1 = "hello\nworld";
const s2 = 'tab\there';
const t1 = ` + "`tpl ${x} end`" + `;
const t2 = ` + "`plain`" + `;
`
	r := parse(t, src)
	if r.Truncated || r.Malformed != 0 {
		t.Fatalf("unexpected flags: Truncated=%v Malformed=%d", r.Truncated, r.Malformed)
	}
	wantImports := []string{"./mod.js", "mod2", "ns", "side-effect"}
	if got := importSpecs(r.Imports); !reflect.DeepEqual(got, wantImports) {
		t.Errorf("imports = %v, want %v", got, wantImports)
	}
	for i, im := range r.Imports {
		if im.Kind != ImportStatic {
			t.Errorf("import %d kind = %v, want static", i, im.Kind)
		}
		if im.Line != i+1 {
			t.Errorf("import %d line = %d, want %d", i, im.Line, i+1)
		}
	}
	wantExports := []string{"c", "e", "default", "x", "f", "K", "g"}
	if !reflect.DeepEqual(r.Exports, wantExports) {
		t.Errorf("exports = %v, want %v", r.Exports, wantExports)
	}
	// Import specifiers ARE included in the string stream, in source order,
	// interleaved with the other literals.
	wantStrings := []StringLit{
		{Value: "./mod.js", Line: 1},
		{Value: "mod2", Line: 2},
		{Value: "ns", Line: 3},
		{Value: "side-effect", Line: 4},
		{Value: "hello\nworld", Line: 11},
		{Value: "tab\there", Line: 12},
		{Value: "tpl ${x} end", Line: 13, Template: true},
		{Value: "plain", Line: 14, Template: true},
	}
	if !reflect.DeepEqual(r.Strings, wantStrings) {
		t.Errorf("strings = %+v\nwant %+v", r.Strings, wantStrings)
	}
}

func TestParseImports(t *testing.T) {
	src := `import defaultExport from "./mod.js";
import * as ns from "pkg";
import { a, b as c } from "./deep.js";
import "side-effect.js";
import('./dyn.js');
import(` + "`./tpl.js`" + `);
import(` + "`./${path}.js`" + `);
export { x } from "./re.js";
export * from "./star.js";
export * as renamed from "./renamed.js";
`
	r := parse(t, src)
	want := []Import{
		{Specifier: "./mod.js", Kind: ImportStatic, Line: 1},
		{Specifier: "pkg", Kind: ImportStatic, Line: 2},
		{Specifier: "./deep.js", Kind: ImportStatic, Line: 3},
		{Specifier: "side-effect.js", Kind: ImportStatic, Line: 4},
		{Specifier: "./dyn.js", Kind: ImportDynamic, Line: 5},
		{Specifier: "./tpl.js", Kind: ImportDynamic, Line: 6},
		{Specifier: "", Kind: ImportDynamic, Line: 7},
		{Specifier: "./re.js", Kind: ImportStatic, Line: 8},
		{Specifier: "./star.js", Kind: ImportStatic, Line: 9},
		{Specifier: "./renamed.js", Kind: ImportStatic, Line: 10},
	}
	if !reflect.DeepEqual(r.Imports, want) {
		t.Errorf("imports = %+v\nwant %+v", r.Imports, want)
	}
	// export * as renamed also exports the name.
	if wantExports := []string{"renamed"}; !reflect.DeepEqual(r.Exports, wantExports) {
		t.Errorf("exports = %v, want %v", r.Exports, wantExports)
	}
	// Property access and TypeScript import-equals are NOT imports.
	more := `foo.import("./not.js");
foo?.import("./not2.js");
import x = require("m");
import.meta.url;
import type { T } from "./types.js";
`
	r2 := parse(t, more)
	want2 := []Import{{Specifier: "./types.js", Kind: ImportStatic, Line: 5}}
	if !reflect.DeepEqual(r2.Imports, want2) {
		t.Errorf("imports = %+v, want %+v", r2.Imports, want2)
	}
}

func TestParseCircularImports(t *testing.T) {
	a := `import { b } from "./b.js"; export const a = 1;`
	b := `import { a } from "./a.js"; export const b = 2;`
	ra := parse(t, a)
	rb := parse(t, b)
	if want := []string{"./b.js"}; !reflect.DeepEqual(importSpecs(ra.Imports), want) {
		t.Errorf("a imports = %v, want %v", importSpecs(ra.Imports), want)
	}
	if want := []string{"a"}; !reflect.DeepEqual(ra.Exports, want) {
		t.Errorf("a exports = %v, want %v", ra.Exports, want)
	}
	if want := []string{"./a.js"}; !reflect.DeepEqual(importSpecs(rb.Imports), want) {
		t.Errorf("b imports = %v, want %v", importSpecs(rb.Imports), want)
	}
	if want := []string{"b"}; !reflect.DeepEqual(rb.Exports, want) {
		t.Errorf("b exports = %v, want %v", rb.Exports, want)
	}
}

func TestParseExports(t *testing.T) {
	src := `export { a, b as c, d as default };
export default 42;
export const k1 = 1;
export let k2 = 2;
export var k3 = 3;
export function f1() {}
export class C1 {}
export async function f2() {}
export function* f3() {}
export async function* f4() {}
export { a };
export const a = 1;
`
	r := parse(t, src)
	want := []string{"a", "c", "default", "k1", "k2", "k3", "f1", "C1", "f2", "f3", "f4"}
	if !reflect.DeepEqual(r.Exports, want) {
		t.Errorf("exports = %v, want %v", r.Exports, want)
	}
	if r.Truncated || r.Malformed != 0 {
		t.Errorf("unexpected flags: Truncated=%v Malformed=%d", r.Truncated, r.Malformed)
	}
}

func TestParseStrings(t *testing.T) {
	src := "var a = \"\\n\\t\\\"\\\\\\/\\u0041\\x41\";\n" +
		"var b = \"\\u{1F600}\";\n" +
		"var c = \"\\xZZ\\u12\\q\";\n" +
		"var d = \"line\\\ncont\";\n" +
		"var t1 = `x${y}z`;\n" +
		"var t2 = `a\\nb`;\n" +
		"var t3 = `\\${not}`;\n" +
		"var p = \"\\uD83D\\uDE00\";\n"
	r := parse(t, src)
	want := []StringLit{
		{Value: "\n\t\"\\/AA", Line: 1},
		{Value: "\U0001F600", Line: 2},
		{Value: `\xZZ\u12q`, Line: 3},
		{Value: "linecont", Line: 4},
		// The continuation line ("cont";) physically occupies line 5, so the
		// following statements start on line 6.
		{Value: "x${y}z", Line: 6, Template: true},
		{Value: "a\nb", Line: 7, Template: true},
		{Value: "${not}", Line: 8, Template: true},
		{Value: "\U0001F600", Line: 9},
	}
	if !reflect.DeepEqual(r.Strings, want) {
		t.Errorf("strings = %+v\nwant %+v", r.Strings, want)
	}
	// Invalid escapes (\xZZ, \u12) are counted malformed by the scanner even
	// though the literals are retained with raw text; \q (unknown escape)
	// and line continuations are legal and count nothing.
	if r.Malformed != 2 {
		t.Errorf("malformed = %d, want 2 (\\xZZ and \\u12)", r.Malformed)
	}
}

func TestParseMinified(t *testing.T) {
	src := "import{a}from\"./m.js\";export const b=1;var s=\"x\";var t=`y`;"
	r := parse(t, src)
	if r.Truncated || r.Malformed != 0 {
		t.Fatalf("unexpected flags: Truncated=%v Malformed=%d", r.Truncated, r.Malformed)
	}
	if want := []Import{{Specifier: "./m.js", Kind: ImportStatic, Line: 1}}; !reflect.DeepEqual(r.Imports, want) {
		t.Errorf("imports = %+v, want %+v", r.Imports, want)
	}
	if want := []string{"b"}; !reflect.DeepEqual(r.Exports, want) {
		t.Errorf("exports = %v, want %v", r.Exports, want)
	}
	wantStrings := []StringLit{
		{Value: "./m.js", Line: 1},
		{Value: "x", Line: 1},
		{Value: "y", Line: 1, Template: true},
	}
	if !reflect.DeepEqual(r.Strings, wantStrings) {
		t.Errorf("strings = %+v, want %+v", r.Strings, wantStrings)
	}
	for _, s := range r.Strings {
		if s.Line != 1 {
			t.Errorf("string on line %d, want 1 (minified single line)", s.Line)
		}
	}
}

func TestParseMalformed(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		check  func(t *testing.T, r Parsed)
		minMal int
	}{
		{
			name: "unterminated string at EOL",
			src:  "import \"ok.js\";\nvar s = \"never ends\nvar x = 1;",
			check: func(t *testing.T, r Parsed) {
				if want := []string{"ok.js"}; !reflect.DeepEqual(importSpecs(r.Imports), want) {
					t.Errorf("imports = %v, want %v", importSpecs(r.Imports), want)
				}
			},
			minMal: 1,
		},
		{
			name: "unterminated block comment",
			src:  "import \"ok2.js\"; /* never closed",
			check: func(t *testing.T, r Parsed) {
				if want := []string{"ok2.js"}; !reflect.DeepEqual(importSpecs(r.Imports), want) {
					t.Errorf("imports = %v, want %v", importSpecs(r.Imports), want)
				}
			},
			minMal: 1,
		},
		{
			name: "unterminated template",
			src:  "var t = `never closed",
			check: func(t *testing.T, r Parsed) {
				if len(r.Strings) != 1 || !r.Strings[0].Template {
					t.Errorf("strings = %+v, want one template", r.Strings)
				}
			},
			minMal: 1,
		},
		{
			name: "unterminated regex at EOL",
			src:  "import \"ok3.js\"; var re = /never closed\nexport const ok = 1;",
			check: func(t *testing.T, r Parsed) {
				if want := []string{"ok"}; !reflect.DeepEqual(r.Exports, want) {
					t.Errorf("exports = %v, want %v", r.Exports, want)
				}
			},
			minMal: 1,
		},
		{
			name:   "stray binary bytes",
			src:    "\x00\x01\x02 var a = 1;",
			minMal: 3,
		},
		{
			name:   "broken utf8",
			src:    "var \xff\xfe = 1;",
			minMal: 2,
		},
		{
			name: "crlf is not malformed",
			src:  "import \"a.js\";\r\nimport \"b.js\";",
			check: func(t *testing.T, r Parsed) {
				if r.Malformed != 0 {
					t.Errorf("malformed = %d, want 0 for CRLF", r.Malformed)
				}
				if r.Imports[0].Line != 1 || r.Imports[1].Line != 2 {
					t.Errorf("import lines = %d,%d want 1,2", r.Imports[0].Line, r.Imports[1].Line)
				}
			},
		},
		{
			name: "unterminated after valid parts",
			src:  "import \"ok.js\"; var s = \"unterminated",
			check: func(t *testing.T, r Parsed) {
				if want := []string{"ok.js"}; !reflect.DeepEqual(importSpecs(r.Imports), want) {
					t.Errorf("imports = %v, want %v", importSpecs(r.Imports), want)
				}
			},
			minMal: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := parse(t, tc.src)
			if r.Malformed < tc.minMal {
				t.Errorf("malformed = %d, want >= %d", r.Malformed, tc.minMal)
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

func TestParseLarge(t *testing.T) {
	// ~500 KiB of generated statements with strings: all caps respected, so
	// the parse is complete (Truncated=false) and deterministic.
	var b strings.Builder
	const stmts = 20000
	for i := 0; i < stmts; i++ {
		if i%3 == 0 {
			fmt.Fprintf(&b, "var v%d = \"s%d\";\n", i, i)
		} else {
			fmt.Fprintf(&b, "var v%d = v%d + v%d;\n", i, i-1, i-2)
		}
		if i%100 == 0 {
			fmt.Fprintf(&b, "export function f%d() {}\n", i)
		}
		if i%200 == 0 {
			fmt.Fprintf(&b, "import \"m%d\";\n", i)
		}
	}
	if b.Len() < 400<<10 {
		t.Fatalf("generated input only %d bytes, want ~500 KiB", b.Len())
	}
	src := b.String()
	r1 := parse(t, src)
	if r1.Truncated {
		t.Error("Truncated = true, want false for a within-caps large input")
	}
	if r1.Malformed != 0 {
		t.Errorf("malformed = %d, want 0", r1.Malformed)
	}
	if got := len(r1.Imports); got != stmts/200 {
		t.Errorf("import count = %d, want %d", got, stmts/200)
	}
	if got := len(r1.Exports); got != stmts/100 {
		t.Errorf("export count = %d, want %d", got, stmts/100)
	}
	// i%3 == 0 fires for i = 0, 3, ..., stmts-1 — one more than stmts/3
	// (20000 is not divisible by 3). So the generator itself emits
	// stmts/3+1 string literals plus one per import statement.
	if got := len(r1.Strings); got != stmts/3+1+stmts/200 {
		t.Errorf("string count = %d, want %d", got, stmts/3+1+stmts/200)
	}
	if r1.Imports[50].Specifier != "m10000" {
		t.Errorf("import[50] = %q, want \"m10000\"", r1.Imports[50].Specifier)
	}
	// Deterministic.
	r2 := parse(t, src)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("two parses of the same large input differ")
	}
}

func TestParseCaps(t *testing.T) {
	t.Run("strings", func(t *testing.T) {
		r := parse(t, strings.Repeat(`"s";`, maxParserStrings+50))
		if !r.Truncated {
			t.Error("Truncated = false, want true")
		}
		if len(r.Strings) != maxParserStrings {
			t.Errorf("retained strings = %d, want %d", len(r.Strings), maxParserStrings)
		}
	})
	t.Run("string byte cap does not truncate", func(t *testing.T) {
		r := parse(t, `var s = "`+strings.Repeat("A", maxParserStringBytes+100)+`";`)
		if r.Truncated {
			t.Error("Truncated = true, want false (byte cap never truncates)")
		}
		if len(r.Strings) != 0 {
			t.Errorf("retained strings = %d, want 0 (value over the byte cap)", len(r.Strings))
		}
	})
	t.Run("imports", func(t *testing.T) {
		r := parse(t, strings.Repeat(`import "m";`, maxParserImports+10))
		if !r.Truncated {
			t.Error("Truncated = false, want true")
		}
		if len(r.Imports) != maxParserImports {
			t.Errorf("imports = %d, want %d", len(r.Imports), maxParserImports)
		}
	})
	t.Run("exports", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < maxParserExports+10; i++ {
			fmt.Fprintf(&b, "export const a%d = 1;\n", i)
		}
		r := parse(t, b.String())
		if !r.Truncated {
			t.Error("Truncated = false, want true")
		}
		if len(r.Exports) != maxParserExports {
			t.Errorf("exports = %d, want %d", len(r.Exports), maxParserExports)
		}
	})
	t.Run("tokens", func(t *testing.T) {
		r := parse(t, strings.Repeat("a;", maxParserTokens/2+10))
		if !r.Truncated {
			t.Error("Truncated = false, want true")
		}
	})
	t.Run("input too large errors", func(t *testing.T) {
		src := make([]byte, maxParseInputBytes+1)
		if _, err := NewParser().Parse(src); err == nil {
			t.Error("Parse over maxParseInputBytes: error = nil, want error")
		}
	})
	t.Run("exactly at the limit parses", func(t *testing.T) {
		src := []byte(strings.Repeat("a;", maxParseInputBytes/2))
		if len(src) != maxParseInputBytes {
			t.Fatalf("test input is %d bytes, want %d", len(src), maxParseInputBytes)
		}
		r, err := NewParser().Parse(src)
		if err != nil {
			t.Fatalf("Parse at the limit: %v", err)
		}
		if !r.Truncated {
			t.Error("Truncated = false, want true (token cap hit on 8 MiB of statements)")
		}
	})
}

func TestParseSourceMaps(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{name: "hash marker", src: "//# sourceMappingURL=x.js.map", want: "x.js.map"},
		{name: "legacy at marker", src: "//@ sourceMappingURL=legacy.map", want: "legacy.map"},
		{name: "block comment", src: "/*# sourceMappingURL=block.map */", want: "block.map"},
		{name: "last wins", src: "//# sourceMappingURL=one.map\n//# sourceMappingURL=two.map", want: "two.map"},
		{name: "last wins mixed", src: "//@ sourceMappingURL=legacy.map\n/*# sourceMappingURL=block.map */", want: "block.map"},
		{name: "garbage after marker", src: "//# sourceMappingURL=x.js.map extra", want: "x.js.map extra"},
		{name: "mid file", src: "var a = 1;\n//# sourceMappingURL=mid.js.map", want: "mid.js.map"},
		{name: "surrounding whitespace", src: "//   # sourceMappingURL=  spaced.map  ", want: "spaced.map"},
		{name: "multiline block", src: "/*\n# sourceMappingURL=multi.map\n*/", want: "multi.map"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := parse(t, tc.src)
			if !r.HasSourceMapRef {
				t.Fatalf("HasSourceMapRef = false, want true")
			}
			if r.SourceMapRef != tc.want {
				t.Errorf("ref = %q, want %q", r.SourceMapRef, tc.want)
			}
		})
	}
	t.Run("no marker", func(t *testing.T) {
		for _, src := range []string{
			"//# not-a-sourcemap",
			"//# sourceMappingURLx=no.map",
			"//#sourceMappingURL=no-space.map",
			"var a = 1;",
			"/* plain */",
		} {
			r := parse(t, src)
			if r.HasSourceMapRef {
				t.Errorf("%q: HasSourceMapRef = true, want false", src)
			}
		}
	})
	t.Run("overlong ref dropped", func(t *testing.T) {
		src := "//# sourceMappingURL=" + strings.Repeat("x", maxSourceMapRefBytes+1)
		r := parse(t, src)
		if r.HasSourceMapRef {
			t.Error("HasSourceMapRef = true, want false (overlong ref dropped)")
		}
		if r.Malformed < 1 {
			t.Errorf("malformed = %d, want >= 1", r.Malformed)
		}
	})
	t.Run("exactly at the ref limit", func(t *testing.T) {
		ref := strings.Repeat("x", maxSourceMapRefBytes)
		r := parse(t, "//# sourceMappingURL="+ref)
		if !r.HasSourceMapRef || r.SourceMapRef != ref {
			t.Errorf("ref = %q (has=%v), want the %d-byte ref", r.SourceMapRef, r.HasSourceMapRef, maxSourceMapRefBytes)
		}
	})
}

func TestParseRegexDivision(t *testing.T) {
	src := `export default /a\/b/g;
const re1 = /[a-z/]+/;
function f(a, b) { return a / b / 2; }
const r2 = ( /x/ );
x = a && /re/.test(b);
x = a ? /r/ : /s/;
var re2 = /a\/b/g; x = a / b / c;
`
	r := parse(t, src)
	if r.Malformed != 0 {
		t.Errorf("malformed = %d, want 0 (regexes and divisions both clean)", r.Malformed)
	}
	if want := []string{"default"}; !reflect.DeepEqual(r.Exports, want) {
		t.Errorf("exports = %v, want %v", r.Exports, want)
	}
}

func TestParseShebangBOM(t *testing.T) {
	r := parse(t, "#!/usr/bin/env node\nimport \"m\";")
	if len(r.Imports) != 1 || r.Imports[0].Line != 2 {
		t.Errorf("imports = %+v, want one import on line 2", r.Imports)
	}
	r = parse(t, "\xEF\xBB\xBFimport \"m\";")
	if len(r.Imports) != 1 || r.Imports[0].Line != 1 {
		t.Errorf("BOM import = %+v, want one import on line 1", r.Imports)
	}
	r = parse(t, "\xEF\xBB\xBF#!node\nimport \"m\";")
	if len(r.Imports) != 1 || r.Imports[0].Line != 2 {
		t.Errorf("BOM+shebang import = %+v, want one import on line 2", r.Imports)
	}
}

func TestParseEmpty(t *testing.T) {
	for _, src := range [][]byte{nil, {}, []byte("   "), []byte("\n\n")} {
		r, err := NewParser().Parse(src)
		if err != nil {
			t.Fatalf("Parse(%v) error: %v", src, err)
		}
		if !reflect.DeepEqual(r, Parsed{}) {
			t.Errorf("Parse(%v) = %+v, want empty Parsed", src, r)
		}
	}
}

func TestParseDeterministic(t *testing.T) {
	src := `import {a} from "./m.js";
export const b = 1;
var s = "x" + 'y' + ` + "`t`" + `;
//# sourceMappingURL=app.js.map
`
	r1 := parse(t, src)
	r2 := parse(t, src)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("two parses of the same input differ")
	}
}

func TestParserReuse(t *testing.T) {
	p := NewParser()
	inputs := []string{
		`import "./a.js"; export const x = 1;`,
		"var s = \"unterminated",
		"`x${y}`",
		`//# sourceMappingURL=a.map
import("./b.js");
export default 1;`,
		"",
	}
	baseline := make([]Parsed, len(inputs))
	for i, s := range inputs {
		r, err := p.Parse([]byte(s))
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		baseline[i] = r
	}
	// Sequential reuse: identical results.
	for i, s := range inputs {
		r, err := p.Parse([]byte(s))
		if err != nil || !reflect.DeepEqual(r, baseline[i]) {
			t.Fatalf("reused parse of %q differs: %v", s, err)
		}
	}
	// Concurrent reuse: no shared mutable state (race detector).
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				for i, s := range inputs {
					r, err := p.Parse([]byte(s))
					if err != nil || !reflect.DeepEqual(r, baseline[i]) {
						t.Errorf("concurrent parse of %q differs: %v", s, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

// TestParseFuzzAdversarial drives Parse with nasty byte sequences and
// deterministic random inputs: no panic, no hang, deterministic results.
func TestParseFuzzAdversarial(t *testing.T) {
	nasties := []string{
		`'`, `''''`, `"`, `""""`, "`", "````", `/*`, `/*/*/`, `\`, `\\`, `${`,
		"`${`${`${", `"\x"`, `"\u"`, `"\u{`, `"\`, `'\\`, `a && /`, `/[/`, `//`,
		`/**/`, `#!`, "\x00", "\x00\x01\x02", "'a\r\nb'", "`a\r\nb`",
		`a??b`, `a?.b`, `a?.3:b`, `import(`, `export {`, `export {a`, `a=>`,
		`===>`, `0x`, `1e+`, `...`, `....`, `a+++`, `"\\`, `return /`,
		"`${'}", "`${/*}", "`a${`b", "\xff", "\x80", "\xc3", "a\xc3\x28b",
		"`${`${`${`${`", `x = /[a/`, `"a\`, "`a\\", `import("`, `import(` + "`" + `$`,
		`export {`, `export default`, `export const`, `export async`,
		`import { a } from "m`, `import a from`, `a / b /`,
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		nasties = append(nasties, string(b))
	}
	p := NewParser()
	for _, src := range nasties {
		r1, err1 := p.Parse([]byte(src))
		if err1 != nil {
			t.Fatalf("Parse(%q) error: %v", src, err1)
		}
		r2, err2 := p.Parse([]byte(src))
		if err2 != nil {
			t.Fatalf("second Parse(%q) error: %v", src, err2)
		}
		if !reflect.DeepEqual(r1, r2) {
			t.Fatalf("nondeterministic parse of %q:\n%+v\n%+v", src, r1, r2)
		}
	}
}

// TestParseHostileTimingRegression pins the lookahead-window bounds
// (maxLookaheadTokens, parse.go): the walk's forward/backward scans are
// LINEAR-bounded even on adversarial inputs whose pre-window behavior was
// quadratic in the token count. The three shapes below are the worst cases
// documented in parse.go — each import/export keyword scans the whole
// remaining (or preceding) stream without the window:
//
//   - "import a " × 116466: findFromSpecifier scans the ENTIRE remaining
//     stream for `from "spec"` — pre-window ~2.7e10 scan steps (~n² steps,
//     tens of seconds to minutes), post-window 116466 × 1024 ≈ 1.2e8;
//   - "export {" × 131072: exportList's closing-brace hunt scans the whole
//     remaining stream (the brace never closes) — pre-window ~3.4e10 steps;
//   - "//c\n" × 700000 + "import a\n" × 25850: prevSig walks BACKWARD over
//     the whole preceding comment run for every import keyword — pre-window
//     ~1.8e10 steps.
//
// Assertions: Parse never errors, a second parse is byte-identical
// (deterministic), the clause-hunt shapes honestly report Truncated
// (window exhaustion), and each shape completes within a wall-clock budget
// that the quadratic pre-window implementation exceeds by an order of
// magnitude. The measured post-window cost of each shape is ~0.3-0.8 s on
// development hardware; the 10 s budget leaves ~12-35× headroom for slow
// CI machines while still failing in seconds+ on a reintroduced quadratic
// scan (each shape is ~2-4e10 steps pre-window — tens of seconds on any
// machine).
func TestParseHostileTimingRegression(t *testing.T) {
	shapes := []struct {
		name string
		src  string
		// truncated: the clause-hunt scans exhaust the window mid-stream.
		truncated bool
	}{
		{name: "import-without-specifier", src: strings.Repeat("import a ", 116466), truncated: true},
		{name: "unterminated-export-list", src: strings.Repeat("export {", 131072), truncated: true},
		{name: "comment-run-before-imports", src: strings.Repeat("//c\n", 700000) + strings.Repeat("import a\n", 25850), truncated: true},
	}
	const budget = 10 * time.Second
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			start := time.Now()
			r1, err := NewParser().Parse([]byte(s.src))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			t.Logf("first parse: %s", elapsed)
			if r1.Truncated != s.truncated {
				t.Errorf("Truncated = %v, want %v", r1.Truncated, s.truncated)
			}
			r2, err := NewParser().Parse([]byte(s.src))
			if err != nil {
				t.Fatalf("second Parse: %v", err)
			}
			if !reflect.DeepEqual(r1, r2) {
				t.Errorf("nondeterministic parse of shape %s", s.name)
			}
			if elapsed > budget {
				t.Errorf("parse took %s, exceeding the %s wall-clock budget (the maxLookaheadTokens window bounds these scans; without it this shape is quadratic — ~1e10+ steps)", elapsed, budget)
			}
		})
	}
}

// TestParseLookaheadWindowEnvelope pins the documented maxLookaheadTokens
// envelope (parse.go): a single import/export clause spanning more than the
// window is a binding list of ~250 aliased names / ~500 plain names —
// beyond any legitimate source. Within-window lists resolve COMPLETELY and
// correctly; an outside-window list terminates with an honest Truncated
// prefix — the closing brace lies beyond the window, so the local name
// collection never runs (0 exports, 0 imports, nothing fake). Every input
// is parsed twice and must be byte-identical (deterministic window scans).
func TestParseLookaheadWindowEnvelope(t *testing.T) {
	// Per-name token costs: the aliased form costs 4 tokens (name, `as`,
	// alias, comma), the plain form 2 (name, comma); the clause adds
	// keyword, `{`, `}` — and a trailing `;`. The window bounds the scan
	// FROM the opening brace, so the counts below put the closing brace
	// just inside or just beyond maxLookaheadTokens.
	aliasedInside := maxLookaheadTokens/4 - 2 // 254 names: 4*254+4 = 1020 tokens
	plainInside := maxLookaheadTokens/2 - 12  // 500 names: 2*500+4 = 1004 tokens
	aliasSrc := func(n int) string {
		var b strings.Builder
		b.WriteString("export {")
		for i := 1; i <= n; i++ {
			if i > 1 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " a%d as b%d", i, i)
		}
		b.WriteString(" };")
		return b.String()
	}
	plainSrc := func(n int) string {
		var b strings.Builder
		b.WriteString("export {")
		for i := 1; i <= n; i++ {
			if i > 1 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " a%d", i)
		}
		b.WriteString(" };")
		return b.String()
	}
	importSrc := func(n int) string {
		var b strings.Builder
		b.WriteString("import {")
		for i := 1; i <= n; i++ {
			if i > 1 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " a%d", i)
		}
		b.WriteString(" } from \"m\";")
		return b.String()
	}
	cases := []struct {
		name          string
		src           string
		wantExports   int
		wantImports   []string
		wantTruncated bool
	}{
		{
			name:        "aliased list inside the window",
			src:         aliasSrc(aliasedInside),
			wantExports: aliasedInside,
		},
		{
			name:        "plain list inside the window",
			src:         plainSrc(plainInside),
			wantExports: plainInside,
		},
		{
			name:          "aliased list outside the window",
			src:           aliasSrc(maxLookaheadTokens / 4), // 256 names > the window
			wantTruncated: true,
		},
		{
			name:          "plain list outside the window",
			src:           plainSrc(maxLookaheadTokens / 2), // 512 names > the window
			wantTruncated: true,
		},
		{
			name:        "import list inside the window",
			src:         importSrc(plainInside),
			wantImports: []string{"m"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r1 := parse(t, tc.src)
			r2 := parse(t, tc.src)
			if !reflect.DeepEqual(r1, r2) {
				t.Fatalf("nondeterministic parse of %s:\n%+v\n%+v", tc.name, r1, r2)
			}
			if r1.Truncated != tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", r1.Truncated, tc.wantTruncated)
			}
			if r1.Malformed != 0 {
				t.Errorf("Malformed = %d, want 0", r1.Malformed)
			}
			if got := len(r1.Exports); got != tc.wantExports {
				t.Errorf("exports = %d, want %d", got, tc.wantExports)
			}
			if tc.wantImports == nil {
				if len(r1.Imports) != 0 {
					t.Errorf("imports = %d, want none", len(r1.Imports))
				}
			} else if !reflect.DeepEqual(importSpecs(r1.Imports), tc.wantImports) {
				t.Errorf("imports = %v, want %v", importSpecs(r1.Imports), tc.wantImports)
			}
		})
	}
}

// TestParseAdversarialImportWindow pins NEW-26: findFromSpecifier's
// lookahead window (maxLookaheadTokens=1024) makes adversarial repeats
// superlinear. Input like "import x " repeated to the token cap is
// 500k import keywords, each scanning 1024 tokens → ~512M steps without a
// global budget — tens of seconds, and Parse has no context so pool
// deadlines cannot interrupt it. The fix caps total window-scan steps
// (maxTotalScanSteps=100k) and terminates a scan early at the next
// statement keyword (import/export) at depth 0, making the walk linear.
// This test ensures adversarial corpora complete quickly (<100ms) and
// honestly report Truncated when the budget is exceeded, while remaining
// deterministic and not breaking legitimate imports.
func TestParseAdversarialImportWindow(t *testing.T) {
	cases := []struct {
		name          string
		src           string
		wantTruncated *bool // nil means don't assert; just check liveness + determinism
		budget        time.Duration
	}{
		{
			name:   "import-x-repeated-10k-fast",
			src:    strings.Repeat("import x ", 10000),
			budget: 100 * time.Millisecond,
		},
		{
			name:   "import-x-repeated-10k-trailing-from-fast",
			src:    strings.Repeat("import x ", 10000) + "from \"a\";",
			budget: 100 * time.Millisecond,
		},
		{
			name:          "import-x-repeated-60k-exceeds-budget-truncated",
			src:           strings.Repeat("import x ", 60000),
			wantTruncated: boolPtr(true),
			budget:        100 * time.Millisecond,
		},
		{
			name:   "legit-import-still-resolves",
			src:    `import { a, b as c } from "m"; export { c };`,
			budget: 100 * time.Millisecond,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			r1, err := NewParser().Parse([]byte(tc.src))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if elapsed > tc.budget {
				t.Errorf("adversarial parse took %s, exceeding %s budget (superlinear window scan not bounded)", elapsed, tc.budget)
			}
			if tc.wantTruncated != nil && r1.Truncated != *tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", r1.Truncated, *tc.wantTruncated)
			}
			// Deterministic second parse.
			r2, err := NewParser().Parse([]byte(tc.src))
			if err != nil {
				t.Fatalf("second Parse: %v", err)
			}
			if !reflect.DeepEqual(r1, r2) {
				t.Errorf("nondeterministic parse")
			}
			// Legit case must resolve.
			if tc.name == "legit-import-still-resolves" {
				if want := []string{"m"}; !reflect.DeepEqual(importSpecs(r1.Imports), want) {
					t.Errorf("imports = %v, want %v", importSpecs(r1.Imports), want)
				}
				if r1.Truncated {
					t.Errorf("Truncated = true, want false for legit import")
				}
			}
			t.Logf("parse %q: %s truncated=%v imports=%d", tc.name, elapsed, r1.Truncated, len(r1.Imports))
		})
	}
}

func boolPtr(b bool) *bool { return &b }
