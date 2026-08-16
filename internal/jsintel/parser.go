// Package-level documentation lives in doc.go.
package jsintel

import "fmt"

// Bounds applied by the JavaScript parser. These are FIXED constants: they
// never change between runs and never enter cache keys, so a parsed
// observation stays valid under any future configuration that retains at
// least as much. See doc.go for the limits summary.
const (
	// maxParserTokens bounds the token stream the lexer produces for one
	// parse. Hitting it marks the Parsed Truncated (honest prefix analysis):
	// the tokenizer stops and the extraction walk processes the tokens it
	// has. Comments count toward the cap.
	maxParserTokens = 1 << 20

	// maxParserStringBytes bounds the retained VALUE of one string/template
	// literal. Longer literals are still tokenized and still count toward
	// the maxParserStrings budget, but are not retained in Parsed.Strings.
	maxParserStringBytes = 4096

	// maxParserStrings bounds the string/template literals processed per
	// parse. Hitting it marks the Parsed Truncated.
	maxParserStrings = 8192

	// maxParserImports bounds the imports extracted per parse. Hitting it
	// marks the Parsed Truncated.
	maxParserImports = 1024

	// maxParserExports bounds the distinct export names retained per parse.
	// Hitting it marks the Parsed Truncated.
	maxParserExports = 1024

	// maxParserIdentBytes bounds one identifier token. Longer identifiers
	// are split at the cap (on a rune boundary) and counted malformed.
	maxParserIdentBytes = 1024

	// maxParseInputBytes is the hard defense-in-depth cap on Parse input;
	// larger inputs are rejected with an error — the ONLY Parse error. The
	// future fetch layer's own body cap bounds normal inputs; this is
	// defense in depth.
	maxParseInputBytes = 8 << 20

	// maxSourceMapRefBytes bounds a retained sourceMappingURL reference.
	// Longer references are dropped and counted malformed.
	maxSourceMapRefBytes = 4096
)

// ImportKind classifies a module import observation.
type ImportKind int

const (
	// ImportStatic is `import ... from "spec"`, the side-effect form
	// `import "spec"`, or an `export ... from "spec"` re-export.
	ImportStatic ImportKind = iota
	// ImportDynamic is `import("spec")`.
	ImportDynamic
)

// String returns "static" or "dynamic".
func (k ImportKind) String() string {
	if k == ImportDynamic {
		return "dynamic"
	}
	return "static"
}

// Import is one module import observed in a script: the module specifier as
// written (escapes decoded), the import kind, and the 1-based line of the
// import keyword (for a re-export, the line of the export keyword). Dynamic
// imports whose specifier cannot be statically resolved (for example
// `import(expr)` or a template with ${...}) carry Specifier "" — the
// observation is honest, never guessed.
type Import struct {
	Specifier string
	Kind      ImportKind
	Line      int
}

// StringLit is one string or template literal observed in a script. Value is
// the ESCAPES-DECODED text (decode rules in parse.go): for template
// literals, ${...} expression segments are copied verbatim — never decoded,
// never evaluated. Template reports whether the literal was a backtick
// template. Import specifiers are included in the stream like any other
// literal (consumers filter).
type StringLit struct {
	Value    string
	Line     int
	Template bool
}

// Parsed is the complete set of observations extracted from one script body:
// imports in source order (static and dynamic), exported names deduplicated
// in first-observation order, string/template literals in source order, the
// LAST sourceMappingURL reference observed (per the source map spec), and
// two honesty flags: Truncated when any token/string/import/export cap was
// hit (the results are a partial prefix — never a complete parse) and
// Malformed, the count of recovered-from lexical errors (stray bytes,
// invalid escapes, unterminated constructs).
//
// The parser never builds an AST, never executes code, and never rewrites
// code: it extracts observations.
type Parsed struct {
	Imports         []Import
	Exports         []string
	Strings         []StringLit
	SourceMapRef    string
	HasSourceMapRef bool
	Truncated       bool
	Malformed       int
}

// Parser is the JavaScript parsing abstraction. Later passes (fetch,
// pipeline, analyzers) consume ONLY this interface and the Parsed model —
// the architecture is deliberately NOT tied to any parser implementation.
//
// Parse is deterministic and safe for concurrent use on one Parser
// instance: a Parser keeps no state between calls. Malformed input never
// fails Parse — the scanner recovers and counts (see doc.go). The only
// error is input over maxParseInputBytes; empty input is a valid parse that
// yields an empty Parsed.
type Parser interface {
	Parse(src []byte) (Parsed, error)
}

// parser is the single Parser implementation: a hand-rolled, error-tolerant
// JavaScript tokenizer (lex.go) plus an extraction walk over its tokens
// (parse.go). It is stateless between calls: NewParser returns an instance
// that may be reused for any number of Parse calls, sequentially or
// concurrently.
type parser struct{}

// NewParser returns a Parser usable for any number of Parse calls.
func NewParser() Parser {
	return &parser{}
}

// Parse tokenizes src and extracts observations. See the Parser interface
// documentation for the full contract.
func (p *parser) Parse(src []byte) (Parsed, error) {
	if len(src) > maxParseInputBytes {
		return Parsed{}, fmt.Errorf("jsintel: parse input is %d bytes, exceeding the %d byte hard limit", len(src), maxParseInputBytes)
	}
	lx := &lexer{src: src, line: 1, regexOK: true}
	lx.run()
	w := &walker{
		src:         src,
		toks:        lx.toks,
		seenExports: make(map[string]struct{}),
	}
	w.walk()
	return Parsed{
		Imports:         w.out.Imports,
		Exports:         w.out.Exports,
		Strings:         w.out.Strings,
		SourceMapRef:    w.out.SourceMapRef,
		HasSourceMapRef: w.out.HasSourceMapRef,
		Truncated:       lx.truncated || w.truncated,
		Malformed:       lx.malformed + w.malformed,
	}, nil
}
