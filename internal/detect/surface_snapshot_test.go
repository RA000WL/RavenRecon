// TestSDKAPISurfaceSnapshot pins the frozen Level-1 SDK surface of package
// detect (the "SDK v1 (Core)" freeze of milestone v1.2.5; see api.go for
// the three-layer versioning and the Level-1 stability policy). It
// serializes the package's exported surface from its own Go source
// (go/parser + go/ast over the non-test files, no compiled export data),
// diffs it against testdata/api_v1.golden, and fails on ANY drift: added or
// removed exported symbol, changed signature, changed struct fields/tags,
// or changed constant value.
//
// The golden pins ONLY the exported Go contract: unexported struct fields
// (a type's internals) and parameter/result names (and receiver names,
// which are never rendered) are not part of the contract and are never
// serialized. A cosmetic rename or an internal refactor (e.g. replacing an
// atomic.Bool field with a mutex-guarded bool) therefore cannot drift the
// snapshot — only exported symbols, exported fields (name + type + tag),
// signature TYPES, and constant values are pinned.
//
// The golden is regenerated ONLY through the explicit -update opt-in:
//
//	go test ./internal/detect/ -run TestSDKAPISurfaceSnapshot -update
//
// A normal run never writes: it compares, and a missing or drifted golden
// fails with the symbol-set delta and a line diff.
//
// # Level-2/Level-3 exclusions (documented, deliberately not in the contract)
//
// The exported symbols below are the package's experimental / instrumentation
// surface, NOT part of the frozen Level-1 contract, and are excluded from the
// golden — their presence is tolerated and their shape may evolve freely:
//
//   - Metrics — the run's internal execution counters (engine.go's sibling
//     instrumentation). Run-internal detail, not a rule-author contract:
//     packs never read it, and the engine's Metrics field on EngineConfig
//     (a Level-1 struct field) is the only touch point, which stays pinned.
//   - MetricsSnapshot — Metrics' point-in-time copy; same reason.
//   - RuleStats — per-rule counter accumulation inside Metrics; same reason.
//   - BenchmarkDetector — developer-only measurement helper for unregistered
//     rules (no caching, no scheduling); not part of the pack-loading
//     contract packs depend on.
//   - BenchResult — the benchmark's measurement result; same reason.
//
// Any exported symbol that is neither in the Level-1 golden nor named in
// excludedSurface FAILS the snapshot: a new experimental helper must be
// deliberately added to excludedSurface with a reason — never silently —
// and a deliberate Level-1 change must go through the maintainer-approved
// API path (api.go) and the -update regeneration.
package detect

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// updateGolden regenerates testdata/api_v1.golden instead of comparing. It
// is the ONLY regeneration path: a normal run never writes.
var updateGolden = flag.Bool("update", false, "regenerate testdata/api_v1.golden instead of comparing")

// goldenFile is the snapshot file, relative to this package's directory.
const goldenFile = "testdata/api_v1.golden"

// excludedSurface names the package's Level-2/Level-3 surface: exported
// symbols deliberately NOT part of the frozen Level-1 contract (see the
// file header for the per-symbol reasons). Lookup only — iteration order is
// irrelevant to the serializer.
var excludedSurface = map[string]string{
	"Metrics":           "Level-2: run-internal execution metrics, not a rule-author contract",
	"MetricsSnapshot":   "Level-2: point-in-time copy of the internal metrics",
	"RuleStats":         "Level-2: per-rule counter accumulation inside Metrics",
	"BenchmarkDetector": "Level-3: developer-only benchmarking helper, not a pack-loading contract",
	"BenchResult":       "Level-3: benchmark measurement result",
}

// surfaceGoldenHeader is the fixed, deterministic header of the golden file:
// no timestamps, no absolute paths, no toolchain versions.
const surfaceGoldenHeader = `# api_v1.golden — frozen Level-1 SDK surface of package detect ("SDK v1
# Core", milestone v1.2.5; see api.go for the stability policy). Pinned by
# TestSDKAPISurfaceSnapshot: any drift — added/removed exported symbol,
# changed signature, changed struct fields/tags, changed constant value —
# fails the test. Only the exported contract is pinned: unexported fields
# and parameter/result names are never rendered. Regenerate ONLY with:
#
#   go test ./internal/detect/ -run TestSDKAPISurfaceSnapshot -update
#
# Do not edit by hand. The Level-2/Level-3 experimental surface (Metrics,
# MetricsSnapshot, RuleStats, BenchmarkDetector, BenchResult) is documented
# in surface_snapshot_test.go and deliberately absent here.
`

// surfaceSymbol is one serialized exported symbol.
type surfaceSymbol struct {
	kind   string // "const", "var", "type", "method", "func"
	name   string // symbol name (methods: rendered receiver + "." + name)
	sortBy string // deterministic sort key (base type without "*" for methods)
	text   string // serialized form (multi-line for struct types)
}

// collectSurface parses the package's non-test source files and returns
// every exported symbol minus the documented exclusions, deterministically
// ordered by section sort key.
func collectSurface(dir string) ([]surfaceSymbol, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read package directory: %w", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	// Constants are collected raw first and evaluated after every file is
	// parsed, so a constant may reference an earlier-declared constant.
	type pendingConst struct {
		name string
		typ  ast.Expr
		val  ast.Expr
	}
	var pending []pendingConst
	var syms []surfaceSymbol

	fset := token.NewFileSet()
	for _, name := range files {
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				switch d.Tok {
				case token.CONST, token.VAR:
					last := []ast.Expr{} // implicit-repetition carrier (`A = 1; B` repeats A's value)
					for _, spec := range d.Specs {
						vs := spec.(*ast.ValueSpec)
						vals := vs.Values
						if len(vals) == 0 {
							vals = last
						} else {
							last = vals
						}
						for i, n := range vs.Names {
							if !n.IsExported() {
								continue
							}
							if d.Tok == token.CONST {
								var val ast.Expr
								switch {
								case i < len(vals):
									val = vals[i]
								case len(vals) == 1 && len(vs.Names) > 1:
									val = vals[0] // parallel `A, B = x` form
								default:
									return nil, fmt.Errorf("%s: constant %s has no value to evaluate", name, n.Name)
								}
								pending = append(pending, pendingConst{name: n.Name, typ: vs.Type, val: val})
								continue
							}
							text := "var " + n.Name + " <inferred>"
							if vs.Type != nil {
								text = "var " + n.Name + " " + surfaceRenderType(vs.Type)
							}
							syms = append(syms, surfaceSymbol{kind: "var", name: n.Name, sortBy: n.Name, text: text})
						}
					}
				case token.TYPE:
					for _, spec := range d.Specs {
						ts := spec.(*ast.TypeSpec)
						if !ts.Name.IsExported() {
							continue
						}
						syms = append(syms, surfaceSymbol{
							kind:   "type",
							name:   ts.Name.Name,
							sortBy: ts.Name.Name,
							text:   surfaceRenderTypeSpec(ts),
						})
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil {
					base, ok := surfaceReceiverBase(d.Recv)
					if !ok || !ast.IsExported(base) || !d.Name.IsExported() {
						continue
					}
					recv := surfaceRenderType(d.Recv.List[0].Type)
					syms = append(syms, surfaceSymbol{
						kind:   "method",
						name:   recv + "." + d.Name.Name,
						sortBy: base + "." + d.Name.Name,
						text:   recv + "." + d.Name.Name + surfaceRenderFuncSuffix(d.Type),
					})
					continue
				}
				if d.Name.IsExported() {
					syms = append(syms, surfaceSymbol{
						kind:   "func",
						name:   d.Name.Name,
						sortBy: d.Name.Name,
						text:   "func " + d.Name.Name + surfaceRenderFuncSuffix(d.Type),
					})
				}
			}
		}
	}

	// Evaluate and render constants through a package-wide table.
	table := make(map[string]constant.Value, len(pending))
	for _, pc := range pending {
		v, ok := surfaceEvalConst(pc.val, table)
		if !ok {
			return nil, fmt.Errorf("constant %s has a value that cannot be evaluated statically (%s)", pc.name, surfaceRenderExpr(pc.val))
		}
		table[pc.name] = v
		line := "const " + pc.name
		if pc.typ != nil {
			line += " " + surfaceRenderType(pc.typ)
		}
		line += " = " + surfaceRenderConstValue(v)
		syms = append(syms, surfaceSymbol{kind: "const", name: pc.name, sortBy: pc.name, text: line})
	}

	// Drop the documented Level-2/Level-3 exclusions (a type exclusion
	// covers the type and every method on it).
	kept := syms[:0]
	for _, s := range syms {
		if s.kind == "method" {
			base := s.sortBy[:strings.Index(s.sortBy, ".")]
			if _, excl := excludedSurface[base]; excl {
				continue
			}
			kept = append(kept, s)
			continue
		}
		if _, excl := excludedSurface[s.name]; excl {
			continue
		}
		kept = append(kept, s)
	}
	syms = kept

	sort.SliceStable(syms, func(i, j int) bool { return syms[i].sortBy < syms[j].sortBy })
	return syms, nil
}

// surfaceSerialize renders the collected symbols into the golden document:
// fixed header plus "## consts", "## types", "## methods", "## funcs"
// sections, each entry deterministically sorted by name.
func surfaceSerialize(syms []surfaceSymbol) []byte {
	var consts, types, methods, funcs []string
	for _, s := range syms {
		switch s.kind {
		case "const":
			consts = append(consts, s.text)
		case "type":
			types = append(types, s.text)
		case "method":
			methods = append(methods, s.text)
		case "func":
			funcs = append(funcs, s.text)
		}
	}
	sort.Strings(consts)
	sort.Strings(types)
	sort.Strings(methods)
	sort.Strings(funcs)

	var b strings.Builder
	b.WriteString(surfaceGoldenHeader)
	if len(consts) > 0 {
		b.WriteString("\n## consts\n\n")
		b.WriteString(strings.Join(consts, "\n") + "\n")
	}
	if len(types) > 0 {
		b.WriteString("\n## types\n\n")
		b.WriteString(strings.Join(types, "\n\n") + "\n")
	}
	if len(methods) > 0 {
		b.WriteString("\n## methods\n\n")
		b.WriteString(strings.Join(methods, "\n") + "\n")
	}
	if len(funcs) > 0 {
		b.WriteString("\n## funcs\n\n")
		b.WriteString(strings.Join(funcs, "\n") + "\n")
	}
	return []byte(b.String())
}

// surfaceRenderTypeSpec serializes one type declaration: struct types get
// one line per field (declared order — field order and tags are part of the
// contract), interfaces get their methods inline, everything else one line.
func surfaceRenderTypeSpec(ts *ast.TypeSpec) string {
	if ts.Assign.IsValid() {
		return "type " + ts.Name.Name + " = " + surfaceRenderType(ts.Type)
	}
	switch t := ts.Type.(type) {
	case *ast.StructType:
		var b strings.Builder
		b.WriteString("type " + ts.Name.Name + " struct {\n")
		for _, f := range surfaceRenderFields(t.Fields, true, false) {
			b.WriteString("\t" + f + "\n")
		}
		b.WriteString("}")
		return b.String()
	case *ast.InterfaceType:
		return "type " + ts.Name.Name + " interface { " + strings.Join(surfaceRenderFields(t.Methods, false, true), "; ") + " }"
	default:
		return "type " + ts.Name.Name + " " + surfaceRenderType(ts.Type)
	}
}

// surfaceRenderFields serializes a field list (struct fields or interface
// methods), one entry per source field, tags included when withTags is set.
// methodForm renders fields as interface methods ("Log(LogLevel, string,
// string)") instead of struct fields ("Log func(...)"). Unexported fields
// are skipped: only the exported Go contract is pinned (see
// surfaceFieldExported).
func surfaceRenderFields(list *ast.FieldList, withTags, methodForm bool) []string {
	if list == nil {
		return nil
	}
	out := make([]string, 0, len(list.List))
	for _, f := range list.List {
		if !surfaceFieldExported(f) {
			continue
		}
		var b strings.Builder
		if len(f.Names) > 0 {
			names := make([]string, len(f.Names))
			for i, n := range f.Names {
				names[i] = n.Name
			}
			if methodForm {
				if ft, ok := f.Type.(*ast.FuncType); ok {
					b.WriteString(strings.Join(names, ", ") + surfaceRenderFuncSuffix(ft))
					out = append(out, b.String())
					continue
				}
			}
			b.WriteString(strings.Join(names, ", ") + " ")
		}
		b.WriteString(surfaceRenderType(f.Type))
		if withTags && f.Tag != nil {
			b.WriteString(" " + f.Tag.Value)
		}
		out = append(out, b.String())
	}
	return out
}

// surfaceFieldExported reports whether a struct field or interface method
// belongs to the exported Go contract. A named field is exported when at
// least one of its names is exported — an exported field with an
// unexported TYPE is still exported, so only the name governs visibility.
// A nameless embedded field is exported when its (base) type name is
// exported. Unknown shapes default to kept.
func surfaceFieldExported(f *ast.Field) bool {
	if len(f.Names) > 0 {
		for _, n := range f.Names {
			if n.IsExported() {
				return true
			}
		}
		return false
	}
	switch t := f.Type.(type) {
	case *ast.Ident:
		return t.IsExported()
	case *ast.SelectorExpr:
		return t.Sel.IsExported()
	case *ast.StarExpr:
		return surfaceFieldExported(&ast.Field{Type: t.X})
	}
	return true
}

// surfaceRenderFuncSuffix serializes "(params) results" of a function type
// without the "func" keyword. Parameter and result lists render as types
// only — names are not part of the exported Go contract.
func surfaceRenderFuncSuffix(t *ast.FuncType) string {
	params := surfaceRenderParams(t.Params)
	if t.Results == nil || len(t.Results.List) == 0 {
		return params
	}
	if len(t.Results.List) == 1 && len(t.Results.List[0].Names) <= 1 {
		return params + " " + surfaceRenderType(t.Results.List[0].Type)
	}
	return params + " " + surfaceRenderParams(t.Results)
}

// surfaceRenderParams serializes a parameter or result list as TYPES ONLY
// (parameter/result names are never rendered), always parenthesized. A
// field entry declares one parameter per name, so "a, b int" renders as
// "int, int" — the name list encodes arity, and arity is part of the
// signature contract.
func surfaceRenderParams(list *ast.FieldList) string {
	if list == nil || len(list.List) == 0 {
		return "()"
	}
	parts := make([]string, 0, len(list.List))
	for _, f := range list.List {
		typ := surfaceRenderType(f.Type)
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			parts = append(parts, typ)
		}
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// surfaceRenderType serializes a type expression deterministically and
// toolchain-independently (no go/printer, no token.FileSet positions). The
// package's own types render unqualified, exactly as the source declares
// them.
func surfaceRenderType(t ast.Expr) string {
	switch v := t.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return surfaceRenderType(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + surfaceRenderType(v.X)
	case *ast.ParenExpr:
		return "(" + surfaceRenderType(v.X) + ")"
	case *ast.ArrayType:
		if v.Len == nil {
			return "[]" + surfaceRenderType(v.Elt)
		}
		return "[" + surfaceRenderType(v.Len) + "]" + surfaceRenderType(v.Elt)
	case *ast.Ellipsis:
		return "..." + surfaceRenderType(v.Elt)
	case *ast.MapType:
		return "map[" + surfaceRenderType(v.Key) + "]" + surfaceRenderType(v.Value)
	case *ast.ChanType:
		switch v.Dir {
		case ast.SEND:
			return "chan<- " + surfaceRenderType(v.Value)
		case ast.RECV:
			return "<-chan " + surfaceRenderType(v.Value)
		}
		return "chan " + surfaceRenderType(v.Value)
	case *ast.FuncType:
		return "func" + surfaceRenderFuncSuffix(v)
	case *ast.InterfaceType:
		return "interface { " + strings.Join(surfaceRenderFields(v.Methods, false, true), "; ") + " }"
	case *ast.StructType:
		return "struct { " + strings.Join(surfaceRenderFields(v.Fields, true, false), "; ") + " }"
	case *ast.IndexExpr:
		return surfaceRenderType(v.X) + "[" + surfaceRenderType(v.Index) + "]"
	case *ast.IndexListExpr:
		args := make([]string, len(v.Indices))
		for i, ix := range v.Indices {
			args[i] = surfaceRenderType(ix)
		}
		return surfaceRenderType(v.X) + "[" + strings.Join(args, ", ") + "]"
	default:
		return "<" + fmt.Sprintf("%T", t) + ">"
	}
}

// surfaceRenderExpr renders a constant value expression for error messages
// only.
func surfaceRenderExpr(e ast.Expr) string {
	if bl, ok := e.(*ast.BasicLit); ok {
		return bl.Value
	}
	return surfaceRenderType(e)
}

// surfaceReceiverBase returns the base name (without "*") of a method
// receiver.
func surfaceReceiverBase(recv *ast.FieldList) (string, bool) {
	if recv == nil || len(recv.List) != 1 {
		return "", false
	}
	switch t := recv.List[0].Type.(type) {
	case *ast.Ident:
		return t.Name, true
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name, true
		}
	}
	return "", false
}

// surfaceStdlibConsts maps the stdlib constants the package's exported
// constants reference. go/constant cannot evaluate selector expressions
// without type-checking, so the frozen standard-library values are spelled
// out here; they are stable across Go toolchains. The Level-1 surface
// references exactly the time durations below (MaxRuleTimeout).
var surfaceStdlibConsts = map[string]constant.Value{
	"time.Nanosecond":  constant.MakeInt64(1),
	"time.Microsecond": constant.MakeInt64(1_000),
	"time.Millisecond": constant.MakeInt64(1_000_000),
	"time.Second":      constant.MakeInt64(1_000_000_000),
	"time.Minute":      constant.MakeInt64(60_000_000_000),
	"time.Hour":        constant.MakeInt64(3_600_000_000_000),
}

// surfaceEvalConst evaluates a constant expression to a go/constant value:
// literals, package constants (through the accumulated table), the known
// stdlib selectors, and unary/binary/paren operators. Anything else is
// reported as unevaluable so the test fails loudly rather than pinning
// something silently.
func surfaceEvalConst(e ast.Expr, table map[string]constant.Value) (constant.Value, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		return constant.MakeFromLiteral(v.Value, v.Kind, 0), true
	case *ast.Ident:
		if v.Name == "iota" {
			return nil, false // no iota constants in the frozen surface
		}
		val, ok := table[v.Name]
		return val, ok
	case *ast.SelectorExpr:
		val, ok := surfaceStdlibConsts[surfaceRenderType(v)]
		return val, ok
	case *ast.UnaryExpr:
		x, ok := surfaceEvalConst(v.X, table)
		if !ok {
			return nil, false
		}
		return constant.UnaryOp(v.Op, x, 0), true
	case *ast.BinaryExpr:
		x, ok1 := surfaceEvalConst(v.X, table)
		y, ok2 := surfaceEvalConst(v.Y, table)
		if !ok1 || !ok2 {
			return nil, false
		}
		return constant.BinaryOp(x, v.Op, y), true
	case *ast.ParenExpr:
		return surfaceEvalConst(v.X, table)
	}
	return nil, false
}

// surfaceRenderConstValue renders a constant value canonically: strings
// quoted, bools as true/false, numbers exactly (Int renders as exact
// decimal, Float as the shortest round-trip form) — deterministic across
// runs and toolchains.
func surfaceRenderConstValue(v constant.Value) string {
	switch v.Kind() {
	case constant.String:
		return strconv.Quote(constant.StringVal(v))
	case constant.Bool:
		return strconv.FormatBool(constant.BoolVal(v))
	default:
		return v.String()
	}
}

// TestSDKAPISurfaceSnapshot is the golden snapshot test (see the file
// header for the contract and the documented exclusions).
func TestSDKAPISurfaceSnapshot(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(file)

	syms, err := collectSurface(pkgDir)
	if err != nil {
		t.Fatalf("collect SDK surface: %v", err)
	}
	got := surfaceSerialize(syms)

	golden := filepath.Join(pkgDir, goldenFile)
	if *updateGolden {
		if err := surfaceWriteGolden(golden, got); err != nil {
			t.Fatalf("regenerate golden: %v", err)
		}
		re, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("re-read regenerated golden: %v", err)
		}
		if !bytes.Equal(re, got) {
			t.Fatalf("regenerated golden is not byte-stable (rerun without -update)")
		}
		t.Logf("regenerated %s (%d bytes)", goldenFile, len(got))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s: %v (generate it with: go test ./internal/detect/ -run TestSDKAPISurfaceSnapshot -update)", goldenFile, err)
	}
	if bytes.Equal(want, got) {
		return
	}

	var msg strings.Builder
	if added, removed := surfaceSetDiff(surfaceNames(string(want)), surfaceSymbolNames(syms)); len(added) > 0 || len(removed) > 0 {
		msg.WriteString("exported symbol set changed:\n")
		for _, n := range added {
			msg.WriteString("  + added: " + n + "\n")
		}
		for _, n := range removed {
			msg.WriteString("  - removed: " + n + "\n")
		}
		msg.WriteString("(a deliberate Level-1 change must go through the maintainer-approved API path (api.go) and -update regeneration; a new experimental helper must be added to excludedSurface with a reason)\n")
	}
	msg.WriteString(diffLines(string(want), string(got)))
	t.Fatalf("detect SDK surface drifted from %s:\n%s", goldenFile, msg.String())
}

// surfaceWriteGolden writes the golden atomically (temp file + fsync +
// rename) — the only regeneration path.
func surfaceWriteGolden(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".api_v1.golden.tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// surfaceNames extracts the symbol names from a serialized golden document:
// "const X ..." / "var X ..." / "type X ..." / "func F(...) ..." lines and
// method lines ("R.M(...)"). Struct continuation lines (tab-indented field
// lines) are skipped: they contain a space before any "(".
func surfaceNames(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "##"):
			continue
		case strings.HasPrefix(line, "const "), strings.HasPrefix(line, "var "),
			strings.HasPrefix(line, "type "), strings.HasPrefix(line, "func "):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := fields[1]
			if i := strings.Index(name, "("); i > 0 {
				name = name[:i]
			}
			out = append(out, name)
		default:
			if i := strings.Index(line, "("); i > 0 && !strings.Contains(line[:i], " ") {
				out = append(out, line[:i])
			}
		}
	}
	return out
}

// surfaceSymbolNames extracts the symbol names from the collected symbols,
// in the same textual form surfaceNames produces from the golden.
func surfaceSymbolNames(syms []surfaceSymbol) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, s.name)
	}
	return out
}

// surfaceSetDiff returns the added and removed names, sorted.
func surfaceSetDiff(want, got []string) (added, removed []string) {
	wantSet := make(map[string]bool, len(want))
	for _, n := range want {
		wantSet[n] = true
	}
	gotSet := make(map[string]bool, len(got))
	for _, n := range got {
		gotSet[n] = true
	}
	for _, n := range got {
		if !wantSet[n] {
			added = append(added, n)
		}
	}
	for _, n := range want {
		if !gotSet[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// surfaceSplitLines splits a document into lines, dropping the single
// trailing empty element a final newline produces.
func surfaceSplitLines(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// diffLines returns a compact unified-style line diff (LCS-based, at most
// three context lines around every change, unchanged runs collapsed with a
// marker, output byte-capped). The golden documents are small; the cell cap
// bounds memory on pathological inputs.
func diffLines(oldText, newText string) string {
	oldLines := surfaceSplitLines(oldText)
	newLines := surfaceSplitLines(newText)

	const maxCells = 4_000_000
	if len(oldLines)*len(newLines) > maxCells {
		return "old:\n" + oldText + "new:\n" + newText
	}

	lcs := make([][]int, len(oldLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			switch {
			case oldLines[i] == newLines[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	type op struct {
		kind byte // '=', '-', '+'
		line string
	}
	var ops []op
	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		if oldLines[i] == newLines[j] {
			ops = append(ops, op{'=', oldLines[i]})
			i++
			j++
			continue
		}
		if lcs[i+1][j] >= lcs[i][j+1] {
			ops = append(ops, op{'-', oldLines[i]})
			i++
		} else {
			ops = append(ops, op{'+', newLines[j]})
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		ops = append(ops, op{'-', oldLines[i]})
	}
	for ; j < len(newLines); j++ {
		ops = append(ops, op{'+', newLines[j]})
	}

	// Collapse unchanged runs: keep at most 2*context+1 context lines around
	// the changes; longer runs become a marker with ctx lines either side.
	const ctx = 3
	var b strings.Builder
	var run []string
	flush := func() {
		if len(run) == 0 {
			return
		}
		if len(run) > 2*ctx+1 {
			for _, l := range run[:ctx] {
				b.WriteString("  " + l + "\n")
			}
			fmt.Fprintf(&b, "… (%d unchanged lines)\n", len(run)-2*ctx)
			for _, l := range run[len(run)-ctx:] {
				b.WriteString("  " + l + "\n")
			}
		} else {
			for _, l := range run {
				b.WriteString("  " + l + "\n")
			}
		}
		run = run[:0]
	}
	const maxOut = 8 << 10
	for _, o := range ops {
		if o.kind == '=' {
			run = append(run, o.line)
			continue
		}
		flush()
		if o.kind == '-' {
			b.WriteString("- " + o.line + "\n")
		} else {
			b.WriteString("+ " + o.line + "\n")
		}
		if b.Len() >= maxOut {
			b.WriteString("… (diff truncated)\n")
			return b.String()
		}
	}
	flush()
	return b.String()
}
