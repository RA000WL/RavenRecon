// TestSemanticCompat is the maintainer's "run it forever" semantic gate for
// the examples pack (milestone v1.2.5 SDK freeze). The SDK freeze's shape
// golden (internal/detect/surface_snapshot_test.go + testdata/api_v1.golden)
// catches compile-level surface drift and the behavior contract tests pin
// framework behavior; THIS test closes the remaining gap: the pack's actual
// OUTPUT — the engine's deterministic report for a fixed synthetic snapshot —
// is pinned byte-for-byte against testdata/api_v1_report.golden, so any
// semantic drift in pack output (a changed finding subject, metadata,
// evidence record, related-asset citation, rule status, finding count, or
// log line) fails CI even though every signature still compiles.
//
// # Pipeline (the full pack run, exactly as a consumer would load it)
//
//  1. examples.Rules() — the API-compatibility check runs first.
//  2. detect.ValidateRule on every pack rule.
//  3. Register every rule in a fresh Registry, Validate (the dependency
//     graph), Seal.
//  4. detect.Run with the fixed injected clock and the cache DISABLED
//     (cfg.Cache stays nil): deterministic execution with zero cache
//     interference, the same EngineConfig shape the pack's own pipeline
//     tests use, on the same fixed synthetic snapshot (buildSnapshot in
//     rules_test.go), which exercises all six rules.
//  5. The report is marshaled with encoding/json (MarshalIndent over the
//     full detect.Report — the same struct and JSON tags the pack's
//     TestPackDeterministicReports byte-compares) and diffed against the
//     golden. The engine's report is deterministic under a fixed clock:
//     rule results sorted by rule ID, findings merged and sorted by
//     finding identity, log entries sorted, map keys sorted by
//     encoding/json, timestamps from the injected clock.
//
// # Golden format
//
// The golden is a fixed documentation header (this contract) followed by
// the deterministic JSON document, one field per line (two-space indent):
//
//	"outcome"         aggregate run outcome ("completed" for this pack)
//	"rules"           one entry per pack rule, sorted by rule ID:
//	                  rule_id, rule_version, status, findings (count)
//	"findings"        the run's findings, sorted by finding identity; every
//	                  field is pinned: rule_id, rule_name, category, subject
//	                  (kind + value), confidence, evidence records (method,
//	                  indicator, value, source, provenance), related_assets,
//	                  priority, status, created/updated (fixed clock), and
//	                  metadata
//	"completed"/...   per-rule status counts
//	"levels"          dependency levels of the executed schedule
//	"logs"            the audit rule's config-driven log lines (the
//	                  logger-rule output)
//
// # Lifecycle
//
// A normal run never writes: it compares, and a missing or drifted golden
// fails with a line diff. The golden is regenerated ONLY through the
// explicit -update opt-in:
//
//	go test ./internal/detect/examples/ -run TestSemanticCompat -update
//
// Regeneration is the documented reopening path when the pack LEGITIMATELY
// changes its output (new rule, new finding, detector behavior change,
// version bump — rule.go's bump contract). Before regenerating, the test
// still asserts the expected run shape (assertColdRunShape), so a broken
// run can never be promoted into a fresh golden.
package examples

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/detect"
)

// updateCompatGolden regenerates testdata/api_v1_report.golden instead of
// comparing. It is the ONLY regeneration path: a normal run never writes.
var updateCompatGolden = flag.Bool("update", false, "regenerate testdata/api_v1_report.golden instead of comparing")

// compatGoldenFile is the golden file, relative to this package's directory.
const compatGoldenFile = "testdata/api_v1_report.golden"

// compatGoldenHeader is the fixed, deterministic header of the golden file:
// no timestamps, no absolute paths, no toolchain versions. It documents the
// format and the regeneration path inside the golden itself.
const compatGoldenHeader = `# api_v1_report.golden — semantic-compatibility regression golden of the
# examples pack (milestone v1.2.5 SDK freeze). Pinned by TestSemanticCompat
# in internal/detect/examples/compat_test.go: one full pack run (fixed
# synthetic snapshot from rules_test.go's buildSnapshot, fixed injected
# clock, cache disabled) is marshaled with encoding/json and byte-compared
# against this file. Any drift in pack output — rule results (statuses,
# versions, finding counts), finding fields (subjects, evidence records,
# related-asset citations, metadata, fixed-clock timestamps), or the audit
# rule's log lines — fails the test.
#
# The document below is the deterministic JSON form of detect.Report:
#   "outcome"         aggregate run outcome
#   "rules"           one entry per pack rule, sorted by rule ID:
#                     rule_id, rule_version, status, findings (count)
#   "findings"        the run's findings, sorted by finding identity; every
#                     field is pinned, incl. subject (kind + value),
#                     category, confidence, evidence records (method,
#                     indicator, value, source, provenance),
#                     related_assets, priority, status,
#                     created/updated (fixed clock), and metadata
#   "completed"/...   per-rule status counts
#   "levels"          dependency levels of the executed schedule
#   "logs"            the audit rule's config-driven log lines
#
# Regenerate ONLY when the pack LEGITIMATELY changes its output (new rule,
# new finding, detector behavior change, version bump) with:
#
#   go test ./internal/detect/examples/ -run TestSemanticCompat -update
#
# A normal run never writes. Do not edit by hand.
`

// TestSemanticCompat runs the full pack pipeline (see the file header) and
// byte-compares the deterministic report against the golden. Any drift in
// pack output fails the test with a line diff.
func TestSemanticCompat(t *testing.T) {
	snap, err := buildSnapshot()
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 6 {
		t.Fatalf("pack carries %d rules, want 6", len(rules))
	}

	// Full load path: ValidateRule per rule, then a fresh registry, the
	// dependency-graph validation, and the seal.
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := detect.ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%q): %v", r.ID, err)
		}
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("registry Validate: %v", err)
	}
	reg.Seal()

	// Deterministic run: fixed clock, cache disabled (nil), the pack
	// tests' configuration (the audit rule's detail flag).
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	cfg.Config = packConfig

	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Shape guard before ANY golden interaction: a broken run (failed
	// rules, truncated findings, wrong counts) must fail here, so a
	// regeneration can never promote a broken run into a fresh golden.
	assertColdRunShape(t, rep)

	got, err := compatSerialize(rep)
	if err != nil {
		t.Fatalf("serialize report: %v", err)
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	golden := filepath.Join(filepath.Dir(file), compatGoldenFile)

	if *updateCompatGolden {
		if err := compatWriteGolden(golden, got); err != nil {
			t.Fatalf("regenerate golden: %v", err)
		}
		re, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("re-read regenerated golden: %v", err)
		}
		if !bytes.Equal(re, got) {
			t.Fatalf("regenerated golden is not byte-stable (rerun without -update)")
		}
		t.Logf("regenerated %s (%d bytes)", compatGoldenFile, len(got))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s: %v (generate it with: go test ./internal/detect/examples/ -run TestSemanticCompat -update)", compatGoldenFile, err)
	}
	if bytes.Equal(want, got) {
		return
	}
	t.Fatalf("examples pack output drifted from %s:\n%s", compatGoldenFile, compatDiffLines(string(want), string(got)))
}

// compatSerialize renders the report into the golden document: the fixed
// header plus the deterministic indented JSON form of the full report (the
// same struct and JSON tags TestPackDeterministicReports byte-compares).
func compatSerialize(rep detect.Report) ([]byte, error) {
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	out := make([]byte, 0, len(compatGoldenHeader)+len(j)+1)
	out = append(out, compatGoldenHeader...)
	out = append(out, j...)
	out = append(out, '\n')
	return out, nil
}

// compatWriteGolden writes the golden atomically (temp file + fsync +
// rename) — the only regeneration path.
func compatWriteGolden(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".api_v1_report.golden.tmp*")
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

// compatSplitLines splits a document into lines, dropping the single
// trailing empty element a final newline produces.
func compatSplitLines(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// compatDiffLines returns a compact unified-style line diff (LCS-based, at
// most three context lines around every change, unchanged runs collapsed
// with a marker, output byte-capped) — the same comparison shape the detect
// package's surface snapshot test uses, so a drifted golden produces a
// reviewable delta instead of an opaque byte mismatch.
func compatDiffLines(oldText, newText string) string {
	oldLines := compatSplitLines(oldText)
	newLines := compatSplitLines(newText)

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

	// Collapse unchanged runs: keep at most 2*ctx+1 context lines around
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
