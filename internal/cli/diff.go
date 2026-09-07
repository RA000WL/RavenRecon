package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/RA000WL/RavenRecon/internal/diff"
)

const diffUsage = `RavenRecon diff - compare two report JSON exports

Usage:
  ravenrecon diff [options] <old-report.json> <new-report.json>

Options come before the two paths (the ingest convention: the flag
package stops at the first positional, so trailing options would parse
as paths).

Compares two runs of the same target and reports what changed: per-dataset
added/removed identities (domains, hosts, IPs, URLs, endpoints,
parameters, technologies, secrets, findings, JavaScript, source maps,
ports, services, TLS certificates) plus priority surface movements. The
delta is observational only — it never rescans, never mutates either
input, and never claims exploitability. Digests are carried from the
inputs (recorded, not recomputed): an empty delta on matching recorded
digests means "recorded identical", not an independent verification.

  --output <dir>        Directory for delta.json and delta.md, created
                        with parents as needed (default: the directory
                        containing <new-report.json>, so deltas sit
                        next to the current report)

Exit codes:
  0   the delta was computed and written (even when empty — an empty delta
       is a finding: nothing changed, proven by matching recorded digests)
  1   usage errors, unreadable/incompatible inputs (schema mismatch, target
      mismatch), or unwritable output

Examples:
  ravenrecon diff old-report.json new-report.json
  ravenrecon diff --output deltas/ old.json new.json
`

// runDiff implements the diff command: two report paths plus options.
func runDiff(ctx context.Context, w io.Writer, args []string) error {
	if ctx == nil {
		return fmt.Errorf("diff: context must not be nil")
	}
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outputDir := fs.String("output", "", "directory for delta.json and delta.md")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return printDiffUsage(w)
		}
		return fmt.Errorf("diff: %w", err)
	}
	if rest := fs.Args(); len(rest) > 0 && (rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help") {
		return printDiffUsage(w)
	}
	paths := fs.Args()
	if len(paths) != 2 {
		return fmt.Errorf("diff: need exactly two report paths, old and new (usage: ravenrecon diff [options] <old-report.json> <new-report.json>)")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("diff: %w", err)
	}
	oldM, err := diff.LoadReport(paths[0])
	if err != nil {
		return err
	}
	newM, err := diff.LoadReport(paths[1])
	if err != nil {
		return err
	}
	oldS, err := diff.SnapshotOf(oldM)
	if err != nil {
		return err
	}
	newS, err := diff.SnapshotOf(newM)
	if err != nil {
		return err
	}
	d, err := diff.Diff(oldS, newS)
	if err != nil {
		return err
	}
	outDir := *outputDir
	if outDir == "" {
		outDir = filepath.Dir(paths[1])
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("diff: create output directory %s: %w", outDir, err)
	}
	if _, err := fmt.Fprint(w, d.Summary()); err != nil {
		return err
	}
	if err := diff.WriteJSON(filepath.Join(outDir, "delta.json"), d); err != nil {
		return err
	}
	if err := diff.WriteMarkdown(filepath.Join(outDir, "delta.md"), d); err != nil {
		return err
	}
	return nil
}

func printDiffUsage(w io.Writer) error {
	_, err := io.WriteString(w, diffUsage)
	return err
}
