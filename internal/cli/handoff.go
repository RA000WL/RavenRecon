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

const handoffUsage = `RavenRecon handoff - export scanner feeder files from a report

Usage:
  ravenrecon handoff [options] <report.json>

Reads one report JSON export and writes feeder files for external
scanners (nuclei, httpx, katana): targets.txt (observed root URLs, one
per line, sorted — as recorded in the report, never re-verified and
possibly stale) and handoff.json (targets plus per-host technology
attribution plus per-finding severity ordering hints). The export
restates the report — it never re-verifies reachability and never claims
a finding is a vulnerability. Technology attribution is host-only
(host_to_technology edges); url/endpoint technology edges are out of
scope by design.

  --output <dir>        Directory for targets.txt and handoff.json,
                        created with parents as needed (default: the
                        directory containing <report.json>)

Exit codes:
  0   the export was written (even when empty — nothing observed to feed is
      itself a finding)
  1   usage errors, unreadable/incompatible input, or unwritable output

Examples:
  ravenrecon handoff report.json
  ravenrecon handoff --output feed/ report.json
  nuclei -l feed/targets.txt -severity critical,high
`

// runHandoff implements the handoff command.
func runHandoff(ctx context.Context, w io.Writer, args []string) error {
	if ctx == nil {
		return fmt.Errorf("handoff: context must not be nil")
	}
	fs := flag.NewFlagSet("handoff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outputDir := fs.String("output", "", "directory for targets.txt and handoff.json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return printHandoffUsage(w)
		}
		return fmt.Errorf("handoff: %w", err)
	}
	if rest := fs.Args(); len(rest) > 0 && (rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help") {
		return printHandoffUsage(w)
	}
	paths := fs.Args()
	if len(paths) != 1 {
		return fmt.Errorf("handoff: need exactly one report path (usage: ravenrecon handoff [options] <report.json>)")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("handoff: %w", err)
	}
	m, err := diff.LoadReport(paths[0])
	if err != nil {
		return err
	}
	h := diff.HandoffOf(m)
	outDir := *outputDir
	if outDir == "" {
		outDir = filepath.Dir(paths[0])
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("handoff: create output directory %s: %w", outDir, err)
	}
	if _, err := fmt.Fprintf(w, "handoff %s: %d targets, %d hosts with tech, %d findings ranked (targets as recorded, not re-verified)\n",
		h.Target, len(h.Targets), len(h.Tech), len(h.Severity)); err != nil {
		return err
	}
	return diff.WriteHandoff(outDir, h)
}

func printHandoffUsage(w io.Writer) error {
	_, err := io.WriteString(w, handoffUsage)
	return err
}
