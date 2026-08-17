// Package report is RavenRecon's Reporting Framework (phase 11): it consumes
// the canonical graph, findings, evidence, and metadata the earlier phases
// produced and exports them as deterministic, reproducible reports in
// multiple formats.
//
// Reporting is presentation only. The framework never rescans a target,
// never mutates the data it is given, and never invents a field: every value
// in every export traces back to the caller-composed Context. A renderer
// that received the same Model twice produces byte-identical output — the
// Model is built once per run (validated through the Phase 2 builders,
// deduplicated, merged, and sorted), and every format renders from that one
// canonical model, so no format re-normalizes, re-sorts, or re-traverses the
// graph.
//
// The framework pieces:
//
//   - Context: the caller-composed run input (typed Phase 2 assets,
//     relationships, priority surfaces, run/error/cache/execution
//     statistics). It mirrors the other engines' snapshot seams: a Context
//     entry that is not a canonical Phase 2 value is rejected, not silently
//     repaired.
//   - Model: the canonical report model NewModel builds — normalized,
//     deterministic (same input multiset, same model), with the run summary,
//     error summary, statistics, and digest computed once.
//   - Registry: reports register like rules, with validated metadata
//     (ID, name, description, version, output format, compression support,
//     enabled flag) and duplicate-ID rejection.
//   - Renderers: the four built-in exports (JSON, CSV, Markdown, HTML).
//     JSON and CSV are complete machine-readable exports; Markdown and HTML
//     are human summaries with documented, honestly surfaced row caps.
//     Future formats plug into the same Reporter contract.
//   - Engine: Run renders every enabled report on the shared bounded runtime
//     pool (one job per report, no new scheduler), streams output through
//     atomic crash-safe file writes (unique temp file + fsync + rename — a
//     reader never sees a partial report, and a cancelled or failed render
//     leaves no file behind), validates every export before it is exposed,
//     and can optionally compose cache-before-execute around renders through
//     the existing internal/cache (operation "report.render").
//
// Security posture: all HTML output is escaped; CSV exports neutralize
// spreadsheet formula injection (the JSON export carries the exact bytes);
// output filenames are derived from a sanitized base name, so no untrusted
// string ever reaches a filesystem path; every list and message is bounded.
//
// There is no ravenrecon report CLI command yet — the framework is a library
// capability only.
package report
