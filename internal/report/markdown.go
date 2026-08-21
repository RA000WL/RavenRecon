package report

import (
	"bufio"
	"context"
	"fmt"
	"strings"
)

// Markdown presentation bounds (fixed constants). Markdown is the human
// summary view: long lists are cut at a documented bound with an honest
// "and N more" line — the JSON and CSV exports carry the complete datasets.
const (
	maxMarkdownListRows    = 200
	maxMarkdownTopFindings = 20
	maxMarkdownTopSurfaces = 20
	maxMarkdownTopPaths    = 10
)

// renderMarkdown writes the human-readable summary report. Identical
// models produce identical documents: every section renders the model's
// pre-sorted lists and bounded top-N projections, and no wall clock is
// read.
func renderMarkdown(ctx context.Context, m *Model, s Sink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w, err := s.Writer("")
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(w, sinkBufferSize)
	err = writeMarkdown(ctx, bw, m)
	if err == nil {
		err = bw.Flush()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("report: markdown: %w", err)
	}
	return nil
}

func writeMarkdown(ctx context.Context, bw *bufio.Writer, m *Model) error {
	target := m.Target
	if target == "" {
		target = "(no target declared)"
	}
	writeln := func(format string, args ...any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(bw, format+"\n", args...); err != nil {
			return err
		}
		return nil
	}

	if err := writeln("# RavenRecon Report — %s", mdEscape(target)); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}

	// Target / run block.
	if err := writeln("**Target:** %s", mdEscape(target)); err != nil {
		return err
	}
	if !m.StartedAt.IsZero() || !m.EndedAt.IsZero() {
		if err := writeln(""); err != nil {
			return err
		}
		if err := writeln("- Started: %s", formatTime(m.StartedAt)); err != nil {
			return err
		}
		if err := writeln("- Ended: %s", formatTime(m.EndedAt)); err != nil {
			return err
		}
		if err := writeln("- Duration: %s", formatDuration(m.Stats.Duration)); err != nil {
			return err
		}
	}
	if err := writeln("- Model digest: `%s`", m.Digest); err != nil {
		return err
	}

	// Summary.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Summary"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	sum := m.Summary
	if err := writeMarkdownTable(bw, []string{"metric", "value"}, [][]string{
		{"assets", fmt.Sprintf("%d", sum.Assets)},
		{"hosts", fmt.Sprintf("%d", sum.Hosts)},
		{"urls", fmt.Sprintf("%d", sum.URLs)},
		{"javascript", fmt.Sprintf("%d", sum.JavaScript)},
		{"secrets", fmt.Sprintf("%d", sum.Secrets)},
		{"findings", fmt.Sprintf("%d", sum.Findings)},
		{"rules", fmt.Sprintf("%d", sum.Rules)},
		{"relationships", fmt.Sprintf("%d", sum.Relationships)},
		{"recommendations", fmt.Sprintf("%d", sum.Recommendations)},
		{"cache hits / misses", fmt.Sprintf("%d / %d", sum.CacheHits, sum.CacheMisses)},
		{"worker time", formatDuration(sum.WorkerTime)},
	}); err != nil {
		return err
	}

	// Interesting assets (top surfaces by score).
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Interesting Assets"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.Surfaces) == 0 {
		if err := writeln("_No scored surfaces (the priority engine produced no output for this run)._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, min(maxMarkdownTopSurfaces, len(m.Surfaces)))
		for _, surf := range m.Surfaces {
			if len(rows) >= maxMarkdownTopSurfaces {
				break
			}
			reason := ""
			if len(surf.Factors) > 0 {
				reason = surf.Factors[0].Reason
			}
			rows = append(rows, []string{
				surf.Identity.String(),
				formatScore(surf.Score),
				string(surf.Level),
				reason,
			})
		}
		if err := writeMarkdownTable(bw, []string{"surface", "score", "level", "top factor"}, rows); err != nil {
			return err
		}
		if len(m.Surfaces) > len(rows) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more scored surfaces — see the JSON export._", len(m.Surfaces)-len(rows)); err != nil {
				return err
			}
		}
	}

	// Technologies.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Technologies"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.Technologies) == 0 {
		if err := writeln("_None observed._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, min(maxMarkdownListRows, len(m.Technologies)))
		for _, t := range m.Technologies {
			if len(rows) >= maxMarkdownListRows {
				break
			}
			rows = append(rows, []string{t.Name, string(t.Category), t.Version, conf(t.Prov.Confidence)})
		}
		if err := writeMarkdownTable(bw, []string{"name", "category", "version", "confidence"}, rows); err != nil {
			return err
		}
		if len(m.Technologies) > len(rows) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more technologies — see the JSON and CSV exports._", len(m.Technologies)-len(rows)); err != nil {
				return err
			}
		}
	}

	// Secrets.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Secrets"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("_Detected candidates only — never verified, never severity-rated._"); err != nil {
		return err
	}
	if len(m.Secrets) == 0 {
		if err := writeln("_None observed._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, min(maxMarkdownListRows, len(m.Secrets)))
		for _, sec := range m.Secrets {
			if len(rows) >= maxMarkdownListRows {
				break
			}
			rows = append(rows, []string{string(sec.Type), sec.Value, sec.Source.String(), conf(sec.Prov.Confidence)})
		}
		if err := writeMarkdownTable(bw, []string{"type", "value", "source", "confidence"}, rows); err != nil {
			return err
		}
		if len(m.Secrets) > len(rows) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more candidates — see the JSON and CSV exports._", len(m.Secrets)-len(rows)); err != nil {
				return err
			}
		}
	}

	// Live URLs (urllive, OPT-P0-3) — presentation-only, never rescans.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Live URLs"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.LiveRecords) == 0 {
		if err := writeln("_No live URL observations for this run._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, min(maxMarkdownListRows, len(m.LiveRecords)))
		for _, lr := range m.LiveRecords {
			if len(rows) >= maxMarkdownListRows {
				break
			}
			status := fmt.Sprintf("%d", lr.Status)
			if lr.Status == 0 && lr.Err != nil {
				status = lr.Err.Error()
				if len(status) > 64 {
					status = status[:64] + "…"
				}
			} else if lr.Status == 0 {
				status = "—"
			}
			redirect := "—"
			if lr.RedirectObserved {
				redirect = lr.RedirectLocation
				if redirect == "" {
					redirect = "yes"
				}
			}
			tls := "—"
			if lr.TLS != nil {
				tls = lr.TLS.Fingerprint[:8]
			} else if lr.TLSMeta != nil {
				tls = "handshake"
			}
			rows = append(rows, []string{lr.URL.String(), status, redirect, tls, fmt.Sprintf("%v", lr.Truncated)})
		}
		if err := writeMarkdownTable(bw, []string{"url", "status", "redirect", "tls", "truncated"}, rows); err != nil {
			return err
		}
		if len(m.LiveRecords) > len(rows) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more live URLs — see the JSON export._", len(m.LiveRecords)-len(rows)); err != nil {
				return err
			}
		}
	}

	// Top findings.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Top Findings"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.Findings) == 0 {
		if err := writeln("_None — no detection rules produced findings for this run._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, min(maxMarkdownTopFindings, len(m.Findings)))
		for _, f := range m.Findings {
			if len(rows) >= maxMarkdownTopFindings {
				break
			}
			rows = append(rows, []string{
				f.RuleID,
				f.Category,
				f.Subject.String(),
				formatScore(f.Confidence),
				f.Priority,
			})
		}
		if err := writeMarkdownTable(bw, []string{"rule", "category", "subject", "confidence", "priority"}, rows); err != nil {
			return err
		}
		if len(m.Findings) > len(rows) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more findings — see the JSON and CSV exports._", len(m.Findings)-len(rows)); err != nil {
				return err
			}
		}
	}

	// Attack surface.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Attack Surface"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.Groups) == 0 && len(m.AttackPaths) == 0 {
		if err := writeln("_No correlated attack surface for this run._"); err != nil {
			return err
		}
	} else {
		if len(m.Groups) > 0 {
			rows := make([][]string, 0, min(maxMarkdownTopSurfaces, len(m.Groups)))
			for _, g := range m.Groups {
				if len(rows) >= maxMarkdownTopSurfaces {
					break
				}
				rows = append(rows, []string{
					g.Anchor.String(),
					formatScore(g.Score),
					string(g.Level),
					fmt.Sprintf("%d", len(g.Members)),
				})
			}
			if err := writeMarkdownTable(bw, []string{"group anchor", "score", "level", "members"}, rows); err != nil {
				return err
			}
			if len(m.Groups) > len(rows) {
				if err := writeln(""); err != nil {
					return err
				}
				if err := writeln("_And %d more groups — see the JSON export._", len(m.Groups)-len(rows)); err != nil {
					return err
				}
			}
		}
		if len(m.AttackPaths) > 0 {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_Reconnaissance reading orders (hypotheses, never exploitation chains):_"); err != nil {
				return err
			}
			shown := m.AttackPaths
			if len(shown) > maxMarkdownTopPaths {
				shown = shown[:maxMarkdownTopPaths]
			}
			for _, path := range shown {
				if err := writeln(""); err != nil {
					return err
				}
				if err := writeln("- **%s** (score %s, %s)", mdEscape(path.Root.String()), formatScore(path.Score), string(path.Level)); err != nil {
					return err
				}
				for _, step := range path.Steps {
					if err := writeln("  - `%s` — %s", mdEscape(step.Identity.String()), mdEscape(step.Reason)); err != nil {
						return err
					}
				}
			}
			if len(m.AttackPaths) > len(shown) {
				if err := writeln(""); err != nil {
					return err
				}
				if err := writeln("_And %d more paths — see the JSON export._", len(m.AttackPaths)-len(shown)); err != nil {
					return err
				}
			}
		}
	}

	// Recommendations.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Recommendations"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if len(m.Recommendations) == 0 {
		if err := writeln("_None — no indicator-driven guidance for this run._"); err != nil {
			return err
		}
	} else {
		if err := writeln("_Reconnaissance guidance only; every item cites the evidence it came from._"); err != nil {
			return err
		}
		shown := m.Recommendations
		if len(shown) > maxMarkdownTopSurfaces {
			shown = shown[:maxMarkdownTopSurfaces]
		}
		for _, rec := range shown {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("- **%s** (%s, weight %s): %s", mdEscape(rec.Surface.String()), rec.Factor, formatScore(rec.Weight), mdEscape(rec.Text)); err != nil {
				return err
			}
		}
		if len(m.Recommendations) > len(shown) {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("_And %d more recommendations — see the JSON export._", len(m.Recommendations)-len(shown)); err != nil {
				return err
			}
		}
	}

	// Statistics.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Statistics"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	st := m.Stats
	if err := writeMarkdownTable(bw, []string{"metric", "value"}, [][]string{
		{"hosts", fmt.Sprintf("%d", st.HostCount)},
		{"urls", fmt.Sprintf("%d", st.URLCount)},
		{"endpoints", fmt.Sprintf("%d", st.EndpointCount)},
		{"technologies", fmt.Sprintf("%d", st.TechnologyCount)},
		{"secrets", fmt.Sprintf("%d", st.SecretCount)},
		{"relationships", fmt.Sprintf("%d", st.RelationshipCount)},
		{"findings", fmt.Sprintf("%d", st.FindingCount)},
		{"live urls", fmt.Sprintf("%d", st.LiveRecordCount)},
		{"rules", fmt.Sprintf("%d", st.RuleCount)},
		{"surfaces / groups / paths", fmt.Sprintf("%d / %d / %d", st.SurfaceCount, st.GroupCount, st.AttackPathCount)},
		{"worker time", formatDuration(st.Runtime.WorkerTime)},
		{"execution time", formatDuration(st.Duration)},
	}); err != nil {
		return err
	}

	// Errors.
	if err := writeln(""); err != nil {
		return err
	}
	if err := writeln("## Errors"); err != nil {
		return err
	}
	if err := writeln(""); err != nil {
		return err
	}
	if m.Errors.Total == 0 {
		if err := writeln("_No errors recorded for this run._"); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, len(m.Errors.Categories))
		for _, cat := range m.Errors.Categories {
			rows = append(rows, []string{string(cat.Category), fmt.Sprintf("%d", cat.Total), fmt.Sprintf("%d", cat.Unique)})
		}
		if err := writeMarkdownTable(bw, []string{"category", "total", "unique"}, rows); err != nil {
			return err
		}
		for _, cat := range m.Errors.Categories {
			if err := writeln(""); err != nil {
				return err
			}
			if err := writeln("### %s", string(cat.Category)); err != nil {
				return err
			}
			for _, sample := range cat.Samples {
				if err := writeln("- `[%s]` %s (x%d)", mdEscape(sample.Stage), mdEscape(sample.Message), sample.Count); err != nil {
					return err
				}
			}
			if cat.Unique > len(cat.Samples) {
				if err := writeln("- _… and %d more_", cat.Unique-len(cat.Samples)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// writeMarkdownTable writes a GitHub-flavored Markdown table (header,
// separator, rows). Every cell — header and row alike — is mdEscaped
// exactly once here, the single escaping choke point: values carrying
// pipes or backslashes must render inside one cell, and a second escape
// pass would re-escape the emitted "\|" into a literal backslash plus a
// live cell delimiter.
func writeMarkdownTable(bw *bufio.Writer, header []string, rows [][]string) error {
	cells := func(record []string) string {
		escaped := make([]string, len(record))
		for i, c := range record {
			escaped[i] = mdEscape(c)
		}
		return "| " + strings.Join(escaped, " | ") + " |"
	}
	if _, err := fmt.Fprintln(bw, cells(header)); err != nil {
		return err
	}
	sep := make([]string, len(header))
	for i := range sep {
		sep[i] = "---"
	}
	if _, err := fmt.Fprintln(bw, "| "+strings.Join(sep, " | ")+" |"); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(bw, cells(row)); err != nil {
			return err
		}
	}
	return nil
}
