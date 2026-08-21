package report

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"sort"
	"strings"
)

// maxHTMLTableRows bounds one HTML data table (fixed constant). HTML is the
// human interactive view; the cut is honest and the complete datasets live
// in the JSON and CSV exports.
const maxHTMLTableRows = 1000

// renderHTML writes a self-contained static HTML report: one file, inline
// CSS, a small inline vanilla script for search and filtering (no
// frameworks, no external resources), and collapsible sections through the
// native <details> element. The full document is meaningful without
// scripting. Every interpolated byte passes html.EscapeString — URL,
// script, and style contexts never receive unescaped data because all
// dynamic content is text-node or quoted-attribute interpolated.
func renderHTML(ctx context.Context, m *Model, s Sink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w, err := s.Writer("")
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(w, sinkBufferSize)
	err = writeHTML(ctx, bw, m)
	if err == nil {
		err = bw.Flush()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("report: html: %w", err)
	}
	return nil
}

func writeHTML(ctx context.Context, bw *bufio.Writer, m *Model) error {
	esc := html.EscapeString
	writeln := func(format string, args ...any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := fmt.Fprintf(bw, format+"\n", args...)
		return err
	}

	target := m.Target
	if target == "" {
		target = "(no target declared)"
	}

	if err := writeln("<!DOCTYPE html>"); err != nil {
		return err
	}
	if err := writeln("<html lang=\"en\">"); err != nil {
		return err
	}
	if err := writeln("<head>"); err != nil {
		return err
	}
	if err := writeln("<meta charset=\"utf-8\">"); err != nil {
		return err
	}
	if err := writeln("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"); err != nil {
		return err
	}
	if err := writeln("<title>RavenRecon Report — %s</title>", esc(target)); err != nil {
		return err
	}
	if err := writeln("<style>%s</style>", htmlCSS); err != nil {
		return err
	}
	if err := writeln("</head>"); err != nil {
		return err
	}
	if err := writeln("<body>"); err != nil {
		return err
	}
	if err := writeln("<header>"); err != nil {
		return err
	}
	if err := writeln("<h1>RavenRecon Report</h1>"); err != nil {
		return err
	}
	if err := writeln("<p class=\"target\">Target: <strong>%s</strong></p>", esc(target)); err != nil {
		return err
	}
	if m.Digest != "" {
		if err := writeln("<p class=\"digest\">Model digest: <code>%s</code></p>", esc(m.Digest)); err != nil {
			return err
		}
	}
	if err := writeln("<input id=\"raven-search\" type=\"search\" placeholder=\"Filter rows across every table…\" autocomplete=\"off\">"); err != nil {
		return err
	}
	if err := writeln("<select id=\"raven-priority-filter\" aria-label=\"Filter findings by priority\">"); err != nil {
		return err
	}
	if err := writeln("<option value=\"all\">All finding priorities</option>"); err != nil {
		return err
	}
	for _, p := range findingPriorities(m) {
		if err := writeln("<option value=\"%s\">Priority: %s</option>", esc(p), esc(p)); err != nil {
			return err
		}
	}
	if err := writeln("</select>"); err != nil {
		return err
	}
	if err := writeln("</header>"); err != nil {
		return err
	}

	// Overview.
	if err := writeln("<main>"); err != nil {
		return err
	}
	if err := writeln("<section id=\"overview\"><h2>Overview</h2>"); err != nil {
		return err
	}
	sum := m.Summary
	if err := writeHTMLTable(bw, "", []string{"metric", "value"}, [][]string{
		{"started", formatTime(sum.StartedAt)},
		{"ended", formatTime(sum.EndedAt)},
		{"duration", formatDuration(sum.Duration)},
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
	if err := writeln("</section>"); err != nil {
		return err
	}

	// Statistics.
	if err := writeln("<section id=\"statistics\"><h2>Statistics</h2>"); err != nil {
		return err
	}
	st := m.Stats
	if err := writeHTMLTable(bw, "", []string{"metric", "value"}, [][]string{
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
	if err := writeln("</section>"); err != nil {
		return err
	}

	// Hosts.
	if err := writeln("<details id=\"hosts\" open><summary>Hosts (%d)</summary>", len(m.Hosts)); err != nil {
		return err
	}
	hostRows := make([][]string, 0, min(maxHTMLTableRows, len(m.Hosts)))
	for _, h := range m.Hosts {
		if len(hostRows) >= maxHTMLTableRows {
			break
		}
		hostRows = append(hostRows, []string{h.Name, h.Prov.Source, formatTime(h.Prov.DiscoveredAt)})
	}
	if err := writeHTMLTable(bw, "", []string{"host", "source", "discovered"}, hostRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.Hosts), len(hostRows)); err != nil {
		return err
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Technologies.
	if err := writeln("<details id=\"technologies\" open><summary>Technologies (%d)</summary>", len(m.Technologies)); err != nil {
		return err
	}
	techRows := make([][]string, 0, min(maxHTMLTableRows, len(m.Technologies)))
	for _, t := range m.Technologies {
		if len(techRows) >= maxHTMLTableRows {
			break
		}
		techRows = append(techRows, []string{t.Name, string(t.Category), t.Version, conf(t.Prov.Confidence)})
	}
	if err := writeHTMLTable(bw, "", []string{"name", "category", "version", "confidence"}, techRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.Technologies), len(techRows)); err != nil {
		return err
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Secrets.
	if err := writeln("<details id=\"secrets\" open><summary>Secrets (%d)</summary>", len(m.Secrets)); err != nil {
		return err
	}
	if err := writeln("<p class=\"note\">Detected candidates only — never verified, never severity-rated.</p>"); err != nil {
		return err
	}
	secretRows := make([][]string, 0, min(maxHTMLTableRows, len(m.Secrets)))
	for _, sec := range m.Secrets {
		if len(secretRows) >= maxHTMLTableRows {
			break
		}
		secretRows = append(secretRows, []string{string(sec.Type), sec.Value, sec.Source.String(), conf(sec.Prov.Confidence)})
	}
	if err := writeHTMLTable(bw, "", []string{"type", "value", "source", "confidence"}, secretRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.Secrets), len(secretRows)); err != nil {
		return err
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Live URLs (urllive, OPT-P0-3) — presentation-only.
	if err := writeln("<details id=\"live-urls\" open><summary>Live URLs (%d)</summary>", len(m.LiveRecords)); err != nil {
		return err
	}
	if err := writeln("<p class=\"note\">URL liveness triage — status, redirect, and TLS observations (single GET, no body, redirect observed-not-followed).</p>"); err != nil {
		return err
	}
	liveRows := make([][]string, 0, min(maxHTMLTableRows, len(m.LiveRecords)))
	for _, lr := range m.LiveRecords {
		if len(liveRows) >= maxHTMLTableRows {
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
		liveRows = append(liveRows, []string{lr.URL.String(), status, redirect, tls, fmt.Sprintf("%v", lr.Truncated)})
	}
	if err := writeHTMLTable(bw, "", []string{"url", "status", "redirect", "tls", "truncated"}, liveRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.LiveRecords), len(liveRows)); err != nil {
		return err
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Findings.
	if err := writeln("<details id=\"findings\" open><summary>Findings (%d)</summary>", len(m.Findings)); err != nil {
		return err
	}
	findingRows := make([][]string, 0, min(maxHTMLTableRows, len(m.Findings)))
	for _, f := range m.Findings {
		if len(findingRows) >= maxHTMLTableRows {
			break
		}
		findingRows = append(findingRows, []string{
			"@@PRIORITY@@" + f.Priority, f.RuleID, f.Category, f.Subject.String(), formatScore(f.Confidence), f.Status, formatTime(f.Created),
		})
	}
	if err := writeHTMLTable(bw, "findings", []string{"priority", "rule", "category", "subject", "confidence", "status", "created"}, findingRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.Findings), len(findingRows)); err != nil {
		return err
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Attack surface (groups, paths, recommendations).
	if err := writeln("<details id=\"attack-surface\" open><summary>Attack Surface (%d groups, %d paths)</summary>", len(m.Groups), len(m.AttackPaths)); err != nil {
		return err
	}
	if err := writeln("<p class=\"note\">Reconnaissance hypotheses and reading orders — never exploitation chains; recommendations are guidance language only.</p>"); err != nil {
		return err
	}
	groupRows := make([][]string, 0, min(maxHTMLTableRows, len(m.Groups)))
	for _, g := range m.Groups {
		if len(groupRows) >= maxHTMLTableRows {
			break
		}
		groupRows = append(groupRows, []string{g.Anchor.String(), formatScore(g.Score), string(g.Level), fmt.Sprintf("%d", len(g.Members))})
	}
	if err := writeHTMLTable(bw, "", []string{"group anchor", "score", "level", "members"}, groupRows); err != nil {
		return err
	}
	if err := writeHTMLTruncationNote(writeln, len(m.Groups), len(groupRows)); err != nil {
		return err
	}
	if len(m.AttackPaths) > 0 {
		if err := writeln("<h3>Attack paths</h3>"); err != nil {
			return err
		}
		shown := m.AttackPaths
		if len(shown) > maxHTMLTableRows {
			shown = shown[:maxHTMLTableRows]
		}
		for _, path := range shown {
			if err := writeln("<details class=\"path\"><summary>%s (score %s, %s)</summary>", esc(path.Root.String()), formatScore(path.Score), string(path.Level)); err != nil {
				return err
			}
			if err := writeln("<ul>"); err != nil {
				return err
			}
			for _, step := range path.Steps {
				if err := writeln("<li><code>%s</code> — %s</li>", esc(step.Identity.String()), esc(step.Reason)); err != nil {
					return err
				}
			}
			if err := writeln("</ul></details>"); err != nil {
				return err
			}
		}
		if err := writeHTMLTruncationNote(writeln, len(m.AttackPaths), len(shown)); err != nil {
			return err
		}
	}
	if len(m.Recommendations) > 0 {
		if err := writeln("<h3>Recommendations</h3>"); err != nil {
			return err
		}
		if err := writeln("<ul class=\"recommendations\">"); err != nil {
			return err
		}
		shownRecs := m.Recommendations
		if len(shownRecs) > maxHTMLTableRows {
			shownRecs = shownRecs[:maxHTMLTableRows]
		}
		for _, rec := range shownRecs {
			if err := writeln("<li><strong>%s</strong> (%s, weight %s): %s</li>", esc(rec.Surface.String()), esc(rec.Factor), formatScore(rec.Weight), esc(rec.Text)); err != nil {
				return err
			}
		}
		if err := writeln("</ul>"); err != nil {
			return err
		}
		if err := writeHTMLTruncationNote(writeln, len(m.Recommendations), len(shownRecs)); err != nil {
			return err
		}
	}
	if err := writeln("</details>"); err != nil {
		return err
	}

	// Errors.
	if err := writeln("<details id=\"errors\"><summary>Errors (%d total)</summary>", m.Errors.Total); err != nil {
		return err
	}
	if m.Errors.Total == 0 {
		if err := writeln("<p class=\"note\">No errors recorded for this run.</p>"); err != nil {
			return err
		}
	} else {
		errRows := make([][]string, 0, len(m.Errors.Categories))
		for _, cat := range m.Errors.Categories {
			errRows = append(errRows, []string{string(cat.Category), fmt.Sprintf("%d", cat.Total), fmt.Sprintf("%d", cat.Unique)})
		}
		if err := writeHTMLTable(bw, "", []string{"category", "total", "unique"}, errRows); err != nil {
			return err
		}
		for _, cat := range m.Errors.Categories {
			if err := writeln("<details class=\"error-cat\"><summary>%s (%d unique)</summary><ul>", esc(string(cat.Category)), cat.Unique); err != nil {
				return err
			}
			for _, sample := range cat.Samples {
				if err := writeln("<li><code>[%s]</code> %s (x%d)</li>", esc(sample.Stage), esc(sample.Message), sample.Count); err != nil {
					return err
				}
			}
			if cat.Unique > len(cat.Samples) {
				if err := writeln("<li>… and %d more</li>", cat.Unique-len(cat.Samples)); err != nil {
					return err
				}
			}
			if err := writeln("</ul></details>"); err != nil {
				return err
			}
		}
	}
	if err := writeln("</details>"); err != nil {
		return err
	}
	if err := writeln("</main>"); err != nil {
		return err
	}

	if err := writeln("<script>%s</script>", htmlScript); err != nil {
		return err
	}
	if err := writeln("</body>"); err != nil {
		return err
	}
	return writeln("</html>")
}

// writeHTMLTable writes one escaped table. When tableID is "findings", the
// first cell may carry the "@@PRIORITY@@<label>" marker, which is unwrapped
// into a data-priority attribute (the filter target) and rendered as the
// cell text.
func writeHTMLTable(bw *bufio.Writer, tableID string, headers []string, rows [][]string) error {
	attrs := ""
	if tableID != "" {
		attrs = fmt.Sprintf(" id=\"%s\"", html.EscapeString(tableID))
	}
	if _, err := fmt.Fprintf(bw, "<table%s>\n<thead><tr>", attrs); err != nil {
		return err
	}
	for _, h := range headers {
		if _, err := fmt.Fprintf(bw, "<th>%s</th>", html.EscapeString(h)); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("</tr></thead>\n<tbody>\n"); err != nil {
		return err
	}
	const priorityMarker = "@@PRIORITY@@"
	for _, row := range rows {
		rowAttrs := ""
		cells := row
		if len(row) > 0 && strings.HasPrefix(row[0], priorityMarker) {
			priority := row[0][len(priorityMarker):]
			rowAttrs = fmt.Sprintf(" data-priority=\"%s\"", html.EscapeString(priority))
			cells = append([]string{priority}, row[1:]...)
		}
		if _, err := fmt.Fprintf(bw, "<tr%s>", rowAttrs); err != nil {
			return err
		}
		for _, c := range cells {
			if _, err := fmt.Fprintf(bw, "<td>%s</td>", html.EscapeString(c)); err != nil {
				return err
			}
		}
		if _, err := bw.WriteString("</tr>\n"); err != nil {
			return err
		}
	}
	_, err := bw.WriteString("</tbody>\n</table>\n")
	return err
}

// writeHTMLTruncationNote writes the honest cut note when a table was
// capped.
func writeHTMLTruncationNote(writeln func(string, ...any) error, total, shown int) error {
	if total <= shown {
		return nil
	}
	return writeln("<p class=\"note\">Showing first %d of %d — the JSON and CSV exports carry the complete dataset.</p>", shown, total)
}

// findingPriorities returns the sorted distinct finding priorities in the
// model (the filter's options).
func findingPriorities(m *Model) []string {
	seen := make(map[string]struct{})
	for _, f := range m.Findings {
		seen[f.Priority] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// htmlCSS is the report's entire stylesheet (inline; no external
// resources).
const htmlCSS = `body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0 auto;max-width:1100px;padding:1rem;color:#1a1a2e;background:#fafafa}header{border-bottom:2px solid #4a4a6a;padding-bottom:1rem}h1{margin:0 0 .25rem;font-size:1.5rem}h2{font-size:1.15rem;border-bottom:1px solid #ddd;padding-bottom:.25rem}h3{font-size:1rem}code{background:#eee;padding:0 .25rem;border-radius:3px;word-break:break-all}.target,.digest{margin:.15rem 0}.note{color:#666;font-style:italic}table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #ddd;padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:#f0f0f5}tbody tr:nth-child(even){background:#f7f7fa}details{margin:.75rem 0}summary{cursor:pointer;font-weight:600;padding:.35rem 0}#raven-search,#raven-priority-filter{margin:.5rem .5rem .5rem 0;padding:.4rem}ul{margin:.25rem 0}.path ul{margin-left:1rem}`

// htmlScript is the report's entire script (inline vanilla JavaScript; no
// frameworks). It progressively enhances the static document with a global
// row filter and a finding-priority filter; without scripting every row
// stays visible.
const htmlScript = `(function(){
"use strict";
var search=document.getElementById("raven-search");
var priority=document.getElementById("raven-priority-filter");
function apply(){
  var q=(search&&search.value||"").toLowerCase();
  var p=priority&&priority.value||"all";
  var rows=document.querySelectorAll("tbody tr");
  for(var i=0;i<rows.length;i++){
    var row=rows[i];
    var matchesPriority=p==="all"||row.getAttribute("data-priority")===p;
    var matchesText=q===""||row.textContent.toLowerCase().indexOf(q)!==-1;
    row.style.display=(matchesPriority&&matchesText)?"":"none";
  }
}
if(search){search.addEventListener("input",apply);}
if(priority){priority.addEventListener("change",apply);}
})();`
