package report

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
)

// The CSV export's datasets: one table per part, in the fixed (part name
// sorted) render order. Every table carries a header row even when empty,
// so consumers always have the schema.
var csvParts = []string{"endpoints", "findings", "hosts", "secrets", "technologies", "urls"}

// renderCSV streams one CSV table per dataset. Fields are written through
// the stdlib csv.Writer (correct quoting for every byte, UTF-8 preserved,
// no BOM); every field additionally passes csvSafe, which neutralizes
// spreadsheet formula injection. The complete, unmodified data lives in the
// JSON export.
func renderCSV(ctx context.Context, m *Model, s Sink) error {
	for _, part := range csvParts {
		if err := ctx.Err(); err != nil {
			return err
		}
		w, err := s.Writer(part)
		if err != nil {
			return err
		}
		if err := writeCSVTable(ctx, m, part, w); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("report: csv %s: %w", part, err)
		}
	}
	return nil
}

// writeCSVTable renders one dataset table, honoring cancellation between
// rows.
func writeCSVTable(ctx context.Context, m *Model, part string, w io.Writer) error {
	cw := csv.NewWriter(w)
	var writeErr error
	writeRecord := func(record []string) {
		if writeErr != nil {
			return
		}
		if err := ctx.Err(); err != nil {
			writeErr = err
			return
		}
		writeErr = cw.Write(csvRow(record))
	}

	switch part {
	case "hosts":
		writeRecord([]string{"host", "source", "discovered_at"})
		for _, h := range m.Hosts {
			writeRecord([]string{h.Name, h.Prov.Source, formatTime(h.Prov.DiscoveredAt)})
		}
	case "urls":
		writeRecord([]string{"url", "scheme", "hostport", "path", "query", "source", "discovered_at"})
		for _, u := range m.URLs {
			writeRecord([]string{u.String(), u.Scheme, u.HostPort, u.Path, u.Query, u.Prov.Source, formatTime(u.Prov.DiscoveredAt)})
		}
	case "endpoints":
		writeRecord([]string{"method", "url", "source", "discovered_at"})
		for _, ep := range m.Endpoints {
			writeRecord([]string{ep.Method, ep.URL.String(), ep.Prov.Source, formatTime(ep.Prov.DiscoveredAt)})
		}
	case "technologies":
		writeRecord([]string{"name", "category", "version", "confidence", "source", "discovered_at"})
		for _, t := range m.Technologies {
			writeRecord([]string{t.Name, string(t.Category), t.Version, conf(t.Prov.Confidence), t.Prov.Source, formatTime(t.Prov.DiscoveredAt)})
		}
	case "secrets":
		writeRecord([]string{"type", "value", "source_asset", "confidence", "discovered_at"})
		for _, sec := range m.Secrets {
			writeRecord([]string{string(sec.Type), sec.Value, sec.Source.String(), conf(sec.Prov.Confidence), formatTime(sec.Prov.DiscoveredAt)})
		}
	case "findings":
		writeRecord([]string{"finding", "rule_id", "rule_name", "category", "subject", "confidence", "priority", "status", "created_at"})
		for _, f := range m.Findings {
			writeRecord([]string{f.Identity().String(), f.RuleID, f.RuleName, f.Category, f.Subject.String(), formatScore(f.Confidence), f.Priority, f.Status, formatTime(f.Created)})
		}
	default:
		return fmt.Errorf("report: csv: unknown part %q", part)
	}
	if writeErr != nil {
		return fmt.Errorf("report: csv %s: %w", part, writeErr)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("report: csv %s: %w", part, err)
	}
	return nil
}
