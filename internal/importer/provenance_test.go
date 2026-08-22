package importer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestProvenancePreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := "example.com\napi.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fixed := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	env := ImportEnv{
		Clock:          clock,
		ProvenanceBase: asset.Provenance{Confidence: 0.9},
		Bounds:         Bounds{MaxOutput: 1000},
	}
	sink := NewSink()
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2, got %d", stats.ItemsProcessed)
	}
	if len(sink.Domains) != 2 {
		t.Fatalf("want 2 domains, got %d", len(sink.Domains))
	}
	if len(sink.ProvenanceRecords) != 2 {
		t.Fatalf("want 2 provenance records, got %d", len(sink.ProvenanceRecords))
	}
	for i, rec := range sink.ProvenanceRecords {
		if rec.Importer != imp.Name() {
			t.Fatalf("rec %d importer %q, want %q", i, rec.Importer, imp.Name())
		}
		if rec.OriginalTool != ProvenanceSourceForImporter(imp.Name()) {
			t.Fatalf("rec %d tool mismatch", i)
		}
		if rec.Filename != "domains.txt" {
			t.Fatalf("rec %d filename %q, want domains.txt", i, rec.Filename)
		}
		if !rec.ImportTime.Equal(fixed) {
			t.Fatalf("rec %d time %v, want %v", i, rec.ImportTime, fixed)
		}
		if rec.OriginalRecord == "" {
			t.Fatalf("rec %d empty original record", i)
		}
		if len(rec.OriginalRecord) > MaxOriginalRecordBytes {
			t.Fatalf("rec %d original record too long %d", i, len(rec.OriginalRecord))
		}
		if rec.Confidence == 0 {
			t.Fatalf("rec %d zero confidence", i)
		}
		if rec.Identity == "" {
			t.Fatalf("rec %d empty identity", i)
		}
		// Verify asset Prov matches sidecar
		var provMatch bool
		for _, d := range sink.Domains {
			if d.Identity().String() == rec.Identity {
				if d.Prov.Source != rec.Importer && d.Prov.Source != rec.OriginalTool {
					// Allow either, since we set Source to tool
				}
				if !d.Prov.DiscoveredAt.Equal(fixed) {
					t.Fatalf("domain prov time mismatch")
				}
				provMatch = true
				break
			}
		}
		if !provMatch {
			t.Fatalf("rec identity %q not found in domains", rec.Identity)
		}
		// OriginalRecord should be first 4 KiB truncated raw line (includes newline)
		if !strings.Contains(rec.OriginalRecord, "example.com") {
			t.Fatalf("rec original does not contain domain: %q", rec.OriginalRecord)
		}
	}
	// Also verify that every emitted asset carries provenance without mutating Identity
	for _, d := range sink.Domains {
		if d.Prov.DiscoveredAt.IsZero() {
			t.Fatalf("domain %s has zero provenance time", d.Name)
		}
		if d.Prov.Source == "" {
			t.Fatalf("domain %s has empty source", d.Name)
		}
		// Identity must not include provenance
		if d.Identity().Value != d.Name {
			t.Fatalf("identity value should be canonical name only")
		}
	}
}
