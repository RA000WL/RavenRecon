package importer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegressionMEDIUM_JSONArrayHugeValueBounded verifies that a single huge
// JSON array element (> effectiveMaxLine / MaxLineBytes) is counted as
// failed+truncated instead of being processed unbounded (OOM path).
// Mirrors readLines oversized drain semantics for NDJSON: NDJSON oversized
// lines are failed+truncated without calling handle. Array mode previously
// called dec.Decode(&RawMessage) and then handled the value unconditionally,
// violating the per-record 32 KiB bound.
func TestRegressionMEDIUM_JSONArrayHugeValueBounded(t *testing.T) {
	dir := t.TempDir()

	// Single huge array value ~50 KiB field, well above default 32 KiB bound.
	hugePad := strings.Repeat("x", 50*1024)
	content := `[{"url":"https://example.com/a","body":"` + hugePad + `"}]`
	path := filepath.Join(dir, "huge_array.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("huge array value should be failed=1, got failed=%d processed=%d", stats.ItemsFailed, stats.ItemsProcessed)
	}
	if !stats.Truncated {
		t.Fatalf("huge array value should set Truncated=true")
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want StickyFlags import_truncated=true, got %v", stats.StickyFlags)
	}
	if stats.ItemsProcessed != 0 {
		t.Fatalf("huge array value should not be processed, got processed=%d", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 0 {
		t.Fatalf("huge array value should not be stored, got %d urls", len(sink.URLs))
	}
}

// TestRegressionMEDIUM_JSONArrayHugeValueMixed ensures a huge element is
// skipped but surrounding valid elements are still processed.
func TestRegressionMEDIUM_JSONArrayHugeValueMixed(t *testing.T) {
	dir := t.TempDir()
	hugePad := strings.Repeat("y", 50*1024)
	// Array with valid, huge, valid
	content := `[{"url":"https://example.com/good1","status_code":200},{"url":"https://example.com/huge","body":"` + hugePad + `"},` +
		`{"url":"https://example.com/good2","status_code":200}]`
	path := filepath.Join(dir, "mixed_array.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed (huge), got %d failed %d processed", stats.ItemsFailed, stats.ItemsProcessed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated for huge element")
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want import_truncated sticky")
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2 processed, got %d", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 2 {
		t.Fatalf("want 2 urls stored, got %d", len(sink.URLs))
	}
}

// TestRegressionMEDIUM_JSONArrayHugeValueBounded_CustomBound verifies the
// bound respects custom MaxLineBytes (e.g., 8 KiB) rather than only default.
func TestRegressionMEDIUM_JSONArrayHugeValueCustomBound(t *testing.T) {
	dir := t.TempDir()
	// With 8 KiB bound, a 9 KiB value should be oversized.
	hugePad := strings.Repeat("z", 9*1024)
	content := `[{"url":"https://example.com/a","body":"` + hugePad + `"}]`
	path := filepath.Join(dir, "custom_bound.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 8 * 1024}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsFailed != 1 || !stats.Truncated {
		t.Fatalf("custom 8KiB bound: want failed=1 truncated=true, got failed=%d truncated=%v", stats.ItemsFailed, stats.Truncated)
	}
	if len(sink.URLs) != 0 {
		t.Fatalf("should not store oversized with custom bound")
	}
}
