package importer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRegressionMED_JSONArrayHugeElementBoundedHeap verifies the MEDIUM
// finding: a single huge JSON array element (12 MiB vs 32 KiB per-record cap)
// is counted failed+truncated with handle never called, WITHOUT materializing
// the element in memory. The heap delta must stay under 5 MiB — proving the
// bound applies during framing, not after an unbounded dec.Decode.
func TestRegressionMED_JSONArrayHugeElementBoundedHeap(t *testing.T) {
	if isRaceEnabled() {
		t.Skip("heap guard unreliable under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "huge_element.json")

	// 12 MiB single array element: {"url":"https://example.com/a","body":"xxxx..."}
	const hugeSize = 12 << 20
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.WriteString(`[{"url":"https://example.com/a","body":"`); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	const chunk = 8192
	chunkStr := strings.Repeat("x", chunk)
	for written := 0; written < hugeSize; written += chunk {
		if _, err := f.WriteString(chunkStr); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
	}
	if _, err := f.WriteString(`"}]`); err != nil {
		t.Fatalf("write suffix: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)
	var delta uint64
	if m2.HeapInuse > m1.HeapInuse {
		delta = m2.HeapInuse - m1.HeapInuse
	}
	if delta > 5<<20 {
		t.Fatalf("unbounded decode: heap delta %d bytes (> 5 MiB) for 12 MiB element", delta)
	}

	if stats.ItemsFailed != 1 {
		t.Fatalf("want failed=1 for oversized element, got failed=%d processed=%d", stats.ItemsFailed, stats.ItemsProcessed)
	}
	if stats.ItemsProcessed != 0 {
		t.Fatalf("oversized element must not be processed/handled, got processed=%d", stats.ItemsProcessed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated=true for oversized element")
	}
	if !stats.StickyFlags["import_truncated"] {
		t.Fatalf("want StickyFlags[import_truncated]=true, got %v", stats.StickyFlags)
	}
	if len(sink.URLs) != 0 {
		t.Fatalf("oversized element must not be stored, got %d urls", len(sink.URLs))
	}
}

// TestRegressionMED_JSONArrayFramerResyncAfterHuge ensures that after an
// oversized element the framer resumes cleanly on the next element: valid
// elements surrounding the huge one are still processed, brackets/commas
// inside string values do not desynchronize framing, and nested elements are
// framed intact.
func TestRegressionMED_JSONArrayFramerResyncAfterHuge(t *testing.T) {
	dir := t.TempDir()

	huge := strings.Repeat("q", 40*1024)
	// Element 3 exercises escape awareness (\\" in file = escaped quote inside
	// a JSON string); element 4 exercises nesting + comma-inside-string.
	content := `[` +
		`{"url":"https://example.com/first","status_code":200},` +
		`{"url":"https://example.com/huge","body":"` + huge + `"},` +
		`{"url":"https://example.com/x,\"quoted\",path","status_code":201},` +
		`{"url":"https://example.com/nested","tags":["a,b",["deep"]],"status_code":202},` +
		`{"url":"https://example.com/last","status_code":203}` +
		`]`
	path := filepath.Join(dir, "resync.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want exactly 1 failed (the huge element), got failed=%d processed=%d", stats.ItemsFailed, stats.ItemsProcessed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated=true")
	}
	if stats.ItemsProcessed != 4 {
		t.Fatalf("want 4 processed after resync, got %d", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 4 {
		t.Fatalf("want 4 urls stored after resync, got %d", len(sink.URLs))
	}
}

// TestRegressionMED_JSONArrayTruncatedMidElement verifies honest truncation
// accounting when the file ends inside an element (no closing bracket): the
// partial element is counted failed+truncated rather than silently dropped.
func TestRegressionMED_JSONArrayTruncatedMidElement(t *testing.T) {
	dir := t.TempDir()
	content := `[{"url":"https://example.com/good"},{"url":"https://example.com/cut","bo`
	path := filepath.Join(dir, "midcut.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 1 {
		t.Fatalf("want 1 processed (good), got %d", stats.ItemsProcessed)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed (cut element), got failed=%d", stats.ItemsFailed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated=true for EOF mid-element")
	}
}

// TestRegressionMED_JSONArraySmallCapStillFramed verifies small-array parity:
// plain scalar arrays and empty arrays still behave (no crash, no spurious
// failures) after the framer switch.
func TestRegressionMED_JSONArraySmallCapStillFramed(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty array", func(t *testing.T) {
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte(`[]`), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
		stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 0 || stats.ItemsFailed != 0 {
			t.Fatalf("empty array: want 0/0, got %+v", stats)
		}
	})

	t.Run("scalar elements fail honestly not crash", func(t *testing.T) {
		path := filepath.Join(dir, "scalars.json")
		if err := os.WriteFile(path, []byte(`["https://example.com/s1"]`), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
		stats, err := NewJSONGenericImporter().Import(context.Background(), env, path, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		// Generic importer treats bare URL strings as URLs.
		if stats.ItemsProcessed != 1 || len(sink.URLs) != 1 {
			t.Fatalf("scalar url string should process via generic, got processed=%d urls=%d failed=%d", stats.ItemsProcessed, len(sink.URLs), stats.ItemsFailed)
		}
	})
}

// TestRegressionMED_JSONArrayCommaPaddingCapped reproduces the MEDIUM finding:
// "[" + 8 MiB of "," + a tiny element + "]" with MaxDecompressedBytes 64 KiB.
// Previously only retained element bytes plus oversized framer totals were
// tallied, so bytes BETWEEN elements (commas, whitespace, brackets) escaped
// the decompressed cap entirely: the import completed with Truncated=false.
// Now the cumulative framer tally counts every consumed byte, so the padding
// trips the cap and the import aborts honestly truncated before the element
// is handled.
func TestRegressionMED_JSONArrayCommaPaddingCapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comma_padding.json")

	content := "[" + strings.Repeat(",", 8<<20) + `{"url":"https://example.com/padded"}]`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxDecompressedBytes: 64 * 1024}}
	stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated=true: 8 MiB inter-element commas exceed the 64 KiB decompressed cap")
	}
	if !stats.StickyFlags["import_truncated"] {
		t.Fatalf("want StickyFlags[import_truncated]=true, got %v", stats.StickyFlags)
	}
	if stats.ItemsProcessed != 0 || len(sink.URLs) != 0 {
		t.Fatalf("cap must abort before handling the trailing element, got processed=%d urls=%d", stats.ItemsProcessed, len(sink.URLs))
	}
	if stats.ItemsFailed != 0 {
		t.Fatalf("cap abort is a tail-drop, not failures, got failed=%d", stats.ItemsFailed)
	}
}

// TestRegressionMED_JSONArraySmallPaddingStillProcessed guards the fix against
// over-truncation: inter-element separators are tallied exactly, so arrays
// whose TOTAL size fits the cap keep processing normally despite padding.
func TestRegressionMED_JSONArraySmallPaddingStillProcessed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small_padding.json")

	// Whitespace/newline-padded pretty-printed array (~4 KiB total), cap 8 KiB.
	pad := "\n  "
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 32; i++ {
		b.WriteString(pad)
		b.WriteString(fmt.Sprintf(`{"url":"https://example.com/%d"}`, i))
		b.WriteString(",")
	}
	b.WriteString(pad)
	b.WriteString(`{"url":"https://example.com/last"}`)
	b.WriteString("\n]")
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxDecompressedBytes: 8 * 1024}}
	stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Truncated {
		t.Fatalf("total size fits the 8 KiB cap, want Truncated=false, got %+v", stats)
	}
	if stats.ItemsProcessed != 33 || len(sink.URLs) != 33 {
		t.Fatalf("want 33 processed/33 urls under the cap, got processed=%d urls=%d failed=%d", stats.ItemsProcessed, len(sink.URLs), stats.ItemsFailed)
	}
}

// TestINFO_JSONArrayBOMAndDeepNesting covers committed cheap cases: UTF-8 BOM
// before the opening bracket must not break detection/framing/tallying, and
// deeply nested structures inside an element must frame intact via the
// depth-aware state machine.
func TestINFO_JSONArrayBOMAndDeepNesting(t *testing.T) {
	dir := t.TempDir()

	t.Run("BOM prefixed array", func(t *testing.T) {
		path := filepath.Join(dir, "bom_array.json")
		content := "\xef\xbb\xbf[" +
			`{"url":"https://example.com/bom1","status_code":200},` + "\n\t" +
			`{"url":"https://example.com/bom2","status_code":201}` +
			"\n]"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
		stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 2 || len(sink.URLs) != 2 {
			t.Fatalf("BOM-prefixed array: want 2 processed/2 urls, got processed=%d urls=%d failed=%d truncated=%v", stats.ItemsProcessed, len(sink.URLs), stats.ItemsFailed, stats.Truncated)
		}
	})

	t.Run("deep nesting frames intact", func(t *testing.T) {
		const depth = 128
		path := filepath.Join(dir, "deep_nesting.json")
		nested := strings.Repeat("[", depth) + `"leaf"` + strings.Repeat("]", depth)
		content := `[{"url":"https://example.com/deep","tags":` + nested + `,"status_code":200}]`
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
		stats, err := NewJSONHttpxImporter().Import(context.Background(), env, path, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsFailed != 0 {
			t.Fatalf("depth-%d element must frame intact, got failed=%d truncated=%v", depth, stats.ItemsFailed, stats.Truncated)
		}
		if stats.ItemsProcessed != 1 || len(sink.URLs) != 1 {
			t.Fatalf("depth-%d element: want 1 processed/1 url, got processed=%d urls=%d", depth, stats.ItemsProcessed, len(sink.URLs))
		}
	})
}

// TestLOW_DnsxDuplicateHostAccounting pins honest dedup accounting for the
// dnsx importer: a record whose host is a duplicate must count as processed
// only when it actually appended at least one NEW IP asset. Records listing
// only already-seen IPs are duplicates (neither processed nor failed), not
// phantom-processed.
func TestLOW_DnsxDuplicateHostAccounting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsx_dup_host.json")

	content := "" +
		`{"host":"a.example.com","a":["1.2.3.4"]}` + "\n" + // fresh host+ip → processed
		`{"host":"a.example.com","a":["1.2.3.4"]}` + "\n" + // dup host, dup ip → duplicate
		`{"host":"a.example.com","a":["9.9.9.9"]}` + "\n" + // dup host, NEW ip → processed
		`{"host":"a.example.com","aaaa":["2001:db8::1"],"a":["1.2.3.4"]}` + "\n" + // dup host, new AAAA ip → processed
		`{"host":"a.example.com","a":["1.2.3.4","9.9.9.9"]}` + "\n" + // dup host, all ips seen → duplicate
		`{"host":"a.example.com"}` + "\n" // dup host, no ips → duplicate
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
	stats, err := NewJSONDnsxImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	// Records 1, 3, 4 store something (host once, then two more IPs);
	// records 2, 5, 6 store nothing and must NOT count as processed.
	if stats.ItemsProcessed != 3 {
		t.Fatalf("want processed=3 (records storing new assets), got processed=%d failed=%d", stats.ItemsProcessed, stats.ItemsFailed)
	}
	if stats.ItemsFailed != 0 {
		t.Fatalf("duplicates are neither processed nor failed, got failed=%d", stats.ItemsFailed)
	}
	if len(sink.Hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(sink.Hosts))
	}
	if len(sink.IPs) != 3 {
		t.Fatalf("want 3 distinct ips (1.2.3.4, 9.9.9.9, 2001:db8::1), got %d", len(sink.IPs))
	}
}
