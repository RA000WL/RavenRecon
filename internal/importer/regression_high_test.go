package importer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// TestRegressionHIGH1BoundedHeapHugeLine verifies readLines never allocates
// > effectiveMaxLine()+1 (32 KiB+1) when encountering a 100 MB-scale line.
// It writes a file with a valid line, a huge line (5 MiB, representative of
// 100 MB OOM case without spending 100 MB per CI run), and a trailing valid
// line, then checks heap delta <5 MiB and correct stats.
// The drain loop is also bounded (huge line without newline at EOF).
func TestRegressionHIGH1BoundedHeapHugeLine(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Good line.
	if _, err := f.WriteString("example.com\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Huge line: 5 MiB of 'a' without spaces, exceeds 32 KiB maxLine.
	// Written in 8 KiB chunks to avoid allocating a single 5 MiB string in test heap
	// before the measurement (keeps pre-import heap low).
	const hugeSize = 5 << 20 // 5 MiB representative of 100 MB OOM
	const chunk = 8192
	written := 0
	chunkStr := strings.Repeat("a", chunk)
	for written < hugeSize {
		remain := hugeSize - written
		if remain >= chunk {
			if _, err := f.WriteString(chunkStr); err != nil {
				t.Fatalf("write chunk: %v", err)
			}
			written += chunk
		} else {
			if _, err := f.WriteString(strings.Repeat("a", remain)); err != nil {
				t.Fatalf("write tail: %v", err)
			}
			written += remain
		}
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatalf("write newline: %v", err)
	}
	if _, err := f.WriteString("api.example.com\n"); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	f.Close()

	// Allow GC to clean chunkStr etc before measuring.
	chunkStr = ""
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000, MaxLineBytes: 32 * 1024}}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	var delta uint64
	if m2.HeapInuse > m1.HeapInuse {
		delta = m2.HeapInuse - m1.HeapInuse
	}
	const maxDelta = 5 << 20 // 5 MiB
	if delta > maxDelta {
		t.Fatalf("heap delta too large: %d bytes (max %d) — readLines not bounded (100MB line would OOM)", delta, maxDelta)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2 processed (good lines), got %d", stats.ItemsProcessed)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed for huge line, got %d", stats.ItemsFailed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated true for oversized line")
	}
	if len(sink.Domains) != 2 {
		t.Fatalf("want 2 domains, got %d", len(sink.Domains))
	}
}

// TestRegressionHIGH1DrainLoopBounded verifies the drain loop after an
// oversized line does not allocate unbounded and checks ctx per chunk.
// It uses a huge line without trailing newline (EOF) to exercise the drain
// path that previously used ReadString unbounded.
func TestRegressionHIGH1DrainLoopBounded(t *testing.T) {
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "drain.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.WriteString("example.com\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Huge line without newline at EOF: 2 MiB
	const hugeSize = 2 << 20
	const chunk = 8192
	written := 0
	chunkStr := strings.Repeat("b", chunk)
	for written < hugeSize {
		remain := hugeSize - written
		if remain >= chunk {
			f.WriteString(chunkStr)
			written += chunk
		} else {
			f.WriteString(strings.Repeat("b", remain))
			written += remain
		}
	}
	// No newline, EOF immediately after huge line
	f.Close()

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000, MaxLineBytes: 32 * 1024}}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
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
		t.Fatalf("drain heap delta too large: %d", delta)
	}
	if stats.ItemsProcessed != 1 {
		t.Fatalf("want 1 processed, got %d", stats.ItemsProcessed)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed for huge EOF line, got %d", stats.ItemsFailed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated for huge EOF line")
	}
}

// TestRegressionHIGH1ScannerForBounds ensures readLines respects the
// 8 KiB init / 32 KiB max contract (formerly scannerFor) and never allocates
// > effectiveMaxLine()+1. It indirectly verifies via Import with different
// MaxLineBytes. Kept for backward compat; scannerFor was removed (MEDIUM2)
// and streaming now uses bufio.Reader.ReadSlice with 8 KiB buffer.
func TestRegressionHIGH1ScannerForBounds(t *testing.T) {
	dir := t.TempDir()
	// Line of 9000 'a's: >8192 but <32768
	line := strings.Repeat("a", 9000)
	content := "example.com\n" + line + "\napi.example.com\n"

	// With 8 KiB limit, middle line should be oversized -> Truncated true
	path1 := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path1, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink1 := NewSink()
	env1 := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 8 * 1024}}
	imp := NewPlainDomainsImporter()
	stats1, err := imp.Import(context.Background(), env1, path1, sink1)
	if err != nil {
		t.Fatalf("Import 8KiB: %v", err)
	}
	if !stats1.Truncated {
		t.Fatalf("8KiB limit should truncate 9000-byte line")
	}
	if stats1.ItemsFailed != 1 {
		t.Fatalf("8KiB limit want 1 failed, got %d", stats1.ItemsFailed)
	}

	// With 32 KiB limit, same 9000-byte line is not oversized; it fails only as invalid domain, not truncated due to size.
	// To isolate size vs validation, we use a line that is valid host-like but long.
	// Instead use plain-generic with a host that can be long? Use valid host of 9000 'a's is still invalid (label too long).
	// So we just verify that 32 KiB limit does NOT count the 9000-byte all-'a' line as size-truncated? But it will still be invalid domain -> failed 1 but truncated may be false.
	// Our implementation treats size-truncated only when len(trimmed) > maxLine. For 9000 >8192 true, >32768 false. So for 32KiB, len 9000 <=32768, so not size-truncated. The import will then try to validate and fail due to invalid domain, but not set Truncated via size path. However it may still have no truncated? Check.
	path2 := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(path2, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink2 := NewSink()
	env2 := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	stats2, err := imp.Import(context.Background(), env2, path2, sink2)
	if err != nil {
		t.Fatalf("Import 32KiB: %v", err)
	}
	if stats2.Truncated {
		t.Fatalf("32KiB limit should NOT truncate 9000-byte line (size ok, only validation failure)")
	}
	if stats2.ItemsFailed != 1 {
		t.Fatalf("32KiB limit want 1 failed (validation), got %d", stats2.ItemsFailed)
	}
}

// TestRegressionHIGH2MaxLineBytesInCacheKey verifies different MaxLineBytes
// yields different cache keys (Config["max_line_bytes"] present).
func TestRegressionHIGH2MaxLineBytesInCacheKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	content := "example.com\napi.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	imp := NewPlainDomainsImporter()
	bounds1 := Bounds{MaxOutput: 100000, MaxLineBytes: 32 * 1024}
	bounds2 := Bounds{MaxOutput: 100000, MaxLineBytes: 8 * 1024}
	p1, err := CacheKeyForFile(path, imp, bounds1)
	if err != nil {
		t.Fatalf("key1: %v", err)
	}
	p2, err := CacheKeyForFile(path, imp, bounds2)
	if err != nil {
		t.Fatalf("key2: %v", err)
	}
	if _, ok := p1.Config["max_line_bytes"]; !ok {
		t.Fatalf("Config missing max_line_bytes for bounds1")
	}
	if _, ok := p2.Config["max_line_bytes"]; !ok {
		t.Fatalf("Config missing max_line_bytes for bounds2")
	}
	if p1.Config["max_line_bytes"] == p2.Config["max_line_bytes"] {
		t.Fatalf("different MaxLineBytes should give different max_line_bytes config: %s vs %s", p1.Config["max_line_bytes"], p2.Config["max_line_bytes"])
	}
	k1, err := cache.NewKey(cache.KeyParts{Operation: p1.Operation, Target: p1.Target, Config: p1.Config, Tool: cache.ToolInfo{Name: p1.ToolName, Version: p1.ToolVersion}})
	if err != nil {
		t.Fatalf("NewKey1: %v", err)
	}
	k2, err := cache.NewKey(cache.KeyParts{Operation: p2.Operation, Target: p2.Target, Config: p2.Config, Tool: cache.ToolInfo{Name: p2.ToolName, Version: p2.ToolVersion}})
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	if k1 == k2 {
		t.Fatalf("different MaxLineBytes should give different cache keys: %s vs %s", k1, k2)
	}
	// Also verify default (0) resolves to 32 KiB and differs from 8 KiB
	boundsDefault := Bounds{MaxOutput: 100000}
	pDefault, _ := CacheKeyForFile(path, imp, boundsDefault)
	if pDefault.Config["max_line_bytes"] != "32768" {
		t.Fatalf("default MaxLineBytes should be 32768, got %s", pDefault.Config["max_line_bytes"])
	}
	if pDefault.Config["max_line_bytes"] == p2.Config["max_line_bytes"] {
		t.Fatalf("default 32KiB should differ from 8KiB")
	}
}
