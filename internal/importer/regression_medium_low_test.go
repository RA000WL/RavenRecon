package importer

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// TestRegressionMEDIUM1_GzipBombCapped verifies that a gzip file whose
// decompressed payload exceeds effectiveMaxDecompressed (100 MiB default,
// overridden here to a small limit) aborts with Truncated=true instead of
// OOM. It uses a highly-compressible payload (repeated valid domains) so
// compressed size stays tiny while decompressed exceeds the cap.
func TestRegressionMEDIUM1_GzipBombCapped(t *testing.T) {
	dir := t.TempDir()
	// Small limit to trigger bomb without allocating 100 MiB in test.
	const maxDecomp = 64 * 1024 // 64 KiB
	path := filepath.Join(dir, "bomb.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gw := gzip.NewWriter(f)
	// Write 200 KiB of valid domains: each "example.com\n" = 12 bytes.
	// 20k lines ~ 240 KiB decompressed, but gzipped is ~ few KiB.
	const lines = 20000
	for i := 0; i < lines; i++ {
		if _, err := gw.Write([]byte("example.com\n")); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	f.Close()

	sink := NewSink()
	env := ImportEnv{
		Clock:  fixedClock(),
		Bounds: Bounds{MaxOutput: 100000, MaxDecompressedBytes: maxDecomp},
	}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated {
		t.Fatalf("gzip bomb should abort with Truncated=true when decompressed %d bytes > limit %d, got stats %+v", 240*1024, maxDecomp, stats)
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want import_truncated sticky flag")
	}
	// Must not have processed all lines; truncated early prevents OOM.
	if stats.ItemsProcessed >= lines {
		t.Fatalf("should have truncated early: processed %d, total %d", stats.ItemsProcessed, lines)
	}
	// Plain file exceeding same limit should also truncate (non-gzip).
	plainPath := filepath.Join(dir, "plain_big.txt")
	pf, _ := os.Create(plainPath)
	for i := 0; i < lines; i++ {
		pf.WriteString("example.com\n")
	}
	pf.Close()
	sink2 := NewSink()
	stats2, err := imp.Import(context.Background(), env, plainPath, sink2)
	if err != nil {
		t.Fatalf("plain Import: %v", err)
	}
	if !stats2.Truncated {
		t.Fatalf("plain file exceeding decompressed cap should also Truncated")
	}
}

// TestRegressionMEDIUM1_MaxDecompressedBytesInCacheKey ensures the new
// max_decompressed_bytes config participates in the cache key and defaults
// to 100 MiB (104857600).
func TestRegressionMEDIUM1_MaxDecompressedBytesInCacheKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	imp := NewPlainDomainsImporter()
	b1 := Bounds{MaxOutput: 100000, MaxDecompressedBytes: 64 * 1024}
	b2 := Bounds{MaxOutput: 100000, MaxDecompressedBytes: 128 * 1024}
	p1, err := CacheKeyForFile(path, imp, b1)
	if err != nil {
		t.Fatalf("key1: %v", err)
	}
	p2, err := CacheKeyForFile(path, imp, b2)
	if err != nil {
		t.Fatalf("key2: %v", err)
	}
	if _, ok := p1.Config["max_decompressed_bytes"]; !ok {
		t.Fatalf("Config missing max_decompressed_bytes")
	}
	if p1.Config["max_decompressed_bytes"] == p2.Config["max_decompressed_bytes"] {
		t.Fatalf("different MaxDecompressedBytes should give different config: %s vs %s", p1.Config["max_decompressed_bytes"], p2.Config["max_decompressed_bytes"])
	}
	k1, _ := cache.NewKey(cache.KeyParts{Operation: p1.Operation, Target: p1.Target, Config: p1.Config, Tool: cache.ToolInfo{Name: p1.ToolName, Version: p1.ToolVersion}})
	k2, _ := cache.NewKey(cache.KeyParts{Operation: p2.Operation, Target: p2.Target, Config: p2.Config, Tool: cache.ToolInfo{Name: p2.ToolName, Version: p2.ToolVersion}})
	if k1 == k2 {
		t.Fatalf("different MaxDecompressedBytes should give different cache keys")
	}
	// Default resolves to 100 MiB.
	bDef := Bounds{MaxOutput: 100000}
	pDef, _ := CacheKeyForFile(path, imp, bDef)
	if pDef.Config["max_decompressed_bytes"] != "104857600" {
		t.Fatalf("default MaxDecompressedBytes should be 104857600 (100 MiB), got %s", pDef.Config["max_decompressed_bytes"])
	}
}

// TestRegressionMEDIUM2_ScannerForRemoved verifies dead code was removed:
// scannerFor no longer exists and streaming uses ReadSlice with 8 KiB buffer.
// We verify indirectly: doc.go must mention ReadSlice/8 KiB and not the old
// Scanner 32 KiB phrasing, and bounded line behavior still works.
func TestRegressionMEDIUM2_ScannerForRemoved(t *testing.T) {
	// Verify bounded line still enforced via readLines/ReadSlice after removal.
	dir := t.TempDir()
	line := strings.Repeat("a", 9000) // >8192
	content := "example.com\n" + line + "\napi.example.com\n"
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 8 * 1024}}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated || stats.ItemsFailed != 1 {
		t.Fatalf("8KiB limit should truncate 9000-byte line after scannerFor removal: truncated %v failed %d", stats.Truncated, stats.ItemsFailed)
	}
	// Also verify doc.go updated and scannerFor dead code removed.
	candidatesDoc := []string{"doc.go", "internal/importer/doc.go", filepath.Join("..", "importer", "doc.go")}
	var doc string
	found := false
	for _, cand := range candidatesDoc {
		if b, err := os.ReadFile(cand); err == nil {
			doc = string(b)
			found = true
			break
		}
	}
	if !found {
		// Try absolute via runtime caller dir fallback: search relative to this file's dir via TempDir check
		// If still not found, fail explicitly instead of skip so dead-code removal is enforced.
		t.Fatalf("cannot locate doc.go for verification (tried %v)", candidatesDoc)
	}
	if strings.Contains(doc, "Scanner with Buffer 32 KiB") {
		t.Fatalf("doc.go still mentions old 'Scanner with Buffer 32 KiB' after dead code removal; should mention ReadSlice 8 KiB")
	}
	if !strings.Contains(doc, "ReadSlice") || !strings.Contains(doc, "8 KiB") {
		t.Fatalf("doc.go should document ReadSlice with 8 KiB buffer after fix, got %q", doc)
	}
	if !strings.Contains(doc, "max_decompressed_bytes") {
		t.Fatalf("doc.go should document max_decompressed_bytes after MEDIUM1 fix")
	}
	// Verify reader.go no longer contains scannerFor.
	candidatesReader := []string{"reader.go", "internal/importer/reader.go", filepath.Join("..", "importer", "reader.go")}
	var rdr string
	found = false
	for _, cand := range candidatesReader {
		if b, err := os.ReadFile(cand); err == nil {
			rdr = string(b)
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("cannot locate reader.go for dead-code check")
	}
	if strings.Contains(rdr, "func scannerFor") {
		t.Fatalf("reader.go still contains dead code func scannerFor; should be removed")
	}
	if strings.Contains(rdr, "scannerFor") {
		t.Fatalf("reader.go still references scannerFor; dead code not fully removed")
	}
}

// TestRegressionLOW_ErrorRedaction verifies errors from readLines do not leak
// full filesystem path: only Base appears, not the full temp dir.
func TestRegressionLOW_ErrorRedaction(t *testing.T) {
	dir := t.TempDir()
	// Nested path to ensure leak would be obvious.
	nested := filepath.Join(dir, "secret", "subdir")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	missing := filepath.Join(nested, "missing.txt")
	// Ensure file does not exist.
	os.Remove(missing)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewPlainDomainsImporter()
	_, err := imp.Import(context.Background(), env, missing, sink)
	if err == nil {
		t.Fatalf("want open error for missing file")
	}
	msg := err.Error()
	base := filepath.Base(missing) // "missing.txt"
	if !strings.Contains(msg, base) {
		t.Fatalf("error should contain base %q, got %q", base, msg)
	}
	// Full path must not appear (redacted to base). Check that the temp dir
	// or nested path does not appear verbatim.
	if strings.Contains(msg, nested) {
		t.Fatalf("error leaks full path %q in %q (should only contain base)", nested, msg)
	}
	if strings.Contains(msg, dir) {
		t.Fatalf("error leaks full dir %q in %q", dir, msg)
	}
	// Also ensure the old format "open <fullpath>:" is gone.
	if strings.Contains(msg, "open "+missing) {
		t.Fatalf("error still contains old 'open <fullpath>' format: %q", msg)
	}
	// Underlying cause should still be unwrappable (e.g., os.ErrNotExist)
	if !strings.Contains(msg, "open") {
		t.Fatalf("error should mention open op: %q", msg)
	}
}
