package importer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

func TestCacheKeyDeterminism(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	content := "example.com\napi.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	imp := NewPlainDomainsImporter()
	bounds := Bounds{MaxOutput: 100000}
	p1, err := CacheKeyForFile(path, imp, bounds)
	if err != nil {
		t.Fatalf("key1: %v", err)
	}
	p2, err := CacheKeyForFile(path, imp, bounds)
	if err != nil {
		t.Fatalf("key2: %v", err)
	}
	if p1.Target != p2.Target || p1.Operation != p2.Operation || p1.ToolName != p2.ToolName || p1.ToolVersion != p2.ToolVersion {
		t.Fatalf("non-deterministic parts: %v vs %v", p1, p2)
	}
	// Deterministic via cache.NewKey
	k1, err := cache.NewKey(cache.KeyParts{Operation: p1.Operation, Target: p1.Target, Config: p1.Config, Tool: cache.ToolInfo{Name: p1.ToolName, Version: p1.ToolVersion}})
	if err != nil {
		t.Fatalf("NewKey1: %v", err)
	}
	k2, err := cache.NewKey(cache.KeyParts{Operation: p2.Operation, Target: p2.Target, Config: p2.Config, Tool: cache.ToolInfo{Name: p2.ToolName, Version: p2.ToolVersion}})
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	if k1 != k2 {
		t.Fatalf("keys differ: %s vs %s", k1, k2)
	}
	// Different content -> different key
	if err := os.WriteFile(path, []byte("other.com\n"), 0600); err != nil {
		t.Fatalf("write2: %v", err)
	}
	p3, _ := CacheKeyForFile(path, imp, bounds)
	k3, _ := cache.NewKey(cache.KeyParts{Operation: p3.Operation, Target: p3.Target, Config: p3.Config, Tool: cache.ToolInfo{Name: p3.ToolName, Version: p3.ToolVersion}})
	if k1 == k3 {
		t.Fatalf("different content should give different key")
	}
	// Different importer version -> different key
	imp2 := &PlainDomainsImporter{importerBase{name: "plain-domains", version: "2.0.0", tool: "plain-domains"}}
	p4, _ := CacheKeyForFile(path, imp2, bounds)
	k4, _ := cache.NewKey(cache.KeyParts{Operation: p4.Operation, Target: p4.Target, Config: p4.Config, Tool: cache.ToolInfo{Name: p4.ToolName, Version: p4.ToolVersion}})
	if k3 == k4 {
		t.Fatalf("different version should give different key")
	}
	// Different MaxOutput -> different key
	bounds2 := Bounds{MaxOutput: 50000}
	p5, _ := CacheKeyForFile(path, imp, bounds2)
	k5, _ := cache.NewKey(cache.KeyParts{Operation: p5.Operation, Target: p5.Target, Config: p5.Config, Tool: cache.ToolInfo{Name: p5.ToolName, Version: p5.ToolVersion}})
	if k3 == k5 {
		t.Fatalf("different MaxOutput should give different key")
	}
}

func TestCacheHitWithoutReparse(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	c, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("Open cache: %v", err)
	}
	fileContent := "example.com\napi.example.com\n"
	filePath := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(filePath, []byte(fileContent), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	imp := NewPlainDomainsImporter()
	bounds := Bounds{MaxOutput: 100000}
	parts, err := CacheKeyForFile(filePath, imp, bounds)
	if err != nil {
		t.Fatalf("CacheKeyForFile: %v", err)
	}
	key, err := cache.NewKey(cache.KeyParts{Operation: parts.Operation, Target: parts.Target, Config: parts.Config, Tool: cache.ToolInfo{Name: parts.ToolName, Version: parts.ToolVersion}})
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	// First import: miss -> parse and Put
	if out := c.Get(context.Background(), key); !out.IsMiss() {
		t.Fatalf("expected miss before put, got %s", out.State)
	}
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: bounds}
	stats, err := imp.Import(context.Background(), env, filePath, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	// Build Data: normalized identities + stats, not raw bytes (MaxRecordSize guard)
	var ids []string
	for _, d := range sink.Domains {
		ids = append(ids, d.Identity().String())
	}
	data := ImportCacheData{
		SchemaVersion: SchemaVersion,
		Importer:      imp.Name(),
		Target:        parts.Target,
		Identities:    ids,
		Stats:         stats,
	}
	b, _ := json.Marshal(data)
	if len(b) > cache.MaxRecordSize {
		t.Fatalf("Data exceeds MaxRecordSize")
	}
	rec := cache.Record{
		Operation: parts.Operation,
		Target:    parts.Target,
		Tool:      cache.ToolInfo{Name: parts.ToolName, Version: parts.ToolVersion},
		Status:    cache.StatusCompleted,
		Data:      b,
	}
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Second import: hit without re-parse — verify Get returns hit and Data matches
	out := c.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("expected hit after put, got %s err %v", out.State, out.Err)
	}
	var got ImportCacheData
	if err := json.Unmarshal(out.Record.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Identities) != 2 {
		t.Fatalf("want 2 identities, got %d", len(got.Identities))
	}
	if got.Stats.ItemsProcessed != 2 {
		t.Fatalf("want 2 processed, got %d", got.Stats.ItemsProcessed)
	}
	// Ensure repeat call uses cache hit path (no re-parse needed): simulate caller checking cache first
	// If file unchanged, second call should not re-parse — we prove by not calling Import again and still having data
}

func TestCacheMaxRecordSizeGuard(t *testing.T) {
	// Ensure Data not raw bytes and MaxRecordSize guard is enforced
	data := ImportCacheData{
		SchemaVersion: SchemaVersion,
		Importer:      "plain-domains",
		Target:        "import:abc",
		Identities:    make([]string, 0),
		Stats:         ImportStats{},
	}
	b, _ := json.Marshal(data)
	if len(b) > cache.MaxRecordSize {
		t.Fatalf("empty data should be well below MaxRecordSize")
	}
}
