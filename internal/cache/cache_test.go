package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var testKey = func() Key {
	k, _ := NewKey(KeyParts{Operation: "op", Target: "host:example.com"})
	return k
}()

func newTestFS(t *testing.T, opts ...Option) (*FS, Key) {
	t.Helper()
	c, err := Open(t.TempDir(), opts...)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	return c, mustKey(t, baseParts("op", "host:example.com"))
}

func completedRecord(op, target string, data any) Record {
	rec := Record{
		Operation: op,
		Target:    target,
		Status:    StatusCompleted,
	}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}
		rec.Data = b
	}
	return rec
}

func TestGetMiss(t *testing.T) {
	c, key := newTestFS(t)
	out := c.Get(context.Background(), key)
	if !out.IsMiss() || out.IsHit() || out.IsUsable() {
		t.Fatalf("expected miss, got state %s", out.State)
	}
	if out.State != StateMiss {
		t.Fatalf("expected StateMiss, got %s", out.State)
	}
}

func TestPutGetHit(t *testing.T) {
	c, key := newTestFS(t)
	rec := completedRecord("op", "host:example.com", map[string]string{"result": "ok"})
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	out := c.Get(context.Background(), key)
	if !out.IsHit() || !out.IsUsable() || out.IsMiss() {
		t.Fatalf("expected hit, got state %s", out.State)
	}
	if out.Record.Status != StatusCompleted {
		t.Fatalf("expected completed status, got %q", out.Record.Status)
	}
	if !strings.Contains(string(out.Record.Data), `"result":"ok"`) {
		t.Fatalf("unexpected data %q", out.Record.Data)
	}
	if out.Record.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version %d", out.Record.SchemaVersion)
	}
	if out.Record.CreatedAt.IsZero() {
		t.Fatal("CreatedAt was not populated")
	}
}

func TestPutStampDefaults(t *testing.T) {
	c, key := newTestFS(t)
	// SchemaVersion 0 and zero CreatedAt should be auto-filled.
	rec := Record{Operation: "op", Target: "host:example.com", Status: StatusCompleted}
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	o := c.Get(context.Background(), key)
	if o.Record.SchemaVersion != SchemaVersion {
		t.Fatalf("schema not stamped: %d", o.Record.SchemaVersion)
	}
	if o.Record.CreatedAt.IsZero() {
		t.Fatal("created_at not stamped")
	}
}

func TestPutRejectsWrongSchema(t *testing.T) {
	c, key := newTestFS(t)
	rec := completedRecord("op", "host:example.com", nil)
	rec.SchemaVersion = SchemaVersion + 1
	if err := c.Put(context.Background(), key, rec); err == nil {
		t.Fatal("expected error for wrong schema on Put")
	}
	if o := c.Get(context.Background(), key); o.State != StateMiss {
		t.Fatalf("expected no entry written, got state %s", o.State)
	}
}

func TestPutRejectsInvalidStatus(t *testing.T) {
	c, key := newTestFS(t)
	rec := Record{Operation: "op", Target: "host:example.com", Status: "bogus"}
	if err := c.Put(context.Background(), key, rec); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestPutRejectsInvalidData(t *testing.T) {
	c, key := newTestFS(t)
	rec := completedRecord("op", "host:example.com", nil)
	rec.Data = json.RawMessage(`{"broken":`)
	if err := c.Put(context.Background(), key, rec); err == nil {
		t.Fatal("expected error for invalid JSON data")
	}
}

func TestPutSameKeyLastWriteWins(t *testing.T) {
	c, key := newTestFS(t)
	for i := 0; i < 3; i++ {
		if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", map[string]int{"i": i})); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	o := c.Get(context.Background(), key)
	var got map[string]int
	if err := json.Unmarshal(o.Record.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["i"] != 2 {
		t.Fatalf("expected last write to win, got %+v", got)
	}
}

// TestPutNoTempLeftover verifies the atomic write path leaves exactly one
// entry file and no temporary files.
func TestPutNoTempLeftover(t *testing.T) {
	c, key := newTestFS(t)
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(files) != 1 {
		for _, f := range files {
			t.Logf("found unexpected file: %s", f.Name())
		}
		t.Fatalf("expected exactly 1 entry file, got %d", len(files))
	}
	if files[0].Name() != filepath.Base(path) {
		t.Fatalf("unexpected file name %q, want %q", files[0].Name(), filepath.Base(path))
	}
}

func TestEquivalentKeysShareEntry(t *testing.T) {
	c, _ := newTestFS(t)
	k1 := mustKey(t, baseParts("dns.resolve", "host:example.com"))
	k2 := mustKey(t, baseParts(" dns.resolve ", " host:example.com "))
	if k1 != k2 {
		t.Fatal("keys should be equal")
	}
	if err := c.Put(context.Background(), k1, completedRecord("dns.resolve", "host:example.com", nil)); err != nil {
		t.Fatalf("Put k1: %v", err)
	}
	if o := c.Get(context.Background(), k2); !o.IsHit() {
		t.Fatalf("expected hit via equivalent key, got %s", o.State)
	}
}

func TestDistinctOperationsDoNotCollide(t *testing.T) {
	c, _ := newTestFS(t)
	a := mustKey(t, baseParts("dns.resolve", "host:example.com"))
	b := mustKey(t, baseParts("http.probe", "host:example.com"))
	if err := c.Put(context.Background(), a, completedRecord("dns.resolve", "host:example.com", nil)); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if o := c.Get(context.Background(), b); !o.IsMiss() {
		t.Fatalf("expected different keys not to collide, got %s", o.State)
	}
}

func TestDelete(t *testing.T) {
	c, key := newTestFS(t)
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if o := c.Get(context.Background(), key); o.State != StateMiss {
		t.Fatalf("expected miss after delete, got %s", o.State)
	}
	// Deleting a missing key is idempotent.
	if err := c.Delete(context.Background(), key); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
}

func TestClear(t *testing.T) {
	c, _ := newTestFS(t)
	for i := 0; i < 5; i++ {
		k := mustKey(t, KeyParts{Operation: "op", Target: fmt.Sprintf("host:h%d.example.com", i)})
		if err := c.Put(context.Background(), k, completedRecord("op", "x", nil)); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	if err := c.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for i := 0; i < 5; i++ {
		k := mustKey(t, KeyParts{Operation: "op", Target: fmt.Sprintf("host:h%d.example.com", i)})
		if o := c.Get(context.Background(), k); o.State != StateMiss {
			t.Fatalf("expected miss after clear for %d, got %s", i, o.State)
		}
	}
	// The cache remains usable after a clear.
	if err := c.Put(context.Background(), testKey, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put after clear: %v", err)
	}
	if o := c.Get(context.Background(), testKey); !o.IsHit() {
		t.Fatalf("expected hit after clear + put, got %s", o.State)
	}
}

// writeEntryFixture writes raw bytes directly at a key's entry path,
// simulating a partial/corrupt/malicious on-disk entry.
func writeEntryFixture(t *testing.T, c *FS, key Key, content []byte) {
	t.Helper()
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestCorruptEntryTreatsAsMissAndSelfHeals(t *testing.T) {
	c, key := newTestFS(t)
	writeEntryFixture(t, c, key, []byte("this is not json {{{"))

	o := c.Get(context.Background(), key)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt, got %s", o.State)
	}
	if o.IsHit() || o.IsUsable() {
		t.Fatal("corrupt entry must not be usable")
	}
	if o.Err == nil {
		t.Fatal("expected diagnostic error for corrupt entry")
	}
	// Self-healing: the corrupt entry is removed; a fresh Put then works.
	if o := c.Get(context.Background(), key); o.State != StateMiss {
		t.Fatalf("expected miss after self-heal, got %s", o.State)
	}
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put after self-heal: %v", err)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit after rewrite, got %s", o.State)
	}
}

// TestTruncatedEntry simulates a crash that left a partial write visible at
// the entry path (not possible through the atomic rename path, but possible
// through external corruption).
func TestTruncatedEntry(t *testing.T) {
	c, key := newTestFS(t)
	partial := []byte(`{"schema_version":1,"operation":"op","target":"ho`)
	writeEntryFixture(t, c, key, partial)
	o := c.Get(context.Background(), key)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt for truncated entry, got %s", o.State)
	}
	if o.IsUsable() {
		t.Fatal("truncated entry must not be usable")
	}
}

func TestOversizedEntryRejectedOnWrite(t *testing.T) {
	c, key := newTestFS(t)
	big := `{"pad":"` + strings.Repeat("x", MaxRecordSize+1) + `"}`
	rec := completedRecord("op", "host:example.com", nil)
	rec.Data = json.RawMessage(big)
	if err := c.Put(context.Background(), key, rec); err == nil {
		t.Fatal("expected error for oversized record")
	}
	if o := c.Get(context.Background(), key); o.State != StateMiss {
		t.Fatalf("expected nothing written, got %s", o.State)
	}
}

func TestOversizedEntryOnDiskRemovedOnRead(t *testing.T) {
	c, key := newTestFS(t)
	// Directly place an oversized file at the entry path, as if a runaway
	// writer or external process wrote it.
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir shard: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte(`{"schema_version":1,"data":"`)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := f.Write([]byte(strings.Repeat("x", MaxRecordSize))); err != nil {
		t.Fatalf("write body: %v", err)
	}
	_ = f.Close()

	o := c.Get(context.Background(), key)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt for oversized entry, got %s", o.State)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("oversized entry not self-healed (stat err %v)", err)
	}
}

func TestSchemaIncompatibleEntry(t *testing.T) {
	c, key := newTestFS(t)
	// A valid record with an unsupported schema version.
	rec := completedRecord("op", "host:example.com", nil)
	rec.SchemaVersion = SchemaVersion + 10
	buf, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writeEntryFixture(t, c, key, buf)

	o := c.Get(context.Background(), key)
	if o.State != StateSchemaIncompatible {
		t.Fatalf("expected StateSchemaIncompatible, got %s", o.State)
	}
	if o.IsUsable() {
		t.Fatal("incompatible entry must not be usable")
	}
	// Self-healed so a fresh Put works.
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put after incompatible: %v", err)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit after rewrite, got %s", o.State)
	}
}

func TestMalformedValidJSONEntry(t *testing.T) {
	c, key := newTestFS(t)
	// Valid JSON but semantically invalid: missing status and target.
	writeEntryFixture(t, c, key, []byte(`{"schema_version":1,"operation":"op"}`))
	o := c.Get(context.Background(), key)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt for malformed record, got %s", o.State)
	}
	if o.IsUsable() {
		t.Fatal("malformed record must not be usable")
	}
}

func TestIncompleteFailedCancelledNotUsable(t *testing.T) {
	c, key := newTestFS(t)
	for _, st := range []Status{StatusIncomplete, StatusFailed, StatusCancelled} {
		rec := Record{Operation: "op", Target: "host:example.com", Status: st, Data: json.RawMessage(`{"partial":true}`)}
		if err := c.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("Put %s: %v", st, err)
		}
		o := c.Get(context.Background(), key)
		if o.IsUsable() {
			t.Fatalf("%s entry must not be a usable result", st)
		}
		if o.State != StateIncomplete {
			t.Fatalf("expected StateIncomplete for %s, got %s", st, o.State)
		}
		if o.Record == nil || o.Record.Status != st {
			t.Fatalf("%s status not preserved on outcome", st)
		}
		if !strings.Contains(string(o.Record.Data), `"partial":true`) {
			t.Fatalf("%s partial data not preserved", st)
		}
	}
}

// TestResumeDoesNotTrustIncomplete verifies resume semantics: a partial entry
// is surfaced (with its partial Data) but never consumed as a successful hit.
func TestResumeDoesNotTrustIncomplete(t *testing.T) {
	dir := t.TempDir()
	c1, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("crawl", "url:https://example.com/"))
	partial := Record{
		Operation: "crawl",
		Target:    "url:https://example.com/",
		Status:    StatusIncomplete,
		Data:      json.RawMessage(`{"found":["/a","/b"]}`),
	}
	if err := c1.Put(context.Background(), key, partial); err != nil {
		t.Fatalf("Put partial: %v", err)
	}

	// Simulate a process restart: a fresh instance over the same directory.
	c2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	o := c2.Get(context.Background(), key)
	if o.IsUsable() {
		t.Fatal("partial result must not be reusable as a hit")
	}
	if o.State != StateIncomplete {
		t.Fatalf("expected StateIncomplete, got %s", o.State)
	}
	if !strings.Contains(string(o.Record.Data), `"/a"`) {
		t.Fatalf("partial data must be available for resume, got %q", o.Record.Data)
	}

	// When the work later completes, the completed record replaces the partial.
	done := Record{
		Operation: "crawl",
		Target:    "url:https://example.com/",
		Status:    StatusCompleted,
		Data:      json.RawMessage(`{"found":["/a","/b","/c"]}`),
	}
	if err := c2.Put(context.Background(), key, done); err != nil {
		t.Fatalf("Put completed: %v", err)
	}
	if o := c2.Get(context.Background(), key); !o.IsUsable() {
		t.Fatalf("expected usable after completion, got %s", o.State)
	}
}

// TestRestartResume verifies a completed entry survives a process restart
// (a fresh cache instance over the same directory sees it as a hit).
func TestRestartResume(t *testing.T) {
	dir := t.TempDir()
	c1, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("dns.resolve", "host:example.com"))
	if err := c1.Put(context.Background(), key, completedRecord("dns.resolve", "host:example.com", map[string]string{"ip": "1.2.3.4"})); err != nil {
		t.Fatalf("Put: %v", err)
	}

	c2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	o := c2.Get(context.Background(), key)
	if !o.IsUsable() {
		t.Fatalf("expected hit after restart, got state %s", o.State)
	}
	if !strings.Contains(string(o.Record.Data), `"1.2.3.4"`) {
		t.Fatalf("unexpected data after restart: %q", o.Record.Data)
	}
}

func TestTTL(t *testing.T) {
	now := time.Unix(1_000_000_000, 0).UTC()
	c, err := Open(t.TempDir(), WithTTL(10*time.Second), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Exactly at TTL: not expired (requires strictly greater elapsed time).
	now = now.Add(10 * time.Second)
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit at TTL boundary, got %s", o.State)
	}
	// Just past TTL: expired and never usable.
	now = now.Add(1 * time.Nanosecond)
	o := c.Get(context.Background(), key)
	if o.State != StateExpired {
		t.Fatalf("expected StateExpired, got %s", o.State)
	}
	if o.IsUsable() || o.IsMiss() == false {
		t.Fatal("expired entry must not be usable and must be a miss")
	}
	// A completed replacement restores the hit.
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit after rewrite, got %s", o.State)
	}
}

func TestTTLDisabledNeverExpires(t *testing.T) {
	// Default TTL (0) = disabled; an old entry stays valid.
	c, key := newTestFS(t)
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Force a far-future clock only for the read path via a new instance.
	c2, err := Open(c.Dir(), WithClock(func() time.Time { return time.Unix(1<<40, 0) }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if o := c2.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit with disabled TTL, got %s", o.State)
	}
}

func TestInvalidateIncompatible(t *testing.T) {
	c, _ := newTestFS(t)
	good := mustKey(t, baseParts("op", "host:good.example.com"))
	bad := mustKey(t, baseParts("op", "host:bad.example.com"))
	corrupt := mustKey(t, baseParts("op", "host:corrupt.example.com"))
	old := mustKey(t, baseParts("op", "host:old.example.com"))

	if err := c.Put(context.Background(), good, completedRecord("op", "x", nil)); err != nil {
		t.Fatalf("put good: %v", err)
	}
	writeEntryFixture(t, c, corrupt, []byte("garbage!!"))

	rec := completedRecord("op", "x", nil)
	rec.SchemaVersion = SchemaVersion - 1
	buf, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal old: %v", err)
	}
	// old schema record written directly, plus one valid old-schema at bad key path handled by put rejection? Use fixture.
	writeEntryFixture(t, c, old, buf)

	// "bad" is a valid record for the current schema — must be kept.
	if err := c.Put(context.Background(), bad, completedRecord("op", "x", nil)); err != nil {
		t.Fatalf("put bad: %v", err)
	}

	removed, err := c.InvalidateIncompatible(context.Background())
	if err != nil {
		t.Fatalf("InvalidateIncompatible: %v", err)
	}
	if removed != 2 { // corrupt + old-schema
		t.Fatalf("removed = %d, want 2", removed)
	}
	if o := c.Get(context.Background(), good); !o.IsHit() {
		t.Fatalf("good entry removed unexpectedly: %s", o.State)
	}
	if o := c.Get(context.Background(), bad); !o.IsHit() {
		t.Fatalf("good entry removed unexpectedly (bad): %s", o.State)
	}
	if o := c.Get(context.Background(), old); o.State != StateMiss {
		t.Fatalf("old-schema entry should be gone, got %s", o.State)
	}
	if o := c.Get(context.Background(), corrupt); o.State != StateMiss {
		t.Fatalf("corrupt entry should be gone, got %s", o.State)
	}
}

func TestTempLeftoverIgnored(t *testing.T) {
	c, key := newTestFS(t)
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	// Simulate a crash that left a temporary file behind.
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "entry-12345.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	// The temp file is inert: reads ignore it and are unaffected.
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit unaffected by leftover temp, got %s", o.State)
	}
	// InvalidateIncompatible ignores non-.json files.
	removed, err := c.InvalidateIncompatible(context.Background())
	if err != nil {
		t.Fatalf("InvalidateIncompatible: %v", err)
	}
	if removed != 0 {
		t.Fatalf("invalidator must not count leftover temp files, removed %d", removed)
	}
	// Clear removes leftover temp files too: after Clear the whole entries
	// tree is gone, so there can be no leftover temp files anywhere.
	if err := c.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	roots := filepath.Join(c.Dir(), "entries")
	if _, err := os.Stat(roots); os.IsNotExist(err) {
		return
	}
	files, err := os.ReadDir(roots)
	if err != nil {
		t.Fatalf("read entries root: %v", err)
	}
	if len(files) != 0 {
		for _, f := range files {
			t.Logf("leftover after clear: %s", f.Name())
		}
		t.Fatalf("expected empty entries root after clear, got %d entries", len(files))
	}
}

func TestUnsafeTargetCannotEscapeDirectory(t *testing.T) {
	c, _ := newTestFS(t)
	targets := []string{"../../etc/passwd", "/etc/passwd", "..\\..\\win", "host:example.com/x"}
	for _, tg := range targets {
		key := mustKey(t, baseParts("op", tg))
		if err := c.Put(context.Background(), key, completedRecord("op", tg, nil)); err != nil {
			t.Fatalf("put %q: %v", tg, err)
		}
		path, err := c.entryPath(key)
		if err != nil {
			t.Fatalf("entryPath: %v", err)
		}
		rel, err := filepath.Rel(c.Dir(), path)
		if err != nil {
			t.Fatalf("rel: %v", err)
		}
		if strings.HasPrefix(rel, "..") {
			t.Fatalf("entry escaped cache dir for target %q: %s", tg, path)
		}
		want := filepath.Join(c.Dir(), "entries")
		if !strings.HasPrefix(path, want+string(filepath.Separator)) {
			t.Fatalf("entry outside entries root for target %q: %s", tg, path)
		}
	}
}

func TestFabricatedInvalidKeyRejected(t *testing.T) {
	c, _ := newTestFS(t)
	for _, bad := range []Key{
		Key("../../etc/passwd"),
		Key("short"),
		Key(strings.Repeat("g", 64)), // valid hex length but wrong alphabet
		Key(strings.Repeat("Z", 64)),
	} {
		if o := c.Get(context.Background(), bad); o.State != StateError {
			t.Fatalf("expected StateError for fabricated key %q, got %s", bad, o.State)
		}
		if err := c.Put(context.Background(), bad, completedRecord("op", "x", nil)); err == nil {
			t.Fatalf("expected error for fabricated key %q on Put", bad)
		}
	}
}

func TestCachePermissions(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("entry perms = %04o, want 0600", got)
	}
	dinfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dinfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("shard dir perms = %04o, want 0700", got)
	}
}

func TestGetFilesystemError(t *testing.T) {
	c, key := newTestFS(t)
	// Replace the entries directory with a regular file so opens fail.
	entries := filepath.Join(c.Dir(), "entries")
	if err := os.RemoveAll(entries); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.WriteFile(entries, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	o := c.Get(context.Background(), key)
	if o.State != StateError {
		t.Fatalf("expected StateError, got %s", o.State)
	}
	if o.Err == nil {
		t.Fatal("expected error detail")
	}
}

func TestContextCancellation(t *testing.T) {
	c, key := newTestFS(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if o := c.Get(ctx, key); o.State != StateError {
		t.Fatalf("expected StateError for canceled get, got %s", o.State)
	}
	if err := c.Put(ctx, key, completedRecord("op", "x", nil)); err == nil {
		t.Fatal("expected error for canceled put")
	}
	if err := c.Delete(ctx, key); err == nil {
		t.Fatal("expected error for canceled delete")
	}
	if err := c.Clear(ctx); err == nil {
		t.Fatal("expected error for canceled clear")
	}
}

func TestConcurrentSameKeyWrites(t *testing.T) {
	c, key := newTestFS(t)
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := completedRecord("op", "host:example.com", map[string]int{"i": i})
			if err := c.Put(context.Background(), key, rec); err != nil {
				t.Errorf("concurrent Put %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	o := c.Get(context.Background(), key)
	if !o.IsUsable() {
		t.Fatalf("expected a usable result, got state %s", o.State)
	}
	var got map[string]int
	if err := json.Unmarshal(o.Record.Data, &got); err != nil {
		t.Fatalf("final entry is not a complete parseable record: %v", err)
	}
	if got["i"] < 0 || got["i"] >= n {
		t.Fatalf("final entry holds unexpected value %+v", got)
	}
	// Exactly one entry file remains; no temp litter.
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(files) != 1 {
		for _, f := range files {
			t.Logf("file: %s", f.Name())
		}
		t.Fatalf("expected exactly 1 entry file after concurrent writes, got %d", len(files))
	}
}

func TestConcurrentDifferentKeyWrites(t *testing.T) {
	c, _ := newTestFS(t)
	const n = 64
	var wg sync.WaitGroup
	keys := make([]Key, n)
	for i := 0; i < n; i++ {
		keys[i] = mustKey(t, KeyParts{Operation: "op", Target: fmt.Sprintf("host:h%d.example.com", i)})
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := completedRecord("op", "x", map[string]int{"i": i})
			if err := c.Put(context.Background(), keys[i], rec); err != nil {
				t.Errorf("Put %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		o := c.Get(context.Background(), keys[i])
		if !o.IsUsable() {
			t.Fatalf("key %d not usable: %s", i, o.State)
		}
		var got map[string]int
		if err := json.Unmarshal(o.Record.Data, &got); err != nil {
			t.Fatalf("key %d: bad data: %v", i, err)
		}
		if got["i"] != i {
			t.Fatalf("key %d has wrong data %+v", i, got)
		}
	}
}

// TestAtomicVisibilityUnderConcurrentRename exercises the atomic-rename
// guarantee: while one goroutine rewrites the same key with payloads of very
// different sizes, readers must only ever observe a complete record equal to
// one of the written payloads — never a torn/partial file.
func TestAtomicVisibilityUnderConcurrentRename(t *testing.T) {
	c, key := newTestFS(t)
	small := json.RawMessage(`{"kind":"small"}`)
	large := json.RawMessage(`{"kind":"large","pad":"` + strings.Repeat("z", 8192) + `"}`)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	writerDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writerDone)
		for i := 0; i < 200; i++ {
			p := large
			if i%2 == 0 {
				p = small
			}
			rec := completedRecord("op", "host:example.com", nil)
			rec.Data = p
			if err := c.Put(context.Background(), key, rec); err != nil {
				t.Errorf("writer put: %v", err)
				return
			}
		}
		close(stop)
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-writerDone:
					// Drain a couple of final reads after the writer stops.
					for i := 0; i < 5; i++ {
						o := c.Get(context.Background(), key)
						if o.IsUsable() {
							if !bytesEqual(o.Record.Data, small) && !bytesEqual(o.Record.Data, large) {
								t.Errorf("reader observed an entry that matches no written payload")
								return
							}
						}
					}
					return
				default:
				}
				o := c.Get(context.Background(), key)
				switch o.State {
				case StateHit:
					if !bytesEqual(o.Record.Data, small) && !bytesEqual(o.Record.Data, large) {
						t.Errorf("reader observed an entry that matches no written payload")
						return
					}
				case StateMiss:
					// Writer has not placed the first entry yet; acceptable.
				case StateCorrupt, StateSchemaIncompatible, StateError:
					t.Errorf("reader observed invalid state %s during concurrent rename", o.State)
					return
				case StateExpired, StateIncomplete:
					t.Errorf("reader observed unexpected state %s", o.State)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func bytesEqual(a, b json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestConcurrentMixedOperations runs Put/Delete/Get concurrently over a small
// shared key set and asserts the cache never surfaces a corrupt, incompatible,
// or failed outcome, and every usable result matches a known written payload.
func TestConcurrentMixedOperations(t *testing.T) {
	c, _ := newTestFS(t)
	const keys = 8
	const perOp = 150
	ks := make([]Key, keys)
	candidate := make(map[string]bool) // canonical json strings ever written
	var mu sync.Mutex
	for i := 0; i < keys; i++ {
		ks[i] = mustKey(t, KeyParts{Operation: "op", Target: fmt.Sprintf("host:m%d.example.com", i)})
	}

	write := func(i int, it int) {
		rec := completedRecord("op", "x", map[string]int{"key": i, "it": it})
		candidateMu(candidate, &mu, string(rec.Data))
		if err := c.Put(context.Background(), ks[i], rec); err != nil {
			t.Errorf("put: %v", err)
		}
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for it := 0; it < perOp; it++ {
				i := (g + it) % keys
				switch (g + it) % 3 {
				case 0:
					write(i, it)
				case 1:
					_ = c.Delete(context.Background(), ks[i])
				default:
					o := c.Get(context.Background(), ks[i])
					switch o.State {
					case StateHit:
						data := string(o.Record.Data)
						mu.Lock()
						ok := candidate[data]
						mu.Unlock()
						if !ok {
							t.Errorf("usable result %q never written", data)
							return
						}
					case StateMiss, StateExpired:
						// acceptable under delete races
					case StateCorrupt, StateSchemaIncompatible, StateError:
						t.Errorf("unexpected state %s", o.State)
						return
					case StateIncomplete:
						t.Errorf("unexpected incomplete state")
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

func candidateMu(m map[string]bool, mu *sync.Mutex, s string) {
	mu.Lock()
	defer mu.Unlock()
	m[s] = true
}

func TestConcurrentReads(t *testing.T) {
	c, key := newTestFS(t)
	for i := 0; i < 5; i++ {
		rec := completedRecord("op", "host:example.com", map[string]string{"run": "complete"})
		if err := c.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	var wg sync.WaitGroup
	for r := 0; r < 32; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if o := c.Get(context.Background(), key); !o.IsUsable() {
					t.Errorf("concurrent read got %s", o.State)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestOpenValidation(t *testing.T) {
	if _, err := Open("", WithTTL(0)); err == nil {
		t.Fatal("expected error for empty dir")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "sub"), WithTTL(-1*time.Second)); err == nil {
		t.Fatal("expected error for negative TTL")
	}
}

func TestDefaultDir(t *testing.T) {
	d, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if !strings.HasSuffix(d, "ravenrecon") {
		t.Fatalf("default dir %q does not end with ravenrecon", d)
	}
}

// getWithin runs Get with a watchdog so tests can assert that a Get over an
// entry path that previously could block (a planted FIFO or directory) now
// returns promptly instead of hanging.
func getWithin(t *testing.T, c *FS, key Key, d time.Duration) Outcome {
	t.Helper()
	ch := make(chan Outcome, 1)
	go func() { ch <- c.Get(context.Background(), key) }()
	select {
	case o := <-ch:
		return o
	case <-time.After(d):
		t.Fatalf("Get for key %s blocked longer than %s", key, d)
		return Outcome{}
	}
}

// TestSelfHealKeepsConcurrentValidPut deterministically exercises the
// interleaving the mutex-guarded re-check protects against: Get observes a
// corrupt entry, then a concurrent Put installs a valid entry for the same
// key before the re-check runs. The self-healing removal must not delete the
// valid entry, and a subsequent Get must return it.
func TestSelfHealKeepsConcurrentValidPut(t *testing.T) {
	c, key := newTestFS(t)
	writeEntryFixture(t, c, key, []byte("this is not json {{{"))

	// Pause Get between its initial read (which sees the corrupt entry) and
	// the mutex-guarded re-check, so the interleaving is forced rather than
	// probabilistic.
	readDone := make(chan struct{})
	release := make(chan struct{})
	c.beforeSelfHeal = func() {
		close(readDone)
		<-release
	}

	got := make(chan Outcome, 1)
	go func() { got <- c.Get(context.Background(), key) }()
	<-readDone

	valid := completedRecord("op", "host:example.com", map[string]string{"result": "ok"})
	if err := c.Put(context.Background(), key, valid); err != nil {
		t.Fatalf("concurrent Put: %v", err)
	}
	close(release)

	o := <-got
	if o.State != StateCorrupt {
		t.Fatalf("first Get observed the corrupt entry, want StateCorrupt, got %s", o.State)
	}

	// The valid entry installed by the concurrent Put must have survived the
	// self-healing removal.
	after := c.Get(context.Background(), key)
	if !after.IsHit() {
		t.Fatalf("self-heal removed the concurrent Put; subsequent Get state %s", after.State)
	}
	if string(after.Record.Data) != string(valid.Data) {
		t.Fatalf("subsequent Get returned %s, want %s", after.Record.Data, valid.Data)
	}
}

// TestRejectedPutKeepsExistingEntry verifies that a Put rejected by
// validation (oversized payload or invalid JSON data) leaves any pre-existing
// valid entry for the key intact and readable: validation happens before
// anything reaches the filesystem.
func TestRejectedPutKeepsExistingEntry(t *testing.T) {
	c, key := newTestFS(t)
	valid := completedRecord("op", "host:example.com", map[string]string{"result": "ok"})
	if err := c.Put(context.Background(), key, valid); err != nil {
		t.Fatalf("initial Put: %v", err)
	}

	// Oversized payload.
	oversized := completedRecord("op", "host:example.com", nil)
	oversized.Data = json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxRecordSize+1) + `"}`)
	if err := c.Put(context.Background(), key, oversized); err == nil {
		t.Fatal("expected oversized Put to be rejected")
	}

	// Invalid JSON in Data.
	badJSON := completedRecord("op", "host:example.com", nil)
	badJSON.Data = json.RawMessage(`{"broken":`)
	if err := c.Put(context.Background(), key, badJSON); err == nil {
		t.Fatal("expected invalid-JSON Put to be rejected")
	}

	o := c.Get(context.Background(), key)
	if !o.IsHit() {
		t.Fatalf("pre-existing valid entry lost after rejected Puts: %s", o.State)
	}
	if string(o.Record.Data) != string(valid.Data) {
		t.Fatalf("pre-existing entry content changed: %s", o.Record.Data)
	}
}

// TestDirectoryAtEntryPath verifies that a directory planted at an entry path
// yields a non-usable outcome quickly (never hangs), is self-healed, and does
// not wedge the key forever: a later Put must be able to replace it.
func TestDirectoryAtEntryPath(t *testing.T) {
	c, key := newTestFS(t)
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir at entry path: %v", err)
	}

	o := getWithin(t, c, key, 5*time.Second)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt for directory at entry path, got %s", o.State)
	}
	if o.IsUsable() {
		t.Fatal("directory at entry path must not be usable")
	}

	// Self-healed: the directory is gone and the key is writable again.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("directory not self-healed (stat err %v)", err)
	}
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put after directory self-heal: %v", err)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit after rewrite, got %s", o.State)
	}
}

// TestPutFsyncsDirectoryAfterRename pins the crash-safe-write hardening:
// after the atomic rename, Put applies its directory-durability step to the
// shard directory exactly once (NEW-33). The dirSync seam makes the call
// observable without depending on filesystem sync semantics.
func TestPutFsyncsDirectoryAfterRename(t *testing.T) {
	c, key := newTestFS(t)
	var called []string
	c.dirSync = func(dir string) error {
		called = append(called, dir)
		return nil
	}
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	wantDir := filepath.Dir(path)
	if len(called) != 1 {
		t.Fatalf("dirSync called %d times, want exactly 1", len(called))
	}
	if called[0] != wantDir {
		t.Fatalf("dirSync called with %q, want shard directory %q", called[0], wantDir)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit after Put, got %s", o.State)
	}
}

// TestPutSkipsDirSyncWhenRenameFails verifies the durability step only
// follows a successful rename: a failed Put must not report the directory
// as synced.
func TestPutSkipsDirSyncWhenRenameFails(t *testing.T) {
	c, key := newTestFS(t)
	var calls int
	c.dirSync = func(dir string) error {
		calls++
		return nil
	}
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	// A directory at the entry path makes the rename fail.
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir at entry path: %v", err)
	}
	defer os.RemoveAll(path)
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err == nil {
		t.Fatal("expected Put to fail when the rename target is a directory")
	}
	if calls != 0 {
		t.Fatalf("dirSync called %d times on failed rename, want 0", calls)
	}
}

// TestPutSucceedsWhenDirSyncFails pins the best-effort contract: the entry
// is already complete and in place when the directory sync runs, so a
// dir-sync failure must never fail the Put nor leave an unreadable entry.
func TestPutSucceedsWhenDirSyncFails(t *testing.T) {
	c, key := newTestFS(t)
	c.dirSync = func(dir string) error { return fmt.Errorf("injected dir-sync failure") }
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", map[string]string{"k": "v"})); err != nil {
		t.Fatalf("Put must succeed despite dir-sync failure: %v", err)
	}
	o := c.Get(context.Background(), key)
	if !o.IsHit() {
		t.Fatalf("expected hit despite dir-sync failure, got %s", o.State)
	}
}

// TestSyncDirBestEffort exercises the real helper on a live directory and
// pins which errnos count as "filesystem does not support directory fsync"
// (ENOSYS, EINVAL) — those are swallowed by the helper, everything else is
// reported.
func TestSyncDirBestEffort(t *testing.T) {
	dir := t.TempDir()
	if err := syncDirBestEffort(dir); err != nil {
		t.Logf("directory fsync unsupported or failed on this filesystem (treated as best-effort): %v", err)
	}
	if err := syncDirBestEffort(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("syncDirBestEffort on a missing directory must report the open error")
	}
	for _, tc := range []struct {
		err         error
		unsupported bool
	}{
		{fmt.Errorf("wrap: %w", syscall.ENOSYS), true},
		{fmt.Errorf("wrap: %w", syscall.EINVAL), true},
		{fmt.Errorf("wrap: %w", syscall.EIO), false},
		{fmt.Errorf("wrap: %w", os.ErrPermission), false},
	} {
		if got := isUnsupportedDirSync(tc.err); got != tc.unsupported {
			t.Fatalf("isUnsupportedDirSync(%v) = %v, want %v", tc.err, got, tc.unsupported)
		}
	}
}
