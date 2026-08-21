package cache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzStoredRecordDecode drives the untrusted on-disk boundary: arbitrary
// bytes are placed at a valid entry path and classified through the
// production decode path (Get → readEntry → json.Unmarshal →
// validateContent → evaluate) plus the self-heal walk
// (InvalidateIncompatible). Invariants under hostile bytes:
//
//   - no panic, no hang;
//   - every Outcome carries one of the seven defined states — never an
//     undefined classification;
//   - garbage is never served as a usable record: StateHit implies the
//     decoded record passes validateContent with status completed and the
//     current schema version;
//   - self-healing is honest: corrupt/schema-incompatible entries are
//     removed by Get, and nothing of either class survives
//     InvalidateIncompatible.
func FuzzStoredRecordDecode(f *testing.F) {
	valid, err := json.Marshal(Record{
		SchemaVersion: SchemaVersion,
		Operation:     "fuzz-op",
		Target:        "example.com",
		CreatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:        StatusCompleted,
		Data:          json.RawMessage(`{"urls":["https://example.com/a"]}`),
		Meta:          map[string]string{"run": "fuzz"},
	})
	if err != nil {
		f.Fatalf("marshal seed record: %v", err)
	}

	seeds := [][]byte{
		valid,
		valid[:len(valid)/2], // truncated mid-JSON
		append([]byte(nil), valid[:12]...),
		[]byte(`{}`),
		[]byte(`{"schema_version":999,"operation":"op","target":"t","status":"completed","created_at":"2026-01-01T00:00:00Z"}`),
		[]byte(`{"schema_version":-1,"operation":"","target":"","status":"bogus","created_at":"0001-01-01T00:00:00Z"}`),
		[]byte(`{"schema_version":"one"}`), // type confusion
		[]byte("\xff\xfe\x00binary junk{"),
		append([]byte("\xef\xbb\xbf"), valid...), // UTF-8 BOM before JSON
		[]byte(`{"schema_version":1,"operation":"o","target":"t","status":"completed","created_at":"2026-01-01T00:00:00Z","meta":{"k":"` + strings.Repeat("v", 4096) + `"}}`),
		[]byte(`[[[[[[[[[[not an object]]]]]]]]]]`),
		[]byte(`null`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	ctx := context.Background()
	key, err := NewKey(KeyParts{Operation: "fuzz-op", Target: "example.com"})
	if err != nil {
		f.Fatalf("derive key: %v", err)
	}

	f.Fuzz(func(t *testing.T, recBytes []byte) {
		c, err := Open(t.TempDir())
		if err != nil {
			t.Fatalf("open cache: %v", err)
		}
		path, err := c.entryPath(key)
		if err != nil {
			t.Fatalf("entry path: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("shard dir: %v", err)
		}
		if err := os.WriteFile(path, recBytes, 0o600); err != nil {
			t.Fatalf("write entry: %v", err)
		}

		out := c.Get(ctx, key)
		switch out.State {
		case StateHit:
			if out.Record == nil {
				t.Fatalf("StateHit with nil record")
			}
			if err := out.Record.validateContent(); err != nil {
				t.Fatalf("garbage served as a hit: %v", err)
			}
			if out.Record.Status != StatusCompleted || out.Record.SchemaVersion != SchemaVersion {
				t.Fatalf("hit violates policy: status=%q schema=%d", out.Record.Status, out.Record.SchemaVersion)
			}
		case StateMiss, StateExpired, StateIncomplete, StateError:
			// Honest non-hit classifications; nothing further to assert.
		case StateCorrupt, StateSchemaIncompatible:
			if _, statErr := os.Lstat(path); statErr == nil {
				t.Fatalf("%s entry was not self-healed (still present after Get)", out.State)
			}
		default:
			t.Fatalf("undefined outcome state %d", int(out.State))
		}

		removed, err := c.InvalidateIncompatible(ctx)
		if err != nil {
			t.Fatalf("InvalidateIncompatible: %v", err)
		}
		if removed < 0 {
			t.Fatalf("negative removal count %d", removed)
		}
		switch after := c.Get(ctx, key); after.State {
		case StateCorrupt, StateSchemaIncompatible:
			t.Fatalf("unusable entry survived InvalidateIncompatible: %s", after.State)
		}
	})
}
