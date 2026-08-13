package cache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cache is the minimal contract future runtime stages use to persist and
// reuse reconnaissance results. Implementations must be safe for concurrent
// use by multiple goroutines in one process.
//
// The cache is a record store, not a log: Put replaces the whole entry for a
// key. Callers that want to accumulate partial results merge them into the
// record they store (see StatusIncomplete in record.go).
type Cache interface {
	// Get returns the outcome for key. Corrupt, oversized, expired,
	// schema-incompatible, and non-completed entries are never returned as
	// valid results; each is reported through Outcome.State (see outcome.go).
	Get(ctx context.Context, key Key) Outcome

	// Put writes record for key, replacing any previous entry atomically.
	Put(ctx context.Context, key Key, record Record) error

	// Delete removes the entry for key. Deleting a key that has no entry is
	// not an error (the operation is idempotent).
	Delete(ctx context.Context, key Key) error

	// Clear removes every entry (and any leftover temporary files) in the
	// cache.
	Clear(ctx context.Context) error
}

// MaxRecordSize bounds the serialized size of a single cache entry in bytes.
// Entries larger than this are rejected on write and removed as corrupt on
// read, so a runaway result cannot exhaust memory or disk through the cache.
const MaxRecordSize = 16 << 20 // 16 MiB

// options configures a filesystem-backed cache.
type options struct {
	ttl time.Duration
	now func() time.Time
}

// Option customizes a filesystem-backed cache created by Open.
type Option func(*options)

// WithTTL sets the freshness lifetime of entries, measured from CreationAt.
// Zero (the default) disables expiration: entries are valid indefinitely.
func WithTTL(d time.Duration) Option {
	return func(o *options) { o.ttl = d }
}

// WithClock injects a clock for deterministic tests. Nil means time.Now.
func WithClock(f func() time.Time) Option {
	return func(o *options) { o.now = f }
}

// FS is the filesystem-backed cache. Entries are stored at
//
//	<dir>/entries/<aa>/<bb>/<key>.json
//
// where <aa>/<bb> is a two-level shard derived from the key digest, so a
// lookup is O(1) in the number of entries. With uniformly distributed key
// digests there are 65,536 possible second-level shards, each holding an
// expected ~N/65536 entries; the maximum number of entries in any one shard
// is unbounded (a uniform distribution bounds only the expectation).
//
// Reads are lock-free (atomic rename guarantees readers observe only complete
// files). Mutating operations (Put/Delete/Clear and self-healing removal) are
// serialized by an internal per-instance mutex.
type FS struct {
	dir string
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex // serializes mutating operations

	// beforeSelfHeal is a test-only hook invoked after a read classified an
	// entry as unusable and immediately before the mutex-guarded self-heal
	// re-check. Tests set it to force interleavings with concurrent writers
	// deterministically; it is nil in production.
	beforeSelfHeal func()
}

var _ Cache = (*FS)(nil)

// Open returns a filesystem-backed cache rooted at dir, creating the
// directory tree if needed. dir must be a local directory path; entries never
// escape it because on-disk paths are derived only from key digests.
func Open(dir string, opts ...Option) (*FS, error) {
	o := options{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	if o.ttl < 0 {
		return nil, fmt.Errorf("cache: TTL must not be negative")
	}
	if o.now == nil {
		o.now = time.Now
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("cache: directory must not be empty")
	}
	entries := filepath.Join(dir, "entries")
	if err := os.MkdirAll(entries, 0o700); err != nil {
		return nil, fmt.Errorf("cache: create cache directory %s: %w", entries, err)
	}
	return &FS{dir: dir, ttl: o.ttl, now: o.now}, nil
}

// DefaultDir returns the default cache directory,
// os.UserCacheDir()/ravenrecon.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cache: resolve user cache directory: %w", err)
	}
	return filepath.Join(base, "ravenrecon"), nil
}

// Dir returns the cache root directory.
func (c *FS) Dir() string { return c.dir }

// entryPath derives the on-disk location of key. Only lowercase hex digests
// are accepted, so key bytes can never escape the cache directory or traverse
// paths, even if a caller fabricates a Key value.
func (c *FS) entryPath(key Key) (string, error) {
	h := string(key)
	if len(h) != sha256.Size*2 {
		return "", fmt.Errorf("cache: invalid key length %d (want %d)", len(h), sha256.Size*2)
	}
	for i := 0; i < len(h); i++ {
		if !isHex(h[i]) {
			return "", fmt.Errorf("cache: invalid non-hex key byte at position %d", i)
		}
	}
	return filepath.Join(c.dir, "entries", h[0:2], h[2:4], h+".json"), nil
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f'
}

// Get returns the outcome for key. See the Cache interface and outcome.go.
func (c *FS) Get(ctx context.Context, key Key) Outcome {
	if err := ctx.Err(); err != nil {
		return Outcome{State: StateError, Err: fmt.Errorf("cache get %s: %w", key, err)}
	}
	path, err := c.entryPath(key)
	if err != nil {
		return Outcome{State: StateError, Err: fmt.Errorf("cache get: %w", err)}
	}

	found := c.readEntry(path)
	switch found.state {
	case entryMissing:
		return Outcome{State: StateMiss}
	case entryOK:
		return c.evaluate(key, found.rec)
	case entryOversized, entryCorrupt:
		c.removeUnusable(path)
		return Outcome{State: StateCorrupt, Err: found.err}
	case entrySchema:
		c.removeUnusable(path)
		return Outcome{State: StateSchemaIncompatible, Err: found.err}
	default:
		return Outcome{State: StateError, Err: found.err}
	}
}

// evaluate applies TTL and status policies to a well-formed decoded record.
func (c *FS) evaluate(key Key, rec Record) Outcome {
	if c.ttl > 0 && c.now().Sub(rec.CreatedAt) > c.ttl {
		return Outcome{State: StateExpired, Record: &rec}
	}
	if rec.Status != StatusCompleted {
		return Outcome{State: StateIncomplete, Record: &rec}
	}
	return Outcome{State: StateHit, Record: &rec}
}

// Put writes record for key, replacing any previous entry atomically: the
// record is serialized and validated, written to a unique temporary file in
// the entry's directory, synced, and renamed over the final name. A reader
// observes either the previous or the new complete entry, never a partial
// one. Validation failures reject the Put before anything reaches the
// filesystem, leaving any existing entry for key intact.
//
// The cache indexes by key only and cannot verify that the record's identity
// fields match the inputs that derived key. record.Operation and
// record.Target should therefore be the trimmed values used to derive key
// (see NewKey), or records are stored under keys their identity fields do
// not describe.
//
// Before writing, SchemaVersion and CreatedAt are completed when left at
// their zero values: a record with SchemaVersion 0 is stamped with the
// current version, and a record with a zero CreatedAt is stamped with the
// current clock. A record with an explicitly wrong schema version is
// rejected.
func (c *FS) Put(ctx context.Context, key Key, record Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cache put %s: %w", key, err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		return fmt.Errorf("cache put: %w", err)
	}

	if record.SchemaVersion == 0 {
		record.SchemaVersion = SchemaVersion
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = c.now().UTC()
	}
	if err := record.validate(); err != nil {
		return fmt.Errorf("cache put %s: %w", key, err)
	}
	if len(record.Data) > MaxRecordSize {
		return fmt.Errorf("cache put %s: record payload is %d bytes, exceeding maximum %d", key, len(record.Data), MaxRecordSize)
	}

	buf, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("cache put %s: encode record: %w", key, err)
	}
	if len(buf) > MaxRecordSize {
		return fmt.Errorf("cache put %s: encoded record is %d bytes, exceeding maximum %d", key, len(buf), MaxRecordSize)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cache put %s: %w", key, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cache put %s: create shard directory %s: %w", key, dir, err)
	}
	tmp, err := os.CreateTemp(dir, "entry-*.tmp")
	if err != nil {
		return fmt.Errorf("cache put %s: create temporary file: %w", key, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cache put %s: write temporary file: %w", key, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cache put %s: sync temporary file: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cache put %s: close temporary file: %w", key, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cache put %s: rename into place: %w", key, err)
	}
	return nil
}

// Delete removes the entry for key. Deleting a missing key is not an error.
func (c *FS) Delete(ctx context.Context, key Key) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cache delete %s: %w", key, err)
	}
	path, err := c.entryPath(key)
	if err != nil {
		return fmt.Errorf("cache delete: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cache delete %s: %w", key, err)
	}
	return nil
}

// Clear removes every entry and leftover temporary file in the cache.
func (c *FS) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cache clear: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := filepath.Join(c.dir, "entries")
	if err := os.RemoveAll(entries); err != nil {
		return fmt.Errorf("cache clear: %w", err)
	}
	if err := os.MkdirAll(entries, 0o700); err != nil {
		return fmt.Errorf("cache clear: recreate %s: %w", entries, err)
	}
	return nil
}

// InvalidateIncompatible removes every entry that this build cannot use:
// schema-incompatible records and unparseable (corrupt) or oversized files.
// It returns the number of entries removed. This is an explicit maintenance
// operation; it walks the entry tree once and is also useful for pruning
// records left by an older schema whose keys are no longer reachable.
func (c *FS) InvalidateIncompatible(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("cache invalidate: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	root := filepath.Join(c.dir, "entries")
	removed := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // no entries yet
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil // ignore leftover temporary files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch c.readEntry(path).state {
		case entryOversized, entryCorrupt, entrySchema:
			if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
				return fmt.Errorf("cache invalidate: remove %s: %w", path, rerr)
			}
			removed++
		}
		return nil
	})
	if err != nil {
		return removed, fmt.Errorf("cache invalidate: %w", err)
	}
	return removed, nil
}

// entryState is the internal classification of a decoded on-disk entry.
type entryState int

const (
	entryOK entryState = iota
	entryMissing
	entryOversized
	entryCorrupt
	entrySchema
	entryError
)

// entryRead is the result of readEntry.
type entryRead struct {
	state entryState
	rec   Record
	err   error
}

// readEntry classifies the entry at path without mutating anything. The path
// is never opened unless it is a regular file: opening a FIFO, device, or
// similar special file directly can block indefinitely, and a directory must
// never be treated as an entry. Non-regular files (including directories,
// FIFOs, sockets, and symlinks) are classified as corrupt without being
// opened, so the normal self-healing path removes them.
func (c *FS) readEntry(path string) entryRead {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return entryRead{state: entryMissing}
		}
		return entryRead{state: entryError, err: fmt.Errorf("cache: stat %s: %w", path, err)}
	}
	if !fi.Mode().IsRegular() {
		return entryRead{state: entryCorrupt, err: fmt.Errorf("cache: entry %s is not a regular file", path)}
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return entryRead{state: entryMissing}
		}
		return entryRead{state: entryError, err: fmt.Errorf("cache: open %s: %w", path, err)}
	}
	defer func() { _ = f.Close() }()

	buf, err := io.ReadAll(io.LimitReader(f, MaxRecordSize+1))
	if err != nil {
		return entryRead{state: entryError, err: fmt.Errorf("cache: read %s: %w", path, err)}
	}
	if len(buf) > MaxRecordSize {
		return entryRead{state: entryOversized, err: fmt.Errorf("cache: entry %s exceeds maximum size %d bytes", path, MaxRecordSize)}
	}

	var rec Record
	if err := json.Unmarshal(buf, &rec); err != nil {
		return entryRead{state: entryCorrupt, err: fmt.Errorf("cache: parse entry %s: %w", path, err)}
	}
	if rec.SchemaVersion != SchemaVersion {
		return entryRead{state: entrySchema, err: fmt.Errorf("cache: entry %s has unsupported schema version %d (want %d)", path, rec.SchemaVersion, SchemaVersion)}
	}
	if err := rec.validateContent(); err != nil {
		return entryRead{state: entryCorrupt, err: fmt.Errorf("cache: invalid entry %s: %w", path, err)}
	}
	return entryRead{state: entryOK, rec: rec}
}

// removeUnusable re-checks the entry under the mutation lock and removes it
// only if it is still unusable (oversized, unparseable, not a regular file,
// or schema-incompatible). The re-check prevents a self-healing removal from
// deleting a valid entry that a concurrent Put just installed: within one
// process the mutex makes read-then-remove atomic with respect to writers.
func (c *FS) removeUnusable(path string) {
	if c.beforeSelfHeal != nil {
		c.beforeSelfHeal()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.readEntry(path).state {
	case entryOversized, entryCorrupt, entrySchema:
		if info, err := os.Lstat(path); err == nil && info.IsDir() {
			// A directory cannot be unlinked; remove its whole subtree so
			// the key becomes writable again instead of wedging Put forever.
			_ = os.RemoveAll(path)
			return
		}
		_ = os.Remove(path)
	}
}
