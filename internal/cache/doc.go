// Package cache provides RavenRecon's persistent, filesystem-backed cache
// foundation, used by future runtime stages to skip repeated reconnaissance
// work and to resume interrupted scans.
//
// Design summary:
//
//   - Deterministic keys. cache.NewKey derives a 64-character hex SHA-256
//     digest from the operation, the canonical Phase 2 asset identity
//     (e.g. asset.Identity{Kind, Value}.String(), such as
//     "host:example.com"), the operation's result-relevant configuration, and
//     (where applicable) the external tool and version. See key.go.
//
//   - Structured records. A cache entry is a versioned, self-describing JSON
//     record (record.go) whose Status distinguishes completed, failed,
//     cancelled, and incomplete work. Terminal output is never the primary
//     data model; results live in the structured Data payload.
//
//   - Filesystem backend. Entries are stored at
//     <dir>/entries/<aa>/<bb>/<key>.json where the two-level shard is derived
//     from the key digest, so lookups are O(1) in the number of entries. With
//     uniformly distributed key digests there are 65,536 possible second-level
//     shards, each holding an expected ~N/65536 entries; the maximum entries
//     in any one shard is unbounded. Writes are crash-safe: content is
//     written and synced to a unique temporary file in the entry's directory
//     and atomically renamed over the final name. A reader therefore sees
//     either the previous or the new complete entry, never a partial one.
//
//   - Corruption handling. Unparseable, oversized, or schema-incompatible
//     entries are never returned as valid results. They are reported as
//     distinct outcome states (see outcome.go), removed on read
//     (self-healing) so the next execution writes a fresh entry, and are
//     never treated as successful hits.
//
// Concurrency: the cache is safe for concurrent goroutines within one
// process. Atomic rename also makes individual cross-process reads and
// writes safe, but there is no cross-process locking: concurrent same-key
// writers are last-writer-wins, read-modify-write is not coordinated across
// processes, and a narrow race can let a one-process self-healing removal
// delete an entry another process just wrote. No multi-process locking is
// claimed or tested.
package cache
