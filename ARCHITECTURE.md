# RavenRecon Architecture

## Purpose

RavenRecon is designed as a reconnaissance framework rather than a collection of shell commands.

The architecture separates:

- CLI
- configuration
- scheduling
- execution
- rate limiting
- caching
- asset modeling
- tool adapters
- pipeline stages
- output

External tools are adapters.

They are not the architecture.

## Planned architecture

The following describes the target architecture. Not all components exist yet.

```text
CLI
 |
 v
Configuration
 |
 v
Scheduler
 |
 +--> Worker Pool
 |
 +--> Rate Limiter
 |
 +--> Cache
 |
 v
Pipeline
 |
 +--> Discovery
 +--> DNS
 +--> HTTP
 +--> TLS
 +--> Crawling
 +--> JavaScript
 +--> Technology
 +--> Secret Analysis
 |
 v
Asset Graph
 |
 v
Scoring
 |
 v
Reports
```

## Asset model

The asset model (implemented in `internal/asset`) provides normalized types
for reconnaissance data:

* Domain
* Host
* IP
* Port
* Service
* URL
* Endpoint
* JavaScript

Deferred to later phases: Technology, SecretCandidate, Finding.

Every implemented asset has:

* a canonical, normalized representation
* a deterministic, namespaced identity for deduplication
* provenance (source, discovery time, optional reference and confidence)
* deterministic merge primitives that refuse to merge distinct assets
* JSON serialization

Identity values are namespaced by asset kind (`domain:example.com` vs
`host:example.com`), so different asset kinds can never collide.

Relationships are represented by the typed `Relationship` primitive
(Host -> IP, IP -> Port, Port -> Service, Host -> URL, URL -> Endpoint,
URL -> JavaScript). This phase provides the representation only; the graph
store, traversal, and correlation engine are planned for a later phase.

## Pipeline requirements

Major pipeline stages should support:

* cancellation
* bounded concurrency
* timeouts
* rate limiting
* deduplication
* caching
* structured errors
* deterministic behavior where practical
* resumability

## External tools

External tools must be isolated behind adapters.

An adapter should:

1. Validate configuration.
2. Build structured arguments.
3. Execute with context cancellation.
4. Capture output safely.
5. Parse the result.
6. Normalize it into RavenRecon types.
7. Return structured errors.

Never construct shell commands by concatenating untrusted strings.

## Concurrency

RavenRecon must use bounded concurrency.

Do not create an unbounded goroutine for every:

* target
* domain
* host
* URL
* endpoint
* result

Long-running operations must support `context.Context`.

## Rate limiting

Rate limiting must be centralized where practical.

Individual adapters should not independently invent incompatible rate-limit behavior.

The runtime should eventually support:

* global limits
* per-origin limits
* per-tool limits
* concurrency limits
* request delays
* cancellation

## Cache and resume

`internal/cache` provides the persistent cache foundation. It is
infrastructure only: no stage calls it yet, and the runtime engine that will
consume it is deferred. It is independent of CLI, external tools, HTTP, DNS,
and specific recon stages.

### Cache keys

`cache.NewKey` derives a 64-character hex SHA-256 digest from a canonical JSON
payload containing:

- the cache `SchemaVersion` (currently `1`) — a schema bump makes every old
  key unreachable, invalidating old data by construction
- the operation, a stable namespaced capability name ("passive-discovery",
  "dns.resolve", ...)
- the normalized target: the Phase 2 canonical asset identity
  (`asset.Identity{Kind, Value}.String()`, e.g. "host:example.com"). Raw user
  input never enters a cache key; Phase 2 normalization happens first
- the operation's result-relevant configuration as sorted key/value pairs
  (only values that materially change the result's meaning)
- the external tool name/version when the operation's results depend on it

The key contains no input-derived bytes, so it is safe to embed in filesystem
paths: no user-controlled string ever reaches a path. Two equivalent
normalized inputs always produce the same key; different operations, targets,
or relevant configurations never collide. Timing, rate limits, TTL, and cache
location are deliberately not part of a key.

### Cache records

Entries are structured, self-describing JSON records (`Record` in
`internal/cache/record.go`) carrying schema version, operation, target, tool,
creation time, a `Status` (completed / failed / cancelled / incomplete), a
structured `Data` payload (any JSON document; never terminal output), and
optional metadata. Records are versioned; a build never interprets a record
whose schema version it does not support.

### Backend

`cache.Open(dir)` serves `Get`, `Put`, `Delete`, and `Clear` over a
deterministic filesystem layout:

```text
<dir>/entries/<aa>/<bb>/<key>.json
```

where `<aa>/<bb>` is a two-level shard from the key digest, so lookups are
O(1) in the number of entries and no single directory grows unboundedly.
Writes are crash-safe: content is written and fsynced to a unique temporary
file in the entry's directory and atomically renamed over the final name. A
reader therefore sees either the previous or the new complete entry, never a
partial one. The entry's parent directory is deliberately not fsynced after
the rename: a power loss may lose the rename itself (the entry reverts to its
previous state), but it can never expose partially written content. Cache directories and files are created with `0700`/`0600`
permissions. Entries are bounded by `MaxRecordSize` (16 MiB) on both write and
read, so a runaway result cannot exhaust memory or disk through the cache.

### Outcomes

`Get` never returns an unusable entry as a valid result. Outcomes distinguish
hit, miss, expired, corrupt, schema-incompatible, incomplete (exists but not
successful), and error; `Outcome.IsMiss` is the coarse "no valid result"
predicate callers use to decide whether to execute work. Corrupt, oversized,
and schema-incompatible entries are removed on read (self-healing) so the next
execution writes a fresh entry.

### TTL

An optional per-cache TTL (default 0 = disabled) is measured from the record's
creation time; expired entries are reported as expired and never as hits. No
eviction machinery exists beyond `Delete` and `Clear`.

### Resume semantics

A previously completed operation is reused only when its computed key — and
therefore its schema, operation, normalized target, configuration, and tool
identity — matches and its record is `completed` and unexpired. Entries with
failed, cancelled, or incomplete status are surfaced as `StateIncomplete` with
their partial `Data` attached so a future run can continue without repeating
finished sub-work; the cache itself never treats them as success. If the TTL
has also elapsed, expiration takes precedence and such records are reported as
`StateExpired` instead, still with their partial `Data` attached.

### Concurrency model

The cache is safe for concurrent goroutines within one process: reads are
lock-free (atomic rename guarantees complete files), mutating operations
(`Put`/`Delete`/`Clear` and self-healing removal) are serialized by an
internal per-instance mutex, and concurrent writes of the same key are
last-writer-wins with every intermediate file always a complete record. A
mutex-guarded re-check prevents a self-healing removal from deleting a valid
entry that a concurrent `Put` just installed.

Across processes, individual reads and writes are atomic-rename safe, but
there is no cross-process locking: same-key writers are last-writer-wins,
read-modify-write/check-then-act is not coordinated, and a narrow race can let
a one-process self-healing removal delete an entry another process just wrote.
No multi-process locking is claimed or tested. Leftover temporary files from a
crashed write are inert (never read as entries) and are removed by `Clear`.

## Configuration precedence

Future configuration should follow:

```text
CLI flags
   ↓
Environment
   ↓
Config file
   ↓
Defaults
```

## Safety boundary

RavenRecon is reconnaissance-focused.

Do not add:

* credential stuffing
* password spraying
* authentication brute force
* persistence
* automated exploitation
* automatic vulnerability submission

## v0.2 boundary

Implemented:

* CLI foundation
* configuration defaults
* version metadata
* basic tests
* normalized asset model (see "Asset model" above)
* filesystem-backed cache and resume foundation (see "Cache and resume"
  above; roadmap v0.4, implemented before the runtime engine per phase
  sequencing)

Planned, not yet implemented:

* runtime scheduler and worker pool
* discovery engines (DNS, HTTP, TLS, URL, JS)
* asset store, graph, and correlation engine
* reporting and terminal UI
