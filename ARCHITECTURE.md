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

Implemented so far: the bounded worker pool and the central rate limiter
(v0.3, `internal/runtime`, generic and cache-independent), and passive
subdomain discovery (v0.5, `internal/discovery`) as the runtime's first
consumer — external-tool adapters with detection, bounded execution,
parsing/normalization, provenance merging, and cache-before-execute (see
"Passive discovery"). The cache is not part of the runtime: consumer stages
compose "cache-before-execute" around runtime jobs (see "Runtime engine").
The DNS/HTTP/URL/JS pipeline stages, asset graph, scoring, and reports do not
exist yet.

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

The v0.3 runtime engine (`internal/runtime`) provides a single central,
stdlib-only token-bucket limiter gating every job start: `Rate` tokens per
second with a `Burst` capacity (default 1), so the aggregate job start rate
is bounded regardless of concurrency. That covers the global limit; the
concurrency limit is the worker pool itself (exactly `Concurrency` workers).
Per-origin limits, per-tool limits, and request delays are not implemented by
the engine — consumer stages are expected to add them without bypassing the
central limit.

## Cache and resume

`internal/cache` provides the persistent cache foundation. It is
infrastructure only: no stage calls it yet. It is independent of CLI, external
tools, HTTP, DNS, and specific recon stages. The runtime engine (v0.3,
`internal/runtime`) deliberately does not use it: caching is composed by
consumer stages ("cache-before-execute", see "Runtime engine").

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

Entry reads carry a safe-open guarantee: the path is Lstat-pre-checked, then
opened with platform-specific no-follow/non-blocking flags (on unix
`O_NOFOLLOW|O_NONBLOCK`), and the OPENED descriptor is fstat-verified to be a
regular file before any byte is read. A regular file swapped for a FIFO or
symlink between the pre-check and the open therefore can never block a
lock-free `Get` and can never be read: such objects classify as corrupt
promptly and are removed by self-healing.

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

## Runtime engine

`internal/runtime` (roadmap v0.3) is the execution engine: a bounded,
cancellable, rate-limited job pool. It is generic infrastructure — a job is
plain `func(ctx context.Context) (any, error)`, and the engine knows nothing
about discovery, tools, DNS, HTTP, assets, or caching.

### Execution model

- A `Pool` is created from a `Config` (exact `Concurrency`, bounded
  `QueueSize`, default per-job `Timeout`, optional central `Rate`/`Burst`) and
  a lifetime `context.Context`.
- Exactly `Concurrency` worker goroutines run jobs inline; the pool never
  creates a goroutine per job, so at most `Concurrency` jobs execute at any
  instant (plus at most `Concurrency` more parked on the rate limiter or on
  event delivery).
- `Submit` enqueues into a channel of capacity `QueueSize`; a full queue
  blocks the submitter (backpressure) and never grows without bound. A
  per-job deadline (pool default or per-job override) covers both the
  rate-limit token wait and the execution itself.

### Cancellation and shutdown

- Cancellation is context-based everywhere: pool context, submit context,
  shutdown drain context, subscription `Next`, and rate-limit waits.
- Terminal classification is deterministic, in priority order: deadline
  exceeded -> timed out; any other context cancellation -> cancelled; job
  error -> failed; otherwise -> completed. A cancelled job is never reported
  as failed or as success.
- `Shutdown(ctx)` stops new work (`ErrPoolClosed`), drains the queue and
  in-flight jobs, closes all subscriptions, and returns only after every
  pool-owned goroutine has terminated. If the drain context is cancelled
  first, shutdown is forced: remaining queued and running jobs are cancelled,
  the pool still unwinds completely, and `Shutdown` returns an error wrapping
  `ctx.Err()`. During a forced shutdown, terminal events may be dropped for
  subscribers whose buffers are full.
- Inherent limits (cannot be fixed without killing goroutines): a job that
  ignores cancellation can delay shutdown up to its deadline (or indefinitely
  when deadlines are disabled), and queued jobs dropped by a forced shutdown
  receive no terminal event.

### Rate limiting

A single central token-bucket limiter (standard library only) gates every job
start: `Rate` tokens per second, `Burst` capacity (default 1), starting full.
Bucket state is serialized by one mutex and the limiter never sleeps while
holding it, so concurrent waiters cannot deadlock; waits honor context
cancellation; rates at or below zero disable the limiter. The clock is
injectable for deterministic tests.

### Events

Subscribers (`Subscribe(buffer)`) receive started / completed / failed /
cancelled / timed-out events carrying the job ID and pool-clock timestamps.
Buffers are bounded per subscriber and delivery is blocking, so events are
never silently lost during normal operation: a slow subscriber applies
backpressure rather than dropping events. Events are in-memory only;
persistence is the cache layer's concern, and there are no cross-process
semantics.

### Layering decision: the runtime is cache-independent

The runtime deliberately does not import `internal/cache` (and never will).
Cache policy — "cache-before-execute": look up a deterministic cache key, run
the job only on a miss, store the result — belongs to the consumer stages
(for example passive discovery, roadmap v0.5), which compose it around
runtime jobs. This keeps the engine generic and testable, prevents cache
semantics from leaking into scheduling, and lets each stage choose its own
cache key, while the engine still provides the bounded execution,
cancellation, rate limiting, and event plumbing every stage needs.

## Passive discovery

`internal/discovery` (roadmap v0.5) is the runtime's first consumer: passive
subdomain enumeration through three external tools — subfinder, assetfinder,
and amass. It was implemented with the phase requirements below.

### Adapter architecture

Every tool is isolated behind the `Source` interface (`Name`, `Detect`,
`Discover`); the core pipeline contains no `if tool ==` branching. Tool
differences — flag assembly, detection strategy, name — live inside the
adapters (`subfinder.go`, `assetfinder.go`, `amass.go`); execution and
parsing are shared (`runner.go`, `parse.go`). The pipeline acts only on the
interface, so a new tool is a new adapter file plus a registry entry.

### Execution safety

Adapters execute through `exec.CommandContext` with arguments passed as
separate argv values: there is no shell, and target-derived strings can never
become shell syntax or injected flags (tool flags are fixed, and the
normalized target is validated to contain only lowercase letters, digits,
hyphens, and dots). Every execution honors context cancellation, pool
deadlines, and bounded capture. On unix the child runs as the leader of its
own process group and cancellation kills the whole group, so a wrapper script
or PATH shim that spawned a descendant holding the output pipes has that
descendant terminated with the group (unless it escaped into its own session
with `setsid`). The captured streams flow through pipes the runner owns
itself (`os.Pipe` plus its own copy goroutines; see `pipeCopies` in
`runner.go`), whose read ends are force-closed and copy goroutines joined
before `Run` returns on every path: even a descendant that escaped the
process group while holding the write ends can pin no goroutine, file
descriptor, or capture buffer past `Run`'s return. On Windows there are no
POSIX process groups, so only the direct child is killed; a wrapper-spawned
descendant may itself outlive a cancelled run, but it can pin no runner
resource and `Run` never blocks on it. A short wait bound (`waitGrace`)
covers the single residual case of a child that cannot be killed at all (an
unkillable D-state process). stdout and stderr are
collected through size-limited sinks (`DefaultMaxOutput` = 4 MiB per stream;
never an unbounded `io.ReadAll`), overflow is truncated and diagnosed, a
non-zero exit is a structured error (never a panic), and a child killed
because its context was cancelled or timed out is classified by the context
error as `OutCancelled` — never as a clean exit-code failure. Failed,
cancelled, and timed-out executions are classified by the run layer, never by
parsing the tools' messages.

### Tool detection

Detection distinguishes four stages: (1) the executable exists
(`exec.LookPath`), (2) it executes, (3) a version can be determined, and (4)
a capability check succeeds. The result is one of `[OK]` / `[WARN]` /
`[MISSING]` with a human-readable reason, per source:

- subfinder: `-version` (version flag supported; subfinder prints its banner
  on stderr, which detection reads as well as stdout).
- amass: `-version` (version flag supported).
- assetfinder: no reliable version flag; detection runs `-h` and requires
  observable output (Go's flag package prints usage and exits 2 — that is an
  OK capability result, never a MISSING and never a WARN about the flag).

A broken, unsupported, garbled, or timing-out version command is at worst a
WARN, never a MISSING: existence and capability are separate concerns, and a
correctly installed tool is never reported missing because its version flag
misbehaved. Detection runs before the pool, sequentially, once per selected
source, each bounded by `DetectTimeout` (default 5 s). The same
implementation (`DetectAll`) feeds the doctor command's Discovery section and
the discover command's per-source report — there is no second detection path.

### Passive/active boundary

Every adapter invokes only passive enumeration; the exact argv is asserted in
the adapter tests so the boundary cannot silently drift:

```text
subfinder:   subfinder -d <domain> -silent
assetfinder: assetfinder <domain>
amass:       amass enum -passive -d <domain>
```

amass's default active enumeration, its intel mode, and its brute-force mode
are never reachable from RavenRecon. Tools that support their own internal
rate/throttle settings use their defaults; RavenRecon never passes active or
aggressive options.

### Parsing, normalization, and deduplication

Tool stdout is untrusted input. Each non-blank line contributes its first
whitespace-delimited token (this also handles amass's historical
`name (FQDN) --> 1.2.3.4` format). Blank, whitespace-only, CRLF-terminated,
and duplicate lines are handled; lines that do not normalize to a valid Phase
2 host are counted in a malformed diagnostic and never emitted, so bad lines
cannot poison results. Every candidate is normalized only through
`asset.NewDomain`/`asset.NewHost` — there is no second normalization
implementation, so `Example.COM`, `example.com.`, and ` example.com ` produce
the same identity. Deduplication is by Phase 2 identity, both within one
source (per-source sorted host lists) and across sources (`Report.All` merges
same-identity hosts with `asset.MergeHosts`: the earliest observation's
provenance wins, ties resolve to the first-encountered source, and no
duplicate assets are emitted).

### Provenance

Every host carries provenance: the source name (per `internal/asset`, the
core model names generic capabilities, so discovery uses the tool name as the
source and records the discovery timestamp from an injectable clock). The
same identity found by two tools carries two distinct provenance sources and
merges through the Phase 2 merge primitives.

### Cache integration

Discoveries are cached with Phase 3 "cache-before-execute", composed around
runtime jobs inside the discovery layer (the runtime itself remains
cache-independent). The key (`cache.NewKey`) contains every input that
materially changes the result:

- operation: `"passive-discovery"`
- target: the canonical Phase 2 domain identity (`domain:example.com`); raw
  user input never reaches a key
- result-relevant configuration: today exactly `{"mode": "passive"}` — any
  future invocation mode that changes results must extend this map; timings,
  rate limits, concurrency, and output caps must never enter the key
- tool identity: name plus detected version (empty for assetfinder), because
  a tool version change can change results

Only a completed, unexpired record for the exact key is a usable hit.
Failed, cancelled, incomplete, expired, corrupt, or schema-incompatible
entries are never treated as results: the cache surfaces them as distinct
miss states, and a stale record can never be served for a different target
or configuration.

Tools whose version cannot be determined (`Version == ""` — assetfinder
always, and any WARN detection with a broken version flag) are not cached at
all: an unknown version cannot be distinguished from any other unknown
version, so the pipeline builds no key, performs no Get and no Put, and the
source executes fresh on every run. This guarantees an undetectable tool
upgrade can never serve stale results.

### Partial result semantics

- Non-zero exit with usable output: partial — the captured hosts are kept,
  reported as `partial`, and stored as `StatusIncomplete` with the partial
  data attached (a later run may inspect it; discovery has no sub-work units,
  so a rerun reruns the source).
- Cancellation or timeout: `StatusCancelled`; the report keeps whatever each
  job observed.
- Clean failure with no usable output: `StatusFailed`.
- Established success (exit 0, stdout within the capture cap): `StatusCompleted`.
  Empty-but-successful output is a legitimate completed-empty result.
- Truncated stdout (oversized stream): stored `StatusIncomplete` — the
  captured set is incomplete by definition.

Tool execution failures are never cached as successful discoveries. The
cache is disabled by default (`CacheConfig.Enabled = false`); the discover
command wires it only when configuration enables it, and `--no-cache`
overrides that.

### Runtime integration and rate limiting

One `runtime.Pool` per discover run, configured from `discovery.Config`
(Concurrency, QueueSize, per-job Timeout, Rate/Burst) — mapped in the CLI
from the global configuration. Each selected source is exactly one pool job;
discovery spawns no goroutines of its own, and there is no second worker
pool. `Run`'s `Shutdown` is the join point: it drains queued and in-flight
jobs with a bounded budget, and the report carries every job's outcome.

The pool's central limiter gates job STARTS only. It does not and cannot
rate-limit network requests inside an external binary: subfinder and amass
perform their own throttling, and RavenRecon never fakes per-request limits
for external processes. The global rate limit remains respected for
RavenRecon-owned work; tool-internal traffic is the tool's own
responsibility.

### Configuration and CLI

The global `config.Discovery` section adds only: source selection
(`Sources`), optional per-tool executable path overrides (`Bin`), and
per-tool execution / detection / capture tunables (`Timeout`,
`DetectTimeout`, `MaxOutputSize`); all default to the stage's safe defaults,
so no discovery-specific configuration is required.

`ravenrecon discover <domain>` validates and normalizes the target through
the Phase 2 asset model, runs pooled discovery (caching only if enabled in
configuration), and prints per-source detection `[OK]`/`[WARN]`/`[MISSING]`
states with reasons, per-source outcomes, hosts with provenance, and the
merged unique-host list. Options (after the domain): `--sources <a,b>` and
`--no-cache`. The doctor command prints the same per-source detection states
through the shared `DetectAll` implementation. Help text documents exactly
these behaviors. Ctrl-C or SIGTERM cancels a discover run gracefully: the
partial report is still printed and the command exits 1 with a
`run interrupted` error (a per-source cancelled outcome caused by a job
deadline does not change the exit code); a second signal force-exits
immediately with status 130 (128+SIGINT).

### Known limitations

- Discovery is passive and stdout-based; tools that write results only to
  files or databases are unsupported by design.
- No Windows-specific retry of failed detection on `.exe` suffixes: binary
  overrides must name an executable resolvable by `exec.LookPath`.
- IDN/Unicode targets are rejected by the Phase 2 asset model (normalization
  is ASCII-only) and therefore unsupported.
- A per-run cache miss reruns the whole source; there are no sub-work units
  to resume from a partial record.
- `amass enum -passive` output format varies across versions; the parser
  tolerates the two known forms and counts anything else as malformed.
- Tool-internal network traffic is not subject to RavenRecon's rate limiter
  (see "Runtime integration and rate limiting").
- On Windows, cancellation kills only the direct child process (no POSIX
  process groups); a wrapper script that spawned a pipe-holding descendant
  can therefore outlive a cancelled run, though Run's own pipe teardown
  guarantees the CLI never hangs and the descendant can pin no runner
  goroutine, file descriptor, or capture buffer.
- Tools whose version cannot be determined (assetfinder always; any WARN
  detection with a broken version flag) are never cached: unknown-version
  runs bypass the cache entirely — no read, no write — and execute fresh on
  every run, so an undetectable upgrade can never serve stale results.
  Versioned tools cache on the detected version (a detectable upgrade misses
  and re-executes).

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

## v0.3 boundary

Implemented:

* CLI foundation
* configuration defaults
* version metadata
* basic tests
* normalized asset model (see "Asset model" above)
* filesystem-backed cache and resume foundation (see "Cache and resume"
  above; roadmap v0.4, implemented before the runtime engine per phase
  sequencing)
* runtime engine (see "Runtime engine" above; roadmap v0.3): bounded worker
  pool with exact concurrency, bounded backpressure queue, central
  token-bucket rate limiter, context cancellation, graceful and forced
  shutdown, and lossless event subscriptions
* passive discovery (see "Passive discovery" above; roadmap v0.5):
  subfinder/assetfinder/amass adapters with tool detection, bounded
  execution, passive-only invocations, Phase 2 normalization/dedup and
  provenance merging, cache-before-execute with statused records, the
  `discover` CLI command, and the doctor's per-source detection section

Planned, not yet implemented:

* discovery engines beyond passive subdomain enumeration (DNS, HTTP, TLS,
  URL, JS)
* asset store, graph, and correlation engine
* reporting and terminal UI
