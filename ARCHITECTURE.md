# RavenRecon Architecture

## Reader's map (agents, read this first)

This file is a reference, not a novel — never read it in full. Read only
the sections relevant to the task at hand (typically one or two); the map
below is the index. Line ranges describe the current file state — if an
edit shifts them, re-grep the `^#` headings and refresh the table.

| Section | Lines | What's inside |
|---|---:|---|
| Purpose | 51-72 | what the framework is: layer split; adapters are not the architecture |
| Planned architecture | 72-174 | historical target diagram — read only for context on why, never as current state |
| Asset model | 175-222 | typed asset model, identity/dedup, provenance, merge — the one normalization point |
| Pipeline requirements | 223-236 | cross-cutting stage requirements: cancellation, bounding, caching, determinism |
| External tools | 237-252 | adapter rules: structured args, context, safe output capture; no shell interpolation |
| Concurrency | 253-267 | bounded-concurrency rules; context.Context for long-running operations |
| Rate limiting | 268-282 | central token-bucket limiter in the runtime; what stages must add themselves |
| Cache and resume | 283-426 | persistent fs cache: crash-safe writes, self-healing, schema-versioned keys |
| Cache and resume — keys | 291-312 | key composition: schema version, config, tool version, operation, normalized target |
| Cache and resume — records | 313-321 | record shape, statuses, strict decode re-validation |
| Cache and resume — backend | 322-349 | filesystem backend layout, atomic writes, self-healing |
| Cache and resume — outcomes | 350-358 | per-key outcome vocabulary and metrics |
| Cache and resume — TTL | 359-364 | expiration semantics |
| Cache and resume — resume semantics | 365-375 | how cache hits resume runs; partial/incomplete never served from cache |
| Cache and resume — concurrency model | 376-392 | bounded cache access under the runtime pool |
| Cache and resume — instrumentation | 393-426 | observer option: exactly one canonical hit/miss event per Get |
| Runtime engine | 427-505 | bounded pool, central rate limiter, cancellation/shutdown, observer bridge; cache-independent |
| Passive discovery | 506-723 | subfinder/assetfinder/amass adapters, tool detection, merge, cache-before-execute |
| DNS pipeline | 724-910 | A/AAAA/CNAME resolution into typed observations; library only |
| HTTP probing | 911-1251 | root-path probes, TLS metadata capture, observations/relationships; library only |
| URL intelligence | 1252-1464 | canonical-URL streaming, parameter extraction, endpoint classification; gau/waybackurls/waymore |
| Technology detection | 1465-1656 | fingerprint engine + database, analyzers, confidence scoring |
| JavaScript intelligence | 1657-1865 | discovery/fetch/parse/analyze of script URLs; adapters; bounded retention |
| Secret intelligence | 1866-2092 | evidence & secret-candidate engine: patterns, entropy, context, correlation |
| Priority engine | 2093-2295 | scoring catalogs, correlation, attack paths, recommendations |
| Detection framework | 2296-2810 | Finding model, rule registration, dependency scheduling, execution, metrics |
| Detection framework — SDK contract | 2515-2719 | v1.2.5 frozen rule-author SDK (API 1.0): lifecycle, rule/finding contracts, pack story |
| Detection framework — SDK stability policy | 2720-2810 | versioning contract, reopening criteria |
| Reporting framework | 2811-2995 | report model, JSON/CSV/Markdown/HTML exporters, summaries, atomic writes |
| Event bus | 2996-3138 | canonical event model + bounded non-blocking bus; observer-only |
| Terminal observability (TUI) | 3141-3233 | single-goroutine controller, deterministic frames; live stage feed with data-source gating; wired into `scan --tui` (v1.4) |
| Configuration precedence | 3234-3247 | CLI flags → environment → config file → defaults |
| Safety boundary | 3248-3260 | recon-only: what must never be added |
| v0.3 boundary | 3261-3487 | implemented-vs-planned inventory of every subsystem |

**Before Tier C work on package X: read only its section(s) from this map.**

**Design history lives in the narrative sections; current-state facts are in the per-subsystem sections.**

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
The DNS pipeline (roadmap v0.6, sub-milestone 5A; `internal/dns`) and the
HTTP probing pipeline (roadmap v0.6, sub-milestone 5B; `internal/httpprobe`)
exist as library-level stages — DNS: A/AAAA/CNAME resolution into typed
Phase 2 observations with per-(host, type) caching and typed relationships
(see "DNS pipeline"); HTTP: root-path GET probes of every host's http and
https targets with typed, cached observations, bounded limits, and typed
relationships (see "HTTP probing"); neither has a CLI command yet. The URL
intelligence pipeline (roadmap v0.7, sub-milestone 6B; `internal/urlintel`)
is the next library-level stage — canonical-URL streaming with parameter
extraction, endpoint classification, per-(URL, adapter) caching, and typed
graph edges (see "URL intelligence"); its historical-URL tool adapters
landed in sub-milestone 6C (`internal/urlintel/adapt`, see "URL
intelligence — Historical-URL tool adapters"). The JavaScript intelligence
pipeline (roadmap v0.8, phase 7; `internal/jsintel`) is a
library-level stage — discovery seams, a bounded fetch engine, the
stdlib-only parser, import expansion, source map detection, endpoint and
secret-candidate extraction, JS technology detection, and two
cache-before-execute operations (see "JavaScript intelligence"); it has no
CLI command yet. The secret intelligence pipeline (phase 8;
`internal/secrentel`) is the latest library-level stage — the Evidence &
Secret Intelligence Engine: bounded documents are scanned against a
compile-once pattern database and every candidate is classified into a
structured evidence model with entropy, context, multi-evidence
correlation, confidence scoring, explicit false-positive suppression, a
`secret.scan` cache-before-execute record, and an offline verification
queue (see "Secret intelligence"); it has no CLI command yet. The
priority pipeline (phase 9; `internal/priority`) is the latest
library-level stage — the Attack Surface Intelligence Engine: canonical
assets reduced to scoring signals are matched against two compile-once
indicator catalogs, every score is a fully explained factor list carrying
evidence and rendered reconnaissance recommendations, surfaces correlate
into groups and evidence-tied attack-path hypotheses, and the engine
stage composes cache-before-execute (operation `priority.score`) around
bounded pool jobs with strict decode re-validation (see "Priority
engine"); it has no CLI command yet. The detection framework (phase 10;
`internal/detect`) is the latest library-level stage — the Detection
Framework & Rule Engine: immutable, validated rules execute against a
normalized knowledge-graph snapshot on the shared runtime pool with
dependency-ordered levels, per-rule deadlines, panic isolation, a
`detect.rule` cache-before-execute record with strict decode
re-validation, execution metrics, and the canonical Finding model the
Phase 2 asset model gained with this phase (see "Detection framework");
it has no CLI command yet. The reporting framework (phase 11;
`internal/report`) is the latest library-level stage — the Reporting
Framework & Evidence Export: a caller-composed Context is normalized once
into the canonical report Model (validated through the Phase 2 builders,
deduplicated, merged, identity-sorted, with statistics, run/error
summaries, and a digest computed exactly once), and validated, registered
reporters (JSON, CSV, Markdown, HTML) render it on the shared runtime
pool through atomic crash-safe file writes with an optional
`report.render` cache-before-execute record (see "Reporting framework");
it has no CLI command yet. The asset graph store does not exist yet;
scoring exists only as the priority engine's library-level surface
judgments.

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
* Parameter

The technology asset landed with phase 6.5 (`asset.Technology`,
`asset.Evidence`) and the secret candidate with phase 7
(`asset.SecretCandidate`). Phase 8 extended the secret vocabulary to 35
canonical types, added the `secret` detection method for evidence records,
and added the `url -> secret_candidate` and `secret_candidate -> evidence`
relationship kinds (see "Secret intelligence"). Phase 10 added the
canonical Finding (`asset.Finding`, identified by "ruleID@subject" under
the `finding` kind) and the `detect` evidence method for records produced
by rule execution.

Deferred to later phases: the asset store/graph and the graph correlation
engine.

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
URL -> JavaScript, URL -> Parameter, Endpoint -> Parameter). This phase
provides the representation only; the graph store, traversal, and
correlation engine are planned for a later phase (the priority
engine's identity-anchored `Correlate`, phase 9, is not that engine: it
groups scored surfaces by identity-derived anchors without graph
traversal).

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

### Cache instrumentation

The cache (`internal/cache`, Phase 12) is instrumented like the runtime
pool: `Open` accepts an optional observer through `WithObserver` (an
`internal/event` Observer; the `Bus` satisfies it). A nil observer is the
off switch: zero behavior change and a single nil check per lookup. When
set, every `Get` publishes exactly one canonical `cache_hit` or
`cache_miss` event (`event.CacheAccess`) carrying the REAL outcome of the
lookup:

- `event.CacheAccess.Key` <- the `cache.Key` digest (the 64-character
  lowercase hex SHA-256; by construction it encodes the schema version,
  the operation, the normalized target, the result-relevant
  configuration, and the tool identity — see "Cache keys");
- `event.CacheAccess.State` <- `cache.Outcome.State.String()` ("hit",
  "miss", "expired", "corrupt", "schema-incompatible", "incomplete",
  "error");
- `event.CacheAccess.Hit` <- `cache.Outcome.IsHit()` (true exactly for
  `StateHit`), and the kind is `cache_hit` exactly when it is true, so the
  payload can never contradict its kind (the bus enforces that).

The event timestamp is the cache's own injected clock (`WithClock`), so
deterministic tests can pin it. The cache measures no lookup latency
today, so none is reported. Emission never blocks a cache operation: the
observer is invoked inline (one nil check per lookup) and the Observer
contract bounds the call; with the canonical `Bus` observer, publish is a
non-blocking enqueue that drops and counts on a full subscriber buffer.
Only `Get` emits — `Put`/`Delete`/`Clear`/`InvalidateIncompatible` are
not lookups and publish nothing, and the eviction/self-healing paths are
reported through the outcome of the `Get` that triggered them, never as
separate events. The instrumentation is purely additive: the cache's
read/write semantics, self-healing, and outcome vocabulary are unchanged
by it (pinned by outcome-equality tests).

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

Phase 12 adds optional canonical observability instrumentation on top of
this subscription model: `Config.Observer` (an `internal/event` Observer;
nil = zero behavior change) makes the pool emit canonical pool-boundary
events — scan/worker/task lifecycle, phase transitions, honest progress,
and shutdown — alongside the runtime `Event` stream, and `Config.Deriver`
converts task results into derived events at the pool-job boundary (see
"Runtime pool instrumentation" under "Event bus").

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

## DNS pipeline

`internal/dns` (roadmap v0.6, sub-milestone 5A of Active Infrastructure)
implements the DNS resolution stage as a library capability: it resolves
discovered host assets and attaches typed DNS observations to the Phase 2
asset model. It is a pipeline stage, not a CLI command — there is no
`ravenrecon dns` yet (HTTP probing has landed as 5B, with TLS metadata 5C
captured as part of the probe; see `ROADMAP.md`).

### Records and relationships

Exactly three record families are supported: A, AAAA, and CNAME. Every
observation is normalized through the Phase 2 asset model — `asset.IP` for
addresses, `asset.Host` for CNAME targets — and every host result carries
typed `asset.Relationship` edges: `host -> address`
(`RelationshipHostToIP`) and `host -> CNAME target`
(`RelationshipHostToCNAME`). CNAME queries use the stdlib's `LookupCNAME`,
which follows the chain to the final canonical target. When a host's CNAME
query completes with a target, the direct target's A and AAAA records are
resolved at depth exactly 1, so the canonical target becomes a first-class
host asset with its own address edges; no deeper recursion ever happens, so
CNAME loops are impossible by construction (see "Known limitations" for the
multi-hop flattening trade-off). Relationships are deduplicated by edge
identity and emitted sorted, deterministically.

### Scope boundary

`Resolve` accepts an explicit host list plus the run's declared target
domain. Every input hostname is re-validated canonically through the Phase 2
asset model and must be the target domain itself or a subdomain of it;
anything non-canonical (raw input, uppercase, trailing dots, IP literals,
hand-built structs) or out-of-domain is rejected before a single query is
issued. A queried host's CNAME target is a DNS observation and may
legitimately point outside the target domain (cross-domain CNAMEs are
observed, never chased beyond depth 1). The package is a boundary, not an
arbitrary-scanning feature.

### Concurrency and rate limiting

One bounded `runtime.Pool` per run owns all scheduling, with exactly one job
per input host: `Concurrency` workers (default 8), a bounded queue (default
256), and a per-job deadline (default 30 s) covering the rate-limit waits
and the queries themselves. Each job performs its bounded per-type queries
sequentially and honors cancellation: once the job context is done, no
further query is issued and every un-attempted type is recorded cancelled.

The pool's job-start rate limiting is deliberately disabled; instead one
central token-bucket limiter (the runtime engine's `Limiter`; default 20
queries/second, burst 1) gates every outbound query's DISPATCH: each
cache-missing query waits for a token before the resolver is called, so the
aggregate query dispatch rate is bounded regardless of concurrency.
Rate-limiting honesty: the limiter controls only RavenRecon's own dispatch
pacing. It does not and cannot throttle traffic the system resolver sends —
the resolver performs its own server selection, retries, and nameserver
rotation per `/etc/resolv.conf`, and RavenRecon never claims to control any
of that and never fakes per-request limits it does not enforce.

### Caching

Each (host, record type) pair is cached under its own Phase 3 key composed
of exactly the operation (`"dns.resolve"`), the canonical Phase 2 host
identity, and the record type — nothing else: timings, timeouts,
concurrency, and rate limits never enter a key, and the fixed answer cap is
deliberately not configuration (a cap change never invalidates an entry,
and truncated entries are never served under any cap).
Partial results are naturally per-type: an A hit with a fresh AAAA miss is
normal, never all-or-nothing. Record statuses mirror the Phase 4
conventions: positive answers, legitimate empty answers (NODATA-style), and
NXDOMAIN observations are all stored `completed`; truncated answer sets are
stored `incomplete` and never served as hits; failed, timed-out, and
cancelled types are stored `failed`/`cancelled` and can never be served as
success. A cache hit performs zero DNS requests (asserted in the benchmark
harness). TTL semantics are the Phase 3 cache's own: records expire per the
cache instance's configured TTL and expired records are reported as misses.

### Limits

- `MaxAnswersPerType` (64, fixed constant): per-type answer retention is
  deduplicated by Phase 2 identity, sorted, and capped; oversized sets are
  retained truncated and reported/stored `incomplete` — never completed.
- CNAME depth is ≤ 1 by construction: only the direct target's A/AAAA are
  resolved, exactly once, with no recursion.
- Per-job deadline: 30 s by default (`DefaultConfig.Timeout`), covering the
  central limiter wait and the queries.
- Pool bounds: exactly `Concurrency` workers (default 8) and a bounded
  queue (default 256); no goroutine per host, query, or answer.
- Retention is bounded: answers are retained only as normalized
  `netip.Addr`/string values with bounded counts and per-type caps, and
  cache records are bounded by the cache's own `MaxRecordSize`.

### Cancellation

Cancellation is classified per type: a query cancelled before dispatch is
recorded cancelled without issuing a request; a query cancelled while in
flight is recorded cancelled (the surfaced stdlib-shaped error, a
`*net.DNSError` wrapping the context error, is classified through
`classifyQueryError`, which checks context errors before resolver flags);
a host whose job never started keeps its initialized cancelled status (see
"Partial result semantics").

Stdlib known limitation (verified against the Go 1.26 pure-Go resolver
source): the resolver does not abort an in-flight UDP query when its context
is cancelled — the in-flight read fails only at the per-attempt deadline
(resolv.conf timeout × attempts), so the query may return as late as that
deadline, and the surfaced error then carries `IsTimeout|IsTemporary` with
no reachable context error (classified `ErrTimeout`, the honest
classification for the query the resolver actually performed). RavenRecon's
own code issues no further queries once its context is done, and the pool
shutdown budgets bound the overall drain: the drain context is the per-job
timeout plus a 15 s grace (30 s force budget when per-job deadlines are
disabled), which comfortably covers the default resolv.conf ≈ 5 s × 2
attempts plus a possible TCP retry. Cancellation of an in-flight query is
therefore not prompt, only bounded.

### Partial result semantics

A host's overall status is derived from its per-type outcomes in fixed
priority order (see `classifyHost` in `run.go`):

1. any cancelled type -> `cancelled` (run teardown; never success)
2. any truncated retention -> `incomplete`
3. any timed-out type -> `incomplete`
4. failed with at least one completed type -> `incomplete` (partial)
5. every attempted type failed -> `failed`
6. otherwise (all types completed, including NXDOMAIN and legitimate empty
   answers) -> `completed`

The successful parts of a partial result are always retained, with their
typed assets and relationships, and are never discarded.

### DNS security considerations

- DNS rebinding boundary: the pipeline makes resolution-time observations
  only. It never fetches content and never pins an address for later
  revalidation, so rebinding risk does not materialize here — it
  materializes at the HTTP stage (5B), which consumes these observations
  with its own policy (see "HTTP security considerations").
- Malicious answer sizes: raw answer sets are capped at `MaxAnswersPerType`
  with truncated retention recorded `incomplete`, and cache records are
  bounded by the cache's `MaxRecordSize`; an oversized hostile response can
  never exhaust memory or disk and can never be served as a completed
  result.
- CNAME loops: impossible by construction — the CNAME chain is followed
  once by the stdlib's `LookupCNAME`, and the pipeline recurses to depth at
  most 1 (the direct target's A/AAAA only).
- Resolver exhaustion: query dispatch is bounded by the pool's exact
  concurrency (default 8) and the central limiter (default 20 q/s), and
  every job has a per-job deadline (default 30 s); a hostile or failing
  resolver can delay a run only within those bounds.
- Cancellation leaks: the pool's `Shutdown` is the join point — it drains
  queued and in-flight jobs with bounded budgets and returns only after
  every pool-owned goroutine has terminated; leak tests
  (`TestResolveNoGoroutineLeakAfterShutdown`,
  `TestResolveNoGoroutineLeakAfterCancellation`) pin this behavior.
- Cache poisoning: the cache stores exactly the answers the resolver
  observed, keyed by host + record type + configuration. There is no
  resolver authentication, no DNSSEC validation, and no upstream trust: the
  trust model is "trust the OS resolver" — the same trust the system's own
  applications place in it. Stored answers are re-validated through the
  Phase 2 asset model before they can be served as hits
  (`decodeStoredType`), and records whose identity fields contradict their
  key are deleted and recomputed, so a corrupt or tampered record can never
  produce bogus assets.
- Identity collisions: every observation enters the asset model only
  through the Phase 2 normalizers — `asset.NewIP` unmaps IPv4-mapped IPv6
  addresses, so `::ffff:192.0.2.1` and `192.0.2.1` deduplicate to one
  identity — and identities are namespaced by kind, so a hostname can never
  collide with an address.

### Known limitations

- Multi-hop CNAME chains are flattened: `LookupCNAME` follows the chain to
  the final canonical target, so intermediate hops are not observed and the
  relationship is `host -> final-target` (a multi-hop chain loses its
  intermediate edges).
- The stdlib pure-Go resolver completes an in-flight query at its own
  per-attempt deadline before returning on cancellation (see
  "Cancellation"); cancellation of an in-flight query is not prompt, only
  bounded.
- The system resolver's own retries and server selection are not subject to
  RavenRecon's limiter (see "Concurrency and rate limiting").
- Library capability only: no CLI command.
- Answers come from the OS resolver with the OS resolver's trust model; no
  DNSSEC validation is performed or claimed.
- All tests are hermetic: a fake resolver and a real filesystem-backed
  cache, never the public Internet (see `bench_test.go`).

## HTTP probing

`internal/httpprobe` (roadmap v0.6, sub-milestones 5B and 5C of Active
Infrastructure) implements the HTTP probing stage as a library capability:
it probes discovered host assets at their two root targets and attaches
typed HTTP observations — including TLS metadata (5C) — to the Phase 2
asset model. It is a pipeline stage, not a CLI command — there is no
`ravenrecon http` yet.

### Probe model

Every host is probed at exactly two targets — `http://host/` and
`https://host/` — with a GET on the root path (canonical Phase 2 form:
default port removed, so the two probe targets of one host are the distinct
identities `url:http://host` and `url:https://host`). The probe target URL
is the probe's IDENTITY — the observed asset and the cache-key target — and
it is never a dial address. Requests carry the canonical host (Host header,
and SNI for https) while the transport resolves and dials, and the dial
destination is deliberately a transport detail: the identity of the
observation is independent of where the bytes went. This is the probe seam
the tests and benchmarks use — a transport whose dial goes to a resolved
loopback address for any destination. Honest statement: when the caller
provides no resolved addresses, probing dials through the transport's own
resolution; the caller-provided addresses (DNS-pipeline observations, keyed
by canonical host name) are never dialed directly either — they only feed
`ip -> port` relationship edges for ports observed open.

### Observation model

Each probe records a typed outcome, in a fixed classification order:

- HTTP response received — `completed`, with any status code (404- and
  500-class results are ordinary completed observations), the final URL,
  the bounded redirect chain, the bounded sorted final headers, the counted
  body size, and the TLS-handshake flag.
- Connection refused — `completed`, `conn_refused`: the service is absent
  on this port; a legitimate negative observation with no HTTP response.
- TLS handshake failure (certificate verification, protocol mismatch, or a
  non-TLS server on the https port) — `completed`, `tls`: https is not
  served on this endpoint from RavenRecon's trust perspective.
- Timeout (the per-request deadline, the per-job deadline, or a net-level
  timeout, including DNS timeouts) — `failed`, `timeout`.
- DNS resolution failure — `failed`, `dns`.
- Anything else — `failed`, `other`.
- Hard-cap hit (redirects, header bytes, header entries, body bytes) —
  `truncated-incomplete`: the captured observation is incomplete by
  definition and is never served from cache.

Classification is structural, never server-tainted text matching: TLS
handshake failures are tagged at the dial boundary with a typed sentinel,
and the header-cap abort is recognized only by exact equality on a wrapped
error. The stdlib embeds raw server bytes in some error strings, so text
matching would let a hostile server fabricate a `tls` or
`truncated-incomplete` classification.

Retention is bounded: at most MaxRedirects+1 redirect hops, at most
MaxHeaders sorted header entries from a byte-capped header block, and a
counted (never retained) body size capped at MaxBodyBytes. The TLS flag
records whether an https probe completed its handshake, and it is set on
EVERY terminal path: the final response, an out-of-scope redirect terminal,
and a cap-exceeding redirect terminal each carry the handshake state of the
response that ended the walk; http probes and failed handshakes record
false.

### TLS metadata (5C)

TLS metadata is captured as part of the https probe (sub-milestone 5C) —
one dial, no duplicate connections: the handshake the probe already
performs yields the leaf certificate, and the typed observation is attached
to the probe result (`ProbeResult.TLSMeta`, a `TLSMetadata`; nil for probes
that completed no handshake). What is captured:

- the leaf certificate as a Phase 2 `asset.TLSCertificate` — identity: the
  lowercase hex SHA-256 fingerprint of the DER encoding — with the observed
  subject/issuer CNs, SAN DNS names, validity window, serial, algorithms,
  key size (RSA modulus bits, ECDSA curve bits, Ed25519 256), self-signed
  flag, and chain depth (1..8);
- the techintel.TLSInfo-shaped fields — ALPN (the server's negotiated
  protocol), issuer DN, subject CN, SAN DNS names — which map field for
  field onto `techintel.TLSInfo`, so a caller composing a techintel
  Observation from a completed https ProbeResult copies those four fields
  into `Observation.TLS`.

Retention bounds (fixed constants, never configuration; see `tls.go`): the
ALPN list is capped at 32 entries of at most 64 bytes each; SAN DNS names at
32 entries of at most 253 bytes each; issuer and subject strings at 256
bytes of printable ASCII each; the chain at depth 8. Values outside the
bounds are dropped field-by-field ("not observed"), NEVER truncated into
misleading data. A chain deeper than the model's 1..8 cap is the ONE
material drop: the certificate asset is suppressed with a diagnostic joined
into the probe's errors, while the metadata fields and the handshake
observation itself are never lost.

Redirect-walk correctness: the metadata is captured per response and
overwritten on every iteration, so a followed hop's handshake can never
leak into the terminal observation — the terminal response's own handshake
state is what the probe reports, including on a terminal out-of-scope or
cap-exceeding redirect response — and the error paths (limiter wait,
round-trip failure) clear both the TLS flag and the metadata. A truncated
probe (a cap-exceeding redirect, header cap, or body cap) retains that
terminal handshake's metadata in the observation but contributes no
certificate asset or edges: assets and edges exist only for certs from
COMPLETED probes, not merely completed handshakes, and the truncated
record is stored incomplete and never served.

Cache consistency: the metadata is stored with the completed record
(`tls_meta` in the payload) and re-validated on decode before a hit is
served (`validateStoredTLS`): metadata may appear only on a completed https
probe with `TLS=true`, every bounded field must be within its cap, and the
embedded certificate asset re-validates through the Phase 2 builders. A
violating record is refused, deleted, and recomputed by the self-healing
path — never served.

### Relationship mapping

Each host result carries typed `asset.Relationship` edges through the
existing kinds:

- `host -> url` (`RelationshipHostToURL`) for served URLs (a probe completed
  with an HTTP response);
- `ip -> port` (`RelationshipIPToPort`) for ports observed open (served, or
  TLS-proven listeners) — only when the caller provided the host's resolved
  address;
- `port -> service` (`RelationshipPortToService`) for confirmed services (a
  probe completed with an HTTP response; a TLS failure proves a listener,
  not a service);
- `url -> endpoint` (`RelationshipURLToEndpoint`, GET on each probe target)
  for the probe shapes of every executed job, regardless of outcome;
- `host -> tls_certificate` (`RelationshipHostToTLSCertificate`) and
  `port -> tls_certificate` (`RelationshipPortToTLSCertificate`) for every
  leaf certificate captured from a completed https handshake (5C): the
  certificate asset is collected on the host result
  (`HostResult.TLSCertificates`) alongside the edges, and the report-level
  `AllTLSCertificates` merges the same certificate observed on many hosts
  into one asset by fingerprint.

Redirect-hop and final URLs are recorded in the observations only; the
graph stays about the probed surface. The same holds for port edges: a
`port -> tls_certificate` edge names the probed port (443 for the https
probe target) even when an in-scope redirect to a non-default https port
was followed — hops are observation-only, mirroring the 5B `ip -> port` /
`port -> service` convention. Edges are deduplicated by edge identity and
emitted sorted, deterministically.

### Cache behavior

Each probe target is cached under its own Phase 3 key composed of the
operation (`"http.probe"`), the canonical Phase 2 URL identity of the
target, and the canonical declared domain — the redirect scope boundary is
a key input, so two runs of the same target under different declared
domains are distinct keys (pinned by test). The request shape is fixed
(GET, no body, a fixed RavenRecon user agent) and the redirect policy and
caps are fixed constants, so there is no other result-relevant
configuration today; whatever configuration could matter in the future
must enter the key, but timings, timeouts, concurrency, rate limits, and
the transport (trust roots, dial routing) never do — exactly like the DNS
pipeline. HTTP responses of any
code and the two legitimate negative observations (`conn_refused`, `tls`)
are stored `completed`; truncated probes are stored `incomplete` and never
served; failed and cancelled probes are stored `failed`/`cancelled` and can
never be served as success. A cache hit performs zero network requests
(asserted in the benchmark harness). TTL semantics are the Phase 3 cache's
own: records expire per the cache instance's configured TTL, and expired
records are reported as misses.

Before a stored record can be served as a hit it is re-validated
(`decodeStoredProbe`): every URL re-parses canonically through the Phase 2
asset model, the payload must match the probe's own target and scheme, the
redirect chain must be internally consistent and agree with the final URL,
the terminal status must be honest — including the rule that a terminal 3xx
with a Location header and a followed chain is contradictory: a 3xx WITHOUT
a Location (Go client semantics: terminal) is the only legitimate
terminal-redirect completion — and outcome flags must not contradict each
other. Records whose URLs carry credentials in their original form are
refused. A record failing any check is deleted and recomputed in the same
run (self-healing), never served.

### Limits

Per probe, fixed constants — deliberately not configuration:

- `MaxRedirects` 10: in-scope redirect hops followed (the observed chain is
  recorded at most 11 entries; the cap-exceeding hop is observed, never
  requested);
- `MaxHeaderBytes` 64 KiB: the response header block (enforced by the
  production transport via `MaxResponseHeaderBytes`);
- `MaxHeaders` 128: retained header entries;
- `MaxBodyBytes` 1 MiB: counted body size (bytes counted only, never
  retained);
- `MaxConcurrentPerHost` 2: requests in flight per host (the per-host
  politeness contract; the current single-job-per-host design stays at 1).

Budget chain, strict and invariant: per-request 10 s
(`Config.RequestTimeout`, the slowloris budget, on top of the transport's
response-header timeout) ⊆ per-job 30 s (`DefaultConfig.Timeout`) ⊆
shutdown drain gradient 15 s grace + 30 s force budget. Pool bounds default
to exactly 8 workers and a bounded queue of 256.

### Concurrency and rate limiting

One bounded `runtime.Pool` per run owns all scheduling, with exactly one
job per input host: `Concurrency` workers (default 8), a bounded queue
(default 256), and a per-job deadline (default 30 s) covering the
central-limiter waits and the requests themselves. Each job performs its
two probes sequentially and honors cancellation: once the job context is
done, no further request is issued and every un-attempted target is
recorded cancelled.

The pool's job-start rate limiting is deliberately disabled; instead one
central token-bucket limiter (the runtime engine's `Limiter`; default 20
requests/second, burst 1) gates every OUTBOUND REQUEST's dispatch, after
the cache check — including each followed redirect hop — so the aggregate
request dispatch rate is bounded regardless of concurrency. Rate-limiting
honesty: the limiter is dispatch-pacing only. It paces RavenRecon's own
request dispatch and nothing else — it does not and cannot throttle the
transport's connection handling, TCP behavior, or resolver-internal traffic
— and RavenRecon never claims to control what it does not enforce.
Per-host politeness is additionally bounded by `MaxConcurrentPerHost`: a
RavenRecon-side contract only — with one job per host probing its two
targets sequentially, at most 1 request per host is in flight (the
per-host-concurrency test pins the cap; the server itself may of course
accept connections from other hosts).

Cancellation is classified per probe: a probe cancelled before dispatch
and a probe cancelled while in flight are both recorded cancelled, a host
whose job never started keeps its initialized cancelled status, and once
the job context is done no further request is issued. In-flight requests
are cancelled promptly by the stdlib transport when their context is
cancelled. Shutdown budgets bound the overall drain: the drain context is
the per-job timeout plus a 15 s grace (30 s force budget when per-job
deadlines are disabled), so the budget chain request ⊆ job ⊆ shutdown
holds by construction and a stalled server can delay a run only within
those bounds.

### Partial result semantics

A host's overall status is derived from its per-probe outcomes in fixed
priority order (see `classifyHost` in `observe.go`):

1. any cancelled probe -> `cancelled` (run teardown; never success)
2. any truncated probe -> `incomplete` (the captured observation is
   incomplete by definition)
3. failed with at least one completed probe -> `incomplete` (partial)
4. every probe failed -> `failed`
5. otherwise (all probes completed, including the legitimate negative
   observations) -> `completed`

The successful parts of a partial result are always retained: an http probe
that completed while the https probe failed keeps its status code, final
URL, headers, body size, typed assets, and edges — successes are never
discarded (pinned by
`TestProbePartialHTTPOKHTTPSFailNeverDiscardsSuccess`).

### Scope boundary

`Probe` accepts an explicit host list plus the run's declared target
domain. Every input hostname is re-validated canonically through the Phase
2 asset model and must be the target domain itself or a subdomain of it;
anything non-canonical (raw input, uppercase, trailing dots, IP literals,
hand-built structs) or out-of-domain rejects the WHOLE list before a single
request is issued. Redirects are followed ONLY into the target domain: an
in-scope Location is normalized through `asset.ParseURL` and may be
followed (up to MaxRedirects hops), while an out-of-scope Location —
including any IP literal, which is never in scope — is recorded as a
canonicalized display string and NEVER requested. The package is a
boundary, not an arbitrary-scanning feature, and redirect handling cannot
be abused to chase probing outside the declared domain or to rebind to
arbitrary addresses.

### HTTP security considerations

- SSRF boundary: requests are issued only to validated in-scope hosts,
  from asset-derived canonical URLs; redirect targets outside the target
  domain are observed-not-requested, so a hostile or compromised in-scope
  server can never redirect probing onto arbitrary hosts or addresses.
- DNS rebinding: the identity-vs-dial seam keeps observations independent
  of dialing, and redirects into IP literals are never in scope — a
  redirect can never rebind the walk. On dialing, honest statement:
  RavenRecon does NOT pin dial addresses itself — probing dials through the
  configured transport's own resolution whether or not the caller provided
  resolved addresses (the provided addresses are observations that feed
  `ip -> port` edges). The seam is what would allow a future stage to pin
  the observed addresses at dial time without changing the observations;
  today, in the transport-resolves-when-absent case, the dial follows the
  DNS view at probe time.
- Slowloris/hang budget chain: every request is bounded by the per-request
  deadline (10 s default) on top of the transport's response-header
  timeout, inside the per-job deadline (30 s default), inside the bounded
  shutdown drain (15 s grace + 30 s force) — a stalled server can delay a
  run only within those bounds, never wedge it.
- Header bombs, huge bodies, redirect loops: the response-header block is
  byte-capped (64 KiB) and entry-capped (128), the body is counted only and
  capped (1 MiB), and the redirect chain is capped (10); any cap hit marks
  the probe truncated-incomplete — never completed, and never served from
  cache.
- TLS trust: the production transport uses Go's default certificate
  verification; RavenRecon never sets `InsecureSkipVerify` and never
  disables chain or hostname checks. Certificate metadata (5C) is captured
  AFTER verification, from the completed handshake; verification itself is
  never relaxed.
- Cache poisoning: stored records are re-validated through the Phase 2
  asset model and cross-checked against their own key before they can be
  served (`decodeStoredProbe`); tampered or contradictory records are
  deleted and recomputed, never served. Trust = the network the probe
  observed + the caller's resolver; there is no separate cache trust
  domain.
- Identity collisions: every observation enters the asset model only
  through the Phase 2 normalizers — probe targets, final URLs, and followed
  hops are canonical identities, and the scheme is part of the URL
  identity, so the http and https probes of one host can never collide.
  Credentials in a hostile Location are redacted at the observation
  boundary — the single construction point where Location-derived strings
  become asset URLs — so userinfo can never reach the report, the cache, or
  errors. Location values that fail to parse at all (out-of-range ports,
  control bytes) are never echoed verbatim either: they are observed only
  in sanitized form (userinfo and control bytes stripped) and never
  requested.

### Known limitations

- Default ports and root path only: probing covers `http://host/` and
  `https://host/`; non-default ports, non-root paths, and crawling are not
  supported.
- No title or body content, and no technology detection: bodies are
  counted, never retained; technology detection is a later roadmap
  milestone.
- Stale-IP caveat: the caller-provided resolved-address map attaches at
  most one address per host, the DNS pipeline's multi-address closure is
  not yet wired to probing, and probing never dials those addresses — it
  dials through the transport's own resolution — so the observed `ip ->
  port` edges describe the DNS-time addresses, which may be stale by probe
  time.
- Redirect following is in-scope-only by design: out-of-scope targets are
  observed as display strings and never requested (see "Scope boundary").
- Single-job-per-host: each job runs its two probes sequentially, so one
  stalled probe can consume the host's job deadline (documented in
  `doc.go`).
- Library capability only: no CLI command.
- All tests are hermetic: loopback HTTP/TLS servers and a real
  filesystem-backed cache, never the public Internet (see `bench_test.go`).

## URL intelligence

The URL intelligence pipeline (roadmap v0.7, sub-milestone 6B;
`internal/urlintel`) is a library-level stage with no CLI command yet: a
streaming engine that canonicalizes raw observed URLs into Phase 2 assets,
extracts query parameters and endpoints, caches per (URL, adapter), merges
observations at emit time, and assembles the typed asset-graph edges. The
source seam is the `LineSource` interface (`SliceSource` wraps a fixed
slice for tests and static input); the historical-URL tool adapters
(sub-milestone 6C, `internal/urlintel/adapt`) present external commands
as LineSource streams and are documented under "Historical-URL tool
adapters" below. There is no scope layer: urlintel accepts any canonical
URL, and scope filtering is the caller's obligation.

### Historical-URL tool adapters

Historical-URL tool adapters (roadmap v0.7, sub-milestone 6C) live in
`internal/urlintel/adapt`: external commands presented as
`urlintel.LineSource` streams. They reuse the hardened execution layer of
`internal/discovery` (Runner, Limits, Detection) — there is no second
execution implementation — and each ingest runs with the tool name as the
engine's adapter identity.

#### Supported tools

Three built-in tools, described as data (Tool descriptors; the pipeline
never branches on tool names):

```text
gau:         gau <host>                  # positional target; -version probe
waybackurls: waybackurls <host>          # positional target; existence-only
waymore:     waymore -i <host> -mode U   # URL-only mode; --version probe
```

waymore runs in `-mode U` (URLs only): archived response downloading is
never reachable from RavenRecon. katana and paramspider are deliberately
deferred (documented future work): they are crawling / active-discovery
tools with heavier invocation shapes, scheduling, and output formats — the
three passive archive URL tools cover 6C's historical-URL scope.

#### Detection semantics

Detection is tool-specific, per the discovery layer's four-stage
contract (existence, execution, version, capability). Version-probed
tools (gau `-version`, waymore `--version`) run their probe through the
runner and require a recognizable semver-like token in the bounded
capture (stdout first, then stderr); a broken, unsupported, garbled, or
timing-out probe is at worst a WARN, never a MISSING — existence and
capability are separate concerns, and a correctly installed tool is never
reported missing because its version flag misbehaved (AGENTS.md
requirement). Existence-only tools (waybackurls) have no probe at all:
executable lookup IS the detection, so no probe can misreport an
installed tool. Each tool is detected once per run, sequentially, before
any execution, bounded by the detection timeout (default 5 s).

#### Execution safety

Every invocation goes through the shared hardened runner:
`exec.CommandContext` with arguments as separate argv values (never a
shell, never string concatenation — the canonical target is passed as its
own single argv element), bounded per-tool capture (`Limits.MaxOutput`,
default 4 MiB per stream; overflow is truncated and honestly reported as
partial), the per-detection timeout, and process-group kill on
cancellation (unix) so a cancelled run leaves no child process behind (on
Windows only the direct child is killed; no POSIX process groups). The
adapt package contains no `os/exec` usage of its own beyond the `LookPath`
seam, so there is exactly one execution path to harden.

#### The adapter ≠ model boundary

Adapters translate tool stdout into RAW lines on the `LineSource` seam:
lines are trimmed (CRLF and surrounding whitespace stripped), blank lines
are skipped, and everything else passes through unchanged. No parsing,
normalization, or canonicalization happens inside an adapter: the
canonical model — `asset.URL` / `asset.Parameter`, cache records, and
merge-at-emit — lives entirely in `urlintel` / `asset`. Canonical-boundary
rejection (non-URLs, oversized lines, control-character garbage) is the
engine's Malformed accounting at the ingest boundary, never the adapter's,
so garbage from a noisy tool is counted and reported, never fatal and
never silently dropped. Tool output is never trusted as a URL until
`asset.ParseURL` has canonicalized it.

#### Adapter identity and cache keys

The orchestration passes the tool name as the engine's adapter identity
(`urlintel.Config.Adapter`), which enters the per-(URL, adapter) cache
keys AND the provenance of every asset. The same URL observed by two
tools is two cache records; the engine's accumulator merges them at emit
time into ONE report entry with unioned sources in first-observation
order — one URL seen via two adapters emits one merged report entry,
never two. Callers must pass the same tool name across runs (the engine's
key contract).

#### Orchestration and outcomes

`Run()` owns one bounded `runtime.Pool`: exactly one job per (tool,
target), pool `Concurrency` bounds concurrent tool processes, the bounded
queue applies backpressure, and job-start rate limiting paces job starts
(tool-internal network traffic is the tool's own responsibility —
RavenRecon never fakes per-request limits for external processes). Each
job executes its tool through a `toolSource` and feeds
`urlintel.IngestInto` with a small inner pool (`IngestWorkers` workers):
the composite bound is Concurrency × IngestWorkers ingest workers plus
Concurrency tool processes, all bounded. The outer per-job deadline
bounds the tool execution AND the ingest of its lines; job-start pacing,
timings, and concurrency never enter cache keys. Every slot reports an
honest `ToolResult`: skipped (detection MISSING — never an error, never
an execution attempt), completed (clean run, fully ingested), partial
(non-zero exit with usable output, or stdout truncated at the capture
cap), failed (no usable output), cancelled (run teardown), or timed-out
(job deadline elapsed). A failing tool never aborts the run; errors and
truncation are summarized per result, the run level keeps total Malformed
on the merged report, and only non-fatal diagnostics and shutdown
failures are joined on the returned error.

### Pipeline

One bounded `runtime.Pool` owns all scheduling: exactly one job per raw
line, `Config.Concurrency` workers, a bounded submission queue (the reader
blocks on a full queue — backpressure, never unbounded memory), optional
per-job deadlines and job-start rate limiting. Raw strings exist only at
the ingest boundary: a line is capped at 32 KiB, rejected as malformed
(counted, reported, never cached, never fatal) when oversized or
unparseable, then immediately canonicalized through `asset.ParseURL` —
raw strings never travel beyond the parse stage. Userinfo carried by a raw
line is redacted at that same construction point: the asset is rebuilt
through its canonical string, so credentials never reach records, reports,
exports, or merges. Each canonical URL is
pre-registered as a cancelled entry before submission, so a job dropped by
a forced shutdown still appears in the report with an honest status.

### Extraction

Every canonical URL classifies as exactly one endpoint: GET on the
canonical URL, whose identity includes the query string. Query parameters
are extracted from the canonical query only; names and values stay exactly
as observed (escaped forms never unescape, so `a%20b`, `a+b`, and raw
non-ASCII values remain distinct identities), repeated names merge within
one URL, and value-less keys (`?flag`) are not representable in the Phase 2
model and are skipped. The path and body parameter locations are reserved
for future phases.

### Records and relationships

Cache records are stored per (canonical URL, adapter): the operation is
`url.ingest`, the key target is the canonical URL identity, and the
configuration carries the adapter identity and the result-relevant
`ParseParameters` flag — so the same URL observed by two adapters is two
records, and a run with parameter extraction disabled is never served a
record written with it enabled. The accumulator merges at emit time keyed
by canonical URL identity only: sources union in first-observation order,
timestamps are min/max, parameters merge via `asset.MergeParameters`,
endpoints and relationships deduplicate by identity. Each entry carries
typed edges — host -> url, url -> endpoint, url -> parameter, and endpoint
-> parameter — deduplicated by edge identity and emitted sorted; cached
observations rebuild the identical graph (host and edges are not stored).

### Limits

The line cap (32 KiB), the per-URL parameter cap (256 distinct parameters,
beyond which the entry is flagged `Overflow` but stays completed — the
AGENTS.md truncation carve-out: `completed` with the end-to-end sticky
flag, which consumers treat as an incomplete retained set), and the
Phase 2 per-parameter value cap (1024, flagged `Truncated` on the
parameter) are fixed constants, deliberately not configuration, and never
enter cache keys. Failed and cancelled observations are never cached: a
second run re-works them.

### Cancellation

`context.Context` flows through everything. Cancelled mid-stream, the
reader stops, submitted jobs are cancelled by the pool, pre-registered
entries keep an honest cancelled status, completed observations are still
persisted (with a detached, bounded store context), and the pool's bounded
shutdown budgets bound the drain. Lines not yet read are never consumed
and not represented. `IngestInto` returns only after every pool-owned
goroutine has terminated.

### Security considerations

Hostile input is bounded end to end: raw lines before parsing, parameters
per URL, values per parameter, sources per observation, and payload sizes
at decode time. Stored records are never trusted: every cached payload is
re-validated through the Phase 2 model (canonical forms, identity
consistency with the queried URL and adapter, bounds re-checked), and a
corrupt, tampered, or mismatched record is deleted and recomputed in the
same run (self-healing), never served as a hit. Machine-readable output
stays separate from diagnostics: run counters on `Metrics`, observations
in the report, and warnings joined on the returned error.

### Known limitations

- GET-only classification: other HTTP methods are not observable in 6B
  inputs (the Phase 2 model supports them).
- Path/body parameter extraction is not performed (reserved by the Phase 2
  model for future phases).
- Value-less query keys are skipped: the Phase 2 Parameter model requires
  a non-empty observed value.
- Raw lines over 32 KiB are rejected as malformed, not truncated.
- Cache keys include the adapter: callers must pass the same adapter name
  for the same tool across runs.
- katana and paramspider are deferred (documented future work): crawling /
  active-discovery tools with heavier invocation shapes, scheduling, and
  output formats (see "Historical-URL tool adapters").
- The adapters are library-level only: there is no `ravenrecon url` CLI
  command yet, and tool results are reported per (tool, target) while
  malformed-line counts are run-level only.
- Cache hits replay the stored record's FirstSeen/LastSeen: a zero-work hit
  does not advance LastSeen, and TTL expiry (when configured) bounds how
  stale a served record can become.
- All tests are hermetic: synthetic input and a real filesystem-backed
  cache, never the public Internet.

## Technology detection

Technology detection (roadmap v0.6's final open bullet, phase 6.5;
`internal/techintel`) is a library-level engine with no CLI command yet: it
consumes typed observations — response headers, body, cookies, TLS
metadata, DNS metadata, endpoint paths — and produces typed Phase 2
technology assets, evidence records, and asset-graph edges against the
data-only fingerprint database (`internal/techintel/fingerprints`). The
engine never fetches and never executes JavaScript: a caller composes an
Observation from its own probes (HTTP probing 5B, TLS metadata 5C, DNS
resolution 5A) and feeds it to Ingest. It mirrors the urlintel pipeline
shape: Config/DefaultConfig, an ObservationSource seam (with
SliceObservationSource for tests and static input), one bounded
runtime.Pool, cache-before-execute, merge-at-emit, bounded diagnostics,
cancellation with honest statuses, and a deterministic report.

### Model

`asset.Technology` is identified by category/name ("framework/react") —
version is an OBSERVED attribute, never part of the identity, and
`asset.MergeTechnologies` prefers the non-empty version deterministically
(later observation wins exact ties). `asset.Evidence` is identified by
method/indicator/value/source: the stored value is capped at 256 bytes by
a rune-safe truncation ("…" marker; the identity covers exactly the stored
bytes, so two observations differing only past the bound are the same
evidence), and the source component is the identity of the asset the
observation came from — the same indicator matched on two different hosts
is two evidence records, never one merged record that drops attribution.

### Fingerprint database

`internal/techintel/fingerprints` is DATA ONLY: structured definitions in
category tables plus the compile-once compiler. The production database
holds 145 fingerprints with 296 indicators across all 21 categories.
Indicator kinds are tiered — TierSpoofable (headers, cookies, DNS CNAMEs:
any operator can emit them) vs TierStructural (HTML markers, script/CSS
paths, endpoints, TLS certificate fields) — and the tier is derived from
the kind, never stored per entry, so data cannot mislabel it.
`SchemaVersion = 1` enters every detection cache key: bumping it
invalidates every cached result by construction (cache schema versioning
mirrors `internal/cache`). `Load()` validates every entry — NaN indicator
weights are rejected at load (a NaN weight would poison the confidence
product) — and compiles every regular expression exactly once; the engine
NEVER compiles its own
regexes and consumes the DB only through the compile-once accessors
(`MatchRe`/`VersionRe`). Extension is a data-only change: add a table entry
(name, category, indicators, optional version spec) and `Load` validates
it — duplicate names across tables and malformed entries fail the load.

### Confidence

Score = 1 − ∏(1 − wᵢ) over INDEPENDENT indicator matches; independence is
exactly: distinct indicator kinds OR distinct match slots (same
kind+slot collapses to the max weight). Thresholds: ≥0.8 High, ≥0.5
Medium, ≥0.2 Low, else Unknown — Unknown detections are still reported.
Caps: a spoofable-only detection (no structural indicator) is pinned at
0.59, so it can never exceed Medium; High requires at least one structural
indicator; a lone weak indicator (weight < 0.35) never exceeds Low. The
per-technology version comes from the highest-weight version-bearing
matched indicator (ties: first in DB order), applied to the matched value
as observed. Equal-score merges resolve by the deterministic tie-break
chain: a version-bearing contributor outranks a version-less one, then the
earliest ObservedAt, then the lowest source name, then the version-bearing
indicator's flat DB ordinal (persisted in cache records, so cache-served
contributors tie-break identically to fresh ones), then the lowest version
string, then the level — a total order, so merge order never matters.

### Analyzers

One corpus extraction per observation (one HTML pass, one lowercase body
copy, cookie parsing bounded at maxObservationCookies entries), then every
fingerprint indicator matches against its kind's slots: header
(case-insensitive substring of the "Name: value" line), cookie (name or
value), html_regex / html_substring (body; substring evidence values are
byte-aligned back to the ORIGINAL body through per-rune case folding, so
non-ASCII bodies never tear evidence values), meta_name, generator (regex
on generator meta content), script_name / script_path, css_path,
attribute (version from the attribute value), endpoint_path (the canonical
URL path), tls_issuer / tls_cn / tls_alpn (the typed TLSInfo seam), the
dns_cname CNAME chain (the typed DNSInfo seam), and sourcemap_path —
extracted PRESENCE-ONLY from sourceMappingURL tokens; JavaScript is never
executed. The cookie analyzer combines caller-provided cookies with
Cookie/Set-Cookie header parsing: the FIRST Set-Cookie pair is the real
cookie, later pairs are ingested only when they are REAL attributes (Path,
Domain, Expires, Max-Age, SameSite, Secure, HttpOnly, Partitioned), and
session flags (HttpOnly/Secure/SameSite) become evidence-only records
(cookie_flag:* indicator keys) that fire no technology.

### Cache integration

Operation `tech.detect`. The key is the observation identity (the canonical
URL identity, or the endpoint identity when attached) plus
`fingerprints.SchemaVersion` plus the fingerprint database CONTENT digest
(`fingerprints.DB.Digest`: any data-only table edit — with no schema bump —
changes the digest and invalidates every cached detection) plus the
sources bitmask (sorted letters: b body, c cookies, d DNS, e endpoint,
h headers, t TLS), so a body-ful and a
headers-only observation of the same target are never served each other's
results. A completed hit serves the stored result with ZERO analysis
(pinned by the Metrics.Analyzed counter) and rebuilds the identical graph;
on a hit the entry's StatusCode and FirstSeen/LastSeen come from the stored
record, never from the observation, and the status code never enters keys.
Timings, concurrency, and the fixed caps never enter keys either. Decode
re-validation covers identity containment, mask equality, parallel-array
lengths (levels, version ordinals), timestamp ordering, canonical
technology and evidence identities, scores in [0,1] (NaN rejected), levels
never stronger
than the score allows, and the method-possible guard (a body-less record
can never carry HTML-derived evidence — the truncated-as-completed tamper
class); a rejected record is deleted and recomputed in the same run, never
served. Failed and cancelled observations are never stored as success.

### Pipeline

One bounded runtime.Pool owns all scheduling: exactly one job per
observation, configurable Concurrency and bounded QueueSize (the reader
blocks on a full queue — backpressure, never unbounded memory), optional
per-job deadlines and job-start rate limiting. The reader validates and
bounds each observation at the ingest boundary (malformed input is counted
and the run continues; a hostile oversized URL never reaches the parser),
pre-registers a cancelled placeholder per identity (so a forced shutdown's
dropped jobs appear honestly as cancelled), and submits one bounded job.
Each job: cache-before-execute -> analyze (cache miss) -> store the
completed record -> merge into the entry accumulator -> optional Emit hook.
Cancellation performs a bounded drain with honest cancelled statuses and
never leaks workers; completed results are still persisted under a
detached bounded store budget. Statuses: completed / cancelled / failed
(entries) and malformed (counted on the Report, never an entry, never
cached). Per-observation bounds: canonical URL 32 KiB (malformed beyond),
body 1 MiB (truncated, Truncated flag), 128 header entries (malformed
beyond), 256 cookies (analyzer cap, Overflow.Cookies), 128 technologies /
512 indicators per observation (configurable caps with documented
defaults, Overflow flags), bounded HTML candidate lists (scripts/css/metas
128, attributes 256, sourcemaps 32, generators 16), and evidence values
capped by `asset.NewEvidence` — a flagged entry stays `completed` only per
the AGENTS.md truncation carve-out (the flag survives record → cache hit →
merge → report), and consumers treat it as an incomplete retained set.

### Relationships

Every observation emits typed edges, deduplicated by edge identity and
deterministic in technology order (score desc, name asc): host (hostname
URLs only) -> technology, url -> technology, endpoint -> technology (when
an endpoint is attached), and technology -> evidence for every retained
match that fired the technology. Evidence records whose technology was
dropped past the technology cap are still reported as observed evidence,
but carry no technology edge.

### Security considerations

Spoofing is bounded by design: spoofable-only detections never exceed
Medium, High requires a structural indicator, and isolated weak indicators
stay at Low — a banner alone can never produce a High classification.
Resource use is bounded end to end: observation caps, match caps, evidence
value caps, HTML candidate caps, the bounded pool/queue, and bounded
diagnostics. HTML scanning is naive by design (single-pass tag scanning,
not a DOM parser): comment text and JavaScript string literals can
false-fire script/attribute/meta indicators, honestly and reproducibly —
but never beyond the caps, and never as a trusted classification. The
engine never fetches (observations are caller-composed) and never executes
JavaScript (source maps are presence-only). Cache poisoning is guarded by
strict decode re-validation: tampered, corrupt, or contradictory records
are deleted and recomputed in the same run, never served, and the schema
version plus the sources mask enter every key.

### Known limitations

- HTML scanning is naive, by design: it walks raw markup ("<"...">" tag
  scans, sourceMappingURL token presence) rather than parsing a document
  tree. Comment text and JavaScript string literals can false-fire
  script/attribute/meta indicators (for example a JS string containing
  `src="/app.js"`), and quoted attribute values inside tags follow a
  simple quote model. The scan is bounded and fully deterministic — false
  positives are honest, reproducible observations — but it is not a DOM
  parser.
- Ingest's cancellation unwinds the reader, pool, and drain — but only if
  the ObservationSource honors ctx: a caller source whose Next ignores
  cancellation and blocks forever can wedge Ingest. This is a seam
  contract: sources must return promptly (io.EOF, or an error) when ctx is
  done, exactly as SliceObservationSource does.
- Cache hits replay the stored record's StatusCode and
  FirstSeen/LastSeen: they are never re-derived from the observation, a
  zero-work hit does not advance LastSeen, and TTL expiry (when
  configured) bounds how stale a served record can become.
- The method-possible guard is deliberately permissive where a method can
  arise from more than one observation family: cookie evidence is possible
  under 'c' OR 'h' (the cookie analyzer parses Cookie/Set-Cookie headers
  into cookie observations), and endpoint-derived evidence is possible
  under ANY mask because every observation carries a canonical URL path.
- All tests and benchmarks are hermetic: synthetic input and a real
  filesystem-backed cache, never the public Internet.

## JavaScript intelligence

JavaScript intelligence (roadmap v0.8, phase 7; `internal/jsintel`) is a
library-level engine with no CLI command yet: a typed Source seam feeds a
bounded worker pool where every candidate script URL runs
cache-before-execute fetch → classify → parse → extract → merge → emit →
bounded import expansion. Package layout: the core (`internal/jsintel`)
owns the whole model — normalization, fetch, parse, analysis, cache
records, report; `internal/jsintel/adapt` only presents external commands
as Source streams of raw lines. Adapters never parse, normalize, or
canonicalize: the engine's line seam owns all of it.

### Asset model

Phase 2 gained three asset kinds and five relationship kinds. The
JavaScript asset records the observation window (size, lowercase-hex
SHA-256 content hash ≤ 64 chars, content type ≤ 128 bytes, ETag ≤ 256,
discovery source ≤ 128, status ≤ 599, last-modified, final URL, host) with
setter-enforced bounds and deterministic merging. The SecretCandidate is
identified by (type, stored value, subject identity): the stored value is
capped at 512 bytes by a rune-safe truncation ("…" marker), and the
identity covers exactly the stored bytes, so two observations differing
only past the bound are the same candidate. The SourceMap asset is a
detected reference (canonical URL + provenance) — nothing more. Edges:
`javascript_to_javascript`, `javascript_to_endpoint`,
`javascript_to_secret_candidate`, `javascript_to_source_map`, and
`javascript_to_technology`; per-marker evidence uses `MethodJS` ("js").

### Discovery seams

`Item` is the ingest seam with two forms. `ItemLine` carries one raw line
(a URL, a relative reference resolved against `Config.Base`, a secretfinder
progress line, or a secretfinder match line); `ItemHTML` carries a canonical
page URL, response headers, and a body bounded to 1 MiB at ingest. HTML
extraction is single-pass and tag-scanned (no DOM): script `src` attributes,
`link` hrefs whose rel/as qualify (modulepreload, or preload/prefetch with
as=script), Link response headers (≤ 32 entries × 4096 bytes), and the
static/dynamic imports of inline src-less script bodies — resolved against
the page URL. Every reference — lines, HTML, imports, source maps —
resolves through the ONE shared resolver (`resolveRef`): absolute http(s),
protocol-relative, root-relative, and `./`/`../` forms resolve with
root-clamped dot-segment cleaning, query preserved, fragment stripped; bare
specifiers (`react`, `@scope/pkg`) have no relative meaning and are never
fetched.

Line-secret ingestion (the D2 contract): a `"[ + ] URL: <u>"` progress line
sets the seam's current URL context, and every following
`"name\t->\tvalue"` match line becomes a typed candidate attributed to that
URL — the name maps through the documented table in discover.go
(google_api/google_api_key → google, json_web_token → jwt,
amazon_aws_access_key_id/aws_access_key_id/aws_secret_access_key → aws,
firebase/firebase_api_key → firebase, stripe/stripe_secret_key → stripe,
github/github_token → github, private_key → private_key, bearer → bearer,
anything else → generic) and the value is bounded to 4096 bytes, mirroring
the parser's literal cap. Pending line-secrets accumulate per URL in a
bounded map (32 URL contexts × 64 secrets each; every cap drop is counted
Skipped, arrival-order and deterministic), and after the pool drains they
are attached to their URL's entry with the URL's JavaScript identity as the
candidate source — deduplicated against the content-derived candidates by
candidate identity, so a match line and a literal with the same type and
value are ONE candidate. Secret lines with no current URL context, and
secrets of URLs never admitted (cap-dropped targets), are counted and
dropped; SecretLines counts every raw match line, ingested or not.

### Fetch engine

One bounded GET per canonical URL: fixed user agent, no cookies or custom
headers, ≤ 5 redirect hops following http(s) targets ONLY — a redirect to
a non-http(s) target is observed, never followed, the walk ending with the
redirect response as the final observation (the cap-exceeding 3xx is the
terminal completed observation in the same way) — a per-attempt deadline
(default 10 s) covering the
whole walk, a 64 KiB header-block cap, and content retention streamed
under `MaxJSBytes` (default 2 MiB, clamped to [64 KiB, 8 MiB]) with
transparent gzip decompression (the stored content is the decompressed
bytes). Truncation is honest: an oversized body — declared by
Content-Length or discovered while streaming — retains NOTHING (a partial
prefix would be a misleading observation); failed attempts retry
immediately up to `Retries` (default 1, ≤ 3). Outcome classification
mirrors httpprobe, including the completed negatives: response received →
completed; connection refused → completed, `conn_refused`; TLS handshake
failure → completed, `tls`; deadline/DNS → failed; cancellation →
cancelled. The transport is a seam (nil = the bounded production
transport: header cap, header timeout, direct-only); tests inject hermetic
loopback transports.

### Parser

The parser abstraction is `type Parser interface { Parse(src []byte)
(Parsed, error) }`; `NewParser` returns the single stdlib implementation —
a hand-rolled tokenizer plus an extraction walk. It never builds an AST,
never executes, never rewrites. Malformed JavaScript never fails Parse:
the scanner recovers from unterminated strings/comments/templates/regexes
(at EOL or EOF), stray bytes, and invalid UTF-8, counting each recovery on
`Parsed.Malformed` while still extracting around the damage; the regex vs
division ambiguity is resolved by a regex-allowed state keyed on the
previous token. The only error is input over 8 MiB. Fixed bounds (they
never enter cache keys): 1 Mi tokens, 8192 string/template literals, 4096
bytes per retained literal value, 1024 imports, 1024 export names, 1024
bytes per identifier, 4096 bytes per sourceMappingURL reference. Any cap
hit marks `Parsed.Truncated` — an honest partial prefix, never a complete
parse. Extracted observations: static and dynamic imports (unresolvable
dynamic specifiers are honestly empty), exported names, literal VALUES
with escapes decoded, and the LAST sourceMappingURL reference.

### Import graph, source maps, endpoints, secrets, technologies

Resolved imports become `javascript_to_javascript` edges AND expansion
candidates at depth+1, bounded by `MaxImportDepth` (4) and the run's
`MaxScripts` total (500); a URL is admitted at most once per run, so
circular imports terminate. Edges are recorded even when the target was
never fetched (depth/total caps): the graph is the honest observation.
Bare specifiers deduplicate into the third-party library list, bounded by
`MaxImportsPerFile` (256). Source maps are detected from the trailing
`sourceMappingURL` comment and the `X-SourceMap` header, resolved against
the file's own URL, and normalized as SourceMap assets — never fetched,
never parsed (content parsing is deferred future work). Endpoint
extraction walks the parsed literals: dynamic `${...}` templates are
skipped, ws/wss absolutes classify "WS", and resolved references classify
by path ("GQL" for graphql segments/extensions, "SSE" for events/stream/
sse last segments, else "GET") — the class rides in the endpoint's Method
field and is NEVER an observed HTTP method; different-host absolutes are
additionally retained as URL assets (CDN/external observations). Secret
extraction scans every literal against 8 families (JWT, AWS, Google,
Firebase, Stripe, GitHub, bearer, private-key marker): CANDIDATES ONLY —
no verification, no severity, no context — a deliberate boundary; a later
phase verifies. Technology detection runs a fixed marker table (19
specifications) over the raw content with techintel's confidence math
(score = 1 − ∏(1 − wᵢ) over matched markers; ≥ 0.8 High, ≥ 0.5 Medium,
else Low) and emits Technology assets plus per-marker `MethodJS` evidence.

### Cache integration

Two operations, both cache-before-execute. `js.fetch` keys on the
operation and the canonical URL identity ONLY — the request shape is
fixed, and timings, retries, caps, and concurrency never enter a key, so
cap changes never invalidate entries (a lowered cap simply re-truncates on
the re-fetch path; truncated records are stored incomplete and never
served as hits). `js.analyze` keys on the operation, the URL identity, and
the parser schema version plus the family mask ("1:eimst") — a record
written by a different analysis contract is unreachable by construction.
A fetch hit performs zero network requests and zero limiter waits; an
analysis hit performs ZERO parses — the stored payload rebuilds a
byte-identical entry through the same applyAnalysis. Both records are
re-validated at decode (identity containment, content hash re-verified,
bounds re-checked, statuses consistent); a tampered or corrupt record is
deleted and recomputed in the same run (self-healing). Completed
negatives are stored completed with their reason; failed and cancelled
observations are never stored.

### Pipeline, statuses, and limits

One bounded `runtime.Pool` (8 workers, queue 256, per-job deadline 30 s
default) owns all scheduling; the pool is NOT paced — every fetch already
waits on the central token-bucket limiter inside Fetch, and pacing
cache-hit jobs would double-limit. The reader normalizes items, admits
candidates atomically (visited set + total cap), and pre-registers a
cancelled placeholder per URL so a forced shutdown's dropped jobs appear
honestly. Entry statuses: completed / incomplete (truncated fetch or
truncated parse — the JS asset, when present, is still recorded) / failed
/ cancelled; merge-at-emit unions sources (≤ 32), keeps min/max
timestamps, deduplicates every payload list by identity, and applies the
per-file caps. Fixed resource limits: per-run MaxScripts 500 and
MaxImportDepth 4; per-file imports 256, source maps 8, HTML scripts 128,
endpoints 64 (bounding the URL list too), secrets 32, technologies 32,
evidence 64; endpoint candidates ≤ 1024 bytes; secret values ≤ 512 bytes
(asset layer); line-secret contexts 32 URL contexts × 64 secrets each
(engine-side, they never enter cache keys); diagnostics ≤ 32 per run;
shutdown drain bounded by the
job timeout + 15 s grace (30 s force).

### Adapters

`internal/jsintel/adapt` presents three ACTIVE tools as jsintel Sources
(the tools fetch the target themselves; their traffic is their own
responsibility, bounded only by the runner's limits): subjs (`subjs -c 1
-t 15 -i <tmpfile>`; MIT; version-probed), LinkFinder (`linkfinder.py -i
<target> -o cli`; MIT; existence-probed; requires jsbeautifier), and
SecretFinder (`SecretFinder.py -i <target> -o cli`; GPL-3.0;
existence-probed). The executable IS the script for the python pair — the
documented install contract is a PATH wrapper with a shebang (or a
symlink), or a per-run path override keyed by executable name; the
adapter never resolves executables itself. Every output line becomes one
`ItemLine`; lines over 32 KiB are skipped and counted; the engine's
parseLine owns URL canonicalization, relative resolution, the "[ + ] URL:"
progress form (which sets the per-URL line-secret context), and the
"name -> value" secret-line form (typed ingestion against that context; see
"Discovery seams"). A broken version
probe is at worst a WARN — never a MISSING. Katana's JS output is
deliberately deferred (consistent with the urlintel deferral): the
engine's own extraction covers this phase's scope.

### Known limitations

- Library capability only: no `ravenrecon js` CLI command yet.
- Secret candidates are detected, never verified; no severity is claimed.
- Source map content is never fetched or parsed (detected references
  only); parsing lands with a future phase.
- LinkFinder HTML-escapes its output; the line seam does not yet unescape
  entities (documented follow-up).
- No content sniffing: JS classification is Content-Type or path based
  (`.js`/`.mjs`/`.cjs`) — a `text/plain` body at `/app.js` IS a JS asset.
- The engine's line seam has no line cap of its own; the 32 KiB cap lives
  in the adapter.
- Cache hits replay stored FirstSeen/LastSeen; TTL expiry (when
  configured) bounds staleness.
- All tests and benchmarks are hermetic: synthetic input, loopback
  servers, and a real filesystem-backed cache, never the public Internet.

## Secret intelligence

Secret intelligence (phase 8; `internal/secrentel`) is a library-level
engine with no CLI command yet: the Evidence & Secret Intelligence Engine.
It is deliberately NOT a "secret scanner" — it is an evidence engine. Every
emitted candidate carries its canonical Phase 2 `asset.SecretCandidate`
identity, the pattern fingerprints that matched, an entropy assessment,
extracted context, multi-evidence correlation, and a confidence verdict
composed of every contributing factor. Anonymous strings are never
returned. Package layout: the core (`internal/secrentel`) owns the whole
model — the document seam, the scan/correlation/confidence pipeline, cache
records, and the report; `internal/secrentel/patterns` is the data-only,
compile-once pattern database (mirroring `internal/techintel/fingerprints`).

### Phase boundary

Candidates are detected, NEVER verified: no network call, no cloud API
validation, no AWS/GitHub/Stripe validation, no exploitation, no severity.
The offline verification QUEUE records which candidates a future
verification module should consume (medium confidence and above, unflagged,
deterministically ordered); it executes nothing, contacts nothing, and is
itself never cached — it is derived from the report's secrets at build
time.

### Document seam

`Document` is the ingest seam (caller-composed; the engine never fetches):
one of 11 kinds (js, sourcemap, html, json, env, config, yaml, xml,
graphql, openapi, http), bounded content, an optional canonical URL, an
optional source asset identity (a JavaScript asset identity from jsintel
makes the candidates' source identity IDENTICAL to Phase 7's — the two
phases deduplicate on one Phase 2 candidate), filename/repo/hostname
hints, and optional technology names (techintel detections used as
correlation signals). `prepareDocument` is the single normalization point:
bounds are enforced there (content 2 MiB, filename 512 B, repo 512 B, 32
technology hints, hostname validated through `asset.NewHost`), larger
documents become an honest truncated prefix, and malformed input is
rejected (counted, never fatal). The scan identity is a SHA-256 over every
result-relevant input — kind, content digest, filename, URL identity,
source asset, hostname, technology hints — so two documents whose scans
differ can never collide on one accumulator entry or one cache key, and no
raw content byte ever reaches a cache-key payload.

### Pattern database

`internal/secrentel/patterns` is DATA ONLY: 43 pattern fingerprints across
the 35-type vocabulary plus a 22-provider correlation table (the fingerprint
count is asserted by the patterns package test), with
`SchemaVersion = 1` entering every scan cache key. Each pattern declares
provider, type, family, regex, capture group, trailing-material extension
(PEM key blocks), strength, length bounds, an offline structural validator
(JWT header/alg shape, hex, base64, UUID, mixed-alnum), an entropy rule
(minimum Shannon and class-normalized entropy), negative indicators,
positive indicators, and context hints. Families are contract: `structured`
(strong prefix/marker shapes, High eligible), `contextual`
(assignment-shaped matches — the variable name is part of the match —
Medium/High only with entropy support), `generic` (random base64 under a
generic name — capped at Low: "random base64" alone is never more than a
weak signal), and `public` (public keys, definitionally not secrets,
capped at Low). `Load()` validates every entry and compiles every regular
expression exactly once; the engine never compiles its own regexes.

ANCHORS are the database's performance contract: contextual and generic
families REQUIRE lowercase literal anchors (necessary substrings of any
match, e.g. `aws_secret_access_key` → "secret"). Case-insensitive regexes
cannot use RE2's literal-prefix fast path — a measured ~1000x per-pattern
penalty — so the scanner lowercases the document once and gates every
anchored pattern behind a substring check. Anchor-free content skips the
case-insensitive families entirely; measured scan throughput improved
~40x (1.2 → ~47 MB/s on a 512 KiB anchor-free bundle). Two structured
patterns carry optional anchors for the same reason (alternation or class
prefixes: `sk|rk _live_`, the Discord token's leading class).

### Scan pipeline

One bounded `runtime.Pool` owns all scheduling (mirroring techintel): one
job per document, cache-before-execute (operation `secret.scan`), bounded
per-pattern matches (64), per-document candidates (64, overflow counted),
evidence per candidate (8), and a per-document entropy memo (4096 values —
minified bundles repeat values constantly). The scan: pattern matching →
per-match validation (length bounds, negative indicators, structural
validators, false-positive VALUE classification, entropy rules) → dedup by
(type, value) with pattern-ID accumulation → cross-family duplicate
removal (contextual duplicates of structured matches and generic
duplicates of either are dropped: the specific classification wins) →
context extraction → correlation → confidence → canonical assets, evidence
records, and graph edges. RE2 has no catastrophic backtracking by
construction; every bound is a fixed constant that never enters cache keys.

### Entropy, context, correlation

The entropy engine is a pure observation (it NEVER classifies alone):
byte-level Shannon entropy, character-class detection (hex, base64url,
base64, alnum, other), class-normalized randomness, UUID and JWT shape
recognition, and length weighting (values under 32 bytes are progressively
weaker evidence). A pattern's entropy rule is a gate — values below the
minimum are DROPPED (counted) — and satisfied rules contribute one
confidence factor.

The context engine extracts the surrounding evidence of each match from a
±256-byte window: the assignment variable name or JSON key (backward scan,
separator-normalized so camelCase matches snake_case hints), comment
containment (//, #, unclosed /* */), nearby positive indicators, and
whether a pattern hint or the provider name appears in the name (the
strong context signal). Line/column locations come from a bounded line
index (65,536 tracked lines; matches beyond report line 0 — honest, never
unbounded).

Correlation accumulates evidence: provider ENDPOINTS observed in the
document (the 22-provider table: s3.amazonaws.com next to an AWS key),
provider TECHNOLOGIES (caller-provided techintel detections), same-provider
sibling PAIRS (AWS access key + AWS secret key → both boosted and
cross-linked), and cross-document REPEATS (the same (type, value) observed
under two source identities — each keeps its own candidate identity;
attribution is never merged away — widens the observation count and links
the siblings). Evidence must accumulate; a lone random base64 blob gains
none of these factors.

### Confidence model

Score = 1 − ∏(1 − wᵢ) over the recorded factors (pattern strength always;
entropy 0.35/0.15; context 0.4 strong / 0.15 weak; technology 0.25;
endpoint 0.3; pair 0.45; repeat 0.2 — the pair/repeat factors are appended
to the stored factor list and recomputed through the same pure function, so
cache-served and fresh candidates score identically). Caps, in order:
documentation/test context → 0.45 (Low); generic family → 0.45; public
family → 0.35; a structured match with ZERO supporting factors → 0.59.
Thresholds: ≥0.8 High, ≥0.5 Medium, ≥0.2 Low, else Unknown. Level gates:
High requires at least TWO non-pattern factors (never one signal);
Medium requires at least one. Thresholds, weights, and caps are fixed
constants — the confidence model is a documented contract, not
configuration.

### False-positive reduction

Two explicit layers. VALUE suppression — the candidate is NOT emitted
(counted with a reason): providers' documented EXAMPLE values (matched
case-sensitively so `db.example.com` hostnames in real connection strings
survive), placeholder/dummy/lorem markers, uniform filler runs, and short
plain words. CONTEXT capping — the candidate IS emitted but capped at Low:
test/spec/example/docs/mock/fixture/tutorial markers in the filename or URL
path (a test file can still contain a real secret — the observation is
honest, the confidence is not). Additionally: entropy rules drop prose;
cross-family duplicate removal drops re-classified values; Stripe test keys
(`sk_test_`) are deliberately not matched at all.

### Cache integration

Operation `secret.scan`, keyed on the scan identity plus the pattern schema
version, the engine analysis version, and the result-relevant metadata the
identity does not already cover. A completed hit serves the stored scan
with ZERO analysis (pinned by the Metrics.Scanned counter) and rebuilds the
identical graph from the stored edge source and evidence links. Truncated
documents are stored `StatusIncomplete` and NEVER served as hits — their
prefix candidates still report for the run (the AGENTS.md rule: truncated
results are never completed and never served from cache). Decode
re-validation covers the envelope, payload version, kind, timestamps,
counts within caps, canonical candidate assets (round-trip through the
asset constructor), families, levels never stronger than the score allows
and re-gated from the stored factor list (High needs two non-pattern
factors, Medium one — a stored level the factors could never produce is
tampering or a bug), factor weights in [0,1], confidence caps re-derived
from the stored candidate's own type/family/FP flags (a score above the cap
the current engine could produce — or a url_type_cap marker absent where
the type is capped, or present where it is not — is tampering or a bug),
the stored score equal to the score recomposed from the stored factors
through the same pure functions (a factor list that contradicts its own
score is tampering or a bug), canonical
evidence, evidence links, and edge-kind
consistency with the document; a rejected record is deleted and recomputed
in the same run (self-healing). Failed and cancelled documents are never
stored. Cache hits replay stored FirstSeen/LastSeen; the verification queue
is never cached.

### Statuses, limits, and determinism

Entry statuses: completed / incomplete (truncated prefix) / cancelled /
failed, plus run-level malformed counting. Fixed limits: content 2 MiB,
64 candidates per document, 64 matches per pattern, 8 evidence records per
candidate, 4 nearby indicators, ±256-byte context windows, 65,536 tracked
lines, 4096-entry entropy memo, 512 queue entries (overflow counted), 32
run diagnostics. Reports are fully deterministic: secrets by score
desc then candidate ID, evidence and relationships by identity, the queue
in priority order — two identical runs produce identical reports (pinned
by test), and a cache-served run produces the identical report modulo the
Cached flag.

### Security considerations

- Regex DoS: RE2 (Go's regexp) has no catastrophic backtracking by
  construction; every pattern is compile-once and data-validated; matches
  and candidates are hard-capped per pattern and per document.
- Resource abuse: documents are bounded at ingest (2 MiB); the line index,
  entropy memo, context windows, evidence, and diagnostics are all bounded;
  the pool bounds concurrency with backpressure (verified leak-free under
  cancellation by test).
- Cache poisoning: strict decode re-validation (see "Cache integration") —
  tampered, corrupt, or contradictory records are deleted and recomputed,
  never served; the truncated-as-completed tamper class is rejected
  explicitly.
- Secret handling: values are bounded to the asset layer's 512-byte stored
  form; error strings and diagnostics never echo secret values —
  decode-rejection diagnostics carry only a redacted candidate form (type
  plus a 4-byte SHA-256 prefix), never the candidate value; cache keys
  carry content digests, never raw bytes.
- Verification boundary: nothing is ever validated online; the queue is
  bookkeeping for a future phase, and no severity is ever claimed.

### Known limitations

- Library capability only: no CLI command.
- Candidates are detected, never verified; the queue is not execution.
- Assignment-shaped (contextual) patterns depend on the variable name
  appearing in the same statement; minified single-letter names still match
  but carry only weak context.
- The anchor gate trades a bounded amount of recall for speed: a Discord
  bot token in a document containing neither "discord" nor a bot-token
  name anywhere is not scanned for (documented, deliberate).
- Source-map documents are scanned as JSON-shaped content; dedicated
  source-map semantics (sourcesContent walking) is future work.
- Context extraction is lexical (backward scans), not a parser; quoted-key
  forms like `config["apiKey"]` yield no name.
- Cache hits replay stored FirstSeen/LastSeen; TTL expiry (when
  configured) bounds staleness.
- All tests and benchmarks are hermetic: synthetic input and a real
  filesystem-backed cache, never the public Internet.

## Priority engine

Priority intelligence (phase 9; `internal/priority`) is a library-level
engine with no CLI command yet: the Attack Surface Intelligence Engine.
It consumes canonical Phase 2 assets reduced to scoring signals —
already normalized by the earlier phases — and produces explainable,
deterministic priorities for which surfaces deserve a researcher's
attention first. It is explicitly NOT a vulnerability detector: it never
claims a weakness, never assigns severity, and never tests anything;
every score is a ranked, fully explained interestingness judgment whose
every factor cites the canonical asset identity it was derived from.

### Layer and data flow

```text
signal channel
  → reader (validate at ingest, pre-register cancelled placeholder)
  → runtime.Pool (bounded workers, optional central job-start limiter)
      → job: cache lookup → score → store      ← the consumer composes
  → merge-at-emit accumulator (deterministic duplicate merge)
  → Report (per-asset outcomes + aggregate outcome)
```

The layering follows the architecture rule exactly: `internal/runtime`
never imports `internal/cache`; THIS consumer stage performs the
cache-before-execute sequencing (lookup → score → store) around pool
jobs, exactly like discovery, dns, httpprobe, urlintel, techintel,
jsintel, and secrentel before it. The layer sits after the intelligence
phases (it consumes their outputs as signals) and before a future
reporting phase.

### Catalogs and the scoring contract

Two data-driven catalogs — interestingness (40 entries) and risk (13
entries), 53 total — are validated and compiled once at load: unique
lowercase IDs, weights in (0,1] with NaN rejected, exactly one matcher
form per entry (literal terms, regex, a JavaScript size threshold, or a
kind equality), and templated reason AND recommendation texts carrying
EXACTLY ONE `%s` substitution seam each — their only percent sign: any
other `%` (a second verb, `%q`, `%d`, `%%`, …) fails the load, because
score-time rendering substitutes the matched term for exactly one
occurrence and any other percent would leak into the emitted factor raw;
verbatim regex/size/kind texts must be percent-free. The worst-case
rendered length is bounded at compile time
(`len(template) − len("%s") + maxTermBytes ≤ bound` for term entries,
verbatim bounds for the rest) so no matched term can push an emitted
factor past the model-side bound. Every entry carries a recommendation
that references its evidence type — the production-table test rejects
generic boilerplate — and the guidance language is reconnaissance only
(inventory, verify, record; never an exploitation instruction).

Signals carry only data the earlier phases actually emit: paths, host
labels, technology names/categories with the detection phase's own
confidences, secret candidate types with the secret engine's own
confidences, parameter names, service names, ports, bounded
final-response headers, JavaScript bundle sizes, asset kinds, and
endpoint classes. The confidence sub-score is composed ONLY from those
recorded confidences plus the cross-source observation count — never
invented. The overlap policy emits one factor per (category, field)
group: the longest matching literal term wins, literals beat
regex/size/kind matches, ties break by indicator ID. NaN is hardened at
the type level — `Factor.validate` rejects NaN weights, and the
clamp/combine helpers are NaN-safe (NaN maps to zero contribution) — so
a NaN can never become a score.

Composition (the same combine math as the confidence engines):

```text
score   = 1 − ∏(1 − w_g)        over groups g
w_g     = min(cap_g, 1 − ∏(1 − w_f))   over group g's factors f
cap_g   = 0.6 per indicator category; 0.5 for the confidence group
level   = gated: high ≥ 0.8 AND ≥ 2 indicator categories;
          medium ≥ 0.5 AND ≥ 1; low ≥ 0.2; else unknown
```

The single composition point (`compose`) is shared by surface scoring,
the correlation aggregate, and cache decode re-validation, so every
consumer provably uses the same math.

### Correlation, attack paths, recommendations

`Correlate` groups scored surfaces deterministically. Grouping keys are
derived exclusively through the Phase 2 normalizers — there is no second
normalization: URL, endpoint, JavaScript, and source-map identities
re-parse through `asset.ParseURL` (endpoints drop their `"METHOD "`
prefix, the shape `asset.Endpoint` itself defines) to the canonical
host; the host canonicalizes through `asset.NewHost` (or `asset.NewIP`
for address literals); a name with three or more labels anchors at its
first-label-dropped parent (re-validated through `asset.NewDomain`),
shorter names at themselves; IP surfaces anchor at themselves; anything
that does not re-canonicalize forms an honest singleton group at its own
identity. A group's aggregate score recomputes through `compose` over
the UNION of its retained members' factors — repeated indicators
strengthen the aggregate up to the cap, never past it — and
`SharedIndicators` is the intersection of the members' factor names.
Output is bounded (1024 groups, 64 members per group) with every cut
surfaced: `Group.Truncated` flags a per-group member cut, and
`Correlate`'s boolean return flags the run-level group cut (a truncated
result is never silently presented as complete). Groups sort by
(score desc, anchor asc) and members by (score desc, identity asc,
serialized surface asc) — total orders, so identical input produces
bit-for-bit identical output.

`AttackPaths` derives evidence-tied reconnaissance hypotheses from the
groups: for each group with contributing members, an ordered walk — the
correlation root (citing the member identities it groups), then one step
per contributing member ordered container-first (domain → host →
URL/endpoint/JavaScript/source map → other), each citing the member's
highest-weight factor with its EXACT reason and a deep copy of its
evidence references (steps never alias the factor's backing array). The last
contributing step is the final evidence attachment. Bounds: 8 steps per
path (truncation flagged), 32 paths per run, ranked by group score. An
attack path is a reading order for a human researcher — a recon
hypothesis, NEVER an exploitation chain, never a vulnerability claim;
nothing about a path has been tested.

Recommendations ride ON the factors: the winning catalog entry's
template is rendered at score time with the matched term substituted,
so the `%s` substitution contract holds exactly (the term exists only
at match time) and the recommendation survives cache round trips
verbatim as part of the serialized factor. `Recommend` is a pure
projection of a surface's factor list — deterministic, evidence-tied,
no catalogs, no clock, no I/O.

### Cache integration

One `priority.score` record per cacheable signal, cache-before-execute
composed inside the engine stage. The key (`cache.NewKey`) contains:
the operation; the cache schema version (by construction); the priority
`SchemaVersion`; a combined FNV-1a digest of BOTH compiled catalogs
rendered entry-by-entry — ANY catalog edit (weight, term, regex,
threshold, kind, reason, recommendation) changes the digest and
invalidates every cached score; and a SHA-256 fingerprint of every
score-material signal field (identity, kind, path, host, endpoint
class, parameters in given order, bundle size, technologies with
confidences, secrets with confidences, port, service, headers,
observation count). Observation timestamps (`FirstSeen`, `ScoredAt`)
deliberately do NOT enter the key: they are echoed result metadata, not
score inputs — including them would bust the cache on every distinct
timestamp while producing bit-identical scores.

Strict decode re-validation: EVERY decoded surface is re-validated
before use — the envelope (completed status, operation, matching
target, payload version), the identity (non-zero, equal to the signal's,
kind mirror consistent, canonically parseable through the Phase 2
builders for its kind), the level (known, and exactly the level the
stored score and category count re-gate to), every factor
(`Factor.validate`, including the NaN weight guard, within the factor
bound, indicator factors carrying a bounded recommendation and
confidence factors none), and the numbers (score, interestingness, and
confidence finite in [0,1] and equal to `compose` re-run on the stored
factor list). Any failure treats the record as a miss and EVICTS it;
the engine recomputes and re-stores in the same run. The encode side
mirrors the same gate (only surfaces that would re-validate are
stored), and signals whose identities do not re-parse canonically
bypass the cache entirely (no read, no write — mirroring discovery's
unknown-tool rule) while still being scored, keeping the Round-1
`ScoreSurface` contract unchanged.

### Engine semantics

The engine (`Score`) reads a signal channel (the receive selects on the
run context, so a stalled producer cannot wedge a run), validates at
ingest (invalid signals become per-asset failed results with structured
errors — never panics), pre-registers a cancelled placeholder per valid
signal (a job dropped by a forced shutdown still appears in the report
with an honest status), and submits one bounded job per signal.
Duplicate identities merge deterministically: completed beats failed
beats cancelled; among completed results the higher score wins, ties by
the smaller serialized surface — the kept result never depends on
processing order. An optional emit hook fires per processed surface
(fresh or cache-served) with panics contained: a panicking hook surfaces
as one bounded run diagnostic while the asset itself stays completed.
Shutdown drains with the
shared bounded budgets; cancellation leaves no goroutines behind (pinned
by leak tests under both normal and cancelled runs).

Outcome vocabulary: per asset — completed (fresh or cache-served),
failed (structured error attached), cancelled (work never executed); at
run level, derived in fixed priority order — any cancelled →
`cancelled`; failed alongside completed → `incomplete` (the vocabulary's
"partial": successes kept and reported, the run not completed); all
attempted failed → `failed`; otherwise `completed`. A warm cache hit
serves the stored surface with ZERO scoring (asserted by the metrics
and the warm-run bench).

### Known limitations

- Library capability only: no CLI command yet; the reporting phase that
  would consume groups, paths, and recommendations is a later roadmap
  milestone.
- Correlation anchors derive from identity values alone (no
  relationship traversal): surfaces whose host cannot be derived from
  their identity form singleton groups.
- Attack paths are hypotheses over recorded evidence only; they never
  claim reachability, exploitability, or any tested behavior.
- The catalog digest is an FNV-1a 64-bit fingerprint: collision-safe for
  change detection by construction of the test (every field edit
  changes it), though it is not a cryptographic commitment.
- NaN-weighted records cannot exist on disk (encoding/json refuses
  NaN); the decode-side NaN guard is defense in depth behind the cache
  layer's own corrupt classification, and is pinned by unit tests.

## Detection framework

The detection framework (phase 10; `internal/detect`) is a library-level
engine with no CLI command yet: the Detection Framework & Rule Engine. It
executes reusable detection rules against the canonical knowledge graph
and produces canonical Findings. The framework itself detects nothing —
there are no vulnerability-specific rules in this phase (XSS, SSRF, BAC,
SQLi, CVE matching, browser automation, exploitation, and AI are all
explicitly out of scope and all deferred to future phases); the framework
is only the execution engine future detectors plug into.

### Finding model

The Finding landed in the Phase 2 asset model (`asset.Finding`, following
the Technology and SecretCandidate precedent): one structured,
evidence-cited judgment a rule produced about one subject asset. Fields:
identity, category, rule ID and name (denormalized), subject, confidence
in [0,1] (NaN rejected), evidence records (Phase 2 `asset.Evidence`, at
least one REQUIRED — a judgment that rests on nothing is not
representable), related assets, related-asset relationships (typed edges
between the cited assets; a finding is a judgment about assets, never a
graph node with its own edges), priority (an attention-ordering label —
info/low/medium/high/critical — never a severity or exploitability
claim), status (open; dismissed reserved for downstream bookkeeping),
created/updated timestamps, and metadata as a bounded TYPED
`map[string]string` (16 entries, 64-byte keys, 256-byte values — never an
anonymous map). The identity is "ruleID@subject" (each component
percent-encoded) under the new `finding` kind, so the same rule firing
twice on the same subject is one finding that merges
(`MergeFindings`: earliest created, latest updated, max confidence,
denormalized fields from the higher-confidence side with a total-order
tie-break, unioned deduplicated evidence/related/relationships) — and a
finding can never collide with any other asset kind. The evidence
vocabulary gained the `detect` method (mirroring phase 8's `secret`): the
indicator is the rule ID, the source is the finding's subject.

### Rules and registration

A Rule is an immutable descriptor plus a Detector function:
`func(ctx context.Context, dctx *Context) ([]asset.Finding, error)`. The
descriptor carries the canonical ID (lowercase slug charset), name,
description, one of 14 categories (information, misconfiguration,
exposure, authentication, authorization, configuration, discovery, cloud,
api, javascript, secrets, infrastructure, business_logic, custom), a
"major.minor.patch" version, declared input domains (exactly the Context
domains), outputs (findings — evidence and relationships ride ON
findings), dependencies (≤ 16 rule IDs), required asset kinds (validated
through the new `asset.Kind.Valid`/`KnownKinds`), estimated cost class,
timeout (> 0, ≤ 10 min), author, and the enabled flag. The Registry
validates everything at Register — metadata completeness, duplicate IDs,
duplicate names (case-insensitive), vocabularies, dependency syntax, nil
detector — and rejects invalid rules at startup, never at execution.
Registered rules are deep-copied on the way in and on the way out, so no
caller-held alias can mutate a registered rule. The registry cap is
FIXED and INTENTIONAL at 4096 rules — far above the documented
100/500/1000 performance targets, and there is no requirement to exceed
it.

### Dependency model

Dependencies order execution; they do not (yet) flow data. Layered Kahn
elimination computes deterministic dependency levels in O(V log V + E)
(no quadratic scheduling): level 0 holds every dependency-free rule,
level n+1 every rule whose dependencies all live in earlier levels, IDs
sorted within each level. Cycles and missing references are rejected
(before every run, and by `Registry.Validate` at startup) with the
smallest offending rule named. At execution, a rule runs only after every
dependency COMPLETED; a failed, cancelled, or skipped dependency cascades
an honest skipped result naming the dependency and its status. Extending
the Context with prior-rule outputs is documented future work.

### Detection context and execution

`Snapshot` is the caller-composed run input: the canonical structured
corpus (core assets as identities, relationships, evidence, technologies,
secret candidates, JavaScript, endpoints). It is NOT untrusted tool
output — every entry must be a canonical Phase 2 value;
`normalizeSnapshot` validates each entry (round-trips through the Phase 2
builders), bounds every domain (assets 100k, relationships 200k, evidence
100k, technologies 50k, secrets 50k, JavaScript 50k, endpoints 100k —
over-bound input is REJECTED, never silently truncated, because
truncating input would silently change findings), deduplicates through
the Phase 2 merge primitives, sorts by identity, and derives the observed
identity set plus the per-kind census. The `Context` handed to detectors
carries exactly: the seven corpus domains, the bounded configuration map
(64 entries), a bounded Logger (256 retained entries, oversized messages
truncated, excess counted), and the injected Clock — nothing else; the
cancellation context is the detector's first argument. Rules operate only
on these structured domains: no raw HTTP parsing, no JS parsing, no URL
parsing (those phases are complete).

The engine deliberately passes ONE Context to every rule of a run: the
same immutable snapshot (all seven corpus domains), bounded Config map,
bounded Logger, and injected Clock are shared across every rule, and
rules within a level execute in parallel on the shared runtime pool. The
Context is immutable by contract, not by enforcement — a rule must not
mutate it or any state it references, and a mutating rule is a data race
by definition. The engine neither detects nor isolates such violations:
rules are trusted, in-repo code, and a rule that mutates its Context is
a rule bug, not an engine hazard.

One bounded `runtime.Pool` per run owns all scheduling (no new
scheduler): exactly one job per rule, per-job deadline = the rule's own
timeout (belt: the pool's deadline; suspenders: the engine wraps the
detector call in `context.WithTimeout`), rules within a level in
parallel, levels strictly ordered. Every level's wait is
cancellation-aware (a resolution channel per level; jobs dropped by a
forced shutdown keep honest cancelled placeholders, and EVERY registered
rule appears in the report). Detector calls are panic-contained: a
panicking rule fails alone with a structured error (metrics count it),
never taking down the worker, the run, or sibling rules. Findings
validate against the framework's output contract (below), merge by
identity, stream through an optional per-finding emit hook (hook panics
and errors are contained as run diagnostics — findings are never lost),
and land in the deterministic Report: rules sorted by ID, findings sorted
by identity under the 4096-finding run cap (cut surfaced through
FindingsTruncated, never silent — and the run's outcome becomes
incomplete: truncated results are never completed), counts, aggregate
outcome in the house vocabulary (any cancelled → cancelled; a truncated
findings list → incomplete even when every attempted rule completed;
failed alongside completed → incomplete; all attempted failed → failed;
skipped rules — disabled, required-kind-absent, or cascaded — are honest
observations that do not force a non-completed outcome), the bounded rule
logs, and cache-hit counts. Two identical runs under an identical
injected Clock produce identical reports (pinned by test) — identical up
to the findings cap: above the 4096-finding cap the retained findings
are the completion-order prefix, which is not deterministic across runs.
Execution timings live in Metrics, never the Report.

The output contract (enforced identically for fresh and cache-served
findings): the finding re-validates canonically through
`asset.NewFinding` and round-trips byte-identically; the denormalized
rule metadata (RuleID, RuleName, Category) matches the EXECUTING rule
exactly — the finding-corruption guard that makes it impossible for a
rule to forge another rule's findings; the priority and status labels are
known vocabulary; the subject, every related asset, and every evidence
record's source asset were OBSERVED in the corpus (findings can never
cite assets the earlier phases never produced — not as the subject, not
as a related asset, not as an evidence source); and an optional
"rule_version" metadata entry must equal the
executing rule's version. A rule that returns more than 256 findings, or
any contract-violating finding, fails with a structured error.

### Cache behavior

One `detect.rule` record per rule per run, cache-before-execute composed
around pool jobs exactly like the other consumer stages (the runtime pool
stays cache-independent). The key (`cache.NewKey`) carries: the
operation; the detect `SchemaVersion` (`2` today — records written under
version 1 are refused at decode and self-invalidate); the rule ID (the
target) plus the
fingerprint of the rule's full declared metadata — version included; the
documented contract is that a rule's Version is bumped whenever its
detector logic changes, so a bump invalidates its cached results; the
fingerprint of the normalized snapshot — identities plus every observable
JavaScript asset field (content hash, size, content type, ETag,
last-modified, discovery source, status code, final URL, host) and full
provenance — source, reference, confidence — on JavaScript, technology,
evidence, endpoint, and secret entries. Relationships carry no provenance
in the asset
model, so their edge ID is the complete observable. Provenance
timestamps (DiscoveredAt) are deliberately excluded from every form
(echoed metadata that changes every run while
producing identical findings); and every run configuration entry
(prefixed). Only COMPLETED executions are cached — partial executions
(failed, timed out, cancelled, panicked) are never stored, never served.
Decode re-validation is strict: envelope (status, operation, target,
payload version) plus EVERY finding through the same output-contract
validation; a rejected record is deleted (evicted) and recomputed in the
same run, never served.

### Metrics and benchmarking

`Metrics` accumulates — per rule and in aggregate — executions, total
execution time, findings, errors, timeouts, panics, and cache hits and
misses; snapshots are consistent and per-rule stats sort by ID; a nil
Metrics is a no-op. `BenchmarkDetector` measures any rule (registered or
not) against a snapshot: bounded iterations, each under the rule's own
deadline with the engine's panic isolation, findings validated through
the same contract, deterministic min/max/mean/median duration summary.

### Security considerations

- Panic isolation: detector and emit-hook panics are recovered and
  contained as structured per-rule errors or bounded run diagnostics; a
  malicious rule cannot crash the run or corrupt sibling results.
- Finding corruption: the executing-rule metadata match makes cross-rule
  forgery unrepresentable; observed-corpus membership makes fabrication
  unrepresentable; both checks run identically on cache-decoded records.
- Cache poisoning: strict decode re-validation with eviction-and-recompute
  (see "Cache behavior"); the schema version, rule fingerprint, snapshot
  fingerprint, and configuration all enter the key.
- Resource exhaustion: bounded pool and queue (backpressure), per-rule
  deadlines, snapshot bounds (reject, never truncate), per-rule and
  per-run finding caps, bounded diagnostics, bounded logs, bounded
  metadata, and the bounded registry.
- Dependency loops: rejected before any work executes, deterministically.
- Inherent limit (mirroring the runtime engine's documented one): a
  detector that ignores its context can delay its level's barrier and the
  run until it returns — contexts and deadlines bound cooperative
  detectors; no hard preemption exists or is claimed.

### Known limitations

- Library capability only: no `ravenrecon detect` CLI command.
- No rules ship with phase 10; the framework is the plug-in surface for
  future detector phases.
- Dependencies order execution but do not yet flow data between rules;
  the Context's domains are the fixed pre-run corpus (documented future
  work).
- The detector closure is not fingerprintable; the version-bump contract
  (bump Version when logic changes) is the cache-coherence mechanism.
- Streaming order across parallel rules is completion order; the REPORT
  is the deterministic artifact.
- Findings carry a researcher-attention priority, never a severity; no
  verification, exploitation, or submission is represented or claimed.
- All tests and benchmarks are hermetic: synthetic corpora and a real
  filesystem-backed cache, never the public Internet.

### SDK contract

Milestone v1.2.5 freezes the rule-author surface as "SDK v1 (Core)" at
API level 1.0 (`APIMajor = 1`, `APIMinor = 0`). The freeze itself is
documented in `internal/detect/api.go` (three-layer versioning and the
Level-1 stability policy) and `internal/detect/doc.go`; this subsection
is the pack-author guide: the lifecycle, the rule contract, the finding
contract, the pack story, and the tests that are the executable
documentation. Every claim below is verifiable against the code it names.

#### Lifecycle

```text
Rule (immutable descriptor + Detector)
  |
  v
Registry: Register -> Validate -> Seal        registration confined to startup
  |                                            (deep copies; never mutated)
  v
Run(ctx, EngineConfig{Registry, ...}, Snapshot)
  |   normalizeSnapshot: bound, deduplicate, sort; derive the observed
  |   identity set and the per-kind census (the RequiredAssetTypes gate)
  v
one bounded pool job per rule, dependency levels in order
  |   cache-before-execute per rule:            <- findings cached per
  |     key = Operation "detect.rule"             (rule, snapshot, config):
  |         + detect SchemaVersion (= 2)          SchemaVersion=2 enters the
  |         + fingerprintRule(rule)                key and the stored payload;
  |             (full declared metadata,          fingerprintRule covers the
  |              Description included)            full declared metadata;
  |         + rule Version                        a Version bump invalidates
  |         + snapshot fingerprint                the rule's cached results;
  |         + every cfg:* config entry            only COMPLETED executions
  |                                               are stored, never partial
  v
Detector(ctx, Context) -> []asset.Finding
  |   validateFinding: canonical round-trip; denormalized RuleID/RuleName/
  |     Category match the EXECUTING rule; subject, related assets, and
  |     evidence sources were observed in the corpus
  v
Report (RuleResults sorted by ID; Findings merged and sorted; outcome;
        counts; bounded logs)
  |
  v
Report consumer (reporting framework, TUI, next pipeline stage)

Finding vocabulary path (asset.Finding, identity "ruleID@subject"):
  Category — the rule's declared label (14 fixed values), denormalized
             onto every finding the rule emits
  Priority — info / low / medium / high / critical: attention ordering
             only, NEVER a severity or exploitability claim (the
             framework defines no severity vocabulary)
  Status   — open / dismissed: the framework emits open only; dismissed
             is downstream consumer bookkeeping
```

#### Rule authoring contract

A rule is a `detect.Rule` value: an immutable metadata descriptor plus
a `Detector` (`func(ctx context.Context, dctx *Context) ([]asset.Finding,
error)`). The engine enforces the contract at registration and at
execution; the single validation entry point is `ValidateRule`, which
`Registry.Register` and `BenchmarkDetector` both delegate to — a rule
rejected there is rejected identically everywhere.

- **Metadata.** `ID` is the canonical lowercase slug: letters, digits,
  `.`, `-`, `_`, at most `MaxRuleIDBytes` (128) — the shape enforced by
  `validateRuleID`, which also guards every dependency reference. `Name`
  and `Description` are required and bounded; `Category` must be one of
  the 14 fixed labels; `Version` must be numeric "major.minor.patch"
  (`ParseRuleVersion` is the exported parser, shared with validation);
  `Inputs` and `Outputs` are non-empty, duplicate-free vocabulary lists;
  `Dependencies` (at most `MaxRuleDependencies` = 16) are rule IDs, never
  self-references; `RequiredAssetTypes` are validated `asset.Kind`
  values; `EstimatedCost` is one of low/medium/high; `Timeout` is
  `> 0` and at most `MaxRuleTimeout` (10 min); `Author` is required;
  `Detector` must not be nil. `Enabled = false` keeps the rule
  registered and validated but skipped at run time.
- **The version-bump contract** (documented on `Rule.Version` in
  rule.go): bump the version whenever the detector's logic or metadata
  changes — the version enters the rule result cache key, so an edit
  without a bump can serve stale cached findings. The examples pack
  demonstrates the contract in its own style:
  `example.relationships.degree-index` is the pack's only rule at
  `1.0.1` (every other rule sits at `1.0.0`).
- **Inputs and required kinds.** `Inputs` is descriptive metadata
  ("the Context always carries every domain and a rule reads what it
  declared"); `RequiredAssetTypes` is a run-time gate — when the
  snapshot's census shows zero members of a required kind, the engine
  skips the rule with an honest reason instead of executing it against
  nothing.
- **Config, logging, time.** `Context.Config` is the run's bounded
  typed map (at most `MaxContextConfigEntries` = 64 entries, keys ≤ 64
  bytes, values ≤ 256 bytes) and every entry enters the rule's cache
  key. `Context.Logger` is the bounded logging seam (at most
  `MaxLogEntries` = 256 retained entries, messages truncated at
  `MaxLogMessageBytes` = 512, excess counted); a caller-provided logger
  replaces the engine's default, and only the default's entries surface
  on the Report. `Context.Clock` is the injectable time seam — findings
  must be stamped with it (`dctx.Clock.Now()`), never the wall clock,
  or reports stop being deterministic.
- **Determinism.** A rule must be a deterministic function of its
  Context: the engine shares ONE immutable Context across every rule of
  a run, rules within a level execute in parallel, and identical runs
  under an identical injected Clock must produce byte-identical reports
  (pinned by `TestContractRunDeterminismByteIdentical` and the pack's
  `TestPackDeterministicReports`). A rule that mutates the Context is a
  data race by definition — the engine documents the boundary, it does
  not police it.

#### Finding contract

Findings are canonical `asset.Finding` values built through
`asset.NewFinding` (which requires at least one evidence record — a
judgment that rests on nothing is not representable) and validated by
`validateFinding` on both the fresh-execution and the cache-decode
paths, identically:

- the finding re-validates canonically and round-trips byte-identically;
- the denormalized `RuleID`, `RuleName`, and `Category` match the
  EXECUTING rule exactly — a rule can never forge another rule's
  findings;
- `Priority` and `Status` are known vocabulary values;
- the subject, every related asset, and every evidence record's source
  asset were OBSERVED in the run's corpus — findings can never cite
  assets the earlier phases never produced (the observed-corpus rule;
  the examples pack demonstrates both sides: `endpointCoverageDetector`
  cites a URL only when the corpus observed it, and
  `degreeIndexDetector` skips relationship endpoints the corpus never
  observed);
- an optional `rule_version` metadata entry must equal the executing
  rule's version.

A rule that returns more than `maxFindingsPerRule` (256) findings, or
any contract-violating finding, fails with a structured error. The
finding identity is `ruleID@subject` under the `finding` kind, so the
same rule firing twice on the same subject merges into one finding
(`MergeFindings`).

#### The pack story

`internal/detect/examples` (package `examples`) ships as a SIBLING
package of the framework, loaded explicitly by importing it — the
framework auto-detects nothing, and "no rules ship with the framework"
stays true: package `detect` contains no rule definitions, and a pack
is just another caller of the exported SDK. Because the pack can use
only what `internal/detect` exports, it proves by construction that a
pack loads, validates, and runs without special-case code in the
framework (the Go compiler enforces this; `TestPackUsesOnlyExportedSurface`
carries it into the suite). The pack gates itself at load time: its
`Rules()` entry point begins with `detect.CheckAPIVersion(1, 0)`
(`requiredAPIMajor`/`requiredAPIMinor` constants), so an incompatible
SDK level surfaces as a structured load-time error before any rule is
registered. Its six rules exercise every Context domain, the dependency
pair (`example.relationships.degree-index` depends on
`example.assets.census`), `RequiredAssetTypes` gating
(`example.technology.version-listing`), config + logging + the
empty-output path (`example.config.audit-summary`), observed-corpus
citations, and the cache round-trip; its content policy is mechanical
demonstration only (`example.` IDs, information/discovery categories,
never vulnerability detections). A pack's registration pattern is:
`examples.Rules()` → `NewRegistry` + `Register` per rule →
`Registry.Validate()` (dependency graph) → optional `Registry.Seal()` →
`Run` with `DefaultEngineConfig`.

#### Executable documentation

The milestone's contract tests are the runnable form of this guide:

- **Surface snapshot** — `TestSDKAPISurfaceSnapshot`
  (`internal/detect/surface_snapshot_test.go`) serializes the package's
  exported surface from its own Go source and diffs it against
  `internal/detect/testdata/api_v1.golden`: any added/removed symbol,
  changed signature, changed struct field/tag, or changed constant
  value fails. Regeneration is opt-in only:
  `go test ./internal/detect/ -run TestSDKAPISurfaceSnapshot -update`.
- **Behavior contracts** — `internal/detect/behavior_contract_test.go`:
  nine semantic contracts (`TestContractSealRejectsLateRegistration`,
  `TestContractPostSealReadsStillWork`, `TestContractRegisterDeepCopiesRule`,
  `TestContractGraphValidationDeterministic`, `TestContractAPIVersioning`,
  `TestContractVocabularyCompletenessAndRoundTrip`,
  `TestContractReportOutcomeVocabulary`,
  `TestContractRunDeterminismByteIdentical`,
  `TestContractContextImmutabilityHonestBoundary`).
- **SDK unit surface** — `internal/detect/sdk_test.go`:
  `TestValidateRuleExportedAcceptsFixture`, `TestRegisterDelegatesToValidateRule`,
  `TestParseRuleVersion`, `TestSDKBoundsConstants`, `TestRuleBoundsEnforced`,
  `TestContextBoundsEnforced`, `TestRegistrySeal`, `TestCheckAPIVersion`.
  The seal race is pinned by `TestRegistrySealRegisterRace`
  (`registry_race_test.go`).
- **External examples** — `internal/detect/example_test.go` (package
  `detect_test`, exported surface only): `ExampleDetector`,
  `ExampleRegistry_Register`, `ExampleRun` (the full register → seal →
  cold/warm cached run, executed by `go test`).
- **Pack tests** — `internal/detect/examples/rules_test.go`:
  `TestPackRulesValidate`, `TestPackFullPipelineWithCache`,
  `TestDegreeIndexSkipsUnobservedNodes`, `TestPackDeterministicReports`,
  `TestPackUsesOnlyExportedSurface`.
- **Semantic compatibility** — the compat regression
  (`internal/detect/examples/compat_test.go` against
  `internal/detect/testdata/api_v1_report.golden`) replays a fixed
  snapshot through the pack and diffs the deterministic report against
  the pinned golden; it lands with this milestone and is part of the
  reopening gates below.

### SDK stability policy

The "SDK v1 (Core)" freeze is formalized as a three-level stability
policy. The levels name which exported surface changes require what
process; the mechanical gates are the tests listed under "Executable
documentation" above.

**Level 1 — frozen forever (the SDK contract).** The rule-author
contract: `Rule`, `Detector`, `Registry` (including `Seal`), `Context`,
`Finding` (the `asset.Finding` model), `Snapshot`, and `Run`, plus the
run-contract surface: `EngineConfig` and `DefaultEngineConfig`,
`Report`, `RuleResult`, `RuleStatus`, `Outcome`, the vocabularies
(`Category`, `RuleInput`, `RuleOutput`, `FindingPriority`,
`FindingStatus`, `Cost`, `LogLevel`, `LogEntry`, `Logger`) with their
`Valid`/`Parse`/`Known*` helpers, the cache constants (`Operation`,
`SchemaVersion`), `CheckAPIVersion`, `ValidateRule`,
`ParseRuleVersion`, and the 12 exported bounds constants
(`MaxRuleIDBytes` … `MaxLogMessageBytes`). Level 1 is pinned by the
surface snapshot golden, the nine behavior contracts, and the semantic
compat regression; any change to it happens ONLY through the reopening
process below.

**Level 2 — frozen after pipeline validation.** The instrumentation and
execution-observability surface: `Metrics`, `MetricsSnapshot`,
`RuleStats`, and any future event/metrics surface the engine gains.
These are currently EXCLUDED from the golden with documented reasons
(see the header of `surface_snapshot_test.go`: run-internal detail, not
a rule-author contract — packs never read them, and the only Level-1
touch point, the `EngineConfig.Metrics` field, stays pinned). They
freeze when a real pipeline consumer depends on them, per the roadmap
rule that public interfaces stabilize only after pipeline integration
or real-world validation.

**Level 3 — experimental.** Helper functions, benchmark utilities, and
internal optimizations: `BenchmarkDetector` and `BenchResult` today.
Their shape may evolve freely; a new experimental helper must be
deliberately added to the snapshot test's `excludedSurface` map with a
reason — never silently — and any exported symbol that is neither
Level-1 nor a named exclusion fails the surface snapshot test.

#### Versioning contract

The three layers are independent (documented in `api.go`):
`SchemaVersion` versions the cache record layout (a bump invalidates
stored rule results, never the SDK contract); `APIMajor`/`APIMinor`
version the frozen Level-1 surface; `Rule.Version` versions rule
content (the cache-coherence bump contract). Because the surface golden
pins the `SchemaVersion` constant itself, a record-layout bump follows a
documented carve-out: it regenerates the Level-1 golden in the same
change as the schema edit, with NO `CheckAPIVersion` bump — a schema
bump changes only cache-record layout and never the SDK contract.
`CheckAPIVersion` is the
single gate pack loaders call: compatibility holds exactly when the
required major equals this build's `APIMajor` and this build's
`APIMinor` >= the required minor — a major mismatch means the pack must
be recompiled, a too-new required minor means this build predates the
pack, and a minor bump is backward compatible (this build understands
every pack compiled against its own minor or lower). `TestCheckAPIVersion`
pins the gate's own semantics.

#### Reopening criteria

A Level-1 change requires all four steps, in order:

1. **A concrete failing need** — a pack inexpressible on the frozen
   surface. The standing bar is the v1.7 acceptance criterion: "Any
   SDK reopening is backed by concrete evidence, not preference"
   (ROADMAP.md).
2. **A proposal naming the exact symbols to change** and their new
   shapes.
3. **Maintainer approval** — the api.go policy: "a deliberate,
   documented reopening decision that bumps APIMajor — never a silent
   alteration of the contract."
4. **Golden regeneration and version bump in the SAME change** —
   regeneration of `testdata/api_v1.golden` and
   `testdata/api_v1_report.golden` plus a `CheckAPIVersion` bump
   (`APIMajor` for breaking changes, `APIMinor` for compatible
   additions) land in the same change as the surface edit, never in a
   follow-up.

The criteria are mechanically enforced: `TestSDKAPISurfaceSnapshot`
fails on any surface drift (the golden diff names every added/removed
symbol and changed shape); the nine behavior contracts fail on semantic
drift (seal semantics, deep copies, deterministic graph validation, API
versioning, vocabulary round-trips, outcome vocabulary, run
determinism, Context immutability); the semantic compat regression
fails on report output drift; and `TestCheckAPIVersion` fails if the
gate's semantics drift. A Level-1 change that passes every gate without
following the four steps above is evidence it was additive — and
additions to a frozen surface still require steps 2 and 3.

## Reporting framework

`internal/report` (phase 11) is the Reporting Framework & Evidence Export:
it consumes the canonical graph, findings, evidence, and metadata the
earlier phases produced and exports them as deterministic, reproducible
reports. Reporting is presentation only — the framework never rescans a
target, never mutates the data it is given, and never invents a field.
It is a library capability only; there is no `ravenrecon report` command
yet.

### Report lifecycle

1. **Context** — the caller composes one run input: the typed Phase 2
   corpus (domains, hosts, IPs, ports, services, URLs, endpoints,
   JavaScript, parameters, technologies, secrets, evidence, findings, TLS
   certificates, source maps, relationships), the priority engine's
   outputs (surfaces, groups, attack paths), the run's error log, and the
   run's runtime/cache/execution statistics. A Context entry that is not
   a canonical Phase 2 value is rejected with a structured error naming
   it — the same normalize-or-reject snapshot contract the detection
   framework enforces. The engine reads no wall clock: StartedAt/EndedAt
   are caller-declared inputs, so identical inputs produce identical
   reports.
2. **Model** — `NewModel` builds the canonical report model exactly once
   per run: every list is validated through the Phase 2 builders,
   deduplicated by identity, merged through the Phase 2 merge primitives,
   and sorted by canonical identity; surfaces, groups, and attack paths
   are deduplicated by identity and ordered by (score desc, identity
   asc); the recommendations are the deterministic `priority.Recommend`
   projection (capped at 10,000); the error summary groups by category
   with totals and bounded samples; and the statistics, run summary, and
   SHA-256 model digest are computed once. The digest covers every byte
   the exports render — corpus identities and observations, priority
   outputs and factors, recommendations, statistics, summaries, error
   records, and run metadata — so any export-visible change (a technology
   version, a finding's confidence, a factor list) changes the digest and
   therefore the render-cache key. Every renderer — current and future —
   renders from this one model, so no format re-validates, re-sorts, or
   re-traverses the corpus.
3. **Registry** — reports register like rules: `Reporter` carries the
   validated metadata (bounded lowercase ID, name, description, version,
   output format, compression support, enabled flag) plus the render
   function and an optional output validator. Duplicate IDs and duplicate
   case-insensitive names are rejected at registration; the registry is
   concurrent-read safe and optionally sealable. Four builtins ship
   (json, csv, markdown, html) through `NewDefaultRegistry`; future
   formats plug into the same contract.
4. **Render + commit** — the engine runs every active reporter as exactly
   one job on one bounded `runtime.Pool` (no new scheduler; default 4
   workers, bounded queue, per-render deadline, cancellation honored
   between output units). Each job renders into a `Sink`: every part
   writes to a unique temporary file in the output directory (created as
   needed, 0700/0600), is flushed and fsynced, VALIDATED on the temp
   file, and only then atomically renamed into place. A cancelled,
   failed, or invalid render therefore never leaves a file behind, and a
   failed render never overwrites the previous good one. Filenames are
   deterministic (`<base>.<ext>`, `<base>.<part>.<ext>` for CSV datasets,
   `.gz` when compressed), derived from a sanitized base name — no
   untrusted string ever reaches a filesystem path. Per-report outcomes
   follow the house vocabulary (completed/failed/cancelled/skipped), and
   the aggregate outcome folds them with the usual precedence.
5. **Validation** — every output is validated BEFORE exposure: JSON must
   decode as exactly one value carrying the framework's schema version;
   CSV must reparse completely with a header row and a uniform field
   count; Markdown must start with a heading and carry balanced code
   fences; HTML must be non-empty, closed, and carry balanced
   `<details>` sections. Custom reporters may install their own
   validator; the default requires non-empty (and decompressible)
   output.

### Output formats

- **JSON** — the complete canonical model as one compact, versioned
  (`schema_version`), machine-readable document: every dataset in
  identity order, the statistics, run summary, error summary,
  recommendations, and the model digest. Struct field order is fixed and
  map keys are encoder-sorted, so two renders of one model are
  byte-identical; HTML escaping is disabled so `<`, `>`, and `&` appear
  literally, as in the data.
- **CSV** — one table per dataset (hosts, urls, endpoints, technologies,
  secrets, findings), each with a header row even when empty. Every field
  passes `csvSafe`: a field beginning with `=`, `+`, `-`, `@`, tab, or CR
  is prefixed with a single quote, neutralizing spreadsheet formula
  injection in the presentation (the JSON export carries the exact
  bytes). UTF-8 is preserved; no BOM.
- **Markdown** — the human summary: target, summary, interesting assets
  (top 20 scored surfaces with their top factor), technologies, secrets,
  top findings (20), attack surface (top 20 groups, top 10 paths),
  recommendations, statistics, and errors; cell content escapes pipes,
  with content backslashes doubled first so a literal backslash-pipe can
  never re-parse as a live delimiter. Long lists are cut at
  documented bounds (200 rows per list) with honest "_And N more — see
  the JSON and CSV exports._" lines.
- **HTML** — a self-contained static report: inline CSS, native
  `<details>` collapsible sections, a global search box and a
  finding-priority filter driven by a small inline vanilla script (no
  frameworks, no external resources; the document is fully meaningful
  without scripting). Tables are capped at 1,000 rows with the same
  honest truncation note. Every interpolated byte passes
  `html.EscapeString`.

### Run summary, error summary, statistics

The run summary is the fixed-vocabulary block (target, times, duration,
assets, hosts, URLs, JavaScript, secrets, findings, rules, relationships,
recommendations, cache hits/misses, worker time). The error summary
groups the run's bounded error records into the fixed category vocabulary
(dns, http, tls, parsing, cache, timeout, cancellation, tool_failure,
permission, unknown) with per-category totals, unique counts, and at most
8 samples; `ClassifyError` derives categories structurally (context
cancellation, deadlines, DNS errors, URL errors, permission errors,
net-level timeouts) and never guesses from message text — callers that
know an error's stage record an explicit category. The statistics engine
computes the dataset census once (per-kind counts, asset total,
relationship count, surface/group/path/recommendation/rule counts, the
runtime/cache/execution statistics, and the duration).

### Render cache

The engine can optionally compose cache-before-execute around renders
through the existing `internal/cache` (operation `report.render`), off by
default (no cache configured). The key covers the operation, the model
digest, the reporter ID, the reporter's declared version (the same bump
contract as detection rules), the output format, and whether the output
is compressed — nothing timing- or path-derived. A hit serves the exact
stored bytes through the same atomic pipeline with zero rendering; the
record is strictly re-validated on decode (identity match on report ID,
version, format, and digest; declared part sizes must equal their bytes;
the total must sit under the cacheable bound; a zero-byte part payload is
refused outright with a descriptive error) and a violating record is
evicted and re-rendered in the same run, never served. Oversized renders
(total over 11 MiB, comfortably inside the cache's 16 MiB record bound
after base64 inflation) are honestly never cached — nothing is truncated
to fit a cache record. A failed store never fails the committed render.

### Performance and resource bounds

The documented targets (100 / 1,000 / 10,000 / 100,000 assets) are
covered by benchmarks: at 100,000 mixed assets the one-time model build
takes ~1.1 s, the JSON export ~0.6 s, and the CSV export ~0.2 s
(measured, not extrapolated; Markdown and HTML are bounded by their row
caps). Every renderer streams through a 64 KiB buffered writer — no
format buffers a whole report in memory — and every model list is bounded
by a fixed constant, with over-bound input rejected outright rather than
silently truncated.

### Reporting security considerations

- HTML escaping: every dynamic byte in the HTML export passes
  `html.EscapeString` in text and quoted-attribute contexts; the
  injection tests pin that hostile values (script tags, event-handler
  attributes, SQL-ish strings) never reach the document raw.
- CSV injection: `csvSafe` neutralizes spreadsheet formula prefixes in
  the CSV presentation only; JSON remains byte-exact.
- Path traversal: output filenames derive from `sanitizeBaseName`
  (lowercase, `[a-z0-9.-]` only, runs collapsed, both ends trimmed,
  bounded, non-empty) plus framework-vocabulary parts and extensions —
  no target- or caller-derived string reaches a path unsanitized, and
  the tests pin traversal-shaped inputs.
- Unsafe temporary files: every part renders into a `os.CreateTemp`
  file (0600, created in the output directory), fsynced before rename;
  aborted renders remove their temps, and no temp file is ever read as a
  report.
- Resource exhaustion: fixed bounds on every model list, error log, and
  recommendation projection; streamed rendering; per-render deadlines;
  the bounded pool; and the cacheable-render cap.
- Secret leakage: the exports present exactly what the caller's corpus
  carries — secret candidates are detection-only values the secret
  engine already bounded and truncated; the framework adds no redaction
  layer and no new secret surface (error records are caller-composed and
  message-bounded).

### Known limitations

- Library capability only: no CLI command.
- Multi-part commits (CSV) are atomic per file, not transactional across
  files.
- The HTML and Markdown exports are deliberately capped summary views;
  the complete datasets live in JSON and CSV only.
- The render cache stores base64-encoded bytes; at the 11 MiB cap a
  cached render re-materializes in memory during a cache hit (bounded,
  and the cache is optional and off by default).
- Reports render from the in-memory corpus; there is no persistent asset
  store to reload a past run's graph from yet (deferred roadmap work).

## Event bus

The event bus (roadmap v1.2, phase 12; `internal/event`) is the
observability foundation: the canonical runtime event model plus a
concurrent, bounded, non-blocking fan-out bus. It is OBSERVER-ONLY — the
data flow is one way (`instrumented code -> Bus -> consumers`), a consumer
can never call an engine through it, and no engine mutates run state
through it. The TUI controller is the first consumer (see "Terminal
observability" below); the runtime pool is already instrumented (see
"Runtime pool instrumentation" below), the cache is instrumented too (see
"Cache instrumentation" under "Cache and resume"), and loggers and replays
are later v1.2 items.

### Canonical event model

Every observability event is a structured, typed `Event`: a canonical
`Kind` (29 values: scan/worker/task/stage lifecycle, cache hit/miss, asset
discovered, relationship/evidence/finding/recommendation created, request
observed, rule executed, warning, error, progress, phase transition,
shutdown, run metadata, summary ready), a bus-assigned strictly increasing
`Sequence`, an injected-clock timestamp (`At`), a `Severity`
(info/warning/error), bounded context labels (`Phase`, `Category`,
`Identity`, `Value`, 512 bytes each via the `With*` constructors, rune-safe
truncation with an explicit "…" marker), and a sealed, typed `Payload`
(marker-method interface: anonymous maps are impossible; every field is a
documented projection of a real Phase 2 / runtime / report / detect /
priority field, with the source field named in the payload docs).
`Event.Validate` enforces the whole contract — known kind, non-zero
timestamp, valid severity, bounded labels, payload matches kind, and
per-payload field rules (message bounds, state vocabularies, confidence/
weight ranges, progress counts, cache-hit consistency) — so hand-built
hostile events cannot smuggle oversized values past consumers. Bounded
payload constructors (`NewWarning`, `NewError`, `NewTaskTerminal` and the
four terminal-task wrappers) truncate message/category fields at
construction, so a well-behaved emitter never produces an event the bus
must reject.

### Bus semantics

A `Bus` fans one event out to any number of `Subscriber`s, each with a
bounded buffer set at `Subscribe`. Publish never blocks the caller beyond a
bounded enqueue: a full buffer drops the event for that subscriber and
counts it (per-subscriber `Drops` and the bus aggregate), so a slow or dead
consumer can never stall a producer and never costs other subscribers
events. An event with a zero timestamp is stamped with the bus clock before
validation (emitters that do not track time can publish zero-timestamp
events; the canonical flow has emitters construct events with their own
injected clock and the bus preserves them). Invalid events are dropped and
counted in `Invalid` — never delivered, never sequenced. Valid events are
sequenced and delivered to every subscriber under the publish lock, which
makes the ordering contract real: every subscriber receives events in
bus-assignment order even under concurrent publish (delivery is a
non-blocking enqueue, so the lock hold is bounded and Publish remains
non-blocking). Subscribers are single-consumer: exactly one goroutine calls
`Next` (or receives from `Events`) at a time. `Close` is idempotent and
concurrent-safe; the `Done` channel fires exactly once, buffered events are
drained by `Next` before it reports `ErrSubscriptionClosed`, and the
delivery channel is never closed (consumers selecting on it must also
select on `Done`). `Bus.Close` closes every open subscriber and drops —
counted, unsequenced — all later publishes, and `Subscribe` after close
fails.

### Instrumentation contract

`Observer` is the single seam: instrumented packages (the runtime pool,
the cache, the pipeline runner, stage result bridges) accept an optional
`Observer` via their configuration; nil means zero behavior change. The
`Bus` satisfies
`Observer` (`Observe` is `Publish`), so instrumented code publishes
straight into a bus. Derived events — asset discovered, finding created,
relationship created — are produced only at the pool-job boundary by the
`Deriving` bridge: it forwards every observed event untouched and, for
`task_completed` events, passes the raw job result to the caller-provided
`Deriver`, whose returned canonical events are forwarded after the terminal
event. Engines never emit events themselves; a `Deriver` must recognize
only its own result types (nil otherwise), never mutate the terminal event,
return only valid events (the bus drops and counts anything else), and
never panic.

### Concurrency and resource bounds

All concurrency is bounded and explicit: no goroutine per event (publish
and delivery are inline under the bus mutex), per-subscriber buffers are
bounded at subscribe time, and `Publish`/`Observe` never block the caller.
There is no global state — every bus is explicit and independent. The
counter state (`Seq`, `Drops`, `Invalid`, per-subscriber `Drops`) is
atomic; `Seq` is safe to call concurrently with publish. Leak and race
tests pin the teardown paths (subscriber close, bus close, concurrent
publish/close under `-race`), and benchmarks pin the cost shape: ~0.5 µs
per publish with a draining subscriber and ~1.7 µs for a four-subscriber
fanout on current hardware (measured with `BenchmarkBusPublishFanout` /
`BenchmarkBusPublishFanoutFourSubscribers`) — the event layer cannot
materially slow a run.
Events are in-memory only with no cross-process semantics; persistence is
the cache layer's concern, and the event bus never touches the cache.

### Runtime pool instrumentation

The runtime pool (`internal/runtime`, Phase 12) is the first instrumented
engine. Its `Config` accepts an optional `Observer` (an `internal/event`
`Observer`; the `Bus` satisfies it) and an optional `Deriver`. A nil
observer is the off switch: zero behavior change and a single nil check per
emit point. When set, the pool emits canonical pool-boundary events for its
whole lifecycle — `scan_started` (the pool configuration projection),
`worker_started`/`worker_stopped` (per-worker index; `completed` for a
graceful drain, `cancelled` for an abort), the task lifecycle
(`task_submitted`/`task_started`/`task_running` plus the four terminal
kinds carrying the real `JobID`, worker index, `StartedAt` — zero for jobs
cancelled before they could start — the classification projected onto the
report framework's `ErrorCategory` vocabulary ("timeout", "cancellation",
"unknown"), the wrapped error text, and the raw job `Result` on
completion), `phase_transition` ("running"/"draining"), honest `progress`
(the pool's own submitted/terminated counters, `TotalKnown` always true;
`Completed` never exceeds `Total` on the wire because the submission
counter increments before enqueue and every rejection compensates it, and
the final progress event emitted by shutdown carries exact totals),
and `shutdown`/`scan_stopped` (graceful vs forced, plus the number of
queued jobs dropped). Every payload field is grounded in a real pool field;
terminal events are emitted before the corresponding runtime `Event` is
delivered to pool subscriptions. Task results flow through the
`Deriving` bridge, so a caller-provided `Deriver` converts raw job results
into derived canonical events (asset discoveries, findings, ...) at the
pool-job boundary — engines never emit those events themselves. All events
are purely additive: the pool's execution, rate limiting, and
classification semantics are unchanged by instrumentation.

### Known limitations

- No replay consumes the bus yet; the TUI controller does, and
  `ravenrecon scan --tui` wires the bus as the run's event sink (see
  "Terminal observability" below). The runtime pool, the pipeline runner,
  and the cache are instrumented (see "Runtime pool instrumentation" above
  and "Cache instrumentation" under "Cache and resume"); loggers and
  replays are later v1.2 items.
- `Publish` is O(subscribers): fan-out cost grows linearly with
  subscribers, by design (the TUI controller, loggers, and replays are a
  small fixed set).
- Events are lost when a subscriber's buffer overflows — by design, and
  always counted; downstream consumers must treat drops as observable
  signal (a healthy TUI should never see them).
- Subscribers are single-consumer; sharing one subscriber across goroutines
  is a caller error.
- The pool's queued-but-dropped jobs (forced shutdown) have no terminal
  event; the `shutdown` event's `Dropped` field reports the count.

## Terminal observability

`internal/tui` (roadmap v1.2) is the first consumer of the event bus: a
library that renders deterministic, human-readable frames of a running
scan. It is observer-only — the data flow is `instrumented code -> Bus ->
Subscriber -> Controller.Run -> State.Apply -> Render -> one whole Write`;
a frame is a pure function of (events consumed so far, the injected clock,
the resolved options) and no path leads back into an engine.

The `Controller` is single-goroutine by contract: `Run` owns the state,
the replay history, and the writer for its whole lifetime, spawns no
goroutines, and selects on events / refresh ticks / context cancellation /
subscriber close, rendering one whole frame per tick. The run concludes on
a consumed `scan_stopped` event (the pool emits it last, after shutdown),
subscriber close, or context cancellation — an already-cancelled context
is detected before the loop starts and wins over any buffered events.
Before returning, the controller drains the subscriber buffer
non-blocking (the final frame reflects the whole stream), renders exactly
one final summary frame (`RenderFinal`) at the timestamp of the last
consumed event, and returns the first write error, `ctx.Err()`, or nil. A
failed or partial write (including EPIPE) disables rendering for the rest
of the run while events keep flowing; the controller never panics.

The state machine is single-consumer (the Run goroutine, or a test) and
projects the stream into the documented components: progress (phase —
fed by the pipeline's stage events in a scan run, so the live phase is
the current stage and survives stage_finished, keeping the last stage
name until the next one starts — in-flight, honest totals — unknown
renders as "unknown", never a faked percentage), the live stage feed — a
`stages N/unknown` line (the stream never declares the stage total, so a
denominator is never fabricated) plus the ordered list of concluded
stages, bounded to 64 records keeping the run's beginning — the worker
dashboard (per-worker idle/waiting/running/stopped with current task and
duration), fixed-window throughput rates over a 10 s window (assets,
urls, requests, js, rules, relationships, cache hits and misses, plus an
internal task rate backing the ETA), an ETA estimator honest about
unknown totals and zero rates, best-effort resource sampling on render
ticks only (heap, goroutines, open FDs via `/proc/self/fd` on Linux,
queue depth, active workers — any failure degrades to "—"), a
rate-limited and deduplicated interesting-asset feed, a severity-ranked
grouped error feed, and the final run summary derived only from the
consumed stream. The worker dashboard (including queue depth) and the
throughput section render only when their event sources exist: a stream
with no Worker*/Task* events shows no dashboard, and one with no
throughput-recording events shows no rates — honest degradation instead
of fabricated zeros — while a mixed stream renders all of them. The final
summary closes with a per-stage block — a `stages completed N · current
X` header naming the last started stage, then one bounded line per
concluded stage (`name outcome · N processed · M failed · dur`, plus
`· truncated` and `· err: …` markers when set). A bounded replay history
carries the stream tail in sequence order (`MaxEventHistory`, hard cap
4096), so the tail is fully replayable.

`config.TUIConfig` flows in through `OptionsFromConfig`, which normalizes
zero fields to the documented defaults (250 ms refresh interval,
1024-event history, 10 events/s interesting rate) and resolves `Color`
only for exactly `"on"` — `"auto"` is the caller's terminal detection, and
the library never probes the terminal, never enters raw mode, never reads
keys, and never touches signals. Every dynamic string — stage names,
outcomes, and stage error text included — is sanitized at the controller
boundary (ESC sequences, C0/C1 controls, DEL, and invalid UTF-8
stripped; the renderer adds only its own fixed ANSI codes), and every
structure is bounded — subscriber buffer, history ring, throughput sample
rings (128 samples per metric), a 64-item interesting feed, a 32-group
error feed, 200-byte lines, 64 KiB frames — with drop counters exposed
(`History.Dropped`, `InterestingFeed.Dropped`, `ErrorFeed.Dropped`) so
loss is measurable, never silent. The package is hermetic: deterministic
fake-clock tests with an injected resource sampler, no terminal probing,
no public Internet; race and leak tests pin the Run teardown paths.

### CLI wiring (`ravenrecon scan --tui`, v1.4)

The scan command wires the controller as the run's live observability
surface: one `event.NewBus(nil)` (wall clock) and one bounded subscriber
(64 events) are built after config/cache construction, the bus becomes the
run's single event sink (`ScanConfig.Observer` — the only observer the
pipeline runner consults), and the controller runs on exactly one goroutine
for the run's lifetime. The frame renders to stderr (the summary on stdout
is the machine-facing result); color is resolved at the CLI from stderr's
character-device state (`resolveTUIColor`: TTY → `on`, pipe/redirect →
`off`) and the flags supply `Enabled`/`Compact` (`--tui`, `--tui-compact`).
Termination is deterministic: after `pipeline.Run` returns on every path,
a defer closes the subscriber (its `Done` channel ends the controller
loop), joins the goroutine with a bounded receive (the loop returns
promptly on `Done`), and closes the bus last (subsequent publishes are
dropped and counted). A non-nil controller result — a write failure (e.g. a
broken pipe), or the controller reporting the run context's cancellation —
is printed as a `tui: ...` warning on stderr, never changing the exit
codes or the summary. `--tui` and `--verbose` are mutually exclusive (one
event sink per run), `--tui-compact` requires `--tui`, and controller
construction errors return before the stages run, mirroring usage errors
(`internal/cli`).

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
* DNS pipeline (see "DNS pipeline" above; roadmap v0.6 sub-milestone 5A):
  library-level A/AAAA/CNAME resolution with typed Phase 2 observations and
  relationships, per-(host, type) cache-before-execute with statused
  records, a bounded pool with a central query limiter, per-type
  cancellation classification, and hermetic tests
* HTTP probing (see "HTTP probing" above; roadmap v0.6 sub-milestone 5B):
  library-level root-path GET probes of every host's http and https targets
  with typed Phase 2 observations and relationships, per-target
  cache-before-execute with statused records, a bounded pool with a central
  per-request limiter, per-probe cancellation classification, bounded
  limits, and hermetic tests
* URL intelligence (see "URL intelligence" above; roadmap v0.7): a
  library-level canonical-URL streaming engine with parameter extraction,
  endpoint classification, per-(URL, adapter) caching, cross-adapter emit
  merging, typed graph edges, and historical-URL tool adapters for gau,
  waybackurls, and waymore (`internal/urlintel/adapt`)
* JavaScript intelligence (see "JavaScript intelligence" above; roadmap
  v0.8, phase 7): a library-level discovery/fetch/parse/analysis engine
  over script URLs with typed Phase 2 assets (JavaScript, SecretCandidate,
  SourceMap), five `javascript_to_*` relationship kinds, bounded import
  expansion with third-party identification, endpoint and secret-candidate
  extraction, JS technology detection, `js.fetch`/`js.analyze`
  cache-before-execute records, and tool adapters for subjs, LinkFinder,
  and SecretFinder (`internal/jsintel/adapt`)
* secret intelligence (see "Secret intelligence" above, phase 8): a
  library-level Evidence & Secret Intelligence Engine over bounded
  documents with the extended 35-type Phase 2 secret vocabulary, the
  `secret` evidence method, `url -> secret_candidate` and
  `secret_candidate -> evidence` relationship kinds, the compile-once
  anchored pattern database, entropy/context/correlation/confidence
  engines, explicit false-positive suppression, a `secret.scan`
  cache-before-execute record with strict decode re-validation, and an
  offline verification queue (`internal/secrentel`)
* priority intelligence (see "Priority engine" above, phase 9): a
  library-level Attack Surface Intelligence Engine over scoring signals
  with two compile-once indicator catalogs, fully explained factor-list
  scores, deterministic correlation, evidence-tied attack-path
  hypotheses, rendered reconnaissance recommendations, and a
  cache-integrated bounded engine stage (`internal/priority`)
* detection framework (see "Detection framework" above, phase 10): a
  library-level Detection Framework & Rule Engine — the canonical
  `asset.Finding` model, rule registration with startup validation,
  dependency-ordered level scheduling on the shared runtime pool,
  per-rule deadlines with panic isolation, the fixed detection Context,
  a `detect.rule` cache-before-execute record with strict decode
  re-validation, execution metrics, and detector benchmarking
  (`internal/detect`; no rules ship with the framework)
* event bus (see "Event bus" above; roadmap v1.2): the canonical runtime
  event model and the concurrent, bounded, non-blocking bus — typed,
  validated, clock-stamped events with sealed payloads, per-subscriber
  bounded buffers with drop counters, bus-assigned sequence order,
  zero-timestamp stamping, the Observer instrumentation seam, and the
  Deriver/Deriving pool-job-boundary bridge (`internal/event`; observer
  only, nothing consumes it yet); plus the runtime pool instrumentation:
  the pool emits canonical scan/worker/task lifecycle, phase-transition,
  honest-progress, and shutdown events through its optional
  `Config.Observer`/`Config.Deriver`, with every payload field grounded in
  a real pool field (`internal/runtime`; nil observer = zero behavior
  change)
* terminal observability (see "Terminal observability" above; roadmap
  v1.2): the first bus consumer — a single-goroutine `Controller`
  consuming a `Subscriber` into sanitized, bounded `State`, live and
  final deterministic frames, `OptionsFromConfig` normalization, bounded
  replay history, and drop counters on every dropping component
  (`internal/tui`; library only until v1.4, when `ravenrecon scan --tui`
  wired it as the run's live stderr surface — see "CLI wiring" under
  "Terminal observability")
* cache instrumentation (see "Cache instrumentation" under "Cache and
  resume"; roadmap v1.2): the cache emits exactly one canonical
  `cache_hit`/`cache_miss` event per `Get` through its optional
  `WithObserver` option, with every payload field grounded in the real
  lookup outcome (key digest, `Outcome.State`, `Outcome.IsHit()`), and a
  nil observer as the zero-change off switch (`internal/cache`)
* pipeline stage eventing (see "Event bus" above; roadmap v1.2): the
  pipeline runner emits exactly one `stage_started` and one
  `stage_finished` event per stage entry — on every path (normal,
  pre-cancelled, unresolvable), synchronously in stage order, before Run
  returns, with the finished payload mirroring the recorded `StageRecord`
  field for field (outcome, truncation, clamped non-negative counters,
  duration, bounded error text) and a nil `Observer` as the zero-change
  off switch (`internal/pipeline`)
* pipeline results channel (see "Pipeline requirements" above; v1.3 T3b):
  the runner merges every stage's result-channel additions
  (`StageResult.Results`) into one shared `Results` channel — 16 channels
  mirroring `report.Context` 1:1 (`IPs`, `Ports`, `Services`, `Endpoints`,
  `JavaScript`, `Parameters`, `Technologies`, `Secrets`, `Evidence`,
  `Findings`, `TLSCertificates`, `SourceMaps`, `Relationships`, `Surfaces`,
  `Groups`, `AttackPaths`) — first-seen dedup keyed by canonical identity
  (the asset `Identity()` "kind:value" string, `Relationship.ID()`, and
  the priority `Identity`/`Anchor`/`Root` fields), deterministic first-seen
  order, merged regardless of the stage's outcome (failed stages' retained
  results still merge, mirroring the corpus), exposed as
  `RunReport.Results`. `MaxOutput` is enforced per result channel per
  stage at the merge: every channel holds at most `MaxOutput` entries
  after each stage, and every cut channel records its `<channel>_truncated`
  sticky flag (`ips_truncated`, `attack_paths_truncated`, ... — the
  AGENTS §0.6 carve-out, mirroring `corpus_capped`) plus `Truncated`.
  Stages receive the merged PRIOR state via `StageInput.Results`
  (read-only, identical contract to the corpus slices) and never see
  their own additions. Adapter-side production is complete (T3d):
  dns → IPs; httpprobe → IPs/Ports/Services/Endpoints/
  TLSCertificates/Relationships; urlintel → Parameters/Endpoints/
  Relationships; techintel → Technologies/Evidence/Relationships;
  jsintel → JavaScript/SourceMaps/Relationships plus Endpoints/Secrets/
  Technologies/Evidence; priority → Surfaces/Groups/AttackPaths; detect
  → Findings — and the report stage consumes the full `Context` from
  this struct (corpus + every results channel, copied whole)
  (`internal/pipeline`)
* pipeline full-run determinism + the discovery clock seam (see
  "Pipeline requirements" above; v1.3 T4): the full ten-stage pipeline
  with the REAL discovery adapter is pinned deterministic at any pool
  concurrency — per-source discovery result order is selection order
  (the engine pre-allocates the Results slot array; each job writes only
  its own slot, never pool-completion order), per-source host lists are
  deduped and sorted by canonical name, `Report.All()` merges + sorts,
  the adapter's `discoveryAdditions = FilterHosts(in.Target, All())`
  preserves that order, and the corpus merge is first-seen — so racing
  runs produce byte-identical RunReports (three-run DeepEqual at
  Concurrency 4, incl. provenance at the injected clock with
  earliest-wins tool-name sources). Cache-hit vs execute parity holds
  end-to-end over a real filesystem cache: known-version sources are
  served from cache (zero executions) while the NON-CACHEABLE
  unknown-version source (assetfinder) executes fresh, and the warm
  RunReport DeepEquals the cold one with zero new dns/http/jsintel
  work. T4 also fixed the one cache-parity break the full-run test
  caught: `asset.NewFinding` normalizes an absent
  `RelatedAssets`/`Relationships` set to nil (never an empty-but-non-nil
  slice), so findings replayed from detect cache records DeepEqual
  freshly normalized ones. The discovery engine's only clocks are the
  injected seam and nil-clock defaults — the adapter always bridges
  `Now = in.Clock.Now`, so no wall clock reaches the report; the pool's
  rate-limiter wall clock gates job starts only and never changes an
  outcome at the default Timeout 0 (`internal/discovery`,
  `internal/pipeline/adapt`, `internal/asset`)
* pipeline document channel + secrentel adapter (see "Pipeline
  requirements" and "Secret intelligence" above; v1.3 T3c): the
  pipeline-internal document channel (`StageResult.Documents` /
  `StageInput.Documents` / `RunReport.Documents`) carries bounded retained
  script bodies (`pipeline.Document{Identity, URL, Content, Truncated}`,
  content bounded by `pipeline.MaxDocumentBytes` = 2 MiB — the secrentel
  engine's own ingest cap — merged by reference, never copied, and never
  exposed on the report `Context`), merged by the runner exactly like the
  corpus/results channels: first-seen dedup keyed by the canonical
  identity string, deterministic first-seen order, merged regardless of
  the stage's outcome, per-stage `MaxOutput` cap at the merge with the
  `documents_truncated` sticky flag + `Truncated` on a cut (AGENTS §0.6
  carve-out), and a hostile-producer guard at the merge: over-cap content
  is dropped WHOLE (`Content` nil + `Truncated`), never a partial prefix.
  The secrentel adapter (`NewSecretIntelStage`, `internal/pipeline/adapt/
  secrentel.go`) consumes the channel as its document source — every
  pipeline document becomes one `secrentel.Document` (`KindJS`,
  `SourceAsset` = the pipeline document's canonical identity, `Source`
  left to the engine default "secrentel"), truncated and nil-content
  documents are skipped (nothing honest to scan), the engine's per-
  document analysis caps stay at their defaults (64 candidates / 8
  evidence), and the engine's overflow signal (≥ 64 candidates) maps to
  `Truncated` + the `secrentel_overflow` sticky flag — with the engine's
  §0.6 truncation chain verified intact end-to-end (record write →
  replay → sticky merge → report exposure), so the flags replay from
  cache hits and completed+flag is the legal carve-out; `secrentel_
  truncated` is mapped too, though unreachable through this adapter
  (bounded pipeline content, truncated documents skipped). Counters and
  outcome fold mirror the T2c adapters exactly; the engine's offline
  verification queue is never executed or propagated (T6). The jsintel
  stage family is the document producer (T3d — NEW-15 resolved: the
  document channel is pipeline-internal, separate from the Results
  channel; secrentel consumes the channel, never the
  `Results.JavaScript` field) (`internal/pipeline`)
* pipeline scan command (see "Pipeline requirements" above; v1.3 T6): the
  `ravenrecon scan <domain>` CLI command wires the full ten-stage pipeline
  — discover → dns → httpprobe → urlintel → techintel → jsintel →
  secrentel → priority → detect → report — with `--stages` selection
  (validated against the fixed vocabulary), `--sources` (discovery),
  `--request-timeout` (httpprobe param), `--concurrency`/`--timeout`
  (per-stage bounds for every selected stage), `--cache`/`--no-cache`
  (mirroring the discover command's cache semantics), `--output` (report
  directory, default `ravenrecon-report`), `--verbose` (one line per
  stage event on stderr via a synchronous `event.Observer`), and
  `--tui`/`--tui-compact` (the live observability frame on stderr via the
  same v1.2 event layer — see "CLI wiring" under "Terminal
  observability"; `--tui` and `--verbose` are mutually exclusive and
  `--tui-compact` requires `--tui`; diagnostics stay off the summary
  stream). The target is normalized through
  `asset.NewDomain` — the single normalization point (uppercase, whitespace,
  and a trailing dot are normalized away; IP literals are rejected).
  Exit semantics: completed/partial → 0 (the summary states the outcome
  explicitly); failed/cancelled/incomplete, usage/validation errors, cache
  open failures, and Ctrl-C/SIGTERM → 1, with the summary always printed
  first (partial results are never lost). The summary is stable across
  runs — no durations or timestamps (the CLI runs on the real wall clock;
  determinism is a pipeline property). The report file listing is read
  honestly from the output directory itself. All production seams are the
  adapters' documented nil defaults (external tools via PATH, engine
  default resolver/transport, compiled-in fingerprint/pattern databases,
  the EMPTY detect registry per D2, the four builtin reporters)
  (`internal/cli`, `internal/pipeline/adapt`)

Planned, not yet implemented:

* discovery engines beyond passive subdomain enumeration, DNS, HTTP,
  URL intelligence, and JavaScript intelligence (TLS)
* asset store, graph, and graph correlation engine (the priority
  engine's identity-anchored Correlate is landed; relationship traversal
  is not)
* standalone reporting CLI front-end (report rendering is reachable today
  only through the scan command's embedded report stage)
