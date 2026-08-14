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
The DNS pipeline (roadmap v0.6, sub-milestone 5A; `internal/dns`) and the
HTTP probing pipeline (roadmap v0.6, sub-milestone 5B; `internal/httpprobe`)
exist as library-level stages — DNS: A/AAAA/CNAME resolution into typed
Phase 2 observations with per-(host, type) caching and typed relationships
(see "DNS pipeline"); HTTP: root-path GET probes of every host's http and
https targets with typed, cached observations, bounded limits, and typed
relationships (see "HTTP probing"); neither has a CLI command yet. The
URL/JS pipeline stages, asset graph, scoring, and reports do not exist yet.

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

## DNS pipeline

`internal/dns` (roadmap v0.6, sub-milestone 5A of Active Infrastructure)
implements the DNS resolution stage as a library capability: it resolves
discovered host assets and attaches typed DNS observations to the Phase 2
asset model. It is a pipeline stage, not a CLI command — there is no
`ravenrecon dns` yet (HTTP probing has landed as 5B and TLS metadata 5C is
still pending; see `ROADMAP.md`).

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
- Library capability only: no CLI command; TLS metadata (5C) is still
  pending.
- Answers come from the OS resolver with the OS resolver's trust model; no
  DNSSEC validation is performed or claimed.
- All tests are hermetic: a fake resolver and a real filesystem-backed
  cache, never the public Internet (see `bench_test.go`).

## HTTP probing

`internal/httpprobe` (roadmap v0.6, sub-milestone 5B of Active
Infrastructure) implements the HTTP probing stage as a library capability:
it probes discovered host assets at their two root targets and attaches
typed HTTP observations to the Phase 2 asset model. It is a pipeline stage,
not a CLI command — there is no `ravenrecon http` yet (TLS metadata, 5C, is
still pending; see `ROADMAP.md`).

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

Retention is bounded: at most MaxRedirects+1 redirect hops, at most
MaxHeaders sorted header entries from a byte-capped header block, and a
counted (never retained) body size capped at MaxBodyBytes. The TLS flag
records whether an https probe completed its handshake, and it is set on
EVERY terminal path: the final response, an out-of-scope redirect terminal,
and a cap-exceeding redirect terminal each carry the handshake state of the
response that ended the walk; http probes and failed handshakes record
false.

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
  for the probe shapes of every executed job, regardless of outcome.

Redirect-hop and final URLs are recorded in the observations only; the
graph stays about the probed surface. Edges are deduplicated by edge
identity and emitted sorted, deterministically.

### Cache behavior

Each probe target is cached under its own Phase 3 key composed of exactly
the operation (`"http.probe"`) and the canonical Phase 2 URL identity of the
target — nothing else. The request shape is fixed (GET, no body, a fixed
RavenRecon user agent) and the redirect policy and caps are fixed
constants, so there is no result-relevant configuration today; whatever
configuration could matter in the future must enter the key, but timings,
timeouts, concurrency, rate limits, and the transport (trust roots, dial
routing) never do — exactly like the DNS pipeline. HTTP responses of any
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
  disables chain or hostname checks. Certificate metadata extraction is the
  TLS milestone (5C) and is out of scope here.
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
  errors.

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
- Library capability only: no CLI command, and TLS metadata (5C) is still
  pending.
- All tests are hermetic: loopback HTTP/TLS servers and a real
  filesystem-backed cache, never the public Internet (see `bench_test.go`).

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

Planned, not yet implemented:

* discovery engines beyond passive subdomain enumeration, DNS, and HTTP
  probing (TLS, URL, JS)
* asset store, graph, and correlation engine
* reporting and terminal UI
