# RavenRecon

Intelligent reconnaissance framework for authorized bug bounty and security testing.

## Status

**v0.5.0 — Passive Discovery** (DNS pipeline landed as Active
Infrastructure sub-milestone 5A)

RavenRecon has a normalized asset model (`internal/asset`), a persistent,
filesystem-backed cache and resume foundation (`internal/cache`), a bounded,
cancellable, rate-limited runtime engine (`internal/runtime`), and its first
consumer: passive subdomain discovery (`internal/discovery`) with adapters
for subfinder, assetfinder, and amass (passive mode only).

Active infrastructure is landing incrementally: the DNS pipeline
(`internal/dns`, roadmap v0.6 sub-milestone 5A) and the HTTP probing
pipeline (`internal/httpprobe`, sub-milestone 5B) now exist as library-level
capabilities. DNS resolves A/AAAA/CNAME records into typed, cached Phase 2
observations with host→address and host→CNAME relationships; HTTP probing
attaches typed HTTP observations (status code, final URL, redirect chain,
bounded headers, counted body size, TLS flag) to every host's http and
https root targets. Neither has a CLI command yet; the remaining active
engines (TLS metadata, URL intelligence, JavaScript analysis, crawling, and
secret scanning) are still later roadmap milestones.

## Asset model

The asset model provides typed, canonical representations of reconnaissance
data:

- Domain, Host, IP, Port, Service
- URL, Endpoint, JavaScript

Every asset has a deterministic, namespaced identity for deduplication,
records provenance ("where did this come from?"), supports deterministic
merging, and serializes to JSON. See `ARCHITECTURE.md` for details.

Deferred to later phases: Technology, SecretCandidate, Finding, the asset
store/graph, and the correlation engine.

## Cache and resume

RavenRecon ships a persistent, filesystem-backed cache foundation
(`internal/cache`) that future stages use to skip repeated work and resume
interrupted scans:

- Deterministic cache keys derived from the operation, the normalized Phase 2
  asset identity, the operation's result-relevant configuration, and (where
  applicable) the external tool and version. See "Cache keys" in
  `ARCHITECTURE.md`.
- Structured, schema-versioned JSON records that distinguish completed,
  failed, cancelled, and incomplete work. Terminal output is never the
  primary data model.
- Crash-safe writes (unique temp file + fsync + atomic rename). A reader never
  observes a partially written entry.
- Self-healing corruption handling: corrupted, oversized, or
  schema-incompatible entries are reported as distinct outcomes, never
  trusted, and removed so the next run recomputes them.
- An optional, configurable TTL measured from creation time (zero disables
  expiration).
- A documented single-process concurrency model; no cross-process locking is
  claimed.

Cache configuration lives in `internal/config` (`CacheConfig`: `Enabled`,
`Dir`, `TTL`). The default cache directory is
`os.UserCacheDir()/ravenrecon`, and the cache is **disabled by default**. The
`discover` command reads and writes the cache only when it is enabled in
configuration; `--no-cache` forces it off for a single run.

## Passive discovery

`ravenrecon discover <domain>` runs passive subdomain enumeration through
installed external tools:

```text
subfinder -d <domain> -silent
assetfinder <domain>
amass enum -passive -d <domain>
```

Only passive modes are ever invoked; no active enumeration, brute force, or
intel modes are reachable from RavenRecon. Output is normalized through the
Phase 2 asset model, deduplicated by identity, and merged across sources with
provenance (source + discovery time). Each source reports its detection
state — `[OK]`, `[WARN]`, or `[MISSING]` with a reason — and its outcome
(completed / partial / failed / cancelled / skipped). Tool detection
distinguishes executable existence, execution, version, and capability; a
broken version flag never reports an installed tool as missing. Every tool
invocation is bounded (timeout, cancellation, capped stdout/stderr capture).
A Ctrl-C/SIGTERM mid-run cancels gracefully — the partial report is still
printed, the exit code is 1, and a second signal force-exits immediately.

Run with cache (when enabled in configuration):

```bash
ravenrecon discover example.com
ravenrecon discover example.com --sources subfinder,amass
ravenrecon discover example.com --no-cache
```

Results are cached per source with keys covering the operation, the canonical
target identity, the passive mode, and the tool name/version; only completed,
unexpired entries are reused. The `doctor` command reports the same per-source
detection states. See `ARCHITECTURE.md` ("Passive discovery") for details,
partial-result semantics, and known limitations.

## DNS pipeline (library)

`internal/dns` (roadmap v0.6, sub-milestone 5A) resolves host assets into
typed, cached DNS observations: A, AAAA, and CNAME records normalized
through the Phase 2 asset model, with typed host→address and host→CNAME
relationships, a bounded pool with a central query limiter, per-(host,
record type) cache-before-execute, and hermetic tests (no public Internet).
NXDOMAIN and legitimate empty answers are completed observations; truncated,
failed, and cancelled types are never served as success. It is a library
capability only — there is no `ravenrecon dns` command yet. TLS metadata
(5C) is the remaining Active Infrastructure milestone. See
`ARCHITECTURE.md` ("DNS pipeline") for the full design and security
considerations.

## HTTP probing (library)

`internal/httpprobe` (roadmap v0.6, sub-milestone 5B) probes discovered host
assets at their two root targets — `http://host/` and `https://host/` — with
typed, cached observations: final status code, final URL, bounded redirect
chain, bounded final headers, counted body size, and the TLS-handshake
flag. Connection refusals ("service absent") and TLS handshake failures
("https not served") are completed negative observations; timeouts and DNS
failures are failed probes; hard-cap hits are truncated-incomplete and
never served from cache. Probing runs on a bounded pool with one central
request limiter, per-target cache-before-execute, and hermetic tests
(loopback servers, no public Internet). It is a library capability only —
there is no `ravenrecon http` command yet. See `ARCHITECTURE.md` ("HTTP
probing") for the full design and security considerations.

## Runtime engine

A bounded, cancellable, rate-limited job execution engine lives in
`internal/runtime` (roadmap v0.3):

- Exactly `Concurrency` worker goroutines run jobs inline; the pool never
  creates a goroutine per job, so the parallelism is exactly bounded.
- A bounded submission queue applies backpressure: `Submit` blocks while full
  and the queue never grows without bound.
- A single central, standard-library token-bucket limiter (`Rate`/`Burst`)
  gates every job start, regardless of concurrency.
- Every job's lifecycle — started, completed, failed, cancelled, timed-out —
  is delivered to subscribers through bounded, lossless event channels.
  Cancellation is always reported as cancelled, never as failure or success.
- `Shutdown` drains queued and in-flight work gracefully, with a forced path
  when the drain context is cancelled.
- The engine is generic and cache-independent by design: consumer stages
  (passive discovery, v0.5) compose "cache-before-execute" around runtime
  jobs. See `ARCHITECTURE.md` ("Runtime engine").

## Current commands

Show help:

```bash
go run ./cmd/ravenrecon --help
```

Show version:

```bash
go run ./cmd/ravenrecon version
```

Run environment diagnostics:

```bash
go run ./cmd/ravenrecon doctor
```

Run passive subdomain discovery:

```bash
go run ./cmd/ravenrecon discover example.com
go run ./cmd/ravenrecon discover example.com --sources subfinder,amass
```

`discover` options (after the domain): `--sources <a,b>` restricts the
sources, `--no-cache` disables the cache for the run.

Build:

```bash
go build -o ravenrecon ./cmd/ravenrecon
```

Test:

```bash
go test ./...
```

Race test:

```bash
go test -race ./...
```

## Design priorities

1. Reliability
2. Signal quality
3. Safety
4. Performance
5. User experience
6. Extensibility

## Architecture

See `ARCHITECTURE.md`.

## Roadmap

See `ROADMAP.md`.

## AI agents

All coding agents must read `AGENTS.md` before modifying the repository.

Agents must implement only the current roadmap milestone unless explicitly instructed otherwise.

## Responsible use

RavenRecon is intended for authorized security research, security assessments, and bug bounty programs where the target is explicitly in scope.

It is not intended to automate credential attacks, persistence, or exploitation.

## License

MIT.
