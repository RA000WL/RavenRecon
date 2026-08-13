# RavenRecon

Intelligent reconnaissance framework for authorized bug bounty and security testing.

## Status

**v0.2.0 — Asset Model + Cache Foundation**

RavenRecon has a normalized asset model (`internal/asset`) and a persistent,
filesystem-backed cache and resume foundation (`internal/cache`). The runtime
engine (roadmap v0.3) is deferred; the cache infrastructure ships first per
the phase sequencing.

This release intentionally does not implement reconnaissance engines yet.

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
`os.UserCacheDir()/ravenrecon`, and the cache is **disabled by default**. No
CLI cache flags are wired yet — the existing CLI parses commands rather than
flags, and no runtime command consumes the cache. Flag wiring arrives with
the runtime engine milestone.

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
