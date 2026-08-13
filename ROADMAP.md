# RavenRecon Roadmap

The roadmap is intentionally incremental.

Each milestone must be stable before the next major subsystem is added.

Implementation order is fixed by the phase instructions; milestones are
numbered to match the order work actually happens.

---

## v0.1 — Foundation

Status: complete

- [x] Go module
- [x] CLI
- [x] `--help`
- [x] version command
- [x] doctor command
- [x] configuration foundation
- [x] unit-test baseline
- [x] CI baseline
- [x] agent instructions
- [x] architecture documentation

---

## v0.2 — Asset Model

Status: complete

- [x] Domain model
- [x] Host model
- [x] IP model
- [x] Port model
- [x] Service model
- [x] URL model
- [x] Endpoint model
- [x] JavaScript model (minimal)
- [x] normalized representations
- [x] namespaced deterministic identity
- [x] provenance
- [x] deterministic merge primitives
- [x] relationship primitive
- [x] JSON serialization
- [x] normalization tests
- [x] identity/deduplication tests
- [x] serialization tests
- [ ] persistent asset store
- [ ] correlation engine
- [ ] asset graph storage/traversal

Deferred: Technology, SecretCandidate, Finding (introduced with the phases
that consume them).

---

## v0.3 — Runtime Engine

Status: deferred — the cache foundation (v0.4) ships first per phase
sequencing; no runtime/scheduler code exists in this repository yet.

- [ ] Context-aware scheduler
- [ ] Bounded worker pool
- [ ] Configurable concurrency
- [ ] Central rate limiter
- [ ] Graceful shutdown
- [ ] Progress events
- [ ] Structured errors
- [ ] Cancellation tests
- [ ] Concurrency tests
- [ ] Race tests

No reconnaissance tools should be implemented in this milestone.

---

## v0.4 — Cache and Resume

Status: complete

Implemented in `internal/cache` (persistent, filesystem-backed; no database):

- [x] Persistent cache
- [x] Cache schema versioning
- [x] Resume support
- [x] Cache invalidation
- [x] Deterministic cache keys

Details, semantics, and known limitations: see `ARCHITECTURE.md`
("Cache and resume").

---

## v0.5 — Passive Discovery

Initial adapters:

- [ ] subfinder
- [ ] assetfinder
- [ ] amass

Requirements:

- [ ] normalized output
- [ ] timeout
- [ ] cancellation
- [ ] tool detection
- [ ] parser tests
- [ ] integration fixtures

---

## v0.6 — DNS / HTTP

- [ ] DNS pipeline
- [ ] HTTP probing
- [ ] TLS metadata
- [ ] HTTP metadata normalization
- [ ] technology detection

---

## v0.7 — URL Intelligence

- [ ] Historical URLs
- [ ] URL normalization
- [ ] parameter extraction
- [ ] deduplication
- [ ] endpoint classification

---

## v0.8 — JavaScript Intelligence

- [ ] JS discovery
- [ ] JS retrieval
- [ ] endpoint extraction
- [ ] source-map detection
- [ ] secret candidate detection
- [ ] third-party library identification

---

## v0.9 — Prioritization

- [ ] asset scoring
- [ ] technology-aware prioritization
- [ ] API/admin classification
- [ ] confidence scoring
- [ ] interesting-asset ranking

---

## v0.10 — Reporting

- [ ] JSON
- [ ] CSV
- [ ] Markdown
- [ ] HTML
- [ ] run summaries
- [ ] error summaries

---

## v0.11 — Terminal UI

- [ ] live progress
- [ ] worker status
- [ ] throughput
- [ ] ETA
- [ ] errors
- [ ] interesting assets

---

## v1.0 — Production Foundation

- [ ] comprehensive integration tests
- [ ] race-tested concurrency
- [ ] benchmark suite
- [ ] stable configuration format
- [ ] compatibility policy
- [ ] release automation
- [ ] documentation

---

## Future

Native implementations may replace external tools where that produces a meaningful improvement in:

- reliability
- performance
- portability
- observability
- control

Do not replace a tool merely for novelty.
