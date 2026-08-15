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

Status: complete

Implemented in `internal/runtime` as a generic, cache-independent runtime
engine: bounded worker pool, central token-bucket rate limiter, cancellation,
graceful/forced shutdown, and lossless event subscriptions. It is generic
infrastructure and deliberately does not import `internal/cache`; its
consumer (passive discovery, v0.5, the next milestone) composes
"cache-before-execute" around runtime jobs.

- [x] Context-aware scheduler
- [x] Bounded worker pool
- [x] Configurable concurrency
- [x] Central rate limiter
- [x] Graceful shutdown
- [x] Progress events
- [x] Structured errors
- [x] Cancellation tests
- [x] Concurrency tests
- [x] Race tests

No reconnaissance tools are implemented in this milestone.

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

Status: complete

Implemented in `internal/discovery`: three external-tool adapters (subfinder,
assetfinder, amass passive mode) orchestrated through the v0.3 runtime engine
with Phase 3 cache-before-execute composition and Phase 2 asset
normalization/deduplication, plus the `ravenrecon discover` CLI command, the
doctor's per-source detection section, and the `Discovery` configuration
section.

Initial adapters:

- [x] subfinder
- [x] assetfinder
- [x] amass

Requirements:

- [x] normalized output
- [x] timeout
- [x] cancellation
- [x] tool detection
- [x] parser tests
- [x] integration fixtures
- [x] passive-only invocations with asserted argv
- [x] bounded output capture
- [x] provenance and cross-source merge
- [x] cache-before-execute with statused records
- [x] discover CLI command and doctor detection section

Details, semantics, and known limitations: see `ARCHITECTURE.md`
("Passive discovery").

---

## v0.6 — Active Infrastructure

DNS lands as sub-milestone 5A of Active Infrastructure: the `internal/dns`
pipeline exists as a library capability — A/AAAA/CNAME resolution into
typed, cached Phase 2 observations with host→address and host→CNAME
relationships (see `ARCHITECTURE.md`, "DNS pipeline"). HTTP probing lands
as sub-milestone 5B (`internal/httpprobe`, see `ARCHITECTURE.md`, "HTTP
probing") and covers the HTTP metadata normalization work items. Technology
detection lands as Phase 6.5 (`internal/techintel` — the technology and
evidence asset models, the fingerprint database, and the detection engine;
see `ARCHITECTURE.md`, "Technology detection"); TLS metadata (5C) remains
the only open v0.6 item. None of the pipelines has a CLI command yet.

- [x] DNS pipeline
- [x] HTTP probing
- [ ] TLS metadata
- [x] HTTP metadata normalization
- [x] technology detection — landed as Phase 6.5 `internal/techintel`
  (technology + evidence asset models, fingerprint database, detection
  engine); TLS metadata (5C) stays pending

---

## v0.7 — URL Intelligence

URL intelligence lands as sub-milestone 6B of the pipeline stages: the
`internal/urlintel` library exists as a capability — canonical-URL
streaming into typed, cached Phase 2 observations with query-parameter
extraction, GET endpoint classification, per-(URL, adapter) cache records,
cross-adapter emit merging, and typed graph edges (see `ARCHITECTURE.md`,
"URL intelligence"). The Phase 2 asset model gained the Parameter asset
(identity = name within location, capped observed values) and the
url→parameter and endpoint→parameter relationship kinds. There is no CLI
command yet. Historical URLs land as sub-milestone 6C:
`internal/urlintel/adapt` presents the external tools as line streams
into the engine.

- [x] Historical URLs
- [x] URL normalization
- [x] parameter extraction
- [x] deduplication
- [x] endpoint classification

Implemented as urlintel tool adapters: gau, waybackurls, and waymore;
katana and paramspider are deferred as documented future work.

Outstanding work: v0.6's TLS metadata (5C) remains pending; the project
version stays at 0.5.0, and the next version bump awaits v0.6 completion.
JavaScript intelligence (v0.8) has not begun.

---

## Phase 6.5 — Technology Intelligence

Technology detection — v0.6's final open bullet — lands as phase 6.5:
`internal/techintel` is a library-level detection engine that consumes
typed observations (headers, body, cookies, TLS metadata, DNS metadata,
endpoint paths) and produces typed technology assets, evidence records,
and asset-graph edges against the compiled fingerprint database
(`internal/techintel/fingerprints`, 145 fingerprints / 296 indicators
across the 21 categories), with weight-based confidence scoring and Phase 3
cache integration (operation `tech.detect`). It mirrors the urlintel
pipeline shape: an observation source seam, a bounded runtime pool,
cache-before-execute, merge-at-emit, bounded diagnostics, and cancellation
with honest statuses. See `ARCHITECTURE.md` ("Technology detection"). There
is no CLI command yet.

- [x] technology asset model
- [x] fingerprint engine
- [x] header analyzer
- [x] HTML fingerprinting
- [x] cookie analyzer
- [x] CDN detection
- [x] WAF detection
- [x] framework detection
- [x] infrastructure detection
- [x] authentication provider detection
- [x] API technology detection
- [x] cloud detection
- [x] build tool detection
- [x] confidence scoring
- [x] cache integration
- [x] technology relationships
- [x] evidence model
- [x] fingerprint database
- [x] benchmarks
- [x] documentation

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
