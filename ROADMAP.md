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
- [x] correlation engine — landed with Phase 9 as the deterministic
  identity-anchor `Correlate` grouping in `internal/priority`
  (relationship-traversal correlation stays deferred, see v0.9)
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
see `ARCHITECTURE.md`, "Technology detection"); TLS metadata lands as
sub-milestone 5C, an extension of `internal/httpprobe` (see below) — v0.6
is complete. None of the pipelines has a CLI command yet.

- [x] DNS pipeline
- [x] HTTP probing
- [x] TLS metadata — landed as sub-milestone 5C, an extension of
  `internal/httpprobe`: the https probe already performs the handshake, and
  5C captures typed TLS metadata from it — the leaf certificate as a Phase 2
  asset, plus ALPN / issuer / subject / DNS names mapped onto
  `techintel.TLSInfo` (one dial, no duplicate connections; see
  `ARCHITECTURE.md`, "HTTP probing", "TLS metadata (5C)")
- [x] HTTP metadata normalization
- [x] technology detection — landed as Phase 6.5 `internal/techintel`
  (technology + evidence asset models, fingerprint database, detection
  engine)

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

Outstanding work: the project version stays at 0.5.0; the next version bump
is a release decision. JavaScript intelligence (v0.8) is complete; secret
intelligence (Phase 8) is complete.

---

## Phase 6.5 — Technology Intelligence

Technology detection — v0.6's active-infrastructure companion — lands as
phase 6.5:
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

JavaScript intelligence lands as Phase 7: `internal/jsintel` is a
library-level engine that discovers script URLs from raw lines, HTML
observations, and tool adapters (`internal/jsintel/adapt`), fetches them
with bounded, honestly truncated content retention, parses them through the
stdlib-only parser abstraction, and analyzes them into typed Phase 2 assets
— JavaScript observations, an import graph with bounded expansion and
third-party (bare-specifier) identification, source map detection,
endpoint extraction, secret candidates (detection only, never
verification), and JS technology detection — with `js.fetch` and
`js.analyze` cache-before-execute records. See `ARCHITECTURE.md`,
"JavaScript intelligence". There is no CLI command yet.

Status: complete

- [x] JS discovery
- [x] JS retrieval
- [x] endpoint extraction
- [x] source-map detection
- [x] secret candidate detection
- [x] third-party library identification

Implemented as jsintel tool adapters: subjs, LinkFinder, and SecretFinder.
Deferred as documented future work: Katana's JS output (an optional
adapter — the engine's own extraction replaces it; consistent with the
urlintel katana deferral) and source-map content parsing (references are
detected and normalized now; parsing the map content lands with a future
phase).

---

## Phase 8 — Secret Intelligence

Secret intelligence lands as Phase 8: `internal/secrentel` is the Evidence
& Secret Intelligence Engine — deliberately an evidence engine, not a
"secret scanner". Bounded documents (JavaScript, source maps, HTML, JSON,
environment files, configuration, YAML, XML, GraphQL, OpenAPI, HTTP
responses) are scanned against the compile-once, anchor-gated pattern
database (`internal/secrentel/patterns`, 43 fingerprints across the
35-type vocabulary extended in the Phase 2 asset model; the count is
asserted by the patterns package test), and every
candidate is classified into a structured evidence model: pattern
fingerprints, entropy assessment, extracted context, multi-evidence
correlation (provider endpoints, sibling pairs, cross-document repeats),
and a multi-factor confidence score with explicit false-positive
suppression (documented example values suppressed; documentation/test
contexts capped at Low; entropy alone never classifies). A `secret.scan`
cache-before-execute record with strict decode re-validation covers
rescans; an offline verification queue (never cached, never executed)
records what the future verification phase should consume. See
`ARCHITECTURE.md`, "Secret intelligence". There is no CLI command yet.

Status: complete

- [x] secret asset model (35-type vocabulary extension)
- [x] evidence model (secret evidence method + candidate→evidence edges)
- [x] pattern engine and fingerprint database (compile-once, anchored)
- [x] entropy engine (Shannon, classes, UUID/JWT, length weighting)
- [x] context engine (variables, JSON keys, comments, nearby indicators)
- [x] multi-evidence correlation (endpoints, technologies, pairs, repeats)
- [x] confidence scoring (factor-composed, capped, gated)
- [x] false-positive reduction (value suppression + context capping)
- [x] cache integration (`secret.scan`, truncated-never-served)
- [x] runtime reuse (bounded pool, cancellation, streaming)
- [x] verification queue (offline only)
- [x] tests, race tests, and benchmarks

Deferred as documented future work: online secret verification (the
explicit Phase 9 boundary — nothing in Phase 8 contacts any provider) and
dedicated source-map semantics.

---

## v0.9 — Prioritization

Status: Phase 9, Rounds 1, 2A, 2B, and 2C complete (library capability;
no CLI command yet)

Implemented in `internal/priority` — the Attack Surface Intelligence
Engine. Round 1 landed the canonical model types (`Signal`,
`SurfaceAsset`, `Factor`), the two compile-once data-driven catalogs (40
interestingness + 13 risk indicators = 53 entries, all validated at
load), and the pure scoring engine with its caps, gates, overlap policy,
factor bound, tests, and benchmarks. Round 2A landed the intelligence
layer: the compile-time rendered-reason/recommendation bound, type-level
NaN hardening, deterministic `Correlate` grouping (anchors derived
exclusively through the Phase 2 normalizers), evidence-tied
`AttackPaths` (bounded, recon-hypothesis-only), and the recommendation
catalog (every entry carries evidence-referencing reconnaissance
guidance, rendered at score time onto the emitted factors). Round 2B
landed the engine stage — bounded workers on the runtime pool,
cache-before-execute composed around pool jobs (operation
`priority.score`), catalog-digest cache keys, and strict decode
re-validation with eviction — with cancellation, leak, determinism,
tamper, and race tests plus 100k-asset benchmarks. Round 2C updated the
documentation (README, ARCHITECTURE). A Round-2 gate pass then hardened
the catalog template validation to a total percent rule (exactly one `%s`
seam per term template — its only percent sign; any other `%` such as a
second verb, `%q`, `%d`, or `%%` fails the load, closing holes where such
templates compiled and leaked raw verbs into emitted factors; verbatim
regex/size/kind texts must be percent-free), surfaced `Correlate`'s
group-cap truncation through a boolean return (member cuts were already
flagged per group), made the member tie-break a total order (final
tie-break on the serialized surface, so duplicate-identity inputs order
deterministically), deep-copied path-step evidence (steps never alias the
factor's backing array), extended the emit-hook test to genuinely exercise
the panic-containment branch (a canonical sentinel value trips the hook),
and rejected empty-value identities in signal validation (a kind without
a value is not a canonical asset). See `ARCHITECTURE.md` ("Priority
engine") for the full design and known limitations.

- [x] asset scoring
- [x] technology-aware prioritization
- [x] API/admin classification
- [x] confidence scoring
- [x] interesting-asset ranking

Deferred to future rounds: CLI wiring (a `ravenrecon priority` command is
NOT part of Phase 9's landed scope), the reporting phase that consumes
groups, attack paths, and recommendations, and any correlation beyond
identity-derived anchors (relationship traversal).

---

## Phase 10 — Detection Framework & Rule Engine

Status: complete (library capability; no CLI command yet)

Implemented in `internal/detect` — the Detection Framework & Rule
Engine. The framework itself detects nothing: it is the execution engine
reusable detection rules plug into. It landed with: the canonical
Finding model in the Phase 2 asset model (`asset.Finding` under the new
`finding` kind, plus the `detect` evidence method); rule registration
with full startup validation (duplicate IDs and names, metadata
completeness, category/version/cost/input/output/asset-kind
vocabularies, dependency syntax, timeout bounds, nil detector) and
immutable deep-copied storage; the dependency system — layered Kahn
level scheduling (O(V log V + E), deterministic) with cycle and
missing-reference rejection and honest cascade skips; the fixed
detection Context (assets, relationships, evidence, technologies,
secrets, JavaScript, endpoints, bounded configuration, bounded Logger,
injected Clock — nothing else) over a bounded, canonical,
normalize-or-reject Snapshot; execution on the SHARED runtime pool (no
new scheduler) with per-rule deadlines, panic isolation, streaming emit,
and deterministic reports; a `detect.rule` cache-before-execute record
keyed on the rule fingerprint (version included), the snapshot
fingerprint, and the configuration, with strict decode re-validation and
eviction — partial executions never cached; per-rule and aggregate
execution metrics; and a `BenchmarkDetector` measurement helper.
Vulnerability-specific rules are future phases; none ship here. See
`ARCHITECTURE.md` ("Detection framework") for the full design and known
limitations.

- [x] Detection Framework (engine, statuses, deterministic report)
- [x] Rule Registration (validated, immutable)
- [x] Rule Scheduler (dependency levels, no quadratic scheduling)
- [x] Detection Context (fixed domains, bounded)
- [x] Finding Model (canonical asset.Finding)
- [x] Evidence Model Extension (`detect` method)
- [x] Rule Configuration (descriptor + run configuration)
- [x] Rule Metadata (full descriptor vocabulary)
- [x] Rule Dependencies (ordering, cycles rejected)
- [x] Rule Result Cache (`detect.rule`)
- [x] Rule Categories (14 typed categories)
- [x] Rule Execution Metrics (per-rule and aggregate)
- [x] Detector Benchmarking (BenchmarkDetector)
- [x] Rule Validation (startup + output contract)
- [x] tests, race tests, and benchmarks (100/500/1000 rules)

Deferred to future phases: any vulnerability-specific rule (XSS, SSRF,
BAC, SQLi, CVE matching, browser automation, exploitation, AI are all
out of scope), data flow between dependent rules, and CLI wiring.

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
