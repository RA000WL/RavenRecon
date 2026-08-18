# RavenRecon Roadmap

> **Goal**
>
> Keep the core stable, make the pipeline real, and move new detection logic into versioned packs.

The roadmap is intentionally incremental.

Each phase must be stable before the next major subsystem is added.

Implementation order is fixed by the phase instructions; milestones are numbered to match the order work actually happens.

---

## Roadmap rules

Every phase must satisfy these before it is complete:

- Reuse the Runtime, Asset Graph, Cache, Reporting, and Detection frameworks.
- Prefer extending existing models over introducing new ones.
- Preserve deterministic behavior and reproducible output.
- Every output must include provenance: source, derivation path, confidence, timestamp.
- Every subsystem must have tests, docs, and fixture-based acceptance.
- No phase is complete until it passes `gofmt`, `go vet`, `go build`, `go test`, and `go test -race`.
- Public interfaces should only be stabilized after pipeline integration or real-world validation.

---

## Status overview

| Version | Phase | Status |
|--------:|-------|:------:|
| v0.1 | Foundation | ✅ Complete |
| v0.2 | Asset Model | ✅ Complete |
| v0.3 | Runtime Engine | ✅ Complete |
| v0.4 | Cache and Resume | ✅ Complete |
| v0.5 | Passive Discovery | ✅ Complete |
| v0.6 | Active Infrastructure | ✅ Complete |
| v0.6.5 | Technology Intelligence | ✅ Complete |
| v0.7 | URL Intelligence | ✅ Complete |
| v0.8 | JavaScript Intelligence | ✅ Complete |
| v0.9 | Secret Intelligence | ✅ Complete |
| v1.0 | Attack Surface Intelligence / Detection Framework | ✅ Complete |
| v1.1 | Reporting Framework | ✅ Complete |
| v1.2 | Eventing, observability, operator feedback | ✅ Complete |
| v1.2.5 | SDK and extension API stabilization | ⏳ Implemented — final review pending |
| v1.3 | End-to-end pipeline | ⏳ Planned |
| v1.4 | CLI surface area | ⏳ Planned |
| v1.5 | Robustness and hostile-input hardening | ⏳ Planned |
| v1.6 | Integration and acceptance testing | ⏳ Planned |
| v1.7 | Real-world validation | ⏳ Planned |
| v2.0 | Detection packs | ⏳ Planned |

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
- [x] correlation engine — landed as the deterministic identity-anchor `Correlate` grouping in `internal/priority` (relationship-traversal correlation stays deferred)
- [ ] asset graph storage/traversal

Deferred: Technology, SecretCandidate, Finding (introduced with the phases that consume them).

---

## v0.3 — Runtime Engine

Status: complete

Implemented in `internal/runtime` as a generic, cache-independent runtime engine: bounded worker pool, central token-bucket rate limiter, cancellation, graceful/forced shutdown, and lossless event subscriptions. It is generic infrastructure and deliberately does not import `internal/cache`; its consumer stages compose cache-before-execute around runtime jobs.

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

Details, semantics, and known limitations: see `ARCHITECTURE.md` (“Cache and resume”).

---

## v0.5 — Passive Discovery

Status: complete

Implemented in `internal/discovery`: three external-tool adapters (subfinder, assetfinder, amass passive mode) orchestrated through the runtime engine with Phase 3 cache-before-execute composition and Phase 2 asset normalization/deduplication, plus the `ravenrecon discover` CLI command, the doctor's per-source detection section, and the Discovery configuration section.

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

Details, semantics, and known limitations: see `ARCHITECTURE.md` (“Passive discovery”).

---

## v0.6 — Active Infrastructure

DNS lands as sub-milestone 5A of Active Infrastructure: the `internal/dns` pipeline exists as a library capability — A/AAAA/CNAME resolution into typed, cached Phase 2 observations with host→address and host→CNAME relationships (see `ARCHITECTURE.md`, “DNS pipeline”). HTTP probing lands as sub-milestone 5B (`internal/httpprobe`, see `ARCHITECTURE.md`, “HTTP probing”) and covers the HTTP metadata normalization work items. Technology detection lands as Phase 6.5 (`internal/techintel` — the technology and evidence asset models, the fingerprint database, and the detection engine; see `ARCHITECTURE.md`, “Technology detection”). TLS metadata lands as sub-milestone 5C, an extension of `internal/httpprobe` — v0.6 is complete. None of the pipelines has a CLI command yet.

- [x] DNS pipeline
- [x] HTTP probing
- [x] TLS metadata — captured as sub-milestone 5C through the HTTPS probe handshake
- [x] HTTP metadata normalization
- [x] technology detection — landed as Phase 6.5 `internal/techintel`

---

## v0.7 — URL Intelligence

URL intelligence lands as sub-milestone 6B of the pipeline stages: the `internal/urlintel` library exists as a capability — canonical-URL streaming into typed, cached Phase 2 observations with query-parameter extraction, GET endpoint classification, per-(URL, adapter) cache records, cross-adapter emit merging, and typed graph edges (see `ARCHITECTURE.md`, “URL intelligence”). The Phase 2 asset model gained the Parameter asset (identity = name within location, capped observed values) and the url→parameter and endpoint→parameter relationship kinds. There is no CLI command yet. Historical URLs land as sub-milestone 6C: `internal/urlintel/adapt` presents the external tools as line streams into the engine.

Status: complete

- [x] Historical URLs
- [x] URL normalization
- [x] parameter extraction
- [x] deduplication
- [x] endpoint classification

Implemented as urlintel tool adapters: gau, waybackurls, and waymore; katana and paramspider are deferred as documented future work.

---

## v0.6.5 — Technology Intelligence

Technology detection lands as phase 6.5: `internal/techintel` is a library-level detection engine that consumes typed observations (headers, body, cookies, TLS metadata, DNS metadata, endpoint paths) and produces typed technology assets, evidence records, and asset-graph edges against the compiled fingerprint database (`internal/techintel/fingerprints`, 145 fingerprints / 296 indicators across 21 categories), with weight-based confidence scoring and Phase 3 cache integration (`tech.detect`). It mirrors the urlintel pipeline shape: an observation source seam, a bounded runtime pool, cache-before-execute, merge-at-emit, bounded diagnostics, and cancellation with honest statuses. See `ARCHITECTURE.md` (“Technology detection”). There is no CLI command yet.

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

JavaScript intelligence lands as Phase 7: `internal/jsintel` is a library-level engine that discovers script URLs from raw lines, HTML observations, and tool adapters (`internal/jsintel/adapt`), fetches them with bounded, honestly truncated content retention, parses them through the stdlib-only parser abstraction, and analyzes them into typed Phase 2 assets — JavaScript observations, an import graph with bounded expansion and third-party (bare-specifier) identification, source map detection, endpoint extraction, secret candidates (detection only, never verification), and JS technology detection — with `js.fetch` and `js.analyze` cache-before-execute records. See `ARCHITECTURE.md`, “JavaScript intelligence”. There is no CLI command yet.

Status: complete

- [x] JS discovery
- [x] JS retrieval
- [x] endpoint extraction
- [x] source-map detection
- [x] secret candidate detection
- [x] third-party library identification

Implemented as jsintel tool adapters: subjs, LinkFinder, and SecretFinder. Deferred as documented future work: Katana's JS output (optional adapter) and source-map content parsing.

---

## v0.9 — Secret Intelligence

Status: complete

Secret intelligence lands as Phase 8: `internal/secrentel` is the Evidence & Secret Intelligence Engine — deliberately an evidence engine, not a secret scanner. Bounded documents (JavaScript, source maps, HTML, JSON, environment files, configuration, YAML, XML, GraphQL, OpenAPI, HTTP responses) are scanned against the compile-once, anchor-gated pattern database (`internal/secrentel/patterns`, 43 fingerprints across the 35-type vocabulary extended in the Phase 2 asset model), and every candidate is classified into a structured evidence model: pattern fingerprints, entropy assessment, extracted context, multi-evidence correlation, and a multi-factor confidence score with explicit false-positive suppression. A `secret.scan` cache-before-execute record with strict decode re-validation covers rescans; an offline verification queue (never cached, never executed) records what the future verification phase should consume. See `ARCHITECTURE.md`, “Secret intelligence”. There is no CLI command yet.

- [x] secret asset model (35-type vocabulary extension)
- [x] evidence model
- [x] pattern engine and fingerprint database
- [x] entropy engine
- [x] context engine
- [x] multi-evidence correlation
- [x] confidence scoring
- [x] false-positive reduction
- [x] cache integration (`secret.scan`)
- [x] runtime reuse
- [x] verification queue (offline only)
- [x] tests, race tests, and benchmarks

Deferred as documented future work: online secret verification and dedicated source-map semantics.

---

## v1.0 — Attack Surface Intelligence / Detection Framework

Status: complete

Implemented in `internal/priority` and `internal/detect` — the attack-surface prioritization engine and the reusable detection framework. Phase 9 (Attack Surface Intelligence) landed the canonical model types, the data-driven interestingness/risk catalogs, the pure scoring engine, deterministic correlation grouping, evidence-tied attack paths, recommendation catalog, cache-before-execute execution, and benchmarks. Phase 10 (Detection Framework) landed the canonical Finding model, rule registration with validation, the dependency system, the fixed detection context, execution on the shared runtime pool, the `detect.rule` cache-before-execute record, execution metrics, and benchmarking.

- [x] asset scoring
- [x] technology-aware prioritization
- [x] API/admin classification
- [x] confidence scoring
- [x] interesting-asset ranking
- [x] Detection Framework
- [x] Finding model
- [x] Rule registration and validation
- [x] Rule dependencies
- [x] Rule execution metrics
- [x] Rule result cache
- [x] Detector benchmarking

Deferred to future phases: vulnerability-specific rules, CLI wiring for the framework, and any correlation beyond identity-derived anchors.

---

## v1.1 — Reporting Framework

Status: complete

Implemented in `internal/report` — the Reporting Framework & Evidence Export. Reporting is presentation only: the framework never rescans a target and never mutates the data it is given. It landed with: the canonical report context and model, the report registry, the four built-in exporters (JSON, CSV, Markdown, HTML), the run summary, the error summary, the statistics engine, export validation, and atomic file writes. The engine runs on the shared runtime pool and includes an optional `report.render` cache-before-execute record with strict decode re-validation and eviction.

- [x] JSON
- [x] CSV
- [x] Markdown
- [x] HTML
- [x] run summaries
- [x] error summaries

---

## v1.2 — Eventing, observability, operator feedback

Status: complete

Goal: make runs visible, debuggable, and measurable in real time.

The event bus lands first (`internal/event`, Phase 12): the canonical
runtime event model — typed, validated, severity-marked, clock-stamped
events with sealed payloads projected from the Phase 2 asset model, the
runtime engine, and the report framework — fanned out through a concurrent,
bounded, non-blocking bus (per-subscriber bounded buffers, drop counters,
bus-assigned sequences preserved in per-subscriber order, zero-timestamp
stamping, closed-bus drop semantics), plus the Observer contract and the
`Deriver`/`Deriving` pool-job-boundary bridge that converts job results
into derived events. It is observer-only: no engine consumes or mutates it
yet. The runtime pool is already instrumented (the pool emits canonical
scan/worker/task lifecycle, phase-transition, honest-progress, and shutdown
events through its optional `Config.Observer`), and the cache is
instrumented too (every `Get` emits exactly one canonical
`cache_hit`/`cache_miss` event through its optional `WithObserver`
option, nil observer = zero behavior change). The terminal observability
library (`internal/tui`) landed
as the first bus consumer and delivers the observability surface below:
a single-goroutine controller replays a subscriber's stream into
sanitized, bounded state and renders live frames plus one deterministic
final summary frame, with all rendering hermetic and deterministic (no
CLI wiring yet).

- [x] Event bus
- [x] Structured runtime events (runtime pool instrumentation)
- [x] Cache instrumentation (cache hit/miss events)
- [x] Progress reporting (TUI library: progress, phase, in-flight,
  honest totals/ETA)
- [x] Worker health/status (TUI library: per-worker dashboard)
- [x] Throughput and ETA (TUI library: fixed-window rates)
- [x] Resource monitoring (TUI library: sampled heap/goroutines/FDs/queue)
- [x] Interesting-asset feed (TUI library: rate-limited, deduplicated)
- [x] Error feed (TUI library: grouped, severity-ranked)
- [x] Final execution summary (TUI library: `RenderFinal` block)

Acceptance criteria:

- Every stage emits structured events.
- The TUI can reconstruct a live run from events alone.
- Metrics are consistent across repeated runs.
- Errors are visible without breaking execution flow.
- Tests cover event ordering, progress aggregation, and summary generation.
- Benchmarks show the event layer does not materially slow discovery.

---

## v1.2.5 — SDK and extension API stabilization

Status: implemented — final review pending (all items landed; milestone stays open until reviewer sign-off)

Goal: freeze the contracts that v2.0 packs will depend on, but only after the data flow is real enough to validate.

- [x] Stable Rule SDK — frozen Level-1 surface ("SDK v1 (Core)", API 1.0): Rule, Detector, the vocabularies and parsers, ValidateRule (rule.go, api.go)
- [x] Stable Context API — fixed, immutable Context (context.go), pinned in the Level-1 surface golden
- [x] Rule registration — Registry.Register/Seal with deep copies and post-seal locking (registry.go)
- [x] Metadata validation — one validation entry point (ValidateRule), enforced identically by Register and BenchmarkDetector
- [x] Helper utilities — ParseCost, ParseRuleVersion, ParseFindingPriority, ParseFindingStatus, ParseCategory, KnownRuleInputs/KnownRuleOutputs/Categories
- [x] Compatibility/versioning rules — three-layer versioning (SchemaVersion / APIMajor.Minor / Rule.Version) with CheckAPIVersion(1,0) as the pack-loading gate; enforced by the surface golden and nine behavior contracts
- [x] Example rules — internal/detect/examples, the only rule pack (explicitly loaded, never auto-loaded)
- [x] Developer documentation — ARCHITECTURE.md "Detection framework → SDK contract / SDK stability policy"; pack-author guide in internal/detect/doc.go
- [x] Reopening criteria — written, testable, and present in code (api.go Level-1 policy; surface snapshot golden + CheckAPIVersion gates) and docs (ARCHITECTURE.md "Detection framework → SDK contract / SDK stability policy")

Acceptance criteria:

- SDK examples compile and run against the released interfaces.
- At least one internal rule pack loads through the SDK without special-case code.
- Contract tests prove backward compatibility for the supported API version.
- Reopening criteria are written down and testable.
- Any new engine capability is expressed through the SDK instead of ad hoc core changes.

---

## v1.3 — End-to-end pipeline

Status: planned

Goal: turn the disconnected engines into one deterministic workflow.

Pipeline:

`discover → dns → httpprobe → urlintel → techintel → jsintel → secrentel → priority → detect → report`

- [ ] `ravenrecon scan`
- [ ] Pipeline orchestration
- [ ] Shared runtime wiring
- [ ] Shared asset graph propagation
- [ ] Shared cache and report flow
- [ ] End-to-end execution paths
- [ ] Pipeline-level error handling

Acceptance criteria:

- A single run can move from discovery to report without manual stitching.
- Assets and evidence retain identity across all stages.
- Intermediate failures do not corrupt the final report.
- Pipeline runs are deterministic for the same input and config.
- End-to-end tests cover success, partial failure, and retry paths.

---

## v1.4 — CLI surface area

Status: planned

Goal: expose each engine as an independently usable command while keeping the UX consistent.

- [ ] `ravenrecon discover`
- [ ] `ravenrecon dns`
- [ ] `ravenrecon http`
- [ ] `ravenrecon tech`
- [ ] `ravenrecon js`
- [ ] `ravenrecon secrets`
- [ ] `ravenrecon priority`
- [ ] `ravenrecon detect`
- [ ] `ravenrecon report`
- [ ] Shared flags
- [ ] Shared configuration
- [ ] Consistent output modes

Acceptance criteria:

- Every command runs independently with documented flags.
- Common options behave identically across commands.
- Output formats are consistent and machine-readable where expected.
- The CLI uses the same runtime, cache, and asset graph as the pipeline.
- Help output and example invocations are complete and tested.

---

## v1.5 — Robustness and hostile-input hardening

Status: planned

Goal: treat all parsers and ingestion paths as untrusted-input boundaries.

- [ ] Go fuzzing harnesses
- [ ] Property tests
- [ ] JS fuzzing for `internal/jsintel`
- [ ] Secret fuzzing for `internal/secrentel`
- [ ] URL fuzzing for `internal/urlintel`
- [ ] Cache fuzzing for `internal/cache`
- [ ] Report fuzzing
- [ ] Parser hardening based on fuzz results

Acceptance criteria:

- Each high-risk parser has at least one fuzz target.
- Fuzz discoveries are triaged into fixed regressions, accepted behavior, or invalid inputs.
- Crashers, hangs, and memory blowups are eliminated.
- Property tests cover normalization, deduplication, and invariants.
- Regression tests exist for every confirmed issue.

---

## v1.6 — Integration and acceptance testing

Status: planned

Goal: prove the platform works reliably across realistic fixture targets.

- [ ] Fixture targets
- [ ] Expected outputs
- [ ] Snapshot tests
- [ ] Performance baselines
- [ ] Memory baselines
- [ ] CI integration
- [ ] Regression suite for core engine interactions

Acceptance criteria:

- Core fixtures produce stable, versioned outputs.
- CI detects output drift and performance regressions.
- The suite covers common and edge-case recon scenarios.
- Baselines are documented and reproducible locally.
- A failing snapshot clearly identifies which stage regressed.

---

## v1.7 — Real-world validation

Status: planned

Goal: validate the system against authorized targets and use those results to refine existing engines.

- [ ] Output quality
- [ ] False positive rate
- [ ] False negative rate
- [ ] Priority scoring accuracy
- [ ] Technology identification accuracy
- [ ] Secret suppression quality
- [ ] Relationship quality in the asset graph
- [ ] Limited contract revision only if real-world data proves it necessary

Acceptance criteria:

- Real runs produce actionable, reviewable findings.
- False positives are measured and reduced.
- Priority scoring correlates with manual triage value.
- The system remains stable under messy or contradictory target data.
- Any SDK reopening is backed by concrete evidence, not preference.

---

## v2.0 — Detection packs

Status: planned

Goal: shift new detection logic into stable, versioned packs built on the frozen SDK.

Design rule: core packages stay stable. New detection capabilities should be implemented as packs unless they require a fundamental platform change.

### Pack families

**Web**

- [ ] Security headers
- [ ] CSP
- [ ] CORS
- [ ] Source maps
- [ ] Robots
- [ ] Backup files
- [ ] Debug endpoints

**Authentication**

- [ ] JWT
- [ ] OAuth
- [ ] Session handling
- [ ] Cookie analysis

**Authorization**

- [ ] IDOR heuristics
- [ ] Privilege boundaries
- [ ] Role relationships

**APIs**

- [ ] REST
- [ ] GraphQL
- [ ] OpenAPI
- [ ] Endpoint clustering

**JavaScript**

- [ ] DOM XSS indicators
- [ ] postMessage analysis
- [ ] Prototype pollution indicators
- [ ] Dangerous API usage

**Cloud**

- [ ] AWS
- [ ] Azure
- [ ] GCP
- [ ] Firebase
- [ ] Buckets
- [ ] IAM indicators

**Business logic**

- [ ] Workflow mapping
- [ ] State transitions
- [ ] Multi-step process analysis

Acceptance criteria:

- Packs load through the SDK without core edits.
- Packs declare metadata, dependencies, and compatibility versions.
- Pack output is normalized into the same evidence model as core engines.
- Pack failures are isolated and do not crash the platform.
- Pack behavior is covered by pack-level tests and fixtures.

---

## Optional future work

Deferred until the core platform is stable:

- Browser automation
- Historical comparisons
- Distributed execution
- Plugin marketplace
- Continuous monitoring
- Graph visualization
- AI assistant integration
- Knowledge graph querying

---

## Phase review checklist

A phase is only complete when all of the following are true:

- Scope matches the phase goal.
- Tests are passing.
- Benchmarks are recorded.
- Documentation is updated.
- Outputs are reproducible.
- Backward compatibility impact is understood.
- A reviewer confirms the phase does not introduce hidden coupling.