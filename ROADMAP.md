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
- Milestones own features, not files: supporting infrastructure strictly required by a phase may touch any subsystem (AGENTS.md §5); later milestones' user-facing functionality stays out.

---

## Status overview

| Version | Phase | Status | Summary / commits |
|--------:|-------|:------:|---|
| v0.1 | Foundation | ✅ Complete | Bootstrap: go.mod, CLI (`--help`, version, doctor), config foundation, unit-test + CI baseline, agent instructions, architecture docs (2d491b1). |
| v0.2 | Asset Model | ✅ Complete | Domain/Host/IP/Port/Service/URL/Endpoint/JS(minimal) models, normalized representations, namespaced deterministic identity, provenance, merge + relationship primitives, JSON serialization (ae3911f). |
| v0.3 | Runtime Engine | ✅ Complete | internal/runtime: bounded pool, central token-bucket rate limiter, cancellation, graceful/forced shutdown, lossless event subscriptions; cache-independent by design (8c82e64). |
| v0.4 | Cache and Resume | ✅ Complete | internal/cache (filesystem-backed, no DB): schema versioning, resume, invalidation, deterministic keys; hardened lifecycle (cec152f, 5d9c2b0). |
| v0.5 | Passive Discovery | ✅ Complete | subfinder/assetfinder/amass adapters via runtime with cache-before-execute + Phase 2 normalization; `ravenrecon discover` CLI + doctor detection section (ea8589e). |
| v0.6 | Active Infrastructure | ✅ Complete | DNS (5A), HTTP probing (5B), TLS metadata (5C) — library-only pipelines, no CLI (00dc622, 0baf664, eb8b156). |
| v0.6.5 | Technology Intelligence | ✅ Complete | internal/techintel: header/HTML/cookie/CDN/WAF/framework/infra/auth/API/cloud/build-tool analyzers, fingerprint DB, weighted confidence scoring, tech.detect cache (f074ad4). |
| v0.7 | URL Intelligence | ✅ Complete | internal/urlintel (6B): canonical-URL streaming, Parameter asset, url→parameter + endpoint→parameter edges; gau/waybackurls/waymore adapters (454dc5f). |
| v0.8 | JavaScript Intelligence | ✅ Complete | internal/jsintel (Phase 7): script discovery, bounded truncated fetch, stdlib-only parser, import graph, source maps, endpoint extraction, secret candidates; subjs/LinkFinder/SecretFinder adapters (e8cc0da). |
| v0.9 | Secret Intelligence | ✅ Complete | internal/secrentel (Phase 8): evidence engine over bounded docs, 43 patterns / 35-type vocabulary, entropy+context+multi-evidence+multi-factor confidence, secret.scan cache, offline verification queue (46e2a54). |
| v1.0 | Attack Surface Intelligence / Detection Framework | ✅ Complete | internal/priority + internal/detect landed (ef0e219, 717df6b); 14 audit findings closed (0865b66). Deferred: vulnerability-specific rules, framework CLI wiring, non-identity correlation. |
| v1.1 | Reporting Framework | ✅ Complete | Presentation-only (never rescans, never mutates): JSON/CSV/Markdown/HTML exporters, run/error summaries, statistics, export validation, atomic writes, report.render cache record (a8b1587). |
| v1.2 | Eventing, observability, operator feedback | ✅ Complete | Observer-only event bus + pool events via Config.Observer + cache events via WithObserver (one per Get; nil observer = zero change) + internal/tui first consumer (single-goroutine controller, deterministic frames); no CLI wiring yet (a8b3cee). |
| v1.2.5 | SDK and extension API stabilization | ✅ Complete | SDK v1 (Core): frozen Level-1 surface, API 1.0, surface golden + 9 behavior contracts + semantic compat golden, examples pack (internal/detect/examples), stability policy + reopening criteria (bbf23c8, db7a00c). |
| v1.3 | End-to-end pipeline | ⏳ Planned | — |
| v1.4 | CLI surface area | ⏳ Planned | — |
| v1.5 | Robustness and hostile-input hardening | ⏳ Planned | — |
| v1.6 | Integration and acceptance testing | ⏳ Planned | — |
| v1.7 | Real-world validation | ⏳ Planned | — |
| v1.8 | Universal Asset Ingestion Framework | ⏳ Planned | — |
| v2.0 | Detection packs | ⏳ Planned | — |

---

## Legacy notes (v0.1–v0.9)

Facts retained from the collapsed milestone sections (not derivable from the commit refs alone):
- v0.1: bootstrap milestone — foundation checklist only; CI baseline and agent instructions landed here.
- v0.2: correlation engine landed differently than planned — as the deterministic identity-anchor `Correlate` grouping in `internal/priority`; relationship-traversal correlation stays deferred. Persistent asset store and asset graph storage/traversal were never landed (still open). Technology, SecretCandidate, and Finding asset models were deferred to the phases that consume them.
- v0.3: runtime is deliberately cache-independent — consumer stages compose cache-before-execute around pool jobs (now AGENTS.md §0.4). No reconnaissance tools shipped in this milestone.
- v0.4: implementation details, semantics, and known limitations live in ARCHITECTURE.md (“Cache and resume”).
- v0.5: `ravenrecon discover` + the doctor's per-source detection section are the only CLI wiring to date; adapters invoke tools in passive-only mode with asserted argv, bounded output capture, statused cache-before-execute records, and cross-source provenance merge.
- v0.6: HTTP metadata normalization landed with 5B; DNS (5A), HTTP probing (5B), and TLS metadata (5C) remain library-only pipelines — none has a CLI command yet (still true).
- v0.6.5: fingerprint database ships 145 fingerprints / 296 indicators across 21 categories; the engine mirrors the urlintel pipeline shape (observation seam, bounded pool, cache-before-execute, merge-at-emit, honest statuses).
- v0.7: Parameter asset identity = name within location, with capped observed values; per-(URL, adapter) cache records with cross-adapter emit merging; katana and paramspider adapters deferred as documented future work.
- v0.8: content retention is bounded and honestly truncated; secret candidates are detection-only, never verification; `js.fetch`/`js.analyze` cache-before-execute records; Katana JS output and source-map content parsing deferred.
- v0.9: deliberately an evidence engine, not a secret scanner; `secret.scan` cache record enforces strict decode re-validation; the verification queue is offline-only (never cached, never executed); online verification and dedicated source-map semantics deferred.
- v1.2: acceptance criteria — every stage emits structured events, the TUI reconstructs a live run from events alone, metrics are consistent across repeated runs, errors are visible without breaking execution flow; bus semantics (per-subscriber bounded buffers, drop counters, bus-assigned sequence preservation, zero-timestamp stamping, closed-bus drop behavior, Deriver/Deriving bridge) live in ARCHITECTURE.md "Event bus".

---

## v1.2.5 — SDK and extension API stabilization

Status: ✅ Complete — SDK v1 (Core) frozen and committed (bbf23c8, db7a00c); contract
gates (surface golden, behavior contracts, semantic compat golden) enforce it.

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
- [x] Intermediate failures do not corrupt the final report.
- [x] Pipeline runs are deterministic for the same input and config.
- [x] End-to-end tests cover success, partial failure, and retry paths.

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

## v1.8 — Universal Asset Ingestion Framework

Status: planned

Goal: consume reconnaissance artifacts from any source — RavenRecon itself or
external tools — normalize them into the canonical asset graph, preserve
provenance, and enrich them through the existing pipeline so the framework
becomes a recon intelligence platform: ingest, normalize, correlate, enrich,
and report on data regardless of where it came from. Most recon tools stop at
collecting; v1.8 makes RavenRecon an analysis platform over other tools'
output (subdomains.txt, alive.txt, urls.txt, js.txt, burp.xml, nuclei.json,
...), reconstructing the asset graph and producing the same reports as if
RavenRecon had discovered the assets itself.

Prerequisite: the v1.3 pipeline is stable — ingestion feeds the same stages,
it does not create a parallel execution path.

Design rules:

- Importers are adapters behind one interface (`internal/importer`):
  `Name()`, `CanImport(...)`, `Import(...)`; no importer owns runtime, cache,
  reporting, or asset identities — everything is reused from the existing
  frameworks.
- Every imported record becomes canonical Phase 2 assets through the single
  normalization point (`asset.NewDomain`/`NewHost`/`ParseURL`, ...); importers
  never write their own normalizers.
- Import is passive data ingestion only: imported findings (e.g. nuclei JSON)
  are evidence to be reported and enriched, never re-executed or verified.
- Provenance is first-class: every imported asset records importer, original
  tool, filename, import time, original record, confidence, metadata.
- Streaming only: bounded memory, progress events, cancellation, resume —
  targets 10MB/100MB/1GB+ files without whole-file loads.

Checklist:

- [ ] `internal/importer` package: importer interface, registry, format
      detection, streaming readers, validation, normalization, progress events
- [ ] Automatic format detection — extension, MIME, structure, content
      signature; no `--type` flag (files/folders only)
- [ ] Plain-text importers: domains, subdomains, urls, alive, js, ips, cidrs
- [ ] JSON importers: httpx, dnsx, naabu, katana, nuclei
- [ ] XML importers: Burp sitemap/issues, OWASP ZAP
- [ ] Crawl-output importers: katana, hakrawler, gospider, waymore, gau
- [ ] Archive sources: wayback (Common Crawl future)
- [ ] Streaming parsers: bounded memory, incremental parsing, progress events,
      cancellation, resume
- [ ] Provenance preserved on every imported asset (importer, original tool,
      filename, import time, original record, confidence, metadata)
- [ ] Deduplication reuses the existing identity/merge/provenance/relationship
      logic — no duplicate systems
- [ ] Cache integration: content hash + import config + schema version +
      importer version; repeat imports of unchanged files become cache hits
- [ ] Imported assets flow through the standard pipeline
      (DNS → HTTP → Tech → JS → Secrets → Priority → Detection → Reporting)
- [ ] `ravenrecon ingest` CLI: single files, multiple files, folders
- [ ] Reporting distinguishes Discovered / Imported / Enriched / Generated with
      source attribution
- [ ] Tests: empty files, malformed input, duplicates, huge files, cancellation,
      resume, cache, streaming, mixed imports

Acceptance criteria:

- Every supported format imports without a `--type` hint.
- Imported assets carry full provenance and deduplicate against existing
  assets via the shared identity/merge logic.
- Imports are streaming with bounded memory; a 1 GB input does not spike
  memory.
- Repeat imports of unchanged files are cache hits.
- Imported data produces reports structurally identical to pipeline-discovered
  data (provenance aside).
- All gates pass (gofmt, vet, build, test, race); benchmarks recorded for
  large imports.

---

## v2.0 — Detection packs

Status: planned

Goal: shift new detection logic into stable, versioned packs built on the frozen SDK.

Design rule: core packages stay stable. New detection capabilities should be implemented as packs unless they require a fundamental platform change.

### Pack families

- **Web** — security headers, CSP, CORS, source maps, robots, backup files, debug endpoints
- **Authentication** — JWT, OAuth, session handling, cookie analysis
- **Authorization** — IDOR heuristics, privilege boundaries, role relationships
- **APIs** — REST, GraphQL, OpenAPI, endpoint clustering
- **JavaScript** — DOM XSS indicators, postMessage analysis, prototype pollution indicators, dangerous API usage
- **Cloud** — AWS, Azure, GCP, Firebase, buckets, IAM indicators
- **Business logic** — workflow mapping, state transitions, multi-step process analysis

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
- Supporting changes are classified (infrastructure/refactor) and documented, not future-feature creep.
- A reviewer confirms the phase does not introduce hidden coupling.
