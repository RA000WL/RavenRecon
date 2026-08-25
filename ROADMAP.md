# RavenRecon Roadmap

> **Goal**
>
> Keep the core stable, make the pipeline real, and move new detection logic into versioned packs.

The roadmap is intentionally incremental.

Each phase must be stable before the next major subsystem is added.

Implementation order is fixed by the phase instructions; milestones are numbered to match the order work actually happens.

> **Optimization companion:** `OPTIMIZATION.md` is the prioritized audit backlog for this roadmap.
> Every milestone below links to its `OPT-*` items there (with `file:line` evidence). The roadmap
> owns *what* ships and *when*; `OPTIMIZATION.md` owns the *evidence, fix, and verification* for each.

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
| v1.2 | Eventing, observability, operator feedback | ✅ Complete | Observer-only event bus + pool events via Config.Observer + cache events via WithObserver (one per Get; nil observer = zero change) + internal/tui first consumer (single-goroutine controller, deterministic frames); no CLI wiring yet at the time (wired into `scan --tui` in v1.4) (a8b3cee). |
| v1.2.5 | SDK and extension API stabilization | ✅ Complete | SDK v1 (Core): frozen Level-1 surface, API 1.0, surface golden + 9 behavior contracts + semantic compat golden, examples pack (internal/detect/examples), stability policy + reopening criteria (bbf23c8, db7a00c). |
| v1.3 | End-to-end pipeline | ✅ Complete | T2d–T6 landed (ad791c3, f31cf3a, 9da5793, 9abe2d3, df3672d, 91074ff, 382e218); ROADMAP/NEW-13 closed. |
| v1.4 | Live terminal observability | ✅ Complete | `scan --tui`/`--tui-compact` wired + NEW-21 render fix proven live (field trials 1–2); OPT-P2-3 + OPT-P1-1 landed; OPT-P1-5 deferred to v1.6 (jsintel still text-matches `"tls:"`). |
| v1.5 | Real-world validation, URL hunting, discovery data quality | ✅ Complete | Quality gate b46a110; JS→URL 2d06b94; urllive 7fc7e4c; per-tool+health f44cecc; honest duration 08861f0; chaos 184796a; dnsx brute 0a19d67; katana crawl 1ab2e99; validated across 5 real-target field trials (NEW-19/36/38/39/40). Remainder: NEW-48 (OPT-P2-1 --dry-run/help docs). |
| v1.6 | Robustness and hostile-input hardening | ✅ Complete | OPT-P1-5 9575e14; OPT-P1-4 d10d719; OPT-P1-3 3b21401 (8 fuzz targets, property tests, sortQuery idempotence crasher fixed); OPT-P2-6 4e31f8d; OPT-P2-4 8c795eb. Remaining migrations NEW-53; httpprobe race-flake family NEW-54. |
| v1.7 | Integration and acceptance testing | ✅ Complete | Closed 2026-08-23 — fixtures/goldens/bench-gate landed (53f2f46, 2dcdc96, 9370f3f, 14f61a9, e043555; NEW-56/57/58): `fixtures/<profile>/` hybrid manifests, per-stage goldens via `internal/golden` (`-update`), `testdata/bench/*.txt` + `cmd/benchgate` stdlib comparator (D4, no `benchstat`), CI bench-gate job, memory guards (C-4 drift + HeapInuse), D6 interaction suite across 12 stages; validated deterministic, `gofmt`/`vet`/`build`/`test`/`-race` green. |
| v1.8 | Universal Asset Ingestion Framework | ✅ Complete | Closed 2026-08-23 — `internal/importer` (18 importers behind one interface, auto detection, bounded streaming, provenance sidecar, cache integration), pipeline ingest stage + report attribution, `ravenrecon ingest` CLI, benchmarks + memory guards (1ede060, 81785f2, 3e5ba4e, 5e806fe, 7fd312a, cf0e939). Deferred: Common Crawl remote ingestion; Enriched/Generated origin derivation; CIDR report channel. Optimizations: `OPT-P3-2`. |
| v2.0 | Detection packs | ✅ Complete | Closed 2026-08-24 — OPT-P1-2 per-rule Context + per-render Model isolation (7956f0d); four built-in packs load through frozen SDK v1 via the pipeline seam: Web (7d71aa8), JS (453de88), APIs (7c2c3f1), Cloud informational-only per §0.1 (c9e45fa). Deferred to v2.1+: Auth/AuthZ/Business-logic families (need inter-rule data flow / graph traversal not present on SDK v1). `OPT-P3-4` logger/replay remains open. |

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

Status: ✅ Complete — all six pipeline-integration criteria met; the `ravenrecon scan`
command (T6 CLI wiring, uncommitted at writing) drives the ten production stages
end-to-end. Milestone commit refs: T3a ad791c3, T3b f31cf3a, T3c 9da5793, T3d 9abe2d3,
T4 df3672d, T5 91074ff, T6 (uncommitted at writing). Acceptance state: all met —
hermetic smoke E2E (TestRunScanSmokeE2E drives the production stage shape over
substituted exec/network seams), full-run determinism and partial-failure/retry pins;
gates green (gofmt, go vet, go build, go test, go test -race).

Goal: turn the disconnected engines into one deterministic workflow.

Pipeline:

`discover → dns → httpprobe → urlintel → techintel → jsintel → secrentel → priority → detect → report`

- [x] `ravenrecon scan`
- [x] Pipeline orchestration
- [x] Shared runtime wiring
- [x] Shared asset graph propagation
- [x] Shared cache and report flow
- [x] End-to-end execution paths
- [x] Pipeline-level error handling

Acceptance criteria:

- [x] A single run can move from discovery to report without manual stitching.
- [x] Assets and evidence retain identity across all stages.
- [x] Intermediate failures do not corrupt the final report.
- [x] Pipeline runs are deterministic for the same input and config.
- [x] End-to-end tests cover success, partial failure, and retry paths.

---

## v1.4 — Live terminal observability

Status: ✅ Complete (closed 2026-08-21) — `scan --tui`/`--tui-compact` wired
(NEW-18 VERIFIED), TUI renders real stage events (NEW-21 VERIFIED, proven
live in field trials 1–2: 901 frames with live phase feed + final 12-stage
table). OPT-P1-5 (jsintel TLS sentinel) NOT landed — deferred to v1.6 where
it is a checklist item.

Goal: wire the terminal observability library (`internal/tui`, v1.2) into
`ravenrecon scan`: a live frame on stderr driven by the run's canonical
stage events, terminating deterministically, with scan's exit semantics
and summary unchanged. This fulfills v1.2's acceptance criterion "the TUI
reconstructs a live run from events alone" at the CLI level.

- [x] `ravenrecon scan --tui` — live observability frame on stderr while
      the run progresses (stage lifecycle, worker dashboard, throughput,
      errors, one deterministic final summary frame); color resolved from
      os.Stderr's character-device state (TTY → on, pipe/redirect → off);
      never changes the summary (stdout) or the exit codes
- [x] `ravenrecon scan --tui-compact` — condensed frame (no per-worker or
      resource sections); requires --tui (usage error alone)
- [x] `--tui`/`--verbose` mutual exclusion — usage error listing both
      flags; one event sink per run (the bus or the line observer)
- [x] Deterministic termination + bounded join — subscriber Close ends the
      controller loop, the goroutine is joined before runScan returns on
      every path, and a TUI write failure is a stderr warning only
- [x] Exit semantics and summary unchanged with and without --tui;
      hermetic wiring tests (event flow, cancellation, write failure,
      leak-regression ordering)
- [x] NEW-21 close-out: TUI consumes the pipeline's real stage events —
      live stage feed, honest widget degradation, bounded stage list,
      sanitized strings (fix + render-content tests, reviewer APPROVE
      WITH NITS)

Optimizations in scope for v1.4 (see `OPTIMIZATION.md:5`):

- [x] `OPT-P2-3` — TUI fidelity: bounded stage list, real `StageStarted/Finished`
      from `pipeline/run.go:341`, sanitized strings (`tui/sanitize.go`), honest
      `unknown` totals; `cli/scan.go:454` color `auto` + deterministic
      `sub.Close() → <-tuiDone → bus.Close()` join.
- [x] `OPT-P1-1` (allowed in-flight) — `report/writer.go:334` + `cache/cache.go:292`
      durability: `fsync(dir)` after `Rename` (best-effort, `ENOSYS` ignored).
      Landed as NEW-33 (commit 1f4b0c8).
- [ ] `OPT-P1-5` (allowed in-flight) — `jsintel/fetch.go:678` → structural
      `tlsHandshakeError` sentinel mirroring `httpprobe/run.go:371,912`; remove
      `strings.Contains(...,"tls:")` text fallback. **Deferred to v1.6**
      (verified still open 2026-08-21).

Deferred (user-approved re-scope): per-engine standalone commands (dns,
http, tech, js, secrets, priority, detect, report — reconsider after v1.6
hardening; `OPT-P2-5`).

Acceptance criteria:

- `scan --tui` renders the live run on stderr while the pipeline runs,
  driven by stage events alone (proven hermetically through the wiring
  tests: the bus is the run's event sink and every event reaches the
  controller's subscriber).
- The TUI terminates deterministically on run conclusion and joins
  leak-free on every path (including cancellation), with write failures
  surfaced as warnings.
- Exit codes and the summary are identical with and without `--tui`.
- `--tui` and `--verbose` are mutually exclusive; `--tui-compact` requires
  `--tui`.

---

## v1.5 — Real-world validation, URL hunting, and discovery data quality

Status: ✅ Complete (closed 2026-08-21) — all engineering deliverables landed
and validated live across five real-target field trials (NEW-19/36/38/39/40:
example.com + verily.com, cold/warm, chaos fix proven, gau unlocked 6,120
URLs, urllive 8k-URL triage with honest truncation, duration_ms 452249).
Carried: NEW-48 (OPT-P2-1 remainder); formal FP/FN-rate measurement below.

Goal: validate the system against authorized real targets (the field trial
running against example.com is this milestone's opening activity) and use
the evidence to land the two high-value URL-hunting refinements the field
trial motivates: JS-extracted endpoints must enter the corpus and get
live-checked, and every corpus URL gains a bounded live-status triage.

> Audit companion: `OPTIMIZATION.md:3` — `OPT-P0-1`…`OPT-P0-5` plus `OPT-P1-6`/`OPT-P2-1`/`OPT-P2-2`.
> Each refinement below cites its `OPT-*` entry with `file:line` evidence.

Validation checklist (field-trial depth: NEW-19/36/38; formal FP/FN
measurement not produced — revisit as triage data accumulates):

- [x] Output quality — alive-host yields reviewed per trial (182×2xx on verily)
- [ ] False positive rate *(not formally measured)*
- [ ] False negative rate *(not formally measured)*
- [x] Priority scoring accuracy — groups/attack paths reviewed in trials 2–3
- [x] Technology identification accuracy — GKE clusters, real tech observed
- [ ] Secret suppression quality *(candidates counted, suppression not formally measured)*
- [x] Relationship quality in the asset graph — edges inspected in trial reports
- [x] Limited contract revision only if real-world data proves it necessary — none required

Refinement deliverable — URL hunting (drafted 2026-08-20, orchestrator; revised 2026-08-20 from audit):

- [x] `internal/httpprobe`: new `ProbeURLs(ctx, domain, urls, cfg)` —
      per-URL headers/status only, redirects observed-not-followed (M-6
      consistency), TLS metadata reuse, per-URL timeout, bounded pool,
      existing ProbeFailed/ReasonOther error taxonomy, results sorted by
      URL (determinism) — `OPT-P0-3`
- [x] jsintel corpus feedback: the adapter additionally emits filtered URL
      additions (shared `filterURLs`, canonical-host/in-domain, dedupe
      against incoming corpus, bounded per-run cap with honest overflow
      reporting) from the analyzer URL output (record_analyze.go:176) — `OPT-P0-2` (2d06b94)
- [x] Discovery data-quality gate (field-trial-driven, NEW-22): a single
      passive source burst of 37,248 wordlist-shaped hosts for
      example.com (subfinder v2.15.0, config clean) cascaded into
      12,366 probe URLs, 1,024 priority groups, 32 attack paths, 755
      recommendations and 500/500 jsintel fetch failures — all garbage.
      Gate: per-source output caps + burst-anomaly detection + a
      suspicious-source decision point (flag/abort/continue) BEFORE the
      corpus is poisoned; verify the local subfinder binary/config
      (possible tampered build) as part of the fix — `OPT-P0-1` (b46a110;
      proven live in trial 2: subfinder divergence flagged pre-ingestion)
- [x] urlintel tool hardening (field-trial-driven): per-tool timeouts
      separate from the stage deadline (gau burned the full 10m stage
      budget on the trial run; 3 tools × caps stack up); amass opt-in
      decision (20 min for 0 results on example.com — make it opt-in or
      hard-timeout by default); jsintel health-based early stop when
      fetch failures dominate the first batch (500/500 failed on the
      trial run) — `OPT-P0-4` (f44cecc). Amass opt-in resolved WON'T FIX
      by user decision (NEW-41): exclusion via --sources.
- [x] Report-status nit: summary.started_at == ended_at and duration_ms 0
      (report timestamps the summary write, not the run) — honest run
      duration in the JSON report — `OPT-P0-5` (`report/model.go:142`) (08861f0; verified live 452s, NEW-40)
- [x] New stage `urllive` inserted between secrentel and priority:
      discover → dns → httpprobe → urlintel → techintel → jsintel →
      secrentel → urllive → priority → detect → report; consumes corpus
      URLs (historical + jsintel-fed), produces live-status records — `OPT-P0-3` (7fc7e4c)
- [x] Live records as a NEW results-channel entity (URL + status + redirect
      observed + TLS summary) — NOT a field on `asset.URL` (avoids
      asset-model churn and schema bump); report renderers gain a
      URL-status section (presentation-only) — `OPT-P0-3` (`pipeline/results.go`)
- [x] Pins updated: AllStages + stage vocabulary, T4 determinism,
      T5 full-run E2E, T6 --stages rows, cache op type for per-URL liveness
      (key = schema/op/config-digest/URL) — `OPT-P0-3`
- [x] `OPT-P1-6` — `jsintel/fetch.go:480` fetch truncation counted in
      `Report.Metrics` + `StickyFlags["js_fetch_truncated"]`
      (mirrors `httpprobe` `probe_truncated`); `OPT-P2-1` — `scan --help`
      documents per-tool timeouts + `--amass` opt-in + `scan --dry-run`
      for effective timeouts. **P1-6 landed** (flag proven in trials);
      **P2-1 remainder carried to NEW-48** (--dry-run absent, help docs
      missing; --amass opt-in resolved WON'T FIX via NEW-41).
- [x] Precondition (ops, not code): install gau/waybackurls/waymore — the
      URL corpus is 0 without them (installed; gau unlocked 6,120 URLs in trial 3)

Acceptance criteria:

- Real runs produce actionable, reviewable findings.
- False positives are measured and reduced.
- Priority scoring correlates with manual triage value.
- The system remains stable under messy or contradictory target data.
- Any SDK reopening is backed by concrete evidence, not preference.
- Every corpus URL (historical or JS-fed) ends the run with a bounded live
  status (2xx/4xx/5xx/timeout/refused) in the report.
- JS-extracted endpoints provably flow analyzer → corpus → urllive →
  priority → report.
- Zero recursion; bounded concurrency; honest truncation (per-run URL cap +
  per-URL caps + flags); fixed outcome vocabulary.
- Determinism preserved (updated pins); cold/warm cache parity; race-clean;
  full gate suite green; real-target field trial with the URL tools
  installed shows live URL counts + statuses + cold/warm parity.
- `OPT-P0-1` E2E: synthetic `37k` burst → `discovery_truncated` flagged,
  downstream probe URLs capped not `12k`; `OPT-P0-2` E2E: JS URLs filtered
  in-domain only + overflow flag; `OPT-P0-3` hermetic `ProbeURLs` with
  canned `200/404/500/timeout/refused` → sorted `LiveRecords`, cold/warm parity.

Explicitly out of scope: crawling/spidering or HTML-body link extraction;
robots.txt/sitemap ingestion (later milestone); active brute force/fuzzing
(out of charter); new passive URL sources; per-engine commands; asset.URL
schema change.

---

## v1.6 — Robustness and hostile-input hardening

Status: ✅ Complete (closed 2026-08-21) — OPT-P1-5 9575e14; OPT-P1-4 d10d719;
OPT-P1-3 3b21401 (8 fuzz targets + property tests + sortQuery idempotence
crasher fixed); OPT-P2-6 4e31f8d; OPT-P2-4 8c795eb (one measured win, three
evidence-backed declines). dns/resolver.go fuzz target honestly descoped
(network I/O behind net.Resolver — no pure parse boundary; NEW-49 record).

Goal: treat all parsers and ingestion paths as untrusted-input boundaries.

> Audit companion: `OPTIMIZATION.md:4` — `OPT-P1-3`/`OPT-P1-4`/`OPT-P1-5` + `OPT-P2-4`/`OPT-P2-6` + `C-1`…`C-5`.

- [x] Go fuzzing harnesses — `OPT-P1-3` (eight native targets: asset ParseURL,
      discovery parseHostLines, urlintel parseRawURL, jsintel parser,
      secrentel scanDocument, cache stored-record decode/self-heal, report
      renderCSV + error context; synthetic seeds; real invariants asserted in
      each body; `dns/resolver.go` descoped — no pure boundary)
- [x] Property tests — parse→Identity→parse round-trip, merge idempotence,
      dedup invariants (`testing/quick` + hand-rolled; `OPT-P1-3`)
- [x] JS fuzzing for `internal/jsintel` — `OPT-P1-3`
- [x] Secret fuzzing for `internal/secrentel` — `OPT-P1-3`
- [x] URL fuzzing for `internal/urlintel` — `OPT-P1-3`
- [x] Cache fuzzing for `internal/cache` — `OPT-P1-3`
- [x] Report fuzzing — `OPT-P1-3`
- [x] Parser hardening based on fuzz results — canonicalization idempotence
      fix in `asset/sortQuery` (fuzz crasher "A://0? %0& 0": same URL minted
      two identities across parses → MergeURLs refused merges; regression
      corpus + table pins)
- [x] Silent-truncation hardening — `OPT-P1-4` (`TLSCertificate.DNSNamesTruncated`
      + `Finding.Truncated`; four genuinely-silent finding cuts incl. metadata;
      exactly-at-cap → false; adapter sticky flags `probe_tls_dns_names_truncated`,
      `detect_finding_lists_truncated`)
- [x] TLS classification hardening — `OPT-P1-5` (`jsintel/fetch.go` structural
      `tlsHandshakeError` sentinel mirroring `httpprobe/run.go:360-429`;
      `strings.Contains(,"tls:")` fallback removed; hostile-text
      misclassification fixed; ServerName deviation documented vs httpprobe —
      httpprobe's own IP-literal defect filed as NEW-50)
- [x] Hot-path allocation pass — `OPT-P2-4` (techintel lowered-target cache:
      183→78 allocs/op on the match-indicator hot path; three declines with
      benchmark evidence: priority marshalSurface tie-break, httpprobe TLS
      clone, event bus publish)
- [x] Scope/version dedup refactor — `OPT-P2-6` (`asset.InDomain`,
      `discovery.VersionPattern`/`ExtractVersion` single homes; remaining
      mechanical migrations tracked as NEW-53)

Acceptance criteria:

- Each high-risk parser has at least one fuzz target. ✅ (dns/resolver.go
  descoped with recorded rationale)
- Fuzz discoveries are triaged into fixed regressions, accepted behavior, or invalid inputs. ✅
- Crashers, hangs, and memory blowups are eliminated. ✅ (one crasher fixed)
- Property tests cover normalization, deduplication, and invariants. ✅
- Regression tests exist for every confirmed issue. ✅
- `OPT-P1-4`/`OPT-P1-5`/`OPT-P2-6` landed with `go test -race` green; `OPT-P2-4` `go test -bench` before/after
  shows no regression (bus `~0.5 µs/publish` held at 133–405 ns with 0 allocs; feed `1024` not regressed). ✅

---

## v1.7 — Integration and acceptance testing

Status: ✅ Complete (closed 2026-08-23; formerly v1.6, renumbered 2026-08-20 so roadmap order ==
execution order — commits 53f2f46, 2dcdc96, 9370f3f, 14f61a9, e043555; TODO.closed.md NEW-56/57/58)

Goal: prove the platform works reliably across realistic fixture targets.

> Audit companion: `OPTIMIZATION.md:6` — `OPT-P3-1` + `OPT-P2-4` bench baselines; metrics in `OPTIMIZATION.md:9`.
> Acceptance framework: `fixtures/<profile>/` hybrid weighted-static manifests materialized through the
> existing T4 harness seams (fixed clock + fresh temp-dir cache + loopback JS), per-stage goldens via
> shared `internal/golden` (`go test -update` regenerates, LCS diff, atomic write), `testdata/bench/*.txt`
> baselines (`-count=10 -benchmem`) + stdlib-only `cmd/benchgate` comparator (decision D4 — hand-rolled,
> no `benchstat` dependency; ROADMAP wording conflict recorded, see `testdata/bench/README.md`), CI
> `.github/workflows/ci.yml` bench-gate job (continue-on-error first), memory guards (structural C-4
> drift detectors + HeapInuse delta guards, SKIPPED under `-race`). Pipeline is twelve stages
> (`AllStages()` = 12 via `internal/pipeline/config.go:64`; see ARCHITECTURE.md pipeline sections) —
> goldens and D6 interaction suite cover all 12.

- [x] Fixture targets — `fixtures/{clean-baseline,messy-contradictory,hostile-adversarial}/` hybrid weighted-static (`OPT-P3-1`, D1) — manifests `fixtures/<profile>/manifest.json`, materialized via T4 seams, not a forked harness
- [x] Expected outputs — `internal/pipeline/adapt/testdata/acceptance_{clean,messy,hostile}/` normalized `RunReport` + 12 stage-named goldens + markdown report goldens (`OPT-P3-1`, D2) — shared `internal/golden` home, second consumer justifies it; `detect` migrated
- [x] Snapshot tests — failing subtest IS the stage name (`OPT-P3-1`, D2) — `go test -update` round-trips byte-stable, perturbation swap fails exactly swapped stages, hermetic (`PATH=/nonexistent`, loopback)
- [x] Performance baselines — `go test -bench` + `cmd/benchgate` stdlib comparator recorded (`OPT-P2-4` before/after; ROADMAP said `benchstat` but D4 landed hand-rolled comparator, no `benchstat` dep) — `testdata/bench/*.txt` (`-count=10 -benchmem`, 6 packages: event/techintel/priority/jsintel/httpprobe/urlintel filtered) vs `benchstat` wording conflict resolved per D4
- [x] Memory baselines — `benchmem` + bounded-memory assertions (structural C-4 drift detectors pinning every `OPTIMIZATION.md:7 C-4` constant where it lives + byte-tier `HeapInuse` delta guards `32 MiB` ceiling, `SKIPPED` under `-race`; no exact-MiB equality) — C-4 clarified (`pipeline.MaxDocumentBytes` + `techintel` caps one line each)
- [x] CI integration — output drift + perf regression gates (`OPT-P3-1`, D5) — `.github/workflows/ci.yml` `bench-gate` job (`needs:test`, `continue-on-error:true`, `timeout 25m`, `go test -benchmem` + `cmd/benchgate` per pkg, `urlintel` filtered, `httpprobe` `grep -v FAIL` both sides, `median B/op`/`allocs/op` `>25%` fails, `ns/op` advisory)
- [x] Regression suite for core engine interactions — `OPT-P3-1` + D6 (pipeline-level corrupt-cache recovery, sticky truncation cold→warm, mid-run cancellation across all 12 stages — `internal/pipeline/adapt/interaction_test.go` + `acceptance_profiles_test.go`)

Acceptance criteria:

- [x] Core fixtures produce stable, versioned outputs. (3 profiles × `RunReport` + 12 stage goldens + markdown; `-update` round-trip byte-stable; 3×/5× determinism, hermetic)
- [x] CI detects output drift and performance regressions. (goldens via `go test` fail on drift; bench-gate fails `>25%` median `B/op`/`allocs/op`, advisory `ns/op`; `continue-on-error` until calibrated)
- [x] The suite covers common and edge-case recon scenarios. (clean/messy/hostile profiles: 1025-host sticky truncation, corrupt-cache self-heal, cancellation before/during/after each stage, over-cap document drop, poisoned DNS)
- [x] Baselines are documented and reproducible locally. (`testdata/bench/README.md` exact `-count=10 -benchmem` commands, `internal/golden` docs, `ARCHITECTURE.md` pipeline/acceptance mentions; reproducible via `go test -update`/`benchgate`)
- [x] A failing snapshot clearly identifies which stage regressed. (per-stage golden file + subtest name = stage name; perturbation swap proves isolation)
- [x] `OPT-P3-1` gates green: `gofmt`, `go vet`, `go build`, `go test`, `go test -race`, `go test -bench` recorded. (all green: batch D 18s adapt, E/F 17s, `internal/event`/`techintel`/`priority`/`jsintel`/`httpprobe`/`urlintel` baselines)

---


## v1.8 — Universal Asset Ingestion Framework

Status: complete (closed 2026-08-23)

Goal: consume reconnaissance artifacts from any source — RavenRecon itself or
external tools — normalize them into the canonical asset graph, preserve
provenance, and enrich them through the existing pipeline so the framework
becomes a recon intelligence platform: ingest, normalize, correlate, enrich,
and report on data regardless of where it came from. Most recon tools stop at
collecting; v1.8 makes RavenRecon an analysis platform over other tools'
output (subdomains.txt, alive.txt, urls.txt, js.txt, burp.xml, nuclei.json,
...), reconstructing the asset graph and producing the same reports as if
RavenRecon had discovered the assets itself.

> Audit companion: `OPTIMIZATION.md:6` — `OPT-P3-2`. Cross-cutting invariants in `OPTIMIZATION.md:7`
> (`C-1`…`C-5`) remain in force. Upgrade sequencing in `OPTIMIZATION.md:8`.

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

- [x] `internal/importer` package: importer interface, registry, format
      detection, streaming readers, validation, normalization, progress events
      (1ede060 core + registry + detection waterfall + bounded streaming;
      archive content probes extended in 5e806fe)
- [x] Automatic format detection — extension, MIME, structure, content
      signature; no `--type` flag (files/folders only) (1ede060 waterfall,
      confidence desc / Name asc with generic fallbacks last; gzip peeks
      inflated ≤32 KiB for content-first detection in 5e806fe; `ingest`
      CLI rejects any `--type` flag, cf0e939)
- [x] Plain-text importers: domains, subdomains, urls, alive, js, ips, cidrs
      (1ede060 — 7 importers via the asset builders only)
- [x] JSON importers: httpx, dnsx, naabu, katana, nuclei (81785f2 — plus a
      json-generic fallback; modern katana `-jsonl` nested
      `request.endpoint` shape covered by 5e806fe's fix round)
- [x] XML importers: Burp sitemap/issues, OWASP ZAP (3e5ba4e)
- [x] Crawl-output importers: katana, hakrawler, gospider, waymore, gau
      (5e806fe — disposition: no redundant adapters; these tools' documented
      outputs are bare URL lists → plain family, or flat url-key JSON →
      json family, and are claimed by existing importers; see
      `internal/importer/doc.go` for the per-tool verification)
- [x] Archive sources: wayback (Common Crawl future) (5e806fe — CDX lines +
      WARC records, local files incl. `.gz`; Common Crawl remote ingestion
      deliberately deferred)
- [x] Streaming parsers: bounded memory, incremental parsing, progress events,
      cancellation, resume (1ede060 line streaming with 32 KiB line cap +
      drained bounded chunks + 100 MiB decompression cap; 81785f2 array
      framer with exact decompressed-byte accounting; 3e5ba4e XML ring
      window + sticky-decoder contract; resume = unchanged-file repeat
      imports served by cache hits — a mid-file resume cursor is not built)
- [x] Provenance preserved on every imported asset (importer, original tool,
      filename, import time, original record, confidence, metadata)
      (1ede060 sidecar records + asset Prov.Source; projected into report
      attribution by 7fd312a/cf0e939)
- [x] Deduplication reuses the existing identity/merge/provenance/relationship
      logic — no duplicate systems (1ede060 Sink dedups by canonical
      Identity().String(); report-side first-seen-wins merge in 7fd312a)
- [x] Cache integration: content hash + import config + schema version +
      importer version; repeat imports of unchanged files become cache hits
      (1ede060 key parts via CacheKeyForFile; 7fd312a stage-level
      cache-before-execute with self-healing decode and
      StatusIncomplete-for-truncated storage)
- [x] Imported assets flow through the standard pipeline
      (DNS → HTTP → Tech → JS → Secrets → Priority → Detection → Reporting)
      (7fd312a ingest stage feeds Additions/Results into the SAME stages;
      production AllStages() = 12 untouched)
- [x] `ravenrecon ingest` CLI: single files, multiple files, folders
      (cf0e939 — flags before positionals, target normalization via
      asset.NewDomain, default selection [ingest]+AllStages minus discover)
- [x] Reporting distinguishes Discovered / Imported / Enriched / Generated with
      source attribution (7fd312a Origin vocabulary + census + per-asset
      Attribution entries, CSV/Markdown/HTML origin columns and provenance
      sections, digest-stable; cf0e939 CLI wiring. Disposition: only
      Discovered and Imported are derived today — Enriched/Generated have no
      producing subsystem yet and are deferred rather than fabricated)
- [x] Tests: empty files, malformed input, duplicates, huge files, cancellation,
      resume, cache, streaming, mixed imports (across all six commits:
      hermetic table suites per format, heap guards skipped under -race,
      C-4 drift detectors, regression tests with RED proofs; T14 adds
      benchmarks + committed baseline + CI bench-gate step)

Acceptance criteria:

- [x] Every supported format imports without a `--type` hint. (16-importer
      detection tables per format family in `internal/importer/*_test.go`;
      generic fallbacks last; honest gap recorded in TODO.md NEW-60: an
      UNCOMPRESSED-only caveat applies to gzipped bare-link lists at
      detection time even though the streaming path is gzip-transparent)
- [x] Imported assets carry full provenance and deduplicate against existing
      assets via the shared identity/merge logic. (Sink identity dedup tests;
      provenance sidecar verbatim OriginalRecord windows; report
      attribution projection tests incl. boundary-filter honesty)
- [x] Imports are streaming with bounded memory; a 1 GB input does not spike
      memory. (Structural: never-whole-file streaming under MaxLineBytes
      32 KiB / MaxDecompressedBytes 100 MiB / MaxOutput 100k caps — pinned by
      `internal/importer/bounds_c4_test.go`. Empirical: HeapInuse guards over
      10 MB streams measure ~0 retained delta (<8 MiB ceiling), 12 MiB single
      array elements and multi-MiB XML padding stay capped; the 1 GB claim
      rests on those structural caps plus the 10 MB empirical runs, not on a
      recorded 1 GB lab pass)
- [x] Repeat imports of unchanged files are cache hits. (counting-importer +
      counting-cache proofs in `internal/pipeline/adapt/import_test.go` —
      warm run executes the importer exactly once across two runs;
      truncated imports stored StatusIncomplete are never served)
- [x] Imported data produces reports structurally identical to pipeline-discovered
      data (provenance aside). (TestOriginOfParity: same host discovered vs
      imported → identical asset fields, differing only origin/attribution;
      absent-attribution exports stay byte-identical to legacy goldens)
- [x] All gates pass (gofmt, vet, build, test, race); benchmarks recorded for
      large imports. (gates green at close-out; `testdata/bench/importer.txt`
      baselines + CI bench-gate step landed with T14)

Honest dispositions (recorded at close-out):

- Crawl tools: katana/hakrawler/gospider/gau outputs route through the plain
  and json families (verified against each tool's documented output formats);
  waymore uncompressed link lists likewise — gzipped bare-link lists are
  claimed by nobody at detection time today (NEW-60).
- Common Crawl remote ingestion is deferred: archive sources cover local CDX/
  WARC files only.
- Enriched/Generated origins are vocabulary-complete but derivation-deferred:
  no subsystem produces them today, so reports carry discovered/imported
  counts only.
- CIDR imports reach the provenance sidecar but have no Results channel in
  the pipeline/report model yet (Results mirrors Context 1:1; neither has a
  CIDR slot).

---

## v2.0 — Detection packs

Status: complete (closed 2026-08-24)

Goal: shift new detection logic into stable, versioned packs built on the frozen SDK.

> Audit companion: `OPTIMIZATION.md:6` — `OPT-P3-3` + `OPT-P1-2` (`detect/context.go:68` isolation for
> third-party packs). Sequencing in `OPTIMIZATION.md:8`: standalone CLIs (`OPT-P2-5`) remain deferred
> until after `v1.6` hardening; see `OPTIMIZATION.md:5`.

Design rule: core packages stay stable. New detection capabilities should be implemented as packs unless they require a fundamental platform change.

### Pack families

Landed in `internal/detect/packs/<family>`; every pack enters only through
the frozen SDK (`Rules()` → `CheckAPIVersion(1,0)` → `ValidateRule` →
`Register` → `Validate` → `Seal`) via the pipeline seam
(`internal/pipeline/adapt/detect.go`). 14 built-in rules load through
`NewDetectStageWithAllPacks`; `AllStages()` stays 12.

- **Web** ✅ SHIPPED (7d71aa8) — 5 rules: `web.csp.missing`, `web.hsts.missing`,
  `web.cors.wildcard`, `web.robots.exposed`, `web.sourcemap.exposed`
- **Authentication** ⏳ DEFERRED to v2.1+ — JWT/OAuth/session/cookie analysis needs
  inter-rule data flow and graph traversal that SDK v1 does not carry
- **Authorization** ⏳ DEFERRED to v2.1+ — IDOR heuristics and privilege-boundary
  reasoning need cross-asset relationship traversal not present on SDK v1
- **APIs** ✅ SHIPPED (7c2c3f1) — 3 rules: `api.openapi.exposed`,
  `api.rest.idor-indicator`, `api.graphql.introspection`
- **JavaScript** ✅ SHIPPED (453de88) — 3 rules: `js.dom.xss`,
  `js.postmessage.no-origin-check`, `js.prototype.pollution`
- **Cloud** ✅ SHIPPED, INFORMATIONAL-ONLY per §0.1 (c9e45fa) — 3 indicator-shape
  rules: `cloud.aws.key-indicator`, `cloud.bucket.url`, `cloud.firebase.indicator`;
  descriptions explicitly disclaim validity/publicness/exposure claims, no live
  verification performed or represented
- **Business logic** ⏳ DEFERRED to v2.1+ — workflow/state-transition analysis needs
  multi-step data flow across rules; not expressible on SDK v1 without a formal
  SDK reopening (stability policy gates apply)

Acceptance criteria:

- [x] Packs load through the SDK without core edits. (`internal/detect/packs/{web,js,apis,cloud}`
      compile against only the exported `detect` surface; loaders live in
      `internal/pipeline/adapt/detect.go`; the framework gained no pack-specific
      code paths — the only post-freeze `detect` change is the unexported
      OPT-P1-2 cloning internals, 7956f0d)
- [x] Packs declare metadata, dependencies, and compatibility versions. (every
      `Rules()` gates on `CheckAPIVersion(1,0)`; per-pack `MetadataDepsCompat` tests)
- [x] Pack output is normalized into the same evidence model as core engines.
      (canonical `asset.Finding` through the shared engine; deterministic per-pack
      report goldens under `internal/detect/packs/*/testdata/`)
- [x] Pack failures are isolated and do not crash the platform. (per-pack
      `FailuresIsolated` panic→failed-not-crashed tests)
- [x] Pack behavior is covered by pack-level tests and fixtures. (13 hermetic tests +
      golden per pack; seam tests in `internal/pipeline/adapt/detect_seam_test.go`)
- [x] `OPT-P1-2` landed: `detect/context.go:109` `cloneContextForRule` gives every rule
      its own Context copy and `report/model.go:171` `cloneModel` deep-clones the Model
      per render; `TestContextIsolation`/`TestModelIsolation` red→green, `-race` green
      (7956f0d).

---

## Optimization index

All audit optimizations live in `OPTIMIZATION.md` with `file:line` evidence. Summary mapping:

| Roadmap | Optimizations |
|---------|---------------|
| v1.4 | `OPT-P2-3` TUI fidelity + `OPT-P1-1`/`OPT-P1-5` allowed in-flight |
| v1.5 | `OPT-P0-1`…`OPT-P0-5` + `OPT-P1-6` + `OPT-P2-1`/`OPT-P2-2` |
| v1.6 | `OPT-P1-3` fuzzing + `OPT-P1-4`/`OPT-P1-5` + `OPT-P2-4`/`OPT-P2-6` + `C-1`…`C-5` |
| v1.7 | `OPT-P3-1` fixtures/snapshots/baselines + `OPT-P2-4` bench |
| v1.8 | `OPT-P3-2` ingestion |
| v2.0 | `OPT-P3-3` packs + `OPT-P1-2` isolation + `OPT-P3-4` logger/replay |
| Cross-cutting | `OPTIMIZATION.md:7` `C-1`…`C-5` concurrency/cache/trust/bounding invariants; `OPTIMIZATION.md:9` metrics |

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
