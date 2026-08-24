# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-96).
- **Statuses:**
  - `OPEN` — needs work; reporter recorded it.
  - `IN PROGRESS` — owner claimed it (owner sets this).
  - `VERIFIED` — implementation + tests exist, gates run, orchestrator confirmed.
  - `DEFERRED` — acknowledged, deliberately not doing now (reason required).
  - `WON'T FIX` — decision recorded (reason required).
- **Archive:** VERIFIED / CLOSED / RESOLVED / WON'T FIX entries move to
  `TODO.closed.md` (orchestrator maintains both files).
- **Closing:** the orchestrator (not the implementer) moves entries to
  VERIFIED and archives them under "Recently closed". Implementers never
  claim work that was not actually run (AGENTS.md §0.9).
- **Reporter duties:** include file:line evidence, severity, and the
  concrete fix to do — not just the problem.
- **Suggestions vs. mandates:** any agent may add ideas/notes (builder
  refactor ideas, reviewer hardening notes, researcher tooling
  suggestions) — tag them `(note)` in the title so they are not mistaken
  for mandated fixes.

## Role guidance

- **Reviewer:** files findings as entries (severity + evidence + required
  fix), status OPEN. Never fixes.
- **Builder:** claims entries (IN PROGRESS), implements, reports gates;
  may add `(note)` suggestions for future work.
- **Tester:** files coverage gaps, flaky tests, missing race coverage.
- **Researcher:** files tooling/architecture suggestions with trade-offs.
- **Docs:** files doc-drift entries (comments, README/ARCHITECTURE skew).
- **Master:** assigns owners, verifies closures against acceptance
  criteria, archives completed entries, keeps this file honest.

## Entry template

    ### NEW-n (SEVERITY) — short title (package)
    - Status: OPEN | IN PROGRESS | DEFERRED
    - Reporter: reviewer | builder | tester | researcher | docs
    - Owner: (unassigned) | builder | docs | ...
    - Problem: <one or two lines, file:line evidence>
    - Fix: <actionable steps>
    - Verification: <tests/gates that prove it done>

## Open items

> **2026-08-23 cleanup wave c — VERIFIED:** NEW-91 and both NEW-73 residuals
> fixed (two builders), merged gates green, orchestrator-verified. NEW-91/73/92
> archived to TODO.closed.md. Open board now holds only DEFERRED items.

> **2026-08-23 cleanup wave (wave b) — VERIFIED:** NEW-3, NEW-14, NEW-60, NEW-73
> (deferred residuals), NEW-74 (residual docs), NEW-85..NEW-89, and NEW-90
> (new: stage-level failures absent from report error summary — found in the
> vulnbank.org field test) dispatched to six parallel builders; merged diff reviewer-APPROVED
> (merge-level cross-agent review) and orchestrator-verified same day.
> NEW-3/14/60/85..90 archived to TODO.closed.md; NEW-73/74 keep only their
> genuinely-open residuals; NEW-91 filed from merge-review Finding 1. NEW-93 (live-found crawl
> breakage) fixed + live-validated; NEW-94 remains OPEN for design decision.

> **2026-08-23 implementation wave:** NEW-61 through NEW-84 were implemented
> by a builder batch (10 parallel fix agents + orchestrator integration).
> Gates at close: gofmt clean, go vet clean, `go build ./...` OK,
> `go test ./... -count=1` 28/28 packages pass, `go test -race` green on
> runtime/cache/event/pipeline/adapt/tui/crawl, CLI smoke-tested live
> (doctor; discover + scan against vulnbank.org incl. --tui header and exit
> codes). Entries below flipped to IN PROGRESS — never self-closed; orchestrator
> verified 2026-08-23 (4-cluster reviewer sweep + gap fixes): all 22 entries
> VERIFIED and archived to TODO.closed.md. NEW-85..NEW-89 filed from findings
> the sweep surfaced.

### NEW-95 (HIGH) — v2.0 Detection packs (ROADMAP v2.0)
- Status: IN PROGRESS (orchestrator, 2026-08-24) — scoping round; Batch 1 (OPT-P1-2) IMPLEMENTED + REVIEWED + VERIFIED; Batch 2 (Web pack) IMPLEMENTED + REVIEWED + VERIFIED
- Reporter: master
- Owner: builder (per-wave dispatches)
- Problem: ROADMAP v2.0 — detection packs loadable through frozen SDK v1
  without core edits (families: Web/Auth/AuthZ/APIs/JS/Cloud/Business-logic),
  metadata+deps+compat declarations, failure isolation, normalized evidence,
  pack-level tests. Prerequisite OPT-P1-2 (shared mutable Context/Model)
  rises to HIGH once third-party packs exist. Constraint: SDK surface frozen
  (v1.2.5 golden) — exported-API additions require formal reopening; fixes
  must stay inside package internals.
- Batch 1 — OPT-P1-2 Context/Model isolation (builder; reviewer APPROVE after interior-clone fix; orchestrator VERIFIED 2026-08-24): internal per-job cloning via unexported cloneContextForRule (slices.Clone per slice + maps.Clone) and cloneModel deep-cloning interior slices (Surfaces.Factors, Groups.Members, etc.); barrier tests TestContextIsolation + TestModelIsolation FAIL→PASS, interior deep-clone tests, TestContractContextImmutabilityHonestBoundary updated, golden byte-identical, full gates green incl. -race on detect/report.
- Batch 2 — Web pack (builder ses_fcccba2d6ffeFmcgwNDv2vSxBf, 2026-08-24) IMPLEMENTED + REVIEWED + VERIFIED (reviewer ses_fccb9d416ffe7BGGhl0wxdYQWz APPROVE 2026-08-24; orchestrator VERIFIED: re-ran gofmt/vet/build/test/race + surface golden, no exported drift): internal/detect/packs/web (doc.go, helpers.go, csp.go, hsts.go, cors.go, robots.go, sourcemap.go, rules.go) exporting Rules() with CheckAPIVersion(1,0) → 5 rules web.csp.missing / web.hsts.missing / web.cors.wildcard / web.robots.exposed / web.sourcemap.exposed (each <100 lines, deterministic, context-honoring, RequiredAssetTypes gated, Config deterministic via sortedKeys, bounded at 256, PriorityInfo/StatusOpen/CategoryInformation or Misconfig, MethodDetection evidence, observed-host/endpoint/js subjects); pipeline seam internal/pipeline/adapt/detect.go NewDetectStageWithPacks / LoadWebPack (nil→empty unchanged, web pack loaded via ValidateRule→Register deepCopy→Validate→Seal, AllStages unchanged); tests hermetic: packs/web/web_test.go (13 tests: CheckAPIVersion, LoadsThroughSDK deepCopy+Seal, MetadataDepsCompat, RequiredAssetTypesSkipHonestly, DetectorsHonorContext, FailuresIsolated panic→failed not crashed, CacheColdWarmParity same FindingsTruncated, DeterminismGolden via internal/golden -update byte-stable 2 runs equal, per-rule emission, ConfigDeterministic sorted) + adapt/detect_web_test.go (3 tests: WithPacks loads 5, ProvidedRegistry merges+seal, EmptyStillEmpty); goldens internal/detect/packs/web/testdata/web_report.golden (-update regenerates byte-identical); gates gofmt/go vet/go build green, go test ./... 28/28 pass (discovery 112s), go test -race ./internal/detect/... green, api_v1.golden untouched (TestSDKAPISurfaceSnapshot pass without -update).
- Verification: per ROADMAP v2.0 acceptance criteria.

## Operational warnings (all agents)

- **`go test ./...` is safe to run** — verified green with `-count=1` on this
  workspace (all packages pass). internal/discovery is slow (~75 s:
  bounded `waitForTrue` polling of 2-3 s per cache/subprocess test) but does
  NOT hang; the earlier "deterministic hang" warning referred to a parallel
  in-flight workspace and is resolved here.
- Tests must stay hermetic (loopback servers, fake transports, temp dirs —
  no public internet).
- Stdlib only; go.mod must not gain dependencies. No real secrets in tests
  (synthetic values only).
- External tools are adapters behind interfaces; core pipelines never branch
  on tool names.

