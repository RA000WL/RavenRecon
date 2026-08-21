# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-57).
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

### NEW-3 (INFO) — Set-Cookie retained verbatim in boundedHeaders (internal/httpprobe)
- Status: DEFERRED
- Reporter: reviewer
- Owner: (none)
- Problem: boundedHeaders retains Set-Cookie verbatim; session cookies could
  be stored in probe records. Pre-existing behavior, outside the audit
  scope — documented here only, per AGENTS.md §5.
- Fix (if ever scoped): redact Set-Cookie values like Location userinfo;
  requires a scoped milestone decision first.
- Verification: n/a while deferred.

### NEW-14 (INFO) — priority stage parameter-name derivation diverges from urlintel's extraction (internal/pipeline/adapt)
- Status: DEFERRED
- Reporter: reviewer (T2d round, INFO-2)
- Owner: (none)
- Problem: the priority adapter derives Signal.ParameterNames from the URL
  asset's canonical query (internal/pipeline/adapt/priority.go:371-389,
  queryParamNames) while urlintel's own extraction
  (internal/urlintel/extract.go:103-140, extractParams) differs on the same
  URL: (a) queryParamNames includes value-less keys (`?flag` → name
  `flag`) that urlintel deliberately skips; (b) a URL with >64 parameters
  fails the priority engine's signal validation (internal/priority/
  score.go:644-646 → per-asset failed), whereas urlintel caps at 256 with
  an explicit Overflow flag. Both outcomes are honest (no §0.6 violation —
  nothing is silently completed) and the derivation is deterministic on the
  canonical query, but a pathological URL surfaces as a FAILED priority
  asset with no truncation signal, and parameter-name semantics differ
  between the two consumers.
- Fix (if ever scoped): align queryParamNames with urlintel's extraction
  semantics (skip value-less keys) and decide the >64-parameter path
  (either a parameter cap with an explicit truncation signal or acceptance
  of longer lists) — requires a scoped milestone decision; the engines'
  fixed bounds are deliberate contracts.
- Verification: n/a while deferred.

### NEW-56 (HIGH) — v1.7 Integration and acceptance testing (ROADMAP v1.7)
- Status: IN PROGRESS (orchestrator, 2026-08-21) — milestone tracker;
  per-task records appended below as batches land
- Reporter: master
- Owner: builder (per-task dispatches)
- Problem: ROADMAP v1.7 — fixtures/<target>/, golden snapshots naming the
  regressed stage, perf/memory baselines, CI drift gates, regression suite
  for engine interactions. Research round completed (session
  ses_fdaca5d04ffeeHnmQcbF4rgv47); reality corrections: CI EXISTS
  (.github/workflows/ci.yml: gofmt/vet/test — extend, don't create);
  OPTIMIZATION.md appendix stale (P0-4/P0-5/P1-3..5/P2-4 still OPEN despite
  closed milestones) and says "ten-stage" (pipeline is twelve since v1.5).
  REPAIR NOTE (2026-08-21): commit 2bf48c3 claimed this tracker was opened,
  but its insertion had failed and the accompanying working-tree edits
  gutted parts of TODO.closed.md; both repaired here from git HEAD.
- Locked decisions (orchestrator, from research):
  D1 fixtures = hybrid weighted static: JSON manifests under
     fixtures/{clean-baseline,messy-contradictory,hostile-adversarial}/
     materialized through the EXISTING T4 harness seams (no forked harness);
     loopback server only for JS fetch bodies; determinism via fixed clock +
     fresh temp-dir cache (T4 machinery carries over)
  D2 goldens = field-masked per-stage: normalized RunReport JSON per profile
     + one golden PER StageRecord (failing subtest IS the stage name) +
     markdown report for clean profile; normalizer zeroes timestamps/
     durations/cache paths/tool versions/runtime versions; sorted keys before
     marshal; reuse detect's -update/atomic-write/LCS-diff pattern via a new
     shared internal/golden test-support home (second consumer justifies it)
  D3 memory bounds two-tier: structural cap-behavior assertions stay the hard
     gate (+ bound-constant drift detector vs C-4 table); byte tier = coarse
     HeapInuse delta guard, order-of-magnitude headroom, SKIPPED under -race;
     no exact-MiB equality (flake factory)
  D4 perf gate: committed testdata/bench/<pkg>.txt baselines (-count=10
     -benchmem); hand-rolled stdlib-only comparator (NO benchstat dep; ROADMAP
     wording conflict recorded) failing only on median B/op or allocs/op >25%
     over baseline; ns/op advisory-only initially; bench gate non-blocking
     until calibrated
  D5 CI: EXTEND ci.yml (build, -race, goldens via go test, bench-gate job
     continue-on-error first)
  D6 interaction regression gaps to cover via profiles: pipeline-level
     corrupt-cache recovery, compound failure+truncation combos w/ sticky
     merges cold->warm, mid-run cancellation across all 12 stages
  D7 docs drift (OPTIMIZATION.md appendix statuses, ten-vs-twelve stage,
     benchstat wording) reconciled in the closing docs wave

## Operational warnings (all agents)

- **`go test ./...` is safe to run** — verified green with `-count=1` on this
  workspace (all 22 packages pass). internal/discovery is slow (~75 s:
  bounded `waitForTrue` polling of 2-3 s per cache/subprocess test) but does
  NOT hang; the earlier "deterministic hang" warning referred to a parallel
  in-flight workspace and is resolved here.
- Tests must stay hermetic (loopback servers, fake transports, temp dirs —
  no public internet).
- Stdlib only; go.mod must not gain dependencies. No real secrets in tests
  (synthetic values only).
- External tools are adapters behind interfaces; core pipelines never branch
  on tool names.
