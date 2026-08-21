# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-56 — active work lives in TODO.md; history in TODO.closed.md).
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

