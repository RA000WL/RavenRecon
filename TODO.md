# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-92).
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

> **2026-08-23 cleanup wave (wave b) — VERIFIED:** NEW-3, NEW-14, NEW-60, NEW-73
> (deferred residuals), NEW-74 (residual docs), NEW-85..NEW-89, and NEW-90
> (new: stage-level failures absent from report error summary — found in the
> vulnbank.org field test) dispatched to six parallel builders; merged diff reviewer-APPROVED
> (merge-level cross-agent review) and orchestrator-verified same day.
> NEW-3/14/60/85..90 archived to TODO.closed.md; NEW-73/74 keep only their
> genuinely-open residuals; NEW-91 filed from merge-review Finding 1.

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

### NEW-91 (LOW) — crawl engine-signal failures remain invisible in the NEW-90 error summary (internal/pipeline/adapt)
- Status: OPEN
- Reporter: reviewer (cleanup wave b merge review, 2026-08-23)
- Owner: (unassigned)
- Problem: the missing-binary path returns {FailedHosts: len(hosts)}, nil with nil Err, and the adapter maps it to OutcomeIncomplete/ItemsFailed without attaching an Err or Diagnostics — so Context.Errors stays total=0 while the stages table says incomplete (the exact symptom shape NEW-90 was filed from; collectStageErr only collects non-nil Err).
- Fix: attach a wrapped Err on total-failure outcomes in the crawl adapter (making them collectible), or record stages-table-as-single-source for engine-signal failures explicitly.
- Verification: hermetic missing-binary run → errors summary names the stage.

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

### NEW-73 (LOW) — Audit LOW/INFO wave A: correctness/hygiene (see REVIEW-2026-08-23.md §3 LOW 1–14)
- Status: VERIFIED for the implemented subitems (orchestrator-verified 2026-08-23: OverflowDropped exactness, dns.go SliceStable sorts w/ determinism pins, candidateAsset surfacing, deadline→cancelled classification, PDCP init removal + t.Setenv migration). STILL OPEN within this entry: ingest path-param lossiness; insertion sorts outside dns.go (techintel/tui/importer) skipped as out-of-wave scope.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: (unassigned)
- Problem: fourteen LOW items with file:line detail in the report — highlights: urlintel live-record TLS-diagnostic stored StatusFailed; NetResolver lazy-init race; outer-deadline discards captured tool stdout prefix; OverflowDropped under-count; configurable-cap decode churn loop; candidateAsset zero-asset swallow; report deadline→failed skew; Fingerprint[:8] panic guard; three divergent URL-filter copies (root cause of H-3); crawl cancellation drops engine error; O(n²) insertion sorts; ingest path param newline/comma lossiness; chaos apex-subdomain mangling; PDCP_API_KEY init()-scope leak in tests.
- Fix: per-item fixes in the report.
- Verification: per-item tests named in the report.

### NEW-74 (INFO) — Audit INFO/doc-skew wave B (see REVIEW-2026-08-23.md §3 INFO)
- Status: VERIFIED except as noted (orchestrator-verified 2026-08-23): CLI usage/--tui claims, AGENTS §10 snippet, inline-script counting, README/ARCHITECTURE drift (progress units, bidi passthrough, detect Context boundary, scan overclaim), fixture_manifest relocation to test-support, provenance-ordinal comment correction — all done and doc-verified. Nothing further open under this entry.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: docs
- Problem: CLI usage lists ten stages vs twelve actual + "no active enumeration ever run" overclaim vs crawl/dnsx_brute; version.go stale migration comment; dns-vs-httpprobe all-timeout classification asymmetry; transport idle-conn hygiene; provenance ordinal drift; progress-event overcount; jsintel inline-script uncounted parse failures; adapt truncation metadata must be consumed at wiring time; priority FNV digest bound; TUI bidi passthrough; detect Context trust boundary; fixture_manifest in prod package.
- Fix: doc corrections + noted follow-ups; details in report §3 INFO.
- Verification: n/a (docs) / per-item notes.
