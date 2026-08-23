# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-90).
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

### NEW-60 (INFO) — gzipped plain-text link lists claimed by nobody at detection time (internal/importer)
- Status: OPEN
- Reporter: reviewer T8 round (entry recorded by fix session ses_fd28d1daaffeOWE1tUkrhAgem8, 2026-08-23)
- Owner: (unassigned)
- Problem: plainConfidence declines any gzipped peek before the line-shape
  classifier (detect.go:363), and no other family claims a gzip of bare URLs
  (archive probes require WARC magic or CDX row shape) — so e.g. a
  waymore.txt.gz bare-link export streams fine once an importer is chosen
  (openStream/readLines are gzip-transparent) but Detect returns no claim at
  all for it. doc.go's waymore bullet previously overstated this as
  gzip-capable coverage; it is now qualified to uncompressed outputs.
- Fix option: mirror the archive branch's bounded inflatePeek (≤PeekSize,
  archive.go inflatePeek) inside plainConfidence (or as a pre-step in
  Detect): if isGzipped(peek), inflate once in memory and run the same
  XML/JSON-decline guards + lineShapeHistogram over the inflated bytes;
  corrupt gzip must keep declining honestly.
- Verification: registry table case with a gzipped one-URL-per-line list →
  top match plain-urls; existing gzipped CDX/WARC content-detection and
  anti-steal cases stay green.


### NEW-85 (MEDIUM) — crawl stage diagnostic-presence heuristic misclassifies linkless successes as failures (internal/pipeline/adapt)
- Status: OPEN
- Reporter: reviewer (v1.8-wave verification cluster A, 2026-08-23)
- Owner: (unassigned)
- Problem: adapt/crawl.go:150-158 — when FailedHosts==0 && len(URLs)==0 && !Truncated && len(Diagnostics)>0, the stage infers failed=len(hosts). A katana run that genuinely succeeded over a linkless site but emitted any benign diagnostic (e.g. "N malformed lines skipped") is reported incomplete with ItemsFailed=len(hosts) — counters lie even though the outcome errs conservative.
- Fix: explicit engine signal instead of inference — engine sets FailedHosts=len(hosts) itself on its genuine failure early-returns (e.g. katana.go missing-binary path), adapter drops the diagnostics heuristic.
- Verification: linkless-success-with-benign-diagnostic fixture → completed, ItemsFailed=0; genuine-failure fixtures still fail.

### NEW-86 (LOW) — crawl exit-0 all-malformed output still stores completed-empty corpus (internal/crawl)
- Status: OPEN
- Reporter: reviewer (v1.8-wave verification cluster A, 2026-08-23)
- Owner: (unassigned)
- Problem: crawl/katana.go:280-320 — hosts exiting 0 but emitting only malformed JSONL increment neither FailedHosts nor Truncated; an all-such-hosts run stores StatusCompleted with an empty corpus that is served permanently (no TTL) — same poison-the-key class as NEW-62.
- Fix: count unparseable-output-with-zero-parsed as host failure (or store incomplete when parsed==0 && malformed>0).
- Verification: fake runner emitting garbage JSONL → no completed record stored; second Crawl re-executes.

### NEW-87 (LOW) — urlintel storeURL drops urlKey build error (internal/urlintel)
- Status: OPEN
- Reporter: reviewer (v1.8-wave verification cluster D, 2026-08-23)
- Owner: (unassigned)
- Problem: record.go:403-405 — `key, err := urlKey(...)` err is silently overwritten by json.Marshal's err; a key-build failure would proceed toward Put("") surfacing a misleading "cache put" diagnostic instead of lookupURL's failed classification (asymmetry with lookupURL:326-333). Practically unreachable today (const operation, validated identity).
- Fix: handle urlKey's error before Marshal, mirroring lookupURL.
- Verification: fault-injection key-builder test asserting failed classification not cache-put diagnostic.

### NEW-88 (LOW) — jsintel/adapt toolRunBudget is package-level mutable state (§7.2) (internal/jsintel/adapt)
- Status: OPEN
- Reporter: reviewer (v1.8-wave verification cluster B, 2026-08-23)
- Owner: (unassigned)
- Problem: adapt/run.go:38-41 — mutable package-level var used as test-only time seam for the NEW-68 timeout budget; production never writes it and tests are not parallel today, but it is global mutable state and a data-race trap if these paths ever run t.Parallel().
- Fix: thread the budget through the unexported env (settable only from tests).
- Verification: tests pass with seam removed from package scope.

### NEW-89 (INFO wave) — doc/comment nits from v1.8-wave verification (multi-package)
- Status: OPEN
- Reporter: reviewer (verification clusters A-D, 2026-08-23)
- Owner: docs
- Problem: cli.go:52/:80 "No active enumeration, brute force, or intel modes are ever run" overclaims given crawl stage + opt-in dnsx_brute (also missing from NEW-74's lists); scanUsage promises "progress counters (completed/remaining/in-flight/eta)" though production emits only stage events (render zero/unknown); event.go AssetDiscovered.Path bound rationale breaks under percent-escaping (escaped path can triple bytes vs decoded cap derivation); discovery/cache.go:27 stale "both callers do" comment (one production caller); techintel truncateUTF8 comment misstates loop purpose (runs exactly when a multi-byte rune is cut); adapt/import_test.go dead `blocker.cancel` assignment; adapt/crawl_test.go garbled first comment line; tui/feed.go percentDecode duplicates asset/service.go encoder inverse (drift risk cosmetic-only — decode failure degrades to whole-identity digest).
- Fix: comment/text corrections; consider one exported codec for candidate-label encoding in a future milestone.
- Verification: n/a (docs) / trivial.

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
- Status: IN PROGRESS — most items implemented 2026-08-23 (urlintel live-record TLS status, NetResolver race, outer-deadline stdout-prefix ingestion, crawl cancellation error preservation, chaos apex mangling, LookPath conflation, marshal-fail cache skip); deliberately NOT changed: L-4/L-5 secrentel OverflowDropped count precision, O(n²) insertion sorts, candidateAsset swallow, report deadline→failed skew, ingest path-param lossiness, PDCP init()-scope in adapt tests — remaining items stay OPEN within this entry.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: (unassigned)
- Problem: fourteen LOW items with file:line detail in the report — highlights: urlintel live-record TLS-diagnostic stored StatusFailed; NetResolver lazy-init race; outer-deadline discards captured tool stdout prefix; OverflowDropped under-count; configurable-cap decode churn loop; candidateAsset zero-asset swallow; report deadline→failed skew; Fingerprint[:8] panic guard; three divergent URL-filter copies (root cause of H-3); crawl cancellation drops engine error; O(n²) insertion sorts; ingest path param newline/comma lossiness; chaos apex-subdomain mangling; PDCP_API_KEY init()-scope leak in tests.
- Fix: per-item fixes in the report.
- Verification: per-item tests named in the report.

### NEW-74 (INFO) — Audit INFO/doc-skew wave B (see REVIEW-2026-08-23.md §3 INFO)
- Status: IN PROGRESS — CLI usage stage count + --tui claims corrected 2026-08-23; AGENTS.md §10 MaxWorkers snippet fixed; jsintel inline-script parse failures now counted. Remaining doc items (README/ARCHITECTURE drift, provenance ordinal, progress-event overcount, TUI bidi passthrough, detect Context trust boundary, fixture_manifest placement) stay OPEN with owner docs.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: docs
- Problem: CLI usage lists ten stages vs twelve actual + "no active enumeration ever run" overclaim vs crawl/dnsx_brute; version.go stale migration comment; dns-vs-httpprobe all-timeout classification asymmetry; transport idle-conn hygiene; provenance ordinal drift; progress-event overcount; jsintel inline-script uncounted parse failures; adapt truncation metadata must be consumed at wiring time; priority FNV digest bound; TUI bidi passthrough; detect Context trust boundary; fixture_manifest in prod package.
- Fix: doc corrections + noted follow-ups; details in report §3 INFO.
- Verification: n/a (docs) / per-item notes.
