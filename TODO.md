# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-22).
- **Statuses:**
  - `OPEN` — needs work; reporter recorded it.
  - `IN PROGRESS` — owner claimed it (owner sets this).
  - `VERIFIED` — implementation + tests exist, gates run, orchestrator confirmed.
  - `DEFERRED` — acknowledged, deliberately not doing now (reason required).
  - `WON'T FIX` — decision recorded (reason required).
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

## Recently closed

### v1.2.5 SDK freeze (bbf23c8, db7a00c)
- T1-T9 VERIFIED (bbf23c8, db7a00c): SDK freeze landed — ValidateRule/ParseRuleVersion/12 bounds consts (rule.go), Registry.Seal (registry.go), APIMajor=1/APIMinor=0/CheckAPIVersion (api.go), sdk_test.go, T4 examples pack (internal/detect/examples), T5a surface_snapshot_test.go, T5b behavior_contract_test.go, T6 semantic compat (compat_test.go), T7/T8 docs.
- Review chain: APPROVE WITH NITS, all closed — NEW-6 registry readonly race (atomic.Bool + re-check under write lock, registry_race_test.go, proven failing pre-fix), degree-rule observed-set guard, variadic newRule deps, explicit version param (degree rule 1.0.1); orchestrator gates (test/vet/-race) green after each round.
- Goldens regenerable only via explicit `-update`: api_v1.golden (7216B, sha256 034f292a; de-overpinned in db7a00c) + api_v1_report.golden (13,853B). Incident: rule.go briefly restored from HEAD during a drift demo — restore byte-exact verified (sha256 0b6829a6).
- Docs-compaction wave (L4/L5/L3): AGENTS.md diet, TODO.md closed-section compaction, ROADMAP.md v0.x collapse — orchestrator-verified, reviewer APPROVE (2 INFOs fixed), gates green; kept UNCOMMITTED by maintainer decision (agent-workflow docs, not project code). Follow-ups in the same uncommitted docs set: (a) v1.8 Universal Asset Ingestion Framework milestone (ROADMAP.md, user-specified, orchestrator-written); (b) Phase Ownership Policy — AGENTS.md §5 rewritten (Primary/Infrastructure/Refactor/Future Feature classification; "modify any subsystem if strictly required, never implement the future milestone's user-facing functionality") + ROADMAP rules & phase-review checklist bullets (user-specified, orchestrator-written). Reviewer sign-off pending on (a)+(b) with the next review round.

### TODO board sweep (0865b66)
- M-1 (tests) — VERIFIED: rawResponder e2e spoof regressions (hostile `tls:fake` status line + no-colon header-line abort) classify ProbeFailed/ReasonOther on the REAL transport; spoof string asserted in surfaced error (fails pre-fix by construction).
- M-2 (tests) — VERIFIED: probeKey domain pinning — key inequality across declared domains, equality for identical inputs, exact-shape pin, and a broader-scope run re-executes instead of being served the narrow record.
- NEW-1 (LOW) — VERIFIED: decodeStoredURL refuses any stored URL asset whose Original is non-empty and non-canonical (parseable + unparseable credential-bearing forms; canonical-form refusal corner); regression rows + end-to-end self-heal subtest.
- NF-1 (INFO) — WON'T FIX: `admin/openapi.yaml` never existed (no dir, no git history, not gitignored); repo-wide `0.5.0` grep already clean — stale entry.
- NF-2 (INFO) — VERIFIED: techintel/doc.go cache section now lists operation, identity, SchemaVersion, db_digest, and the sources bitmask, matching techKey (record.go:26-36) — fixed in the audit changeset itself.
- NF-3 (INFO) — VERIFIED: MaxHeaderBytes comment (run.go:36-43) documents the strict-exceed abort and exact-equality isHeaderCapAbort classification (never substring). Left open by design: NEW-3 (DEFERRED), NEW-4 (OPEN) — see Open items.

### v1.0 audit changeset (0865b66)
- H-1..L-21 — all 14 findings closed (0865b66), senior review APPROVE with 12/14 fully closed + failing-on-pre-fix regressions: H-1 credential echo (sanitizeLocation both raw-echo branches; observe.go Location redaction); H-2 outcome-vocabulary amendment (AGENTS §0 item 6, verified against techintel/urlintel sticky flag chains end-to-end); M-1 typed TLS classification (tlsHandshakeError sentinel at DialTLSContext, tls.RecordHeaderError, exact-equality header-cap abort, no text fallback — code-verified at commit, regression tests landed later in the sweep above); M-2 probeKey declared-domain pinning (code-verified, tests in sweep); M-3 urlintel userinfo redacted at single ingest construction point; M-4 secrentel redactedCandidateID at all four rejection sites; M-5 jsintel content binding (AnalyzedHash cross-validated, stale never served, silent self-heal); M-6 jsintel redirects — non-http(s) targets observed-not-followed; M-7 detect fingerprints full field coverage + provenance, SchemaVersion 2, old records self-invalidate; M-8 techintel NaN rejected at load and decode, neutralized in deriveConfidence; M-9 techintel fingerprint-DB content digest in cache keys (computed once per run); L-10 report zero-byte render parts rejected + self-heal; L-11 mdEscape doubles backslashes before pipes; L-20 version 1.0.0 + UA bump; L-21 CI pinned to go.mod; README/ARCHITECTURE/AGENTS synced.
- NEW-12 (MED) — VERIFIED + CLOSED: T9 sync (ROADMAP ticks + status, README SDK paragraph, AGENTS §2 footnote), final-review NITs (golden de-overpinned, ROADMAP table row, schema-bump carve-out), full-milestone reviewer sign-off APPROVE WITH NITS, committed (bbf23c8, db7a00c); ROADMAP v1.2.5 flipped to ✅ Complete at docs-wave close.

## Open items

### NEW-13 (HIGH) — v1.3 End-to-end pipeline: `ravenrecon scan` (internal/pipeline)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20): v1.3 complete —
  T6 CLI+docs VERIFIED — review APPROVE WITH NITS (FIND-1 LOW +
  FIND-2..8 INFO all closed in a fix round, closure re-verified APPROVE,
  gates re-run), committed 382e218; ROADMAP v1.3 flipped ✅ Complete;
  this entry CLOSED by the orchestrator (the milestone owns it; all
  sub-milestones T1..T6 are VERIFIED above)
- History: T1/T2a/T2b VERIFIED; T2c VERIFIED — review APPROVE
  WITH NITS, all nits closed + gates re-run; T2d VERIFIED — re-review
  APPROVE WITH NITS, all findings closed, gates re-run; T3a stage events
  VERIFIED — review APPROVE (7/7 findings closed, gates re-run), committed
  ad791c3; T3b results channel VERIFIED — review APPROVE WITH NITS
  (FIND-1 LOW + 3 INFO closed in a nit round, gates re-run), committed
  this session; T3c document channel + secrentel adapter VERIFIED —
  review APPROVE WITH NITS (FIND-1 MEDIUM docs + 4 INFO closed across two
  fix rounds, closure verified, gates re-run), committed 9da5793; T3d
  adapters results production/consumption VERIFIED — review APPROVE WITH
  NITS (FIND-1..4 LOW/INFO doc fixes closed in a fix round, closure
  re-verified, gates re-run), committed 9abe2d3; T4 determinism VERIFIED —
  review APPROVE WITH NITS (FIND-1..4 closed in a nit round, closure
  re-verified, gates re-run), committed with this board pass; T5 hermetic
  E2E VERIFIED — review APPROVE WITH NITS (FIND-1 closed in a fix round,
  closure re-verified, gates re-run; NEW-3 board header restored),
  committed with this board pass; T6 CLI+docs IMPLEMENTED — see the T6
  record + fix-round record below)
  (Note: the tail of the History paragraph retains the pre-closure
  wording "T6 CLI+docs IMPLEMENTED" as written at the time; the closure
  state is the Status line above.)
- Reporter: master
- Owner: builder (per-task dispatches)
- Problem: ten library engines exist but nothing composes them; v1.3
  (ROADMAP) requires one deterministic workflow discover→dns→httpprobe→
  urlintel→techintel→jsintel→secrentel→priority→detect→report with
  shared runtime/cache/asset-graph, pipeline-level error handling, and
  hermetic E2E tests (success/partial-failure/retry).
- Fix (locked decisions D1-D5): internal/pipeline package; empty-registry
  detect stage by default (no rules ship with the framework); Level-2
  detect freeze deferred (pipeline consumes Report fields only); techintel
  observations header/TLS/DNS-only (no bodies — documented limitation);
  secrentel offline queue surfaced as count, never executed; scan CLI in
  T9.
- T1 skeleton (config/stage/run/scope + 25 tests): landed; review round 1
  APPROVE WITH NITS (1 MEDIUM + 2 LOW + 4 INFO) — all fixed; re-review
  APPROVE WITH NITS (3 INFO). Gates green after both rounds
  (gofmt/test/vet/-race/build/full-suite; my own verification re-run).
  Runner semantics pinned: stage contract w/ truncation discipline
  (completed+Truncated+empty flags → incomplete), fold precedence table
  (25 pairs), panic isolation incl. Name(), pre-cancelled+empty →
  cancelled, cancelled+ctx-error stays cancelled, Burst:0 default
  semantics, StageParams seam (validated, never aliased).
- T1 INFOs folded into T2 dispatch (non-blocking, do not lose):
  (1) pin OutcomeFailed + ctx.Err() still folds failed — one subtest in
  TestRunStageContractViolations; (2) rephrase resolution-failure message
  when a provided stage's Name() panicked ("could not resolve: no matching
  stage provided (note: a provided stage's Name() panicked)") — run.go
  ~116-135; (3) cosmetic StageInput field naming (Config vs Bounds) —
  accepted as-is, no churn.
- Status per task: T1 done (above) · T2a corpus propagation DONE —
  runner merge (first-seen dedup by asset.Identity, deterministic order,
  defensive copy), per-stage MaxCorpusSize cap at merge (hosts-first
  tail-drop; cut entries stay first-seen, cannot re-enter — documented),
  corpus_capped sticky flag + Truncated (AGENTS §0.6 carve-out), RunReport
  final corpus + StickyFlags, failed-stage additions retained (honest
  output), INFO-1 (failed+ctx.Err stays failed) + INFO-2 (resolution
  message) pinned; review APPROVE WITH NITS (LOW-1 semantics documented,
  LOW-2 pinned ×4 subtests, INFO-3/4/5 documented); gates green incl.
  full suite. Implemented by master orchestrator (builder unavailable —
  stuck at thinking; user override) · T2b httpprobe adapter DONE (this
  session): internal/pipeline/adapt/httpprobe.go + httpprobe_test.go (13
  tests: alive additions, out-of-domain input filtered pre-engine,
  out-of-domain URL-host output filter, all-failed, mixed-partial,
  pre-cancelled + in-flight cancellation, cache pass-through via FS cache
  zero-request second run, empty-filtered short-circuit ± cancelled ctx,
  request_timeout parsing table + e2e 50 ms deadline, header-cap truncation
  flag); mapping Status{Completed,Incomplete,Failed,Cancelled} →
  pipeline{completed,partial,failed,cancelled}, truncation →
  Truncated+StickyFlags["probe_truncated"], params: request_timeout only
  (invalid/absent/≤0 → 0 = engine 10 s default), ips=nil per doc.go v1.3
  note; gates green (gofmt/test/vet/-race/build + full suite). T2b
  discovery adapter DONE (this session): internal/pipeline/adapt/
  discovery.go + discovery_test.go (13 tests: name, happy path w/ clock
  bridge + counts, out-of-domain output filtered via FilterHosts, sources
  param parsing table (absent/empty/comma-only/selection/whitespace/
  unknown-params), truncation flag → Truncated+StickyFlags["truncated"]
  (engine's documented Truncated marker), partial-without-truncation,
  engine error → failed + wrapped "stage %s: %w", per-source failure fold
  → partial, skipped (tool MISSING) → incomplete (no pipeline "skipped"
  value; documented), pre-cancelled + in-flight cancellation →
  cancelled+ctx err, cache pass-through (puts counted; assetfinder never
  cached), full pipeline.Run integration); config-from-StageInput only,
  clock bridge Now=in.Clock.Now, bounds pass-through per engine semantics;
  test identifiers discovery* prefixed; gates green (gofmt/test/vet/
  -race/build + full suite). T2b dns adapter in progress by its builder
  (file present in internal/pipeline/adapt/ — a transient helper-name
  collision between the three concurrent test files was resolved) · T2b
  REVIEW-FIX ROUND 1 (this session): applied the T2b CHANGES-REQUIRED
  findings across all three adapters (dns/httpprobe/discovery) — MEDIUM-1
  outcome-mapping unification: per-host fold is now cancelled > failed&&
  !completed > completed > partial in both dns.go and httpprobe.go
  (engine-incomplete folds into partial; adapters never emit incomplete;
  dns truncation test + httpprobe fold-corner test updated/pinned),
  LOW-1 httpprobe empty-filtered short-circuit gated on targetCanonical
  (non-canonical target falls through to the engine's scope error; mirror
  subtest added), LOW-2 discovery error-path additions preserved
  (discoveryAdditions helper on success + both error branches; ~17 s
  forced-pool-shutdown regression test added), LOW-3 sticky flag renamed
  "truncated" → "discovery_truncated" (literal pinned in test; naming
  convention documented in adapt/doc.go), INFO-1 discovery cancellation
  now joins ctx.Err()+engine error (isContextError traverses the join;
  mirrors httpprobe), INFO-2 unified mapping table + fold precedence
pinned in adapt/doc.go; gates green (gofmt/test/vet/-race/build +
   full suite) · T2b RE-REVIEW (master): APPROVE WITH NITS — all six
   CHANGES-REQUIRED findings verified fixed (mapping table matches code,
   incomplete reserved to discovery OutSkipped, fold reorder equivalent
   across inputs w/ corner pinned, 17 s drain test justified); INFO
   (testing.Short() gate on the 17 s test) applied by orchestrator;
   full + race suites green after gate (17.1 s / 18.1 s) · T2c
   adapters batch 2: urlintel + techintel + jsintel (SECRENTEL DEFERRED
   to T3 — the corpus carries no document content, its engine consumes
   DocumentSource; a no-op stage would violate the no-placeholder rule;
   rationale in adapt/doc.go) · T2d adapters
   batch 3 (priority/detect/report) · T3a stage events DONE (this
   session: kind+payload+validate, ScanConfig.Observer seam, synchronous
   in-order started/finished on every path incl. pre-cancelled, panic-
   contained emission, 7 pipeline tests + event table rows, gates green;
   see the T3a record below — committed ad791c3) · T3b results channel
   DONE (this session: 16-channel Results struct, StageInput/StageResult/
   RunReport plumbing, first-seen identity-keyed per-channel dedup,
   MaxOutput per-channel caps + <channel>_truncated sticky flags, 20
   tests; see the T3b record below) · T3c secrentel
   adapter · T3d adapter results production/consumption · T4 determinism
   (discovery clock seam) · T5 hermetic E2E · T6 CLI+docs.
- SESSION-LOSS AUDIT (2026-08-19, NEW OS — previous machine wiped; all prior
  local gate evidence gone; re-verified fresh with Go 1.26.6):
  - Repo state = origin/main @ ec4b7e7 "T2C midwork" (working tree clean).
    That ONE snapshot commit bundles ALL of internal/pipeline (T1 skeleton +
    T2a corpus + T2b adapters + T2c adapters) AND the previously-uncommitted
    docs-compaction wave (AGENTS.md diet, TODO.md compaction, ROADMAP.md
    v0.x collapse) — a mixed snapshot, not a conventional commit.
  - T2c was SAVED MID-EDIT. Present: urlintel.go + urlintel_test.go (668
    lines, 19 tests), jsintel.go + jsintel_test.go (43 tests), techintel.go
    (346 lines, complete). Gaps: (1) urlintel_test.go:222 one-char syntax
    typo — `error}{` must be `error) {` — the adapt package does NOT
    compile (gofmt/vet/test all fail on it; cascade errors at 223-226, 427);
    (2) techintel_test.go MISSING — the techintel adapter has ZERO test
    coverage; (3) techintel.go not gofmt-clean (comment-block indent at
    lines 140-144 + missing trailing newline); (4) no T2c review round was
    recorded. TODO board was not updated for T2c (still said "T2 next").
  - FRESH GATE RUN (this machine, workspace as-committed): go build ./...
    OK; gofmt/vet/test fail ONLY on the urlintel_test.go typo. On a /tmp
    copy with the typo fixed + gofmt -w: gofmt clean, vet clean, FULL
    suite passes (all 22 packages), go test -race ./internal/pipeline/...
    passes (adapt 18.3s incl. the 17s drain test). Test inventory on the
    copy: discovery 24 / dns 16 / httpprobe 17 / urlintel 19 / jsintel 43
    (= 119 tests; techintel 0). T1/T2a/T2b code + all T2c adapter code is
    therefore SOUND — only the three gaps above block green.
  - ROADMAP.md v1.3 is stale: "Status: planned", zero ticks, despite
    T1/T2a/T2b/T2c code landed. Also the v1.8 milestone + §5 Phase
    Ownership Policy (added in the docs wave) are now committed (they were
    previously deliberately uncommitted — flag if that was unintended).
  - NEXT ACTIONS: builder fixes the typo (one char), writes
    techintel_test.go (mirror the discovery/urlintel test shape; adapter
    documents its contract exhaustively — unit tests must cover the fold
    table, truncation flags, malformed-vs-failed counting, cancellation
    joins, non-canonical target fall-through, empty short-circuit), gofmt
    -w techintel.go; tester runs gates; reviewer round for T2c; then T2d.
  - T2c IMPLEMENTED (this session, master override — builder agent
    unavailable again, 2 failed dispatches; precedent: T2a): typo fixed
    (urlintel_test.go:222 `error}{`→`error) {`), techintel.go gofmt-clean,
    internal/pipeline/adapt/techintel_test.go added (15 tests: Name, happy
    path w/ cache-before-execute proof, production-DB default, out-of-
    domain input filter, empty short-circuit, non-canonical target fall-
    through, malformed observation → failed + ItemsFailed + diagnostic
    surfaced, engine config error → failed, cache-diagnostic surfaced,
    pre-cancelled → cancelled + res.Err=ctx err (Go error nil — adapter
    convention), engine error + fired ctx → cancelled + errors.Join,
    nil cache, truncation/overflow mapping table w/ literal flag pin,
    foldTechOutcome table (9 rows), counters table (6 rows)). Gates run on
    this machine: gofmt clean, build OK, vet OK, full suite OK, -race
    ./internal/pipeline/... OK (18.3s). T2c REVIEW (this session):
    reviewer APPROVE WITH NITS (2 LOW + 3 INFO + 1 accepted INFO). ALL
    closed: LOW-1 doc clarification added (techintel.go Run malformed
    paragraph — stage-level failed via the error path vs fold-level
    never-folded, both pinned); LOW-2 nil-ctx guard added mirroring
    urlintel.go:203 (Run returns failed + "stage techintel: context must
    not be nil") + regression TestTechIntelStageNilContext; INFO-3/4
    test-comment fixes; INFO-5 status line updated; INFO-6 warm cache-hit
    path accepted as engine-tested, not hermetically forceable through
    the stage. Gates re-run after nits: gofmt clean, build OK, vet OK,
    full suite OK, -race ./internal/pipeline/... OK (18.3s). T2c
    VERIFIED — next: T2d adapters batch 3 (priority/detect/report).
  - T2d IMPLEMENTED (this session, master override — builder agent
    unavailable a 3rd time, 2 more failed dispatches): internal/pipeline/
    adapt/priority.go + detect.go + report.go + priority_test.go +
    detect_test.go + report_test.go + doc.go T2d conventions section.
    Verified engine facts driving the design: priority/detect/report
    engines ALL fold internally into the house outcome vocabulary
    (completed/incomplete/failed/cancelled) → adapters map their aggregate
    outcome directly (incomplete → partial; unknown value → failed, never
    masked); priority rejects a nil signal channel (fully-buffered
    synchronous channel, no feeder goroutine) and digests BOTH catalogs
    (single provided seam catalog → explicit empty counterpart);
    detect's empty-registry run is vacuous completed (D2) and rules without
    RequiredAssetTypes genuinely execute on an empty corpus → empty-input
    short-circuit fires ONLY when corpus AND registry are both empty;
    report's engine DEFAULTS zero Concurrency/QueueSize/Timeout (its
    config-error routes are empty OutputDir and negative Timeout) and has
    no Rate/Burst (documented); report render-cache does exactly 1 Get + 1
    Put per reporter (pinned 4/4). Truncation: detect FindingsTruncated →
    Truncated + StickyFlags["detect_findings_truncated"]; priority and
    report have NO truncation signals — absence pinned in doc.go.
    Counters: processed = completed+failed+cancelled (skipped rules/
    reports EXCLUDED — never attempted), failed = failed. Tests: priority
    14 (name, happy path w/ cache-before-execute 4 Gets+4 Puts + no
    additions, empty short-circuit w/ 0 cache interaction, non-canonical
    fall-through, out-of-domain filter, engine config error via zero
    bounds, pre-cancelled, engine error + fired ctx joined, nil-ctx,
    nil-cache, production-catalogs nil/nil seam, single-catalog seam,
    fold table 5 rows, counters), detect 16 (name, empty-registry
    short-circuit, D2 default happy path w/ zero counters, rule happy path
    w/ cache-before-execute 1/1, empty-corpus-with-rules NO-short-circuit
    (unconstrained rule executes, required-kind rule skips), out-of-domain
    filter via asset-capture rule, non-canonical fall-through executes
    rules, engine config error, pre-cancelled, engine error + fired ctx
    joined, nil-ctx, nil-cache, fold table 5 rows, counters +
    truncation-flag mapping ×2), report 13 (name, default-registry happy
    path w/ 4 rendered+committed files + 4 Gets/Puts + no additions,
    empty-corpus still renders, context composition via capture reporter
    (target/bracket/filtered corpus), empty OutputDir → failed, negative
    Timeout → failed, pre-cancelled, engine error + fired ctx joined,
    nil-ctx, nil-cache, synthetic single-reporter registry + 1 committed
    file, fold table 5 rows, counters w/ skipped excluded). Gates run on
    this machine: gofmt clean, vet OK, build OK, full suite OK (24
    packages), -race ./internal/pipeline/... OK (18.3s). T2d REVIEW
    (this session): CHANGES-REQUIRED — MEDIUM-1 gofmt gate violation
    (detect_test.go was edited after the gate; the "gofmt clean" board
    claim was false — corrected: gofmt -w re-run + all four gates re-run
    AFTER the fix, claim amended to the final state), LOW-1 test-count
    corrections (priority 14, detect 16), INFO-1 Rate-wording fixed in
    priority.go/detect.go docs (negative Rate is the engine's config-
    validation error, not "pacing disabled"), INFO-2 recorded as NEW-14
    (deferred), INFO-3 accepted (run bracket documented). All findings
    closed. GATES RE-RUN after the fixes (final state): gofmt clean
    (repo-wide, `gofmt -l` empty), vet OK, build OK, full suite OK (24
    packages), -race ./internal/pipeline/... OK (18.3s). Re-review
    dispatched to reviewer for closure confirmation.
- T6 CLI+docs IMPLEMENTED (this session, builder; claimed IN PROGRESS at
  session start, never self-closed): the `ravenrecon scan` command and its
  hermetic test suite. The command (internal/cli/scan.go + cli.go wiring,
  inherited mid-flight from the prior session and verified line-by-line
  against the T6 contract) parses `scan <target> [options]` with --stages
  (fixed vocabulary), --sources, --request-timeout, --concurrency,
  --timeout, --cache, --no-cache, --output (default ravenrecon-report),
  --verbose (one line per stage event on stderr via a synchronous
  stageObserver on the T3a event layer); maps flags onto
  pipeline.ScanConfig (StageParams for sources/request_timeout, StageBounds
  for every SELECTED stage); normalizes the target through asset.NewDomain
  (single normalization point — uppercase/whitespace/trailing dot
  normalized, IP literals rejected via normalizeHost); opens the cache
  mirroring discover's semantics; runs the ten production adapters via the
  newScanStages seam (all nil production defaults incl. the EMPTY detect
  registry per D2); prints a deterministic summary (no timestamps/durations
  — the T4 determinism property) with the report files listed honestly from
  the output directory; maps outcomes to exit codes (completed/partial →
  0; failed/cancelled/incomplete + validation/cache errors + Ctrl-C → 1,
  summary always printed first). NEW TESTS (internal/cli/scan_test.go, 19
  test functions, all hermetic — fake stages seam, temp dirs, no tools):
  parseScanArgs table (24 rows incl. help forms, empty/unknown stages,
  vocabulary naming, empty sources, invalid/empty/negative durations,
  concurrency < 1, stray args, default output dir, raw target preserved for
  normalization), buildScanConfig defaults + selections (selection order,
  params, bounds only for selected stages), scanCache wiring (default off,
  config-enabled, --cache override, --no-cache force-off), stageObserver
  unit (started/finished lines, truncation/error suffixes, unknown kinds
  ignored, kind-mismatched + nil payloads contained), printScanSummary
  (header/cache state, sorted flags, stage lines with flags+quoted errors,
  sorted report file listing, no-files and unreadable-dir honest notes),
  reportFiles (sorted non-dir entries, missing-dir error),
  TestScanStageVocabularyMatchesPipeline (stageVocabularyCLI pinned to
  pipeline.AllStages — the scan.go comment requires it), runScan outcome
  mapping (all five outcomes → documented exit semantics, summary always
  states the honest outcome), failed-still-summarized, validation errors
  never invoke the stages seam (incl. IP-target rejection via
  normalizeHost), target normalization through the seam (canonical Name +
  raw Original + default OutputDir), cache on/off rendering through the
  real runScan path, pre-cancelled ctx → prompt context.Canceled-wrapped
  "run interrupted" error with the cancelled summary still printed (stages
  never invoked), scan help via runScan and via the Run dispatcher. DOCS
  (T6 "docs" half): README.md Status header v1.0.0 → v1.3.0 (version.go is
  already bumped in this tree) + scan command section under "Current
  commands" + intro paragraph naming the pipeline/scan; ARCHITECTURE.md
  implemented-list bullet for the scan command (wiring, exit semantics,
  normalization, seams) + planned-item reworded ("standalone reporting CLI
  front-end" — report rendering is reachable through scan's embedded report
  stage); ROADMAP.md v1.3 checklist ticked `ravenrecon scan` (per-item tick
  precedent, evidence on the board). GATES RUN THIS SESSION, verbatim:
  gofmt -l $(find . -name '*.go' -type f) → clean (empty); go test
  -count=1 ./internal/cli/ → ok; go vet ./... → ok; go build ./... → ok;
  go test -count=1 ./... → ok (25 packages; discovery 75.6s, adapt 17.4s);
  go test -race -count=1 ./internal/cli/ → ok (1.5s). One test-only fix
  round during development: zero-value StageResult{} is a contract
  violation (empty outcome → recorded failed), so the partial-outcome row
  needed an explicit completed first result; the normalization assertion
  checked the canonical form uppercased (self-defeating — "example.com" IS
  "EXAMPLE.COM" uppercased) and now checks the raw " EXAMPLE.COM. " form
  never appears. No production code changed this session. No new issues
  opened. Remaining for T6: reviewer round, orchestrator verification, and
  the commit decision (working tree currently uncommitted).
- T6 locked-item follow-up (this session, builder): the working tree at session
  start did NOT compile — internal/cli/scan_test.go carried eight unused imports
  (fmt, io, net, net/http, sync, discovery, dns, adapt) and the head-comment-
  referenced smoke E2E (TestRunScanSmokeE2E) did not exist. Step 0 + Item 1:
  implemented TestRunScanSmokeE2E (hermetic — drives runScan with the
  PRODUCTION stage shape via the stages seam; only the exec- and network-
  capable seams substituted: scripted discovery/urlintel runner + fake
  LookupFunc + fake resolver (one A record for www.example.com) + canned
  http.RoundTripper (200 on http and https, also served to jsintel — NEW-16);
  non-exec stages at their production nil defaults incl. the empty detect
  registry + the four builtin report reporters); the previously-unused imports
  are consumed by it. Asserts: outcome line (completed), all ten completed
  stage lines, ravenrecon-report.json/.md existing AND listed in the summary,
  hermeticity (canned transport serves >= 4 round trips: 2 httpprobe + 2
  jsintel), and a second run into a fresh temp dir matching modulo the
  output-dir path. Item 2: ROADMAP.md v1.3 completed (six pipeline-integration
  bullets ticked, Status: planned → Status: ✅ Complete, completion note citing
  T3a ad791c3, T3b f31cf3a, T3c 9da5793, T3d 9abe2d3, T4 df3672d, T5 91074ff,
  T6 uncommitted at writing; acceptance state: all met). Gates final state:
  gofmt clean, go vet OK, go build OK, go test ./internal/cli/ OK, go test
  -race ./internal/cli/ OK, full per-package suite OK. No production code
  changed. No staged commit. New issue opened: NEW-16 (below).
- T6 REVIEW FIX ROUND (this session, builder): applied the reviewer's T6
  findings exactly, everything left uncommitted — FIND-1 (LOW, code+tests):
  negative `--request-timeout` rejected with "must be >= 0" instead of being
  silently absorbed to the engine default (0 and absent stay valid = engine
  default, matching requestTimeoutFromParams); parse-table rows pin `-5s`
  rejection and `0` acceptance (internal/cli/scan.go parseScanArgs +
  scan_test.go). FIND-2 (INFO, tests): unknown-source pass-through pinned as
  a REAL passthrough — `scan example.com --sources nmap` runs the production
  discovery adapter/engine over the smoke fixtures; the seam capture asserts
  StageParams[discover]["sources"] == "nmap", the discover stage records
  failed (`unknown source "nmap"` named), and two rows pin the run-level
  semantics: the full ten-stage run fail-CONTINUES (remaining stages
  complete → fold rule 5 → Outcome partial, exit 0) and the
  `--stages discover` run ends Outcome failed with the named "run outcome
  failed" error — the review finding's expected "run outcome failed" applies
  to the stage-restricted form; the full run honestly folds partial
  (TestRunScanUnknownSourcePassThrough in internal/cli/scan_test.go).
  FIND-3: ROADMAP.md v1.3 acceptance bullets
  ticked (single-run discovery→report; cross-stage asset/evidence identity —
  both met by the smoke E2E + T3d/T4/T5 pins); the "all met" completion note
  now matches the checklist. FIND-4: NEW-16 fix text reworded — techintel has
  no HTTP fetch surface at all (reviewer-verified), now "httpprobe, jsintel
  (and any future body-fetching stage)". FIND-5: scan_test.go comment now
  cites the actual rule — report.Run (engine.go:251-258) + sanitizeBaseName
  (writer.go:26-68); the cited ReportBaseName never existed. FIND-6: AGENTS.md
  §2 — internal/pipeline + internal/pipeline/adapt bullet added; the footnote
  now states the pipeline IS reachable via `ravenrecon scan` while those
  engines still have no standalone commands and the TUI is still unwired.
  FIND-7: NEW-17 opened (INFO, no owner — evidence + proposal only, below).
  FIND-8: status tail appended above — this entry NOT self-closed
  (orchestrator verifies). GATES RE-RUN THIS ROUND, verbatim: gofmt -l
  $(find . -name '*.go' -type f) → clean (empty); go test -count=1
  ./internal/cli/... → ok (0.534s); go vet ./internal/cli/ ./internal/report/
  → ok; go build ./... → ok; go test -race -count=1 ./internal/cli/ → ok
  (1.618s); go test -count=1 ./... → ok (25 packages; discovery 75.6s,
  adapt 17.5s).
- Verification: per-task gates (gofmt/test/vet/-race/build); final wave:
  full-suite gates + reviewer sign-off + TODO close.
- T3a IMPLEMENTED (this session, builder): pipeline stage events on the
  existing v1.2 event layer, exactly per orchestrator contract — no
  deviations. internal/event: KindStageStarted ("stage_started") +
  KindStageFinished ("stage_finished") after KindScanStopped in kind.go
  (+ Kind.Valid), StageStarted{Name}/StageFinished{Name,Outcome,Truncated,
  ItemsProcessed,ItemsFailed,Duration,Err} payloads + bounded
  NewStageFinished constructor (Err via the package's truncateMessage at
  the construction site), validatePayload cases (exact type, non-empty
  Name, Outcome in the fixed AGENTS §0.6 vocabulary as literal strings via
  unexported stageOutcomeValid — no internal/pipeline import, negative
  counts/duration and over-bound Err rejected mirroring TaskTerminal.
  Message). internal/pipeline: ScanConfig.Observer event.Observer field
  (nil = off, zero behavior change, matching internal/event/observer.go's
  documented convention; package-doc milestone line updated: stage
  eventing real, report rendering still separate); Run emits exactly one
  started + one finished per stage entry on ALL paths (pre-cancelled
  entries recorded cancelled, unresolvable entries recorded failed,
  normal path), synchronous, in stage order, before Run returns — no
  goroutines, no buffering; At = injected clock Now, Identity = stage
  name, Phase = "stage", Severity default, Sequence 0 (Bus assigns on
  publish — documented in the Run doc comment); finished mirrors the
  recorded StageRecord field for field (Err = recorded error text, empty
  when nil, bounded); observer.Observe wrapped in deferred-recover
  containment (copy of the runtime pool's observer-path containment — a
  hostile panicking observer can never crash the run). No changes to
  engines, Stage/StageResult/StageInput shapes, caching, or the runtime
  pool. Tests: event table rows (nil payload ×2, wrong-type via mismatch
  list, empty Name ×2, invalid/empty Outcome, negative processed/failed,
  negative Duration, over-bound Err, constructor bounding + validation)
  and internal/pipeline/run_events_test.go (7 tests: order+payload
  equality+field pins, pre-cancelled, per-stage timeout, panicking
  observer contained with later events flowing, nil observer = identical
  report, >512-byte Err truncated with marker + post-truncation Validate,
  unresolvable entry). Gates run this session, verbatim: gofmt -l clean
  (repo-wide), go test -count=1 ./internal/event/... ./internal/pipeline/...
  ok, go vet ./... ok, go build ./... ok, go test -race -count=1
  ./internal/event/... ./internal/pipeline/... ok, full suite
  go test -count=1 ./... ok (25 packages). Existing pipeline tests pass
  unmodified (nil-observer zero change). No new issues opened. Reviewer
  round pending; orchestrator moves to VERIFIED. T3b (results channel)
  observations below — none implemented.
- T3a REVIEW-FIX ROUND applied (this session, builder), per the T3a
  review findings — FIND-1 through FIND-7, nothing else:
  - FIND-1 (MEDIUM): negative ItemsProcessed/ItemsFailed were copied
    verbatim by normalizeResult (internal/pipeline/run.go:457-458
    pre-fix), which could produce a StageRecord whose mirrored
    stage_finished event fails event.ValidatePayload (negative counts
    are rejected there by design). FIX: normalizeResult now treats
    negative counters as a stage contract violation — recorded failed
    with a structured error (matching the existing violation shape for
    invalid outcomes), and counters are clamped to >= 0 on EVERY outcome
    path so a record and its emitted event always validate. Semantics
    documented in the normalizeResult doc comment (run.go), the
    StageRecord counter fields (run.go), and the StageResult counter
    fields (stage.go). Regression test: run_events_test.go
    TestRunStageEventsNegativeCounters (violation path + error-return
    clamp path), asserting the emitted finished event validates and the
    recorded/report counters are clamped.
  - FIND-2 (MEDIUM): stale Tier C docs fixed — ARCHITECTURE.md:3012
    "27 values" -> 29 values with stage lifecycle named; 3060
    Instrumentation contract and 3125 Known limitations now list the
    pipeline runner as instrumented; v0.3 boundary implemented list
    gained a "pipeline stage eventing" entry; README.md instrumented
    list + "27 typed Kind values" -> 29; internal/event/doc.go Role and
    Instrumentation-contract lists now include internal/pipeline.
  - FIND-3 (LOW): TODO.md test count corrected 8 -> 7 (the parenthetical
    already listed 7).
  - FIND-4 (LOW): run.go observeStageEvent doc comment no longer cites
    the runtime pool as the containment source (runtime/observer.go is a
    bare nil-check call with no recovery); it now describes the honest
    shape: recover in the same goroutine as the Observe call, matching
    event.deriveSafe and the pipeline's runStage recovery.
  - FIND-5 (LOW): event_test.go gained TestValidateAcceptsEveryStageOutcome
    (all five outcomes validate); run_events_test.go gained
    TestStageFinishedVocabulariesDriftPin mapping every pipeline.Outcome
    constant through the event payload.
  - FIND-6 (INFO): config.go ScanConfig group doc now states Observer —
    unlike Cache and Clock — is operative in config (nil = off).
  - FIND-7 (INFO): run_events_test.go gained
    TestRunStageEventsCrossRunDeterminism (same cfg/clock/stages run
    twice, recorded event streams DeepEqual).
  Status: still IN PROGRESS — fixes applied, gates re-run below;
  orchestrator verifies and closes (never self-closed).
- T3b IMPLEMENTED (this session, builder): pipeline results channel,
  exactly per orchestrator contract — no deviations. New
  internal/pipeline/results.go: the 16-channel Results struct (asset.IP/
  Port/Service/Endpoint/JavaScript/Parameter/Technology/SecretCandidate/
  Evidence/Finding/TLSCertificate/SourceMap/Relationship + priority.
  SurfaceAsset/Group/AttackPath — one channel per report.Context data
  channel; imports asset+priority only, types only), field doc comments
  name the T3d adapters as the producers (none wired yet), plus
  mergeResults/mergeChannel (the runner-side merge). StageResult.Results
  (additions semantics + AGENTS §0.6 truncation rule doc), StageInput.
  Results (read-only merged PRIOR state, identical contract to the corpus
  slices), RunReport.Results (final merged state, doc mirroring the
  corpus fields). Run merges each stage's Results after its StageRecord
  is finalized — the same place as the corpus merge — unconditionally
  (a failed/partial stage's retained results still merge, mirroring
  Additions; documented in run.go), first-seen dedup keyed by canonical
  identity PER CHANNEL (asset Identity() "kind:value" string; Relationship.
  ID() — the type has no Identity() method, ID() is its documented
  canonical identity (asset/relationship.go:118); priority SurfaceAsset.
  Identity / Group.Anchor / AttackPath.Root fields), keys namespaced per
  channel in the shared seen map so identical identities carried by
  different channels never collide (pinned by test), deterministic
  first-seen order, then the per-channel MaxOutput cap (eff.MaxOutput
  per stage; smaller later caps re-cut, cut entries stay first-seen and
  cannot re-enter — corpus-mirrored), returning the fixed-order list of
  cut channel names → report.StickyFlags["<channel>_truncated"] +
  report.Truncated (AGENTS §0.6 carve-out, mirroring corpus_capped; the
  stage's own outcome untouched). Flag vocabulary: ips, ports, services,
  endpoints, javascript, parameters, technologies, secrets, evidence,
  findings, tls_certificates, source_maps, relationships, surfaces,
  groups, attack_paths. No event emission changes (T3a's emit point
  stays), no normalizeResult changes (Results are not counters), no
  engine/asset/priority/event changes, no Results JSON/caching story.
  Tests: internal/pipeline/results_test.go (18 tests — first-seen dedup
  across stages incl. reverse-edge relationship distinctness, kind-
  namespace no-collision, per-channel dedup namespacing, nil/empty
  additions legal, single+multi-channel caps with flag vocabulary +
  outcome-untouched carve-out, fixed capped-name order, negative-cap
  defensive branch, visibility-at-stage-turn (prior merged state only,
  own additions excluded), RunReport.Results final merged, failed-stage
  results still merged, pre-cancelled empty/no-flags, cross-run
  determinism incl. Results+StickyFlags, cap permanence + smaller-later-
  cap re-cut, defensive copy (no aliasing), corpus+results caps combined,
  all-16-channels unit merge, no-flag-without-cut, stage-not-run-no-
  merge). One leftover fixed in the inherited working tree: the
  mergeChannel unit call in results_test.go was missing the namespace
  argument (build failure). Gates run this session, verbatim: gofmt -l
  clean (repo-wide), go test -count=1 ./internal/pipeline/... ok, go vet
  ./... ok, go build ./... ok, go test -race -count=1
  ./internal/pipeline/... ok, full suite go test -count=1 ./... ok (26
  packages — 20 top-level test functions in results_test.go after the
  nit round). Existing pipeline tests pass unmodified (nil-observer zero
  change). New issue opened: NEW-15 (INFO, T3c document-content gap).
  REVIEW: APPROVE WITH NITS — FIND-1 (LOW) full 16-name flag vocabulary
  pinned by TestMergeResultsFullVocabularyPinned (unit capped-name list
  DeepEqual + runner-level all-16 StickyFlags; typo-failure demonstrated,
  reverted); FIND-4 (INFO) NEW-15 pointers added to adapt/doc.go +
  ARCHITECTURE.md (secrentel document-carrier reads as undecided, not
  settled); FIND-7 (INFO) results.go empty-additions doc reworded (cap
  may re-slice). All 3 closed, closure verified (reviewer), gates re-run.
  FIND-2 carried to T3d: Groups/AttackPaths dedup keys (Anchor/Root) are
  GROUPING keys, not full identities — two distinct groups anchored
  identically collapse silently to first-seen; today's only producer
  (single priority stage, engine-guaranteed unique anchors) cannot hit
  it, but T3d must document "first-seen group per anchor wins" on
  Results.Groups/AttackPaths or widen the key (anchor + members +
  score). FIND-5/FIND-6 accepted as documented semantics (outer-slice
  defensive copy only, same as corpus; per-run seen map grows with total
  distinct identities, same as corpus). Orchestrator moved T3b to
  VERIFIED.
- T3b OBSERVATIONS (no implementation): (1) the stage_started/finished
  events are emitted from the stage LOOP, which is also where T3b's
  per-stage results aggregation will live (run.go:154-235) — the finished
  payload's counters come straight from the finalized StageRecord, so
  whatever T3b adds to StageRecord (e.g. a Results field) will need an
  explicit decision on whether/how it surfaces in stage_finished or stays
  report-only; the current event carries no results, and the contract's
  out-of-scope list treats RunReport.Results as future. (2) The Observer
  seam is config-carried (ScanConfig.Observer), synchronous and inline —
  a results channel would be a NEW seam (config field + delivery), not a
  variant of this one; nothing here constrains that design. (3) Emission
  happens before the corpus merge (finished is emitted right after the
  StageRecord is appended), so if T3b results are derived from the merged
  corpus the emit point may need to move after the merge — flagged now so
  the orchestrator can decide placement deliberately. (4) The stage_finished
   Err field is bounded to 512 bytes and validated; any future results
   payloads added to events must respect the same per-payload bounds in
   validatePayload (hand-built hostile events re-validated by consumers).
- T3b RESOLUTION of the above (this session): (1) StageResult.Results and
  RunReport.Results landed; stage_finished events deliberately carry NO
  results — the contract's out-of-scope list forbids event emission
  changes, and the finished payload stays a mirror of the StageRecord.
  (2) No new delivery seam was needed: the results channel is
  runner-internal struct plumbing (StageInput/StageResult/RunReport), not
  an observer-style channel. (3) The results merge runs AFTER
  emitStageFinished and BEFORE the next stage — placement documented in
  run.go; the finished event therefore never reflects the merged results
  (by design, per (1)). (4) No results payloads were added to events.
- T3c IMPLEMENTED (this session, builder): pipeline-internal document
  channel + secrentel adapter, exactly per orchestrator contract — no
  deviations. New internal/pipeline/document.go: `MaxDocumentBytes` =
  2 << 20 (2 MiB, mirroring the secrentel engine's ingest cap) and the
  `Document{Identity, URL, Content, Truncated}` type (content bounded,
  merged by reference, never copied; never reaches the report Context),
  plus `mergeDocuments` — the runner-side document merge reusing
  mergeChannel with the "documents" namespace and the canonical identity
  string as the dedup key, per-stage MaxOutput cap with the
  "documents" cut-name, and a defensive hostile-producer re-bound BEFORE
  dedup: over-cap content is dropped WHOLE (Content nil + Truncated),
  never a partial prefix, the caller's slice never mutated (a fresh
  normalized copy is built only when a document needs the cut), and the
  document still merges (identity/URL remain). StageResult.Documents
  (additions semantics, mirroring Results), StageInput.Documents (read-only
  merged PRIOR state, identical contract to the corpus/results slices),
  RunReport.Documents (final merged state). Run merges each stage's
  Documents in the same block as the results merge, unconditionally
  (failed-stage documents still merge), and records the
  `documents_truncated` sticky flag + report.Truncated on a cut (AGENTS
  §0.6 carve-out; stage outcome untouched). New
  internal/pipeline/adapt/secrentel.go: `NewSecretIntelStage(db
  *patterns.DB)` (constructor test seam; nil = patterns.Load), consuming
  the document channel as its document source — every pipeline document
  becomes one secrentel.Document (KindJS, Content/URL passed through,
  SourceAsset = the pipeline document's canonical Identity — the engine's
  jsintel dedup contract — Source "" = the engine default "secrentel"),
  truncated/nil-content documents SKIPPED (nothing honest to scan; not
  counted), no scope filtering (the channel is the pipeline's own,
  in-scope by construction), per-document analysis caps at engine defaults
  (64 candidates / 8 evidence — deliberately not configurable), the
  engine's Overflow signal (≥ 64 candidates) mapped to Truncated +
  StickyFlags["secrentel_overflow"] and the engine's Truncated signal to
  StickyFlags["secrentel_truncated"] (unreachable through this adapter —
  bounded pipeline content + truncated documents skipped — but never
  swallowed), counters mirroring techintel exactly (ItemsProcessed =
  Completed+Incomplete+Cancelled+Failed; ItemsFailed = Failed+Malformed),
  outcome fold in the unified adapter precedence (cancelled > failed&&
  !completed > incomplete&&!completed > completed-vacuous > completed-
  mixed > unknown→failed), engine errors wrapped "stage %s: %w" with the
  errors.Join cancellation path, empty-input short-circuit gated on
  targetCanonical (non-canonical falls through to the engine with an
  empty source), nil-ctx guard first, no event emission (the runner owns
  stage events; Config.Emit deliberately ignored), queue never executed
  and never propagated (T6). §0.6 chain verification performed for the
  completed+flag carve-out: engine record write (engine.go:376 +
  record.go:89-90; truncated → StatusIncomplete record.go:130-132),
  replay (record.go:359-360; truncated records never served —
  record.go:172, 198-202 — so only Overflow replays from hits), sticky
  merge (report.go:243-244), report exposure (report.go:377-378) — chain
  INTACT. Tests: internal/pipeline/document_test.go (merge unit tests —
  first-seen dedup, cap tail-drop + ["documents"] cut-name, cut
  permanence across larger later caps, smaller-later-cap re-cut,
  over-cap content dropped whole with input never mutated, in-bound
  content merged by reference, nil/empty/truncated-document edges — plus
  run-level: propagation + visibility at stage turn, cap + flag +
  outcome-untouched carve-out, failed-stage documents still merged,
  pre-cancelled empty/no-flags, cross-run determinism incl. Documents,
  no aliasing) and internal/pipeline/adapt/secrentel_test.go (13 tests:
  name, happy path with counters + source-asset identity + evidence, skip
  truncated/nil-content, empty short-circuit with zero cache reads,
  non-canonical fall-through, nil-ctx, engine config error → failed,
  pre-cancelled → cancelled + ctx err, engine error + fired ctx →
  errors.Join cancelled, overflow flags with exactly the capped 64
  candidates, overflow cache-hit regression over a real FS cache
  (2nd run: zero Puts, flags replayed — never swallowed), fold table all
  rows incl. unknown→failed and malformed-only vacuous, full
  pipeline.Run integration with a jsDocProducer fake (RunReport.Documents
  + Results.Secrets + cross-run determinism)). Docs: adapt/doc.go gained
  the T3c conventions section (document channel semantics, secrentel
  mapping, flag vocabulary, chain reference; T3b section updated —
  secrentel is the first Results producer); ARCHITECTURE.md v0.3 boundary
  gained the "pipeline document channel + secrentel adapter" bullet and
  the results-channel bullet's planned list now names only the remaining
  T3d production (NEW-15 resolved); README.md: no changes needed
  (verified — no line becomes false). NEW-15 → RESOLVED above. Existing
  pipeline tests pass unmodified. Gates run this session, verbatim:
  gofmt -l clean (repo-wide), go test -count=1 ./internal/pipeline/... ok
  (pipeline 0.159s, adapt 17.273s), go vet ./... ok, go build ./... ok,
  go test -race -count=1 ./internal/pipeline/... (see Results below),
  full suite go test -count=1 ./... (see Results below).

- T3d1 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the jsintel engine content-retention surface +
  the jsintel adapter results/documents production, exactly per the
  orchestrator contract — no deviations. Engine (internal/jsintel):
  Config.RetainContent (default false — flag off is byte-identical to
  today's memory profile, all pre-existing jsintel tests pass unmodified)
  retains each entry's fully-retained body on JSEntry.Content (bounded by
  MaxJSBytes, set before every classify return path incl. the cache-hit
  path, whose js.fetch record restores byte-identical content); truncated
  fetches retain NOTHING (FetchResult.Content nil by contract — never a
  partial prefix); new exported RetainedContent{URL asset.URL, Content
  []byte} + Report.RetainedContent() (canonical-URL order, one per URL —
  the report's sorted one-entry-per-URL invariant — non-nil Content only,
  empty when the flag is off); mergeEntries first-seen-wins for Content
  (mirrors the JS asset rule); Accumulator memory doc updated to state the
  optional retention. Adapter (internal/pipeline/adapt/jsintel.go):
  RetainContent always enabled; StageResult.Results populated with
  AllJavaScript/AllSourceMaps/AllRelationships (copied, never rebuilt) +
  Endpoints/Secrets/Technologies/Evidence derived from the sorted entries,
  deduped by canonical identity + sorted (dedupeByIdentity); entry.URLs
  external observations NOT propagated (no Results URL channel — documented
  on jsResults); StageResult.Documents from RetainedContent 1:1, identity =
  the canonical JavaScript asset identity (asset.Identity{KindJavaScript,
  URL string} — exactly asset.JavaScript.Identity()), URL pointer, Content
  by reference, Truncated always false; outcome fold/counters/truncation
  unchanged (T2c semantics). Tests: engine — retention off/on, non-JS
  completed positive retained, truncated never retains a prefix, cache-hit
  restores byte-identical content, merge first-seen-wins; adapter — full
  7-channel results + 3-document production from a loopback synthetic run
  (incl. import-expansion fetch of the resolved shared.js), by-reference
  content pin (same backing array), truncated fetch → no document + flag,
  cache-hit run retains documents + DeepEqual results/documents, cross-run
  determinism (DeepEqual incl. Documents), never-rebuilt pin against a
  direct engine run under the adapter's exact config.
- T3d1 SECOND PASS (this session, builder — the first dispatch was
  cancelled mid-flight; the working tree was verified line-by-line against
  the contract instead of redone): every contract item above verified in
  the tree (engine classify/merge/cache-restore/truncate-nil paths,
  adapter jsResults/jsDocuments identity + by-reference + Truncated=false,
  doc.go retention section, Accumulator memory doc, TODO record). Two
  finishing changes: (1) Report.RetainedContent() now deduplicates by URL
  identity and sorts internally — mirroring the report's other merged
  accessors (AllJavaScript/AllSourceMaps/AllRelationships), which do NOT
  rely on the entries' invariants; real reports are unaffected (one sorted
  entry per URL), a hand-built report is normalized the same way; new
  engine test TestReportRetainedContentSortedDedupedNilSkipped pins it.
  (2) buildJSResult doc comment corrected: it runs on the success +
  cancelled-in-flight paths; the engine-error branches return early with a
  bare failed/cancelled StageResult (T2c behavior, unchanged — pinned by
  the pre-existing engine-error tests).
- T3d1 GATE RECORD (this session, verbatim): gofmt -l $(find . -name
  '*.go' -type f) → clean (empty). go test -count=1 ./internal/jsintel/...
  ./internal/pipeline/... → jsintel, jsintel/adapt, pipeline ok; adapt
  FAILS ONLY on the pre-existing TestHTTPProbeStageResultsChannel (other
  unit's in-flight work, below) — all 43 pre-existing jsintel adapter
  tests + 5 new T3d1 tests pass. go vet ./... → ok. go build ./... → ok.
  go test -race -count=1 ./internal/jsintel/... ./internal/pipeline/...
  → same single pre-existing httpprobe failure; no races elsewhere. Full
  suite go test -count=1 ./... → same single failure. T3d1's own scope is
  fully green; the httpprobe failure blocks the shared pipeline gates
  until the httpprobe unit reconciles it (recorded below).
- T3d1 GATE RECORD (second pass, this session, verbatim): gofmt -l
  $(find . -name '*.go' -type f) → clean. go test -count=1
  ./internal/jsintel/... ./internal/pipeline/... → jsintel ok, jsintel/
  adapt ok, pipeline ok, adapt FAILS ONLY on the same pre-existing
  TestHTTPProbeStageResultsChannel (httpprobe_test.go:331: services
  identity "443/tcp/https" vs expected "443/https" — the httpprobe engine
  at HEAD builds ports with Protocol "tcp" (observe.go:581-588, untouched
  in this tree) and the out-of-scope T3d2 adapter test expects the
  protocol-less form; internal to the httpprobe unit's own files, T3d1
  never touches them). All 43 pre-existing jsintel adapter tests + the 5
  T3d1 tests + 7 engine retention tests (6 prior + 1 added this pass:
  TestReportRetainedContentSortedDedupedNilSkipped) pass. go vet ./... →
  ok. go build ./... → ok. go test -race -count=1 ./internal/jsintel/...
  ./internal/pipeline/... → same single httpprobe failure only; no races.
  Full suite go test -count=1 ./... → same single failure. T3d1 scope
  fully green; the httpprobe failure blocks the shared pipeline gates
  until the httpprobe unit builder reconciles its engine-vs-test
  inconsistency (also recorded above under T3d1 second pass).
- T3d2 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the dns/httpprobe/urlintel/techintel adapter
  results production, exactly per the orchestrator contract — no
  deviations. VERIFICATION of the inherited working tree (line-by-line
  against the contract): dns.go already wired Results.IPs = rep.AllIPs()
  on all four return paths (error branches, ctx-firing branch, success);
  httpprobe.go buildResult already set IPs/Ports/Services/Endpoints/
  TLSCertificates/Relationships from the report accessors on every path;
  urlintel.go urlintelResults (Parameters/Endpoints/Relationships) on all
  five return paths; techintel.go buildTechResult (Technologies/Evidence/
  Relationships) on all four paths. Corpus filtering (FilterHosts/
  filterURLs), folds, counters, cache-before-execute, and truncation flags
  (dnsAnswersTruncated / probe_truncated / urlintel_parameters_truncated /
  tech_indicators_truncated) unchanged in all four — existing tests pass
  unmodified. KNOWN-ISSUE RECONCILIATION (orchestrator-verified, not open
  for debate): httpprobe_test.go asserted the non-canonical service
  identities `service:443/https` / `service:80/http`; the asset model's
  canonical Service identity = Port.String()+"/"+encodedName and the
  engine builds its probe ports with Protocol "tcp" (observe.go
  portForScheme, unchanged at HEAD), so the canonical identities ARE
  `service:443/tcp/https` / `service:80/tcp/http`. FIXED in the test
  (the only protocol-less expectations in the file — repo-wide grep
  confirmed no others); the engine and asset model untouched. SECOND
  TEST-EXPECTATION CORRECTION found while verifying: the same test
  asserted 10 relationships; the engine's AllRelationships sorts WITHOUT
  cross-host dedup (per-host assemble() dedupes within a host only; the
  cross-host collapse is the runner's first-seen per-edge mergeResults),
  so 2 hosts × (2 host->url + 2 url->endpoint + 2 port->service) = 12 —
  corrected to 12 with the reason documented in the test. NEW TESTS added
  (mirroring the T3d1 harness style; all hermetic — canned transport /
  scripted runner / synthetic fingerprint DB / fake resolver): dns —
  TestDNSStageResultsIPsDeduped (two hosts resolving to the same address
  → exactly one canonical IP, engine-merged AllIPs copied verbatim) +
  TestDNSStageResultsDeterminism (two identical runs → DeepEqual
  StageResults incl. IPs); httpprobe — TestHTTPProbeStageResultsDeterminism
  (two identical runs → DeepEqual incl. ports/services/endpoints/
  relationships; IPs/TLS empty pinned in the corrected channel test);
  urlintel — TestURLIntelStageResultsDedupedAcrossDomains (same URL from
  two queried domains → one merged entry: one endpoint, one parameter,
  4 edges) + TestURLIntelStageResultsDeterminism; techintel —
  TestTechIntelStageResultsDeduped (two observations matching the same
  fingerprint → one identity-merged technology, evidence per observation,
  host->technology edge deduped → 5 edges) + TestTechIntelStageResultsDeterminism.
  7 new tests; production mapping was already pinned by the inherited
  working-tree tests (dns happy-path IPs, httpprobe channel test, urlintel
  happy-path endpoints + parameters test, techintel happy-path
  technologies/evidence/relationships). No adapter .go file changed this
  pass; no engine/asset/results.go/doc.go changes; jsintel/priority/
  detect/report/secrentel untouched.
- T3d2 GATE RECORD (this session, verbatim): gofmt -l $(find . -name
  '*.go' -type f) → clean (empty). go test -count=1 ./internal/pipeline/
  ... → ok (pipeline 0.160s, adapt 17.295s — first run failed ONLY on the
  pre-fix relationship count, corrected as above; final run clean). go vet
  ./... → ok. go build ./... → ok. go test -race -count=1
  ./internal/pipeline/... → ok (adapt 18.547s, no races). Full suite go
  test -count=1 ./... → ok (25 packages; discovery 75.6s; adapt 17.3s).
  Existing pipeline tests pass unmodified (the four adapters' pre-existing
  tests unchanged except the two corrected expectations above). No new
  issues opened.
- T3d3 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the priority/detect/report adapter results
  production/consumption, exactly per the orchestrator contract — no
  deviations. VERIFICATION of the inherited working tree (line-by-line
  against the contract): priority.go already wired Surfaces (copied from
  completed AssetResult.Surface, never rebuilt) + Groups/AttackPaths via
  priority.Correlate/AttackPaths in buildPriorityResult on every path,
  with the priority_groups_truncated sticky flag on the correlation cut;
  detect.go already built the full 7-channel engine Snapshot (corpus
  identities + Results Relationships/Evidence/Technologies/Secrets/
  JavaScript/Endpoints, copied whole) with the D2 empty-registry
  short-circuit preserved (fires only when corpus AND snapshot-feeding
  channels AND registry are all empty); report.go already composed the
  full report.Context (corpus Domains/Hosts/URLs + all 16 Results
  channels, copied whole; the render-cache invariant untouched). One
  stale doc comment fixed in detect.go ("in a later milestone" → T3d —
  the results wiring is implemented right below it; techintel.go's
  analogous stale wording noted, out of scope). FIND-2 verified as
  documented on pipeline.Results: the Groups/AttackPaths merge keys on
  the anchor/root only (mergeChannel by Anchor.String()/Root.String()).
  §0.6 TRUNCATION DECISION (evidence + file:line): the priority engine
  caches per-surface records only and builds the Report fresh every run
  (internal/priority/engine.go), so the adapter's Correlate call in
  buildPriorityResult (internal/pipeline/adapt/priority.go) re-derives
  the group set deterministically from replayed surfaces on EVERY path —
  the cut flag can never be lost in replay, is merged stickily into the
  StageRecord, and surfaces via RunReport.Truncated (run.go:330) →
  completed-with-flag is the legal AGENTS §0.6 carve-out. NEW TESTS: the
  one integration test (t3d_integration_test.go — TestT3dEndToEndRun:
  seed stage under the discover name + the real dns/httpprobe/urlintel/
  techintel/jsintel/secrentel/priority/detect/report stages, all hermetic
  — fake resolver, canned transport, scripted gau, loopback HTTP serving
  synthetic script bodies, synthetic secret DB, hermetic detect rule
  emitting one technology-listing finding, capture reporter; asserts
  every stage completed, every Results channel populated producer-by-
  producer, the jsintel→secrentel document flow with the synthetic AWS
  key, the full report Context in the captured model, and DeepEqual
  determinism across two identical runs), plus TestResultsGroupsFirstSeen
  PerAnchorCollapse (FIND-2 pin: distinct groups with the same anchor →
  first-seen wins, later members never merge; same for AttackPaths per
  root), TestPriorityTruncationFlagSurvivesRunReport (§0.6 chain through
  the runner: 1025 distinct-anchor hosts → 1024 groups, Truncated,
  StageRecord flag, completed), TestDetectStageSnapshotResultsChannels
  (all six snapshot-feeding channels reach the rules), and
  TestReportStageContextEveryChannel (all 16 Results channels reach the
  report model). Docs: adapt/doc.go T3d section gained the
  external-URL non-propagation note and the producer/consumer
  per-channel table; ARCHITECTURE.md's two stale "planned / no producer
  yet" lines now state T3d completion; README.md verified — no line
  becomes false. No engine/asset/results.go/run.go changes; T3d1/T3d2
  files untouched.
- T3d3 GATE RECORD (this session, verbatim, all commands actually run):
  gofmt -l $(find . -name '*.go' -type f) → clean (empty output; doc.go
  table + new test file formatted). go test -count=1
  ./internal/pipeline/... → ok (pipeline 0.161s, adapt 17.306s). go vet
  ./... → ok. go build ./... → ok. go test -race -count=1
  ./internal/pipeline/... → ok (pipeline 1.188s, adapt 18.531s). Full
  suite go test -count=1 ./... → ok (24 packages). During development
  the new integration test failed three times on revealed expectations,
  each fixed in the test itself, not in engine code: the detect rule's
  finding needed Name/Category/Version aligned with the rule metadata
  plus Created via the injected clock (engine validation contract);
  the Google secret candidate value is retained at the engine's bounded
  candidate cap (assert by type, not exact value); the report engine
  validates group members and path steps (shape fixed in the fixture).
Existing pipeline tests pass unmodified — the T3d3 delta adds one new
   test file (t3d_integration_test.go), extends detect_test.go and
   report_test.go, and changes one doc line in detect.go. No new issues
   opened.
- T4 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): full-pipeline determinism + the discovery
  clock seam, exactly per the orchestrator contract — no deviations.
  AUDIT RESULT (evidence-complete, no engine/adapter code change
  warranted): per-source discovery result order is selection order at any
  pool concurrency (Results slot array pre-allocated in selection order,
  each job writes only its own slot — internal/discovery/pipeline.go:302,
  332-355; never pool-completion order — the Concurrency=1 comments in
  pipeline_test.go are about clock-advance provenance and cancellation,
  not order); per-source host lists deduped + sorted by canonical name
  (parse.go:41); Report.All() merges + sorts (pipeline.go:244-260);
  discoveryAdditions = FilterHosts(in.Target, report.All()) order-
  preserving (adapt/discovery.go:217-223; scope.go:41-49); mergeCorpus
  first-seen (corpus.go:17-32); the only time.Now in discovery are the
  nil-clock defaults (pipeline.go:98,127; detect.go:105) — the adapter
  always bridges Now = in.Clock.Now (adapt/discovery.go:157-159) and
  cache CreatedAt never reaches RunReport; the pool/rate-limiter wall
  clock (runtime/pool.go:190-192) gates job starts only, Timeout 0 →
  no timing-dependent outcomes; maps (StickyFlags, StageParams, cacheKey
  Config) never serialized into ordered structures on the RunReport path.
  PINS LANDED: internal/discovery/pipeline_determinism_test.go (3 tests:
  TestRunDeterministicAcrossRunsConcurrency — two runs at Concurrency 4
  DeepEqual the whole report, TestRunDeterministicProvenanceAcrossRuns —
  fixed-clock DiscoveredAt + earliest-wins tool-name sources,
  TestRunPerSourceHostsSorted — scrambled tool output → sorted deduped
  per-source lists, malformed never counted); internal/pipeline/adapt/
  t4_determinism_test.go (2 tests: TestT4FullRunDeterminismWithRealDiscovery
  — THREE full ten-stage runs with the REAL discovery adapter at
  Concurrency 4 DeepEqual pairwise, provenance DiscoveredAt == fixedTime
  with sources, corpus shapes (0 domains, 3 hosts, 9 URLs, 12 surfaces,
  1 group anchored domain:example.com with 12 members, 1 attack path, 1
  finding, documents carry the synthetic key, report model bracket),
  TestT4FullRunCacheHitParity — warm run over a real FS cache DeepEquals
  the cold run, discovery executions 3 → 4 (assetfinder only re-executes;
  subfinder/amass served from cache), zero new dns queries / http probes /
  jsintel requests, gau runs once per run by design). CACHE-PARITY BUG
  FOUND + FIXED (the only production change; evidence-based, root-caused
  via a temporary field-level diff): the detect engine's cache-hit replay
  decoded stored findings WITHOUT re-normalization, so a finding whose
  RelatedAssets/Relationships were empty came back nil after the JSON
  round-trip (omitempty) while a freshly executed finding carried
  empty-but-non-nil slices (asset.NewFinding's dedupe normalizers always
  returned non-nil) — DeepEqual broke between cold and warm runs. FIX:
  dedupeFindingIdentities/dedupeFindingRelationships (internal/asset/
  finding.go) now return nil for empty input, matching the JSON round-trip
  representation at the normalization point; Regression test
  TestFindingEmptySetsAreNil (internal/asset/finding_test.go) pins nil
  normalization + byte-identical round-trip + MergeFindings parity. No
  existing test changed. Docs: internal/discovery/doc.go gained a
  Determinism section (selection-order mechanism, sorted lists, clock
  seam, cache parity, pool start-gating note); internal/pipeline/adapt/
  doc.go gained the T4 section (selection order, clock bridge, cache-hit
  parity incl. the asset finding normalization fix).
- T4 GATE RECORD (this session, verbatim, all commands actually run):
  gofmt -l $(find . -name '*.go' -type f) → clean (empty output). go test
  -count=1 ./internal/pipeline/... ./internal/discovery/... → ok (adapt
  incl. the two T4 tests; discovery incl. the three new pins — the
  determinism tests take ~2 s each by design; T4 fix round (FIND-1..4
  closed in a nit round: Rate 0 + runnerBarrier overlap proof +
  maxConcurrent>1 assertions + per-run model assertions + report.go
  comment; determinism tests now ~0 s / full-run ~1.1 s, not ~2 s; gates
  re-run green — reviewer closure APPROVE)). go vet ./... → ok. go build
  ./... → ok. go test -race -count=1 ./internal/pipeline/...
  ./internal/discovery/... ./internal/asset/... ./internal/detect/... →
  ok (no races; discovery 81.7s under race). Full suite go test -count=1
  ./... → ok. The T4 parity test failed pre-fix on the finding
  representation mismatch, passed after the internal/asset fix; the
  full-run determinism test passed from the first run. No new issues
  opened.
- T5 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): hermetic full-run E2E across success,
  partial failure, and retry — WITH the REAL discovery stage, exactly per
  the orchestrator contract and its discovery-inclusion directive. The
  inherited working tree (from a cancelled session) excluded discovery by
  contract (t3dSeedStage under the discover name, mirroring T3d3); that
  exclusion was WRONG for T5 and has been REWORKED: all three T5 tests
  now drive the REAL NewDiscoveryStage over the T4 seam (scripted fake
  discovery.Runner + fake LookupFunc — t4_determinism_test.go's shapes,
  no barrier, plain fixed-output fakes). REUSE, not new code: the T4
  helpers (t4DiscoveryScript/t4DiscoveryExecutions/t4ScanConfig/t4JSLoopback/
  t4GauExecutions/t4HostNames) drive the discovery, JS, gau, and host-name
  assertions; only the failure-injection seam (resolver), run mode (fresh
  vs cache-warm), and per-test assertions differ from T4's wiring.
  REWORKED ASSERTIONS (corpus shapes follow T4's real-discovery pins, not
  T3d3's seed pins): Domains 0 (the discovery adapter reports hosts only —
  adapt/discovery.go) instead of 1; hosts in the engine's sorted merge
  order [admin, api, www] with injected-clock tool-name provenance
  (earliest-wins) instead of seed order; Surfaces 12 (= 3 hosts + 9 URLs,
  no domain surface) and group members 12 instead of 13; report model
  corpus 0/3/9 instead of 1/3/9; captured models 2 (one per run) instead
  of 1; discovery StageRecord pinned completed with ItemsProcessed 5
  (subfinder 2 + assetfinder 2 + amass 1) + 3 executions + host
  provenance; discovery executions counted through the retry runs exactly
  like T4's cache-parity pin (cold 3 → warm 4 — only the NON-CACHEABLE
  unknown-version assetfinder re-executes, internal/discovery/pipeline.go
  :418-426; subfinder/amass served from cache; the healed-cold third run
  adds 3 more → 7 total). UNCHANGED (verified correct in the inherited
  file): the failure-injection pattern (typed per-host resolver failure
  for exactly ONE discovered host on all of A/AAAA/CNAME → dns
  StatusFailed → stage partial with ItemsFailed 1 → run partial with
  ItemsFailed 1); failure ≠ truncation asserts (no sticky flags, no
  Truncated anywhere); honest retained sets (IPs = exactly the two
  surviving hosts' addresses; every surviving host's downstream work
  present — jsintel/secrentel document flow with the synthetic key,
  techintel technologies, urlintel parameters, detect finding, priority
  12-surface group/attack-path shapes); the report model complete and
  internally consistent; 20 stage events per run with the failing stage's
  finished payload mirroring its StageRecord field for field (plus a new
  discovery finished-payload completed assert) and the second run's event
  stream DeepEqual; the healing resolver (first-call-per-(host,type)
  fails, mutex-guarded) with 9 cold / 12 warm resolver-call counts, 3
  re-attempted admin wire queries, zero re-execution of succeeded work
  (http/jsintel counts flat, gau +1 by design) and the healed warm run
  DeepEqual a fresh cold healed run; the persistent-failure resolver with
  9 → 12 query counts, admin 3 → 6, surviving hosts flat 6, warm run
  same partial + ItemsFailed 1, and the two RunReports DeepEqual.
  Docs: adapt/doc.go T5 section rewritten (discovery INCLUDED via the T4
  seam; the exclusion rationale gone; failure-injection pattern; the
  observed cache contract for failed jobs with file:line evidence; the
  discovery NON-CACHEABLE re-execute note on the retry counts; the
  real-discovery corpus shapes); ROADMAP.md ticked "Pipeline runs are
  deterministic for the same input and config." (pinned by T4's
  TestT4FullRunDeterminismWithRealDiscovery + TestT4FullRunCacheHitParity,
  t4_determinism_test.go:278/443 — cited here in the board per the
  orchestrator directive, not in the roadmap). Production code: ZERO
  changes (no engine/adapter/cache/asset code touched; the inherited
  dns_test.go seenCount fixture helper kept). The cancelled session's
  surface was verified line-by-line against the brief before rework (see
  the gate record for what passed from the first run).
- T5 GATE RECORD (this session, verbatim, all commands actually run, in
  sequence): gofmt -l $(find . -name '*.go' -type f) → clean (empty
  output). go test -count=1 ./internal/pipeline/... ./internal/discovery/
  ... → ok (pipeline 0.160s, adapt 17.5s incl. the reworked T5 tests,
  discovery 75.7s; the T5 tests pass from the second run — one fix round
  for the model-count assertion placement, test-side only). go vet ./...
  → ok. go build ./... → ok. go test -race -count=1 ./internal/pipeline/
  ... ./internal/discovery/... → ok (no races; adapt 18.6s, discovery
  81.4s under race). Full suite go test -count=1 ./... → ok (25
  packages). No new issues opened; NEW-13 stays IN PROGRESS (owner:
  builder; orchestrator verifies and closes — never self-closed). No
  commits made (working tree left uncommitted per directive; .gitignore
  and .opencode/ untouched).
- T5 REVIEW FIX ROUND (this session, builder; claimed and completed, never
  self-closed): FIND-1 (LOW, T5 review round) — adapt/doc.go
  over-generalized: "The other engines follow the same Phase 3 convention
  (completed-only hits; partial/incomplete never served), which is what
  makes the full-run warm parity hold" implied every engine's FAILURE-path
  retry contract is pinned by T5, but only the dns engine's failed-job
  retry contract (stored-but-never-served: dns/run.go storeType, cache.go
  typeStatusToCache, cache evaluate — the file:line citations above
  storeType:558-601 / cache.go:133-143 / evaluate:207-209) is pinned HERE
  by the retry tests (TestT5FullRunRetryHealing / Persistent); the
  remaining engines' warm parity is pinned on the SUCCESS path by T4's
  cache-parity test (TestT4FullRunCacheHitParity, t4_determinism_test.go
  :443). REWORDED accordingly — the section's scope now matches what it
  actually pins; no other change, no new issues opened. Gates re-run
  verbatim below. T5 stays IN PROGRESS (owner: builder; orchestrator
  verifies and closes — never self-closed).
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

### NEW-4 (INFO) — TestProbeCompletedHTTPS intermittent flake (internal/httpprobe)
- Status: OPEN
- Reporter: reviewer
- Owner: (unassigned)
- Problem: TestProbeCompletedHTTPS (run_test.go:106-139) flaked once during
  the TODO-sweep re-review (an `-race` run observed the https probe as
  incomplete); reproduced at HEAD with the sweep changeset stashed — a
  pre-existing, rare flake, unrelated to the M-1/M-2/NEW-1 changes. Five
  consecutive plain runs and the re-review's later runs pass.
- Fix: investigate the https probe path for intermittent non-completion
  under race load (TLS handshake / transport timing); make the test
  deterministic or pin the trigger.
- Verification: 20+ consecutive `go test -race -count=1 -run
  'TestProbeCompletedHTTPS' ./internal/httpprobe/` runs pass.

### NEW-16 (INFO) — a nil jsintel transport dials the network once httpprobe recorded probe targets; hermetic run-level tests must substitute the transport (internal/pipeline/adapt/httpprobe.go, jsintel.go, internal/cli/scan_test.go)
- Status: OPEN
- Reporter: builder (T6 locked-item session)
- Owner: (none)
- Problem: the httpprobe engine records the probe-target URL on the result
  regardless of probe outcome, so the URL corpus handed to the jsintel stage
  is non-empty whenever a host was probed. jsintel's nil transport seam equals
  the engine's bounded default transport (a real dial): a run-level test that
  constructs NewJSIntelStage(nil) with a probed host therefore reaches the
  network — violating AGENTS §13 hermeticity. The T6 smoke E2E
  (TestRunScanSmokeE2E) substitutes the canned RoundTripper for jsintel in its
  stages seam so no socket is dialed; production behavior is unchanged
  (newScanStages keeps NewJSIntelStage(nil) = the engine default transport,
  correct for the real CLI).
- Fix (if ever scoped): route an http.RoundTripper through the stages seam to
  every network-capable stage — httpprobe, jsintel (and any future
  body-fetching stage) — instead of relying on nil semantics, or document
  that a nil jsintel transport dials the network and keep hermetic run-level
  tests on the substituted transport.
- Verification: TestRunScanSmokeE2E passes with the canned transport serving
  >= 4 round trips (2 httpprobe + 2 jsintel); go test -race
  ./internal/cli/ OK.

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

### NEW-15 (INFO) — T3c secrentel adapter: the JavaScript channel carries no document content (internal/asset)
- Status: RESOLVED (T3c session — decision: pipeline-internal document
  channel; no asset change)
- Reporter: builder (T3b round)
- Owner: (none)
- Problem: the T3b contract documents secrentel's T3c adapter as consuming
  the channel's `JavaScript` documents as its document source — but
  `asset.JavaScript` (internal/asset/javascript.go:25-77) retains
  OBSERVATIONS only: canonical URL identity, ContentHash (SHA-256 of the
  body), Size, ContentType, ETag, LastModified, StatusCode, FinalURL —
  never the body itself (jsintel's bounded fetch truncates honestly and
  retains no prefix). secrentel's Document seam is caller-composed
  bounded content (the engine never fetches); with no body in the
  channel, a T3c adapter has nothing to scan without re-fetching
  (violates the caller-composed contract) or a new content carrier.
- Resolution (implemented in T3c): a NEW pipeline-internal document
  channel (`internal/pipeline/document.go`) — `StageResult.Documents` /
  `StageInput.Documents` / `RunReport.Documents`, bounded retained script
  bodies (`pipeline.Document{Identity, URL, Content, Truncated}`, content
  ≤ `pipeline.MaxDocumentBytes` = 2 MiB = the secrentel engine's own
  ingest cap), merged by the runner exactly like the corpus/results
  channels (first-seen dedup keyed by the canonical identity string,
  deterministic order, per-stage MaxOutput cap → `documents_truncated`
  sticky flag + Truncated, hostile over-cap content dropped whole with
  the document marked Truncated — never a partial prefix). `asset.
  JavaScript` stays observation-only (NEW-15's original finding stands);
  the secrentel adapter (`internal/pipeline/adapt/secrentel.go`) consumes
  the document channel, never the Results.JavaScript field. Production is
  T3d (the jsintel stage family) — no adapter produces documents yet.
- Verification: full T3c gates (see the T3c IMPLEMENTED record below);
  `documents_truncated` flag, truncation-skip, and overflow-flag
  cache-hit regression pinned by tests.

### NEW-17 (INFO) — scan summary may list interrupted-render temp files (internal/cli scan.go reportFiles)
- Status: OPEN
- Reporter: reviewer (T6 fix round)
- Owner: (none)
- Problem: printScanSummary lists every non-directory entry of the output
  directory via reportFiles (internal/cli/scan.go:541-554) with no
  filtering, so a ".ravenrecon-report-*" temp file left behind by an
  interrupted report render would appear in the summary as if it were a
  report — the report writer's tmpPrefix (internal/report/writer.go:20-23)
  exists precisely so aborted renders "can be identified and never look
  like reports".
- Fix: filter out entries with the tmpPrefix (".ravenrecon-report-") in
  reportFiles so interrupted-render temp files never appear in the summary.
- Verification: extend TestReportFiles/TestPrintScanSummary with a temp
  file present in the output directory and assert it is not listed.

### NEW-18 (HIGH) — v1.4 Live terminal observability: `ravenrecon scan --tui` (internal/cli)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20)
- Reporter: master
- Owner: builder
- Problem: v1.2's acceptance criterion "the TUI reconstructs a live run
  from events alone" has no CLI surface — `internal/tui` is a landed
  library nobody reaches; ROADMAP v1.4 (user-approved re-scope) is now
  live terminal observability for `scan`, with the per-engine standalone
  commands deferred until after v1.5 hardening.
- Fix (locked decisions): `--tui` + `--tui-compact` flags on
  `ravenrecon scan` (compact requires tui; tui and --verbose mutually
  exclusive — one event sink per run); in runScan, one
  `event.NewBus(nil)` + one bounded subscriber (64) + a controller
  goroutine (seam `tuiNew func(config.TUIConfig, *event.Subscriber,
  io.Writer) (tuiRunner, error)`, production adapter `newScanTUI`
  wrapping tui.NewController, injected at the cli.Run call site);
  `cfg.Observer = bus` on the --tui path (nil otherwise — zero change);
  TUIConfig {Enabled, Compact, Color=resolveTUIColor(os.Stderr)} with the
  rest zero → library defaults; defer after construction: sub.Close →
  `<-tuiDone` (bounded join) → bus.Close on EVERY return path; a non-nil
  Run result is a stderr "tui: %v" warning only — exit semantics + summary
  unchanged; construction errors return before the stages run.
- Verification: hermetic wiring tests (fake tuiRunner draining its
  subscriber: 20 events for 10 stages, sequence order, observer wired,
  summary byte-identical with/without --tui, failed-run semantics
  unchanged, pre-cancelled promptness + join, write-failure warning,
  Run-returned-before-runScan-returned ordering); parse rows; pipe → color
  "off"; gates (gofmt/test/vet/build/-race) + `scan --help` smoke;
  docs wave (ROADMAP re-scope + deferred list, README, ARCHITECTURE,
  AGENTS §2, version/UA 1.4.0). Fulfills v1.2's live-reconstruction
  acceptance note. Orchestrator verifies and closes — never self-closed.
- IMPLEMENTED (this session, builder; claimed IN PROGRESS at dispatch,
  never self-closed): the full locked-decision implementation landed —
  flags (`--tui`, `--tui-compact`; mutual exclusion with `--verbose`
  listing both flags; compact requires tui), `resolveTUIColor`
  (ModeCharDevice via Stat; pipe/file/non-*os.File → "off", TTY → "on"),
  the `tuiRunner` + `scanTUIFactory` seams with the production adapter
  `newScanTUI` (wraps tui.NewController; wired at the cli.Run scan call
  site) and a defensive nil-seam guard, and the runScan wiring: after
  parse → config → cache construction, `event.NewBus(nil)` + one bounded
  subscriber (64 — ~20 stage events per run documented) + controller
  goroutine (`go func(){ tuiDone <- ctl.Run(ctx) }()`, buffered result
  channel); `cfg.Observer = bus` on the --tui path (nil otherwise); a
  defer registered right after construction runs on EVERY return path:
  `sub.Close()` (deterministic termination — the controller's loop selects
  on Done) → `<-tuiDone` (bounded join) → warning `tui: %v` on stderr for
  any non-nil result (write failure OR the controller reporting
  ctx.Err() — exit semantics and summary never change) → `bus.Close()`.
  Construction errors return before the stages run. TUIConfig passed to
  the seam: {Enabled: true, Compact: <flag>, Color: resolveTUIColor(
  os.Stderr)} — all other fields zero → library defaults. NEW TESTS
  (internal/cli/scan_test.go, all hermetic, channels only — no sleeps, no
  TTY hacks): parse rows (tui, tui+compact, both exclusivity orders,
  compact-without-tui), TestResolveTUIColor (os.Pipe writer → "off"),
  TestRunScanTUIWiring (observer wired on the seam capture; 20 events in
  started/finished alternation with bus sequences 1..20; seam cfg
  Enabled/Compact from flags; writer == os.Stderr; summary byte-identical
  to the no-flag run; fake Run returned before runScan returned — the
  structural join assertion; compact variant), TestRunScanNoFlagObserverNil
  (zero behavior change), TestRunScanTUIOutcomeUnchanged (failed run:
  same error + honest summary + joined), TestRunScanTUIWriteFailureIsWarning
  (stderr captured via os.Pipe swap — no t.Parallel in this package —
  warning contains "tui:", exit nil, summary printed, joined),
  TestRunScanTUICancelled (pre-cancelled ctx: prompt return, cancelled
  summary, seam consulted exactly once, joined, the controller's ctx.Err()
  surfaced as the honest `tui:` stderr note), TestRunScanTUIRunnerRequired
  (nil seam + --tui errors before the stages run). Docs wave: ROADMAP v1.4
  re-scoped (goal + checklist + deferred per-engine commands line,
  Status stays planned; v1.2 table row notes the later wiring); README
  Status 1.4.0 + scan flags + TUI wiring paragraph; ARCHITECTURE
  Terminal-observability "CLI wiring" paragraph + reader's map + event-bus
  known-limitations + v0.3 boundary + scan-command bullet; AGENTS §2
  parenthetical + tui bullet; version.go → 1.4.0, config.go UA →
  RavenRecon/1.4.0 (doctor output coherent — verified). Forced test
  touch-up: the 9 pre-existing runScan call sites in scan_test.go gained
  the 5th seam arg (nil) — the only existing-test change, required by the
  locked signature growth; ALL pre-existing assertions unchanged and green.
- GATE RECORD (this session, verbatim, in sequence): gofmt -l $(find .
  -name '*.go' -type f) → clean (empty). go test -count=1
  ./internal/cli/... ./internal/tui/... ./internal/event/... → ok (cli
  0.534s, tui 0.036s, event 0.415s). go vet ./... → ok. go build ./... →
  ok. go build -o /tmp/opencode/ravenrecon ./cmd/ravenrecon && /tmp/
  opencode/ravenrecon scan --help → full usage incl. --tui/--tui-compact/
  exclusivity/exit-semantics note; binary smoke: `scan example.com --tui
  --verbose` → "scan: --tui and --verbose are mutually exclusive" exit 1;
  `--tui-compact` alone → "requires --tui" exit 1; `--tui --tui-compact`
  real run completed without hanging (subscriber close/join exercised in
  production); `version` → 1.4.0; `doctor` → User-Agent RavenRecon/1.4.0
  (coherent). go test -race -count=1 ./internal/cli/... ./internal/tui/...
  ./internal/event/... → ok (cli, tui, event all ok, no races). go test
  -count=1 ./... → ok (25 packages, discovery 75.6s, adapt 17.5s). No
  production behavior changes outside the locked decisions; working tree
  left uncommitted.
- REVIEW ROUND (this session, reviewer; APPROVE WITH NITS — no
  CRITICAL/HIGH/MEDIUM; 8 INFO findings): FIND-1 (TUI final frame renders
  after the stdout summary — defer placement; accepted: summary byte-
  identical + separate streams + strictly sequential writes), FIND-2
  (resolveTUIColor = char-device probe, canonical stdlib-only isatty
  approximation; accepted, /dev/null gets harmless color codes), FIND-3
  ("tui: context canceled" honest warning; accepted; 3a fix below),
  FIND-4 (nil-seam guard asymmetry vs --verbose; accepted, pinned by
  test), FIND-5 (FIXED), FIND-6 (join can block on a stuck stderr pipe
  writer — same exposure as --verbose; accepted), FIND-7/FIND-8 (buffer
  64 budget + future instrumented stages; accepted, documented drift).
  FIND-5 FIXED (nit round): bus.Subscribe error path now bus.Close()es
  before returning (uniform with the ctl-construction path; unreachable
  on the current API — consistency only). FIND-3a FIXED: scan usage
  prose now covers both `tui:` warning triggers ("a TUI write failure
  (for example a broken pipe) or shutdown reason (for example the run
  context's cancellation) is a 'tui:' warning on stderr only") — matches
  ARCHITECTURE. NIT-ROUND GATES (verbatim): gofmt clean; go test
  -count=1 ./internal/cli/... ./internal/tui/... ./internal/event/... →
  ok; go vet ./... → ok; go build ./... → ok; go build -o
  /tmp/opencode/ravenrecon ./cmd/ravenrecon → ok; go test -race -count=1
  ./internal/cli/... → ok. Diff: +3/−1 (scan.go only).
- ORCHESTRATOR: full-suite gate + field trial + commit + close sequence
  pending (see NEW-19). DO NOT self-close.

### NEW-19 (INFO) — Field trial: first real-target validation run (cmd/ravenrecon)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20)
- Reporter: master
- Owner: master (orchestrator-run validation; no implementation)
- Problem: the entire automated suite is hermetic by design (AGENTS §13) —
  no real-world validation (live DNS/TLS, real discovery tools, real
  cache behavior, live TUI) has ever been exercised. User requested a
  real-target taste (2026-08-20).
- Fix (locked): `scan example.com` (IANA-reserved smoke target), all 10
  stages, real subfinder/assetfinder/amass (installed); gau/waybackurls/
  waymore ABSENT → urlintel degrades honestly (adapt/source.go:508-510
  ErrExecutableNotFound, recorded per-source errors); fresh cache
  /tmp/opencode/ravenrecon-cache-example; --tui exercises the v1.4 wiring
  on a long real run; report → /tmp/opencode/ravenrecon-report-example;
  --timeout 10m per stage. Two passes: cold (population), then warm
  (cache-hit parity + zero re-execution — the T5 contract at real scale).
- Verification: cold log (summary/outcomes/errors/timing) + report files
  + warm-run comparison; any real-world defect found → file NEW-2x
  finding (severity + file:line + fix), do not fix silently.
- Status notes: cold run launched in background (binary at launch = pre-
  micro-fix image; reachable-path behavior identical to final — the
  micro-fix touched only an unreachable error path + usage prose).
- FINDING (28m in, user-flagged): NOT hung — pipeline progressing
  (discovery incl. ~20 min amass, then dns/httpprobe, then urlintel: gau
  child observed 7+ min in network I/O; cache entries growing). The TUI
  frames were empty because of NEW-21 (stage events ignored by the TUI
  state machine), not because the run stalled. Tools gau/waybackurls/
  waymore confirmed installed (user) — full-stack trial in progress.

### NEW-20 (HIGH) — v1.5 URL-hunting refinement (formerly v1.7): live attack-surface mapping (internal/httpprobe, internal/pipeline/adapt)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-21): all v1.5 P0 items landed and verified — OPT-P0-1 quality gate b46a110 (NEW-22), OPT-P0-2 JS→URL 2d06b94, OPT-P0-3 urllive 7fc7e4c, OPT-P0-4 per-tool+health f44cecc, OPT-P0-5 honest duration 593177a; plus Chaos 184796a, Dnsx brute 0a19d67, Katana early-preview 1ab2e99; field validation pending next real-target run (dispatch pending v1.4 close + field-trial evidence NEW-19)
- Reporter: master
- Owner: (unassigned) | builder at dispatch
- Problem: framework misses most bug-bounty-relevant URLs — httpprobe
  probes hosts never URLs (httpprobe.go:87-88); jsintel analyzer endpoints
  are results-only, zero corpus additions (jsintel.go:100-102); no
  per-URL liveness triage; URL corpus = 0 while gau/waybackurls/waymore
  absent. Full drafted milestone: ROADMAP v1.5 "Refinement deliverable —
  URL hunting" (2026-08-20, orchestrator).
- Fix: ProbeURLs engine + `urllive` stage (between secrentel and priority)
  + jsintel filtered URL additions + new results entity (not asset.URL
  field) + report URL-status section + AllStages/vocabulary/T4/T5/T6 pins
  + cache op + ops precondition (install the three urlintel binaries).
- Verification: as ROADMAP v1.5 acceptance (live statuses end-to-end,
  JS-extracted → corpus → urllive → priority → report, zero recursion,
  determinism/cache parity/race/gates, real-target field trial with tools
  installed).
- Execution priority: NEXT milestone after v1.4 closes (orchestrator
  decision 2026-08-20, user delegated "do what is best"); v1.5/v1.6 slide
  after, content unchanged.

### NEW-21 (HIGH) — TUI renders empty frame on real runs: pipeline stage events ignored by TUI state machine (internal/tui/state.go, internal/pipeline)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20) — builder fix round records kept below
  adaptation implemented (state.go maps StageStarted/StageFinished with the
  event payload fields; render.go gates the worker/throughput sections on
  their data sources and adds the stage-feed line; summary gains the
  bounded stage list; render-content tests added in
  internal/tui/stages_test.go incl. a controller fake-clock live-frame
  test; internal/cli/scan_test.go gains an additive production-adapter
  type assertion). Pipeline/event vocabulary/CLI wiring untouched.
  Reviewer round + field-trial rerun + gates still required before close;
  fix NOT verified, do NOT self-close.
- Reporter: master (field-trial evidence)
- Owner: builder (fix round) | orchestrator (review + verification + close)
- Problem: field-trial evidence (NEW-19, cold run on example.com): the
  TUI rendered "phase —" in 7,024/7,024 frames across 28+ minutes while
  the pipeline progressed through discover → dns → httpprobe → urlintel
  (gau child observed; cache entries growing to 258 records). The
  pipeline emits ONLY KindStageStarted/KindStageFinished (T3a). The TUI's
  State.Apply (internal/tui/state.go:88-130) handles KindScanStarted/
  Stopped, KindPhaseTransition, KindRunMetadata, KindProgress, KindWorker*,
  KindTask* — NO case matches a stage event, so every consumed event is
  ignored: title stays "untitled run", phase —, worker/task/throughput
  widgets stay empty. Controller.finish also renders an empty final state.
  The v1.4 hermetic wiring tests asserted transport (event count/order at
  the subscriber, summary byte-identity) but never rendered frame CONTENT,
  so the gap was invisible to the suite. v1.4's acceptance ("the TUI
  reconstructs a live run from events alone") is NOT met in production.
- Fix (recommended direction): adapt the TUI side, keep the pipeline's
  stage-event vocabulary stable (it is pinned by T3a tests, event
  validation, wiring tests, docs): (a) State.Apply maps KindStageStarted →
  setPhase(stage name) + stage-start timing, KindStageFinished → stage
  progress/task counting; (b) the worker/throughput/queue widgets have NO
  data source in production (pipeline emits no task/worker events) —
  degrade honestly: omit/blank those sections when no task events exist
  instead of rendering misleading zeros; (c) NEW render-content assertion
  in the wiring tests: a fake stage-event stream must produce a frame
  whose phase/title/progress reflect the events (assert rendered text via
  the controller's writer buffer, not just transport counts). Reviewer
  round required before v1.4 can close as verified.
- Verification: TUI wiring test asserting rendered content from stage
  events; field-trial rerun shows a live phase/progress frame; gates
  (gofmt/test/vet/build/-race/full suite) green; v1.4 acceptance then
  VERIFIED → close.
- NIT ROUND (reviewer, APPROVE WITH NITS): FIND-1 LOW FIXED — summary
  stage block gate now symmetric (`StagesStarted > 0 || StagesCompleted
  > 0`, render.go); FIND-2 INFO FIXED — TestStateProgressOnlyKeepsRate
  GateClosed pins KindProgress-only streams keep the throughput gate
  closed (stages_test.go); FIND-3 INFO FIXED — docs wave (ARCHITECTURE
  terminal-observability section + reader's map, README TUI paragraph,
  ROADMAP v1.4 checklist line); FIND-4/FIND-5 INFO accepted as designed
  (sanitize preserves LF/CR/TAB by documented contract; lone
  stage_started renders "stages 0/unknown" under honest-unknown).
  NIT-ROUND GATES (verbatim): gofmt clean; tui+cli tests ok; vet ok;
  build ok; race tui ok; event ok; full suite ok (25 pkgs).
- ORCHESTRATOR DECISION (doc-drift candidates flagged by docs agent,
  accepted as non-issues): (a) README State-components paragraph reads
  always-present but describes the MODEL (the model tracks
  worker/throughput fields); the render-level gating is documented in
  the TUI paragraph — no change; (b) ARCHITECTURE resource-line
  ambiguity ("queue depth, active workers" among sampled values) —
  resources.go carries those fields, render shows heap/goroutines/fds —
  ambiguous-not-wrong, no change. Both recorded here for history.
- ORCHESTRATOR: warm-trial evidence (NEW-19) → final gates → v1.4
  commit → NEW-18/NEW-21 VERIFIED + archived. DO NOT self-close.

### NEW-22 (HIGH) — Discovery data-quality gate: passive-source pollution cascade (internal/discovery, internal/pipeline)
- Status: VERIFIED — gate landed (builder round 1 + nits, reviewer CHANGES REQUIRED → nits fixed, gates green, committed b46a110)
- ORCHESTRATOR NOTE (transport + scope incident): builder dispatch for
  the locked contract failed twice at the transport layer (decode error;
  resume session completed without report). The partial session wrote
  internal/discovery/quality.go (gate core — kept, tree does NOT compile
  until wiring lands) then produced an out-of-contract
  OPTIMIZATION.md audit backlog + ROADMAP status-table rewiring (OPT-P*
  IDs) and zero wiring. Both discarded (git checkout ROADMAP.md; rm
  OPTIMIZATION.md) 2026-08-20 by orchestrator — not on any board, not
  user-requested. Re-dispatch in progress with tightened constraints.
- Status history: OPEN (addressed in v1.5 refinement) → IN PROGRESS
  (builder round 1, 2026-08-20)
- Reporter: master (field-trial evidence, NEW-19 cold run)
- Owner: (unassigned) | builder at v1.5 dispatch
- Problem: cold trial on example.com — subfinder v2.15.0 (config clean;
  no bruteforce/wordlist/permutation settings) returned 37,248 wordlist-
  shaped hosts in one burst (0.0.1.example.com, 0000-forbidden.example.com,
  zzzzzzzzzzzz.example.com; 31,180 rows with 4-label names; all rows
  timestamped 13:58:01Z, source=subfinder; assetfinder: 2 rows, amass: 0
  after 20 min). The framework accepted the entire set → 12,366 probe URLs,
  1,024 priority groups (truncated flag fired), 32 attack paths, 755
  recommendations computed over garbage; jsintel 500/500 fetches failed
  (dead junk hosts). Passive-only contract likely violated at the tool/
  binary level OR a poisoned source — either way the framework gated
  nothing.
- Fix (v1.5 item): per-source output caps + burst-anomaly detection +
  suspicious-source decision point (flag/abort/continue) before corpus
  ingestion; hostname sanity validation where syntax-gated (RFC 1035
  checks); tool-identity verification (binary hash/version pin per
  discovery source); document per-source normality baselines. Include in
  the v1.5 checklist (ROADMAP) alongside URL hunting.
- Verification: reproduction test with a fake source returning wordlist
  junk → gate trips with an honest flag/abort; real-target rerun shows a
  sane host count for a 1-subdomain domain; gates green.
- Builder round 1 (2026-08-20): quality.go kept (verified: defaults, Normalize, over_cap, divergence, median, error); fixed pipeline.go compile (storedResult QualityIssues, runSource 3-ret, no double-store, sticky replay) and cache.go; wired adapter (discovery_quality_flagged, qualityConfigFromParams, abort) and cli doctor line; ROADMAP ticked; tests: quality_test.go (cap, divergence, median, old-schema, sticky, abort, determinism) + discovery_quality_test.go (poisoned flag, divergence, abort, pipeline E2E); gates: gofmt clean, go test ./... ok (discovery 78s adapt 17s), vet ok, build ok, race ok, doctor grep quality ok.

### NEW-23 (HIGH) — DNS brute timeout indistinguishable from a complete run (internal/pipeline/adapt/dns.go)
- Status: VERIFIED — fixed in b5aa88e (attempted-only counters, dns_brute_truncated flag, outcome downgrade to partial/cancelled, 3 hermetic subtests)
- Reporter: reviewer
- Owner: builder
- Problem: AGENTS §0.6 violation. In `runBrute` (adapt/dns.go:504-573), when `dns.BruteTimeout` fires mid-resolution, `dns.Resolve` returns nil error; cancelled candidates carry no IPs/Targets and the resolving filter silently drops them; `ItemsProcessed` counts `len(filtered)` (including never-attempted hosts); only per-type answer-cap `Truncated` flags propagate — no cancellation/timeout flag exists. A timeout-truncated brute is recorded `completed` with no sticky flag.
- Fix: inspect `rep.Results` host statuses for cancelled/timed-out; set `Truncated` + `StickyFlags["dns_brute_truncated"]`, count only attempted hosts, downgrade the outcome per the fold table.
- Verification: fake resolver stalling past BruteTimeout → flag fires, outcome != completed, attempted-only counters; regression fails pre-fix.

### NEW-24 (MED) — techintel cache key lacks observation-content digest: changed page serves stale detections (internal/techintel)
- Status: VERIFIED — fixed in 51abd2d (observationContentHash SHA-256 over Body/Headers/Cookies/TLS/DNS, ContentHash omitempty, decode 64 lower-hex, lookup self-heal, 5 hermetic tests)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: `techKey` (record.go:26-36) binds identity + schema + db_digest + sources mask only; `storedTech` carries no content hash. Siblings solve this: secrentel digests document content into its key (document.go:261), jsintel cross-validates `AnalyzedHash` at lookup and self-heals (record_analyze.go:155-166). Until TTL expiry, a materially changed page replays old detections as zero-analysis cache hits.
- Fix: adopt the jsintel pattern — store an observation payload hash (headers/body/cookies digest) in the record; reject+delete+recompute on mismatch.
- Verification: cross-engine conformance test "content change ⇒ no stale hit"; fails pre-fix for techintel.

### NEW-25 (MED) — validateHostname rejects leading-underscore labels: _dmarc/_domainkey/_acme-challenge hosts cannot become assets (internal/asset)
- Status: VERIFIED — fixed in 4c919d5 (leading underscore per label, rest [a-z0-9-] hyphen rules, mid-label _ still rejected, 23 tests)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: normalize.go:48-53 permits only `[a-z0-9-]`; underscore is rejected everywhere. RFC 8552-style service labels (`_dmarc.example.com`, `s1._domainkey.example.com`, `_acme-challenge.example.com`) are legitimate passive-discovery output and are dropped/error at the sole normalization point (rejection pinned by normalize_test.go:34).
- Fix: permit leading-underscore labels; keep mid-label underscores invalid; document the policy in doc.go.
- Verification: table tests — `_dmarc`/`s1._domainkey` accepted, `exa_mple` still rejected; discovery fixture with such hosts survives end-to-end.

### NEW-26 (LOW) — jsintel import window scans superlinear on adversarial input; Parse uncancellable (internal/jsintel)
- Status: VERIFIED — fixed in 74851fc (maxTotalScanSteps 100k + statement-boundary early exit; adversarial <100ms, truncated honest)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: `findFromSpecifier` (parse.go:184-223) scans up to `maxLookaheadTokens` (1024) from every `import` keyword; input like `import x import x …` repeats gives O(tokens × 1024) (~5e8 steps at the 1M-token cap). `Parse` takes no context, so pool deadlines cannot interrupt it.
- Fix: cap total window-scan steps per parse (fold into `w.truncated`) or stop a scan at the next import/export keyword; thread ctx or accept an explicit step budget.
- Verification: adversarial corpus benchmark with the number pinned in parse.go's comment (§14); parse completes under pool deadline.

### NEW-27 (LOW) — secrentel anchor gate ASCII-lowercases but gated regexes match via Unicode simple fold: silent false negatives (internal/secrentel)
- Status: IN PROGRESS (builder fix round 2026-08-21 — implemented + gates
  green; orchestrator verifies and closes — never self-closed)
- Reporter: reviewer
- Owner: builder
- Problem: scan.go:82-86 builds the anchor haystack with `toLowerASCII`; anchors gate `(?i)` regexes (scan.go:101-112), which match through Unicode simple folding (ſ↔s, U+212A K↔k). A document containing e.g. `aws_ſecret_access_key=` passes the regex yet lacks the ASCII anchor → pattern skipped, violating the "anchor is a necessary substring" contract (patterns/types.go:124-131).
- Fix: fold-compare anchors (walk with `unicode.SimpleFold`) or restrict anchored families to ASCII-only matching explicitly.
- Implementation (2026-08-21): unicode-fold fallback in scanDocument — a lazy
  folded haystack (scan.go:94-102; buildFoldedHaystack/foldRuneToASCIILower at
  scan.go:469/481 map each rune through SimpleFold to its ASCII-lower form,
  matching RE2 (?i) semantics) consulted only when the ASCII fast path misses
  AND the document is non-ASCII (scan.go:136-150). Non-ASCII presence is
  memoized once per document (scan.go:104-115, call site scan.go:140 — review
  follow-up: an unmemoized check paid a full O(n) byte scan per anchored
  miss). Regression: TestScanAnchorHomoglyphRegression (scan_test.go:536) —
  ſ-homoglyph anchor rescued through a custom compiled pattern AND the
  production DB's own "secret" anchor. Gates this session, verbatim: gofmt -l
  clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/
  secrentel -run TestScanAnchorHomoglyphRegression -v ok; go test -race
  -count=1 ./internal/secrentel ok; go test -count=1 ./... ok (25 packages).
- Verification: homoglyph regression row demonstrates match-without-anchor today, correctly anchored after fix.

### NEW-28 (LOW) — secrentel dedup merge upgrades strength/family but not entropyOK (internal/secrentel)
- Status: IN PROGRESS (builder fix round 2026-08-21 — implemented + gates
  green + pre-fix failure proven; orchestrator verifies and closes — never
  self-closed)
- Reporter: reviewer
- Owner: builder
- Problem: scan.go:176-184 merges duplicate candidates by upgrading strength/family from the winning pattern; `entropyOK` stays the creating pattern's. Phase 3 scores with the creating pattern's entropy flag while hints use the winning pattern — the factor list can contradict the winning pattern's entropy requirement (both directions possible).
- Fix: recompute `entropyOK` from the winning pattern at merge time (or evaluate Phase 3 entropy from the winner).
- Implementation (2026-08-21): entropyOK+provider now sync at BOTH points —
  the dedup merge upgrade (scan.go:219-224: `p.Strength > c.strength` also
  overwrites entropyOK/provider) and a Phase-3 winner re-derivation that
  re-syncs strength/family/entropyOK/provider from the winning pattern (max
  strength, ID tie-break) as defense-in-depth (scan.go:303-314). Regression:
  TestScanDedupEntropyWinner (scan_test.go:585). REVIEW FOLLOW-UP fixed this
  round: every subtest previously passed pre-fix because patterns.compile
  sorts by ID (patterns/load.go:69-71), so the eventual winner ("aaa-") was
  always processed first and WAS the creator — the dedup merge never
  executed. IDs reordered so the LOSER sorts first (creator) and the winner
  merges second: Case 1 creator "aaa-loser-no-entropy" (0.5) / merger
  "zzz-winner-with-entropy" (0.9) upgrades entropyOK false→true
  (scan_test.go:595,605); Case 2 mirrored creator "aaa-loser-with-entropy"
  (0.5) / merger "zzz-winner-no-entropy" (0.9) overwrites true→false
  (scan_test.go:649,659 — the merger must carry the higher strength or the
  upgrade path never fires); Case 3 kept as an honest equal-strength
  determinism pin (under sorted processing the tie-break winner is always
  the creator, so it exercises only the Phase-3 re-derivation as
  defense-in-depth). Pre-fix proof: with the NEW-28 hunks reverted on a
  scratch copy, Case 1 fails (entropy factor absent, entropyOK false despite
  strength 0.9 proving the merge ran) and Case 2 fails (spurious
  {Name:entropy Weight:0.35} factor); both pass with the fix. Gates this
  session, verbatim: gofmt -l clean; go vet ./... ok; go build ./... ok;
  go test -count=1 ./internal/secrentel -run TestScanDedupEntropyWinner -v
  ok (3/3 subtests); go test -race -count=1 ./internal/secrentel ok;
  go test -count=1 ./... ok (25 packages).
- Verification: two-pattern same-type dedup case where winner requires entropy and loser does not (and vice versa); factor list matches winner.

### NEW-29 (LOW) — sortQuery collapses ?x= and ?x into one URL identity (internal/asset)
- Status: IN PROGRESS — implemented 2026-08-21, awaiting review (orchestrator closes)
- Reporter: reviewer
- Owner: builder
- Problem: url.go:286-290 writes `=` only when the value is non-empty, so distinct raw forms `?x=` and `?x` serialize identically — contradicting the type doc's "distinct raw forms never collapse" principle (url.go:30-34).
- Fix: track whether each raw pair contained `=` and emit `key=` for present-but-empty values.
- Verification: pin `?a=1&x=` vs `?a=1&x` as distinct identities.
- Implementation (2026-08-21): sortQuery now records strings.Cut's found bool as
  param.hasValue (url.go:272, :284) and emits the '=' whenever the raw pair
  contained one, even for an empty value (`if prm.hasValue`, url.go:293), so
  "?x=" -> "x=" and "?x" -> "x" stay distinct. Type doc and sortQuery doc
  updated to state the rule. Regression pins: TestURLDistinctness case
  "empty value vs no value (NEW-29)" (?a=1&x= vs ?a=1&x) and four canonical-
  form rows in TestURLQueryRawKeyPreservation (url_identity_test.go:113,
  :161-166). Pre-fix proof: reverting only the emission condition on a scratch
  copy fails TestURLQueryRawKeyPreservation ("?x=" collapsed to "x"). Gates:
  gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./...
  ok (25 pkgs); go test -race -count=1 ./internal/asset ok.

### NEW-30 (LOW) — dns wildcard probe bypasses the central query limiter (internal/dns)
- Status: IN PROGRESS — implemented 2026-08-21, awaiting review (orchestrator closes)
- Reporter: reviewer
- Owner: builder
- Problem: `IsWildcard` (brute.go:130-165) issues `resolver.Lookup` directly (brute.go:143), outside Resolve's env; dns/doc.go:40 promises every outbound query waits on the shared token-bucket limiter regardless of concurrency. Called per-run from adapt/dns.go:449.
- Fix: route the probe through the run limiter (accept a Limiter param) or document the exception in doc.go + brute.go.
- Verification: limiter-counting fake resolver asserts the probe consumes a token (or the doc drift is closed).
- Implementation (2026-08-21): took the documented-exception alternative. The
  limiter-param route would need a new exported config surface plus adapter
  wiring, and a separately constructed limiter shares no bucket state with
  Resolve's env (burst >= 1 -> zero wait), so it would pace nothing; for one
  opt-in query per domain, honest docs are the proportionate fix. doc.go
  "Concurrency and rate limiting" now scopes the promise to Resolve's own
  pool-job queries and states the IsWildcard exception with its rationale
  (doc.go:47-55); IsWildcard carries a matching rate-limiting note
  (brute.go:155-159). Behavior unchanged — no new test surface; existing
  TestIsWildcard* all pass. Gates this session: gofmt -l clean; go vet ./...
  ok; go build ./... ok; go test -count=1 ./... ok; go test -race -count=1
  ./internal/dns ok.

### NEW-31 (LOW) — dnsx_resolvers StageParam parsed then discarded; "validates shape" claim inaccurate (internal/pipeline/adapt/dns.go)
- Status: IN PROGRESS — implemented 2026-08-21, awaiting review (orchestrator closes)
- Reporter: reviewer
- Owner: builder
- Problem: `dnsBruteResolvers` (adapt/dns.go:416-438) result discarded at :464 (`_ =`); operator-supplied resolvers are silently ignored. The comment claims parsing validates shape but no IP validation occurs (comma split only).
- Fix: implement (thread resolvers into cfg), or warn-and-ignore with honest wording, or reject the param like other unknown params; fix the comment either way.
- Verification: param supplied → resolvers used or warning surfaced; comment matches behavior.
- Implementation (2026-08-21): warn-and-ignore. dnsBruteResolvers now really
  validates shape — every non-empty entry must parse via netip.ParseAddr,
  invalid entries counted in a second return value, never an error
  (adapt/dns.go:514-537) — and Run sets the new sticky flag
  dns_brute_resolvers_ignored when brute is enabled and anything was supplied
  (adapt/dns.go:169-183); the flag is set on baseRes before every brute path,
  so wildcard-abort/empty/full merges all preserve it. With brute disabled the
  param is inert like every other dnsx_* param and no flag is raised (pinned).
  The `_ =` discard in runBrute is gone; Run doc block and function comments
  state "NOT honored — native resolver always used". Tests:
  TestDNSBruteResolversParsing (shape table) and
  TestDNSBruteResolversIgnoredFlag (flag set for valid+invalid input, outcome
  not downgraded, native seam still used; no flag when absent or brute
  disabled), adapt/dns_test.go:980-1113. Gates this session: gofmt -l clean;
  go vet ./... ok; go build ./... ok; go test -count=1 ./... ok;
  go test -race -count=1 ./internal/pipeline/adapt ok.

### NEW-32 (LOW) — dns brute truncation flag false-positives at exactly-at-cap (internal/pipeline/adapt/dns.go)
- Status: IN PROGRESS — implemented 2026-08-21, awaiting review (orchestrator closes)
- Reporter: reviewer
- Owner: builder
- Problem: `candidateTruncated := len(candidates) >= dns.MaxBruteHostsPerDomain || wordlistTruncated` (:492) fires when generation produced exactly MaxBruteHostsPerDomain candidates without dropping anything (the generator truncates only above cap) → spurious `dns_brute_truncated` sticky flag.
- Fix: return an explicit cap-hit bool from GenerateBruteCandidates instead of inferring from length.
- Verification: wordlist of exactly the cap size → no flag; above cap → flag.
- Implementation (2026-08-21): GenerateBruteCandidates now returns
  ([]asset.Host, bool) — the bool is true iff a distinct valid candidate was
  actually DROPPED at the cap (brute.go:74-91; core extracted into
  buildBruteCandidates brute.go:95-131 so tests can exercise drop detection
  with small caps — with the current equal 5000/5000 constants the public
  path can never observe a drop). The adapter uses the explicit bool:
  `candidatesCapped` (:562) feeds `candidateTruncated := candidatesCapped ||
  wordlistTruncated` (:593); no length inference anywhere. Tests:
  TestBuildBruteCandidatesCapHit (above cap -> true; exactly at cap,
  duplicates beyond cap, invalid labels beyond cap -> false),
  TestGenerateBruteCandidatesCap now also pins capHit=false at exactly-cap;
  adapter level: TestDNSBruteExactlyAtCapNoTruncationFlag (5000 distinct
  labels -> completed, no flag, brute provably ran) and
  TestDNSBruteAboveCapTruncationFlag (5001 labels -> wordlistTruncated ->
  flag+Truncated), adapt/dns_test.go:1116-1167. Pre-fix proof: restoring the
  old inference line on a scratch copy fails
  TestDNSBruteExactlyAtCapNoTruncationFlag ("Truncated = true ... at exactly
  the cap"). Gates this session: gofmt -l clean; go vet ./... ok; go build
  ./... ok; go test -count=1 ./... ok; go test -race -count=1
  ./internal/dns ./internal/pipeline/adapt ./internal/asset ok.

### NEW-33 (LOW) — atomic writes never fsync the parent directory after rename (internal/cache, internal/report)
- Status: VERIFIED — fixed in 1f4b0c8 (dir fsync best-effort + Validate length checks; reviewer gates green)
- Reporter: reviewer
- Owner: builder
- Problem: cache Put syncs the temp file then renames (cache/cache.go:282-291) with no directory fsync; report writer same (writer.go:148 Sync, :334 Rename). After power loss the rename itself may be lost — degrades to a cache miss / missing report, never corruption, but weakens the documented crash-safe guarantee.
- Fix: best-effort open(dir)+Sync()+Close after rename in both writers, or scope the durability wording in docs.
- Verification: injectable sync hook asserts dir sync invoked; docs updated.
- Work note (builder): fsync fix implemented. Both packages gained `syncDirBestEffort(dir)` (open→Sync→Close; ENOSYS/EINVAL swallowed via `isUnsupportedDirSync` as "filesystem does not support dir fsync"; other errors returned for observability) and an injectable unexported `dirSync` field set at construction (same pattern as FS.beforeSelfHeal). cache/cache.go:104-109 (field), :135 (Open init), :305-311 (Put calls it after successful rename; failure never fails the Put), :314-345 (helper + errno filter). report/writer.go:171-179 (field), :198 (init), :351 (Commit syncs once after all renames), :355-387 (helper mirror — duplicated ~15 lines, no shared parent package). Put/Commit doc comments updated to state the best-effort semantics; README/ARCHITECTURE deliberately untouched (outside this task's allowed file list) — their existing "fsync + atomic rename" wording remains true and now understates the guarantee. Tests: TestPutFsyncsDirectoryAfterRename, TestPutSkipsDirSyncWhenRenameFails, TestPutSucceedsWhenDirSyncFails, TestSyncDirBestEffort (errno table) in cache_test.go; TestFileSinkCommitSyncsDirectory, TestFileSinkCommitSkipsDirSyncWhenCommitFails, TestFileSinkCommitToleratesDirSyncFailure, TestSyncDirBestEffort in writer_test.go. Gates this session: gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/cache ./internal/report ./internal/event ok; go test -race -count=1 (same three) ok; go test -count=1 ./... ok.

### NEW-34 (LOW) — event.Validate allocates a map literal per published event (internal/event)
- Status: VERIFIED — fixed in 1f4b0c8 (dir fsync best-effort + Validate length checks; reviewer gates green)
- Reporter: reviewer
- Owner: builder
- Problem: event.go:105-111 builds a 4-entry map per call; Validate runs on every publish — the hottest observability path.
- Fix: four explicit length checks.
- Verification: existing validation table passes unchanged; benchmark shows the allocation removed.
- Work note (builder): map range replaced with four explicit length checks in deterministic order phase→category→identity→value, identical error text (event/event.go:106-121); comment records why. BenchmarkValidate added (event/bench_test.go:13-29). Measured on go1.26.5/amd64: BEFORE 125.1-128.7 ns/op, 0 B/op 0 allocs/op (the compiler already elides ranging over a small map literal, so the allocation premise is stale on this toolchain); AFTER 6.6-8.8 ns/op, still 0 allocs — ~15x faster, allocation-freedom now guaranteed by construction instead of by compiler optimization, and check order deterministic. Existing validation table (TestValidateRejectsCoreContractViolations etc.) passes unchanged. Gates this session: gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/cache ./internal/report ./internal/event ok; go test -race -count=1 (same three) ok; go test -count=1 ./... ok.

### NF-4 (INFO) — config comment cites a discover --timeout flag that does not exist (internal/config)
- Status: VERIFIED — fixed in 7f2f05a (config.go:168 comment corrected to Discovery.Timeout / scan --timeout)
- Reporter: reviewer
- Owner: docs

### NF-5 (INFO) — OPTIMIZATION.md status column stale: OPT-P0-1/P0-2 implemented+verified but marked OPEN
- Status: VERIFIED — fixed in 7f2f05a (OPTIMIZATION.md P0-1/P0-2 OPEN → VERIFIED)
- Reporter: reviewer
- Owner: docs

### NF-6 (INFO) — SECURITY.md gives no actual reporting contact
- Status: VERIFIED — fixed in 7f2f05a (SECURITY.md:9-11 Contact added)
- Reporter: reviewer
- Owner: docs

### NEW-35 (note) — reviewer observations, non-mandated batch (mixed packages)
- Status: OPEN (note)
- Reporter: reviewer
- Owner: (unassigned)
- Notes (independently actionable; no severity claimed):
  1. chaos unset PDCP_API_KEY reports MISSING though the binary exists (chaos.go:50-54; deliberate per in-code comment) — consider WARN semantics distinguishing not-installed vs not-configured.
  2. httpprobe followed-redirect bodies closed undrained (run.go:706) — defeats keep-alive reuse; bounded io.Copy(io.Discard, ...) before close.
  3. isHeaderCapAbort matches an exact stdlib message (run.go:894-902) — pin with a test asserting current stdlib produces it, so a Go upgrade cannot silently disable truncation detection.
  4. asset.Parameter.Sources grows unbounded while ObservedValues caps at 1024 (parameter.go:146-148, merge.go:327-331) — inconsistent bounding on one record.
  5. runtime execute derives a WithCancel child immediately replaced by WithTimeout (pool.go:447-451) — construct the timeout context directly.
  6. asset/merge.go:119 `out.Method = a.Method` is dead code (out already copies a).
- Verification: n/a (notes; claim individually if promoted).

### NEW-36 (INFO) — Field trial 2: verily.com real-target validation (cmd/ravenrecon)
- Status: VERIFIED (orchestrator, 2026-08-21) — evidence recorded below
- Reporter: master
- Evidence (run: /tmp/opencode/fieldtrial-verily.log, report: /tmp/opencode/ravenrecon-report-verily, cache: ravenrecon-cache-verily):
  - Quality gate LIVE: subfinder 1036 hosts flagged divergence vs others [103,1] — discovery_quality_flagged fired BEFORE corpus ingestion (NEW-22 contract proven on real data; no junk cascade).
  - NEW-21 fix PROVEN live: TUI log shows phase crawl/jsintel/urllive etc. across 901 frames with stages N/unknown; final frame carried full 12-stage table with per-stage counters.
  - 12-stage pipeline incl. crawl (1044 hosts crawled, 36.7s) and urllive (2088 URLs triaged: 14×2xx, 254×3xx observed-not-followed, 174×4xx, 2×5xx, 1644 errors) — OPT-P0-3 working end-to-end.
  - jsintel health-relevant: 500 processed/262 failed truncated (js_fetch_truncated) — P0-4 caps visible.
  - Report honest: live_record_count=2088 in statistics; digest stable a6437a7c…; markdown/html Live URLs section rendered.
  - Known issues for follow-up: (1) urllive cancelled at stage deadline with 1644 errors — needs per-URL timeout tuning or higher concurrency for 2k-URL corpora; (2) amass failed after contributing 0 (known slow-source); (3) urlintel completed 0 (gau/wayback empty for this target — tools ran 0.2s); (4) summary duration_ms still 0 (pipeline bracket wiring deferred from P0-5 — model ready, adapt/report.go single-now pending).
- Verification: run outcome cancelled (urllive deadline), but all v1.5 deliverables demonstrated on an authorized real target.

### NEW-38 (INFO) — Field trial 3: verily.com post-chaos-fix validation (cmd/ravenrecon)
- Status: VERIFIED (orchestrator, 2026-08-21) — chaos fix proven; coverage delta recorded
- Evidence (/tmp/opencode/fieldtrial-verily2.log, report-verily2, fresh cache):
  - chaos now contributes 1,044 hosts (was 1); discover 2,183 processed → corpus 1,067 hosts (+23 net-new vs trial 2, all real: dev-v1.login, granular-uw-* GKE clusters, identity-playground…).
  - urlintel UNLOCKED: gau returned 6,120 URLs in 2m00s partial (per-tool timeout fired as designed — P0-4 working); trial 1 had 0.
  - urllive triaged 8,254 URLs: 182×2xx alive (13× net-new incl. dev-files.verily.com, page.verily.com), 2,370×3xx, 4,066×4xx — still cancelled at stage deadline (1,635 errors): per-URL concurrency tuning remains the open item.
  - Full-funnel proof: crawl 1,067 → techintel 8,254 → jsintel 500/267 truncated → secrentel 205 → priority 9,321 surfaces / 97 groups / 32 paths.
  - Remaining known items: urllive deadline tuning; duration_ms wiring (P0-5 deferred); amass opt-in.

### NEW-39 (MED) — urllive stage deadline starvation on large corpora (internal/httpprobe/urls.go, internal/pipeline/adapt/urllive.go)
- Status: VERIFIED — fixed in 990c810 (triage defaults 5s/20-concurrency; cut-short triage marks Truncated+urllive_truncated)
- Reporter: master (field trial 3, NEW-38)
- Problem: 8,254-URL corpus — 10s per dead host starved the shared stage budget; run cancelled with 1,635 errors and no truncation marker.
- Fix: ProbeURLs triage defaults (RequestTimeout 5s, Concurrency 20, QueueSize=Concurrency when unset; explicit config wins); adapter marks Truncated+flag when the budget fires mid-triage.
- Verification: TestProbeURLsTriageDefaults (blocking transport, ~5s cut), cancellation test asserts flag; all gates + race green.

## Operational warnings (all agents)
### NEW-37 (HIGH) — chaos adapter discarded 1,047 of 1,048 subdomains: v0.5+ output shape unhandled (internal/discovery/chaos.go)
- Status: VERIFIED — fixed in 0dc7611 (parseChaosLines expands subdomains array against queried domain; FQDN elements as-is; legacy shapes preserved; live-verified 1,044 hosts on verily.com)
- Reporter: master (field trial 2, NEW-36)
- Problem: chaos v0.5.2 -json emits ONE object {"domain":"<apex>","subdomains":[...],"count":N}; the adapter read only "domain" → apex-only. Real cost: verily.com corpus was built from subfinder's 1,036 hosts alone; every unique chaos find (e.g. wildcard.verily.com, grudge-pandemic.verily.com) was missing from dns/probe/urllive.
- Fix: parse subdomains array; expand labels against domain; FQDN elements as-is; legacy + text fallbacks kept.
- Verification: TestChaosParseSubdomainsArray/FQDNNotDoubled/LegacyApexOnly hermetic; live chaos-only discover run = 1,044 hosts.

### NEW-39 (MED) — urllive stage deadline starvation on large corpora (internal/httpprobe/urls.go, internal/pipeline/adapt/urllive.go)
- Status: VERIFIED — fixed in 990c810 (triage defaults 5s/20-concurrency; cut-short triage marks Truncated+urllive_truncated)
- Reporter: master (field trial 3, NEW-38)
- Problem: 8,254-URL corpus — 10s per dead host starved the shared stage budget; run cancelled with 1,635 errors and no truncation marker.
- Fix: ProbeURLs triage defaults (RequestTimeout 5s, Concurrency 20, QueueSize=Concurrency when unset; explicit config wins); adapter marks Truncated+flag when the budget fires mid-triage.
- Verification: TestProbeURLsTriageDefaults (blocking transport, ~5s cut), cancellation test asserts flag; all gates + race green.

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
