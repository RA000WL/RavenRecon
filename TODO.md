# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-13).
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
- Status: IN PROGRESS (T1/T2a/T2b VERIFIED; T2c VERIFIED — review APPROVE
  WITH NITS, all nits closed + gates re-run; T2d VERIFIED — re-review
  APPROVE WITH NITS, all findings closed, gates re-run; T3a stage events
  VERIFIED — review APPROVE (7/7 findings closed, gates re-run), committed
  ad791c3; T3b results channel VERIFIED — review APPROVE WITH NITS
  (FIND-1 LOW + 3 INFO closed in a nit round, gates re-run), committed
  this session)
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
- Status: OPEN
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
- Fix (when T3c is scoped): decide the document-content source before
  wiring the secrentel adapter — e.g. a pipeline document channel or a
  content-bearing JavaScript field (bounded, honestly truncated) produced
  by the T3d jsintel adapter; the T3b channel shape is final and should
  not be re-opened for this.
- Verification: n/a while open.

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
