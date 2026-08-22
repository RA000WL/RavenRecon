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

- Batch D (memory/bench baselines + comparator) IMPLEMENTED + REVIEWED
  (builder sessions ses_fdab1e38cffeajqRzxUgNvEeI8 +
  ses_fda343727fferNXxxfMWx2vQyj; reviewer APPROVE after one fix round,
  2026-08-22): structural tier — bounds_c4_test.go drift detectors pinning
  every C-4 constant where it lives (discovery/jsintel/pipeline/httpprobe/
  urlintel/techintel/secrentel/detect/report — all 9 packages); byte tier —
  post-GC HeapInuse retained-heap guards for discovery (Δ≈0 B vs 32 MiB
  ceiling) and jsintel (Δ≈11.2 MiB vs 32 MiB) with exact race-skip via
  build-tag pair; NO unbounded growth found. Baselines:
  testdata/bench/{event,techintel,priority,urlintel,jsintel,httpprobe}.txt
  (-count=10 -benchmem; asset substituted by urlintel — zero benchmarks).
  Comparator: cmd/benchgate (stdlib-only), median B/op + allocs/op >25%
  threshold fails exit 1, ns/op advisory-only; 16 unit tests; a new side
  recorded without -benchmem now FAILS LOUDLY instead of passing vacuously
  (review HIGH-1 fixed; NaN/±Inf thresholds rejected exit 2).
  Shared golden support landed: internal/golden (atomic write, LCS diff,
  -update; TEST-SUPPORT ONLY doc constraint) with detect migrated as second
  consumer.
  DEFERRED TO ACCEPTANCE BATCH (review HIGH-2 resolution): fixtures/ +
  internal/pipeline/adapt/fixture_manifest.go land TOGETHER with their
  consumer (acceptance tests materializing through T4 harness seams) plus
  parser tests — never commit the manifest format standalone.
  Queued into D7 docs wave (review INFO-1): C-4 table soft corners —
  pipeline MaxDocumentBytes self-justification and techintel HTML-cap
  wording deserve explicit doc lines.

- Batch E (clean-profile fixtures → goldens) IMPLEMENTED + REVIEWED
  (builder sessions ses_fd696227effeKav1ggph44mtXF verification/fixes +
  ses_fd67b47e1ffeY9992V4okwUJYo review-condition fixes; reviewer APPROVE,
  2026-08-22): fixture_manifest.go gains resolveProfilePath containment
  (LOW-2 hardened; lexical-only caveat documented); parser/loader tests
  cover every rejection branch incl. the previously-untested parse-failure
  wrap; acceptance_clean_test.go materializes fixtures/clean-baseline
  through the EXISTING T4 seams (fixed clock, fresh temp-dir cache, loopback
  JS serving) producing normalized RunReport golden + 12 stage-named goldens
  + markdown report golden under internal/pipeline/adapt/testdata/
  acceptance_clean/ via shared internal/golden -update semantics; redaction
  scrub order made deterministic (longest-first, 64-iteration pin).
  Evidence: determinism 3× (+5× by reviewer), perturbation swap fails
  exactly the two swapped stage subtests (stage name IS the failing subtest),
  -update round-trip byte-stable, hermeticity proven with PATH=/nonexistent,
  -race green. Review conditions applied: timestampMaskKeys completed
  (StartedAt/EndedAt/At/started_at/ended_at/not_before/not_after),
  lexical-containment doc sentence. Staging note: ONLY clean-baseline lands
  with this batch — messy-contradictory/ + hostile-adversarial/ stay
  untracked until their consuming batch (F); HIGH-2 resolved by consumer +
  tests landing together with the format.

- Batch F (messy/hostile profiles + D6) IMPLEMENTED + REVIEWED
  (builder ses_fd65a83beffes97LOKLGsrjXVq; reviewer APPROVE 2026-08-23; hardening
  builder ses_fd63e5b99ffeD8zW78gYeoaN8a): extends cannedTransport with byPath +
  oversized (path-precedence RoundTrip, deterministic >1/2 MiB bodies), merges
  dns_poison after clean DNS (poison overwrites via fakeResolver), handles
  body_oversized / oversized flags; acceptance_profiles_test.go materializes
  messy-contradictory + hostile-adversarial via same seams → normalized
  RunReport + 12 stage-named goldens each under
  internal/pipeline/adapt/testdata/acceptance_{messy,hostile}/; interaction_test.go
  adds D6: a) corrupt-cache recovery (truncated JSON/wrong-schema/empty across
  dns.resolve/http.probe/passive-discovery, self-heal proven via DeepEqual +
  SchemaVersion rewrite), b) sticky truncation cold→warm (65 answers → partial
  + Truncated/dns_answers_truncated, warm hit vs re-exec, Duration-zero DeepEqual),
  c) mid-run cancellation across all 12 stages (before_0..12 + during_0..11 +
  resume_after_cancel, OutcomeCancelled, bounded pool drain, resume DeepEqual).
  Evidence: 3× determinism each profile, perturbation swap fails exactly swapped
  stages, -update byte-stable, hermetic PATH=/nonexistent + loopback, -race green
  (21s). Review hardening applied: parens guard, deterministic corrupt filter
  (fail instead of fallback), event-bus wait vs Sleep + sync.Once guards.

- D5 bench-gate CI IMPLEMENTED + REVIEWED
  (builder ses_fd65f063cffe9px1onHpShV05p; reviewer APPROVE 2026-08-23):
  extends .github/workflows/ci.yml with bench-gate job (needs:test,
  continue-on-error:true, timeout 25m, checkout@v4 + setup-go@v5 via
  go-version-file); regenerates 6 packages with exact README commands
  (-count=10 -benchmem; urlintel filtered, httpprobe grep -v FAIL both sides)
  and runs cmd/benchgate per package (exit 1 regression, ns/op advisory).

### NEW-57 (MED) — BenchmarkIngestMillion fails its own assertion: ~1.8% store shortfall at 1M lines (internal/urlintel)
- Status: VERIFIED — implemented (debugger, 2026-08-23) and reviewer APPROVE 2026-08-23: root cause was inode exhaustion on 2^20-inode tmpfs (1M entry FILES + 65k shard dirs) silently absorbed — Puts failed with ENOSPC, only per-entry Err captured, run returned nil. Fix: (1) production record.go storeURL now surfaces cache-put failures as bounded run diagnostics via recordCacheDiagnostic (mirroring read side, cancellation filtered); (2) bench_test.go capacity arithmetic volumeFitsInodes + shardDirBound + inodeHeadroom with pre-flight millionCacheDir fallback to user cache dir (disk-backed dynamic inodes) and loud skip when no volume qualifies; assertNoEntryDiagnostics pins honesty; header documents ~50 min wall time. Honesty guaranteed by dual channels (entry Err + run diagnostics). Baseline re-inclusion deferred: workload takes ~50 min and is -short-gated; urlintel.txt correctly stays without the million line (benchgate handles missing). Archived to TODO.closed.md on next close.
- Reporter: builder (v1.7 batch D, NEW-56)
- Owner: debugger
- Problem: internal/urlintel/bench_test.go:225 BenchmarkIngestMillion
  observes {Lines:1000000 Canonicalized:1000000 Extracted:1000000
  Stored:981506 Reads:1000000 Malformed:0} and fails wanting a full cold
  pass — 18,494 stores short (~1.8%) with zero malformed lines. Pre-existing
  (reproduced during baseline recording; no production/test code changed).
  Candidates: retained-entry cap interaction, cache-store failures at scale,
  or a flaky assumption in the assertion. Excluded from urlintel.txt baseline
  until fixed; re-include afterwards (~1 min/iteration).
- Fix: root-cause the store shortfall (instrument which records fail to
  store and why); fix or correct the benchmark's expectation if it encodes a
  wrong invariant; add regression coverage.
- Verification: benchmark passes deterministically (3+ consecutive runs);
  included in testdata/bench/urlintel.txt.

### NEW-58 (LOW) — C-4 drift detectors missing for detect/report caps (internal/detect, internal/report)
- Status: VERIFIED — implemented (builder session ses_fda40ee7cffeIG9invXq9imvcA)
  and orchestrator-verified 2026-08-22: constants verified code↔doc before
  pinning (detect.maxFindingsPerRun=4096, report.maxModelPerKind=100_000);
  perturbation evidence shows each detector fails naming constant, actual,
  expected, and doc source; gates green. Archived to TODO.closed.md.
- Reporter: builder (v1.7 batch D, NEW-56)
- Owner: builder
- Problem: every other C-4-documented cap gained an in-package bounds_c4_test.go
  drift detector in batch D; detect (maxFindingsPerRun=4096) and report
  (maxModelPerKind=100000) did not because those packages were scope-restricted
  mid-task. Their constants are unexported, so detectors must be in-package.
- Fix: add bounds_c4_test.go to both packages pinning the documented values.
- Verification: tests pass; constants drift would fail them.

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
