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

## Recently closed — v1.2.5 SDK freeze (uncommitted, pending merge)

Wave-1 + T5 work closed by the orchestrator with evidence from this session's
actual gate runs. Final full-milestone re-review happens at T9 before commit.

- NEW-5 (HIGH) — VERIFIED: T1-T3 landed (ValidateRule/ParseRuleVersion/12
  bounds consts in rule.go; Registry.Seal() in registry.go; APIMajor=1,
  APIMinor=0, CheckAPIVersion in api.go; sdk_test.go). Reviewer APPROVE WITH
  NITS; the nit (NEW-6) fixed and verified. Orchestrator ran
  `go test ./internal/detect/` (ok), `go vet` (ok), `-race` (ok) after all
  wave-1 changes.
- NEW-6 (MED) — VERIFIED: readonly race closed (atomic.Bool + re-check under
  the write lock in registry.go; registry_race_test.go regression). Builder
  proved the test fires on pre-fix code; orchestrator ran
  `go test -race ./internal/detect/` (ok) and
  `-run 'TestRegistrySealRegisterRace|TestRegistrySeal' -count=3` (ok).
  Note: internal/report/registry.go carries the same inherited pattern —
  follow-up scheduled when report is next touched (out of milestone scope).
- NEW-8 (HIGH) — VERIFIED: T5a surface_snapshot_test.go (790 lines) +
  testdata/api_v1.golden — stdlib-only AST snapshot of the Level-1 surface
  with Level-2/3 exclusions documented and drift demonstrated (const value
  change, symbol rename) during development; T5b behavior_contract_test.go
  pins all 9 contracts. Builder gates all green; orchestrator re-ran the
  package (`-count=1` ok), the snapshot test (PASS), and the race suite
  (ok). Golden regenerable only via explicit `-update` flag. Incident note:
  T5a's builder briefly restored rule.go from HEAD during a drift demo;
  restore verified byte-exact via sha256 (0b6829a6) against the pre-demo
  state. FINAL-REVIEW FIX (post-sign-off, in same changeset): golden
  de-overpinned — now pins only exported symbols, exported fields
  (name+type+tag), const values, and signature TYPES (param/result names and
  unexported fields dropped, arity preserved); regenerated in the same
  change (7216 bytes, sha256 034f292a; old: 7301 bytes, abe5dd3e). Proven by
  live demos: cosmetic param rename (dctx→c) and internal-field rename
  (readonly→frozen) PASS; exported-symbol rename still FAILS.

- NEW-7 (HIGH) — VERIFIED: T4 examples pack (internal/detect/examples:
  doc.go, rules.go, rules_test.go + internal/detect/example_test.go).
  Review chain: first review APPROVE WITH NITS (MEDIUM: degree rule could
  emit unobserved relationship-node subjects — fixed with observed-set
  guard mirroring normalizeSnapshot, regression
  TestDegreeIndexSkipsUnobservedNodes proven failing pre-fix; LOW:
  index-coupled dependency wiring — fixed via variadic newRule deps; doc
  NITs applied). Re-review APPROVE WITH NITS (LOW: degree rule logic
  changed without version bump — fixed via explicit version parameter,
  degree rule now 1.0.1; INFO doc phrasing applied). All gates green incl.
  TestSDKAPISurfaceSnapshot (pack not part of the golden) and
  TestPackRulesValidate. Orchestrator verified gates after each round.

- NEW-9 (MED) — VERIFIED: T6 semantic compat regression landed —
  examples/compat_test.go (TestSemanticCompat, LCS-bounded unified diff,
  opt-in `-update` regeneration, atomic golden writes, assertColdRunShape
  guard preventing broken runs from being promoted) + examples/testdata/
  api_v1_report.golden (13,853 bytes, pins outcome + all 6 rule results +
  all 12 findings with every field + status counts + levels + audit-rule
  logs). Drift demonstrated (evidence-value change → clean per-line FAIL)
  and reverted byte-exactly (sha256-verified); golden byte-stable across
  two `-update` runs. All gates green incl. `-race` and the surface
  snapshot.
- NEW-10 (MED) — VERIFIED: T7 docs landed — ARCHITECTURE.md "Detection
  framework → SDK contract": lifecycle diagram (lines 2477-2521, Rule →
  Registry → Run → normalizeSnapshot → cache-before-execute → Report,
  honest note: priority is never a severity claim), Rule authoring
  contract (real bounds, Version-bump citing rule.go), Finding contract
  (validateFinding's five checks, observed-corpus rule with both pack
  demonstrations), pack story (explicit loading, auto-detects nothing),
  executable documentation naming real tests.
- NEW-11 (MED) — VERIFIED: T8 policy landed — ARCHITECTURE.md "SDK
  stability policy" (line 2672): 3-level policy (L1 frozen forever with
  named symbols; L2 after pipeline validation; L3 experimental incl.
  BenchmarkDetector/BenchResult), versioning contract (api.go semantics),
  reopening criteria (concrete failing need → proposal naming symbols →
  maintainer approval → BOTH goldens regenerated + CheckAPIVersion bump in
  the same change) naming the mechanically-enforced gates.
  ROADMAP.md:367 ticked. Note: T7's docs reference the semantic-compat
  test honestly as landing with this milestone.

## Open items

### NEW-12 (MED) — v1.2.5 T9: roadmap/README/AGENTS sync + final verification
- Status: IN PROGRESS (T9 landed — ROADMAP checklist fully ticked, README
  SDK paragraph, AGENTS §2 footnote; final-review NITs closed by builder:
  golden de-overpinned, ROADMAP table row, schema-bump carve-out sentence;
  full-milestone reviewer sign-off APPROVE WITH NITS. Remaining: commit
  pending user decision; close this entry at commit time)

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

## Recently closed — TODO board sweep (uncommitted, pending merge)

The six open board items from the v1.0 audit changeset were researched,
fixed, and closed this session; reviewer APPROVE after one re-review cycle
(MEDIUM NEW-1 corner closed: canonical-form refusal). Summary:

- M-1 (tests) — VERIFIED: rawResponder wired into two end-to-end spoof
  regressions (audit_test.go): hostile `tls:fake` status line and a
  no-colon `server response headers exceeded` header line both classify
  ProbeFailed/ReasonOther on the REAL transport; each test asserts the
  spoof string is present in the surfaced error (fails on pre-fix
  text-matching code by construction). Positive controls unchanged.
- M-2 (tests) — VERIFIED: probeKey domain pinning — key inequality across
  declared domains, equality for identical inputs, exact-shape pin, and a
  behavioral test proving a broader-scope run re-executes
  (Executed=true/Cached=false, followed hop in chain, request count 3)
  instead of being served the narrow-scope record.
- NEW-1 (LOW) — VERIFIED: decodeStoredURL refuses any stored URL asset
  (record URL + every endpoint URL) whose Original is non-empty and
  non-canonical (covers parseable AND unparseable credential-bearing
  Originals; parseRawURL guarantees no legitimate path stores non-canonical
  Originals). Regression table rows + end-to-end self-heal subtest; the
  unparseable-form row was proven to fail on the pre-fix parse-only check.
- NF-1 (INFO) — WON'T FIX: `admin/openapi.yaml` never existed in this repo
  (no directory, no git history, not gitignored); repo-wide grep for
  `0.5.0`/`v0.5.0` (excluding this file) is already clean. Nothing to
  change; entry was stale.
- NF-2 (INFO) — VERIFIED: already fixed in the audit changeset itself —
  techintel/doc.go's Cache section now lists operation, identity,
  SchemaVersion, db_digest, and the sources bitmask, matching techKey
  (record.go:26-36); the entry's ~25-34 line ref predates the fix.
- NF-3 (INFO) — VERIFIED: MaxHeaderBytes comment (run.go:36-43) now
  acknowledges the strict-exceed abort and the exact-equality
  isHeaderCapAbort classification (never substring; safe degradation).

Left open by design: NEW-3 (DEFERRED) and NEW-4 (new INFO flake entry —
TestProbeCompletedHTTPS rare pre-existing flake seen once under -race,
reproduced at HEAD; follow-up tracked).

## Recently closed — v1.0 audit changeset (committed)

All 14 audit findings closed; senior review APPROVE with 12/14 fully closed
and failing-on-pre-fix regressions. M-1 and M-2 were code-verified (reviewer
traced the sentinel wiring and the domain key plumbing); their audit-mandated
regression tests were missing at commit time and landed later in the TODO
board sweep — see "Recently closed — TODO board sweep" above. Summary:

- H-1 credential echo — sanitizeLocation covers both raw-echo branches;
  terminal-response Location also redacted in observe.go.
- H-2 outcome-vocabulary amendment — AGENTS.md §0 item 6, verified against
  the techintel/urlintel sticky flag chains end-to-end.
- M-1 classification — tlsHandshakeError sentinel at DialTLSContext, typed
  TLS set incl. tls.RecordHeaderError, exact-equality header-cap abort,
  no text fallback.
- M-2 cache key — declared domain in probeKey; narrow records unreachable
  by broader-scope runs.
- M-3 urlintel userinfo — redacted at the single ingest construction point.
- M-4 secrentel diagnostics — redactedCandidateID at all four rejection sites.
- M-5 jsintel content binding — AnalyzedHash cross-validated; stale never
  served; silent self-heal.
- M-6 jsintel redirects — non-http(s) targets observed-not-followed.
- M-7 detect fingerprints — full field coverage + provenance, SchemaVersion 2,
  old records self-invalidate.
- M-8 techintel NaN — rejected at load and decode, neutralized in
  deriveConfidence.
- M-9 techintel digest — fingerprint-DB content digest in cache keys,
  computed once per run.
- L-10 report — zero-byte render parts rejected + self-heal.
- L-11 report — mdEscape doubles backslashes before pipes.
- L-20 version 1.0.0 + UA bump; L-21 CI pinned to go.mod; README/
  ARCHITECTURE/AGENTS synced.
