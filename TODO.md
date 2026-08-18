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
  testdata/api_v1.golden (7301 bytes, sha256 abe5dd3e) — stdlib-only AST
  snapshot of the Level-1 surface with Level-2/3 exclusions documented and
  drift demonstrated twice (const value change, symbol rename) during
  development; T5b behavior_contract_test.go pins all 9 contracts. Builder
  gates all green; orchestrator re-ran the package (`-count=1` ok), the
  snapshot test (PASS), and the race suite (ok). Golden regenerable only via
  explicit `-update` flag. Incident note: T5a's builder briefly restored
  rule.go from HEAD during a drift demo; restore verified byte-exact via
  sha256 (0b6829a6) against the pre-demo state.

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

### NEW-7 (HIGH) — v1.2.5 T4: examples pack + Example funcs (internal/detect/examples)
- Status: IN PROGRESS (implemented; review pending)
- Reporter: master
- Owner: builder
- Problem: v1.2.5 requires SDK examples that compile AND run, and at least one
  internal rule pack loading through the SDK with zero special-case code —
  while "no rules ship with the framework" stays true.
- Fix: landed — `internal/detect/examples` (package examples):
  `Rules() ([]detect.Rule, error)` opening with `CheckAPIVersion(1, 0)`;
  6 mechanical rules (`example.` IDs, information/discovery only) covering all
  7 Context domains + dependency pair (Registry.Validate graph) + Config/Logger
  rule + empty-output rule; `ExampleDetector`/`ExampleRegistry_Register`/
  `ExampleRun` in package detect_test (first external test package — compiler
  proves exported-only usage).
- Verification: examples/rules_test.go — validate → register → Run with real
  cache → second run all-Cached hits; deterministic reports; content-policy
  test. Example funcs run under `go test -run '^Example'`. Gates on
  `./internal/detect/...`.
- Review round (builder): reviewer APPROVE WITH NITS — all four closed in the
  examples pack only (rules.go, rules_test.go, doc.go):
  - MEDIUM: degreeIndexDetector emitted findings about relationship endpoints
    the corpus never observed (relationships validate for canonical form
    only; normalizeSnapshot's observed set excludes relationship endpoints)
    → validateFinding rejected the subject and the rule failed loudly.
    Fixed: observed set rebuilt from the Context's observed collections
    (Assets + evidence identities/sources + technologies + secrets +
    javascript + endpoints, mirroring context.go normalizeSnapshot);
    unobserved nodes skipped. Documented in the rule Description and doc.go
    as the pack's second observed-corpus demonstration. Regression:
    TestDegreeIndexSkipsUnobservedNodes — full pipeline on a legal snapshot
    whose relationship cites an unobserved IP; fails pre-fix (verified:
    "finding subject ip:192.0.2.99 was not observed in the corpus",
    outcome incomplete), passes post-fix (1 degree finding for the observed
    host only).
  - LOW: rules[1].Dependencies = []string{rules[0].ID} index-coupled wiring
    replaced by explicit named linkage — newRule gains variadic deps, the
    degree rule declares ruleAssetsCensus by ID constant at construction;
    TestPackRulesValidate still pins the graph.
  - Doc NITs: "One rule per Context domain family" rephrased (six rules,
    seven domains — audit covers secrets+javascript); usage sketch now points
    to ExampleRun for the compilable version.
  - Gates run by builder: gofmt clean; go test ./internal/detect/examples/ ok;
    go test -count=1 ./internal/detect/ ok (incl. TestSDKAPISurfaceSnapshot);
    go vet ./internal/detect/examples/ ./internal/detect/ ok;
    go test -race ./internal/detect/... ok; go build ./... ok;
    go test -count=1 ./... ok (all 22 packages).

### NEW-9 (MED) — v1.2.5 T6: semantic compat regression (internal/detect)
- Status: IN PROGRESS
- Reporter: master
- Owner: builder
- Problem: shape tests catch compile breaks only; semantic drift (Context
  behavior, output changes) must also fail CI — the maintainer's "run it
  forever" compat gate.
- Fix: compat test reusing the examples pack: fixed snapshot → Run →
  deterministic report marshaled and diffed against a pinned golden
  (testdata/api_v1_report.golden); any output drift fails CI.
- Verification: green on clean tree; a deliberate output change fails; gates
  on `./internal/detect/...`.

### NEW-10 (MED) — v1.2.5 T7: SDK docs — pack-author guide + lifecycle diagram (docs)
- Status: OPEN
- Reporter: master
- Owner: docs (builder fallback — docs agent unavailable)
- Problem: v1.2.5 checklist requires developer documentation; pack authors
  need the Rule contract, finding contract, cache-key semantics, and the
  lifecycle picture.
- Fix: lifecycle diagram (Rule → Registry → Snapshot → Run → Finding →
  Report) in ARCHITECTURE.md "Detection framework → SDK contract" subsection;
  pack-author guide (examples/doc.go or dedicated docs file); Level-1 freeze
  + CheckAPIVersion usage documented.
- Verification: docs reference real symbols and test names; gates green.

### NEW-11 (MED) — v1.2.5 T8: SDK stability policy + reopening criteria (docs)
- Status: OPEN
- Reporter: master
- Owner: docs (builder fallback — docs agent unavailable)
- Problem: maintainer requires a formal 3-level stability policy (L1 frozen
  forever; L2 frozen after pipeline validation; L3 experimental) and written,
  testable reopening criteria.
- Fix: policy in ARCHITECTURE.md + ROADMAP.md v1.2.5; reopening = concrete
  failing need (pack inexpressible on the frozen surface) + proposal naming
  symbols + maintainer approval + golden regeneration in the same change;
  testable half = golden test + CheckAPIVersion test.
- Verification: policy names the real gates (api_v1.golden test,
  CheckAPIVersion); ROADMAP v1.2.5 checklist updated; tests green.

### NEW-12 (MED) — v1.2.5 T9: roadmap/README/AGENTS sync + final verification
- Status: OPEN
- Reporter: master
- Owner: master
- Problem: ROADMAP v1.2.5 still "Status: planned"; README detect section lacks
  the SDK-freeze mention; AGENTS.md §2 needs the examples-pack footnote.
- Fix: ROADMAP v1.2.5 checklist ticks + status; README one paragraph; AGENTS.md
  §2 footnote ("no rules ship with the framework; the module ships
  internal/detect/examples"); full-gate verification from clean checkout
  (gofmt, go test ./..., go vet ./..., go build ./..., go test -race on
  changed packages) + reviewer sign-off; then commit.
- Verification: all gates green; reviewer APPROVE; board entries moved to
  VERIFIED by orchestrator.

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
