# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-56).
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
- SIBLING SIGHTING (orchestrator, 2026-08-21): TestProbeTLSMetadataCapture
  failed once during a 9-package concurrent -race run
  (`Err:readLoopPeekFailLocked: %!w(<nil>)`, want completed 400 got
  failed/other); 5/5 passes in isolation under -race immediately after; the
  working-tree diff at the time did not touch httpprobe; full non-race suite
  green same session. Same load-order/TLS-timing family — fold into this
  entry's eventual determinism investigation.

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

### NEW-45 (LOW) — comma-only dnsx_resolvers value raises no ignored-flag (internal/pipeline/adapt/dns.go)
- Status: OPEN
- Reporter: reviewer (NEW-27..32 closure review, 2026-08-21)
- Owner: (unassigned)
- Problem: a supplied-but-empty resolvers value (e.g. `dnsx_resolvers=","` or
  `",,"`) passes the `TrimSpace != ""` guard, splits into only empty segments,
  and yields `(nil, 0)` from dnsBruteResolvers (adapt/dns.go:520-537) → no
  `dns_brute_resolvers_ignored` flag although an operator supplied something.
  Morally identical to the whitespace-only case the spec exempts; builder
  disclosed the corner in the commit message.
- Fix: have dnsBruteResolvers also report `supplied = trimmedRaw != ""` and set
  the flag on `supplied` regardless of per-entry outcomes.
- Verification: table row `","`/`",,"` → flag set; existing rows unchanged;
  gates green.

### NEW-47 (INFO) — ctx firing during the IsWildcard probe reports brute stage completed with no marker (internal/pipeline/adapt/dns.go)
- Status: OPEN
- Reporter: reviewer (NEW-27..32 closure review, 2026-08-21)
- Owner: (unassigned)
- Problem: if the stage context fires during the IsWildcard probe, runBrute
  returns `({}, false, false)` (adapt/dns.go:547-553) and Run falls through to
  bare baseRes (:218-225): opt-in brute silently skipped while the stage can
  record `completed`, no sticky marker. Runner-level teardown observes the
  cancellation elsewhere, so impact is minimal. Pre-existing, not introduced
  by NEW-32.
- Fix: surface a `dns_brute_skipped_cancelled`-style sticky flag (or fold to
  partial/cancelled per the mapping table) when the probe context has fired.
- Verification: fake resolver blocking past deadline with brute enabled →
  marker present; regression fails pre-fix.

### NEW-48 (LOW) — v1.5 OPT-P2-1 remainder: scan --help does not document per-tool timeouts; no --dry-run (internal/cli)
- Status: OPEN
- Reporter: master (ROADMAP v1.5 close-out, 2026-08-21)
- Owner: (unassigned)
- Problem: ROADMAP v1.5's OPT-P2-1 line required "scan --help documents
  per-tool timeouts + --amass opt-in + scan --dry-run for effective
  timeouts". Landed: per-tool timeout exists as config Discovery.Timeout
  (config.go:149) but scan --help doesn't surface it; --amass opt-in was
  resolved as WON'T FIX via NEW-41 (exclusion via --sources); --dry-run does
  not exist (repo grep clean). The remainder must not be lost with the v1.5
  flip to Complete.
- Fix: add per-tool-timeout documentation to scan usage text; implement
  `scan --dry-run` printing effective stage bounds/timeouts without running,
  or descope explicitly with a decision record.
- Verification: scan --help shows the timeout documentation; dry-run smoke
  prints effective config; gates green.

### NEW-54 (MED) — `go test -race ./internal/httpprobe/` intermittently fails on clean HEAD across varying tests (internal/httpprobe)
- Status: OPEN
- Reporter: builder (OPT-P2-4 batch, NEW-49 batch 3b) + orchestrator sighting
  during batch-3a race gate
- Owner: (unassigned)
- Problem: under full-package -race load, different probe tests fail
  intermittently with transport-level errors (observed:
  TestProbeTLSMetadataCapture `readLoopPeekFailLocked: %!w(<nil>)`;
  builder's clean-HEAD reproduction at 8191cf9: TestProbeSpoofTLSNoMisclassification,
  TestProbeSpoofHeaderCapNoMisclassification, TestProbeCompletedHTTPS — 3-of-4
  stashed runs failing a DIFFERENT test each time, passing on rerun). All pass
  in isolation. Same family as NEW-4 (TestProbeCompletedHTTPS). Blocks race-
  gate trust for the package: a red -race run cannot be distinguished from a
  real regression without reruns.
- Fix: capture full `-race -v` output across repeated runs to identify the
  shared fixture/sensitivity (suspects: loopback TLS listener connection
  reuse under load, shared transport keep-alives, or test ordering);
  make the affected tests deterministic (per-test transports, DisableKeepAlives)
  or pin the trigger.
- Verification: 20+ consecutive `go test -race -count=1 ./internal/httpprobe/`
  full-package runs green.

### NEW-55 (LOW) — BenchmarkMatchIndicatorAllKinds exercises no TLS/DNS branches (internal/techintel)
- Status: OPEN
- Reporter: reviewer (OPT-P2-4 review, NEW-49 batch 3b)
- Owner: (unassigned)
- Problem: benchFullObservation sets no TLS/DNS block, so the TLS issuer/CN/
  ALPN and DNS-CNAME lowered-slice branches execute zero iterations — an
  allocation regression reintroduced only in those branches would not move
  the benchmark. Correctness remains covered by unit tests; coverage nicety.
- Fix: add a synthetic TLS/DNS block to the bench fixture.
- Verification: benchmark iterates those branches (assert ≥1 match fires from
  each family); numbers recorded.

### NEW-51 (LOW) — adapt/doc.go overstates marker exposure as "the report" (internal/pipeline/adapt/doc.go)
- Status: OPEN
- Reporter: reviewer (OPT-P1-4 review, NEW-49 batch 1)
- Owner: docs
- Problem: the "Asset-level truncation markers" section says flags are
  "exposed through the report"; rendered report artifacts (internal/report
  html/markdown) surface neither stage sticky flags nor RunReport.Truncated —
  actual exposure is RunReport.Stages[].StickyFlags + the CLI stage summary
  line. Phrasing copies pre-existing house comments, so not a regression.
- Fix: one-line reword in the next docs pass: "exposed via
  RunReport.Stages[].StickyFlags, RunReport.Truncated, and the scan summary's
  per-stage flags= rendering".
- Verification: wording matches run.go/scan.go behavior; no code change.

### NEW-52 (LOW) — engine-level warm-run pin for marked assets missing (internal/detect, internal/httpprobe)
- Status: OPEN
- Reporter: reviewer (OPT-P1-4 review, NEW-49 batch 1)
- Owner: (unassigned)
- Problem: OPT-P1-4 round-trip coverage is asset-level (marshal→unmarshal +
  buildResult), not the full engine chain (storeProbe→decodeStoredProbe→
  replay; encodeStoredFindings→decodeStoredFindings→validateFinding). Every
  link verified safe by inspection, but the load-bearing link — NewFinding's
  in-place normalization preserving Truncated through validateFinding's
  canonical round-trip — is unpinned: a future refactor of NewFinding to
  rebuild-style normalization would silently reject cached records containing
  marked findings.
- Fix: add an engine-level warm-run test injecting a crafted cache record
  containing a marked Finding (and ideally a marked TLSCertificate) and
  asserting the record is served and the sticky flag fires on the warm run.
- Verification: test fails if NewFinding stops preserving the field; gates
  green.
### NEW-50 (MED) — httpprobe DialTLSContext leaves ServerName empty for IP-literal targets: local config rejection recorded as a TLS negative without any handshake (internal/httpprobe/run.go)
- Status: OPEN
- Reporter: builder (OPT-P1-5 batch, NEW-49) + reviewer verification against
  go1.26 toolchain source
- Owner: (unassigned)
- Problem: httpprobe's custom DialTLSContext mirrors the old pattern of
  setting ServerName only when `net.ParseIP(host) == nil`. crypto/tls rejects
  a verifying config with empty ServerName outright (handshake_client.go),
  so an https://<IP-literal> probe fails LOCALLY before any packet is sent
  and classifies as a TLS-relevant negative — a fabricated, cacheable
  completed/tls-style record with no server interaction (same §0.6 honesty
  shape as the hostile-string misclassification fixed in jsintel this
  batch). net/http's own addTLS sets ServerName unconditionally when empty;
  jsintel's new DialTLSContext deliberately deviates from httpprobe and
  documents why (internal/jsintel/fetch.go ~592-600).
- Fix: assign ServerName unconditionally when empty in httpprobe's dialer
  (mirroring net/http addTLS + the jsintel implementation), plus a
  discriminating positive-path test (loopback cert with 127.0.0.1 IP SAN)
  proving an IP-literal probe completes a REAL handshake.
- Verification: new test fails pre-fix (fabricated tls negative) and passes
  post-fix; existing httpprobe TLS tests unchanged; gates + race green.

### NEW-53 (LOW) — remaining dedup migrations after OPT-P2-6 single homes landed (httpprobe/crawl/pipeline/urlintel-adapt/jsintel-adapt)
- Status: OPEN
- Reporter: builder + reviewer (NEW-49 batch 3a)
- Owner: (unassigned)
- Problem: OPT-P2-6 created the single homes asset.InDomain
  (internal/asset/scope.go) and discovery.VersionPattern/ExtractVersion
  (internal/discovery/version.go) but only migrated the dns + discovery/detect
  copies (file allowlist). Still duplicated: inDomain at httpprobe/scope.go:52,
  crawl/katana.go:450, pipeline/scope.go:22 (the latter two typed
  (asset.Domain, asset.Host) WITH empty-input guard — drop-in safe since F1
  added the guard to asset.InDomain); versionPattern/extractVersion at
  urlintel/adapt/tool.go:273 + jsintel/adapt/tool.go:393 (both already import
  internal/discovery). Separately: validateScope/validateInputHost triplicates
  (dns/httpprobe/discovery) differ by pinned error-message prefixes — needs a
  cross-package error-context decision before any unification.
- Fix: migrate the five mechanical copies; decide the validateScope question
  separately (likely document-don't-unify).
- Verification: existing tests pass unmodified; grep shows a single non-test
  definition per concept; gates + race green.

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
