# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-117).
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

> **2026-08-23 cleanup wave c — VERIFIED:** NEW-91 and both NEW-73 residuals
> fixed (two builders), merged gates green, orchestrator-verified. NEW-91/73/92
> archived to TODO.closed.md. Open board at that time held only DEFERRED items.
>
> **2026-08-30 docs-wave — board state (orchestrator-owned):** open board now holds
> **IN PROGRESS** items NEW-96..NEW-109 (deep-pass honesty fixes, IMPLEMENTED awaiting bulk VERIFY),
> NEW-110/111/112 (TLS SAN / naabu / multi-target follow-ups, landed 2026-08-26, awaiting VERIFY),
> and NF-7 (README/version skew note) — next free **NEW-114** unchanged; no status flips in this docs-only wave.

> **2026-08-23 cleanup wave (wave b) — VERIFIED:** NEW-3, NEW-14, NEW-60, NEW-73
> (deferred residuals), NEW-74 (residual docs), NEW-85..NEW-89, and NEW-90
> (new: stage-level failures absent from report error summary — found in the
> vulnbank.org field test) dispatched to six parallel builders; merged diff reviewer-APPROVED
> (merge-level cross-agent review) and orchestrator-verified same day.
> NEW-3/14/60/85..90 archived to TODO.closed.md; NEW-73/74 keep only their
> genuinely-open residuals; NEW-91 filed from merge-review Finding 1. NEW-93 (live-found crawl
> breakage) fixed + live-validated; NEW-94 remains OPEN for design decision.

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

### NEW-95 (HIGH) — v2.0 Detection packs (ROADMAP v2.0)
- Status: VERIFIED — closed 2026-08-24 and archived to TODO.closed.md (five batches,
  all reviewer-APPROVED and orchestrator-verified; commits 7956f0d, 7d71aa8, 453de88,
  7c2c3f1, c9e45fa). Auth/AuthZ/Business-logic pack families deferred to v2.1+;
  Cloud informational-only per §0.1. Full record in TODO.closed.md.

### NF-7 (INFO) — README Status version header diverges from `internal/version` constant (docs)
- Status: IN PROGRESS
- Reporter: builder
- Owner: (unassigned)
- Problem: `README.md:7` reads "**v2.0.0 — Detection packs complete**" while
  `internal/version/version.go:5` pins `Version = "1.4.0"` (what `ravenrecon version`
  prints). Skew predates this wave — the header previously said v1.8.0 against the same
  1.4.0 constant — so the README header has drifted into a milestone marker that no
  longer matches any build-visible string.
- Fix: pick one source of truth — either bump `internal/version.Version` when each
  roadmap milestone closes (and derive the README header from it), or reword the README
  header to an unversioned milestone statement ("Detection packs complete") so no
  version claim can go stale. Code change; outside the docs-wave scope that filed this.
- Verification: after fix, `grep Version internal/version/version.go` output matches the
  README status header (or the header contains no version at all).

### NEW-96 (HIGH) — Asset identities unstable across JSON persistence; invalid UTF-8 silently rewritten (internal/asset)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-H1)
- Owner: builder
- Problem: escapeRawQuery escapes only space/#/&/= (url.go:275–350); parameter/evidence/secret-candidate values accept raw non-UTF-8; json.Marshal (cache.go:266) substitutes U+FFFD → decoded assets recompute DIFFERENT identities. Reproduced by reviewer probe: ID changes across Marshal/Unmarshal. Dedup misses, Merge failures, stale identity-derived keys.
- Fix: utf8.ValidString rejection at validated ingestion points + percent-encode bytes ≥0x80 in escapeRawQuery; ID()-invariance regression tests; FuzzAssetJSONRoundTrip.
- Verification: hostile-input round-trip test asserting ID() equality.

- Fix note (2026-08-25): IMPLEMENTED — url.go utf8.ValidString rejection at ParseURL + canonicalURL query keys/values; escapeRawQuery percent-encodes bytes >=0x80; parameter/evidence/secret_candidate validate UTF-8; ID stable across JSON round-trip (verified).
### NEW-97 (HIGH) — JS-pack rules emit high-priority XSS/pollution findings from URL filename substrings (internal/detect/packs/js)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-H2)
- Owner: builder
- Problem: domxss.go:66–67 fires on Contains(url,"dom") (wisdom.js, DOMPurify); prototypepollution on "proto" (protobuf.js); postmessage on "postmessage". Shipped Priority high/Confidence 0.92, cached warm, propagated to reports as authoritative.
- Fix: cut the three rules until script bodies are analyzable, or re-grade honestly (CategoryInformation, ≤0.5 confidence, signal_source:url_substring metadata, whole-segment tokens).
- Verification: benign-corpus fixtures (mapbox/dompurify/protobuf/years) produce zero findings; pack tests assert non-detection too.

- Fix note (2026-08-25): IMPLEMENTED — URL-substring heuristics removed from domxss/prototypepollution/postmessage; findings re-graded Information/0.5/info priority; benign fixtures produce zero findings; goldens regenerated.
### NEW-98 (HIGH) — techintel cookie matching uses values contrary to fingerprint contract; value path persists cookie material (internal/techintel)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-H3)
- Owner: builder
- Problem: analyze.go:738–745 IndicatorCookie matches name OR value; value branch routes full observed cookie value into Evidence.Value persisted in storedTech.Evidence/reports. Contracts conflict verbatim (fingerprints/doc.go:46 "the cookie name" vs techintel/doc.go:69 "name OR value"); live "session" entry yields flask@Medium from prefs=returning:/session/hub.
- Fix: restrict to name matching (matches DB authoring intent), or explicit per-entry opt-in for value matching with redaction on the evidence path; align both doc packages.
- Verification: value-only-cookie corpus produces no match under name-only policy; doc parity test.

- Fix note (2026-08-25): IMPLEMENTED — IndicatorCookie name-only matching; value branch removed; doc parity aligned (techintel/doc.go 'name only'); value-only corpus yields zero matches.
### NEW-99 (MEDIUM, §0.6) — Pack detectors silently cap at 256 findings; truncated sets stored+cached completed with no marker (internal/detect/packs/*)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M1)
- Owner: builder
- Problem: e.g. web/csp.go:32–33 `if len(out)>=256 {break}` — dropped subjects unrecorded anywhere; engine stores result completed and caches it. Same pattern hsts/cors/robots/sourcemap/apis/js/cloud.
- Fix: return rule-level overflow signal mapped onto the engine's existing FindingsTruncated→incomplete chain, or bounded subjects_dropped metadata.
- Verification: >256-subject snapshot yields flagged/incomplete outcome, not cached completed.

- Fix note (2026-08-25): IMPLEMENTED — all packs (web/apis/js/cloud) now honest overflow: subjects truncated at 256 with dropped count in metadata subjects_dropped+truncated and LevelWarn log.
### NEW-100 (MEDIUM) — web.sourcemap matches .map/sourcemap anywhere in full URL (internal/detect/packs/web)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M2)
- Owner: builder
- Problem: sourcemap.go:29 Contains(uStr,".map") over scheme+host+query — every .mapbox.* host fires.
- Fix: keep HasSuffix(path,".map") + disc=="sourcemap"/content-type carriers only.
- Verification: mapbox-gl.js fixture non-firing.

- Fix note (2026-08-25): IMPLEMENTED — sourcemap restricted to HasSuffix(path,".map") + disc/content-type carriers; mapbox no longer fires.
### NEW-102 (MEDIUM) — apis-pack rule precision: introspection-from-path + bare-"graphql" values; IDOR fires on years/pagination (internal/detect/packs/apis)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M4)
- Owner: builder
- Problem: graphql.go:27–43 emits identical api.graphql.introspection finding from bare /graphql path or any evidence containing "graphql"; restidor.go:53–63 isNumericSegment accepts /2024/, /page/3.
- Fix: split endpoint-present vs introspection signals w/ carrier metadata; exclude year-shaped/short numerics from IDOR segments.
- Verification: blog-date and plain-/graphql corpora don't claim introspection/IDOR.

- Fix note (2026-08-25): IMPLEMENTED — graphql split endpoint vs introspection signals (requires __schema/introspection markers); restidor excludes year-shaped 1900-2100 and <=2-digit pagination.
### NEW-103 (MEDIUM, §15) — ParseURL errors embed userinfo credentials verbatim (internal/asset)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M5)
- Owner: builder
- Problem: url.go:83,86,89,97 wrap %q(raw): reproduced error text carrying https://user:hunter2@…. Errors are logged far more reflexively than Original is inspected; type docs require redaction of exactly this data.
- Fix: redact userinfo before embedding (or scheme+host only); test asserting credential substrings absent from all ParseURL errors.
- Verification: credential-bearing invalid URLs produce redacted error strings.

- Fix note (2026-08-25): IMPLEMENTED — redactURLForError clears userinfo before embedding in ParseURL errors; credential substrings absent (verified).
### NEW-106 (MEDIUM) — fingerprints validation misses Version.Group ≥ NumSubexp()+1 (internal/techintel/fingerprints)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M8)
- Owner: builder
- Problem: load.go:117–126 compiles version pattern but never bounds Group against capture count; analyze guard silently skips → fingerprint permanently version-less, violating load.go's own fail-at-load bar.
- Fix: reject out-of-range Group during compile/validation; loader regression test.
- Verification: Group:5 on one-group pattern fails Load.

- Fix note (2026-08-25): IMPLEMENTED — validateFingerprint rejects Version.Group <1 or >NumSubexp(); loader regression tests for Group:5 on one-group pattern fail Load as required.
### NEW-107 (MEDIUM) — Parameter.WithValue never back-dates FirstSeen despite field contract (internal/asset)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M9)
- Owner: builder
- Problem: parameter.go:164–166 sets FirstSeen only when zero; contract (:67–68) says earliest observation; MergeParameters takes min — asymmetric with LastSeen.
- Fix: honor contract (min on WithValue) or rewrite both docs to "earliest recorded"; pick one.
- Verification: out-of-order observation test pins chosen semantics.

- Fix note (2026-08-25): IMPLEMENTED — WithValue back-dates FirstSeen to min(existing,new); doc comment updated to match contract.
### NEW-108 (LOW) — Deep-pass LOW wave C (see REVIEW-2026-08-25.md §3 LOW)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25)
- Owner: builder
- Problem: ~15 LOW items with file:line in the report — highlights: techKey omits configurable caps; cancellation-path delete diagnostics break Ingest's never-error invariant; repeated-indicator confidence inflation toward High; Progress validates Completed>Total; TaskCompleted.Result aliasing undocumented; Observer-panic process-fatality asymmetry; CacheAccess.State unvalidated; stress test missing monotonicity assertion; negative Timeout echoed on wire; IPv6 zones into identities; open scheme policy undocumented; robots loose match; dead strings.Join lines in web pack; single-kind gates drop carriers; cloneContextForRule depth unpinned.
- Fix: per-item fixes in report.
- Verification: per-item tests named in session reports.

- Fix note (2026-08-25, wave 2): IMPLEMENTED — all ~15 LOW residuals closed:
  (1) repeated-indicator confidence inflation fixed via per-DISTINCT-indicator
  contribution cap (techintel/analyze.go; regression TestAnalyzePerIndicatorContributionCap);
  (2) techKey now carries configurable cap_tech/cap_ind (caps were CONFIGURABLE,
  not fixed — prior sticky note was inaccurate; record.go + key-sensitivity test);
  (3) cancellation-path cache-delete diagnostics no longer break Ingest's
  never-error invariant (adapt/import.go: cancelled skips self-heal delete,
  fold keeps genuine failure detail, run error stays nil — 3 new regressions);
  (4) Progress Completed>Total w/ TotalKnown now rejected at Validate and
  clamped at the pool emitter so it never hits the wire;
  (5) TaskCompleted.Result aliasing documented read-only (payload.go);
  (6) Observer-panic asymmetry made symmetric at Pool.observe choke point
  with ObserverPanics() counter + documented deliberate caller-goroutine
  propagation in cache emitAccess;
  (7) CacheAccess.State validated against a bounded vocabulary synced to
  cache.OutcomeState by a drift test;
  (8) stress test asserts non-decreasing Completed sequence;
  (9) negative Timeout clamped off the wire (Validate reject + emitter clamp);
  (10) IPv6 zone identifiers stripped from URL identities, stance documented
  (url.go WithZone("") + TestParseURLIPv6ZoneIndependence);
  (11) open scheme policy documented at validScheme (host requirement is the
  real gate; data:/javascript: rejected by empty-host);
  (12) robots evidence gate tightened to typed robots.txt carriers (benign
  'robots meta' fixtures yield zero findings);
  (13) dead strings.Join lines removed (wave 1);
  (14) single-kind carrier gates investigated: no detector drops carrier
  evidence — census-gate tradeoff documented at packs/web/rules.go;
  (15) cloneContextForRule depth contract pinned (one-level deep is correct:
  element types immutable-by-value; direct isolation test added).
### NEW-109 (INFO) — Deep-pass INFO wave D + NF-7 reminder (see REVIEW-2026-08-25.md §3 INFO)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25)
- Owner: builder
- Problem: clampProgress wrap comment; doc.go in-flight bound wording; Deriving nil-Observer trap; double key build; FNV/\x1f digest notes; content-hash covers unused DNSNames; fuzz additions post-NEW-96. NF-7 (README v2.0.0 vs version constant 1.4.0) still open below.
- Fix: docs/comment wave.
- Verification: n/a.

- Fix note (2026-08-25, wave 2): IMPLEMENTED — clampProgress int-wrap comment
  (runtime/observer.go); doc.go in-flight bound wording corrected to exact
  worker semantics; Deriving{Observer:nil} inert-bridge trap documented at
  Config.Deriver; techintel cache-key double build merged to one build;
  FNV-1a-64/0x1f digest collision-posture documented (fingerprints/digest.go);
  NF-7 fixed (README header unversioned, wave 1). Remaining sub-items —
  content-hash covering unused DNSNames (conservative-miss only, deliberate)
  and post-NEW-96 fuzz additions — noted as accepted-as-is / follow-up.
### NEW-110 (MEDIUM) — TLS SAN host expansion in the httpprobe stage (internal/pipeline/adapt)
- Status: IN PROGRESS
- Reporter: builder (orchestrator dispatch, NEW-95 follow-up enhancement wave)
- Owner: builder (this session)
- Problem: httpprobe captures TLS certificates with SAN DNS names (ProbeResult.TLSMeta,
  internal/httpprobe/tls.go) but never feeds those names back as Host discoveries —
  certificate SANs are a passive subdomain source the pipeline discards.
- Fix: in adapt/httpprobe.go buildResult, when TLS certificates carry DNSNames, extract each
  name that is a valid canonical in-domain host not already in the corpus and emit it as an
  additional Additions.Hosts entry. Gated by StageParams["tls_san_expansion"] (default ON;
  "false" disables). Wildcard/IP-literal/out-of-domain names are dropped at asset.NewHost /
  pipeline.FilterHosts.
- Verification: hermetic test — canned transport response carrying a synthetic
  tls.ConnectionState whose leaf has an unlisted in-domain SAN → host appears in additions;
  disabled param → no expansion; existing tests/goldens stay green.

- Fix note (2026-08-26): IMPLEMENTED — adapt/httpprobe.go expandTLSSANHosts wired into
  buildResult via probeResultOptions{sanExpansion}; gate tlsSANExpansionEnabled (default ON,
  exact "false" case/space-insensitively disables); dedup vs corpus+report hosts; wildcard/
  IP-literal names dropped at asset.NewHost, out-of-domain at pipeline.FilterHosts;
  provenance Source "tls-san"; deterministic append-after-report-hosts placement.
  Tests: TestHTTPProbeStageTLSSANExpansion{,Disabled,DropsNonHosts,NoCertificates} +
  syntheticTLSCert/tlsStateFor/registerHTTPSWithTLS hermetic harness extension. Gates:
  gofmt clean, go vet clean, go build OK, package suite + -race green, full repo suite 32/32.

### NEW-111 (MEDIUM) — Optional naabu port discovery between dns and httpprobe (internal/pipeline/adapt)
- Status: IN PROGRESS
- Reporter: builder (orchestrator dispatch, NEW-95 follow-up enhancement wave)
- Owner: builder (this session)
- Problem: the pipeline has no active port discovery; open ports on resolved addresses are
  only observed implicitly via HTTP probing of default-scheme targets.
- Fix: new internal/pipeline/adapt/ports.go — naabu adapter following the discovery.Runner
  pattern (exec.CommandContext semantics, separate argv values, bounded capture, per-tool
  timeout). Wired into the httpprobe stage entry (after dns resolution, before probing):
  StageParams["port_discovery"]=="true" + non-empty Results.IPs → run
  `naabu -l <resolved-ips-file> -top-ports 100 -silent -rate 300 -c 25`, parse ip:port pairs,
  emit asset.Port assets + ip→port relationships as results-channel additions. Cache op
  "ports.discover" (scope hash of input IPs + config + tool version; unknown version ⇒ no
  caching). Honest markers: ports_naabu_missing / ports_naabu_failed /
  ports_output_truncated. AllStages stays 12; no new StageName.
- Verification: fake-runner tests (no real naabu): absent param ⇒ zero executions; enabled ⇒
  ports+relationships emitted with pinned argv and temp-file content; missing binary ⇒ flag;
  runner failure ⇒ flag; cache round-trip; stdout truncation ⇒ Truncated+flag.

- Fix note (2026-08-26): IMPLEMENTED — new adapt/ports.go (naabuPortSource over
  discovery.Runner/LookupFunc seams; exec.CommandContext semantics via the runner, separate
  argv values, target-derived IPs in a temp file named by ONE argv value, 4 MiB bounded
  capture, 2m default per-tool timeout, context cancellation honored); cache op
  "ports.discover" (schema+op+target identity+scope hash of sorted input IPs+
  top_ports/rate/concurrency+tool version; unknown version ⇒ no caching; completed-only
  serving with scope revalidation and self-heal). Wired into HTTPProbeStage.Run entry (after
  dns resolution via StageInput.Results.IPs, before probing) gated by
  StageParams["port_discovery"]; sticky flags ports_naabu_missing / ports_naabu_failed /
  ports_output_truncated (+Truncated). Documented deferral: ports propagate through the
  results channel; probe-target-list mutation and the host→ip graph leg stay deferred
  (corpus carries no IPs — mirrors doc.go v1.3). AllStages unchanged at 12; no new
  StageName. Tests: ports_test.go (fakeNaabuRunner/portsStaticCache — gates, argv+file
  content pinning, missing binary, unknown-version no-cache, warm round-trip, corrupt-record
  self-heal, failure mapping, truncation flag, parser shapes incl. bracketed IPv6, stage-level
  emission/gating/inert cases). Gates: gofmt clean, go vet clean, go build OK, package suite
  + -race green, full repo suite 32/32.

### NEW-112 (MEDIUM) — Multi-target scan fan-out implemented; awaiting orchestrator verification (internal/cli)
- Status: IN PROGRESS
- Reporter: builder (orchestrator dispatch: multi-target scan task)
- Owner: builder (this session)
- Problem: `ravenrecon scan` accepted exactly one target domain (internal/cli/scan.go
  parseScanArgs peeled a single positional and rejected any second as "unexpected argument"),
  so scanning N domains required N invocations.
- Fix (implemented, CLI-level fan-out only — no pipeline/cache/asset changes):
  parseScanArgs now peels MULTIPLE leading positionals, adds `--targets FILE` (one domain per
  line, blanks/`#` comments skipped, CRLF/padding trimmed, exact dupes collapsed, read at
  parse time so file errors are usage errors) and `--target-parallel N` (unset=0→sequential,
  explicit value validated 1–8). runScan normalizes EVERY target via asset.NewDomain up front
  (any invalid target aborts the whole invocation before stages/cache); the historical
  single-target flow is extracted verbatim into runScanSingleTarget (backward compat pinned by
  test); >1 targets go through runScanMultiTarget: EXISTING pipeline.Run per target, each its
  own ScanConfig + output subdir `<output>/<canonical-target>/`, shared cache handle (safe:
  cache ops mutex-serialized, keys per-target), shared mutex-guarded stageObserver for
  --verbose, bounded WaitGroup+semaphore fan-out capped at N (§10) with ctx.Done escape so
  Ctrl-C can't deadlock queued targets (recorded cancelled/not-started), per-target summaries
  buffered and flushed in input order under parallelism, combined summary block
  ("RavenRecon scan summary: N targets" + per-target outcome lines + produced-data count),
  exit 0 iff ≥1 target completed/partial else interrupted/all-failed error. --tui restricted
  to exactly one resolved target at parse time (frame declares a single run); multi dry-run
  prints one config block per target. Help text updated in cli.go + scanUsage.
- Files: internal/cli/scan.go, internal/cli/cli.go (usage examples, stageObserver mutex),
  internal/cli/scan_test.go (scanOptions.target→targets []string rename; removed the
  now-valid two-positional error case), internal/cli/scan_multi_test.go (new: 9 test funcs —
  parse grammar/file/dedupe/bounds/tui-rejection, sequential fan-out w/ per-target ScanConfig
  capture, deterministic parallel-bounds proof via gated stage (peak==2 at parallelism 2),
  pre-cancelled skip semantics, exit-code matrix, invalid-target aborts first, --targets E2E,
  multi dry-run, single-target legacy pin).
- Verification: gates run this session: gofmt clean (internal/cli); `go vet ./...` OK;
  `go build ./...` OK; `go test -race ./internal/cli/ -count=1` PASS; `go test ./... -count=1`
  green in every package EXCEPT internal/pipeline/adapt, whose 3 failures
  (TestHTTPProbeStageTLSSANExpansion httpprobe_test.go:1139,
  TestHTTPProbeStageTLSSANExpansionDropsNonHosts :1206, TestPortDiscoveryGates ports_test.go:207)
  belong to the concurrent NEW-110/111 session's in-flight feature code+tests, not this diff
  (internal/cli itself passes plain AND -race; re-checked after each adapt churn wave).
  Orchestrator to verify both entries together once NEW-110/111 settle.

### NEW-113 (HIGH) — v2.0 Triage pack batch 6 (internal/detect/packs/triage)
- Status: VERIFIED — orchestrator-verified 2026-08-27 and archived to TODO.closed.md (8 rules via curated param lists; reviewer APPROVE; gates green). Full record in TODO.closed.md.


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

