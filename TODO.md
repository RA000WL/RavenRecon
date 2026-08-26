# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-110).
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
> archived to TODO.closed.md. Open board now holds only DEFERRED items.

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
### NEW-101 (MEDIUM) — CSP/HSTS absence evaluated corpus-globally, applied per-host (internal/detect/packs/web)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M3)
- Owner: builder
- Problem: helpers.go hasCSP/hasHSTS scan whole corpus: one header-bearing host masks genuinely-missing peers (false negative); zero-evidence corpora flag everything missing @0.9.
- Fix: correlate Evidence Source host → per-host presence; no-header-evidence runs skip rather than claim missing.
- Verification: mixed-host snapshot flags only the truly-missing host.

- Fix note (2026-08-25): IMPLEMENTED — hostHasCSP/hostHasHSTS per-host correlation added to helpers.go; detectors emit only for hosts genuinely lacking evidence; empty-evidence corpora skip.
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
### NEW-104 (MEDIUM) — Relationship.ID() concatenates unencoded components; distinct edges collide (internal/asset)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M6)
- Owner: builder
- Problem: relationship.go:133–135 From.String()+Kind+"\x00"+To with unpinned kind vocabulary; demonstrated two validated edges sharing one ID → silent drop in dedupeFindingRelationships.
- Fix: percentEncode components (package convention elsewhere), add RelationshipKind.Valid() enforced in NewRelationship; collision regression test.
- Verification: prefix-pair edges produce distinct IDs.

- Fix note (2026-08-25): IMPLEMENTED — RelationshipKind.Valid() vocabulary enforced in NewRelationship; ID() uses separator-safe encoding ('%'→%25, \x00→%00, controls escaped) preventing collisions.
### NEW-105 (MEDIUM) — Deriver panic telemetry write-only on pool path; panic value discarded (internal/event, internal/runtime)
- Status: IN PROGRESS
- Reporter: reviewer (deep-pass 2026-08-25, REVIEW-2026-08-25.md R2-M7)
- Owner: builder
- Problem: derive.go:114–124 drops panic value entirely; observer.go:59–64 documents DeriverPanics unreachable via Config.Deriver; grep: zero production readers. Wired deriver bug = silently lost derivation batches forever.
- Fix: pool emits canonical warning event when bridge counter >0 at shutdown (type-assert event.Deriving), and/or retain last panic+debug.Stack() behind an accessor.
- Verification: panicking fake deriver run surfaces observable warning.

- Fix note (2026-08-25): IMPLEMENTED — Deriving captures last panic value+stack behind mutex with LastPanic() accessor; DeriverPanics counting retained; callers can query both after run.
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

