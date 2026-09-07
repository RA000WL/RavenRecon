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

### NEW-133 (HIGH) — mistake-path prober first-review follow-ups (unreviewed-provenance feature)
- Status: VERIFIED — orchestrator-verified 2026-09-05 (fix round APPROVE; gates green)
- Reporter: reviewer (first gate: REQUEST CHANGES, no BLOCK; curated set §0.1-clean)
- Owner: builder
- Problem: per-job 30s budget vs 2+ports+38 sequential probes → systematic Cancelled misreporting outcome; port-exclusion gating untested; path cache warmth unpinned; 3 LOWs (dropped root observations on specs error, stale concurrency comment, hardcoded "38").
- Fix: per review findings HIGH×1 + MEDIUM×2 + LOW×3.
- Verification: re-review gate; hermetic budget/gating/cache tests; gates green.

### NEW-131 (HIGH) — diff/handoff first-review follow-ups (unreviewed-provenance feature)
- Status: VERIFIED — orchestrator-verified 2026-09-05 (2 review rounds; all findings closed with pins; gates green)
- Reporter: reviewer (first gate 2026-09-05: CHANGES-REQUESTED, no BLOCK)
- Owner: builder
- Problem: `cli.go:48-51` usage text corrupted (dangling tool fragment); `SnapshotOf` claims builder re-validation but unmarshals unchecked with dead error return (§0.5-adjacent); handoff "live root URLs" overclaims corpus roots never verified live; domains/ips/tls_certificates silently excluded from delta; unbounded input/output; `--output` never created; 9 test gaps; no ARCHITECTURE section.
- Fix: per review findings HIGH×4 + MEDIUM×5 (+ LOW/INFO as filed).
- Verification: re-review gate; hermetic tests incl. corrupt/empty/mismatch cases; gates green.

### NEW-132 (HIGH) — config-precedence/derive first-review follow-ups (unreviewed-provenance feature)
- Status: VERIFIED — orchestrator-verified 2026-09-05 (2 review rounds; precedence gate now test-pinned; gates green)
- Reporter: reviewer (first gate 2026-09-05: CHANGES-REQUESTED)
- Owner: builder
- Problem: F1 scan ignores file/env scalars (contract untruthful); F2 null-strictness claim false; F3 missing flag-precedence + Deriver tests; F4 WithFile can't turn off / defaults-equality fragile; F5 silent 512 cap + stream/report divergence; F6 empty-env==unset + env parity gap; F7 dry-run hides effective config + stale comment.
- Fix: per review findings HIGH×3 + MEDIUM×5 (F8 batch-split noted).
- Verification: re-review gate; precedence + Deriver table tests; gates green.

### NEW-130 (LOW) — amass bare-word output accepted as hostname (field-found 2026-09-05)
- Status: VERIFIED — orchestrator-verified 2026-09-05 (review APPROVE + comment fix; gates green)
- Reporter: orchestrator (live field test, `ravenrecon discover www.vulnbank.org`)
- Owner: builder
- Problem: amass emitted a bare `no` line; discovery accepted it as a host (`no (amass ...)` in merged output). Likely an amass log/progress line leaking into parsed output. Downstream DNS fails it honestly (discover → incomplete, no corruption), but junk hosts cost resolution budget and pollute the corpus.
- Fix: harden amass output parsing (drop bare single-label tokens / require a dot in enumerated names, mirroring existing malformed-line handling); regression test with `no`-style line in fixture output.
- Verification: hermetic adapter test; `discover` against fixture shows 0 junk hosts.
- Implementation (2026-09-05): dot-guard in `internal/discovery/parse.go:parseHostLines` (shared: subfinder/assetfinder/amass) + `internal/discovery/chaos.go:add` choke point (plaintext fallbacks); bare words count malformed, never emitted. Regression tests `TestParseHostLines/bare_words_rejected_(NEW-130_amass_log_leak)` + `TestChaosBareWordsRejected` pass; `go test ./internal/discovery/ -count=1` green (112s), `gofmt`/`vet` clean. Close-out (2026-09-05, orchestrator): review APPROVE (guard load-bearing — bare words normalize cleanly without it; no legitimate single-label loss; shared-path safe; field case pinned) + truncated-comment tail restored. Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

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

### NEW-113 (HIGH) — v2.0 Triage pack batch 6 (internal/detect/packs/triage)
- Status: VERIFIED — orchestrator-verified 2026-08-27 and archived to TODO.closed.md (8 rules via curated param lists; reviewer APPROVE; gates green). Full record in TODO.closed.md.

### NEW-118 (CRITICAL) — JS pack detectors scan hardcoded synthetic strings, never real JS bodies
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: `internal/detect/packs/js/domxss.go:75-78` ignores its arg (`var x="safe";el.textContent=x;`), `postmessage.go:73-76` returns a `click` handler (never contains `"message"`, always false at `:83`), `prototypepollution.go:73-76` returns `obj.normal=true` (never `__proto__`); tests pin zero findings (`js_test.go:395-399,417-420,452-455`). The 3 JS rules can never fire — pure false negative on top-10 JS bug classes. Root cause: `detect.Snapshot`/`Context` carries `asset.JavaScript` metadata only (no body; `internal/asset/javascript.go` has Hash/Size/ContentType but no content field), so detectors have nothing real to scan.
- Fix: design a bounded JS-body channel on SDK v2 (Context.GraphView-adjacent or snapshot extension, e.g. `Snapshot.JavaScriptContent map[Identity]string` fed from `jsintel.RetainedContent`/pipeline Documents, 2 MiB reuse cap); rewrite the 3 detectors to run `jsintel.NewParser().Parse(realBody)` + whole-token sink checks over `Parsed.Strings`; keep 256-cap/overflow pattern; per-pack determinism goldens with real bodies.
- Verification: hermetic tests with synthetic vulnerable/safe bodies (XSS sink present/absent, postMessage with/without origin check, `__proto__` pollution) asserting findings fire/quiet correctly; cache parity; `gofmt`/`vet`/`build`/`test`/`-race` green; SDK compat goldens updated only via the v2 reopening gate.
- Implementation (2026-09-03): SDK MINOR 2.0→2.1 (additive per policy — backward compatible, `CheckAPIVersion(2,0)` keeps passing; all old packs load unchanged): `detect.JavaScriptContent{Identity, Body}` + `Snapshot`/`Context` fields + caller bounds (`MaxSnapshotJSContents` 1024 / `MaxSnapshotJSContentBytes` 64 MiB exported; 2 MiB per-body unexported, mirrors pipeline `MaxDocumentBytes`) + normalize validation (non-zero javascript-kind identity ∈ observed JS set, valid UTF-8, bounds, dedup, identity-sorted) + per-rule clone + snapshot fingerprint body digests (changed bodies always miss; SchemaVersion stays 3, record layout unchanged) + surface golden regen (exactly the additive delta). Detectors rewritten on real bodies (same predicates/caps/meta — dead synthetic funcs deleted; rules bumped 1.0.0→1.1.0 per content-bump contract, descriptions corrected; body-less snapshots stay silent — old zero tests + goldens preserved). Pipeline adapter maps the document channel (complete/UTF-8/attributed only, deterministic sorted head; producers' own truncation flags stay the honesty channel). ARCHITECTURE detection sections updated. Full gates green incl. `-race` on detect tree + adapt; acceptance goldens byte-identical (fixture bodies benign — fail-open proven on real output). Close-out (2026-09-03, orchestrator): detect-area review CHANGES-REQUESTED → fixed + re-verified (triage 8 rules 1.0.0→1.1.0 + version pin; JS descriptions honest substring-heuristic, postMessage narrowed; MaxSnapshotJSContentBodyBytes exported + adapter over-bound skip; detect_js_contents_incomplete_input flag + seam tests; deterministic dup tie-break; js requiredAPIMinor=1; fpSnapshot key sort; stale js/doc.go parser narrative rewritten; goldens versions-only). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-119 (CRITICAL) — httpprobe observations never reach techintel/priority adapters (145 fingerprints starved)
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: every host is probed only at `/` (`internal/httpprobe/run.go:501-502`), and the pipeline adapters discard the responses: techintel builds one Observation per URL with URL identity only (`internal/pipeline/adapt/techintel.go:94-102`, only `IndicatorEndpointPath` can fire), priority signals carry hostname/path/params only (`priority.go:109-118`, "never fabricates"). Header/cookie/TLS/DNS analyzers starve; priority ranks paths, not live state.
- Fix: wire `ProbeResult` headers/status/body-snippet/TLS into `techintel.Observation{Headers, Body, TLSInfo, StatusCode}` in `adapt/httpprobe.go:buildResult`; extend `buildPrioritySignals` with Technologies/Secrets/Headers/StatusCode from the results channel (no asset-schema bump — the results channel already carries them); extend cache keys only where result-material inputs change; per-stage goldens updated.
- Verification: hermetic pipeline test with canned probe (Server header + cookie + TLS meta) asserting techintel fires header/cookie/TLS families and priority factors cite live observations; cold/warm parity; full gates green.
- Implementation (2026-09-03, scoped to what the channels carry — headers/cookies/bodies/DNS have no results-channel carrier at these stage positions and stay documented gaps): techintel adapter resolves host-level TLS (issuer/subject/SANs; ALPN honestly absent) from `host_to_tls_certificate` edges + `Results.TLSCertificates` with URL identity preserved (engine key mask + content-hash cross-check make this cache-safe by construction; changed-cert re-analysis test); priority adapter enriches URL signals with Technologies (`url_to_technology`), Secrets (`url_to_secret_candidate`), Headers (urllive LiveRecords, sorted lowercased lines), JSBundleBytes, and EndpointMethod (most-specific-wins) — all inside the signal-fingerprint key by construction — with deterministic sorted heads at engine bounds, corrupt-entry filtering, and a `priority_signals_truncated` flag (ports/services stay zero: address-keyed with no host linkage). Engine consts `MaxSignalTechnologies/Secrets/Headers/HeaderBytes/MethodBytes` exported for adapters (NEW-14 pattern). Acceptance goldens regenerated: exactly the intended drift (graphql surface 0/unknown → 0.5/low via confidence:technology factor; aggregates recomputed; nothing removed, no outcome/flag changes). Close-out (2026-09-03, orchestrator): adapter review BLOCK (reflection flag-without-Truncated §0.6; port cross-product join on non-production input) → fixed + re-verified (Truncated rides both reflect flag paths + asserts incl. transport-error; per-IP edges end-to-end with production-edges test; multi-cert sorted-first documented; ARCHITECTURE sections added for host_to_ip/HostPorts/probe_ports/reflection flags). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-120 (HIGH) — Triage pack is param-name-only with no reflection/behavior check
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: `internal/detect/packs/triage/helpers.go:62-87,214-256` emits a finding when a query-param name is in a curated wordlist (confidence fixed 0.6, 256-cap); names like `id/url/page/q/name` fire on most of the web, precedence hides secondary classes, and `meta.subjects_dropped` silently caps — hunters learn to ignore the pack.
- Fix (stays inside §0.1): `urllive`-style reflection enrichment via existing `ProbeURLs` transport — GET each flagged URL with a canary token appended to each flagged param, record reflected-unencoded/encoded/not-reflected as `meta.reflection=` (liveness observation, no payload, no exploitation); triage rules gate reflected→keep, not-reflected→drop/demote.
- Verification: hermetic tests (reflecting vs echo-encoding vs silent endpoints) asserting keep/demote/drop; 256-cap + precedence behavior preserved; full gates green.
- Implementation (2026-09-03): canary-reflection engine in `internal/httpprobe/reflect.go` (op `url.reflect`, deterministic per-(URL,param) canaries, bounded 128 KiB body read, strict cache decode + envelope check, 14 tests incl. truncation/timeout/cache/tamper); `ReflectEvidence`/`ParseReflectEvidence` contract (MethodEndpoint + `reflect:<param>`, unknown never built); urllive stage wiring (`urllive_reflection` default ON / `urllive_reflect_max_urls` default 512 / `urllive_reflect_overflow` + `urllive_reflect_truncated` flags, additive-only outcome, 6 stage tests incl. cache parity + E2E gate proof); triage `runTriage` gate in `helpers.go` (drop all-silent subjects, cite verdicts in 256B-bounded `reflection` meta, fail-open without evidence — existing goldens byte-identical). Close-out (2026-09-03, orchestrator): engines review CHANGES-REQUESTED (bare-?q false-absent HIGH; encoded-case, dead-corpus reflection, analyzeWindows ctx MEDIUMs) → fixed + re-verified (bare params Skipped; case-insensitive encoded match; reflection over liveness-completed URLs only; ctx threaded; triage rules bumped 1.1.0 under NEW-118 round). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-121 (HIGH) — naabu-discovered ports are reported but never probed
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: with `port_discovery` on, open ports land in `Results.Ports` (+ `ip_to_port` edges) but no probe target is ever built for them (`adapt/ports.go:65-71` defers probe-target mutation; `httpprobe.Probe` builds only `http(s)://host/` per host in `run.go:507-533`). Non-HTTP-scheme services on 8443/8080/9000+ — where bounty bugs live — are found and then ignored; they never enter the corpus, techintel, or priority.
- Fix (3 coordinated pieces, no schema/CLI/SDK change): (1) dns adapter publishes `host_to_ip` edges into `Results` (new `dns.Report.AllRelationships`, merged+sorted like the engine's own edges; CNAME edges stay engine-internal); (2) httpprobe engine gains optional per-host ports (`Config.HostPorts map[hostname][]port`, synthesized `http(s)://host:port/` targets in stable order with canonical-identity dedup, fixed cap `maxProbePortsPerHost` = 16 ports/host, sequential probes within the existing per-host job so `MaxConcurrentPerHost` still holds; cache keys are URL identities — port targets key distinctly by construction); (3) httpprobe adapter joins host→IP (direct + one CNAME hop) → naabu `ip_to_port` edges into per-host port lists only when port discovery ran, with an `httpprobe_port_targets_truncated` flag on synthesis cuts. Default OFF preserved (no ports ⇒ byte-identical behavior).
- Verification: hermetic engine tests (synthesis order/dedup/cap/timeout-honesty/cache distinction); adapter tests (CNAME-transitive join, flag, disabled-parity); dns edge publication tests; full gates + golden review (host_to_ip edges enter the graph: detect `graph_digest` shifts by construction, acceptance goldens) green.
- Implementation (2026-09-03): (1) `dns.Report.AllRelationships` (merged, ID-deduped, sorted) + adapter publishes `host_to_ip`/`host_to_cname` edges into `Results` (out-of-domain targets ride along as legitimate observations, jsintel precedent); (2) httpprobe engine `Config.HostPorts map[hostname][]port` with strict whole-call validation (canonical keys, 1..65535, unknown hosts ignored for subset probing), stable target synthesis (roots first, then ascending ports × http/https with canonical-identity dedup — cross-scheme non-defaults stay distinct), sequential probing within the existing per-host job (`MaxConcurrentPerHost` holds), and `portForTarget` replacing `portForScheme` in `assemble` so ports/services/TLS-cert edges name the probed port (roots byte-identical — full engine suite green unchanged); cache keys are URL identities, distinct by construction; (3) adapter `synthesizePortTargets` joins host→IP (direct + one CNAME hop) → naabu `ip_to_port` (a wrong-slice bug caught by the new tests would have shipped silent synthesis), capped at 16 ports/host with `httpprobe_port_targets_truncated`, behind a SEPARATE `probe_ports` knob (discovery-only behavior byte-identical — existing EmitsPorts test green unchanged; synthesized targets join the corpus and flow downstream). Acceptance goldens regenerated: exactly additive `host_to_ip` (+1 CNAME) edges; nothing removed, no outcome/flag/finding changes. Close-out (2026-09-03, orchestrator): port-join review HIGH (cross-product misattribution masked by idealized test) → fixed + re-verified (per-IP attribution end-to-end, old edgeless records self-heal, TestSynthesizePortTargetsProductionEdges pins 1.1.1.1:80/2.2.2.2:443 isolation). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-122 (HIGH) — takeover CNAME findings are DNS-shape-only, never HTTP-confirmed
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: `takeover.cname.unclaimed`/`cname.dangling` fire on DNS shape alone (CNAME without target IPs); a hunter must still manually fetch each candidate to separate provider-confirmed takeovers from dead ends. The dangling host's own root HTTP response usually IS the provider fingerprint page, but no stage retains root bodies.
- Fix (NEW-120 pattern, recon-only): httpprobe confirmation fetch over in-scope dangling hosts (generic DNS-shape selection — CNAME edge with no target IPs — no provider lists outside the pack's DNS suffixes), bounded dual-scheme GETs with 32 KiB bodies, match against an httpprobe-owned curated provider table (github-pages/heroku/aws-s3, case-insensitive), emit `MethodHTML`/`takeover_page:<provider>` evidence per match; pack gates add `confirmed`+`provider` meta when present, fail-open otherwise (rules bump 1.0.0→1.1.0 — meta addition changes findings, so cache keys must turn). No result cache for the fetch (freshness-critical claims; candidates are few; evidence downstream stays coherent via the snapshot fingerprint). S3-endpoint confirmation deferred (often out-of-domain endpoints).
- Verification: hermetic tests (provider pages → confirmed+evidence; silent pages → unconfirmed-silent; timeout/truncation → silent; tampered/unknown hosts); pack gating tests (meta present/absent/foreign); stage tests (dangling selection, caps, flags, disabled); full gates + golden review green.
- Implementation (2026-09-03): httpprobe `ConfirmTakeoverHosts` (in-scope-only via `normalizeInputHosts`, both-schemes-always, redirects never followed, 32 KiB bodies, pool+limiter+timeouts mirroring `ReflectURLs`, deliberately UNCACHED with documented freshness rationale) + curated 3-provider table (github-pages/heroku/aws-s3, case-insensitive, documented curation status) + `TakeoverEvidence`/`ParseTakeoverEvidence` contract (`MethodHTML` + `takeover_page:<provider>`, exact-substring validation); httpprobe stage selection (generic DNS-shape: CNAME edge with target lacking IPs; 64-host cap + overflow flag; `takeover_confirm` default ON; body-cap/hard-error truncated flag; additive-only outcome with runner-contract-safe nil error returns); takeover cname rules cite `confirmed`+`confirmed_provider` when evidence present, fail-open otherwise (1.0.0→1.1.0; S3 rule untouched at 1.0.0; pack golden drift versions-only). Full suite green with ZERO acceptance drift (fixture CNAMEs resolve or serve clean pages — fail-open on real output); `-race` clean on httpprobe/takeover/adapt. Close-out (2026-09-03, orchestrator): session review HIGH (session sent to dangling-takeover hosts) → fixed + re-verified (confirmTakeover clones cfg with RequestHeaders nil — takeover evidence always anonymous, TestTakeoverConfirmationAnonymous). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-123 (HIGH) — JS detector predicates need token-aware precision (measurement-gated)
- Status: VERIFIED — orchestrator-verified 2026-09-03 (redesign beat every baseline; 2 review rounds + polish all APPROVE; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Reporter: reviewer
- Owner: (unassigned)
- Problem: `internal/detect/packs/js/domxss.go:81`, `postmessage.go`, `prototypepollution.go` decide by `strings.Contains` on raw bodies — comments/strings/dead code fire; with real 2 MiB bundles hunters will mute the pack and miss real sinks.
- Fix: use `Parsed` token output (strings vs code, sink LHS, handler scope) — ONLY after FP field measurement pins precision/recall baselines; blind redesign risks regressions. Rule versions bump with the change.
- Verification: FP harness + before/after precision pins; goldens regen reviewed.
- Close-out (2026-09-03, orchestrator): local-tokenizer redesign (jsintel Parsed verified span-less — local code-mask justified) VERIFIED and review-APPROVED twice. Before→after: recall 6/6 same rules, safe 0, FP traps 4→0 (each with fix comment), FN trap fires, benign 2→0, rules 1.2.0→1.3.0, golden versions-only. Fix rounds: linear/bounded scans (4 KiB windows + per-128 ctx, hostile time-bounds), `)`/`,`/`:` terminators, file-global origin documented as known-FN with pins, spacing/ident/paren fixes, short-body ctx + outer-delimiter polish. Residuals pinned as known-FN/liberal edges (bracket notation, regex lexing, call-form proto, 4 KiB literal window). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-124 (HIGH) — Chunked >2 MiB bundle scanning
- Status: VERIFIED (Phase 1) — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out; Phase 2 stays NEW-129)
- Reporter: reviewer
- Owner: builder
- Problem: `pipeline/document.go:MaxDocumentBytes` (2 MiB) drops big webpack bundles whole; `adapt/detect.go:buildJSContents` + snapshot 2 MiB bound skip them — largest bundles (most sinks) invisible to all JS rules, silently.
- Fix: overlapping windowed scan with full-body-hash cache coherence + `scanned=chunked` meta.
- Verification: synthetic 5 MiB bundle with sink in tail window → finding cites full identity; determinism + cache parity; gates green.
- Implementation Phase 1 (2026-09-03, jsintel-internal, DONE awaiting VERIFY): streamed over-cap bodies retain deterministic overlapped windows over the bounded prefix (512 KiB/8 KiB tiling, same memory ceiling; declared-huge fast-fail preserved windowless — pinned test kept); per-window parse+extract merged by identity with summed counters; entries stay Incomplete, nothing cached/retained (truncated contract byte-identical: Content nil, Size/Hash zero; warm runs recompute, shrink-recovery records preserved); non-JS untouched. Delivers endpoints/techs/secrets/evidence/imports from big-bundle prefixes (→ corpus → urllive → priority → triage). Acceptance: hostile `huge.js` now yields its JS asset (+1, no candidates — fixture body is filler); nothing else drifted. Full gates + `-race` green. Phase 2 (filed NEW-129): chunk documents + snapshot bodies + detect-JS findings need chunk-identity design. Close-out Phase 1 (2026-09-03, orchestrator): engines review CHANGES-REQUESTED → fixed + re-verified with two intended behavior deltas over the paragraph above: (a) declared Content-Length is no longer trusted — every body streams to cap+1 (lying 10 GiB declaration + small body → completed, pinned); (b) windowed JS assets now EXIST with Size 0 / Hash "" ("not observed", never the prefix), still Incomplete, still nothing cached/retained. analyzeWindows threads ctx (cancels between windows). hostile huge.js drift unchanged (+1 sizeless asset). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-125 (HIGH) — Operator session headers (no credential acquisition)
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify; gates green, see close-out)
- Reporter: reviewer
- Owner: builder
- Problem: no cookie/header/session plumbing anywhere (`jsintel/fetch.go:295`, `httpprobe` configs, adapters) — all findings pre-auth; authed surface (IDOR/BOLA, admin) invisible.
- Fix: opt-in operator-supplied header/jar file threaded through probe/fetch/crawl configs with log redaction + cache-key binding. Login automation/credential attacks stay §0.1 — never proposed.
- Verification: hermetic authed-cookie tests (header sent, redacted in logs, distinct cache keys); `-race` green.
- Implementation (2026-09-03): session file format + fail-closed parser (`adapt/session.go:ReadSessionFile` — Name:value lines, 32-header/8 KiB-value/64 KiB-file bounds, Host rejection, control-byte rejection, basename-only errors mirroring the importer) + order-independent SHA-256 `SessionDigest` (empty→"" so anonymous keys stay byte-identical); engines: httpprobe (`run.go` env validation, `urls.go` liveness, `reflect.go` canaries, `takeover.go` confirmation — session on origin requests only, followed in-scope redirect hops never inherit, pinned by test; reflect/takeover targets are in-scope corpus/candidate hosts; `sessionDigest` bound into probe/live/reflect keys) and jsintel (`fetch.go` gated fetch, `record_fetch/analyze` digest-bound keys, engine `Config.RequestHeaders` whole-run validation); adapters: httpprobe/jsintel/urllive stages read `session_headers` param via `sessionHeadersFromParams` (broken file fails the stage, never anonymous); CLI `--session-headers` fans the FILE PATH (never values) to the three in-process fetching stages with merge-safe `setStageParam` (also fixes request-timeout/session-headers overwrite on httpprobe). Redaction: errors carry header NAMES only, never values; file paths basename-only; no header flow into evidence/metadata/records (grep-audited). Crawl DELIBERATELY out of scope (`adapt/crawl.go` note): katana's only header channel is argv `-H`, which would leak secrets via the process table — crawl stays anonymous and cache-shared; help text scopes fan-out to the 3 stages. External-tool urlintel/jsintel adapters likewise untouched (same argv wall). Close-out (2026-09-03, orchestrator): session review CHANGES-REQUESTED (F1 takeover-anon HIGH, F2 empty-corpus fail-open HIGH, F3–F5 validator MEDIUMs) → all nine fixed + re-verified (anon confirmation; session resolution above short-circuit on all 3 stages; empty-name rejection; Content-Length/Transfer-Encoding/Connection/User-Agent rejection; FetchConfig.validated normalization; 64-value/64KiB bounds; mid-run + echo-residual + digest-order docs). Crawl exclusion confirmed correct (argv secret exposure). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-126 (HIGH) — DNS MX/TXT/NS/SOA/SRV/CAA records
- Status: VERIFIED — orchestrator-verified 2026-09-03 (T1→T2→T3, each review-gated; gates green, see close-out; CAA/SOA stay deferred)
- Reporter: reviewer
- Owner: builder
- Problem: `internal/dns/run.go` resolves A/AAAA/CNAME only — NS-delegation takeover, dangling MX, SPF/DMARC gaps, CAA/SRV exposure all invisible; takeover pack sees depth-1 CNAME shape.
- Fix: parallel `TypeResult`s with same caps/cache envelope; needs results channels + rules to deliver value (multi-milestone — no zone transfer, no brute force, pure record reads).
- Verification: hermetic fake-resolver tests per type; cache parity; goldens reviewed.
- Scope (2026-09-03, orchestrator recon): T1 engine MX/TXT/NS/SRV (stdlib `net.Resolver` covers these; CAA/SOA have NO stdlib lookup → deferred spike, no hand-rolled DNS client without architectural sign-off); MX/NS/SRV targets get depth-1 A/AAAA closure mirroring CNAME (dangling-MX decidability); TXT answers ride a new strings payload (no asset-schema change in T1); SRV ports decided in T1 within storedType only. T2 publication (new edge kinds + evidence carriage) and T3 informational rules follow as separate tasks. No AXFR (zero hits in repo), no CNAME recursion beyond depth 1.
- T1 close-out (2026-09-03, orchestrator): engine VERIFIED (resolver branches, closureTargets generalization, storedType Strings/Ports + strict kind-gates incl. pre-T1 backward-compat decode, MaxTXTStringBytes=4096 drop-and-count; 17 new records_test.go tests; dns gates + race green) + adapt fixture widening VERIFIED (reviewer APPROVE: all-7-type failure scripting preserves failed-bucket intent, counts exactly hosts×7, no closure miscount, no weakened assertions; full `go test ./...` green). Stale `dns_test.go:724` brute comment (`A/AAAA/CNAME`, `3 plus 2`) left for T2 cleanup.
- T2+T3 close-out (2026-09-03, orchestrator): T2 publication VERIFIED then review-APPROVED (host_to_mx/ns/srv kinds, assemble emission, dns:txt/dns:srv evidence with bounds, out-of-domain scoping, truncation chain, determinism; no golden drift — fixtures script A-only) + follow-ups VERIFIED+APPROVED (brute corpus-only docs, clip-caveat sentence, StickyFlags merge + pin). T3 dnsrec pack VERIFIED then review-APPROVED (5 rules information/0.6/1.0.0: dangling-NS/MX, weak-SPF, missing-DMARC, SRV-exposure; clipped-silence guards traced; takeover untouched; new golden additions-only). Non-blocking LOWs carried as future polish (SPF redirect= precision, multi-target citation, truncation pins for MX/DMARC/SRV, evidence-const drift pin). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-127 (MEDIUM) — POST/body/header reflection scope
- Status: VERIFIED — orchestrator-verified 2026-09-03 (review→fixes→re-verify APPROVE; gates green, see close-out; header reflection stays unprobed)
- Reporter: reviewer
- Owner: builder
- Problem: NEW-120 reflection covers GET query params only (`httpprobe/reflect.go`, `adapt/urllive.go:addReflection`); POST-only endpoints never flagged and GET-clean says nothing about POST.
- Fix: POST form/JSON canary reflection (still benign liveness, §0-compliant) or explicit `reflection_scope=query-get-only` meta so hunters don't trust silence.
- Verification: hermetic POST echo/encode/silent tests; triage gating unchanged for GET; gates green.
- Close-out (2026-09-03, orchestrator): POST form/JSON channel VERIFIED (CT-heuristic discovery, GET-first budget, scoped evidence, triage isolation) → review CHANGES-REQUESTED (HIGH: triage dropped GET-silent+POST-reflected; MEDIUMs: acceptance-framing, lowercased wire fields) → fix round VERIFIED+APPROVED (POST-aware dropSilent via ReflectEvidenceScope with distinct reflection_post meta, isolation preserved; original-spelling wire fields; read-error Truncated both channels; scope rejects unknown; legacy-decode pin). Residuals documented: state-changing endpoints may receive one benign POST; HTML-hosted forms never probed. Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

### NEW-128 (MEDIUM) — Takeover table expansion + S3-endpoint confirmation
- Status: DEFERRED — orchestrator-confirmed 2026-09-03: analysis (2026-09-03) found no safe code delta (NXDOMAIN unclaimed names, CloudFront 403 FP factory, Shopify frozen-store signal, S3-endpoint needs out-of-domain fetches); Fastly "unknown domain" is the single candidate pending field verification of the exact string. Implement ONLY with field-verified strings; hermetic tests cannot verify provider page content.
- Reporter: reviewer
- Owner: (unassigned)
- Problem: HTTP confirmation covers 3 providers vs 13 DNS suffixes (`httpprobe/takeover.go` vs `packs/takeover/helpers.go:70`); S3 rule is shape-only and often out-of-domain.
- Fix: curated strings for the 13 (same bounded-GET contract) + S3-endpoint fetch path (`NoSuchBucket` vs `AccessDenied`); stays informational per §0.1.
- Verification: per-provider hermetic tests; S3 deferral lifted with scope analysis; goldens reviewed.

### NEW-129 (HIGH) — Chunked documents/snapshot for big bundles (windowing Phase 2)
- Status: VERIFIED — orchestrator-verified 2026-09-03 (Slices 1–3, each review-gated; gates green, see close-out)
- Reporter: builder
- Owner: builder
- Problem: NEW-124 Phase 1 recovers endpoints/techs/secrets/evidence/imports from big-bundle prefixes, but secrentel documents, snapshot bodies, and detect-JS findings still skip over-cap files (they need retained BYTES with stable identities, and prefix windows have none).
- Fix: chunk-identity design — per-window documents + snapshot bodies keyed by derived chunk identities (kind-bound, deterministic), windowed fetch-cache records that never serve as complete files, per-chunk analyze records bound to chunk hashes; secrentel scans chunks; detect pack parses chunks. Must preserve: truncated-never-completed invariant, cache coherence across chunking changes, merge determinism.
- Verification: 5 MiB bundle with secret in tail window → secrentel candidate + js.dom.xss finding citing the file; warm-run behavior pinned; goldens reviewed; gates green.
- Slice 1 close-out (2026-09-03, orchestrator): chunk identities (single-constructor, fragment-safe) + manifest (cap/read gates, same-key shrink recovery, incomplete-never-served) + chunk docs (aliased, Truncated false) + file sentinel + SourceAsset=file citation VERIFIED and review-APPROVED (OD-4 measured 800 B vs 8 KiB, OD-5 rune-snap, aliasing genuine); follow-ups done (bound 16→32 + 17-window pin, sentinel seam test, dedup total assert, test-only comment, tail-cut doc); hostile golden regen reviewed by orchestrator (exactly 5 chunk docs + sentinel; secrentel +2 counted/0 candidates; detect incomplete_input flag; clean/messy diffs are pre-existing wave drift, zero rr-chunk). Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures. Slice 2 (per-chunk analyze cache) and Slice 3 (snapshot/detect) remain.
- Slice 2 close-out (2026-09-03, orchestrator): js.analyze.chunk op (parser/tiling/session key, AnalyzedHash cross-validation, verbatim decode gates) + index-order union with single applyAnalysis + OD-3a manifest-based orphan delete VERIFIED and review-APPROVED except 1 HIGH (delete-failure aborted Put) → fixed + orchestrator-verified in code (stash-and-continue, Put always executes, error reported after; keys reconstructed via constructor, never verbatim) + Truncated-reject guard added to both analyze decodes; regression tests green. Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures. Slice 3 (snapshot chunk assets + buildJSContents mapping + JS-pack subject normalization + goldens) remains.
- Slice 3 close-out (2026-09-03, orchestrator): chunk assets in Results.JavaScript (sizeless, files-first) + buildJSContents mapping (direct/file-fallback, sentinel→incomplete_input, displacement documented) + JS-pack subject→file normalization (file-relative offsets, overlap→1 finding, predicates unchanged, rules 1.2.0) VERIFIED and review-APPROVED (context.go linkage minimal, twin assessed, flipped pins legitimate, saturation carve-out correct, no chunk bytes in finding identity); follow-ups done (shared ChunkIdentityOfScript export, numeric window order ×3 sites + pins, doc lines) + js_report.golden regen versions-only, no other drift. 5 MiB tail sink → file-cited finding; warm parity byte-identical. Final tree gates re-run by orchestrator: gofmt/vet/build clean, go test ./... 0 failures.

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

