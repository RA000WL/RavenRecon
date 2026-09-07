# RavenRecon — Elite Hunter Review (2026-09-05)

**Verdict:** strongest-in-class honesty engineering (normalization, truncation,
cache, bounds), weakest-in-class hunting leverage. It will not lose data, lie
about coverage, or melt the box. It will also not today tell you where to
attack first with the conviction a top hunter needs. Data collection →
intelligence transformation is ~60% built. Prioritization and detection are
real code, not stubs — but tuned for defensibility, not for finding the one
weird host that pays.

Scope: read-only review this session. No code changed. No gates run
(review-only, nothing to verify under AGENTS.md §13). Evidence from
`internal/asset`, `internal/pipeline(+adapt)`, `internal/runtime`,
`internal/cache`, `internal/event`, `internal/discovery`, `internal/dns`,
`internal/httpprobe`, `internal/urlintel(+adapt)`, `internal/techintel`,
`internal/jsintel(+adapt)`, `internal/secrentel`, `internal/detect(+packs)`,
`internal/priority`, `internal/report`, `internal/cli`, `internal/config`,
`internal/tui`, `TODO.md` (1 OPEN LOW NEW-130, 1 DEFERRED MEDIUM NEW-128).

## 1. Recon philosophy

Strong: single normalization point (`internal/asset`), fixed outcome vocabulary
(`completed/partial/failed/cancelled/incomplete`), truncation-never-completed
enforced end-to-end (sticky flags `dns_answers_truncated`, `probe_truncated`,
`Truncated`/`Overflow`), cache-before-execute with self-healing deletes.
Degrades honestly instead of hallucinating completeness. Rare and valuable.

Weak: philosophy is lossless retention, not vulnerability anticipation.
Pipeline asks "did we keep everything?" not "what is attacker-interesting?"
12-stage sequential pipeline
(`discover→dns→httpprobe→urlintel→crawl→techintel→jsintel→secrentel→urllive→priority→detect→report`)
computes intelligence after collection — interesting hosts found in stage 11
cannot trigger deeper fetch. No feedback loop. No adaptive behavior
("looks like admin → fetch robots/sitemap/JS aggressively").
`priority/recommend.go` guidance is navigation aid, explicitly not attack plan.

## 2. Bug hunter workflow — the 8 questions

| Question | Answer today |
|---|---|
| Where to attack first? | Partially. Surfaces/Groups/AttackPaths sorted score-desc. But score = recon-interest (High ≥0.8 + ≥2 categories), not exploitability. One leaked AWS key alone stays Medium (2-category gate). Parent-domain grouping can merge unrelated vhosts on shared infra. Usable order, not trusted order. |
| What looks suspicious? | Partially. 29 detect rules + 43 secret patterns + TUI interesting feed (GQL/WS/SSE, admin paths, sourcemap, conf≥0.8). All heuristic/indicator-grade. Triage pack is param-name-only (`?id=`→IDOR, fixed 0.6) — fires on most of the web. |
| What changed? | **No.** No diff engine. Report digest changes but no delta report. Re-runs produce new dirs; hunter diffs manually. Single biggest workflow hole (new deploys = money). |
| Newly exposed? | No — same gap. No CT-stream monitor, no firstSeen surfacing in report. |
| Forgotten? | Weak. Staging/dev/legacy keyword matching only. No staleness detector (old issuers, ancient Server headers, bundle dates, cert age). |
| Internal? | Weak. Private-IP signals in catalogs; no internal-hostname semantics (corp.local, .internal), no metadata-endpoint surfacing. |
| High value? | Catalogs cover admin/secrets/GQL/WS/buckets/Firebase. No SSO/OAuth/OIDC, payment, API-docs, metrics/health semantic ranking. |
| Deserves manual review? | Yes — best part. JSON (pivotable) + Markdown/HTML (writeup-ready) + attack-path steps with verbatim reason + evidence refs. Saves ~30 min/run vs grepping JSON. |

Time-to-first-signal: `doctor` (~1s) → `discover` (minutes, end-buffered —
no streaming hosts, long amass runs look hung) → `scan --stages
discover,dns,httpprobe` (fast triage subset works) → full 12-stage scan
(120s/tool discovery budget dominates) → `ingest` replays foreign exports
(18 adapters, content-first, scope-filtered, provenance-tagged — genuinely good).

## 3. Attack surface coverage

Covered honestly: passive subdomains (5 binaries), 7 DNS types + closure
depth-1, HTTP root+port probe + TLS leaf (fp/issuer/CN/SAN≤32/ALPN), archived
URLs (gau/wayback/waymore), ~124 tech fingerprints (10 tables), JS
fetch+tokenizer+D1/D2, 43 secret patterns, takeover confirm (3 providers),
web-pack rules on imported evidence.

Gaps (verified):

- Subdomains: no CT/crt.sh/certstream/DNS-dataset beyond keyed chaos API.
  `asnmap` adapter exists but omitted from `builtInNames` (dead unless named).
  Brute 10-word default. Misses cert-only + cloud-ephemeral hosts.
- Certs: SANs captured but never fed back as targets. Chain>8 suppresses cert
  asset. TLS DNSNames retained but no indicator analyzes them.
- robots/sitemap/well-known: nothing fetches `/robots.txt`,
  `/sitemap*.xml`, `/.well-known/security.txt`, favicon. Findings depend on
  imported endpoints, never probed. Sitemap discovery absent.
- Crawl: `httpprobe` probes `/` only; no browser/JS-render; no
  JS-link→crawl feedback; unfetched actuator/robots paths never enter
  techintel corpus.
- APIs: REST-IDOR is shape heuristic; no GQL introspection probe, no OpenAPI
  fetch, no gRPC/WS/SSE handshake, no schema inference, no POST/body params
  (urlintel GET-only), fragment/body params missed.
- Auth: 1 rule (jwt-none-alg). No SSO/OAuth/OIDC flow detection, no
  session/cookie-security analysis beyond capture.
- Cloud/buckets: header/TLS-substring heuristics only. S3 confirm deferred
  (out-of-domain fetch wall). CloudFront-403 deliberately excluded → real
  dangling CF/Azure/Fastly unconfirmed. Takeover table = 3 providers
  (github/heroku/s3); expansion correctly deferred (NEW-128 — NXDOMAIN/403
  signals unsafe).
- Secrets: no online verification by design (revoked ≡ live). Contextual
  patterns need `var[:=]value` shape — JSON arrays, concatenations, split
  lines missed. Generic family capped Low but high-volume noise.
- Long tail — all absent: `.git/HEAD` probing, `/debug/pprof`, `/actuator`,
  `/healthz`, `/metrics`, `/swagger.json`, `/graphql`, `/.env`, backup zips,
  feature flags, mobile/APK surface, CI/CD artifacts, `package.json` /
  `composer.json`, header/cookie security parsing (SPF/DMARC in raw TXT only),
  CORS preflight active check, jQuery/CMS-plugin versions (react/vue/svelte/
  solid/nuxt/qwik versionless), WAF-bypass signals, headless-DB detection.

Coverage = union of installed tools + honest merge. No tools → thin (no CT
fallback, no active enum beyond 10-word brute).

## 4. Intelligence quality

Real inference: secrentel provider correlation + pair/repeat + explained
confidence (`1−∏(1−w)`, named factors, caps); techintel tier-aware scoring
(spoofable-only ≤0.59, lone-weak ≤Low); priority correlation + attack paths
(deterministic reading-order hypothesis, ≤8 steps, evidence refs — navigation
aid, not exploit chain); digest-pinned triage ordering.

Cannot infer: likely-admin (keyword only), internal-vs-external (no hostname
semantics), staging (keyword only, no cert/deploy freshness), forgotten (no
staleness), business-critical (no traffic/auth/stack join), privilege
boundaries / trust relationships (edges exist: `host→ip/cname/mx/ns/srv`,
`host→url→endpoint→param`, `url→tech/secret`; no trust-boundary detector
consumes them; CNAME flattening drops intermediate aliases, breaking
takeover-chain attribution).

Root cause: detectors read only the structured Context snapshot. Dropped
content (truncated JS, over-cap endpoints, unparsed inline scripts, unfetched
paths) is invisible downstream — honest skip, silent hole.

## 5. Prioritization engine

Model (`priority/score.go`, `catalog.go`, `table_interesting/risk.go`,
`correlate.go`, `attackpath.go`, `recommend.go`): Signal → per-category
combine (≤0.6) + confidence group (≤0.5) → `1−∏(1−w)`. High ≥0.8+2cats, Med
≥0.5+1, Low ≥0.2. Explainable, deterministic, repeat-evidence to cap.
Correlation by parent-domain (≤1024 groups, ≤64 members).

Better model (keep math, fix inputs):

1. Allow single-signal High at confidence≥0.9 + structural (non-spoofable)
   evidence. One live AWS key must page.
2. Add dimensions from existing channels: exposure (200 + interesting path),
   novelty (firstSeen-this-week via diff store), staleness (cert >2y,
   Apache/2.2, jQuery 1.x), auth-adjacency (login/OAuth/token within 2 hops),
   data-shape (`ssn,card,token,dump,export,backup` params).
3. Gate grouping on PSL + IP-diversity: shared-PSL-suffix + disjoint IPs →
   split. Fixes `*.herokuapp.com` merges.
4. Weight live state over archive: urllive 200-with-body must outweigh
   wayback-only existence. Absent-probe = explicit `unprobed` flag, not
   silent zero.

## 6. Detection quality

Framework excellent (Registry validation, cycle-reject, seal, per-rule
timeout/deadline, panic containment, `asset.NewFinding` validation,
version-in-cache-key, 256/rule + 4096/run caps). Rule quality varies:

- triage (8: sqli/ssti/xss/cmdi/ssrf/lfi/idor/redirect): param-name wordlist,
  fixed 0.6. Precision LOW, recall MEDIUM. Cap truncation in completion order
  is nondeterministic — switch to score-ordered truncation. Fix: require
  second signal (reflection/error/method+param); surface `subjects_dropped`.
- js (3: domxss/postmessage/prototype-pollution): was dead (NEW-118
  CRITICAL, VERIFIED fixed via SDK 2.1 `JavaScriptContent`, 2 MiB/body, 1024
  bodies/64 MiB caps). Now real-body Parse()+sink checks. Precision MEDIUM
  (sink ≠ exploitable, no taint), recall MEDIUM (minified partial). Correct
  scope.
- web (5: robots/sourcemap/csp/cors/hsts): best pack. Precision HIGH, recall
  LOW (nothing fetches robots/sitemap — rules fire only on imported
  evidence).
- apis (3): rest-idor shares triage weakness; graphql/openapi need observed
  paths. No active introspection. Precision MEDIUM, recall LOW.
- auth (1: jwt-none-alg): narrow, precise, low recall by design. Fine.
- cloud (3): shape matchers, informational-only per §0.1. Precision MEDIUM
  (shape ≠ exposed), recall LOW (no active confirm). Needs opt-in confirm.
- dnsrec (3): TXT-string level, no parsed SPF/DMARC. Precision HIGH, recall
  LOW. Parse the TXT — trivial win.
- takeover (3): deliberately narrow, documented refusal on CF/Shopify/Azure.
  Precision HIGH, recall LOW. Correct; NEW-128 deferral right.

## 7. Hunting methodology

Attack paths: real orientation aids, not exploit chains (docs honest).
Pivots: graph written, never read for offense. No shared-infra reasoner, no
CNAME-trust-boundary join, no JS supply-chain fan-out. Misconfig/trust/
smells: indicator-level only, no cross-signal join ("S3-host + open CORS +
secret in JS = now"). No behavior model (no status-change detector).
Developer-mistake surface (`.git`, pprof, actuator, metrics, backup.zip,
swagger.json, fixtures): keywords only, no fetch prober — the highest-ROI
hunter habit unimplemented while effort went to TUI frame bounds and event
byte caps.

## 8. Architecture

Good: thin adapters + pinned outcome/sticky-flag table, no global registry,
fail-continue deterministic first-seen merges, read-only live-slice contract,
observer-only non-blocking bus (drop+count, panic-contained), sharded atomic
FS cache (TTL/status/self-heal), fixed-worker pools, token-bucket limiter,
injected clocks.

Debts:

- Sequential-only pipeline. Slow stage blocks all; Timeout default off.
  DAG-ify: parallel independent groups (dns+urlintel), probe→techintel→
  jsintel feedback edge. 2–4x on wide scopes, medium effort.
- `0 means default` conflates unset with disabled (Timeout/Rate). Explicit-zero
  semantics needed.
- Submit backpressure blocks caller (64/4 defaults) with no overflow signal.
- One central limiter per pool — no per-host fairness; slow host HoLs bucket.
- Per-(URL,adapter) triple records (same URL × 3 tools = 3 records);
  raw-record consumers double-count. IP assets absent from corpus (nil ip
  map) — IP pivots incomplete. External-host JS observations dropped —
  third-party secret signal lost by design.
- Bus drop-on-full silent to data path; TUI can lose `finding_created` with
  only a counter. Production publishes lifecycle only — totals/in-flight/
  ETA/throughput/interesting render empty (self-documented `scanUsage:80-84`).
  Frame scaffolding ahead of data.
- Config precedence documented but unimplemented (flags→env→file→defaults;
  only `Default()` exists). Discover untunable (2 flags). `--timeout`
  per-stage vs `Discovery.Timeout` per-tool naming trap. Ingest grammar
  flipped (options-before-target). Three TUI cliffs (XOR verbose,
  compact-requires-tui, single-target-only).
- Nil transport = live dialer (fail-open default; tests must inject fakes).

## 9. Performance — exact optimizations

No profiles cited; per §14 measure before cutting. Expected, ordered by
probable wall-clock impact:

1. P1 — Pipeline DAG (arch, §8). Sequential stages dominate, not CPU.
2. P2 — Re-sort-per-emit (urlintel accumulator, report `NewModel` O(n log n)
   ×12 stages on 100k URLs). Pass sorted sets forward; sort once at render.
   Impact: large-scope CPU; effort: low-medium; trade-off: merge-contract edits.
3. P3 — Duplicate-URL inflation (`%20` vs `+` distinct, value-preserving
   query semantics → double probe of identical resources). Canonicalize
   encoding once at `asset.ParseURL`. Impact: fewer probes (network = wall
   clock); effort: low; trade-off: identity migration (cache keys shift —
   bump SchemaVersion deliberately).
4. P4 — Per-host limiter fairness (shard token bucket per host, global
   ceiling preserved). Impact: tail-latency/HoL; effort: medium; trade-off:
   limiter complexity.
5. P5 — Report paging/sharding (200k-scope rejection → chunked render +
   per-shard digests). Impact: enables huge scopes; effort: medium;
   trade-off: report-format addition (paged manifest).
6. P6 — Batch limiter wake (timer churn at high rate). Impact: small CPU;
   effort: low.
7. Measure-first: `sanitize-at-boundary` per-event cost; 32 KiB identity
   truncation frequency (grep `…` markers in corpus — missed joins if hot);
   lowered-corpus memory on 8 MiB JS bodies (already bounded; confirm with
   `mem_test.go` + bench before touching).

What NOT to touch: compile-once regex DB, single-pass lowercase corpus,
anchor-gated secret prefilter, bounded queues/rings, 2 MiB document bound —
all sound.

## 10. Hunter experience

Joy: `ingest` replay, `--dry-run` pre-flight, per-source provenance, partial-
on-cancel, multi-format report, per-target summaries.
Friction: end-buffered discover silence (looks hung) + no `--output`;
scan/ingest grammar asymmetry; case-variant duplicates rescanned;
exit-0-if-any-success masks CI fleet failures; TUI shows least
(`--verbose` more informative today); doctor read-only; cache off by default
→ first scan always cold. Net: good assistant, not yet partner.

## 11. Missing features (beyond today's tools)

1. Change-diff engine (`scan --diff last/`): digest-keyed baseline + delta
   report (new hosts/URLs/tech/secrets/status-changes). Medium effort (model
   already digest-pinned). HIGHEST ROI — new deploys = money.
2. Mistake-path prober: 40 well-known fetches on every live host (reuse
   httpprobe transport + techintel corpus). Low effort. Second-highest ROI.
3. CT-stream + SAN-feedback (`crt.sh`/certstream source; SAN→target loop).
   Medium. Closes largest coverage hole.
4. Nuclei/httpx handoff export (target+tech-shaped lists + severity map).
   Low. Feeder, not rival.
5. Offline-safe secret validators (JWT decode+expiry, key-shape checks,
   explicitly non-network). Low. Never auto-verify online (§0.1).
6. API schema inference (archived+crawled+JS-mined → per-host surface).
   Medium-high. Differentiator.
7. Browser-render opt-in pass behind flag + separate pool. High effort.
8. Vhost/shared-infra reasoner over existing graph. Medium.
9. Revolutionary: assumption ledger — detectors emit assumptions as
   queryable evidence; hunter re-ranks under "assume Server headers spoofed".
   Static caps → interactive tradecraft. Nothing does this today.

## 12. Competitive analysis

- ProjectDiscovery: RavenRecon wraps their tools; wins on honesty/caching/
  provenance, loses on ecosystem/templates/active checks. Strategy: feeder.
- Amass: deeper enum + graph; wins on determinism/bounds, loses on depth
  (alt-brute, datasets, graph queries).
- Katana/httpx: deeper crawl / wider probe. Loses both until mistake-prober
  + SAN feedback land.
- Naabu: port scanning absent (HostPorts only); ingest accepts naabu JSON —
  keep as feeder.
- Aquatone: no screenshots; MD/HTML partially substitutes; visual gap open.
- ReconFTW: wins on engineering (typed assets, no shell interpolation,
  cache correctness), loses on tool breadth + notify/diff loops.
- BBOT (closest rival): wins on cache determinism, truncation honesty,
  FP-gated confidence, report quality; loses on module count, active checks,
  cloud enum, ecosystem velocity. BBOT is a workshop; RavenRecon a surveyor's
  instrument.
- AI-assisted: no LLM seam (good — stdlib-only, no leak surface). Opportunity:
  offline-consumable evidence packs (finding+evidence+confidence JSONL); AI
  consumes, never decides; core stays deterministic.

Wins: unattended reliability — the only framework here trusted for wide
scopes without babysitting. Loses: attacker imagination — finds what tools
emit, not what developers hide.

## 13. Brutal criticism

- TUI scaffolding shipped ahead of instrumentation — flagship flag renders
  empty sections on real runs. Theater until publishers exist.
- Triage pack at fixed 0.6 on param names fires everywhere, informs nowhere.
  Require a second signal or cut half the rules.
- `/`-only probing + no robots/sitemap fetch + SANs never becoming targets:
  three coverage decisions costing more missed surface than all 124
  fingerprints polish.
- `0-means-default`, nil-transport-live-dialer, exit-0-if-any-success:
  footguns at the operator boundary in a reliability-first project.
- ARCHITECTURE claims config precedence that doesn't exist. Fix doc or ship
  loader.
- Sequential pipeline guarantees priority stays reporter, never director.
- Subdomain story is "install 5 binaries and pray" — honest-truncation
  machinery papering over missing CT/DNS-dataset built-ins.
- Report refuses 200k-host scopes instead of paging. Reliability that
  refuses large jobs isn't reliability.

Fixable without rewrites except DAG-ification (additive: parallel groups +
feedback edges).

## 14. Scorecard

| Dimension | Score | Reason |
|---|---|---|
| Recon capability | 6 | Honest tool-union + solid base; hollow at CT, crawl, mistake-paths, APIs, cloud, auth. |
| Bug bounty usefulness | 5 | Processes well; doesn't help strike first (no diff, noisy triage, gated High). |
| Signal quality | 6 | Best-in-class gating (secrets/tech/confidence) dragged by param-name detectors + generic-secret volume. |
| Performance | 7 | Bounded, compile-once, sane caps. Sequential stages + re-sort + dup-URL taxes. No profiles. |
| Scalability | 5 | 100k caps, 16 MiB records, 200k rejection, central-limiter HoL, manual sharding. |
| Extensibility | 8 | Registry+seal, Rule/Source contracts, constructor seams, versioned SDK. Adding packs genuinely easy. |
| Code quality | 8 | Single normalizer, injected clocks, containment, redaction, determinism, fixtures. NEW-130 blemish. |
| Architecture | 7 | Clean layers, observer-only bus, sidecar cache, fail-continue. Minus DAG/config/TUI/operator edges. |
| Detection quality | 5 | Framework 9/10, rules 5/10. Web/auth/takeover precise; triage/apis noisy; cloud/dnsrec thin; JS taintless. |
| Hunter experience | 6 | ingest/dry-run/provenance/partial-cancel/report = joy; buffered discover, grammar, TUI emptiness, cold cache = friction. |
| Innovation | 4 | Honesty machinery novel as packaging; zero hunting inventions (no diff/ledger/inference/reasoner). |
| Production readiness | 7 | Unattended-safe: bounded, cancellable, redacted, deterministic. Minus large-scope refusal, silent drops, live-dialer defaults, CI-masking exits. |

## 15. Roadmap (impact × effort)

Immediate (days–2 weeks): mistake-path prober; robots/sitemap/security.txt
fetch + SAN feedback; streaming discover + `--output`; triage second-signal +
score-ordered truncation; single-signal High for structural≥0.9; NEW-130
single-label drop; TXT SPF/DMARC parsing; doc-or-ship config precedence,
`--timeout` rename, grammar unification.
Next milestone (weeks–2 months): diff engine + baseline store + delta report;
CT/certstream source; asnmap default-or-deprecate; DAG parallel groups +
probe→techintel→jsintel feedback + per-host fairness; TUI instrumentation or
demotion; cloud opt-in confirm; JWT offline validators; PSL-aware grouping;
explicit-zero config; large-scope sharding; Nuclei/httpx handoff.
Long-term (quarters): API schema inference; vhost reasoner; browser-render
opt-in; staleness detector; assumption ledger (five-year differentiator).

Trade-offs: active probing costs stealth/time/scope-risk — flag-gated,
default passive. Diff storage costs disk/baseline UX — worth it. DAG
parallelism costs determinism complexity — first-seen order at merges,
independent groups first.

## Optimization & improvement suggestions (consolidated)

| # | Suggestion | Reasoning | Expected impact | Complexity | Trade-offs |
|---|---|---|---|---|---|
| O1 | Pipeline DAG: parallel dns+urlintel; feedback probe→techintel→jsintel | Sequential stages dominate wall-clock; intel can't steer collection | 2–4x faster wide scopes; higher recall on interesting hosts | Medium | Determinism care at merges; keep first-seen order |
| O2 | Sort once, pass sorted sets forward (urlintel/report) | O(n log n) ×12 stages on 100k URLs wasteful | Large-scope CPU down | Low-medium | Merge-contract edits |
| O3 | Canonicalize `%20`/`+` + query encoding once in `asset.ParseURL` | Duplicate identities → double probes (network = wall clock) | Fewer probes, cleaner corpus | Low | Identity migration; deliberate SchemaVersion bump |
| O4 | Per-host limiter fairness under global ceiling | Single slow host HoLs central bucket | Tail-latency down | Medium | Limiter complexity |
| O5 | Report paging/sharding + per-shard digests | 200k-scope refusal = failed reliability promise | Huge scopes runnable | Medium | Report-format addition |
| O6 | Score-ordered finding truncation (replace completion-order prefix) | Re-runs show different sets above 4096 cap | Deterministic, trustworthy caps | Low | None material |
| O7 | Triage second-signal gate; surface `subjects_dropped` | Fixed-0.6 param-name fires everywhere, trains ignore | Pack credibility restored | Low | Fewer (better) findings |
| O8 | Single-signal High at structural≥0.9 | One live key must page; 2-category gate suppresses | Criticals surface | Trivial | Slight High-volume up |
| O9 | Mistake-path prober (40 paths, existing transport) | Highest-ROI hunter habit, unimplemented | Real vuln-leads per run | Low | Scope/stealth — flag-gate, default passive |
| O10 | robots/sitemap/security.txt fetch; SAN→target feedback | Unfetched paths never enter corpus; SANs wasted | Coverage jump, cheap | Low-medium | Extra requests — bound + cache |
| O11 | CT/certstream source; asnmap default-or-deprecate | Largest subdomain hole; dead adapter confuses | Cert-only hosts found | Medium | External dependency; key management |
| O12 | Diff engine + baseline store + delta report | Change = money; currently manual | Transforms bounty workflow | Medium | Disk + baseline UX |
| O13 | Streaming discover + `--output`; TUI instrumentation or demotion | "Looks hung" runs; empty flagship sections | Trust + live signal | Low-medium | Output-contract addition |
| O14 | Parse SPF/DMARC from TXT; JWT offline validators; PSL-aware grouping | Evidence already held, unused | Precision up, merges fixed | Low | None material |
| O15 | Nuclei/httpx handoff export | Stop rivaling PD ecosystem; become best feeder | Adoption + combined value | Low | Format maintenance |
| O16 | Explicit-zero config; unify scan/ingest grammar; rename `--timeout`; ship-or-fix config file/env | Operator-boundary footguns in reliability-branded tool | Fewer misconfigs, less friction | Low | Flag-compat care |
| O17 | Assumption ledger (queryable detector assumptions + re-ranking) | Static caps → interactive tradecraft; no rival offers it | Five-year differentiator | High | Research-grade; keep core deterministic, ledger as observer layer |
