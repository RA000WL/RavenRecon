# RavenRecon

Intelligent reconnaissance framework for authorized bug bounty and security testing.

## Status

**v1.0.0**

RavenRecon has a normalized asset model (`internal/asset`), a persistent,
filesystem-backed cache and resume foundation (`internal/cache`), a bounded,
cancellable, rate-limited runtime engine (`internal/runtime`), and its first
consumer: passive subdomain discovery (`internal/discovery`) with adapters
for subfinder, assetfinder, and amass (passive mode only).

Active infrastructure is landing incrementally: the DNS pipeline
(`internal/dns`, roadmap v0.6 sub-milestone 5A) and the HTTP probing
pipeline (`internal/httpprobe`, sub-milestone 5B) now exist as library-level
capabilities. DNS resolves A/AAAA/CNAME records into typed, cached Phase 2
observations with host→address and host→CNAME relationships; HTTP probing
attaches typed HTTP observations (status code, final URL, redirect chain,
bounded headers, counted body size, TLS flag, and — on completed https
handshakes — typed TLS metadata: the leaf certificate as a Phase 2 asset
plus ALPN/issuer/subject/SAN names) to every host's http and
https root targets. URL intelligence (`internal/urlintel`, roadmap v0.7
sub-milestone 6B) adds canonical-URL streaming with parameter extraction,
endpoint classification, per-(URL, adapter) caching, and typed graph edges;
historical-URL tool adapters for gau, waybackurls, and waymore followed in
sub-milestone 6C (`internal/urlintel/adapt`, see "URL intelligence
(library)" below). Technology detection (`internal/techintel`, phase 6.5)
lands as a library capability: a fingerprint engine that recognizes
frameworks, servers, CDNs, WAFs, clouds, authentication providers, CMSes,
API technologies, build tools, and infrastructure from typed observations
(headers, body, cookies, TLS/DNS metadata, endpoint paths), with
confidence scoring, evidence records, and a 145-fingerprint database (see
"Technology detection (library)" below). JavaScript intelligence
(`internal/jsintel`, roadmap v0.8, phase 7) adds the JavaScript Intelligence
Engine as a library capability: script URLs discovered from raw lines, HTML
observations, and external tool adapters are fetched, parsed, and analyzed
into typed Phase 2 assets with two cache-before-execute operations. Secret
intelligence (`internal/secrentel`, phase 8) adds the Evidence & Secret
Intelligence Engine: bounded documents (JavaScript, source maps, HTML, JSON,
environment files, configuration, YAML, XML, GraphQL, OpenAPI, HTTP
responses) are scanned against a compiled pattern database and every
candidate is classified into a structured evidence model — pattern
fingerprints, entropy assessment, extracted context, multi-evidence
correlation, and a multi-factor confidence score with explicit
false-positive suppression — plus an offline verification queue for a later
verification phase. The priority engine (`internal/priority`, phase 9)
adds the Attack Surface Intelligence Engine: canonical Phase 2 assets
reduced to scoring signals are matched against two data-driven catalogs
(53 indicators), every score is a fully explained factor list with
evidence-tied reconnaissance recommendations, correlated into groups and
evidence-tied attack-path hypotheses, and served through a bounded,
cache-integrated engine stage (see "Priority engine (library)" below). The
detection framework (`internal/detect`, phase 10) adds the Detection
Framework & Rule Engine: reusable detection rules — immutable, validated
descriptors plus detector functions — execute against the canonical
knowledge graph on the shared runtime pool with dependency-ordered levels,
per-rule timeouts, panic isolation, a rule result cache, execution metrics,
and a canonical Finding model; the framework itself detects nothing and no
vulnerability-specific rules ship (see "Detection framework (library)"
below). The reporting framework (`internal/report`, phase 11) adds the
Reporting & Evidence Export engine: a caller-composed run input is
normalized once into the canonical report model (validated, deduplicated,
merged, identity-sorted, with statistics, run/error summaries, and a
digest), and registered, validated reporters render it as deterministic
JSON, CSV, Markdown, and self-contained HTML exports through atomic
crash-safe file writes, with export validation before exposure and an
optional render cache (see "Reporting framework (library)" below). The
eventing foundation (roadmap v1.2, phase 12) adds the canonical runtime
event model and the concurrent, bounded, non-blocking event bus
(`internal/event`) — typed, validated, clock-stamped events with sealed
payloads, per-subscriber bounded buffers with drop counters, bus-assigned
sequence order, the Observer instrumentation seam, and the Deriver/Deriving
pool-job-boundary bridge (see "Eventing (library)" below). Terminal
observability (`internal/tui`, roadmap v1.2) is the first bus consumer,
as a library capability: a single-goroutine controller replays the
canonical event stream into a live terminal frame — progress, worker
dashboard, throughput and ETA, resource sampling, an interesting-asset
feed, and a grouped error feed — plus one deterministic final summary
frame, with every dynamic string sanitized at the boundary and every
structure bounded (see "Terminal observability (library)" below). None
of the pipelines has a CLI command yet; the remaining active engines
(crawling and secret verification) and the remaining v1.2 observability
consumers (loggers and replays) are still later
roadmap milestones.

The JavaScript Intelligence Engine (roadmap v0.8, phase 7) provides:

- a canonical JavaScript asset model — size, content hash, content type,
  ETag, last-modified, status, final URL, host — with typed
  `javascript_to_*` edges;
- discovery seams: raw lines (URLs, relative references resolved against a
  base), full HTML observations (script `src`, qualifying `link`/Link
  headers, inline-script imports), and tool adapters;
- a bounded fetch engine: fixed request shape, bounded retries, bounded
  redirect walks, streaming content limits with honest truncation (a
  partial prefix is never retained), and transparent gzip decompression;
- an error-tolerant, stdlib-only parser abstraction (a hand-rolled
  tokenizer plus an extraction walk) with fixed, cache-stable bounds;
- an import graph with bounded expansion — resolved imports become new
  fetch candidates; bare specifiers (`react`, `@scope/pkg`) identify
  third-party libraries;
- source map detection and normalization (`sourceMappingURL` comments and
  `X-SourceMap` headers become SourceMap assets — never fetched, never
  parsed);
- endpoint extraction (GET/WS/SSE/GQL classes carried in the Method field
  — never an observed HTTP method) plus different-host URL observations;
- secret candidate extraction across 8 families — candidates only, no
  verification, no severity (the boundary is deliberate);
- JavaScript technology detection from a marker table with a confidence
  model consistent with `techintel`'s;
- `js.fetch` and `js.analyze` cache records — per-URL fetch content and
  per-URL analysis payloads, both cache-before-execute;
- bounded limits throughout: per-run script, import-depth, per-file
  import/map/endpoint/secret/technology/evidence caps;
- adapters for subjs (MIT), LinkFinder (MIT), and SecretFinder (GPL-3.0) —
  active tools that fetch the target themselves, installed on PATH or via
  the documented wrapper / per-run path-override contract.

## Asset model

The asset model provides typed, canonical representations of reconnaissance
data:

- Domain, Host, IP, Port, Service
- URL, Endpoint, JavaScript, Parameter
- Technology, Evidence
- Finding (phase 10: the canonical detection finding — one structured,
  evidence-cited judgment a rule produced about one subject asset)

Every asset has a deterministic, namespaced identity for deduplication,
records provenance ("where did this come from?"), supports deterministic
merging, and serializes to JSON. See `ARCHITECTURE.md` for details.

Deferred to later phases: the asset
store/graph and the graph correlation engine (the priority
engine's identity-anchored Correlate, phase 9, is not that engine).

## Cache and resume

RavenRecon ships a persistent, filesystem-backed cache foundation
(`internal/cache`) that future stages use to skip repeated work and resume
interrupted scans:

- Deterministic cache keys derived from the operation, the normalized Phase 2
  asset identity, the operation's result-relevant configuration, and (where
  applicable) the external tool and version. See "Cache keys" in
  `ARCHITECTURE.md`.
- Structured, schema-versioned JSON records that distinguish completed,
  failed, cancelled, and incomplete work. Terminal output is never the
  primary data model.
- Crash-safe writes (unique temp file + fsync + atomic rename). A reader never
  observes a partially written entry.
- Self-healing corruption handling: corrupted, oversized, or
  schema-incompatible entries are reported as distinct outcomes, never
  trusted, and removed so the next run recomputes them.
- An optional, configurable TTL measured from creation time (zero disables
  expiration).
- A documented single-process concurrency model; no cross-process locking is
  claimed.

Cache configuration lives in `internal/config` (`CacheConfig`: `Enabled`,
`Dir`, `TTL`). The default cache directory is
`os.UserCacheDir()/ravenrecon`, and the cache is **disabled by default**. The
`discover` command reads and writes the cache only when it is enabled in
configuration; `--no-cache` forces it off for a single run.

## Passive discovery

`ravenrecon discover <domain>` runs passive subdomain enumeration through
installed external tools:

```text
subfinder -d <domain> -silent
assetfinder <domain>
amass enum -passive -d <domain>
```

Only passive modes are ever invoked; no active enumeration, brute force, or
intel modes are reachable from RavenRecon. Output is normalized through the
Phase 2 asset model, deduplicated by identity, and merged across sources with
provenance (source + discovery time). Each source reports its detection
state — `[OK]`, `[WARN]`, or `[MISSING]` with a reason — and its outcome
(completed / partial / failed / cancelled / skipped). Tool detection
distinguishes executable existence, execution, version, and capability; a
broken version flag never reports an installed tool as missing. Every tool
invocation is bounded (timeout, cancellation, capped stdout/stderr capture).
A Ctrl-C/SIGTERM mid-run cancels gracefully — the partial report is still
printed, the exit code is 1, and a second signal force-exits immediately.

Run with cache (when enabled in configuration):

```bash
ravenrecon discover example.com
ravenrecon discover example.com --sources subfinder,amass
ravenrecon discover example.com --no-cache
```

Results are cached per source with keys covering the operation, the canonical
target identity, the passive mode, and the tool name/version; only completed,
unexpired entries are reused. The `doctor` command reports the same per-source
detection states. See `ARCHITECTURE.md` ("Passive discovery") for details,
partial-result semantics, and known limitations.

## DNS pipeline (library)

`internal/dns` (roadmap v0.6, sub-milestone 5A) resolves host assets into
typed, cached DNS observations: A, AAAA, and CNAME records normalized
through the Phase 2 asset model, with typed host→address and host→CNAME
relationships, a bounded pool with a central query limiter, per-(host,
record type) cache-before-execute, and hermetic tests (no public Internet).
NXDOMAIN and legitimate empty answers are completed observations; truncated,
failed, and cancelled types are never served as success. It is a library
capability only — there is no `ravenrecon dns` command yet. TLS metadata
(5C) has landed as part of HTTP probing (see below). See
`ARCHITECTURE.md` ("DNS pipeline") for the full design and security
considerations.

## HTTP probing (library)

`internal/httpprobe` (roadmap v0.6, sub-milestones 5B and 5C) probes
discovered host assets at their two root targets — `http://host/` and
`https://host/` — with typed, cached observations: final status code, final
URL, bounded redirect chain, bounded final headers, counted body size, and
the TLS-handshake flag. On a completed https handshake the probe also
captures typed TLS metadata (5C) from the very handshake it performs — the
leaf certificate as a Phase 2 asset (identified by its SHA-256 fingerprint)
plus the ALPN protocol, issuer DN, subject CN, and SAN DNS names, mapped
onto `techintel.TLSInfo`. Connection refusals ("service absent") and TLS
handshake failures
("https not served") are completed negative observations; timeouts and DNS
failures are failed probes; hard-cap hits are truncated-incomplete and
never served from cache. Probing runs on a bounded pool with one central
request limiter, per-target cache-before-execute, and hermetic tests
(loopback servers, no public Internet). It is a library capability only —
there is no `ravenrecon http` command yet. See `ARCHITECTURE.md` ("HTTP
probing") for the full design and security considerations.

## URL intelligence (library)

`internal/urlintel` (roadmap v0.7, sub-milestone 6B) streams raw observed
URLs through the Phase 2 asset model: each line is canonicalized at the
ingest boundary (never trusted raw; userinfo carried by a raw line is
redacted at that same construction point), classified as a GET endpoint,
and mined for query parameters
(names and values kept exactly as observed), then cached per (URL, adapter)
with cache-before-execute. Observations merge at emit time across adapters
into one deterministic report per canonical URL, and every entry carries
typed graph edges (host → url, url → endpoint, url → parameter, endpoint →
parameter). Runs use a bounded pool with optional job-start rate limiting,
and all tests are hermetic (synthetic input and a real filesystem-backed
cache). There is no `ravenrecon url` CLI command yet — URL intelligence is
a library capability only.

Historical-URL tool adapters (`internal/urlintel/adapt`, sub-milestone
6C) present external commands as line streams into the engine: gau,
waybackurls, and waymore (katana and paramspider are deferred as
documented future work). The tools must be installed — detection is
tool-specific (version probes where the tool supports them, existence-only
where it does not), and absent tools are skipped honestly: a broken or
garbled version probe never reports an installed tool as missing. Tool
invocations are bounded and shell-free (args as separate argv values, the
target never concatenated), captured output is capped per tool, and the
tool name enters cache keys and provenance so the same URL seen via two
tools merges into one report entry with unioned sources. See
`ARCHITECTURE.md` ("URL intelligence") for the full design and security
considerations.

## Technology detection (library)

`internal/techintel` (roadmap phase 6.5) fingerprints what a target runs —
frameworks, servers, CDNs, WAFs, cloud platforms, authentication
providers, CMSes, API technologies, build tools, and infrastructure —
from typed observations: response headers, HTML body, cookies, TLS
metadata, DNS CNAME chains, and endpoint paths. It never fetches and never
executes JavaScript: a caller composes an observation from its own probes
and feeds it to `Ingest`, which analyzes it against the compiled
fingerprint database (`internal/techintel/fingerprints`, 145 fingerprints
/ 296 indicators across 21 categories), scores every detection by weight
(High/Medium/Low/Unknown, with spoofable-only caps and a structural
requirement for High), and emits typed Technology and Evidence assets plus
asset-graph edges (host/url/endpoint → technology, technology →
evidence). Detections are cached per target under operation `tech.detect`
with cache-before-execute — a cache hit serves the stored result with ZERO
analysis, and the cache key carries the fingerprint database content
digest, so a data-only table edit invalidates every cached detection —
and observations merge deterministically at emit time, with
honest completed/cancelled/failed/malformed statuses. Runs use a bounded
pool with cancellation and bounded diagnostics, and all tests and
benchmarks are hermetic (synthetic input and a real filesystem-backed
cache). There is no `ravenrecon tech` CLI command yet — technology
detection is a library capability only. See `ARCHITECTURE.md` ("Technology
detection") for the full design, confidence model, and security
considerations.

## JavaScript intelligence (library)

`internal/jsintel` (roadmap v0.8, phase 7) is the JavaScript Intelligence
Engine: a typed Source seam (raw lines, HTML page observations, tool
adapters) feeds a bounded worker pool where every candidate URL runs
cache-before-execute fetch → classify → parse → extract → merge → emit →
bounded import expansion. Fetches retain bounded content with honest
truncation (a partial prefix is never kept), follow redirects to http(s)
targets only under fixed caps — a non-http(s) redirect target is observed,
never followed — and classify completed negatives (`conn_refused`, `tls`)
as legitimate observations. The stdlib-only parser extracts imports, string
literals, and source map references without ever building an AST or
executing code; the analyzers turn those observations into endpoint
candidates, secret candidates (detection only — never verification),
technologies, and per-marker evidence. Two cache operations (`js.fetch`,
`js.analyze`) make both the content and the analysis reusable — a warm run
performs zero HTTP requests and zero parses. Tool adapters
(`internal/jsintel/adapt`) present subjs, LinkFinder, and SecretFinder as
line streams; the adapters are active (the tools fetch themselves), and
their executable/wrapper contract is documented in `ARCHITECTURE.md`. There
is no `ravenrecon js` CLI command yet — JavaScript intelligence is a
library capability only. See `ARCHITECTURE.md` ("JavaScript intelligence")
for the full design, limits, and security considerations.

## Secret intelligence (library)

`internal/secrentel` (phase 8) is the Evidence & Secret Intelligence
Engine — deliberately not a "secret scanner": every emitted candidate is a
structured evidence tree, never an anonymous string. A typed `Document`
seam (11 kinds: JavaScript, source maps, HTML, JSON, env files,
configuration, YAML, XML, GraphQL, OpenAPI, HTTP responses; caller-composed,
the engine never fetches) feeds one bounded `runtime.Pool` where every
document runs cache-before-execute (operation `secret.scan`) → scan →
correlate → score → merge-at-emit. Each result carries the canonical Phase 2
`asset.SecretCandidate`, the matched pattern fingerprints, an entropy
assessment (Shannon, character class, UUID/JWT shapes, length weighting),
extracted context (variable/JSON-key names, comment containment, nearby
provider indicators), correlation links (provider endpoints, same-provider
sibling pairs, cross-document repeats), and a confidence verdict with every
contributing factor recorded. The pattern database
(`internal/secrentel/patterns`, 43 compiled fingerprints across 35 secret
types — the count is asserted by the patterns package test) is data-only
and compile-once, with required literal anchors that
gate the case-insensitive families (a measured ~40× scan-speed
improvement). False-positive reduction is a first-class stage: documented
provider example values and placeholders are suppressed outright;
documentation/test/sample contexts cap confidence at Low; entropy rules
drop prose; contextual duplicates of structured matches are removed; and
entropy alone can never classify a secret. An offline verification queue
(medium-confidence and above, unflagged, deterministically ordered) records
what a future verification phase should consume — nothing is ever verified
online, and the queue itself is never cached. Truncated documents report
their prefix candidates but are stored incomplete and never served from
cache. There is no `ravenrecon secret` CLI command yet — secret
intelligence is a library capability only. See `ARCHITECTURE.md` ("Secret
intelligence") for the full design, the confidence model, and security
considerations.

## Priority engine (library)

`internal/priority` (roadmap v0.9, phase 9) is the Attack Surface
Intelligence Engine: it consumes canonical Phase 2 assets reduced to
scoring signals and produces explainable, deterministic priorities for
which surfaces deserve a researcher's attention first. It is explicitly
NOT a vulnerability detector: no severity, no CVEs, no weakness claims —
every score is an interestingness judgment whose every factor cites the
canonical asset identity it was derived from, so every result audits back
to observations.

Signals and the scoring contract: two data-driven, compile-once catalogs
(40 interestingness and 13 risk indicators — 53 entries, every one
validated at load) match observed signals — endpoint/URL paths, host
labels, technology names and categories (carrying the detection phase's
own confidences), secret candidate types (carrying the secret engine's
own confidences), parameter names, service names, ports, final-response
headers, JavaScript bundle sizes, asset kinds, and endpoint classes. The
overlap policy emits one factor per (category, field) group — the longest
matching literal wins, literals beat regexes, ties break by indicator ID.
Composition is the same combine math as the confidence engines:
score = 1 − ∏(1 − w_g) over groups, where each group's weight is
1 − ∏(1 − w_f) capped at 0.6 per indicator category and 0.5 for the
confidence group; levels are gated (high needs score ≥ 0.8 and at least
two independent indicator categories). Confidence is composed only from
confidences the earlier phases actually recorded — never invented. Every
indicator factor also carries a rendered reconnaissance recommendation
(guidance language only), and the catalogs enforce compile-time template
and byte bounds: each reason/recommendation template carries exactly one
`%s` seam — its only percent sign (any other `%`, whether a second verb,
`%q`, `%d`, or `%%`, fails the load, because the score-time render
substitutes exactly one occurrence and any other percent would leak into
the emitted factor raw; verbatim regex/size/kind texts must be
percent-free) — and no rendered reason or recommendation can exceed its
byte bound for any matched term.

Correlation, attack paths, recommendations: `Correlate` groups scored
surfaces under anchors derived exclusively through the Phase 2
normalizers — URL/endpoint/JavaScript/source-map surfaces resolve to
their canonical host, hosts and domains anchor at their first-label-
dropped parent domain, IP literals at themselves, and anything that does
not re-canonicalize forms an honest singleton group. Each group's
aggregate score recomputes through the SAME combine math over the union
of its members' factors (repeat evidence strengthens an aggregate up to
the cap, never past it), with output bounded by fixed group/member caps
whose cuts are both surfaced: a per-group `Truncated` flag for the
member cap and `Correlate`'s boolean return for the group cap.
`AttackPaths` derives evidence-tied reconnaissance hypotheses — ordered
walks from a correlation root through correlated hosts and URLs to a
final evidence attachment, every step citing the exact factor reason and
evidence it came from; they are reading orders for a researcher, never
exploitation chains. `Recommend` projects a surface's factor list into
its recommendations — deterministic, evidence-tied, and preserved
verbatim across cache round trips.

Engine and cache semantics: the engine stage (`Score`) streams signals
from a channel through a bounded worker pool, composing
cache-before-execute around pool jobs per the architecture rule
(cache lookup → score → store; the runtime pool itself stays
cache-independent). Cache keys carry the operation `priority.score`, the
priority schema version, a fingerprint of BOTH compiled catalogs (any
catalog edit invalidates every cached score), and a digest of every
score-material signal field; observation timestamps never enter keys.
Every decoded record is strictly re-validated before use — the identity
must re-parse canonically through the Phase 2 builders, the level must
re-gate, every factor must re-validate (including the NaN guard), and
the score must recompose exactly from its own factor list — a violating
row is evicted and recomputed in the same run, never served. Outcomes
follow the house vocabulary: a run with failures or cancellations is
never `completed`. There is no `ravenrecon priority` command yet — the
priority engine is a library capability only.

## Detection framework (library)

`internal/detect` (phase 10) is the Detection Framework & Rule Engine: the
execution engine that runs reusable detection rules against the canonical
knowledge graph. The framework itself detects nothing — it provides rule
registration, validation, dependency-ordered scheduling on the shared
runtime pool, per-rule timeouts with panic isolation, a rule result cache,
execution metrics, detector benchmarking, and the canonical Finding
pipeline. Vulnerability-specific rules (XSS, SSRF, BAC, SQLi, CVE
matching, ...) are future phases; none ship here, and the framework
contains no browser automation, no exploitation, and no AI.

Rules: every rule is an immutable descriptor — canonical ID, name,
description, one of 14 categories, semantic version, declared input and
output domains, dependencies, required asset kinds, estimated cost,
timeout, author, enabled flag — plus a `Detector` function. The Registry
validates every rule at registration (metadata completeness, duplicate IDs
and names, category/version/cost/input/output/asset-kind vocabularies,
dependency syntax, timeout bounds) and stores deep copies, so a registered
rule can never be mutated through a caller-held alias. The dependency
graph is validated before every run: missing references and cycles are
rejected at startup with the smallest offending rule named.

Context and findings: detectors receive a fixed, immutable Context — the
normalized corpus domains (assets, relationships, evidence, technologies,
secret candidates, JavaScript, endpoints), a bounded configuration map, a
bounded Logger, the cancellation context, and the injected Clock — and
nothing else. They operate only on structured assets (no raw HTTP, JS, or
URL parsing — those phases are complete) and return canonical
`asset.Finding` values: identity (`ruleID@subject`, namespaced by the new
`finding` kind), category, rule metadata, confidence, evidence records,
related assets, relationships, priority, status, timestamps, and bounded
typed metadata — never anonymous maps. The engine validates every finding
against the rule's own metadata (a rule can never forge another rule's
findings), the asset model's bounds, and the observed corpus (a finding
can never cite an asset that was not observed — not as its subject, not
as a related asset, not as an evidence source), and requires at least one
evidence record — a judgment that rests on nothing is not representable.

Execution: one bounded `runtime.Pool` per run (no new scheduler); layered
Kahn elimination computes deterministic dependency levels in
O(V log V + E) — no quadratic scheduling — and rules within a level
execute in parallel while a rule runs only after all of its dependencies
completed (a failed, cancelled, or skipped dependency cascades an honest
skip). Every detector call runs under its rule's own deadline with panic
recovery (a panicking rule fails alone), findings stream through an
optional emit hook, and the report is deterministic: rules sorted by ID,
findings merged by identity and sorted, counts, aggregate outcome in the
house vocabulary (skips for disabled rules or absent required asset kinds
are honest observations, never failures; a run whose retained findings
were cut at the 4096-finding cap reports incomplete — truncated results
are never completed). Identical runs are identical up to the findings
cap; above it, the retained findings are the completion-order prefix.

Cache and metrics: one `detect.rule` record per rule per run,
cache-before-execute composed around pool jobs exactly like the other
consumer stages. The key carries the detect schema version, the rule ID,
the fingerprint of
the rule's full declared metadata (version included — the documented bump
contract), the fingerprint of the normalized snapshot (identities plus
every observable JavaScript asset field — content hash, size, content
type, ETag, last-modified, discovery source, status code, final URL, host
— and full provenance source/reference/confidence on JavaScript,
technology, evidence, endpoint, and secret entries; provenance timestamps
deliberately excluded), and
every configuration entry. Only completed executions are cached — partial
executions never are — and every decoded record is re-validated through
the same checks the fresh path applies; a tampered record is evicted and
recomputed in the same run, never served. Metrics accumulate execution
time, cache hits and misses, errors, timeouts, panics, and finding counts
per rule and in aggregate; `BenchmarkDetector` measures any unregistered
rule against a snapshot with the same isolation and validation.

There is no `ravenrecon detect` command yet — the framework is a library
capability only.

## Reporting framework (library)

`internal/report` (roadmap v0.10, phase 11) is the Reporting Framework &
Evidence Export. Reporting is presentation only: the framework consumes
the canonical graph, findings, evidence, and metadata the earlier phases
produced and never rescans a target, never mutates the data it is given,
and never invents a field.

A caller composes one `Context` — the typed Phase 2 corpus (every asset
kind, relationships, evidence, findings), the priority engine's surfaces,
groups, and attack paths, the run's error log, and its
runtime/cache/execution statistics — and `NewModel` normalizes it exactly
once: every entry re-validated through the Phase 2 builders (a
non-canonical entry is rejected, not repaired), deduplicated, merged, and
identity-sorted, with the statistics engine, the fixed-vocabulary run
summary, the category-grouped error summary, and a SHA-256 model digest
computed once. Every format renders from that one canonical model, so
identical inputs produce byte-identical reports.

Reports register like rules (validated metadata, duplicate-ID rejection)
and four builtins ship: a versioned compact **JSON** export of the
complete model, a six-dataset **CSV** export (one table per dataset, with
spreadsheet-formula injection neutralized in the presentation), a
human-readable **Markdown** summary with honest row caps and escaped cell
delimiters (content backslashes doubled before pipes are escaped), and a
self-contained static **HTML** report (inline CSS, `<details>` sections,
vanilla-script search and filtering, no frameworks, no external
resources, every byte escaped). Every output is validated before it is
exposed (schema version, CSV shape, Markdown structure, HTML balance),
written through atomic crash-safe file writes (unique temp file + fsync +
rename; a failed or cancelled render leaves no file and never overwrites
the previous good one), into deterministic filenames derived from a
sanitized base name. The engine runs every active reporter as one job on
the shared bounded runtime pool with cancellation, streaming, and
per-render deadlines, and can optionally compose cache-before-execute
around renders (operation `report.render`) with strict decode
re-validation — oversized renders are honestly never cached. Benchmarks
cover the 100 / 1,000 / 10,000 / 100,000 asset targets. There is no
`ravenrecon report` command yet — the framework is a library capability
only. See `ARCHITECTURE.md` ("Reporting framework").

## Eventing (library)

`internal/event` (roadmap v1.2, phase 12) is the observability foundation:
a canonical, typed runtime event model and a concurrent, bounded,
non-blocking event bus. It is observer-only — data flows one way from
instrumented code (the runtime pool, the cache, stage result bridges) to
consumers (a future TUI, loggers, replays); no consumer can call an engine
through it, and no engine mutates run state through it.

The canonical event model: 27 typed `Kind` values (scan/worker/task
lifecycle, cache hits and misses, asset/relationship/evidence/finding/
recommendation observations, requests, rule executions, warnings, errors,
progress, phase transitions, shutdown, run metadata, summaries), a
bus-assigned strictly increasing `Sequence`, an injected-clock timestamp
(zero-timestamp events are stamped by the bus clock), a `Severity`, bounded
phase/category/identity/value context labels, and a sealed, typed `Payload`
— never an anonymous map, every field a documented projection of a real
Phase 2 / runtime / report / detect / priority field. Events validate at the
bus boundary (invalid events are dropped and counted, never delivered, never
sequenced) and bounded payload constructors (`NewWarning`, `NewError`,
`NewTaskTerminal` family) truncate rune-safe with an explicit marker, so a
well-behaved emitter never produces an event the bus must reject.

The bus (`Bus`/`Subscriber`): publish never blocks the caller — every
subscriber owns a bounded buffer, a full buffer drops the event for that
subscriber and counts it (per subscriber and in the bus aggregate), and
delivery is a non-blocking enqueue under the publish lock, so every
subscriber receives events in bus-assignment order even under concurrent
publish. Subscribers close explicitly (`Close`, idempotent, `Done` fires,
buffers drain through `Next` before `ErrSubscriptionClosed`); `Bus.Close`
closes all subscribers and drops — counted, unsequenced — later publishes.
The `Observer` interface is the instrumentation seam (nil = off switch, zero
behavior change; the Bus satisfies it, so instrumented code publishes
straight into a bus), and the `Deriver`/`Deriving` bridge is the single
pool-job-boundary construction point for derived events (asset discovered,
finding created, ...): engines never emit them; a caller-provided `Deriver`
converts `task_completed` results into canonical derived events at the
boundary. All concurrency is bounded: no goroutine per event, no unbounded
queue, race-tested, leak-tested, and benchmarked (~0.5 µs/publish with a
draining consumer). The runtime pool is the first instrumented engine: an
optional `Config.Observer`/`Config.Deriver` makes it emit canonical
scan/worker/task lifecycle, phase-transition, honest-progress, and shutdown
events with every payload field grounded in a real pool field — the
progress wire guarantee: `Completed` never exceeds `Total` (the submission
counter increments before enqueue and every rejection compensates it), and
the shutdown final event carries exact totals — with a nil observer
= zero behavior change. The cache is instrumented the same way
(`internal/cache`, roadmap v1.2): `Open` accepts an optional
`WithObserver` option, and when set, every `Get` publishes exactly one
canonical `cache_hit`/`cache_miss` event carrying the real lookup outcome
— the key digest, the `Outcome.State` label ("hit", "miss", "expired",
"corrupt", "schema-incompatible", "incomplete", "error"), and
`Outcome.IsHit()`, with the event kind consistent with the payload (the
bus enforces it). A nil observer is the off switch (zero behavior change,
a single nil check per lookup), emission never blocks a cache operation
(publish is a non-blocking enqueue that drops and counts on a full
subscriber buffer), and only `Get` emits — writes, deletes, clears, and
maintenance walks publish nothing. See `ARCHITECTURE.md` ("Cache
instrumentation"). The TUI controller is the first bus consumer (see
"Terminal observability (library)" below); loggers and replays are the
remaining v1.2 observability items, and there
is still no CLI command wiring any of it. See
`ARCHITECTURE.md` ("Event bus").

## Terminal observability (library)

`internal/tui` (roadmap v1.2) is the first consumer of the event bus: a
library that renders a live, deterministic picture of a running scan from
canonical events alone. It is observer-only — consuming and rendering
never calls an engine, never mutates execution state, and cannot change
what a run does; a frame is a pure function of the events consumed so far,
the injected clock, and the resolved options.

The `Controller` drives the loop over one `event.Subscriber`: `Run` is
single-goroutine by contract (it owns the state, the replay history, and
the writer for its whole lifetime and spawns nothing), selecting on
events / refresh ticks / context cancellation / subscriber close. It
returns when a `scan_stopped` event concludes the stream, the subscriber
closes, or the context is cancelled — an already-cancelled context is
detected before the loop starts and wins over any buffered events. Before
returning, the controller drains whatever remains buffered (non-blocking),
so the final frame reflects the whole stream, and writes exactly one final
summary frame (`RenderFinal`) at the timestamp of the last consumed event.
A failed or partial write (including EPIPE) disables rendering for the
rest of the run while events keep flowing, the controller never panics,
and the first write error is what `Run` returns.

The `State` model projects the stream into the documented components:
progress (phase, in-flight, completed/remaining/total — unknown totals
render honestly, never a faked percentage), the worker dashboard
(per-worker idle/waiting/running/stopped with current task and duration),
fixed-window throughput rates (assets, urls, requests, js, rules,
relationships, cache hits and misses over a 10 s window), an ETA
estimator that is honest about unknown totals and zero rates, best-effort
resource sampling on render ticks only (heap, goroutines, open file
descriptors, queue depth, active workers), a rate-limited and
deduplicated interesting-asset feed, a severity-ranked grouped error
feed, and the final run summary — derived only from the consumed stream.
A bounded replay history (`MaxEventHistory`, hard cap 4096) keeps the
tail of the stream in sequence order, so a fresh `State` is
reconstructible from it.

Configuration flows through the existing `config.TUIConfig`:
`OptionsFromConfig` normalizes zero fields to the documented defaults
(250 ms refresh interval, 1024-event history, 10 events/s interesting
rate), and `Color` renders only when it is exactly `"on"` — the caller
resolves `"auto"` from its own terminal detection, and the library never
probes the terminal, never enters raw mode, and never reads keys. Every
dynamic string is sanitized at the controller boundary before it can
reach a frame (ESC sequences, C0/C1 controls, DEL, and invalid UTF-8 are
stripped; the renderer adds only its own fixed color codes), and every
structure is bounded (subscriber buffer, history ring, throughput sample
rings, a 64-item interesting feed, a 32-group error feed, 200-byte
lines, 64 KiB frames) with drop counters exposed on the components that
drop — loss is measurable, never silent. The package is hermetic: no
terminal probing, no public Internet, deterministic fake-clock tests
with an injected resource sampler. There is no CLI command yet — the
library is a capability for the eventual dashboard command. See
`ARCHITECTURE.md` ("Terminal observability").

## Runtime engine

A bounded, cancellable, rate-limited job execution engine lives in
`internal/runtime` (roadmap v0.3):

- Exactly `Concurrency` worker goroutines run jobs inline; the pool never
  creates a goroutine per job, so the parallelism is exactly bounded.
- A bounded submission queue applies backpressure: `Submit` blocks while full
  and the queue never grows without bound.
- A single central, standard-library token-bucket limiter (`Rate`/`Burst`)
  gates every job start, regardless of concurrency.
- Every job's lifecycle — started, completed, failed, cancelled, timed-out —
  is delivered to subscribers through bounded, lossless event channels.
  Cancellation is always reported as cancelled, never as failure or success.
- `Shutdown` drains queued and in-flight work gracefully, with a forced path
  when the drain context is cancelled.
- The engine is generic and cache-independent by design: consumer stages
  (passive discovery, v0.5) compose "cache-before-execute" around runtime
  jobs. See `ARCHITECTURE.md` ("Runtime engine").

## Current commands

Show help:

```bash
go run ./cmd/ravenrecon --help
```

Show version:

```bash
go run ./cmd/ravenrecon version
```

Run environment diagnostics:

```bash
go run ./cmd/ravenrecon doctor
```

Run passive subdomain discovery:

```bash
go run ./cmd/ravenrecon discover example.com
go run ./cmd/ravenrecon discover example.com --sources subfinder,amass
```

`discover` options (after the domain): `--sources <a,b>` restricts the
sources, `--no-cache` disables the cache for the run.

Build:

```bash
go build -o ravenrecon ./cmd/ravenrecon
```

Test:

```bash
go test ./...
```

Race test:

```bash
go test -race ./...
```

## Design priorities

1. Reliability
2. Signal quality
3. Safety
4. Performance
5. User experience
6. Extensibility

## Architecture

See `ARCHITECTURE.md`.

## Roadmap

See `ROADMAP.md`.

## AI agents

All coding agents must read `AGENTS.md` before modifying the repository.

Agents must implement only the current roadmap milestone unless explicitly instructed otherwise.

## Responsible use

RavenRecon is intended for authorized security research, security assessments, and bug bounty programs where the target is explicitly in scope.

It is not intended to automate credential attacks, persistence, or exploitation.

## License

MIT.
