# RavenRecon

Intelligent reconnaissance framework for authorized bug bounty and security testing.

## Status

**v0.5.0 — Passive Discovery** (DNS pipeline landed as Active
Infrastructure sub-milestone 5A)

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
below). None of the pipelines has a CLI command yet; the remaining active
engines (crawling and secret verification) are still later roadmap
milestones.

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
URLs through the Phase 2 asset model: each line is canonicalized (never
trusted raw), classified as a GET endpoint, and mined for query parameters
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
analysis — and observations merge deterministically at emit time, with
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
truncation (a partial prefix is never kept), follow redirects under fixed
caps, and classify completed negatives (`conn_refused`, `tls`) as
legitimate observations. The stdlib-only parser extracts imports, string
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
consumer stages. The key carries the rule ID, the fingerprint of the
rule's full declared metadata (version included — the documented bump
contract), the fingerprint of the normalized snapshot (identities plus
the provenance fields a rule can read: technology version and provenance
source/reference/confidence, evidence and endpoint provenance
reference/confidence, JavaScript content hash and size plus provenance
reference/confidence, and secret provenance source/confidence;
provenance timestamps deliberately excluded), and
every configuration entry. Only completed executions are cached — partial
executions never are — and every decoded record is re-validated through
the same checks the fresh path applies; a tampered record is evicted and
recomputed in the same run, never served. Metrics accumulate execution
time, cache hits and misses, errors, timeouts, panics, and finding counts
per rule and in aggregate; `BenchmarkDetector` measures any unregistered
rule against a snapshot with the same isolation and validation.

There is no `ravenrecon detect` command yet — the framework is a library
capability only.

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
