# RavenRecon — Optimization & Upgrade Recommendations

> **Source audit:** v1.4.0 (`go 1.26.5`, stdlib-only) — full architecture review across
> `internal/asset`, `internal/cache`, `internal/runtime`, `internal/config`,
> `internal/discovery`, `internal/dns`, `internal/httpprobe`, `internal/urlintel`,
> `internal/techintel`, `internal/jsintel`, `internal/secrentel`, `internal/priority`,
> `internal/detect`, `internal/report`, `internal/event`, `internal/tui`,
> `internal/pipeline`, `internal/cli`.
>
> Complements `ROADMAP.md`, `ARCHITECTURE.md`, `TODO.md`. Each item carries
> **file:line evidence**, **severity**, and **concrete fix + verification**.
> Statuses map to roadmap phases: `v1.4` (in-flight), `v1.5` (next), `v1.6`–`v1.8`, `v2.0`.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [How this document is organized](#2-how-this-document-is-organized)
3. [P0 — Critical: data quality & hunting effectiveness](#3-p0--critical-data-quality--hunting-effectiveness)
4. [P1 — High: hardening, correctness, durability](#4-p1--high-hardening-correctness-durability)
5. [P2 — Medium: operator experience & performance](#5-p2--medium-operator-experience--performance)
6. [P3 — Planned: roadmap-aligned upgrades](#6-p3--planned-roadmap-aligned-upgrades)
7. [Cross-cutting optimizations](#7-cross-cutting-optimizations)
8. [Upgrade paths & sequencing](#8-upgrade-paths--sequencing)
9. [Metrics to track](#9-metrics-to-track)
10. [Appendix — finding index](#10-appendix--finding-index)

---

## 1. Executive summary

**The framework is architecturally sound.** Layering (`CLI → config → runtime → stages → asset`),
bounded concurrency, crash-safe self-healing cache, single normalization point, deterministic
merges/digests, observer-only event bus, and recon-only adapter safety are all systematically
enforced and test-pinned. The biggest unlock is **not a new engine** — it is feeding the
existing ten-stage pipeline (`discover → dns → httpprobe → urlintel → techintel → jsintel →
secrentel → priority → detect → report`) with **honest, bounded, live-checked inputs**.

**Three gaps block effectiveness today** (field-trial evidence in `ROADMAP.md:v1.5`):

- A passive-discovery burst (`37,248` hosts → `12,366` probe URLs, `500/500` jsintel fetch
  failures) poisoned the corpus — no per-source anomaly gate exists yet.
- JS-extracted endpoints are reported but never re-enter the URL corpus for live-checking.
- No per-URL liveness triage — every historical URL lacks `2xx/4xx/5xx/timeout/refused`.

All three are scoped as `v1.5` and sequenced in §3. The remaining items are ordered
hardening → operator experience → future platform work, each with evidence and verification.

---

## 2. How this document is organized

- **Priority:** `P0` blocks field trials; `P1` is correctness/durability; `P2` is operator-visible
  improvement; `P3` is planned roadmap work.
- **Severity:** `CRITICAL / HIGH / MEDIUM / LOW / INFO` — same scale as `TODO.md`.
- **Evidence:** `path:line` from the audited tree. **Fix:** actionable steps. **Verify:** gates/tests
  that prove completion (`gofmt`, `go vet`, `go test`, `go test -race`, `go build`, plus
  hermetic E2E pins).

---

## 3. P0 — Critical: data quality & hunting effectiveness

### OPT-P0-1 (CRITICAL) — Per-source burst anomaly gate — discovery poisoning

- **Evidence:** `ROADMAP.md:v1.5` field trial: `subfinder v2.15.0` burst `37,248` wordlist-shaped
  hosts for `example.com` → `12,366` probe URLs → `1,024` priority groups, `32` attack paths,
  `755` recommendations — all garbage. `discovery/parse.go:21` counts malformed but has no
  volume/burst cap; `pipeline/corpus.go:45` `capCorpus` is global, not per-source.
- **Impact:** Poisoned corpus cascades through `dns → httpprobe → urlintel → techintel → jsintel →
  secrentel → priority → detect → report`; every downstream signal is wasted.
- **Fix:**
  1. `internal/discovery/quality.go` (new) + `pipeline/adapt/discovery.go`: per-source
     `MaxHostsPerSource` (e.g. `5000`, configurable via `StageConfig`/`StageParams`), burst
     heuristic (entropy / label-length distribution / wordlist-shape), `StickyFlags["discovery_truncated"]`
     + `Truncated` already exists — surface the flag in `report`.
  2. Decision point `flag | abort | continue` **before** `mergeCorpus` (`pipeline/run.go:262`);
     never let a suspicious source poison downstream stages.
  3. Verify the local `subfinder` binary/config — trial notes possible tampered build; add
     `doctor` check for binary hash / config path.
- **Verify:** Unit: per-source cap tail-drop + StickyFlag; E2E: synthetic `37k` host burst → flagged
  `discovery_truncated`, downstream `probe URLs` capped not `12k`. `go test ./internal/discovery` +
  `go test -race ./internal/pipeline/...`.
- **Roadmap:** `v1.5` — must land before next field trial.

### OPT-P0-2 (HIGH) — JS → URL corpus feedback loop

- **Evidence:** `internal/jsintel/record_analyze.go:176` analyzer URL output is terminal — not
  emitted as `Document` additions into `pipeline/mergeDocuments` or URL corpus. `pipeline/document.go`
  carries JS documents for `secrentel` but not URL discovery.
- **Impact:** High-value API endpoints extracted from `.js` are dead ends — never
  `urlintel → urllive → priority`.
- **Fix:** `internal/pipeline/adapt/jsintel.go` additionally emits filtered URL additions via
  shared `filterURLs` helper: `asset.ParseURL` → `canonical-host/in-domain` (`pipeline/scope.go:22`
  `InDomain`) → dedup against incoming `StageInput.URLs` → bounded per-run cap with honest
  `jsintel_url_overflow` `StickyFlag` + `Truncated`. Add `Results` channel emission or dedicated
  `URLs` addition path (reuse `mergeCorpus` `seen` semantics).
- **Verify:** `TestJSIntelURLFeedback` — analyzer output `3` URLs (`/api/v1/users`, `https://other.example.com/x`,
  `https://evil.com/y` → only in-domain `2` admitted) → `RunReport.URLs` length probe + cap flag when
  overflow. Determinism pin (same input → same corpus order).
- **Roadmap:** `v1.5` second bullet.

### OPT-P0-3 (HIGH) — Live URL triage — new `urllive` stage

- **Evidence:** `ROADMAP.md:v1.5` refinement spec: every corpus URL (historical + JS-fed) lacks
  bounded live status. `internal/httpprobe/run.go:208` probes only `http://host/` + `https://host/`
  roots, not arbitrary URLs.
- **Fix:**
  1. `internal/httpprobe`: new `ProbeURLs(ctx, domain, urls, cfg)` — per-URL `GET` headers/status only,
     redirects `observed-not-followed` (M-6 consistency `jsintel/fetch.go:448`), TLS metadata reuse,
     per-URL timeout, bounded pool, `ProbeFailed/ReasonOther` taxonomy, results sorted by URL.
  2. New stage `urllive` inserted `secrentel → urllive → priority` (`ROADMAP.md:v1.5` pipeline):
     `adapt/urllive.go` consumes corpus URLs, produces `LiveRecord{URL, Status, RedirectObserved, TLS}` as
     **new results-channel entity** — not a field on `asset.URL` (avoids schema bump).
  3. `internal/pipeline/results.go`: new channel `LiveRecords`, `internal/report` gains URL-status
     section (presentation-only). Cache op `urllive.probe` key `schema/op/config-digest/URL`.
  4. `internal/pipeline/config.go`: update `AllStages` + stage vocabulary, `T4` determinism + `T5` E2E pins,
     `T6 --stages` rows.
- **Verify:** Hermetic: canned `RoundTripper` (`200/404/500/timeout/refused`) → `Report.LiveRecords`
  sorted; `0` recursion; determinism with/without cache; `go test -race ./internal/pipeline/...`.
  Field trial with `gau/waybackurls/waymore` installed shows `LiveRecords>0` + statuses.
- **Roadmap:** `v1.5` core deliverable.

### OPT-P0-4 (HIGH) — URL-intel tool hardening — per-tool deadlines

- **Evidence:** Field trial `gau` burned full `10m` stage budget; `3` tools × caps stack up.
  `internal/urlintel/adapt/source.go:525` copies outer `cfg.Timeout` into inner ingest — conflated.
  `jsintel` `500/500` failures with no early stop.
- **Fix:**
  1. `adapt.Config`: `PerToolTimeout` map + `ToolTimeoutDefault` (e.g. `2m`); `ToolTimeout` encloses
     runner only, ingest has its own budget. `amass` opt-in or `hard-timeout 5m` (trial `20m→0`).
  2. `jsintel/engine.go:648` health gate: if first batch `N≥50` fetch failures `>90%`, abort remaining
     fetches and emit `jsintel_health_abort` diagnostic + `StickyFlag`; still `completed` but honest.
  3. `AllStages` timeout propagation documented in `pipeline/config.go:127` (wall clock vs injected).
- **Verify:** Table test: tool `sleep 10m` + `PerToolTimeout 100ms` → `partial` with diagnostic, ingest still
  processes triaged remainder. E2E shows `gau` no longer starves `waymore`.
- **Roadmap:** `v1.5` tool-hardening bullets.

### OPT-P0-5 (LOW) — Honest run duration in JSON report

- **Evidence:** `ROADMAP.md:v1.5` `summary.started_at == ended_at` and `duration_ms 0` — report
  timestamps the summary write, not the run (`report/model.go:142` `StartAt/EndAt` from summary, not
  `pipeline/RunReport.StartAt/EndAt`).
- **Fix:** `internal/report/model.go`: carry `RunReport.StartAt/EndAt/Duration` into `Model.RunSummary`
  (honest wall-clock, not injected summary-write time); keep `Digest` stable (exclude duration from
  digest input). `report/writer.go` unchanged.
- **Verify:** Smoke E2E asserts `runReport.EndAt.After(StartAt)` and `report.json` `duration_ms>0`.
- **Roadmap:** `v1.5` report-status nit.

---

## 4. P1 — High: hardening, correctness, durability

### OPT-P1-1 (MEDIUM) — Directory fsync durability gap

- **Evidence:** `internal/report/writer.go:334` `Commit` does `Rename` after `tmp.Sync`/`tmp.Close` but
  never `fsync(dir)`; `internal/cache/cache.go:292` same for `Put`. POSIX may lose the rename on crash.
- **Fix:** After `Rename`, `os.Open(dir)` → `Sync` → `Close` (guard with `syncDir` helper; best-effort,
  ignore `ENOSYS` on non-POSIX FS). Keep per-file atomic (`writer.go:321` "per-file, never transactional
  across files") but document durability guarantee post-fix.
- **Verify:** Existing atomic-write tests pass; add `TestCommitSurvivesDirSync` (fault-injection via
  ` afero` not needed — assert `syncDir` call path exists via coverage). `go vet`/`go test`.
- **Phase:** In-flight fix, no roadmap dependency.

### OPT-P1-2 (MEDIUM) — Shared mutable `Context` / `Model` across parallel jobs

- **Evidence:** `internal/detect/context.go:68` `*Context` built once in `Engine.Run:445` and shared
  across parallel detector goroutines; `internal/report/model.go:147` `*Model` shared across concurrent
  `Reporter.Render` jobs. Contract says "must not mutate" but not enforced — a buggy/hostile rule
  can `append(Assets)` or `Config["k"]="v"` affecting peers.
- **Fix:** Option A (preferred): clone per job — `cloneContextForRule` shallow-copies slices/maps
  (new headers `append(nil, src...))` + `maps.Clone(Config)`) or expose getters only (`Findings()` copy).
  Option B: `sync.Once` freeze via `maps.Clone` + `slices.Clone` + document. Same for `report`: `cloneModel`
  or `Model.View()` per render. Cost is allocation per job (bounded by rule count ≤?).
- **Verify:** Regression `TestContextIsolation` — rule mutates `ctx.Assets[0]` + `ctx.Config` → peer rule
  sees original; `go test -race ./internal/detect -run TestContextIsolation` must pass pre- and post-fix
  (pre-fix would show race/flap under `-race`).
- **Severity note:** No exploit today (known-good rules only), but `v2.0` third-party packs raise severity
  to HIGH.

### OPT-P1-3 (MEDIUM) — Fuzz every parser / ingestion boundary

- **Evidence:** `ROADMAP.md:v1.6` planned but not landed — `asset/ParseURL`, `discovery/parse.go:21`,
  `urlintel/engine.go:554`, `jsintel/lex.go+parse.go+fetch.go`, `secrentel/scan.go:61`,
  `cache/cache.go:407 readEntry`, `report/*`, `dns/resolver.go`. No `//go:embed` fuzz corpora.
- **Fix:** Per `ROADMAP.md:v1.6` add `Fuzz*` targets (`testing/F` + `go test -fuzz` harness),
  property tests (`rapid` not available — stdlib `testing/quick` + hand-rolled `parse→Identity→parse`
  round-trip), parser hardening from findings. Seed with `internal/asset/testdata` + field-trial samples.
- **Verify:** `go test -fuzz=FuzzParseURL -fuzztime=30s` per target; triage log `invalid inputs` vs `crashers`;
  regression tests for every confirmed crasher/hang/OOM. Gates `go test ./...` + `go test -fuzz` in CI.
- **Roadmap:** `v1.6`.

### OPT-P1-4 (LOW) — Silent truncation in two merges

- **Evidence:** `asset/tls_certificate.go:334-339` `MergeTLSCertificates` DNSNames `capped 32` drop silent;
  `asset/finding.go:313-321` `MergeFindings` evidence `16`/related `32`/relationships `32` hard cut silent.
  Contrast `asset/merge.go:298 MergeParameters` `Truncated` sticky flag.
- **Fix:** Add `Truncated` boolean to `TLSCertificate`/`Finding` merge result or surface
  `<kind>_truncated` `StickyFlag` via `pipeline/results.go` channel caps (already exists for
  `Relationships` etc.). At minimum document silent-drop and add `TODO` to promote to flagged.
- **Verify:** Unit `TestMergeTLSCertificateTruncationFlag` — `33` DNSNames → `32` retained + flag asserted.
- **Phase:** `v1.6` hardening.

### OPT-P1-5 (LOW) — Weak TLS classification in jsintel fetch

- **Evidence:** `internal/jsintel/fetch.go:678` fallback `strings.Contains(err.Error(),"tls:")`
  vs `internal/httpprobe/run.go:912` structural `tlsHandshakeError` sentinel at `DialTLSContext`.
  Server-controlled bytes in error string could fabricate `tls` observation.
- **Fix:** Remove text fallback; wrap `DialTLSContext` with `tlsHandshakeError` sentinel mirroring
  `httpprobe/run.go:371,424`; classification by `errors.As` first, then typed `tls.AlertError` /
  `x509` set. If any stdlib fixed text must be caught, match on `errors.Is` wrapped sentinel only.
- **Verify:** `TestFetchTLSStructure` — hostile `rawResponder` injecting `tls:fake` status line →
  `ProbeFailed/ReasonOther` not `tls` (mirrors `httpprobe` spoof regression already pinned).
- **Phase:** In-flight.

### OPT-P1-6 (LOW) — `jsintel/fetch.go:480` truncated content honestly dropped but not flagged at engine level

- **Evidence:** `internal/jsintel/fetch.go:480` `readTerminal` declares `ContentLength>MaxJSBytes→truncated` with
  `Content=nil` (honest), but `internal/jsintel/engine.go:966` `processJob` only surfaces `Overflow`
  at analysis cap, not fetch truncation count in final `Metrics`.
- **Fix:** Add `FetchTruncated` counter to `Report.Metrics` (`engine.go:36`) and propagate as
  `StickyFlags["js_fetch_truncated"]` when any fetch truncated (mirrors `httpprobe` `probe_truncated`).
- **Verify:** Unit fetch `>2 MiB` → `Content=nil` + `Truncated=true` → stage `StickyFlags` contains flag
  and `Outcome partial` if vacuous? No — `jsintel` completed+truncated is not `partial` per spec; flag is observation.
- **Phase:** `v1.5` or `v1.6`.

---

## 5. P2 — Medium: operator experience & performance

### OPT-P2-1 (MEDIUM) — Split outer/inner timeouts; amass opt-in

- **Evidence:** §OPT-P0-4 covers fix; this item tracks the CLI/docs surface. `urlintel/adapt/source.go:355`
  outer pool `Timeout 30s`, inner `IngestWorkers 4`, but `gau` alone consumed `10m` stage budget.
- **UX Fix:** `ravenrecon scan --help` documents `GauTimeout / WaybackTimeout / WaymoreTimeout` (or
  `--url-tool-timeout`), and `--amass` as explicit opt-in with warning. Default `amass` skipped unless
  `--sources amass` or `--amass` flag. Add `scan --dry-run` that prints resolved effective timeouts.
- **Verify:** Help text snapshot test (`cli/scan_test.go`); hermetic timeout table test.

### OPT-P2-2 (MEDIUM) — Health-based early stop for jsintel

- **Evidence:** Same as §OPT-P0-4 health gate — operator-visible as bounded runtime.
- **UX Fix:** Log `WARN js_health_abort: 50/55 fetches failed (90%) — skipping remaining 445` at `INFO`
  severity via `event.KindWarning`; `report` `RunSummary` includes `js_health_aborted bool`.

### OPT-P2-3 (MEDIUM) — Observability: `--tui` fidelity

- **Evidence:** `internal/tui/controller.go:156` wired via `ravenrecon scan --tui` (`v1.4`), `tui/stages.go`
  live stage feed, `tui/throughput.go` rates, `tui/workers.go` dashboard. `TODO.md:NEW-21` pending fix:
  bounded stage list, sanitized strings, honest widget degradation when event sources missing.
- **Fix:** Land `NEW-21` (stage events from `pipeline/run.go:341` `StageStarted/Finished` carry real
  `ItemsProcessed/Failed/Duration/Truncated/Err`); dashboard honors `unknown` totals never faking `%`.
  `cli/scan.go:454` `resolveTUIColor` `ModeCharDevice → on else off`; `--tui-compact` requires `--tui`,
  mutually exclusive with `--verbose` (one `Observer` per run). Ensure `sub.Close() → <-tuiDone → bus.Close()`
  deterministic join (`cli/scan.go:512`).
- **Verify:** `TestScanTUIWiring` hermetic event flow + cancellation + broken-pipe warning-only; deterministic
  final frame `RenderFinal` at `lastEventAt`.
- **Roadmap:** `v1.4`.

### OPT-P2-4 (LOW) — Performance: remove hot-path allocations

- **Evidence:** `techintel/analyze.go:580` `strings.ToLower` per indicator (hundreds) on match/header;
  `priority/score.go:614` `json.Marshal` tie-break per surface; `httpprobe/run.go:387` `TLSClientConfig`
  clone per dial; `event/bus.go:97` `Publish` holds `mu` across fan-out.
- **Fix:**
  1. Cache lowercased haystacks once per observation (`buildCorpus` already does `bodyLower` —
     extend to header lower map). Reuse across indicators.
  2. Replace `json.Marshal` tie-break with deterministic tuple compare (`Score,Identity.String()`) —
     avoids marshal alloc + monotonic sensitivity (`OPT-P1`).
  3. Reuse `TLSClientConfig` template per `httpprobe` transport; clone only `ServerName`.
  4. `event.Bus.Publish`: snapshot `subs` slice under `mu`, release `mu`, then fan-out — sequence stays
     monotonic via `atomic next`, latency no longer linear in subscriber count.
- **Verify:** `go test -bench=Benchmark* -benchmem` before/after; no correctness change under `-race`.
  Add `bench_test.go` for each if missing.
- **Phase:** `v1.5`–`v1.6`.

### OPT-P2-5 (LOW) — Standalone stage CLIs (after `v1.6` hardening)

- **Evidence:** `AGENTS.md:2` deferred `dns/httpprobe/urlintel/techintel/jsintel/secrentel/priority/detect/report`
  standalone commands. Operators iteratively want `ravenrecon dns --hosts` / `ravenrecon http --alive`.
- **Fix:** Reconsider after `v1.6` fuzzing; each command reuses `internal/pipeline/adapt` staging but
  single-stage `ScanConfig` with its own `--output`. Keep `scan` as the canonical end-to-end path.
  Do not add before hardening (scope policy `AGENTS.md:5`).
- **Verify:** `cli/*_test.go` hermetic per-command; help snapshot; `doctor` reports stage toolchains.
- **Roadmap:** Deferred `v1.4` — revisit `v1.7`.

### OPT-P2-6 (INFO) — Deduplicate scope + version helpers

- **Evidence:** `dns/scope.go:15`, `httpprobe/scope.go:18`, `discovery/pipeline.go:269` `validateScope`;
  `discovery/detect.go:215`, `urlintel/adapt/tool.go:273`, `jsintel/adapt/tool.go:393` `versionPattern`.
- **Fix:** `internal/asset/scope.go` `InDomain(Host,Domain) bool` + `ValidateHost(Host,Domain) error` (cycle-free;
  `asset` already owns `Domain/Host`); `internal/discovery/version.go` single `versionPattern` exported for
  adapters. Keep `runtime ↔ cache` acyclic (`asset` is leaf).
- **Verify:** `grep -R validateScope` → single definition; `grep -R versionPattern` → single; `go vet`.
- **Phase:** Refactor, no behavior change.

---

## 6. P3 — Planned: roadmap-aligned upgrades

### OPT-P3-1 — Integration & acceptance testing (`v1.7`)

- **Evidence:** `ROADMAP.md:v1.7` — fixtures, expected outputs, snapshot tests, performance/memory baselines,
  CI regression suite. None landed yet.
- **Fix:** Add `fixtures/<target>/` + `testdata/*.golden` snapshot tests (`go test -update` regenerates),
  `Benchmark*` baselines recorded (`benchstat`), CI detects output drift + regression. Cover common +
  edge-case recon scenarios; snapshot failure names the regressed stage.
- **Verify:** `go test ./...` + `go test -bench` recorded; CI matrix `go 1.26.x`.

### OPT-P3-2 — Universal Asset Ingestion Framework (`v1.8`)

- **Evidence:** `ROADMAP.md:v1.8` — import `subdomains.txt/alive.txt/urls.txt/js.txt/burp.xml/nuclei.json`
  into canonical graph.
- **Fix:** `internal/importer` package `Importer{Name,CanImport,Import}` streaming (`10 MB/100 MB/1 GB+`
  bounded, progress events, cancellation, resume), auto format detection (extension/MIME/structure),
  every record via `asset.New*` single normalization, provenance `importer/tool/filename/time/originalRecord`,
  dedup via shared `Identity/Merge`, cache `content-hash+config+schema+importer-version`, `ravenrecon ingest`
  CLI (single/multiple files, folders), report `Discovered/Imported/Enriched/Generated` attribution.
  Imported findings are evidence only — never re-executed.
- **Verify:** Empty/malformed/duplicate/huge-file/cancellation/resume/cache/streaming/mixed imports;
  repeat unchanged import = cache hit; imported report structurally identical to pipeline-discovered.
- **Roadmap:** `v1.8`.

### OPT-P3-3 — Detection packs (`v2.0`)

- **Evidence:** `ROADMAP.md:v2.0` — frozen SDK `v1 (Core)` API `1.0` `internal/detect/api.go`, surface golden
  `testdata/api_v1.golden` + 9 behavior contracts, `internal/detect/examples` only pack (never auto-loaded).
- **Fix:** Pack families (Web, Auth, AuthZ, APIs, JS, Cloud, Business logic) load via `detect.Registry` +
  `CheckAPIVersion(1,0)` without core edits; metadata/dependencies/compat declared, isolated failures,
  same `Evidence` model. Stability policy + reopening criteria already docs-pinned (`ARCHITECTURE.md:2720`).
- **Verify:** Pack loads through SDK sans special-case core; pack tests + fixtures.
- **Roadmap:** `v2.0`.

### OPT-P3-4 — Observability consumers beyond TUI

- **Evidence:** `ARCHITECTURE.md:3141` + `README.md:Eventing` — `internal/event` observer-only bus supports
  multiple consumers; TUI is first (`internal/tui`). Remaining `v1.2` items: structured loggers, replays.
- **Fix:** `internal/tui` stays `library only` + `scan --tui` wiring; add `internal/log` bus consumer
  (JSONL per-event file), `internal/replay` deterministic re-render from recorded event stream.
  Contract: consumers never call engines, never mutate state.
- **Verify:** Hermetic logger/replay tests; `Bus.Drops/Invalid` metrics surfaced in summary.
- **Roadmap:** Post-`v1.4`.

---

## 7. Cross-cutting optimizations

### C-1 Concurrency & rate limiting

- All stages use `runtime.NewPool` — keep it. Central `Limiter` per stage is correct (job-start vs
  query-dispatch separated: `dns/run.go:170 Rate:0` + central limiter vs pool limiter). Do not reintroduce
  per-tool ad-hoc limiters that bypass the central bucket.

### C-2 Cache discipline

- Keys: `schemaVersion + operation + normalized target + material config + tool/digest` (`cache/key.go:98`).
  Timings, TTL, queue sizes never enter keys. `MaxRecordSize 16 MiB` bounds both write+read (`cache/cache.go:47,249`).
  Truncated `StatusIncomplete` never served; flagged `completed+Truncated/Overflow` allowed only where
  chain preserves flag end-to-end (`techintel`/`urlintel`/`jsintel` — verified `secrentel` `engine.go:376 →
  record.go:130 → record.go:172 → report.go:243`).

### C-3 Input trust boundaries

- Every ingest re-validates via `asset` builders (`discovery/parse.go:21`, `dns/scope.go:15`,
  `httpprobe/scope.go:18`, `urlintel/engine.go:560` single-point credential redaction).
  Keep `Original` preservation for provenance but never in `Identity`. Fuzz these boundaries first.

### C-4 Output bounding

- Every stream capped: `discovery 4 MiB`, `urlintel line 32 KiB`, `httpprobe 64 KiB/128/1 MiB/10 redirects`,
  `jsintel 2 MiB JS / 1 MiB HTML`, `techintel 128/512 HTML caps`, `secrentel 64 candidates/8 evidence`,
  `priority` capped, `detect 4096 findings`, `report 100k/modelPerKind`. Lowering caps re-truncates;
  raising caps retains more but never invalidates keys (fixed constants by design).

### C-5 Security invariants to keep

- Recon-only (`AGENTS.md:0.1`), no `sh -c` interpolation (`discovery/runner.go:147`), stdlib-only (`go.mod`),
  `runtime` never imports `cache`, no real secrets committed, errors/logs never leak secrets
  (`asset/url.go:36` `Original` handling, `secrentel` redaction, `tui/sanitize.go` ESC/C0 strip).

---

## 8. Upgrade paths & sequencing

```
v1.4  scan --tui (NEW-21 fix — stage feed, bounded stage list, sanitized strings)
  │
  ├─► v1.5  Real-world validation + URL hunting
  │          OPT-P0-1 burst gate → OPT-P0-2 JS→URL → OPT-P0-3 urllive → OPT-P0-4 per-tool deadlines
  │          + OPT-P0-5 honest duration + OPT-P1-6/P2-1/P2-2
  │
  ├─► v1.6  Fuzzing + hostile-input hardening
  │          OPT-P1-3 (every parser), OPT-P1-4, OPT-P1-5, C-3
  │
  ├─► v1.7  Fixture/snapshot/benchmark baselines + CI regression
  │          OPT-P3-1, OPT-P2-4 bench before/after
  │
  ├─► v1.8  Universal ingestion (Importer adapters)
  │          OPT-P3-2 — reuses every layer above; streaming, cache, provenance
  │
  └─► v2.0  Detection packs on frozen SDK v1
             OPT-P3-3 + OPT-P1-2 Context isolation for third-party packs
```

Do **not** land standalone stage CLIs, browser automation, or AI integration before `v1.6`
hardening — per `AGENTS.md:5` scope policy.

---

## 9. Metrics to track

| Metric | Where | Target |
|--------|-------|--------|
| `discovery_truncated` / `probe_truncated` / `documents_truncated` | `RunReport.StickyFlags` | `0` on clean targets; `>0` honest not silent |
| `cache Hit/Miss/Expired/Corrupt/SchemaIncompatible` | `cache.Outcome` + `event.CacheAccess` | `Hit` rises warm; `Corrupt` self-heals |
| `priority` score determinism | `engine_test.go` cold/warm parity | byte-identical `Surfaces/Groups/AttackPaths` |
| `detect` findings cap `4096` | `detect/engine.go:114` | `FindingsTruncated` monotonic per run |
| `report` digest | `report/model.go:967` | identical inputs → identical `digest` + files |
| `event` drops | `bus.go: Drops/Invalid` | `0` normal; bounded `TUI` `History.Dropped` measurable |
| `js_fetch_truncated` / `js_health_abort` | `jsintel/metrics` | monitored, not fatal |
| Fuzz coverage | `go test -fuzz` | each high-risk parser ≥1 target; zero crashers |
| Benchmarks | `bench_test.go` | `~0.5 µs/publish` bus, `1024` feed not regressed |

---

## 10. Appendix — finding index

| ID | Title | Severity | File:line | Roadmap | Status |
|----|-------|----------|-----------|---------|--------|
| OPT-P0-1 | Burst anomaly gate — discovery poisoning | CRITICAL | `ROADMAP.md:v1.5` `discovery/parse.go:21` | v1.5 | VERIFIED |
| OPT-P0-2 | JS → URL feedback | HIGH | `jsintel/record_analyze.go:176` `pipeline/document.go` | v1.5 | VERIFIED |
| OPT-P0-3 | Live URL triage `urllive` | HIGH | `httpprobe/run.go:208` `pipeline/results.go` | v1.5 | VERIFIED |
| OPT-P0-4 | Per-tool deadlines + amass opt-in | HIGH | `urlintel/adapt/source.go:525` | v1.5 | OPEN |
| OPT-P0-5 | Honest run duration in report | LOW | `report/model.go:142` | v1.5 | OPEN |
| OPT-P1-1 | Dir fsync durability | MEDIUM | `report/writer.go:334` `cache/cache.go:292` | — | OPEN |
| OPT-P1-2 | Shared `Context`/`Model` alias | MEDIUM | `detect/context.go:68` `report/model.go:147` | v2.0 gate | OPEN |
| OPT-P1-3 | Fuzz harnesses | MEDIUM | `ROADMAP.md:v1.6` | v1.6 | OPEN |
| OPT-P1-4 | Silent truncation merges | LOW | `tls_certificate.go:334` `finding.go:313` | v1.6 | OPEN |
| OPT-P1-5 | Weak `jsintel` TLS fallback | LOW | `jsintel/fetch.go:678` | — | OPEN |
| OPT-P1-6 | Fetch truncation flag | LOW | `jsintel/fetch.go:480` `jsintel/engine.go:966` | v1.5 | OPEN |
| OPT-P2-1 | Split timeouts UX | MEDIUM | `urlintel/adapt/source.go:355` `cli/scan.go:158` | v1.5 | OPEN |
| OPT-P2-2 | Health early stop | MEDIUM | `jsintel/engine.go:648` | v1.5 | OPEN |
| OPT-P2-3 | TUI fidelity NEW-21 | MEDIUM | `tui/controller.go:156` `TODO.md:NEW-21` | v1.4 | IN PROGRESS |
| OPT-P2-4 | Hot-path allocs | LOW | `techintel/analyze.go:580` `priority/score.go:614` `event/bus.go:97` | v1.6 | OPEN |
| OPT-P2-5 | Standalone CLIs | INFO | `AGENTS.md:2` | post-v1.6 | DEFERRED |
| OPT-P2-6 | Dedup helpers | INFO | `dns/scope.go:15` `discovery/detect.go:215` | — | OPEN |
| OPT-P3-1 | Fixtures/snapshots/bench | — | `ROADMAP.md:v1.7` | v1.7 | PLANNED |
| OPT-P3-2 | Universal ingestion | — | `ROADMAP.md:v1.8` `internal/importer` | v1.8 | PLANNED |
| OPT-P3-3 | Detection packs | — | `ROADMAP.md:v2.0` `detect/api.go` | v2.0 | PLANNED |
| OPT-P3-4 | Logger/replay consumers | — | `ARCHITECTURE.md:3141` `internal/event` | post-v1.4 | PLANNED |

---

## Change log

- `2026-08-20` — Created from full architecture audit (`v1.4.0`). All optimizations and upgrade
  recommendations consolidated with `file:line` evidence. Next update when `v1.4` closes
  (`NEW-21`) and `v1.5` refinement lands.
