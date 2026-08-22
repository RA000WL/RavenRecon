# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-60).
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

### NEW-58 (LOW) — C-4 drift detectors missing for detect/report caps (internal/detect, internal/report)
- Status: VERIFIED — implemented (builder session ses_fda40ee7cffeIG9invXq9imvcA)
  and orchestrator-verified 2026-08-22: constants verified code↔doc before
  pinning (detect.maxFindingsPerRun=4096, report.maxModelPerKind=100_000);
  perturbation evidence shows each detector fails naming constant, actual,
  expected, and doc source; gates green. Archived to TODO.closed.md.
- Reporter: builder (v1.7 batch D, NEW-56)
- Owner: builder
- Problem: every other C-4-documented cap gained an in-package bounds_c4_test.go
  drift detector in batch D; detect (maxFindingsPerRun=4096) and report
  (maxModelPerKind=100000) did not because those packages were scope-restricted
  mid-task. Their constants are unexported, so detectors must be in-package.
- Fix: add bounds_c4_test.go to both packages pinning the documented values.
- Verification: tests pass; constants drift would fail them.

### NEW-59 (HIGH) — v1.8 Universal Asset Ingestion Framework (ROADMAP v1.8)
- Status: IN PROGRESS (orchestrator, 2026-08-23) — milestone tracker; per-task records appended below as batches land
- Reporter: master
- Owner: builder (per-task dispatches)
- Problem: ROADMAP v1.8 — importer adapters behind one interface, auto format detection without --type, streaming bounded memory (10MB/100MB/1GB+), provenance, dedup via identity/merge, cache integration (content hash + config + schema + importer version), pipeline enrichment, ingest CLI, reporting attribution (Discovered/Imported/Enriched/Generated). Research round completed (ses_fd6274180ffe5S6QP1RyA3jfpI + ses_fd6274179ffeaKw7DHmFFC3Gje); reality: internal/importer does not exist (greenfield, ~10-13 new files, ~8-10 touched), asset builders are single normalization point, cache keys are schema+op+target+material config+tool, pipeline is twelve stages via AllStages()=12 with T4 harness seams, go.mod stdlib-only 1.26.5.
- Locked decisions (orchestrator, from research):
  D1 detection = signature→structure→MIME→extension waterfall with peek 32 KiB + line-shape classifier for plain family (asset.ParseURL/NewHost + netip), confidence desc + Name asc, generic fallback last, peek buffered once + Seek(0,0)
  D2 streaming = incremental line/token parsing: bufio.Reader 8 KiB + ReadSlice maxLine+1 cap (never > effectiveMaxLine+1) + drained bounded chunks + gzip cap 100 MiB via MaxDecompressedBytes, json.Decoder streaming, xml.Decoder token loop, progress every 64 KiB/10k, ctx per record, truncated → partial/incomplete sticky import_truncated
  D3 interface = single generic Importer (Name/Version/CanImport/Import) + ImportEnv (Clock/Observer/Cache/ProvenanceBase/Bounds) + Sink (AddDomain/Host/URL/IP/CIDR/JS/Finding with seen-map dedup) + Registry Register/Seal/List/Detect (sort Name, post-seal lock) — no importer owns runtime/cache/reporting
  D4 cache = per-file key via cache.NewKey Operation ingest.import Target import:<sha256-hex> Config {schema, importer_version, max_output, max_line_bytes, max_decompressed_bytes} Tool Name/Version, Data = bounded identities+stats (not raw bytes, MaxRecordSize 16 MiB), repeat unchanged → hit without re-parse via streaming sha256
  D5 provenance = sidecar ImportDetail map keyed by Identity.String() (importer/tool/filename/importedAt/originalRecord 4 KiB truncated/confidence/metadata) threaded via pipeline Results → report Context→Model, asset Provenance.Source="import:<importer>" + earliest-wins merge, Origin vocabulary Discovered/Imported/Enriched/Generated derived at report assembly
- Batch 1 (T1-T5 core + plain) IMPLEMENTED + REVIEWED (builder ses_fd622d475ffeXCsSQhyXh04kXE + fixes ses_fd5ee7590ffeIEb3JYkTwtowmt + ses_fd5e2b575ffeIOna79Nq54AKwN; reviewer ses_fd6002b21ffeqLq4JuO2d3lOIv REQUEST CHANGES 2 HIGH 2 MEDIUM 1 LOW → ses_fd5cb3a81ffeuTesk0828utOIg APPROVE): internal/importer/* created (doc/importer/registry/detect/reader/provenance/cache + plain_domains/urls/generic/ips/js/adapt_helpers), registry Register/Seal determinism, detection waterfall + line-shape classifier, streaming bounded 8 KiB ReadSlice + drain bounded + gzip 100 MiB cap, cache keys include max_line_bytes+max_decompressed_bytes, plain importers 7 (domains/subdomains/urls/alive/js/ips/cidrs) via asset builders only, CIDR via netip.ParsePrefix canonical, provenance sidecar, Sink dedup, ImportStats truncated+StickyFlags. Evidence: gofmt/vet/build/test/race green (importer 0.64s/3.5s race, full 22 pkgs incl discovery 113s), heap guard 10 MB synthetic <5 MiB delta, regression tests for HIGH1/2 + MEDIUM1/2 + LOW redaction. Fixes: ReadString→ReadSlice bounded, max_line_bytes+max_decompressed_bytes in key, gzip cap, scannerFor removed, importPathError redaction.

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
