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
- Batch 2 (T6 JSON importers) IMPLEMENTED (builder ses_fd5c5c887ffebdqMA6qzBKcnh0): internal/importer/json.go created (httpx/dnsx/naabu/katana/nuclei + json-generic fallback) streaming via json.Decoder on bufio.Reader 8 KiB UseNumber() + array vs NDJSON handling (array via Decoder Token loop, NDJSON via bounded readLines reuse for per-line error isolation), unknown fields ignored forward-compat, every record via asset builders only (ParseURL/NewHost/NewIP/NewFinding via NewEvidence), provenance Source=import:<tool> Reference=filename:line + sidecar OriginalRecord 4 KiB truncated, dedup via Sink.seen (Findings via Finding.Identity), bounded memory 8 KiB + decoder ~4 KiB no whole-file unmarshal, progress/cancellation per-record, honest truncation MaxOutput→Truncated+Sticky import_truncated; detection waterfall extended via jsonProbeShape (decode first value, classify keys url/host/ip/port/template-id) + isJSONLike for NDJSON, confidence 0.85/0.90 specific vs 0.40 generic vs 0.10 plain-generic, registry generic fallback last (json-generic before plain-generic). Tests: internal/importer/json_test.go added (TestJSONDetection 12 cases incl array+renamed, TestJSONImportersTable 17 cases, empty/truncated/provenance/streamingBounded/cancellation/progress/gzip/unknownFields/emptyLines/registryDeterminism). Evidence: go vet/build/test green (importer 1.19s, full 22 pkgs), go test -race importer 6.6s green, heap delta <5 MiB for 200k JSON lines, gofmt clean, go.mod unchanged. Pending: reviewer round, orchestrator VERIFIED.
- Batch 2 review-fix round (fixes ses_fd_fd59f6b62ffezUccDPpXBU08ur): MEDIUM json.go array-mode single-value unbounded — post-Decode cap check (added by builder) still let dec.Decode(&json.RawMessage) materialize the whole element (+string copy) before any bound applied; fixed by replacing array-body decoding with arrayFramer bounded byte-wise state machine (internal/importer/json.go:1228) framing elements verbatim at ≤ effectiveMaxLine() bytes retention, escape-aware string tracking + nesting depth for resync, oversized → failed+truncated + handle never called + exact byte tally toward MaxDecompressedBytes (readLines drain parity), EOF mid-element → io.ErrUnexpectedEOF honest truncation; dead code removed: unused dec/isJSONSyntaxError after framer switch, LOW dead metadata>16 trim block (json.go:647 pre-fix, unreachable — map max 4 keys) deleted with now-unused sort import. Tests: internal/importer/json_array_bounded_test.go (12 MiB element vs 32 KiB cap heap-guard <5 MiB delta skip-under-race, resync after huge incl escaped-quote/comma-in-string/nested elements, EOF mid-element truncation accounting, empty/scalar array parity). Evidence: gofmt clean, go vet ./internal/importer OK, go build ./... OK, go test ./... -count=1 = 28 pkgs ok 0 fail, go test -race ./internal/importer/... 7.8s ok, go.mod untouched. Pending: reviewer round, orchestrator VERIFIED.
- Batch 2 review-fix round 2 IN PROGRESS (fixes session ses_fd560422effeFUtGxs3lCOYFrd, 2026-08-23): MEDIUM array-mode decompressed-byte tally not exact — array path tallied only retained element bytes + oversized framer totals, so bytes BETWEEN elements (commas/whitespace/brackets) escaped MaxDecompressedBytes entirely (reviewer repro: "[" + 8 MiB "," + tiny element + "]" vs 64 KiB cap → processed=1 Truncated=false); fixed by promoting framer counter to cumulative Consumed incremented on every ReadByte across open()+next() (internal/importer/json.go:1262,1318), caller applies only the not-yet-counted delta per array-loop iteration toward bytesRead/progress with the same bytesRead>maxDecomp→truncated early-return used elsewhere (json.go:1090-1109), replacing both per-path tallies (retained-n and framer.total) with one exact accounting. LOW JSONDnsxImporter duplicate-host phantom-processed — dup-host record listing new-but-all-duplicate IPs returned nil (counted processed though nothing stored) because the old branch keyed off len(rec.A)/len(rec.AAAA) instead of actual appends; fixed by tracking addedIP (set only on real out.IPs append, json.go:178-233) and returning errDuplicate when dup-host && !addedIP (json.go:235-243), rambling decision comments replaced. Tests added json_array_bounded_test.go: TestRegressionMED_JSONArrayCommaPaddingCapped (8 MiB commas vs 64 KiB cap → Truncated=true sticky, 0 processed 0 failed 0 stored — tail-drop not failures), TestRegressionMED_JSONArraySmallPaddingStillProcessed (over-truncation guard: pretty-printed 33 elements ~4 KiB vs 8 KiB cap → Truncated=false 33 processed), TestINFO_JSONArrayBOMAndDeepNesting (UTF-8 BOM-prefixed array 2/2 processed; depth-128 nested tags frames intact 1/1), TestLOW_DnsxDuplicateHostAccounting (6-record table: dup-host+dup-ip / all-dup-ips / no-ip records are duplicates, dup-host+new-A or new-AAAA processed; hosts=1 ips=3). Regression evidence verbatim: buggy-tally build → "--- FAIL: TestRegressionMED_JSONArrayCommaPaddingCapped … want Truncated=true: 8 MiB inter-element commas exceed the 64 KiB decompressed cap"; buggy-dnsx build → "--- FAIL: TestLOW_DnsxDuplicateHostAccounting … want processed=3 (records storing new assets), got processed=5 failed=0"; both PASS after fix. Evidence: gofmt -l clean, go vet ./internal/importer/... OK, go build ./... OK, go test ./internal/importer/... -count=1 ok 1.713s, go test -race ./internal/importer/... -count=1 ok 7.806s, full go test ./... -count=1 = 28 pkgs ok 0 fail, go.mod/go.sum untouched. Pending: reviewer round, orchestrator VERIFIED.
- Batch 3 (T7 XML importers) IMPLEMENTED by continuation session (ses_fd315f4e1ffe1yPVQt5P8rL0oi, 2026-08-23) after an interrupted builder session left the package non-compiling. Found incomplete on disk: xml.go/xml_stream.go mostly written but unwired; xml_test.go with 5 compile errors (`names` out of scope at :147, two `fmt.Fprintf(&f, …)` **os.File writer bugs, undefined `gzipWriterFor`, `truncationFlagged` defined but call site used nonexistent `truncatedNotSet`); detect.go XML branch missing; registration only test-side (no production compose point exists yet — ingest CLI is a later milestone). Fixed/implemented: (1) xml_test.go compile fixes preserving intent (hoisted detection-table `names`, inlined gzipWriterFor/gzipTestWriter helper, renamed+inverted Sink helper to truncatedNotSet); (2) HIGH §0.6 bug in streamXMLElements — EOF surfacing through DecodeElement inside handle landed in default branch as failed++ with NO truncation flag (TestXMLTruncatedMidElement expectation unimplementable): added eofTrackingReader over openStream so decode-error-with-input-exhausted classifies as honest truncation (truncated++, nil error) while decode-error-with-input-remaining aborts structured; also pre-open checkCtx fail-fast for already-cancelled contexts; (3) replaced broken arrival-time xmlRecordTap tee capture (OriginalRecord came back EMPTY because bufio read-ahead filled before tap.begin) with position-indexed ring window keyed to dec.InputOffset() offsets — bounded effectiveMaxLine+MaxOriginalRecordBytes, verbatim prefix extraction, honest "" when record head evicted from window; (4) burpSeverityToPriority maps Burp's literal "Information" → "info" (nuclei table lacks it, passthrough produced priority="information"); (5) detect.go waterfall wiring: plainConfidence now declines broad looksLikeXMLPeek (BOM-tolerant, declaration-less fragments incl. <OWASPZAPReport> without decl) instead of literal-<?xml-only isXMLSignature (deleted as dead), header comment documents real root mapping <items>/<issues>→burp, <OWASPZAPReport> case-insensitive→zap, unknown roots → no claim (fall through to plain-generic 0.10 last-resort, no generic-XML importer per scope); (6) provenance.go ProvenanceSourceForImporter gained xml-burp→burpsuite, xml-zap→owaspzap (DEVIATION from may-modify list, strictly required for correct sidecar Source/OriginalTool — §5 minimal-touch rule); (7) registry.go deliberately UNCHANGED: registration is caller-side composition, Detect generic-last sort already treats both XML importers as specific (verified TestXMLRegistryDeterminism); (8) testdata fixtures made load-bearing via TestXMLFixtureFiles (pretty-printed multi-line exports end-to-end: detect+import+provenance). Test corrections with rationale: dedup fixture `/dup` vs `/dup/` changed to case-variant duplicate (asset URL canonicalization deliberately keeps trailing-slash variants distinct — "errs toward splitting", asset/url.go doc); cancellation second half simplified to deterministic context.Canceled assertion (importer now fails fast pre-IO); gzip-bomb fixture writes all bytes through gw.gz (previous mix of raw+compressed writes corrupted the flate stream). Evidence (verbatim): DETECTION TABLE full 16-importer registry — sitemap→xml-burp(0.90)+plain-generic(0.10); issues→xml-burp(0.90); zap→xml-zap(0.90); sitemap-renamed.txt→xml-burp(0.85); zap-renamed.dat→xml-zap(0.85); unknown-xml→plain-generic(0.10) only; DEDUP PROOF 2 identical-identity items→ItemsProcessed=1 len(URLs)=1; TRUNCATION PROOF EOF-mid-record→ItemsProcessed=1 ItemsFailed=0 Truncated=true StickyFlags=map[import_truncated:true] err=<nil>; MALFORMED-ELEMENT PROOF 2 processed 1 failed err=<nil> continued past bad record; EMPTY-FILE PROOF 0/0 Truncated=false; PROVENANCE PROOF Importer="xml-burp" OriginalTool="burpsuite" OriginalRecord(148B) verbatim ≤4096. Gates: gofmt -l clean (repo-wide), go vet ./... OK, go build ./... OK, go test ./internal/importer/... -count=1 ok 2.087s then 1.942s post-cleanup, go test -race ./internal/importer/... -count=1 ok 11.387s/11.315s, full go test ./... -count=1 = 28 pkgs ok 0 fail (discovery 113s slow-but-green per board note), go.mod untouched. Pending: reviewer round, orchestrator VERIFIED.
- Batch 3 review-fix round IMPLEMENTED (fixes session ses_fd2e1800affeT1qsuajX0VBWhP, 2026-08-23), reviewer REQUEST CHANGES 2 HIGH 1 MEDIUM 3 LOW 1 INFO → fixes: HIGH-1 xml.go Burp paths captured tap.raw() BEFORE dec.DecodeElement so OriginalRecord's upper bound was decoder read-ahead position (fragments ending mid-URL / bleeding into next record) — raw() now takes an explicit end and all three capture sites (burp item, burp issue :101→116, zap alertitem mirroring ZAP) capture AFTER DecodeElement succeeds with end=dec.InputOffset(), window exactly [markFrom, end-of-record); LOW-3 same edit documents the between-tokens-only decompressed-cap bound in streamXMLElements tally comment (single huge CharData token peaks at bufio+tap-window memory, cumulative tally exact). Regression TestRegressionHIGH_XMLOriginalRecordExactWindow (xml_test.go): exact-equality + </url></item>/</issue>/</alertitem>-suffix assertions across fine-grained inter-record padding sweeps ([0,2048] step 1, 8192±128 band) + >4 KiB capped-prefix honesty; RED proof verbatim: pre-fix injection → "pad-sweep record 0: OriginalRecord drift", "issue 33 does not end at </issue>: tail=…</path><"; GREEN after fix. HIGH-2 vacuous heap guards (sink unreferenced post-Import ⇒ GC freed retained assets before m2 ReadMemStats while asserting 5 MiB delta): both TestXMLStreamingBounded (xml_test.go) and pre-existing TestJSONStreamingBounded (json_test.go) now structurally pin the sink — post-m2 len(sink.URLs)/len(sink.ProvenanceRecords)==100000 assertions + runtime.KeepAlive — with honest split comments (retained-heap vs streaming-overhead vs unobservable peak) and measured bounds: retained delta measured 53.4 MiB (XML) / 59.6 MiB (JSON) @100k records ⇒ maxDelta 128 MiB; new TestXMLStreamingNoPerRecordRetention isolates streaming overhead via dedup-trick + unique last-record sentinel (EOF proof: urls==2) — measured 0 B delta over 150001 records (~7.2 MiB file), maxDelta 8 MiB. MEDIUM xml_stream.go sticky-decoder double-count (encoding/xml Decoder.err is sticky: content-malformed record → handle failed it, next Token re-reported same error → failed++ again + abort skipping remaining valid records while comment falsely claimed resync): added lastRecErr tracking (cleared on success/duplicate, set on record failure); non-EOF-shaped decode errors matching lastRecErr abort ONCE with structured error naming reason ("record #N is not XML-decodable and encoding/xml cannot resync (sticky decoder error)") without recounting; doc comment now states the honest contract (XML-level undecodable record aborts import counted once; purely semantic failures still resync). LOW-1 truncation classification now requires EOF-shaped error (io.EOF/io.ErrUnexpectedEOF/xml "unexpected EOF") AND sawEOF; input-exhausted-but-not-EOF-shaped surfaces contextually ("malformed XML after %d input bytes (input fully read)"). LOW-2 dead inRecord flag deleted (unreachable: every handle path completes or returns before Token sees EOF). INFO doc.go registration checklist added (plain ×7, json ×5 specific, xml ×2, json-generic+plain-generic fallbacks always last) for the future ingest milestone. Malformed-content probe TestRegressionMED_XMLStickyDecodeAbortsOnce (&bogus; + invalid UTF-8 table): asserts ItemsFailed==1 exactly once, ItemsProcessed==1, structured abort error substring, Truncated=false; RED proof verbatim: sticky-fold disabled → "abort error …invalid character entity &bogus;\" want substring \"not XML-decodable\"". Evidence (verbatim gates, this session): gofmt -l internal/ cmd/ = empty; go vet ./internal/importer/... OK; go build ./... OK; go test ./internal/importer/... -count=1 ok 2.348s; go test -race ./internal/importer/... -count=1 ok 15.769s; full go test ./... -count=1 = 28 pkgs ok 0 fail; go.mod/go.sum untouched. Files: internal/importer/{xml.go, xml_stream.go, xml_test.go, json_test.go (heap guard only), doc.go}. Pending: reviewer round, orchestrator VERIFIED.

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
