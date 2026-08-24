# RavenRecon — Closed-issue archive

Historical record of completed, fixed, closed, and decided board entries.
Split from TODO.md on 2026-08-21 (orchestrator) — active work lives in
TODO.md; nothing here is actionable. Entries are never re-opened by
editing this file: file a new NEW-n entry referencing the old one.

## Recently closed

### NEW-94 (MEDIUM) — discover transient shutdown-deadline discards fully-enumerated host corpus (internal/pipeline)
- Status: VERIFIED — fixed (builder ses_fcd6307caffe3vpMlWQVbdYFOH) and LIVE-VALIDATED on pentest-ground.com run 3 (2026-08-24): discover incomplete processed=21 failed=0 (hosts RETAINED; both prior runs lost them), dns completed processed=21, httpprobe partial processed=21, crawl completed processed=21, 21 hosts in final report. Root cause: runAndParse/chaos.Discover discarded captured stdout on error though runner guarantees quiescent capture incl. cancellation kill; two-layer fix (derived drain budget + post-mortem parse retention) with discovery_partial_retained sticky flag (StageRecord-level; report-level surfacing noted). Note: run-3 overall outcome cancelled was the orchestrator's own 45-min shell ceiling firing mid-urllive — graceful external-cancellation drain + full report render, itself an honesty validation.
- Reporter: orchestrator (vulnbank.org + pentest-ground.com field tests, 2026-08-24)
- Owner: builder (cleanup wave d)
- Problem: in-scan discover hit "pool shutdown: context deadline exceeded" on BOTH live scans (standalone discover completed fine minutes prior each time — subfinder enumerated 21 hosts for pentest-ground before the deadline). The failed stage's additions are dropped → dns/httpprobe processed 0 despite a full host list existing; cascade starves half the pipeline off one transient budget miss.
- Root cause (pinpointed): the engine's two tool-execution paths discarded the captured stdout whenever Runner.Run returned an error — internal/discovery/source.go runAndParse and internal/discovery/chaos.go Discover both did `return DiscoverResult{}, err` — even though the runner guarantees a final quiescent capture on every path including a cancellation kill (runner.go). The drain expiry force-cancelled subfinder mid-stream; the capture was thrown away; classify saw only the context error → cancelled with 0 hosts. The forced path fired in-scan but not standalone because the pipeline adapter passes Bounds.Timeout=0 (pipeline default) → no per-job deadline → the old flat 30 s shutdownForceBudget was the only bound; standalone used DefaultConfig's 30 s per-job deadline which subfinder met.
- Fix implemented (two layers): L1 — Shutdown's drain budget is now derived from the actual job structure (shutdownDrainBudget): waves×Timeout + rate-limited start stagger + 15 s grace when deadlines are enabled; a documented bounded 3-min completion window when disabled (was flat 30 s). Still strictly bounded. L2 — both execution paths parse the captured stdout post-mortem and return the retained hosts alongside the error; classify keeps the honest cancelled/partial outcome; quality gate applies to retained sets (tested); adapter records the new discovery_partial_retained sticky flag on every path when a non-completed source retains hosts.
- Verification: red→green regression tests (TestRunRetainsPartialHostsOnCancellation, TestRunQualityGateAppliesToRetainedHosts — red verbatim: "retained subfinder hosts = []"), TestShutdownDrainBudget table, adapter test TestDiscoveryStagePartialRetainedOnCancellation; gates green: gofmt/vet/build, go test ./... 28/28, go test -race ./internal/discovery/, v1.7 acceptance suite.
- Remaining (for verifier): live revalidation of an in-scan discover under contention; consider surfacing discovery_partial_retained in report summaries/exposers if operators want it beyond stage flags.


### NEW-93 (HIGH) — crawl adapter argv rejected by installed katana + record parser misses modern JSONL shape (internal/crawl)
- Status: VERIFIED — fixed (builder ses_fcd7cdcf5ffeqN8PRakBfWX3kz) and LIVE-VALIDATED on pentest-ground.com rescan 2026-08-24: crawl stage completed processed=2 failed=0 with honest crawl_truncated flag (was: failed, all 4 hosts exit 2, zero output). Red→green argv-pin + nested-shape parse regressions; cli smoke fixture argv updated (flagged §5 crossing, justified).
- Reporter: orchestrator (pentest-ground.com field test, 2026-08-24)
- Owner: builder
- Problem: two compounding defects make crawl systematically non-functional: (1) argv passes `-ps` (undefined in installed katana — every invocation exits 2 at flag parsing with zero output; second invalid flag `-retries` renamed `-retry`) — manual repro: `flag provided but not defined: -ps`, exit 2; corrected argv exits 0 with 1077 endpoints. (2) `katanaRecord` (katana.go:102-106) parses only top-level `endpoint`, but modern katana -jsonl nests it under `request.endpoint` — even with valid argv every line would parse malformed → zero URLs → all hosts failed per NEW-86 semantics. Explains crawl failure on vulnbank.org AND pentest-ground.com (5/5 hosts exit 2).
- Fix: drop `-ps`; `-retries`→`-retry`; add nested `request.endpoint` fallback to katanaRecord parsing (mirror importer's json-katana fix); update argv-pinning tests; add modern-shape parse regression.
- Verification: exact adapter argv exits 0 manually; unit test parses nested line; live scan crawl stage completes with URLs>0.


### NEW-92 (LOW) — cli/ingest.go doc comment still describes the pre-NEW-73-residual paths separator contract (internal/cli)
- Status: VERIFIED — orchestrator-fixed inline 2026-08-23 (one comment line): internal/cli/ingest.go buildIngestConfig doc now states newline is the ONLY separator and commas are reserved/rejected, matching the wave-c contract.
- Reporter: wave-c agent 1
- Owner: (unassigned)
- Problem: internal/cli/ingest.go:276 says the ingest stage's params carry paths newline-joined as "the adapter's preferred separator — paths may contain commas". After the NEW-73 residual fix, internal/pipeline/adapt/import.go ingestPathsParam treats ',' (and '\n') as RESERVED inside individual paths and rejects any entry containing them with a structured error; newline is now the ONLY separator and comma-containing filenames are rejected outright. The stale comment tells operators commas are acceptable when they no longer are.
- Fix: reword internal/cli/ingest.go:276 to state that paths are newline-joined and that ',' / '\n' are reserved inside individual paths (rejected by the adapter); optionally surface a CLI-side hint if an operator passes a comma-containing filename.
- Verification: grep + read of both comments after edit.

### NEW-74 (INFO) — Audit INFO/doc-skew wave B (see REVIEW-2026-08-23.md §3 INFO)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-23) — all claimed and residual items done across waves a/b; nothing further open under this entry.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: docs
- Problem: CLI usage lists ten stages vs twelve actual + "no active enumeration ever run" overclaim vs crawl/dnsx_brute; version.go stale migration comment; dns-vs-httpprobe all-timeout classification asymmetry; transport idle-conn hygiene; provenance ordinal drift; progress-event overcount; jsintel inline-script uncounted parse failures; adapt truncation metadata must be consumed at wiring time; priority FNV digest bound; TUI bidi passthrough; detect Context trust boundary; fixture_manifest in prod package.
- Fix: doc corrections + noted follow-ups; details in report §3 INFO.
- Verification: n/a (docs) / per-item notes.


### NEW-73 (LOW) — Audit LOW/INFO wave A: correctness/hygiene (see REVIEW-2026-08-23.md §3 LOW 1–14)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-23) — every subitem done across waves a/b/c. Wave c closed the last two residuals: ingest paths with reserved separators (, 
) rejected with structured errors naming the path (also uncovered: legacy comma fallback was a literal-substring split bug that mangled comma-joined lists); insertion sorts outside dns.go converted with byte-exact equivalence pins (techintel sourcesMask exhaustive over all 64 subsets; tui worker snapshot stable-by-idx across 25 map permutations — removing a quadratic per-render-frame hazard). xml_stream site was misflagged (validity scan, not a sort) — skipped with evidence.
- Ingest path-param lossiness residual — implemented 2026-08-23 by wave-c agent 1 (import.go adapter only), awaiting orchestrator verification: internal/pipeline/adapt/import.go ingestPathsParam now treats ',' and '\n' as RESERVED inside individual paths and rejects any entry containing either with a structured error naming the offending path ("invalid ingest path %q: contains a reserved separator character …"); params-key doc block updated. Discovery recorded at the site: the legacy comma fallback NEVER actually split — strings.Split was given the two-character separator "\n," (literal-substring match), so comma-joined lists surfaced as one mangled entry with a confusing stat error, while lone comma-paths accidentally survived intact; the fallback is replaced by the explicit rejection (newline is the only separator). Tests: TestIngestStagePathValidation/reserved_separator_rejected_(comma_filename) (red: old code silently imported an existing comma-named file passed alongside another path), reserved_separator_rejected_(comma-joined_list), multi-path_newline_form_unchanged.
- Reporter: reviewer (full audit 2026-08-23)
- Owner: (unassigned)
- Problem: fourteen LOW items with file:line detail in the report — highlights: urlintel live-record TLS-diagnostic stored StatusFailed; NetResolver lazy-init race; outer-deadline discards captured tool stdout prefix; OverflowDropped under-count; configurable-cap decode churn loop; candidateAsset zero-asset swallow; report deadline→failed skew; Fingerprint[:8] panic guard; three divergent URL-filter copies (root cause of H-3); crawl cancellation drops engine error; O(n²) insertion sorts; ingest path param newline/comma lossiness; chaos apex-subdomain mangling; PDCP_API_KEY init()-scope leak in tests.
- Fix: per-item fixes in the report.
- Verification: per-item tests named in the report.


### NEW-3 (INFO) — Set-Cookie retained verbatim in boundedHeaders (internal/httpprobe)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). Set-Cookie values redacted at boundedHeaders choke point (names+attributes preserved for techintel fingerprints); decode-time compliance refusal self-heals pre-fix cached records; integration proof: report marshal contains no cookie secret; name-keyed fingerprint parity test green.
- Reporter: reviewer
- Owner: (none)
- Problem: boundedHeaders retains Set-Cookie verbatim; session cookies could
  be stored in probe records. Pre-existing behavior, outside the audit
  scope — documented here only, per AGENTS.md §5.
- Fix (if ever scoped): redact Set-Cookie values like Location userinfo;
  requires a scoped milestone decision first.
- Verification: n/a while deferred.

### NEW-14 (INFO) — priority stage parameter-name derivation diverges from urlintel's extraction (internal/pipeline/adapt)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). queryParamNames skips value-less keys (?flag and ?flag=), caps at 64 with priority_params_truncated sticky + Truncated — pathological URLs score completed, never fail; alignment with urlintel verified at extract.go.
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

### NEW-60 (INFO) — gzipped plain-text link lists claimed by nobody at detection time (internal/importer)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). plainConfidence inflates gzipped peeks once bounded (≤32 KiB via inflatePeek); corrupt gzip declines; JSON/XML guards re-checked post-inflation; confidence parity with uncompressed equivalents; anti-steal cases green.
- Reporter: reviewer T8 round (entry recorded by fix session ses_fd28d1daaffeOWE1tUkrhAgem8, 2026-08-23)
- Owner: (unassigned)
- Problem: plainConfidence declines any gzipped peek before the line-shape
  classifier (detect.go:363), and no other family claims a gzip of bare URLs
  (archive probes require WARC magic or CDX row shape) — so e.g. a
  waymore.txt.gz bare-link export streams fine once an importer is chosen
  (openStream/readLines are gzip-transparent) but Detect returns no claim at
  all for it. doc.go's waymore bullet previously overstated this as
  gzip-capable coverage; it is now qualified to uncompressed outputs.
- Fix option: mirror the archive branch's bounded inflatePeek (≤PeekSize,
  archive.go inflatePeek) inside plainConfidence (or as a pre-step in
  Detect): if isGzipped(peek), inflate once in memory and run the same
  XML/JSON-decline guards + lineShapeHistogram over the inflated bytes;
  corrupt gzip must keep declining honestly.
- Verification: registry table case with a gzipped one-URL-per-line list →
  top match plain-urls; existing gzipped CDX/WARC content-detection and
  anti-steal cases stay green.

### NEW-85 (MEDIUM) — crawl stage diagnostic-presence heuristic misclassifies linkless successes as failures (internal/pipeline/adapt)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). heuristic deleted; engine sets FailedHosts=len(hosts) on genuine abort paths; linkless-success-with-benign-diagnostic fixture now completed/0-failed (red at HEAD).
- Reporter: reviewer (v1.8-wave verification cluster A, 2026-08-23)
- Owner: (unassigned)
- Problem: adapt/crawl.go:150-158 — when FailedHosts==0 && len(URLs)==0 && !Truncated && len(Diagnostics)>0, the stage infers failed=len(hosts). A katana run that genuinely succeeded over a linkless site but emitted any benign diagnostic (e.g. "N malformed lines skipped") is reported incomplete with ItemsFailed=len(hosts) — counters lie even though the outcome errs conservative.
- Fix: explicit engine signal instead of inference — engine sets FailedHosts=len(hosts) itself on its genuine failure early-returns (e.g. katana.go missing-binary path), adapter drops the diagnostics heuristic.
- Verification: linkless-success-with-benign-diagnostic fixture → completed, ItemsFailed=0; genuine-failure fixtures still fail.

### NEW-86 (LOW) — crawl exit-0 all-malformed output still stores completed-empty corpus (internal/crawl)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). zero-usable-endpoints-with-malformed-lines counts as host failure; completed-empty store now requires zero errors/malformed across all hosts; all-malformed fixture stores incomplete + re-executes (red at HEAD).
- Reporter: reviewer (v1.8-wave verification cluster A, 2026-08-23)
- Owner: (unassigned)
- Problem: crawl/katana.go:280-320 — hosts exiting 0 but emitting only malformed JSONL increment neither FailedHosts nor Truncated; an all-such-hosts run stores StatusCompleted with an empty corpus that is served permanently (no TTL) — same poison-the-key class as NEW-62.
- Fix: count unparseable-output-with-zero-parsed as host failure (or store incomplete when parsed==0 && malformed>0).
- Verification: fake runner emitting garbage JSONL → no completed record stored; second Crawl re-executes.

### NEW-87 (LOW) — urlintel storeURL drops urlKey build error (internal/urlintel)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). storeURL split into storeKeyFailed/storeURLByKey; key-build failure classified like lookupURL, never reaches Marshal/Put; direct-branch unit tests.
- Reporter: reviewer (v1.8-wave verification cluster D, 2026-08-23)
- Owner: (unassigned)
- Problem: record.go:403-405 — `key, err := urlKey(...)` err is silently overwritten by json.Marshal's err; a key-build failure would proceed toward Put("") surfacing a misleading "cache put" diagnostic instead of lookupURL's failed classification (asymmetry with lookupURL:326-333). Practically unreachable today (const operation, validated identity).
- Fix: handle urlKey's error before Marshal, mirroring lookupURL.
- Verification: fault-injection key-builder test asserting failed classification not cache-put diagnostic.

### NEW-88 (LOW) — jsintel/adapt toolRunBudget is package-level mutable state (§7.2) (internal/jsintel/adapt)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). toolRunBudget package var deleted; budget threaded via unexported env (zero→DefaultToolTimeout); grep proves no global remains; all timeout tests unchanged semantics.
- Reporter: reviewer (v1.8-wave verification cluster B, 2026-08-23)
- Owner: (unassigned)
- Problem: adapt/run.go:38-41 — mutable package-level var used as test-only time seam for the NEW-68 timeout budget; production never writes it and tests are not parallel today, but it is global mutable state and a data-race trap if these paths ever run t.Parallel().
- Fix: thread the budget through the unexported env (settable only from tests).
- Verification: tests pass with seam removed from package scope.

### NEW-89 (INFO wave) — doc/comment nits from v1.8-wave verification (multi-package)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). cli overclaim rewritten honestly (incl. a third instance found inside scanUsage itself); --tui counter phrasing qualified; event Path comment corrected to escaped-path reality; discovery cache comments fixed; README scan-vs-ingest argument order documented; truncateUTF8 + dead blocker.cancel + garbled comment fixed by orchestrator; percentDecode codec consolidation deferred as future-milestone note.
- Reporter: reviewer (verification clusters A-D, 2026-08-23)
- Owner: docs
- Problem: cli.go:52/:80 "No active enumeration, brute force, or intel modes are ever run" overclaims given crawl stage + opt-in dnsx_brute (also missing from NEW-74's lists); scanUsage promises "progress counters (completed/remaining/in-flight/eta)" though production emits only stage events (render zero/unknown); event.go AssetDiscovered.Path bound rationale breaks under percent-escaping (escaped path can triple bytes vs decoded cap derivation); discovery/cache.go:27 stale "both callers do" comment (one production caller); techintel truncateUTF8 comment misstates loop purpose (runs exactly when a multi-byte rune is cut); adapt/import_test.go dead `blocker.cancel` assignment; adapt/crawl_test.go garbled first comment line; tui/feed.go percentDecode duplicates asset/service.go encoder inverse (drift risk cosmetic-only — decode failure degrades to whole-identity digest).
- Fix: comment/text corrections; consider one exported codec for candidate-label encoding in a future milestone.
- Verification: n/a (docs) / trivial.

### NEW-90 (MEDIUM) — stage-level structured failures absent from report error summary (internal/pipeline)
- Status: VERIFIED — cleanup wave b, orchestrator-verified 2026-08-23 (merge-level reviewer APPROVE). StageErrors folded: runner collects non-nil StageResult.Err into RunReport.StageErrors (omitempty keeps passing runs byte-stable) → NewStageErrorRecord → error summary; failing-fake-stage test asserts summary ≥1 naming the stage; v1.7 goldens byte-green.
- Reporter: orchestrator (vulnbank.org field test, 2026-08-23)
- Owner: builder
- Problem: crawl stage reported failed=1 / outcome incomplete but RunReport errors summary showed total=0 — StageResult.Err never reaches the operator-facing error summary; a failed stage is visible only in the stages table.
- Fix: fold non-nil StageResult.Err into the run error summary (deduped by stage, bounded by existing caps), or document the stages-table-as-single-source explicitly; prefer folding with tests.
- Verification: hermetic run with a failing fake stage → errors summary counts ≥1 naming the stage; v1.7 goldens unchanged for passing runs.


### NEW-61 (HIGH, §0.7) — Ingest stage deadlocks forever on cancellation (internal/pipeline/adapt)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A: Shutdown-join + pre-initialised cancelled slots; TestIngestStageCancelWithQueuedFilesReturnsPromptly (watchdog) fails at HEAD by deadlock
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md H-2)
- Owner: (unassigned)
- Problem: ingestStage.Run joins via sync.WaitGroup whose Done lives only inside job closures (import.go:283); cancelled runs drop queued jobs without executing Func (runtime/pool.go:403–424), so wg.Wait() at import.go:297 blocks forever before the deferred pool.Shutdown. Reproduced empirically; Ctrl-C during `ravenrecon ingest` hangs.
- Fix: join via pool.Shutdown(budgetedCtx) then fold, treating still-zero outcomes[i] as cancelled.
- Verification: regression test cancelling mid-run with more files than concurrency; pipeline.Run must return promptly with honest cancelled outcomes.

### NEW-62 (HIGH, §0.6) — Crawl caches all-failed run as completed-empty corpus (internal/crawl)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A: FailedHosts tracking, store downgraded StatusIncomplete; TestKatanaAllFailStoresIncompleteAndReexecutes fails at HEAD
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md H-1)
- Owner: (unassigned)
- Problem: KatanaSource.Crawl folds every host failure into Diagnostics (katana.go:233–241,262–264) and stores unconditionally as cache.StatusCompleted (katana.go:280–301) — a broken run poisons the key permanently (cache serves only completed; no TTL).
- Fix: track per-host failures; skip store or store StatusIncomplete/StatusFailed when ≥1 host failed; hermetic fake-runner regression tests.
- Verification: all-fail run writes no completed record; second Crawl re-executes.

### NEW-63 (HIGH) — filterIngestURLs silently drops imported URLs with explicit non-default ports (internal/pipeline/adapt)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A: shared urlHost port-strip at single fold choke point (+L-9 filter consolidation); unit table + whole-stage e2e retain :8443
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md H-3)
- Owner: (unassigned)
- Problem: import.go:819–831 feeds u.HostPort (retains :8080/:8443) to asset.NewHost whose validateHostname rejects ':' → silent skip, outcome stays completed; non-standard-port attack surface vanishes from every importer family, stably across cache replays.
- Fix: strip port via the correct sibling helper (httpprobe.go urlHost) before the InDomain check; consolidate L-9's three filter copies.
- Verification: table test over httpx/Burp/CDX/plain imports containing :8443 URLs asserting retention.

### NEW-64 (MEDIUM, §0.6) — secrentel Overflow flag false-negative after Phase-2 dedup shrink (internal/secrentel)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: overflowCandidates set at both cap sites; TestOverflowFlagSurvivesDedupShrink fails at HEAD both assertions
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-1)
- Owner: (unassigned)
- Problem: engine.go:376 derives Overflow post-hoc from list length; cap trips increment only counts (scan.go:159–163,232–235) and Phase-2 dedup (scan.go:263–283) can shrink below cap → truncated set stored/replayed/reported as complete without the mandatory flag. Reproduced empirically (63<64 kept, 1 dropped, flag FALSE). Dead field overflowCandidates (scan.go:51).
- Fix: set out.overflowCandidates where either cap trips; entry.Overflow = overflowCandidates || counts.OverflowDropped > 0.
- Verification: in-package test with cross-family duplicates at cap pinning flag=true.

### NEW-65 (MEDIUM, §11) — urlintel cache keys omit detected tool version (internal/urlintel)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster D: ToolInfo in urlKey, unknown version never cached; TestIngestCacheToolVersionSeparation + TestIngestUnknownToolVersionNeverCached fail at HEAD
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-2)
- Owner: (unassigned)
- Problem: urlKey (record.go:44–53) hashes adapter name only; Run detects versions then discards them (adapt/source.go:405–465). Tool upgrade serves stale pre-upgrade payloads until TTL; contradicts discovery's versioned-key convention (discovery/cache.go:30–37).
- Fix: include cache.ToolInfo{Name, Version}; unknown version ⇒ never cached (mirror discovery).
- Verification: version-change re-execution test mirroring discovery's TestRunCacheVersionChangeReexecutes.

### NEW-66 (MEDIUM, §11) — Crawl cache key omits Timeout/Concurrency/RateLimit (internal/crawl)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A: key carries timeout/concurrency/rate_limit from effectiveConfig; per-field mutation test fails at HEAD
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-3)
- Owner: (unassigned)
- Problem: crawlCacheKey (katana.go:336–354) carries only depth+scope while output materially depends on cfg.Timeout (-timeout wrap :224–228), -rl/-c (:215–216); short-budget runs poison long-budget configs.
- Fix: add the three normalized values to the Config map.
- Verification: two configs differing only in timeout produce different keys.

### NEW-67 (MEDIUM, §11) — Discovery cache keys omit QualityConfig though the gate shapes stored records (internal/discovery)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C: normalized gate config in key + policy doc; TestCacheKeyIncludesNormalizedQualityConfig
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-4)
- Owner: (unassigned)
- Problem: records persist the producing run's post-gate retained set (pipeline.go:404–459) but cacheKey (cache.go:30–37) excludes gate config; raising MaxPerSource after an over_cap store keeps serving the smaller capped set until TTL.
- Fix: include normalized QualityConfig in the key Config map, or document replay-over-recompute as deliberate policy with the explicitness of the unknown-version policy.
- Verification: key-difference test across gate configs; or doc update pinned by comment.

### NEW-68 (MEDIUM, §8 parity) — jsintel/adapt Run lacks adapter-level execution timeout (internal/jsintel/adapt)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: toolRunBudget WithTimeout before runner handoff; real wedged subprocess killed at budget — pre-fix probe showed NO deadline reached runner
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-5)
- Owner: (unassigned)
- Problem: subjs/linkfinder/SecretFinder are active fetchers; only detection is bounded (tool.go:348). No default per-tool deadline exists; tests use context.Background(); pool permits Timeout=0. Sibling urlintel/adapt enforces DefaultToolTimeout=2m (source.go:143,559). Latent until orchestration wires it.
- Fix: mirror urlintel/adapt — per-tool default timeout wrapped in Run before the runner handoff.
- Verification: test that a hanging fake executable is killed at the default budget.

### NEW-69 (MEDIUM, §0.6 asymmetry) — priority AttackPaths silently caps path count with no truncation signal (internal/priority)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: ([]AttackPath, bool) mirroring Correlate; consumed as priorityPathsTruncated sticky; TestAttackPathsBounds asserts both sides
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-6)
- Owner: (unassigned)
- Problem: attackpath.go:153–156 cuts to maxPathsPerRun silently; correlate.go:189–193 returns (groups, truncated) for the identical cut class. Callers cannot distinguish "exactly 32" from ">32 cut".
- Fix: mirror Correlate's shape (([]AttackPath, bool) or result struct), update doc, extend TestAttackPathsBounds.
- Verification: bounds test asserts the signal.

### NEW-70 (MEDIUM, latent §15) — TUI renders full secret_candidate identities (value embedded) once producers exist (internal/tui)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: redactedSecretCandidateLabel (digest projection = secrentel redactedCandidateID); rendered-frame leak sweep fails at HEAD (verbatim secret rendered)
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-7)
- Owner: (unassigned)
- Problem: feed.go:178–180 uses raw p.Identity as display label; Identity embeds percent-encoded candidate VALUE (asset/secret_candidate.go:232–237); rendered verbatim (render.go:207–216). Dormant (no producer emits these events yet — verified) but the secrentel→bus wiring milestone activates a live terminal/scrollback secret leak; violates the redactedCandidateID discipline (secrentel/record.go:143–153).
- Fix: type+digest display label before any producer lands; keep full identity only in-memory dedupe key; regression-test rendered labels contain no value substring.
- Verification: synthetic high-confidence event renders redacted label.

### NEW-71 (MEDIUM) — Opt-in DNS brute failure paths report bare completed with no marker (internal/pipeline/adapt)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A + completion check: markers on all three abort paths; wildcard-probe fault-injection test present and passing (TestDNSBruteFailedFlagOnWildcardProbeEngineError)
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-8)
- Owner: (unassigned)
- Problem: runBrute abort/failure paths (dns.go:629–636) and swallowed wildcard-probe error (:580–582) produce empty results the propagation heuristic passes through — enabled brute silently absent, no sticky flag/counter; contradicts NEW-47 precedent.
- Fix: return markers from runBrute on every abort/failure path; OR into baseRes.StickyFlags.
- Verification: fault-injection tests per path assert flags.

### NEW-72 (MEDIUM) — urllive fold omits partial bucket; mixed success/failure reports completed (internal/pipeline/adapt)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster A: explicit partial bucket in fold switch; 8-row table test incl. mixed→partial fails at HEAD
- Reporter: reviewer (full audit 2026-08-23, REVIEW-2026-08-23.md M-9)
- Owner: (unassigned)
- Problem: foldUrlliveOutcomes (urllive.go:212–240) has no partial row; deviates from the unified mapping table in adapt/doc.go; unpinned by tests.
- Fix: track allCompleted; return partial on failed/incomplete mix; table test.
- Verification: mixed-outcome table test pins partial.

### NEW-75 (HIGH) — parseHTML index desync between ToLower copy and raw body → remote slice panic (internal/jsintel)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: single-string raw-body case-insensitive scan, all pos updates ≤ len(body); TestParseHTMLCaseFoldNoSecondIndexSpace PANICS at HEAD (slice bounds [41:40]) — the reported DoS shape
- Reporter: reviewer (full-repo review 2026-08-23)
- Owner: (unassigned)
- Problem: discover.go:174 builds `lower := strings.ToLower(body)` but tag offsets computed in `lower` space index raw `body` (:196,:223-227). ToLower can shrink byte length (U+0130→'i', 2→1 bytes); an unterminated inline `<script>` sets `pos = len(body)` (:230) which can exceed len(lower), so the next `findNextTag(lower, pos)` evaluates `lower[pos:]` (:289) → slice-bounds panic in the engine's unrecovered reader loop (remote DoS from one hostile page). Absent the panic, offsets corrupt → wrong/missed candidates.
- Fix: scan and slice ONE string (everything from `lower`, or case-insensitive matching on `body`); at minimum clamp pos at :230, but unify mixed-space slicing regardless.
- Verification: regression test with U+0130 + unterminated `<script>`; engine survives, offsets correct.

### NEW-76 (MEDIUM) — Crawl cache key omits Timeout/Concurrency/RateLimit (internal/crawl)
- Status: VERIFIED — orchestrator-verified 2026-08-23. duplicate of NEW-66 — same fix, same verdict
- Reporter: reviewer (full-repo review 2026-08-23)
- Owner: (unassigned)
- Problem: crawlCacheKey (katana.go:336-354) keys only depth+scope+tool version; retained URL set also depends on per-tool timeout budget and rate/concurrency (crawl_timeout/crawl_rate_limit/crawl_concurrency StageParams) → warm run under different bounds served results it never computed (§11 shape).
- Fix: add effective timeout/rate-limit/concurrency to the key Config.
- Verification: two runs differing only in rate limit produce distinct keys.

### NEW-77 (MEDIUM) — TLS-capture diagnostic flips successful live probe's cache record to failed, forcing permanent re-probes (internal/httpprobe/urls.go live path)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C/D: liveStatusToCache Status!=0→completed before error checks; TestLiveProbeDeepChainTLSDiagnosticKeepsCompletedAndCached (run2 IsHit, transport not called)
- Owner: (unassigned)
- Problem: doLiveProbe joins captureTLS diagnostics (tls.go:216-222 chain-depth cap) into rec.Err even when the HTTP response was fully observed (urls.go:322-334); liveStatusToCache (urls.go:565-597) has no typed branch for plain diagnostics → StatusFailed stored, never a hit, every https host with >8-cert chains re-probed every run; FailureReason=ReasonOther on a completed observation. Host-probe path stores the same class as completed.
- Fix: classify from transport outcome — StatusCompleted whenever rec.Status != 0, error-type checks only when rec.Status == 0; or move captureTLS diagnostics to a field that never feeds liveStatusToCache/FailureReason.
- Verification: fake deep-chain TLS peer → record cached completed, served as hit second run.

### NEW-78 (MEDIUM) — FP context markers match inside unrelated words, capping real secrets at Low and dropping them from queue (internal/secrentel)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster B: ASCII-letter tokenizer + EqualFold whole-segment compare; /latest/app.js & /respectable/ NOT flagged at HEAD (flagged), fixtures still flagged
- Owner: (unassigned)
- Problem: fpContextMarkers (falsepositive.go:47-52) are bare case-insensitive substrings over filename+"/"+urlPath (:116-131): "latest" contains "test", "respect"/"inspection" contain "spec", "demonstration" contains "demo". Flagged candidates are capped at Low AND permanently excluded from the offline verification queue (report.go:504-510 skips len(FPFlags)>0).
- Fix: tokenize subject on non-alphanumeric bytes (/ _ - . digits); compare whole segments exactly.
- Verification: /latest/app.js not flagged; test-fixture.js still flagged.

### NEW-79 (MEDIUM) — HTML-extracted corpus values have count caps but no per-value byte caps (~300x transient memory amplification) (internal/techintel)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C: capHTMLValue/truncateUTF8 across all HTML extraction sites + truncated propagation; TestScanHTMLValueByteCaps
- Owner: (unassigned)
- Problem: scanHTML (analyze.go:430-530) caps counts only (128 scripts/css, 256 attrs, 32 sourceMaps); parseTag copies attr values verbatim → hostile 1 MiB page of `<div a="<junk>">` retains ~256 x ~1 MiB entries, duplicated by full ToLower copies (:277-285); sourceMappingURL tokens run to end-of-body x32 ≈ 300 MiB transient per observation x concurrency. Persistence bounded (NewEvidence truncates 256 B); exposure is analysis-time memory. Headers already use per-value caps (64 KiB).
- Fix: truncate each extracted value to a fixed cap (e.g. 4 KiB) in scanHTML/parseTag; set htmlExtract.truncated when the cap bites.
- Verification: hostile-page test shows bounded peak retention; truncation flag set.

### NEW-80 (MEDIUM) — validatePayload leaves most event payload string fields unbounded despite hostile-event contract (internal/event)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C + completion: FindingCreated.Identity and RecommendationCreated.Identity bounds added with test rows (:241,:248); all listed fields bounded
- Owner: (unassigned)
- Problem: event.go:10-13/92-94 promise Validate re-checks every field; only message-type fields are length-checked (event_test.go:201-216 pins only those). AssetDiscovered.Identity/Kind/Method/Path, CacheAccess.Key/State, RelationshipCreated.From/To/Kind, EvidenceCreated.*, FindingCreated.*, RecommendationCreated.Text/Level, RequestObserved.*, RuleExecuted.RuleID, Progress.Phase, PhaseTransition.Phase, Shutdown.Reason are unbounded — multi-MB Identity passes Validate and fans out to subscribers/TUI.
- Fix: apply existing per-field length caps to every payload string field in Validate.
- Verification: oversized payload fields fail Validate.

### NEW-81 (MEDIUM) — ParseURL no size bound; path/query enter identity unbounded (internal/asset)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C: raw-input size cap before url.Parse; TestParseURLRawInputBound
- Owner: (unassigned)
- Problem: sibling types bound identity sizes via embedded names (parameter.go:32-34, technology.go:103-105, evidence.go:91-93, finding.go:11-13); url.go does not — Path (:208)/Query (:212) flow from arbitrarily large raw input into Identity().Value and derived cache keys.
- Fix: reject raw inputs over a fixed cap (e.g. 4-8 KiB) in ParseURL before url.Parse.
- Verification: oversize input returns error, not a giant identity.

### NEW-82 (MEDIUM) — --tui advertises worker/throughput/interesting sections and target header production can never render (internal/cli)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster D: RunMetadata published before controller start in scan+ingest (25-event wiring tests assert Target/OutputDir first event); usage text honest
- Owner: (unassigned)
- Problem: scanUsage promises stage lifecycle, progress, worker dashboard, throughput, interesting assets, errors (ingest.go:81-82 inherits claim). Production publishes only the runner's 24 stage events: StageInput has no Observer seam (pipeline/stage.go), no runtime.NewPool site sets Observer, nothing emits KindRunMetadata → header renders "ravenrecon — untitled run" (render.go:110-114), dynamic sections never appear.
- Fix: publish event.RunMetadata (Target/OutputDir) from runScan/runIngest before starting the controller; amend usage text for sections requiring a not-yet-existing stage observer seam.
- Verification: manual scan --tui shows target header; usage matches reality.

### NEW-83 (LOW wave) — Full-repo review LOW items A (2026-08-23, reviewer session ox-alpha)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster C+D + orchestrator completion: all implemented subitems verified FIXED with named regressions; the two claimed-but-missing subitems closed this session — crawl adapter now errors.Join(ctx.Err(), engineErr)+retains partial URLs (TestCrawlStageCancelledKeepsJoinedErrorAndPartialURLs) and importer cancelled-handle no longer counts phantom failed (TestReadLinesCancelledHandleRecordNotCountedFailed, fix completed by orchestrator after builder session lost to ECONNRESET mid-dispatch); deliberately-deferred items remain listed in the archived entry
- Owner: (unassigned)
- Problem: verified LOWs with evidence — discovery/pipeline.go:450-457 Put proceeds after marshal failure persisting completed record with empty Data (dns storeType handles correctly); discovery detect.go:161-165 + chaos.go:48-53 + source.go:67-70 conflate permission-denied LookPath errors as StatusMissing instead of broken/WARN; cli scan.go:244-248 `scan --stages ingest` accepted then fails inside pipeline.Run contradicting scan's own help; cli ingest.go:156-170 bare `help` after an option becomes target instead of usage; cli cli.go:139-143 doctor/version silently swallow extra args while other commands reject them; crawl adapter drops katana Diagnostics so missing-binary reports completed with ItemsProcessed=len(hosts) (katana.go:180-183, adapt/crawl.go:146-160); importer reader.go:323-330 cancelled plain imports overcount ItemsFailed by one phantom record; httpprobe urls.go:309-320 RedirectLocation fallback bypasses sanitizeLocation when header-cap truncation drops Location (>128 headers); httpprobe urls.go:341-349 body closed undrained defeating keep-alive contrary to adjacent comment (mirror drainFollowedBody); asset endpoint.go:36-43 validateMethod no length bound into Identity; asset relationship.go:103-113 Kind unbounded into ID(); config config.go:103-104 TUIConfig accepts +Inf InterestingRate disabling rate cap; cache cache.go:285/410-412 crash-leftover entry-*.tmp files never reclaimed by any sweep except Clear; secrentel scan.go:176-183 + techintel observation.go:196-212 Trail-extension/truncation cuts split multi-byte runes → non-UTF-8 values mutate through JSON cache round-trip (cross-run identity drift); jsintel parse.go:590-592,664-666 decodeEscape diverges from scanner on CRLF continuations (spurious CRLF / dropped \r).
- Fix: per-item; details preserved in session transcript.
- Verification: targeted tests per item.

### NEW-84 (INFO wave) — Full-repo review INFO/doc-skew items B (2026-08-23, reviewer session ox-alpha)
- Status: VERIFIED — orchestrator-verified 2026-08-23. cluster D/C: UserAgent composes version.Version; golden fallback capped 4 KiB/side; dns submitCause nil guard; AGENTS §10 snippet Concurrency; CLI twelve-stage usage — all with named tests or doc-verified
- Owner: docs
- Problem: AGENTS.md §10 canonical snippet names runtime.Config{MaxWorkers} but actual field is Concurrency (pool.go:54) — snippet does not compile; config.go:175 Default() UserAgent hardcodes "1.4.0" duplicating internal/version.Version; asset technology.go:184-193 strings.Fields converts NBSP to space although doc claims non-ASCII rejected; golden diff.go:29-34 oversized-diff fallback returns oldText+newText unbounded though Diff documents byte-capped output; dns run.go:207-209 fmt.Errorf("%w", ctx.Err()) renders %!w(<nil>) if Submit fails while ctx live.
- Fix: doc/comment corrections + one-line guards.
- Verification: n/a (docs) / trivial.


### NEW-59 (HIGH) — v1.8 Universal Asset Ingestion Framework (ROADMAP v1.8)
- Status: VERIFIED — milestone complete (closed by orchestrator 2026-08-23; commits 1ede060, 81785f2, 3e5ba4e, 5e806fe, 7fd312a, cf0e939, 1794fcd; every batch reviewer-verified) — implementation COMPLETE through T14 close-out
  (2026-08-23; batches 1-7 below). Remaining steps are orchestrator-only:
  reviewer verdict on batch 7 if dispatched, VERIFIED stamp, and archive
  move to TODO.closed.md — implementers never self-close.
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
- Batch 4 (T8 crawl-output importers + archive sources) IMPLEMENTED (builder ses_fd2bd4759ffetDV75xz35Nl4HI, 2026-08-23): ROADMAP v1.8 row dispositions verified against live upstream tool docs before coding — honesty over checkbox theater: katana text/stdout/-output = bare URLs → plain family; hakrawler stdout bare URLs, -json flat {"url":...} NDJSON → plain/json url-key classification; gospider -q ("only show URL") + -o category files = bare URL lists → plain family; waymore -mode U writes waymore.txt/-oU as deduped bare links (no header/footer format) → gzip-capable plain path; gau bare URLs/--json flat url-key objects → plain/json family. NO redundant importers created for those five (documented in doc.go registration checklist with rationale). Real formats implemented as internal/importer/archive.go (NEW): ArchiveCDXImporter "archive-cdx" (wayback CDX lines .cdx/.cdx.gz — classic SURT+timestamp+original@field-2 and surtless original@field-0 variants, timestamp/mimetype/status/length into provenance metadata ≤128B values) via existing bounded readLines; ArchiveWARCImporter "archive-warc" (.warc/.warc.gz — WARC-Target-URI extraction, WARC-Type metadata, payloads discarded in 8 KiB chunks under MaxDecompressedBytes with per-chunk ctx checks, honest truncation on mid-payload EOF/cap trip, ≤4-byte CRLFCRLF separator consume incl. zero-length payloads, missing-Content-Length resync by stray-line scan, garbage-first-line fails structurally via newImportError, oversized header blocks failed+truncated). Detection extension AFTER xml probes per waterfall order (gzip magic → json → xml → warc/cdx → plain): gzipped peeks inflated IN MEMORY ≤32 KiB (inflatePeek) so content decides while extensions only bump confidence (+0.05); archive-cdx requires majority (≥0.5 of ≤50 sampled lines) CDX-shaped lines at base 0.90 — the majority rule keeps one-stray-CDX-line URL lists owned by plain family (anti-steal test), and 0.90 base beats plain-urls whose ParseURL-based classifier tolerates space-padded CDX rows as ShapeURL (found empirically: surtless export ranked below plain-urls at old 0.80 base); archive-warc claims first-non-empty-line WARC/<digit> magic at 0.90. Both decline XML/JSON signatures. provenance.go +2 labels (archive-cdx→wayback-cdx, archive-warc→warc); doc.go checklist updated to canonical 16-specific + 2 generic = 18 importer set + full per-roadmap-row disposition section incl. Common Crawl remote ingestion OUT OF SCOPE (local files only); xml_test.go newFullRegistry extended with both (all pre-existing detection tests now run against the extended registry — no count pins existed). Tests archive_test.go NEW (33 cases): detection table (15 subtests: renamed exts, .gz content-detection, corrupt-gzip honest decline, anti-steal stray-line, half/half ambiguity pinned, whitespace-only claimed-by-nobody), CDX table (valid/dup/malformed/surtless/empty/decomp-cap/oversized-line/MaxOutput tail-drop), CDX provenance exactness (OriginalRecord verbatim incl trailing newline per readLines contract, metadata map, Identity alignment), CDX gzip, cancellation ×2 (sticky-free), WARC table (dedup across record types/no-target/invalid-URI/empty/garbage-first-line structural error/missing-CL resync/truncated-payload honesty/oversized-header stream-continues/cap-abort), WARC gzip payload-discard (OriginalRecord == exact header block, body bytes never retained, warc_type metadata), streaming retention dedup-trick tests (WARC 0.07 MiB / CDX 0.03 MiB delta over 60001 records ~5 MB files vs 8 MiB cap, sink pinned KeepAlive, sentinel EOF proof), progress emission through Observer. Bug-fix round during TDD: Content-Length:0 records originally skipped separator consumption (guarded contentLen>0) orphaning their CRLFCRLF as 2 failed strays — consumption moved out of guard (safe: unreads non-CRLF byte); fixture bug CL=11-vs-12-byte-body produced 2 strays/record, verified root-caused via probe test then fixed. Evidence verbatim: gofmt clean repo-wide; go vet ./... OK; go build ./... OK; go test ./internal/importer/ -count=1 ok 2.6s; go test -race ./internal/importer/... ok 17.5s; go test ./... 28 pkgs ok 0 fail; git diff go.mod empty. OPEN ISSUE discovered (not fixed here — outside DO-NOT-TOUCH boundary "existing importer behavior beyond detection extension"): modern katana -jsonl nests endpoint under request.endpoint (verified against katana README jsonl sample); classifyJSONObject (json.go:136) sees only top-level keys → shape "generic", json-generic claims at 0.40 but its field scan (json.go:818-986) covers only top-level string values → every nested-endpoint record fails "generic: no url/host/ip field" (json.go:987); concrete fix proposal: teach classifyJSONObject a {"request":{"endpoint"...}} shape → "katana" AND extend JSONKatanaImporter.Import to read rec.Request.Endpoint (or one-level nesting in json-generic); severity MEDIUM (silent under-ingestion of real katana JSONL exports, mis-attributed provenance); recorded in doc.go disposition note. Pending: reviewer round, orchestrator VERIFIED.
- Batch 4 review-fix round IN PROGRESS (fixes session ses_fd28d1daaffeOWE1tUkrhAgem8, 2026-08-23), reviewer REQUEST CHANGES 1 MEDIUM 2 LOW + validated MEDIUM escalation → fixes: MEDIUM ArchiveCDXImporter surtless metadata columns — Import hardcoded classic offsets (mimetype=fields[3], status=fields[4], length=fields[6]) for both layouts, so surtless rows (original ts mime status digest length) persisted mimetype="200"/status=digest/length-missing; fixed by cdxColumnsFor(fields) picking the offset map by which field supplied the original URL (fields[2] parses as URL → classic {mime:3,status:4,length:6}; else surtless {mime:2,status:3,length:5}; timestamp stays field 1), mirroring the existing original-field selection. Regression TestRegressionMED_CDXSurtlessMetadataColumns (archive_test.go): exact metadata equality on a pure surtless fixture + interleaved classic/surtless file proving per-row selection; RED proof verbatim on reverted logic → "metadata[mimetype]=\"200\" want \"text/plain\" (full map: map[mimetype:200 status:DIGESTXX timestamp:20200809173114])". LOW importer-count arithmetic — doc.go said "16-specific-importer set (+2 generic fallbacks = 20 total)" but 7 plain + 5 json + 2 xml + 2 archive = 16 specific + 2 generic = 18 total; corrected doc.go AND the Batch-4 record text above (=18). LOW waymore gzip overclaim — doc.go credited plain-family coverage of waymore outputs to the gzip-capable streaming path, but plain-family probes decline gzipped peeks at detection time (detect.go:363) so a gzipped bare-link file is claimed by nobody today; doc.go qualified to UNCOMPRESSED outputs with pointer to NEW-60 (open INFO entry below, concrete inflatePeek-based fix option). VALIDATED ESCALATION modern katana -jsonl nested endpoint — classifyJSONObject now recognizes {"request":{"endpoint":string,...}} → shape "katana" (isKatanaNestedObject, checked after all flat shapes so flat records keep precedence; nested decode bounded to the ≤32 KiB detection peek) and JSONKatanaImporter decodes an optional nested katanaRequest struct reading request.endpoint when top-level url is absent ("response" sibling deliberately unbound — struct decoder skips it without retention, no whole-file load); regression TestRegressionMED_KatanaNestedJSONL (json_test.go): full-registry detection top match json-katana, mixed flat+nested NDJSON → ItemsProcessed=3 ItemsFailed=0 urls=3 with exact identity set via ParseURL normalization + verbatim nested OriginalRecord provenance, endpoint-less record fails honestly (0 processed / 1 failed); RED proof verbatim on reverted detection → "top match \"json-generic\" want json-katana". Evidence verbatim: gofmt -l . clean (no output); go vet ./internal/importer/... OK; go build ./... OK; go test ./internal/importer/... -count=1 ok 2.667s; go test -race ./internal/importer/... -count=1 ok 16.901s; git diff go.mod empty. Pending: reviewer round, orchestrator VERIFIED.
- Batch 5 (T11 pipeline ingestion stage adapter + T13 reporting attribution) IMPLEMENTED (builder session ses_fd2757c1bffeZCGwE3XClPtmiz, 2026-08-23): D6 honored — ingest is a pipeline stage feeding the SAME stages; production AllStages()=12 untouched (v1.7 goldens green unchanged). internal/pipeline/adapt/import.go (NEW): ingestStage Name "ingest", NewIngestStage() is THE caller-side composition point registering all 18 importers (16 specific + json-generic + plain-generic) then Seal; StageParams keys paths (newline/comma-separated files+dirs; missing → structured error naming the path; ".." segments post-Clean rejected; non-file/non-dir refused via os.Stat) + max_output/max_line_bytes/max_decompressed_bytes overrides (invalid ints are structured errors); dirs walked lexically via WalkDir + final sort.Strings → deterministic file order; ONE bounded runtime.Pool per stage from resolved bounds (Concurrency/QueueSize defensively defaulted for out-of-runner use, ctx propagation, Shutdown drained); per file: 32 KiB peek buffered once → registry.Detect top match = primary (ambiguous → primary wins, pinned by TestIngestStageAmbiguousPrimaryWins: url+method object → json-katana), no claim → ItemsFailed not silent skip; cache-before-execute around importer.Import via CacheKeyForFile→cache.NewKey — hit serves stored payload without re-parse, PROVEN two ways (countingCache wrapper hits>=2 puts==0 warm AND countingImporter fake in custom registry executes exactly once across two runs, TestIngestStageImportCounterProvesNoReparse). DEVIATION FLAGGED (D4 literal reading): cache payload embeds ImportCacheData verbatim (slim shape preserved as embedded struct) PLUS full canonical assets + ProvenanceRecords — a slim-only record would make warm-run assets/provenance differ from cold run and silently drop T13 attribution on warm runs; payload revalidated through asset builders on decode (corrupt/tampered → Delete + fresh execution same run, mirroring discovery decodeStored; TestIngestStageCorruptedCacheSelfHeals plants garbage bytes and pins identical assets after self-heal); truncated imports store cache.StatusIncomplete so cache.Get can NEVER serve them as valid hits; failed invocations store nothing; >cache.MaxRecordSize payloads skip Put (best-effort caching, execution is source of truth). Outcomes: per-file fold cancelled > all-failed > partial(any failed or truncated) > completed; ctx-cancelled imports classify cancelled (not failed) via ctx.Err()/errors.Is; truncated → Truncated=true + engine's own sticky flag "import_truncated" surfaced verbatim; retained sink merged into Additions{Domains/Hosts/URLs boundary-filtered vs target} + Results{IPs/JavaScript/Findings} + Provenance sidecar on EVERY path incl. failed/cancelled. Pipeline support touches (flagged): config.go +StageIngest const, ValidStage accepts it WITHOUT entering pipelineOrder (AllStages still 12), vocabulary message lists it; stage.go +StageResult.Provenance []importer.ProvenanceRecord; results.go +mergeProvenance (first-seen dedup identity|US|filename|US|importer — same asset from two files keeps both records, cache-hit replay dedups); run.go +RunReport.Provenance merged with eff.MaxOutput cap flagging "import_provenance_truncated", field has json:"Provenance,omitempty" because the acceptance golden harness serializes RunReport whole — nil slice keeps golden bytes identical (three acceptance profiles were RED before the tag, GREEN after, goldens untouched). T13 internal/report: Context.Attribution map[string]AttributionEntry {Importer/OriginalTool/Filename/Line/ImportedAt/Confidence} omitempty-zero-change when absent, capped at maxAttributionEntries=100k sorted-key prefix with Model.AttributionTruncated flag (never silent cut, never reject); normalizeAttribution in validate.go rejects keys referencing unknown model identities (structured error naming the key — schema honesty) and confidence outside [0,1]; Model.Attribution/Origins census {"discovered":N,"imported":M} present only when attribution exists; OriginOf = membership → imported else discovered, enriched/generated DEFERRED documented (no subsystem derives them today — inventing them would fabricate provenance); digest includes Attribution+flag+census via omitempty fields so absent attribution hashes byte-identically to legacy payload (TestAttributionAbsentKeepsLegacyExports pins no new JSON keys; TestAttributionDigestDeterminism pins ±attribution/±field/±ImportedAt moves digest, same content+attribution stable across models); renderers: CSV hosts/urls/findings gain origin column (fuzz_test seeds updated 3→4/7→8/9→10 — intentional schema change, only test touched), Markdown "## Provenance" + HTML details id=provenance sections render ONLY with attribution (≤100 rows + honest N-more line), presentation-only sorted by identity; parity acceptance TestOriginOfParity: same host discovered vs imported → identical asset fields both models, origin/attribution differ, census 1 imported / ≥2 discovered. Known deferrals recorded here (no separate entries): CIDR imports have no Results channel (Results mirrors Context 1:1, neither has one) — provenance records still reach the sidecar keyed cidr:<prefix>; AttributionEntry.Line stays 0 until CLI wiring parses asset Prov.Reference filename:line; ImportEnv.Observer nil until StageInput gains an Observer seam (stage_started/finished already flow through the runner's observer). Tests: adapt/import_test.go 9 tests + pipeline/provenance_merge_test.go 2 + report/attribution_test.go 7, all hermetic tempdir/fixed-clock synthetic fixtures. Evidence verbatim: gofmt -l internal/ → empty; go build ./... ok; go vet ./... ok; go test ./... -count=1 → all 28 test-bearing packages ok (discovery 113s, adapt 18.5s, report 0.63s, importer 3.78s); go test -race ./internal/pipeline/... ./internal/report/... ./internal/importer/... → ok (pipeline 1.19s, adapt 21.6s, report 3.44s, importer 17.5s). Pending: reviewer round, orchestrator VERIFIED. REVIEW OUTCOME (2026-08-23): reviewer REQUEST CHANGES (1 MEDIUM 2 LOW + 1 LOW path-handling + 1 INFO — fixes in the review-fix bullet below). D4 deviation ACCEPTED by reviewer as an amendment to locked decision D4: the cache payload embeds assets+provenance for cold/warm byte-parity, bounded retained-set only, oversized-skip honest. INFO-4 caveat: large retained sets exceed MaxRecordSize 16 MiB → skip caching by design → always re-execute; consider surfacing skip counts via the cache observer later.
- Batch 5 review-fix round IN PROGRESS (fixes session ses_fd23dc311ffediu6NLyhyCxmvo, 2026-08-23), reviewer REQUEST CHANGES → fixes: MEDIUM TestIngestStageTruncatedPartialSticky warm leg passed different StageParams overrides ({max_output:2} vs cold {max_output:2,max_line_bytes:4096}) → different CacheKeyForFile config → different key → cache.Get never saw the stored StatusIncomplete record; both legs now share ONE overrides map, and ingestCountingCache gained incompleteGets (Get outcomes in StateIncomplete = well-formed record refused on status, not absent-key miss) + mutex-guarded putRecords capture — test asserts every stored record's Status == StatusIncomplete exactly when stats.Truncated (converse pinned in TestIngestStageCacheHitWithoutReparse: clean imports store completed) and incompleteGets >= 1 on the warm leg; RED proof verbatim: status flip to unconditional StatusCompleted → "import_test.go:531: cold put[0] status = \"completed\", want incomplete (a truncated retained set must never be stored completed)" → restored → PASS. LOW validate() URLs checked parse-success only (tampered-but-parseable URL servable while domain/host tamper self-heals): now compares re-canonicalized form (canon.String() == u.String()) before accepting, mismatch → refuse+Delete+fresh execution; regression TestIngestStageTamperedURLSelfHeals plants an uppercased-host URL payload via ingestStaticCache fake → deletes==1, fresh-exec puts>=1, identities equal cold run. LOW foldIngestOutcomes assigned StickyFlags only inside the truncated-flag branch (future non-truncation engine flags silently dropped): flags assigned whenever len(flags)>0, res.Truncated set separately from the specific flag presence; unit TestIngestFoldPreservesNonTruncationStickyFlags pins a non-truncation flag surviving a clean fold. LOW expandIngestPaths WalkDir skipped in-dir symlinks while top-level os.Stat followed them (symlink-only drop-dir → zero files, silent completed) + file reachable twice (explicit + under listed dir) imported twice double-counting ItemsProcessed: explicit dir expanding to zero regular files now fails the stage with a structured error naming it (top-level missing-file errors unchanged), expanded list deduplicated after sort; pinned by TestIngestStagePathValidation/{directory_with_no_regular_files,symlink-only_drop_directory} + TestIngestStageDeduplicatesExpandedPaths (counter.imports==1, ItemsProcessed==2). INFO AttributionEntry.ImportedAt json omitempty never fires on time.Time struct → misleading tag dropped (behavior-neutral, encoding/json never omits structs). Evidence: gofmt clean; go vet ./... ok; go build ./... ok; go test ./internal/pipeline/... ./internal/report/... ./internal/importer/... -count=1 ok; go test -race same scope ok; go.mod untouched. Pending: reviewer re-review, orchestrator VERIFIED.
- Batch 6 (T12 ingest CLI + provenance→attribution wiring) IMPLEMENTED (builder session ses_fd226e28bffefw6I1jDRnoTsYg, 2026-08-23): internal/cli/ingest.go (NEW) mirrors scan.go structure — `ravenrecon ingest [options] <target> <path> [<path>...]` (flags BEFORE positionals: Go flag stops at first positional with multiple inputs; a flag-looking token after the target is a targeted usage error "looks like an option but follows the target", never a silent path); target normalized via asset.NewDomain; paths flow verbatim newline-joined into StageParams["ingest"]["paths"] (single validation point = stage's expandIngestPaths); default selection = [ingest]+AllStages minus discover DERIVED from pipeline.AllStages() (ingestDownstreamStages — no string-constant drift possible), --stages selects downstream only, rejects "discover" ("imported corpus replaces discovery as corpus source — discovery of a domain is scan's job") and "ingest" ("always runs first"), caller order preserved after ingest; flags --stages/--output/--cache/--no-cache/--verbose/--tui/--tui-compact with scan-identical mutual exclusions; NO --type ever (help states it; unknown-flag pinned by test); cache resolution mirrors scanCache semantics (explicit dir > config > off; --no-cache absolute) with ingest-prefixed errors; TUI wiring identical bounded bus/subscriber/join reusing scan's tuiRunner/fakeTUI seams; summary printIngestSummary = printScanSummary shape with ingest header reusing reportFiles (temp-render exclusion); exit mapping IDENTICAL to scan (completed/partial=0; failed/cancelled/incomplete=1; interrupted summarized-then-error). REQUIRED SCOPE EXTENSION FLAGGED (acceptance demanded origins/attribution in reports; none existed — StageInput carried no provenance and adapt/report.go built Context without Attribution despite context.go:222 calling it "the CLI wiring task's concern"): pipeline/stage.go StageInput.Provenance field (read-only merged-sidecar contract mirroring Results/Documents, runner passes live slice pre-stage-turn) + pipeline/run.go input construction assignment + adapt/report.go projection attributionFromProvenance/in.reportContextIdentities (first-record-per-identity wins; records whose identity is absent from THE CONTEXT handed to report.Run are dropped — NewModel rejects unknown keys outright, and attributing boundary-filtered/capped assets would be false provenance). Additive only: runs without ingestion keep nil Provenance → absent Attribution → legacy exports byte-identical (v1.7 goldens safe, full suite green). cli.go dispatch+usage lines only; main.go untouched (command-agnostic). Tests internal/cli/ingest_test.go hermetic (fake seam via cfg.Stages-name resolution; e2e uses REAL NewIngestStage+NewReportStage over tempdir urls.txt → asserts report.json urls==3, origins{discovered:0,imported:3}, 3 attribution entries importer=plain-urls filename=urls.txt incl url:http://api.example.com/login key): parse table 18 cases, downstream-vocabulary derivation pin, build defaults/selection order, outcome mapping 5 outcomes (failed case fails BOTH selected stages — always-first ingest completing folds failed+completed→partial), validation-never-invokes-stages, target normalization, cache state, interruption, TUI wiring (24 events sequences intact, summary byte-identical to no-flag run), TUI-runner-required, help snapshot (every flag + every downstream name present), dispatch. Evidence: gofmt clean; go vet ./... clean; go build ./... OK; go test ./... -count=1 = 28 pkgs ok 0 fail (incl v1.7 suites); go test -race ./internal/cli/... ok 1.697s; go.mod untouched; live binary: `ingest --help` documents real flags, `--type httpx` → "flag provided but not defined" exit 1, tempdir run completed exit 0 with 9 report files, `--stages discover` rejected exit 1.
- Batch 6 review-fix round IN PROGRESS (fixes session ses_fd2018dcaffeIFF24aoATRRvQ3, 2026-08-23), reviewer 2 MEDIUM on the T12 provenance→attribution projection → fixes TEST-ONLY (internal/pipeline/adapt/report_attribution_test.go NEW; zero production lines touched): MEDIUM-1 attributionFromProvenance/reportContextIdentities edge semantics unpinned — TestReportAttributionProjectionEdges table-drives both against a universe built from corpus + results channels: first-record-wins on duplicate identity (surviving entry asserted field-verbatim amass/first.txt/fixedTime/0.8 — no merge with the later duplicate), empty-Identity record skipped while its valid sibling survives, boundary-filtered target-absent identity ("host:evil.com") dropped AT ADAPTER LEVEL, results-channel identities beyond URLs (ip/javascript/finding kinds) project like corpus assets, plus nil-map honesty rows (all-dropped and empty-sidecar each return nil). MEDIUM-2 reportContextIdentities duplicates unexported modelIdentitySet with no drift guard — TestReportContextIdentitiesParityAllKinds builds one asset of EVERY kind via the existing model constructors (15 asset.New*/ParseURL kinds + LiveRecord through its own distinct URL = 16 identities), composes report.Context exactly as the stage does, asserts each identity is in reportContextIdentities AND survives attributionFromProvenance with fields verbatim, pins negative controls (relationship/priority Surface carry no identity; universe size exactly 16), and adds a REFLECTIVE drift guard walking every exported slice field of report.Context collecting Identity()-method identities (+LiveRecord.URL special case) asserting EXACT set equality in BOTH directions — a future kind added to Model+Context without extending reportContextIdentities fails automatically naming the dropped identity instead of silently discarding provenance into false "discovered" origins. RED proof (temporary mutation, reverted byte-identical): SourceMaps loop deleted from reportContextIdentities → 5 assertions fire incl. "context channel carries identity \"source_map:https://www.example.com/app.js.map\" that reportContextIdentities does not collect" and "identity sets differ in size: reflected 16 vs collected 15". Evidence: gofmt clean repo-wide; go vet ./... OK; go build ./... OK; go test ./internal/pipeline/... ./internal/cli/... ./internal/report/... -count=1 all ok (adapt 18.45s); go.mod diff 0 lines. Pending: reviewer round, orchestrator VERIFIED.
- Batch 7 (T14 benchmarks + memory guards + C-4 detector + v1.8 docs close-out) IMPLEMENTED (builder session ses_fd1f37639ffeIxybY3WzgCDr2Q, 2026-08-23). SCOPE A tests-only, zero production lines touched: (1) internal/importer/bench_test.go NEW — five hermetic benchmarks over synthetic tempdir corpora with untimed workload validation (processed=10000 failed=0 not truncated) so a benchmark can never silently measure an empty pass: BenchmarkPlainURLs10K (10k distinct fixed-width URLs end-to-end: stream→classify→ParseURL→dedup→sink+provenance), BenchmarkJSONHTTPX10K (10k httpx NDJSON records incl. OriginalRecord capture), BenchmarkDetectFullRegistry (sealed 18-importer registry classifying 70 candidates × 7 format families per iteration — the per-file detect() cost), BenchmarkIngestCold/BenchmarkIngestHit over a real FS cache in tempdir mirroring the stage composition (key parts → NewKey → Get → Import → marshal → Put; cold includes Delete per iteration so every iteration misses again — documented in-file); (2) baseline decision RECORD + CI wiring, justified by measurement: three full -count=10 -benchmem sessions, gateable medians stable far under the >25% gate — B/op medians across sessions Detect 23875904/23876294/23875779, Cold 1198713/1198342/1197808, Hit 182298/182304/182307, JSONHTTPX 26864217/26864064/26864421, PlainURLs 21277196/21277192/21277188 (spread ≈0.002-0.08%), allocs/op identical or ±2; ns/op wobbled ≤~6% (fsync noise on IngestCold/Hit) but stays advisory per D4; cmd/benchgate passes run↔run in both directions (exit 0 all three pairs) → testdata/bench/importer.txt committed as verbatim session output (no FAIL-line stripping needed unlike httpprobe), testdata/bench/README.md gained an importer section (stability evidence + fsync-noise caveat), ci.yml bench-gate gained the importer step following the exact event/urlintel conventions (full -bench=. set, no filter); fresh CI-shape run against the committed baseline exits 0; (3) memory guard v1.7 pattern exactly: memguard_test.go NEW (TestMemGuardBoundedImportHeapDelta: 10 MB synthetic plain-subdomains stream over 16 rotating identities = dedup trick so retained set stays tiny while parse machinery runs at full stream size; post-GC HeapInuse delta measured 0 bytes vs 8 MiB ceiling matching the "<8 MiB streaming overhead" claim; sink pinned past m2 via len-reads + runtime.KeepAlive per the HIGH-2 vacuous-guard fix; no exact-MiB equality) + memguard_race_test.go/memguard_norace_test.go build-tag pair (raceEnabled true/false, skip under -race and -short); DISCLOSED test-infra fix riding the same pattern: streaming_test.go isRaceEnabled() was a dead stub always returning false despite its own comment claiming race-skip — rewired to return raceEnabled so the nine pre-existing heap guard tests across six files (archive_test ×2, xml_test ×2, json_array_bounded, json_test, streaming_test, regression_high ×2) now honor their documented contract (behavior change only under -race where guards SKIP per locked decision D3; non-race runs unchanged); (4) C-4 drift check answered YES: OPTIMIZATION.md §7 C-4 gained an importer row (line 32 KiB / decompressed gzip 100 MiB / 100k retained records) and internal/importer/bounds_c4_test.go NEW pins MaxLineBytes=32*1024, MaxDecompressedBytes=100<<20, MaxOutput=100000 (all three also enter cache keys, so drift would be key-invalidating too). SCOPE B docs: ROADMAP.md v1.8 status planned→complete closed 2026-08-23, version-table row ✅ with commit refs (1ede060, 81785f2, 3e5ba4e, 5e806fe, 7fd312a, cf0e939), all 15 checklist items [x] with per-item refs, acceptance criteria checked with honest evidence (1 GB claim stated as structural-caps + 10 MB empirical, NOT a recorded 1 GB lab run; detection gap NEW-60 cross-referenced), plus explicit dispositions block (crawl tools route through plain/json families; Common Crawl remote deferred; Enriched/Generated derivation deferred; CIDR report channel deferred); OPTIMIZATION.md appendix OPT-P3-2 PLANNED→VERIFIED with commits + TODO.md NEW-59 pointer (not TODO.closed.md — archive move is orchestrator-owned); ARCHITECTURE.md new "Universal asset ingestion" section (package layout, detection waterfall incl. NEW-60 gap, streaming bounds, cache keys incl. D4 amendment + self-heal, provenance sidecar, StageIngest fold semantics, origin attribution with Line-field honesty, ingest CLI line) inserted between Terminal observability and Configuration precedence + Reader's map row added and shifted ranges recomputed from a FINAL post-insert heading grep (initial recompute missed the map row's own +1 shift; corrected): TUI 3141-3233 unchanged; ingestion 3235-3339; config 3340-3353; safety 3354-3366; v0.3 3367-3610; README.md status bump v1.7.0→v1.8.0, ingestion feature paragraph, new "Universal asset ingestion" section with `ravenrecon ingest` snippets, Current commands gained the ingest block; stale detect.go:331 refs corrected to :363 in the Batch 4 review-fix record and this entry's Problem field. Gates this session (verbatim outcomes): gofmt -l . → empty; go vet ./... OK; go build ./... OK; go test ./internal/importer/... -count=1 ok 3.0-3.4s; full go test ./... -count=1 → all 28 test-bearing packages ok 0 fail (discovery 113.3s slow-but-green per board note, importer 3.36s); go test -race ./internal/importer/... -count=1 ok 4.107s (guards SKIP under race by design — down from ~17s when they ran, confirming the skip works); benchgate baseline↔fresh exit 0; go.mod/go.sum untouched; production code untouched (git diff shows only _test.go files, testdata/, .github/, and docs).


### NEW-56 (HIGH) — v1.7 Integration and acceptance testing (ROADMAP v1.7)
- Status: VERIFIED (orchestrator, 2026-08-23) — milestone complete: batches D/E/F + D5 CI + D7 docs wave all IMPLEMENTED + REVIEWED (APPROVE), gates green; docs drift reconciled (OPTIMIZATION.md appendix stale → VERIFIED with commit refs, ten-stage → twelve-stage, benchstat → benchgate per D4, C-4 soft corners clarified), pipeline twelve stages (`AllStages()` = 12), acceptance framework (fixtures/<profile>/, per-stage goldens, bench-gate) documented in README/ARCHITECTURE, ROADMAP v1.7 flipped ✅ Complete (53f2f46, 2dcdc96, 9370f3f, 14f61a9, e043555; plus D7 docs)
- Reporter: master
- Owner: builder (per-task dispatches) + docs (D7)
- Problem: ROADMAP v1.7 — fixtures/<target>/, golden snapshots naming the regressed stage, perf/memory baselines, CI drift gates, regression suite for engine interactions. Research round completed (ses_fdaca5d04ffeeHnmQcbF4rgv47); reality corrections: CI EXISTS (.github/workflows/ci.yml: gofmt/vet/test — extend, don't create); OPTIMIZATION.md appendix stale (P0-4/P0-5/P1-3..5/P2-4 still OPEN despite closed milestones) and says "ten-stage" (pipeline is twelve since v1.5). Locked decisions D1–D7 as in TODO.md NEW-56.
- Fix: D1 hybrid weighted-static fixtures under fixtures/{clean-baseline,messy-contradictory,hostile-adversarial}/ via T4 seams; D2 field-masked per-stage goldens via shared internal/golden; D3 two-tier memory (structural C-4 drift detectors + HeapInuse guards); D4 hand-rolled cmd/benchgate stdlib comparator (no benchstat); D5 CI bench-gate job; D6 interaction gaps (corrupt-cache, sticky cold→warm, mid-run cancellation across 12 stages); D7 docs drift reconciliation.
- Verification: Batch D 53f2f46 — 9 packages bounds_c4_test.go + HeapInuse guards (≈0 B / 11.2 MiB vs 32 MiB, -race SKIP), baselines testdata/bench/*.txt (-count=10 -benchmem), cmd/benchgate 16 tests; Batch E 2dcdc96 — clean-profile acceptance (resolveProfilePath containment, 12 goldens + markdown, 3×/5× determinism, hermetic PATH=/nonexistent, -race green); Batch F e043555 — messy/hostile + D6 interactions (byPath+oversized, dns_poison merge, 3 D6 suites 21s -race green); D5 14f61a9 — bench-gate CI (needs:test continue-on-error true, 6 packages, urlintel filtered, httpprobe grep -v FAIL); D7 docs wave — appendix VERIFIED with commit refs (b46a110, 2d06b94, 7fc7e4c, f44cecc, 593177a/08861f0, 1f4b0c8, 3b21401, d10d719, 9575e14, 8c795eb, 4e31f8d), ten-stage→twelve-stage grep 0 (except historical), benchstat→benchgate per D4 (testdata/bench/README.md), C-4 clarified (MaxDocumentBytes + techintel caps), README/ARCHITECTURE twelve-stage + acceptance framework. Gates: gofmt clean, go vet OK, go build OK, go test OK, go test -race OK (adapt 18s, discovery 75s).
- Batches: D+E+F+D5 as in TODO.md NEW-56 (53f2f46, 2dcdc96, 9370f3f, 14f61a9, e043555); D7 docs wave (this session): OPTIMIZATION.md appendix + C-4 + ten-stage + benchstat reconciled; ROADMAP.md v1.7 ✅ Complete; README.md fixtures/goldens/bench-gate + twelve-stage; ARCHITECTURE.md twelve-stage + acceptance framework; TODO.md NEW-56/57 archived, next free NEW-59; gates re-run green. Archived per conventions.

### NEW-57 (MED) — BenchmarkIngestMillion fails its own assertion: ~1.8% store shortfall at 1M lines (internal/urlintel)
- Status: VERIFIED — implemented (debugger, 2026-08-23) and reviewer APPROVE 2026-08-23: root cause inode exhaustion on 2^20-inode tmpfs silently absorbed — Puts failed ENOSPC, only per-entry Err, run nil. Fix: production record.go storeURL surfaces cache-put failures as bounded diagnostics via recordCacheDiagnostic; bench capacity arithmetic volumeFitsInodes + shardDirBound + inodeHeadroom with pre-flight millionCacheDir fallback to user cache dir and loud skip; assertNoEntryDiagnostics pins honesty; header documents ~50 min. Baseline re-inclusion deferred (-short-gated, urlintel.txt stays without million line, benchgate handles missing). Archived per conventions.
- Reporter: builder (v1.7 batch D, NEW-56)
- Owner: debugger
- Problem: internal/urlintel/bench_test.go:225 BenchmarkIngestMillion observes {Lines:1000000 Stored:981506} short 18,494 (~1.8%) with zero malformed — pre-existing, excluded from urlintel.txt.
- Fix: instrument store failures, fix production + bench capacity math, regression coverage.
- Verification: 3× consecutive runs pass; benchgate handles missing; gates green.

### v1.2.5 SDK freeze (bbf23c8, db7a00c)
- T1-T9 VERIFIED (bbf23c8, db7a00c): SDK freeze landed — ValidateRule/ParseRuleVersion/12 bounds consts (rule.go), Registry.Seal (registry.go), APIMajor=1/APIMinor=0/CheckAPIVersion (api.go), sdk_test.go, T4 examples pack (internal/detect/examples), T5a surface_snapshot_test.go, T5b behavior_contract_test.go, T6 semantic compat (compat_test.go), T7/T8 docs.
- Review chain: APPROVE WITH NITS, all closed — NEW-6 registry readonly race (atomic.Bool + re-check under write lock, registry_race_test.go, proven failing pre-fix), degree-rule observed-set guard, variadic newRule deps, explicit version param (degree rule 1.0.1); orchestrator gates (test/vet/-race) green after each round.
- Goldens regenerable only via explicit `-update`: api_v1.golden (7216B, sha256 034f292a; de-overpinned in db7a00c) + api_v1_report.golden (13,853B). Incident: rule.go briefly restored from HEAD during a drift demo — restore byte-exact verified (sha256 0b6829a6).
- Docs-compaction wave (L4/L5/L3): AGENTS.md diet, TODO.md closed-section compaction, ROADMAP.md v0.x collapse — orchestrator-verified, reviewer APPROVE (2 INFOs fixed), gates green; kept UNCOMMITTED by maintainer decision (agent-workflow docs, not project code). Follow-ups in the same uncommitted docs set: (a) v1.8 Universal Asset Ingestion Framework milestone (ROADMAP.md, user-specified, orchestrator-written); (b) Phase Ownership Policy — AGENTS.md §5 rewritten (Primary/Infrastructure/Refactor/Future Feature classification; "modify any subsystem if strictly required, never implement the future milestone's user-facing functionality") + ROADMAP rules & phase-review checklist bullets (user-specified, orchestrator-written). Reviewer sign-off pending on (a)+(b) with the next review round.

### TODO board sweep (0865b66)
- M-1 (tests) — VERIFIED: rawResponder e2e spoof regressions (hostile `tls:fake` status line + no-colon header-line abort) classify ProbeFailed/ReasonOther on the REAL transport; spoof string asserted in surfaced error (fails pre-fix by construction).
- M-2 (tests) — VERIFIED: probeKey domain pinning — key inequality across declared domains, equality for identical inputs, exact-shape pin, and a broader-scope run re-executes instead of being served the narrow record.
- NEW-1 (LOW) — VERIFIED: decodeStoredURL refuses any stored URL asset whose Original is non-empty and non-canonical (parseable + unparseable credential-bearing forms; canonical-form refusal corner); regression rows + end-to-end self-heal subtest.
- NF-1 (INFO) — WON'T FIX: `admin/openapi.yaml` never existed (no dir, no git history, not gitignored); repo-wide `0.5.0` grep already clean — stale entry.
- NF-2 (INFO) — VERIFIED: techintel/doc.go cache section now lists operation, identity, SchemaVersion, db_digest, and the sources bitmask, matching techKey (record.go:26-36) — fixed in the audit changeset itself.
- NF-3 (INFO) — VERIFIED: MaxHeaderBytes comment (run.go:36-43) documents the strict-exceed abort and exact-equality isHeaderCapAbort classification (never substring). Left open by design: NEW-3 (DEFERRED), NEW-4 (OPEN) — see Open items.

### v1.0 audit changeset (0865b66)
- H-1..L-21 — all 14 findings closed (0865b66), senior review APPROVE with 12/14 fully closed + failing-on-pre-fix regressions: H-1 credential echo (sanitizeLocation both raw-echo branches; observe.go Location redaction); H-2 outcome-vocabulary amendment (AGENTS §0 item 6, verified against techintel/urlintel sticky flag chains end-to-end); M-1 typed TLS classification (tlsHandshakeError sentinel at DialTLSContext, tls.RecordHeaderError, exact-equality header-cap abort, no text fallback — code-verified at commit, regression tests landed later in the sweep above); M-2 probeKey declared-domain pinning (code-verified, tests in sweep); M-3 urlintel userinfo redacted at single ingest construction point; M-4 secrentel redactedCandidateID at all four rejection sites; M-5 jsintel content binding (AnalyzedHash cross-validated, stale never served, silent self-heal); M-6 jsintel redirects — non-http(s) targets observed-not-followed; M-7 detect fingerprints full field coverage + provenance, SchemaVersion 2, old records self-invalidate; M-8 techintel NaN rejected at load and decode, neutralized in deriveConfidence; M-9 techintel fingerprint-DB content digest in cache keys (computed once per run); L-10 report zero-byte render parts rejected + self-heal; L-11 mdEscape doubles backslashes before pipes; L-20 version 1.0.0 + UA bump; L-21 CI pinned to go.mod; README/ARCHITECTURE/AGENTS synced.
- NEW-12 (MED) — VERIFIED + CLOSED: T9 sync (ROADMAP ticks + status, README SDK paragraph, AGENTS §2 footnote), final-review NITs (golden de-overpinned, ROADMAP table row, schema-bump carve-out), full-milestone reviewer sign-off APPROVE WITH NITS, committed (bbf23c8, db7a00c); ROADMAP v1.2.5 flipped to ✅ Complete at docs-wave close.

### NEW-13 (HIGH) — v1.3 End-to-end pipeline: `ravenrecon scan` (internal/pipeline)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20): v1.3 complete —
  T6 CLI+docs VERIFIED — review APPROVE WITH NITS (FIND-1 LOW +
  FIND-2..8 INFO all closed in a fix round, closure re-verified APPROVE,
  gates re-run), committed 382e218; ROADMAP v1.3 flipped ✅ Complete;
  this entry CLOSED by the orchestrator (the milestone owns it; all
  sub-milestones T1..T6 are VERIFIED above)
- History: T1/T2a/T2b VERIFIED; T2c VERIFIED — review APPROVE
  WITH NITS, all nits closed + gates re-run; T2d VERIFIED — re-review
  APPROVE WITH NITS, all findings closed, gates re-run; T3a stage events
  VERIFIED — review APPROVE (7/7 findings closed, gates re-run), committed
  ad791c3; T3b results channel VERIFIED — review APPROVE WITH NITS
  (FIND-1 LOW + 3 INFO closed in a nit round, gates re-run), committed
  this session; T3c document channel + secrentel adapter VERIFIED —
  review APPROVE WITH NITS (FIND-1 MEDIUM docs + 4 INFO closed across two
  fix rounds, closure verified, gates re-run), committed 9da5793; T3d
  adapters results production/consumption VERIFIED — review APPROVE WITH
  NITS (FIND-1..4 LOW/INFO doc fixes closed in a fix round, closure
  re-verified, gates re-run), committed 9abe2d3; T4 determinism VERIFIED —
  review APPROVE WITH NITS (FIND-1..4 closed in a nit round, closure
  re-verified, gates re-run), committed with this board pass; T5 hermetic
  E2E VERIFIED — review APPROVE WITH NITS (FIND-1 closed in a fix round,
  closure re-verified, gates re-run; NEW-3 board header restored),
  committed with this board pass; T6 CLI+docs IMPLEMENTED — see the T6
  record + fix-round record below)
  (Note: the tail of the History paragraph retains the pre-closure
  wording "T6 CLI+docs IMPLEMENTED" as written at the time; the closure
  state is the Status line above.)
- Reporter: master
- Owner: builder (per-task dispatches)
- Problem: ten library engines exist but nothing composes them; v1.3
  (ROADMAP) requires one deterministic workflow discover→dns→httpprobe→
  urlintel→techintel→jsintel→secrentel→priority→detect→report with
  shared runtime/cache/asset-graph, pipeline-level error handling, and
  hermetic E2E tests (success/partial-failure/retry).
- Fix (locked decisions D1-D5): internal/pipeline package; empty-registry
  detect stage by default (no rules ship with the framework); Level-2
  detect freeze deferred (pipeline consumes Report fields only); techintel
  observations header/TLS/DNS-only (no bodies — documented limitation);
  secrentel offline queue surfaced as count, never executed; scan CLI in
  T9.
- T1 skeleton (config/stage/run/scope + 25 tests): landed; review round 1
  APPROVE WITH NITS (1 MEDIUM + 2 LOW + 4 INFO) — all fixed; re-review
  APPROVE WITH NITS (3 INFO). Gates green after both rounds
  (gofmt/test/vet/-race/build/full-suite; my own verification re-run).
  Runner semantics pinned: stage contract w/ truncation discipline
  (completed+Truncated+empty flags → incomplete), fold precedence table
  (25 pairs), panic isolation incl. Name(), pre-cancelled+empty →
  cancelled, cancelled+ctx-error stays cancelled, Burst:0 default
  semantics, StageParams seam (validated, never aliased).
- T1 INFOs folded into T2 dispatch (non-blocking, do not lose):
  (1) pin OutcomeFailed + ctx.Err() still folds failed — one subtest in
  TestRunStageContractViolations; (2) rephrase resolution-failure message
  when a provided stage's Name() panicked ("could not resolve: no matching
  stage provided (note: a provided stage's Name() panicked)") — run.go
  ~116-135; (3) cosmetic StageInput field naming (Config vs Bounds) —
  accepted as-is, no churn.
- Status per task: T1 done (above) · T2a corpus propagation DONE —
  runner merge (first-seen dedup by asset.Identity, deterministic order,
  defensive copy), per-stage MaxCorpusSize cap at merge (hosts-first
  tail-drop; cut entries stay first-seen, cannot re-enter — documented),
  corpus_capped sticky flag + Truncated (AGENTS §0.6 carve-out), RunReport
  final corpus + StickyFlags, failed-stage additions retained (honest
  output), INFO-1 (failed+ctx.Err stays failed) + INFO-2 (resolution
  message) pinned; review APPROVE WITH NITS (LOW-1 semantics documented,
  LOW-2 pinned ×4 subtests, INFO-3/4/5 documented); gates green incl.
  full suite. Implemented by master orchestrator (builder unavailable —
  stuck at thinking; user override) · T2b httpprobe adapter DONE (this
  session): internal/pipeline/adapt/httpprobe.go + httpprobe_test.go (13
  tests: alive additions, out-of-domain input filtered pre-engine,
  out-of-domain URL-host output filter, all-failed, mixed-partial,
  pre-cancelled + in-flight cancellation, cache pass-through via FS cache
  zero-request second run, empty-filtered short-circuit ± cancelled ctx,
  request_timeout parsing table + e2e 50 ms deadline, header-cap truncation
  flag); mapping Status{Completed,Incomplete,Failed,Cancelled} →
  pipeline{completed,partial,failed,cancelled}, truncation →
  Truncated+StickyFlags["probe_truncated"], params: request_timeout only
  (invalid/absent/≤0 → 0 = engine 10 s default), ips=nil per doc.go v1.3
  note; gates green (gofmt/test/vet/-race/build + full suite). T2b
  discovery adapter DONE (this session): internal/pipeline/adapt/
  discovery.go + discovery_test.go (13 tests: name, happy path w/ clock
  bridge + counts, out-of-domain output filtered via FilterHosts, sources
  param parsing table (absent/empty/comma-only/selection/whitespace/
  unknown-params), truncation flag → Truncated+StickyFlags["truncated"]
  (engine's documented Truncated marker), partial-without-truncation,
  engine error → failed + wrapped "stage %s: %w", per-source failure fold
  → partial, skipped (tool MISSING) → incomplete (no pipeline "skipped"
  value; documented), pre-cancelled + in-flight cancellation →
  cancelled+ctx err, cache pass-through (puts counted; assetfinder never
  cached), full pipeline.Run integration); config-from-StageInput only,
  clock bridge Now=in.Clock.Now, bounds pass-through per engine semantics;
  test identifiers discovery* prefixed; gates green (gofmt/test/vet/
  -race/build + full suite). T2b dns adapter in progress by its builder
  (file present in internal/pipeline/adapt/ — a transient helper-name
  collision between the three concurrent test files was resolved) · T2b
  REVIEW-FIX ROUND 1 (this session): applied the T2b CHANGES-REQUIRED
  findings across all three adapters (dns/httpprobe/discovery) — MEDIUM-1
  outcome-mapping unification: per-host fold is now cancelled > failed&&
  !completed > completed > partial in both dns.go and httpprobe.go
  (engine-incomplete folds into partial; adapters never emit incomplete;
  dns truncation test + httpprobe fold-corner test updated/pinned),
  LOW-1 httpprobe empty-filtered short-circuit gated on targetCanonical
  (non-canonical target falls through to the engine's scope error; mirror
  subtest added), LOW-2 discovery error-path additions preserved
  (discoveryAdditions helper on success + both error branches; ~17 s
  forced-pool-shutdown regression test added), LOW-3 sticky flag renamed
  "truncated" → "discovery_truncated" (literal pinned in test; naming
  convention documented in adapt/doc.go), INFO-1 discovery cancellation
  now joins ctx.Err()+engine error (isContextError traverses the join;
  mirrors httpprobe), INFO-2 unified mapping table + fold precedence
pinned in adapt/doc.go; gates green (gofmt/test/vet/-race/build +
   full suite) · T2b RE-REVIEW (master): APPROVE WITH NITS — all six
   CHANGES-REQUIRED findings verified fixed (mapping table matches code,
   incomplete reserved to discovery OutSkipped, fold reorder equivalent
   across inputs w/ corner pinned, 17 s drain test justified); INFO
   (testing.Short() gate on the 17 s test) applied by orchestrator;
   full + race suites green after gate (17.1 s / 18.1 s) · T2c
   adapters batch 2: urlintel + techintel + jsintel (SECRENTEL DEFERRED
   to T3 — the corpus carries no document content, its engine consumes
   DocumentSource; a no-op stage would violate the no-placeholder rule;
   rationale in adapt/doc.go) · T2d adapters
   batch 3 (priority/detect/report) · T3a stage events DONE (this
   session: kind+payload+validate, ScanConfig.Observer seam, synchronous
   in-order started/finished on every path incl. pre-cancelled, panic-
   contained emission, 7 pipeline tests + event table rows, gates green;
   see the T3a record below — committed ad791c3) · T3b results channel
   DONE (this session: 16-channel Results struct, StageInput/StageResult/
   RunReport plumbing, first-seen identity-keyed per-channel dedup,
   MaxOutput per-channel caps + <channel>_truncated sticky flags, 20
   tests; see the T3b record below) · T3c secrentel
   adapter · T3d adapter results production/consumption · T4 determinism
   (discovery clock seam) · T5 hermetic E2E · T6 CLI+docs.
- SESSION-LOSS AUDIT (2026-08-19, NEW OS — previous machine wiped; all prior
  local gate evidence gone; re-verified fresh with Go 1.26.6):
  - Repo state = origin/main @ ec4b7e7 "T2C midwork" (working tree clean).
    That ONE snapshot commit bundles ALL of internal/pipeline (T1 skeleton +
    T2a corpus + T2b adapters + T2c adapters) AND the previously-uncommitted
    docs-compaction wave (AGENTS.md diet, TODO.md compaction, ROADMAP.md
    v0.x collapse) — a mixed snapshot, not a conventional commit.
  - T2c was SAVED MID-EDIT. Present: urlintel.go + urlintel_test.go (668
    lines, 19 tests), jsintel.go + jsintel_test.go (43 tests), techintel.go
    (346 lines, complete). Gaps: (1) urlintel_test.go:222 one-char syntax
    typo — `error}{` must be `error) {` — the adapt package does NOT
    compile (gofmt/vet/test all fail on it; cascade errors at 223-226, 427);
    (2) techintel_test.go MISSING — the techintel adapter has ZERO test
    coverage; (3) techintel.go not gofmt-clean (comment-block indent at
    lines 140-144 + missing trailing newline); (4) no T2c review round was
    recorded. TODO board was not updated for T2c (still said "T2 next").
  - FRESH GATE RUN (this machine, workspace as-committed): go build ./...
    OK; gofmt/vet/test fail ONLY on the urlintel_test.go typo. On a /tmp
    copy with the typo fixed + gofmt -w: gofmt clean, vet clean, FULL
    suite passes (all 22 packages), go test -race ./internal/pipeline/...
    passes (adapt 18.3s incl. the 17s drain test). Test inventory on the
    copy: discovery 24 / dns 16 / httpprobe 17 / urlintel 19 / jsintel 43
    (= 119 tests; techintel 0). T1/T2a/T2b code + all T2c adapter code is
    therefore SOUND — only the three gaps above block green.
  - ROADMAP.md v1.3 is stale: "Status: planned", zero ticks, despite
    T1/T2a/T2b/T2c code landed. Also the v1.8 milestone + §5 Phase
    Ownership Policy (added in the docs wave) are now committed (they were
    previously deliberately uncommitted — flag if that was unintended).
  - NEXT ACTIONS: builder fixes the typo (one char), writes
    techintel_test.go (mirror the discovery/urlintel test shape; adapter
    documents its contract exhaustively — unit tests must cover the fold
    table, truncation flags, malformed-vs-failed counting, cancellation
    joins, non-canonical target fall-through, empty short-circuit), gofmt
    -w techintel.go; tester runs gates; reviewer round for T2c; then T2d.
  - T2c IMPLEMENTED (this session, master override — builder agent
    unavailable again, 2 failed dispatches; precedent: T2a): typo fixed
    (urlintel_test.go:222 `error}{`→`error) {`), techintel.go gofmt-clean,
    internal/pipeline/adapt/techintel_test.go added (15 tests: Name, happy
    path w/ cache-before-execute proof, production-DB default, out-of-
    domain input filter, empty short-circuit, non-canonical target fall-
    through, malformed observation → failed + ItemsFailed + diagnostic
    surfaced, engine config error → failed, cache-diagnostic surfaced,
    pre-cancelled → cancelled + res.Err=ctx err (Go error nil — adapter
    convention), engine error + fired ctx → cancelled + errors.Join,
    nil cache, truncation/overflow mapping table w/ literal flag pin,
    foldTechOutcome table (9 rows), counters table (6 rows)). Gates run on
    this machine: gofmt clean, build OK, vet OK, full suite OK, -race
    ./internal/pipeline/... OK (18.3s). T2c REVIEW (this session):
    reviewer APPROVE WITH NITS (2 LOW + 3 INFO + 1 accepted INFO). ALL
    closed: LOW-1 doc clarification added (techintel.go Run malformed
    paragraph — stage-level failed via the error path vs fold-level
    never-folded, both pinned); LOW-2 nil-ctx guard added mirroring
    urlintel.go:203 (Run returns failed + "stage techintel: context must
    not be nil") + regression TestTechIntelStageNilContext; INFO-3/4
    test-comment fixes; INFO-5 status line updated; INFO-6 warm cache-hit
    path accepted as engine-tested, not hermetically forceable through
    the stage. Gates re-run after nits: gofmt clean, build OK, vet OK,
    full suite OK, -race ./internal/pipeline/... OK (18.3s). T2c
    VERIFIED — next: T2d adapters batch 3 (priority/detect/report).
  - T2d IMPLEMENTED (this session, master override — builder agent
    unavailable a 3rd time, 2 more failed dispatches): internal/pipeline/
    adapt/priority.go + detect.go + report.go + priority_test.go +
    detect_test.go + report_test.go + doc.go T2d conventions section.
    Verified engine facts driving the design: priority/detect/report
    engines ALL fold internally into the house outcome vocabulary
    (completed/incomplete/failed/cancelled) → adapters map their aggregate
    outcome directly (incomplete → partial; unknown value → failed, never
    masked); priority rejects a nil signal channel (fully-buffered
    synchronous channel, no feeder goroutine) and digests BOTH catalogs
    (single provided seam catalog → explicit empty counterpart);
    detect's empty-registry run is vacuous completed (D2) and rules without
    RequiredAssetTypes genuinely execute on an empty corpus → empty-input
    short-circuit fires ONLY when corpus AND registry are both empty;
    report's engine DEFAULTS zero Concurrency/QueueSize/Timeout (its
    config-error routes are empty OutputDir and negative Timeout) and has
    no Rate/Burst (documented); report render-cache does exactly 1 Get + 1
    Put per reporter (pinned 4/4). Truncation: detect FindingsTruncated →
    Truncated + StickyFlags["detect_findings_truncated"]; priority and
    report have NO truncation signals — absence pinned in doc.go.
    Counters: processed = completed+failed+cancelled (skipped rules/
    reports EXCLUDED — never attempted), failed = failed. Tests: priority
    14 (name, happy path w/ cache-before-execute 4 Gets+4 Puts + no
    additions, empty short-circuit w/ 0 cache interaction, non-canonical
    fall-through, out-of-domain filter, engine config error via zero
    bounds, pre-cancelled, engine error + fired ctx joined, nil-ctx,
    nil-cache, production-catalogs nil/nil seam, single-catalog seam,
    fold table 5 rows, counters), detect 16 (name, empty-registry
    short-circuit, D2 default happy path w/ zero counters, rule happy path
    w/ cache-before-execute 1/1, empty-corpus-with-rules NO-short-circuit
    (unconstrained rule executes, required-kind rule skips), out-of-domain
    filter via asset-capture rule, non-canonical fall-through executes
    rules, engine config error, pre-cancelled, engine error + fired ctx
    joined, nil-ctx, nil-cache, fold table 5 rows, counters +
    truncation-flag mapping ×2), report 13 (name, default-registry happy
    path w/ 4 rendered+committed files + 4 Gets/Puts + no additions,
    empty-corpus still renders, context composition via capture reporter
    (target/bracket/filtered corpus), empty OutputDir → failed, negative
    Timeout → failed, pre-cancelled, engine error + fired ctx joined,
    nil-ctx, nil-cache, synthetic single-reporter registry + 1 committed
    file, fold table 5 rows, counters w/ skipped excluded). Gates run on
    this machine: gofmt clean, vet OK, build OK, full suite OK (24
    packages), -race ./internal/pipeline/... OK (18.3s). T2d REVIEW
    (this session): CHANGES-REQUIRED — MEDIUM-1 gofmt gate violation
    (detect_test.go was edited after the gate; the "gofmt clean" board
    claim was false — corrected: gofmt -w re-run + all four gates re-run
    AFTER the fix, claim amended to the final state), LOW-1 test-count
    corrections (priority 14, detect 16), INFO-1 Rate-wording fixed in
    priority.go/detect.go docs (negative Rate is the engine's config-
    validation error, not "pacing disabled"), INFO-2 recorded as NEW-14
    (deferred), INFO-3 accepted (run bracket documented). All findings
    closed. GATES RE-RUN after the fixes (final state): gofmt clean
    (repo-wide, `gofmt -l` empty), vet OK, build OK, full suite OK (24
    packages), -race ./internal/pipeline/... OK (18.3s). Re-review
    dispatched to reviewer for closure confirmation.
- T6 CLI+docs IMPLEMENTED (this session, builder; claimed IN PROGRESS at
  session start, never self-closed): the `ravenrecon scan` command and its
  hermetic test suite. The command (internal/cli/scan.go + cli.go wiring,
  inherited mid-flight from the prior session and verified line-by-line
  against the T6 contract) parses `scan <target> [options]` with --stages
  (fixed vocabulary), --sources, --request-timeout, --concurrency,
  --timeout, --cache, --no-cache, --output (default ravenrecon-report),
  --verbose (one line per stage event on stderr via a synchronous
  stageObserver on the T3a event layer); maps flags onto
  pipeline.ScanConfig (StageParams for sources/request_timeout, StageBounds
  for every SELECTED stage); normalizes the target through asset.NewDomain
  (single normalization point — uppercase/whitespace/trailing dot
  normalized, IP literals rejected via normalizeHost); opens the cache
  mirroring discover's semantics; runs the ten production adapters via the
  newScanStages seam (all nil production defaults incl. the EMPTY detect
  registry per D2); prints a deterministic summary (no timestamps/durations
  — the T4 determinism property) with the report files listed honestly from
  the output directory; maps outcomes to exit codes (completed/partial →
  0; failed/cancelled/incomplete + validation/cache errors + Ctrl-C → 1,
  summary always printed first). NEW TESTS (internal/cli/scan_test.go, 19
  test functions, all hermetic — fake stages seam, temp dirs, no tools):
  parseScanArgs table (24 rows incl. help forms, empty/unknown stages,
  vocabulary naming, empty sources, invalid/empty/negative durations,
  concurrency < 1, stray args, default output dir, raw target preserved for
  normalization), buildScanConfig defaults + selections (selection order,
  params, bounds only for selected stages), scanCache wiring (default off,
  config-enabled, --cache override, --no-cache force-off), stageObserver
  unit (started/finished lines, truncation/error suffixes, unknown kinds
  ignored, kind-mismatched + nil payloads contained), printScanSummary
  (header/cache state, sorted flags, stage lines with flags+quoted errors,
  sorted report file listing, no-files and unreadable-dir honest notes),
  reportFiles (sorted non-dir entries, missing-dir error),
  TestScanStageVocabularyMatchesPipeline (stageVocabularyCLI pinned to
  pipeline.AllStages — the scan.go comment requires it), runScan outcome
  mapping (all five outcomes → documented exit semantics, summary always
  states the honest outcome), failed-still-summarized, validation errors
  never invoke the stages seam (incl. IP-target rejection via
  normalizeHost), target normalization through the seam (canonical Name +
  raw Original + default OutputDir), cache on/off rendering through the
  real runScan path, pre-cancelled ctx → prompt context.Canceled-wrapped
  "run interrupted" error with the cancelled summary still printed (stages
  never invoked), scan help via runScan and via the Run dispatcher. DOCS
  (T6 "docs" half): README.md Status header v1.0.0 → v1.3.0 (version.go is
  already bumped in this tree) + scan command section under "Current
  commands" + intro paragraph naming the pipeline/scan; ARCHITECTURE.md
  implemented-list bullet for the scan command (wiring, exit semantics,
  normalization, seams) + planned-item reworded ("standalone reporting CLI
  front-end" — report rendering is reachable through scan's embedded report
  stage); ROADMAP.md v1.3 checklist ticked `ravenrecon scan` (per-item tick
  precedent, evidence on the board). GATES RUN THIS SESSION, verbatim:
  gofmt -l $(find . -name '*.go' -type f) → clean (empty); go test
  -count=1 ./internal/cli/ → ok; go vet ./... → ok; go build ./... → ok;
  go test -count=1 ./... → ok (25 packages; discovery 75.6s, adapt 17.4s);
  go test -race -count=1 ./internal/cli/ → ok (1.5s). One test-only fix
  round during development: zero-value StageResult{} is a contract
  violation (empty outcome → recorded failed), so the partial-outcome row
  needed an explicit completed first result; the normalization assertion
  checked the canonical form uppercased (self-defeating — "example.com" IS
  "EXAMPLE.COM" uppercased) and now checks the raw " EXAMPLE.COM. " form
  never appears. No production code changed this session. No new issues
  opened. Remaining for T6: reviewer round, orchestrator verification, and
  the commit decision (working tree currently uncommitted).
- T6 locked-item follow-up (this session, builder): the working tree at session
  start did NOT compile — internal/cli/scan_test.go carried eight unused imports
  (fmt, io, net, net/http, sync, discovery, dns, adapt) and the head-comment-
  referenced smoke E2E (TestRunScanSmokeE2E) did not exist. Step 0 + Item 1:
  implemented TestRunScanSmokeE2E (hermetic — drives runScan with the
  PRODUCTION stage shape via the stages seam; only the exec- and network-
  capable seams substituted: scripted discovery/urlintel runner + fake
  LookupFunc + fake resolver (one A record for www.example.com) + canned
  http.RoundTripper (200 on http and https, also served to jsintel — NEW-16);
  non-exec stages at their production nil defaults incl. the empty detect
  registry + the four builtin report reporters); the previously-unused imports
  are consumed by it. Asserts: outcome line (completed), all ten completed
  stage lines, ravenrecon-report.json/.md existing AND listed in the summary,
  hermeticity (canned transport serves >= 4 round trips: 2 httpprobe + 2
  jsintel), and a second run into a fresh temp dir matching modulo the
  output-dir path. Item 2: ROADMAP.md v1.3 completed (six pipeline-integration
  bullets ticked, Status: planned → Status: ✅ Complete, completion note citing
  T3a ad791c3, T3b f31cf3a, T3c 9da5793, T3d 9abe2d3, T4 df3672d, T5 91074ff,
  T6 uncommitted at writing; acceptance state: all met). Gates final state:
  gofmt clean, go vet OK, go build OK, go test ./internal/cli/ OK, go test
  -race ./internal/cli/ OK, full per-package suite OK. No production code
  changed. No staged commit. New issue opened: NEW-16 (below).
- T6 REVIEW FIX ROUND (this session, builder): applied the reviewer's T6
  findings exactly, everything left uncommitted — FIND-1 (LOW, code+tests):
  negative `--request-timeout` rejected with "must be >= 0" instead of being
  silently absorbed to the engine default (0 and absent stay valid = engine
  default, matching requestTimeoutFromParams); parse-table rows pin `-5s`
  rejection and `0` acceptance (internal/cli/scan.go parseScanArgs +
  scan_test.go). FIND-2 (INFO, tests): unknown-source pass-through pinned as
  a REAL passthrough — `scan example.com --sources nmap` runs the production
  discovery adapter/engine over the smoke fixtures; the seam capture asserts
  StageParams[discover]["sources"] == "nmap", the discover stage records
  failed (`unknown source "nmap"` named), and two rows pin the run-level
  semantics: the full ten-stage run fail-CONTINUES (remaining stages
  complete → fold rule 5 → Outcome partial, exit 0) and the
  `--stages discover` run ends Outcome failed with the named "run outcome
  failed" error — the review finding's expected "run outcome failed" applies
  to the stage-restricted form; the full run honestly folds partial
  (TestRunScanUnknownSourcePassThrough in internal/cli/scan_test.go).
  FIND-3: ROADMAP.md v1.3 acceptance bullets
  ticked (single-run discovery→report; cross-stage asset/evidence identity —
  both met by the smoke E2E + T3d/T4/T5 pins); the "all met" completion note
  now matches the checklist. FIND-4: NEW-16 fix text reworded — techintel has
  no HTTP fetch surface at all (reviewer-verified), now "httpprobe, jsintel
  (and any future body-fetching stage)". FIND-5: scan_test.go comment now
  cites the actual rule — report.Run (engine.go:251-258) + sanitizeBaseName
  (writer.go:26-68); the cited ReportBaseName never existed. FIND-6: AGENTS.md
  §2 — internal/pipeline + internal/pipeline/adapt bullet added; the footnote
  now states the pipeline IS reachable via `ravenrecon scan` while those
  engines still have no standalone commands and the TUI is still unwired.
  FIND-7: NEW-17 opened (INFO, no owner — evidence + proposal only, below).
  FIND-8: status tail appended above — this entry NOT self-closed
  (orchestrator verifies). GATES RE-RUN THIS ROUND, verbatim: gofmt -l
  $(find . -name '*.go' -type f) → clean (empty); go test -count=1
  ./internal/cli/... → ok (0.534s); go vet ./internal/cli/ ./internal/report/
  → ok; go build ./... → ok; go test -race -count=1 ./internal/cli/ → ok
  (1.618s); go test -count=1 ./... → ok (25 packages; discovery 75.6s,
  adapt 17.5s).
- Verification: per-task gates (gofmt/test/vet/-race/build); final wave:
  full-suite gates + reviewer sign-off + TODO close.
- T3a IMPLEMENTED (this session, builder): pipeline stage events on the
  existing v1.2 event layer, exactly per orchestrator contract — no
  deviations. internal/event: KindStageStarted ("stage_started") +
  KindStageFinished ("stage_finished") after KindScanStopped in kind.go
  (+ Kind.Valid), StageStarted{Name}/StageFinished{Name,Outcome,Truncated,
  ItemsProcessed,ItemsFailed,Duration,Err} payloads + bounded
  NewStageFinished constructor (Err via the package's truncateMessage at
  the construction site), validatePayload cases (exact type, non-empty
  Name, Outcome in the fixed AGENTS §0.6 vocabulary as literal strings via
  unexported stageOutcomeValid — no internal/pipeline import, negative
  counts/duration and over-bound Err rejected mirroring TaskTerminal.
  Message). internal/pipeline: ScanConfig.Observer event.Observer field
  (nil = off, zero behavior change, matching internal/event/observer.go's
  documented convention; package-doc milestone line updated: stage
  eventing real, report rendering still separate); Run emits exactly one
  started + one finished per stage entry on ALL paths (pre-cancelled
  entries recorded cancelled, unresolvable entries recorded failed,
  normal path), synchronous, in stage order, before Run returns — no
  goroutines, no buffering; At = injected clock Now, Identity = stage
  name, Phase = "stage", Severity default, Sequence 0 (Bus assigns on
  publish — documented in the Run doc comment); finished mirrors the
  recorded StageRecord field for field (Err = recorded error text, empty
  when nil, bounded); observer.Observe wrapped in deferred-recover
  containment (copy of the runtime pool's observer-path containment — a
  hostile panicking observer can never crash the run). No changes to
  engines, Stage/StageResult/StageInput shapes, caching, or the runtime
  pool. Tests: event table rows (nil payload ×2, wrong-type via mismatch
  list, empty Name ×2, invalid/empty Outcome, negative processed/failed,
  negative Duration, over-bound Err, constructor bounding + validation)
  and internal/pipeline/run_events_test.go (7 tests: order+payload
  equality+field pins, pre-cancelled, per-stage timeout, panicking
  observer contained with later events flowing, nil observer = identical
  report, >512-byte Err truncated with marker + post-truncation Validate,
  unresolvable entry). Gates run this session, verbatim: gofmt -l clean
  (repo-wide), go test -count=1 ./internal/event/... ./internal/pipeline/...
  ok, go vet ./... ok, go build ./... ok, go test -race -count=1
  ./internal/event/... ./internal/pipeline/... ok, full suite
  go test -count=1 ./... ok (25 packages). Existing pipeline tests pass
  unmodified (nil-observer zero change). No new issues opened. Reviewer
  round pending; orchestrator moves to VERIFIED. T3b (results channel)
  observations below — none implemented.
- T3a REVIEW-FIX ROUND applied (this session, builder), per the T3a
  review findings — FIND-1 through FIND-7, nothing else:
  - FIND-1 (MEDIUM): negative ItemsProcessed/ItemsFailed were copied
    verbatim by normalizeResult (internal/pipeline/run.go:457-458
    pre-fix), which could produce a StageRecord whose mirrored
    stage_finished event fails event.ValidatePayload (negative counts
    are rejected there by design). FIX: normalizeResult now treats
    negative counters as a stage contract violation — recorded failed
    with a structured error (matching the existing violation shape for
    invalid outcomes), and counters are clamped to >= 0 on EVERY outcome
    path so a record and its emitted event always validate. Semantics
    documented in the normalizeResult doc comment (run.go), the
    StageRecord counter fields (run.go), and the StageResult counter
    fields (stage.go). Regression test: run_events_test.go
    TestRunStageEventsNegativeCounters (violation path + error-return
    clamp path), asserting the emitted finished event validates and the
    recorded/report counters are clamped.
  - FIND-2 (MEDIUM): stale Tier C docs fixed — ARCHITECTURE.md:3012
    "27 values" -> 29 values with stage lifecycle named; 3060
    Instrumentation contract and 3125 Known limitations now list the
    pipeline runner as instrumented; v0.3 boundary implemented list
    gained a "pipeline stage eventing" entry; README.md instrumented
    list + "27 typed Kind values" -> 29; internal/event/doc.go Role and
    Instrumentation-contract lists now include internal/pipeline.
  - FIND-3 (LOW): TODO.md test count corrected 8 -> 7 (the parenthetical
    already listed 7).
  - FIND-4 (LOW): run.go observeStageEvent doc comment no longer cites
    the runtime pool as the containment source (runtime/observer.go is a
    bare nil-check call with no recovery); it now describes the honest
    shape: recover in the same goroutine as the Observe call, matching
    event.deriveSafe and the pipeline's runStage recovery.
  - FIND-5 (LOW): event_test.go gained TestValidateAcceptsEveryStageOutcome
    (all five outcomes validate); run_events_test.go gained
    TestStageFinishedVocabulariesDriftPin mapping every pipeline.Outcome
    constant through the event payload.
  - FIND-6 (INFO): config.go ScanConfig group doc now states Observer —
    unlike Cache and Clock — is operative in config (nil = off).
  - FIND-7 (INFO): run_events_test.go gained
    TestRunStageEventsCrossRunDeterminism (same cfg/clock/stages run
    twice, recorded event streams DeepEqual).
  Status: still IN PROGRESS — fixes applied, gates re-run below;
  orchestrator verifies and closes (never self-closed).
- T3b IMPLEMENTED (this session, builder): pipeline results channel,
  exactly per orchestrator contract — no deviations. New
  internal/pipeline/results.go: the 16-channel Results struct (asset.IP/
  Port/Service/Endpoint/JavaScript/Parameter/Technology/SecretCandidate/
  Evidence/Finding/TLSCertificate/SourceMap/Relationship + priority.
  SurfaceAsset/Group/AttackPath — one channel per report.Context data
  channel; imports asset+priority only, types only), field doc comments
  name the T3d adapters as the producers (none wired yet), plus
  mergeResults/mergeChannel (the runner-side merge). StageResult.Results
  (additions semantics + AGENTS §0.6 truncation rule doc), StageInput.
  Results (read-only merged PRIOR state, identical contract to the corpus
  slices), RunReport.Results (final merged state, doc mirroring the
  corpus fields). Run merges each stage's Results after its StageRecord
  is finalized — the same place as the corpus merge — unconditionally
  (a failed/partial stage's retained results still merge, mirroring
  Additions; documented in run.go), first-seen dedup keyed by canonical
  identity PER CHANNEL (asset Identity() "kind:value" string; Relationship.
  ID() — the type has no Identity() method, ID() is its documented
  canonical identity (asset/relationship.go:118); priority SurfaceAsset.
  Identity / Group.Anchor / AttackPath.Root fields), keys namespaced per
  channel in the shared seen map so identical identities carried by
  different channels never collide (pinned by test), deterministic
  first-seen order, then the per-channel MaxOutput cap (eff.MaxOutput
  per stage; smaller later caps re-cut, cut entries stay first-seen and
  cannot re-enter — corpus-mirrored), returning the fixed-order list of
  cut channel names → report.StickyFlags["<channel>_truncated"] +
  report.Truncated (AGENTS §0.6 carve-out, mirroring corpus_capped; the
  stage's own outcome untouched). Flag vocabulary: ips, ports, services,
  endpoints, javascript, parameters, technologies, secrets, evidence,
  findings, tls_certificates, source_maps, relationships, surfaces,
  groups, attack_paths. No event emission changes (T3a's emit point
  stays), no normalizeResult changes (Results are not counters), no
  engine/asset/priority/event changes, no Results JSON/caching story.
  Tests: internal/pipeline/results_test.go (18 tests — first-seen dedup
  across stages incl. reverse-edge relationship distinctness, kind-
  namespace no-collision, per-channel dedup namespacing, nil/empty
  additions legal, single+multi-channel caps with flag vocabulary +
  outcome-untouched carve-out, fixed capped-name order, negative-cap
  defensive branch, visibility-at-stage-turn (prior merged state only,
  own additions excluded), RunReport.Results final merged, failed-stage
  results still merged, pre-cancelled empty/no-flags, cross-run
  determinism incl. Results+StickyFlags, cap permanence + smaller-later-
  cap re-cut, defensive copy (no aliasing), corpus+results caps combined,
  all-16-channels unit merge, no-flag-without-cut, stage-not-run-no-
  merge). One leftover fixed in the inherited working tree: the
  mergeChannel unit call in results_test.go was missing the namespace
  argument (build failure). Gates run this session, verbatim: gofmt -l
  clean (repo-wide), go test -count=1 ./internal/pipeline/... ok, go vet
  ./... ok, go build ./... ok, go test -race -count=1
  ./internal/pipeline/... ok, full suite go test -count=1 ./... ok (26
  packages — 20 top-level test functions in results_test.go after the
  nit round). Existing pipeline tests pass unmodified (nil-observer zero
  change). New issue opened: NEW-15 (INFO, T3c document-content gap).
  REVIEW: APPROVE WITH NITS — FIND-1 (LOW) full 16-name flag vocabulary
  pinned by TestMergeResultsFullVocabularyPinned (unit capped-name list
  DeepEqual + runner-level all-16 StickyFlags; typo-failure demonstrated,
  reverted); FIND-4 (INFO) NEW-15 pointers added to adapt/doc.go +
  ARCHITECTURE.md (secrentel document-carrier reads as undecided, not
  settled); FIND-7 (INFO) results.go empty-additions doc reworded (cap
  may re-slice). All 3 closed, closure verified (reviewer), gates re-run.
  FIND-2 carried to T3d: Groups/AttackPaths dedup keys (Anchor/Root) are
  GROUPING keys, not full identities — two distinct groups anchored
  identically collapse silently to first-seen; today's only producer
  (single priority stage, engine-guaranteed unique anchors) cannot hit
  it, but T3d must document "first-seen group per anchor wins" on
  Results.Groups/AttackPaths or widen the key (anchor + members +
  score). FIND-5/FIND-6 accepted as documented semantics (outer-slice
  defensive copy only, same as corpus; per-run seen map grows with total
  distinct identities, same as corpus). Orchestrator moved T3b to
  VERIFIED.
- T3b OBSERVATIONS (no implementation): (1) the stage_started/finished
  events are emitted from the stage LOOP, which is also where T3b's
  per-stage results aggregation will live (run.go:154-235) — the finished
  payload's counters come straight from the finalized StageRecord, so
  whatever T3b adds to StageRecord (e.g. a Results field) will need an
  explicit decision on whether/how it surfaces in stage_finished or stays
  report-only; the current event carries no results, and the contract's
  out-of-scope list treats RunReport.Results as future. (2) The Observer
  seam is config-carried (ScanConfig.Observer), synchronous and inline —
  a results channel would be a NEW seam (config field + delivery), not a
  variant of this one; nothing here constrains that design. (3) Emission
  happens before the corpus merge (finished is emitted right after the
  StageRecord is appended), so if T3b results are derived from the merged
  corpus the emit point may need to move after the merge — flagged now so
  the orchestrator can decide placement deliberately. (4) The stage_finished
   Err field is bounded to 512 bytes and validated; any future results
   payloads added to events must respect the same per-payload bounds in
   validatePayload (hand-built hostile events re-validated by consumers).
- T3b RESOLUTION of the above (this session): (1) StageResult.Results and
  RunReport.Results landed; stage_finished events deliberately carry NO
  results — the contract's out-of-scope list forbids event emission
  changes, and the finished payload stays a mirror of the StageRecord.
  (2) No new delivery seam was needed: the results channel is
  runner-internal struct plumbing (StageInput/StageResult/RunReport), not
  an observer-style channel. (3) The results merge runs AFTER
  emitStageFinished and BEFORE the next stage — placement documented in
  run.go; the finished event therefore never reflects the merged results
  (by design, per (1)). (4) No results payloads were added to events.
- T3c IMPLEMENTED (this session, builder): pipeline-internal document
  channel + secrentel adapter, exactly per orchestrator contract — no
  deviations. New internal/pipeline/document.go: `MaxDocumentBytes` =
  2 << 20 (2 MiB, mirroring the secrentel engine's ingest cap) and the
  `Document{Identity, URL, Content, Truncated}` type (content bounded,
  merged by reference, never copied; never reaches the report Context),
  plus `mergeDocuments` — the runner-side document merge reusing
  mergeChannel with the "documents" namespace and the canonical identity
  string as the dedup key, per-stage MaxOutput cap with the
  "documents" cut-name, and a defensive hostile-producer re-bound BEFORE
  dedup: over-cap content is dropped WHOLE (Content nil + Truncated),
  never a partial prefix, the caller's slice never mutated (a fresh
  normalized copy is built only when a document needs the cut), and the
  document still merges (identity/URL remain). StageResult.Documents
  (additions semantics, mirroring Results), StageInput.Documents (read-only
  merged PRIOR state, identical contract to the corpus/results slices),
  RunReport.Documents (final merged state). Run merges each stage's
  Documents in the same block as the results merge, unconditionally
  (failed-stage documents still merge), and records the
  `documents_truncated` sticky flag + report.Truncated on a cut (AGENTS
  §0.6 carve-out; stage outcome untouched). New
  internal/pipeline/adapt/secrentel.go: `NewSecretIntelStage(db
  *patterns.DB)` (constructor test seam; nil = patterns.Load), consuming
  the document channel as its document source — every pipeline document
  becomes one secrentel.Document (KindJS, Content/URL passed through,
  SourceAsset = the pipeline document's canonical Identity — the engine's
  jsintel dedup contract — Source "" = the engine default "secrentel"),
  truncated/nil-content documents SKIPPED (nothing honest to scan; not
  counted), no scope filtering (the channel is the pipeline's own,
  in-scope by construction), per-document analysis caps at engine defaults
  (64 candidates / 8 evidence — deliberately not configurable), the
  engine's Overflow signal (≥ 64 candidates) mapped to Truncated +
  StickyFlags["secrentel_overflow"] and the engine's Truncated signal to
  StickyFlags["secrentel_truncated"] (unreachable through this adapter —
  bounded pipeline content + truncated documents skipped — but never
  swallowed), counters mirroring techintel exactly (ItemsProcessed =
  Completed+Incomplete+Cancelled+Failed; ItemsFailed = Failed+Malformed),
  outcome fold in the unified adapter precedence (cancelled > failed&&
  !completed > incomplete&&!completed > completed-vacuous > completed-
  mixed > unknown→failed), engine errors wrapped "stage %s: %w" with the
  errors.Join cancellation path, empty-input short-circuit gated on
  targetCanonical (non-canonical falls through to the engine with an
  empty source), nil-ctx guard first, no event emission (the runner owns
  stage events; Config.Emit deliberately ignored), queue never executed
  and never propagated (T6). §0.6 chain verification performed for the
  completed+flag carve-out: engine record write (engine.go:376 +
  record.go:89-90; truncated → StatusIncomplete record.go:130-132),
  replay (record.go:359-360; truncated records never served —
  record.go:172, 198-202 — so only Overflow replays from hits), sticky
  merge (report.go:243-244), report exposure (report.go:377-378) — chain
  INTACT. Tests: internal/pipeline/document_test.go (merge unit tests —
  first-seen dedup, cap tail-drop + ["documents"] cut-name, cut
  permanence across larger later caps, smaller-later-cap re-cut,
  over-cap content dropped whole with input never mutated, in-bound
  content merged by reference, nil/empty/truncated-document edges — plus
  run-level: propagation + visibility at stage turn, cap + flag +
  outcome-untouched carve-out, failed-stage documents still merged,
  pre-cancelled empty/no-flags, cross-run determinism incl. Documents,
  no aliasing) and internal/pipeline/adapt/secrentel_test.go (13 tests:
  name, happy path with counters + source-asset identity + evidence, skip
  truncated/nil-content, empty short-circuit with zero cache reads,
  non-canonical fall-through, nil-ctx, engine config error → failed,
  pre-cancelled → cancelled + ctx err, engine error + fired ctx →
  errors.Join cancelled, overflow flags with exactly the capped 64
  candidates, overflow cache-hit regression over a real FS cache
  (2nd run: zero Puts, flags replayed — never swallowed), fold table all
  rows incl. unknown→failed and malformed-only vacuous, full
  pipeline.Run integration with a jsDocProducer fake (RunReport.Documents
  + Results.Secrets + cross-run determinism)). Docs: adapt/doc.go gained
  the T3c conventions section (document channel semantics, secrentel
  mapping, flag vocabulary, chain reference; T3b section updated —
  secrentel is the first Results producer); ARCHITECTURE.md v0.3 boundary
  gained the "pipeline document channel + secrentel adapter" bullet and
  the results-channel bullet's planned list now names only the remaining
  T3d production (NEW-15 resolved); README.md: no changes needed
  (verified — no line becomes false). NEW-15 → RESOLVED above. Existing
  pipeline tests pass unmodified. Gates run this session, verbatim:
  gofmt -l clean (repo-wide), go test -count=1 ./internal/pipeline/... ok
  (pipeline 0.159s, adapt 17.273s), go vet ./... ok, go build ./... ok,
  go test -race -count=1 ./internal/pipeline/... (see Results below),
  full suite go test -count=1 ./... (see Results below).

- T3d1 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the jsintel engine content-retention surface +
  the jsintel adapter results/documents production, exactly per the
  orchestrator contract — no deviations. Engine (internal/jsintel):
  Config.RetainContent (default false — flag off is byte-identical to
  today's memory profile, all pre-existing jsintel tests pass unmodified)
  retains each entry's fully-retained body on JSEntry.Content (bounded by
  MaxJSBytes, set before every classify return path incl. the cache-hit
  path, whose js.fetch record restores byte-identical content); truncated
  fetches retain NOTHING (FetchResult.Content nil by contract — never a
  partial prefix); new exported RetainedContent{URL asset.URL, Content
  []byte} + Report.RetainedContent() (canonical-URL order, one per URL —
  the report's sorted one-entry-per-URL invariant — non-nil Content only,
  empty when the flag is off); mergeEntries first-seen-wins for Content
  (mirrors the JS asset rule); Accumulator memory doc updated to state the
  optional retention. Adapter (internal/pipeline/adapt/jsintel.go):
  RetainContent always enabled; StageResult.Results populated with
  AllJavaScript/AllSourceMaps/AllRelationships (copied, never rebuilt) +
  Endpoints/Secrets/Technologies/Evidence derived from the sorted entries,
  deduped by canonical identity + sorted (dedupeByIdentity); entry.URLs
  external observations NOT propagated (no Results URL channel — documented
  on jsResults); StageResult.Documents from RetainedContent 1:1, identity =
  the canonical JavaScript asset identity (asset.Identity{KindJavaScript,
  URL string} — exactly asset.JavaScript.Identity()), URL pointer, Content
  by reference, Truncated always false; outcome fold/counters/truncation
  unchanged (T2c semantics). Tests: engine — retention off/on, non-JS
  completed positive retained, truncated never retains a prefix, cache-hit
  restores byte-identical content, merge first-seen-wins; adapter — full
  7-channel results + 3-document production from a loopback synthetic run
  (incl. import-expansion fetch of the resolved shared.js), by-reference
  content pin (same backing array), truncated fetch → no document + flag,
  cache-hit run retains documents + DeepEqual results/documents, cross-run
  determinism (DeepEqual incl. Documents), never-rebuilt pin against a
  direct engine run under the adapter's exact config.
- T3d1 SECOND PASS (this session, builder — the first dispatch was
  cancelled mid-flight; the working tree was verified line-by-line against
  the contract instead of redone): every contract item above verified in
  the tree (engine classify/merge/cache-restore/truncate-nil paths,
  adapter jsResults/jsDocuments identity + by-reference + Truncated=false,
  doc.go retention section, Accumulator memory doc, TODO record). Two
  finishing changes: (1) Report.RetainedContent() now deduplicates by URL
  identity and sorts internally — mirroring the report's other merged
  accessors (AllJavaScript/AllSourceMaps/AllRelationships), which do NOT
  rely on the entries' invariants; real reports are unaffected (one sorted
  entry per URL), a hand-built report is normalized the same way; new
  engine test TestReportRetainedContentSortedDedupedNilSkipped pins it.
  (2) buildJSResult doc comment corrected: it runs on the success +
  cancelled-in-flight paths; the engine-error branches return early with a
  bare failed/cancelled StageResult (T2c behavior, unchanged — pinned by
  the pre-existing engine-error tests).
- T3d1 GATE RECORD (this session, verbatim): gofmt -l $(find . -name
  '*.go' -type f) → clean (empty). go test -count=1 ./internal/jsintel/...
  ./internal/pipeline/... → jsintel, jsintel/adapt, pipeline ok; adapt
  FAILS ONLY on the pre-existing TestHTTPProbeStageResultsChannel (other
  unit's in-flight work, below) — all 43 pre-existing jsintel adapter
  tests + 5 new T3d1 tests pass. go vet ./... → ok. go build ./... → ok.
  go test -race -count=1 ./internal/jsintel/... ./internal/pipeline/...
  → same single pre-existing httpprobe failure; no races elsewhere. Full
  suite go test -count=1 ./... → same single failure. T3d1's own scope is
  fully green; the httpprobe failure blocks the shared pipeline gates
  until the httpprobe unit reconciles it (recorded below).
- T3d1 GATE RECORD (second pass, this session, verbatim): gofmt -l
  $(find . -name '*.go' -type f) → clean. go test -count=1
  ./internal/jsintel/... ./internal/pipeline/... → jsintel ok, jsintel/
  adapt ok, pipeline ok, adapt FAILS ONLY on the same pre-existing
  TestHTTPProbeStageResultsChannel (httpprobe_test.go:331: services
  identity "443/tcp/https" vs expected "443/https" — the httpprobe engine
  at HEAD builds ports with Protocol "tcp" (observe.go:581-588, untouched
  in this tree) and the out-of-scope T3d2 adapter test expects the
  protocol-less form; internal to the httpprobe unit's own files, T3d1
  never touches them). All 43 pre-existing jsintel adapter tests + the 5
  T3d1 tests + 7 engine retention tests (6 prior + 1 added this pass:
  TestReportRetainedContentSortedDedupedNilSkipped) pass. go vet ./... →
  ok. go build ./... → ok. go test -race -count=1 ./internal/jsintel/...
  ./internal/pipeline/... → same single httpprobe failure only; no races.
  Full suite go test -count=1 ./... → same single failure. T3d1 scope
  fully green; the httpprobe failure blocks the shared pipeline gates
  until the httpprobe unit builder reconciles its engine-vs-test
  inconsistency (also recorded above under T3d1 second pass).
- T3d2 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the dns/httpprobe/urlintel/techintel adapter
  results production, exactly per the orchestrator contract — no
  deviations. VERIFICATION of the inherited working tree (line-by-line
  against the contract): dns.go already wired Results.IPs = rep.AllIPs()
  on all four return paths (error branches, ctx-firing branch, success);
  httpprobe.go buildResult already set IPs/Ports/Services/Endpoints/
  TLSCertificates/Relationships from the report accessors on every path;
  urlintel.go urlintelResults (Parameters/Endpoints/Relationships) on all
  five return paths; techintel.go buildTechResult (Technologies/Evidence/
  Relationships) on all four paths. Corpus filtering (FilterHosts/
  filterURLs), folds, counters, cache-before-execute, and truncation flags
  (dnsAnswersTruncated / probe_truncated / urlintel_parameters_truncated /
  tech_indicators_truncated) unchanged in all four — existing tests pass
  unmodified. KNOWN-ISSUE RECONCILIATION (orchestrator-verified, not open
  for debate): httpprobe_test.go asserted the non-canonical service
  identities `service:443/https` / `service:80/http`; the asset model's
  canonical Service identity = Port.String()+"/"+encodedName and the
  engine builds its probe ports with Protocol "tcp" (observe.go
  portForScheme, unchanged at HEAD), so the canonical identities ARE
  `service:443/tcp/https` / `service:80/tcp/http`. FIXED in the test
  (the only protocol-less expectations in the file — repo-wide grep
  confirmed no others); the engine and asset model untouched. SECOND
  TEST-EXPECTATION CORRECTION found while verifying: the same test
  asserted 10 relationships; the engine's AllRelationships sorts WITHOUT
  cross-host dedup (per-host assemble() dedupes within a host only; the
  cross-host collapse is the runner's first-seen per-edge mergeResults),
  so 2 hosts × (2 host->url + 2 url->endpoint + 2 port->service) = 12 —
  corrected to 12 with the reason documented in the test. NEW TESTS added
  (mirroring the T3d1 harness style; all hermetic — canned transport /
  scripted runner / synthetic fingerprint DB / fake resolver): dns —
  TestDNSStageResultsIPsDeduped (two hosts resolving to the same address
  → exactly one canonical IP, engine-merged AllIPs copied verbatim) +
  TestDNSStageResultsDeterminism (two identical runs → DeepEqual
  StageResults incl. IPs); httpprobe — TestHTTPProbeStageResultsDeterminism
  (two identical runs → DeepEqual incl. ports/services/endpoints/
  relationships; IPs/TLS empty pinned in the corrected channel test);
  urlintel — TestURLIntelStageResultsDedupedAcrossDomains (same URL from
  two queried domains → one merged entry: one endpoint, one parameter,
  4 edges) + TestURLIntelStageResultsDeterminism; techintel —
  TestTechIntelStageResultsDeduped (two observations matching the same
  fingerprint → one identity-merged technology, evidence per observation,
  host->technology edge deduped → 5 edges) + TestTechIntelStageResultsDeterminism.
  7 new tests; production mapping was already pinned by the inherited
  working-tree tests (dns happy-path IPs, httpprobe channel test, urlintel
  happy-path endpoints + parameters test, techintel happy-path
  technologies/evidence/relationships). No adapter .go file changed this
  pass; no engine/asset/results.go/doc.go changes; jsintel/priority/
  detect/report/secrentel untouched.
- T3d2 GATE RECORD (this session, verbatim): gofmt -l $(find . -name
  '*.go' -type f) → clean (empty). go test -count=1 ./internal/pipeline/
  ... → ok (pipeline 0.160s, adapt 17.295s — first run failed ONLY on the
  pre-fix relationship count, corrected as above; final run clean). go vet
  ./... → ok. go build ./... → ok. go test -race -count=1
  ./internal/pipeline/... → ok (adapt 18.547s, no races). Full suite go
  test -count=1 ./... → ok (25 packages; discovery 75.6s; adapt 17.3s).
  Existing pipeline tests pass unmodified (the four adapters' pre-existing
  tests unchanged except the two corrected expectations above). No new
  issues opened.
- T3d3 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): the priority/detect/report adapter results
  production/consumption, exactly per the orchestrator contract — no
  deviations. VERIFICATION of the inherited working tree (line-by-line
  against the contract): priority.go already wired Surfaces (copied from
  completed AssetResult.Surface, never rebuilt) + Groups/AttackPaths via
  priority.Correlate/AttackPaths in buildPriorityResult on every path,
  with the priority_groups_truncated sticky flag on the correlation cut;
  detect.go already built the full 7-channel engine Snapshot (corpus
  identities + Results Relationships/Evidence/Technologies/Secrets/
  JavaScript/Endpoints, copied whole) with the D2 empty-registry
  short-circuit preserved (fires only when corpus AND snapshot-feeding
  channels AND registry are all empty); report.go already composed the
  full report.Context (corpus Domains/Hosts/URLs + all 16 Results
  channels, copied whole; the render-cache invariant untouched). One
  stale doc comment fixed in detect.go ("in a later milestone" → T3d —
  the results wiring is implemented right below it; techintel.go's
  analogous stale wording noted, out of scope). FIND-2 verified as
  documented on pipeline.Results: the Groups/AttackPaths merge keys on
  the anchor/root only (mergeChannel by Anchor.String()/Root.String()).
  §0.6 TRUNCATION DECISION (evidence + file:line): the priority engine
  caches per-surface records only and builds the Report fresh every run
  (internal/priority/engine.go), so the adapter's Correlate call in
  buildPriorityResult (internal/pipeline/adapt/priority.go) re-derives
  the group set deterministically from replayed surfaces on EVERY path —
  the cut flag can never be lost in replay, is merged stickily into the
  StageRecord, and surfaces via RunReport.Truncated (run.go:330) →
  completed-with-flag is the legal AGENTS §0.6 carve-out. NEW TESTS: the
  one integration test (t3d_integration_test.go — TestT3dEndToEndRun:
  seed stage under the discover name + the real dns/httpprobe/urlintel/
  techintel/jsintel/secrentel/priority/detect/report stages, all hermetic
  — fake resolver, canned transport, scripted gau, loopback HTTP serving
  synthetic script bodies, synthetic secret DB, hermetic detect rule
  emitting one technology-listing finding, capture reporter; asserts
  every stage completed, every Results channel populated producer-by-
  producer, the jsintel→secrentel document flow with the synthetic AWS
  key, the full report Context in the captured model, and DeepEqual
  determinism across two identical runs), plus TestResultsGroupsFirstSeen
  PerAnchorCollapse (FIND-2 pin: distinct groups with the same anchor →
  first-seen wins, later members never merge; same for AttackPaths per
  root), TestPriorityTruncationFlagSurvivesRunReport (§0.6 chain through
  the runner: 1025 distinct-anchor hosts → 1024 groups, Truncated,
  StageRecord flag, completed), TestDetectStageSnapshotResultsChannels
  (all six snapshot-feeding channels reach the rules), and
  TestReportStageContextEveryChannel (all 16 Results channels reach the
  report model). Docs: adapt/doc.go T3d section gained the
  external-URL non-propagation note and the producer/consumer
  per-channel table; ARCHITECTURE.md's two stale "planned / no producer
  yet" lines now state T3d completion; README.md verified — no line
  becomes false. No engine/asset/results.go/run.go changes; T3d1/T3d2
  files untouched.
- T3d3 GATE RECORD (this session, verbatim, all commands actually run):
  gofmt -l $(find . -name '*.go' -type f) → clean (empty output; doc.go
  table + new test file formatted). go test -count=1
  ./internal/pipeline/... → ok (pipeline 0.161s, adapt 17.306s). go vet
  ./... → ok. go build ./... → ok. go test -race -count=1
  ./internal/pipeline/... → ok (pipeline 1.188s, adapt 18.531s). Full
  suite go test -count=1 ./... → ok (24 packages). During development
  the new integration test failed three times on revealed expectations,
  each fixed in the test itself, not in engine code: the detect rule's
  finding needed Name/Category/Version aligned with the rule metadata
  plus Created via the injected clock (engine validation contract);
  the Google secret candidate value is retained at the engine's bounded
  candidate cap (assert by type, not exact value); the report engine
  validates group members and path steps (shape fixed in the fixture).
Existing pipeline tests pass unmodified — the T3d3 delta adds one new
   test file (t3d_integration_test.go), extends detect_test.go and
   report_test.go, and changes one doc line in detect.go. No new issues
   opened.
- T4 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): full-pipeline determinism + the discovery
  clock seam, exactly per the orchestrator contract — no deviations.
  AUDIT RESULT (evidence-complete, no engine/adapter code change
  warranted): per-source discovery result order is selection order at any
  pool concurrency (Results slot array pre-allocated in selection order,
  each job writes only its own slot — internal/discovery/pipeline.go:302,
  332-355; never pool-completion order — the Concurrency=1 comments in
  pipeline_test.go are about clock-advance provenance and cancellation,
  not order); per-source host lists deduped + sorted by canonical name
  (parse.go:41); Report.All() merges + sorts (pipeline.go:244-260);
  discoveryAdditions = FilterHosts(in.Target, report.All()) order-
  preserving (adapt/discovery.go:217-223; scope.go:41-49); mergeCorpus
  first-seen (corpus.go:17-32); the only time.Now in discovery are the
  nil-clock defaults (pipeline.go:98,127; detect.go:105) — the adapter
  always bridges Now = in.Clock.Now (adapt/discovery.go:157-159) and
  cache CreatedAt never reaches RunReport; the pool/rate-limiter wall
  clock (runtime/pool.go:190-192) gates job starts only, Timeout 0 →
  no timing-dependent outcomes; maps (StickyFlags, StageParams, cacheKey
  Config) never serialized into ordered structures on the RunReport path.
  PINS LANDED: internal/discovery/pipeline_determinism_test.go (3 tests:
  TestRunDeterministicAcrossRunsConcurrency — two runs at Concurrency 4
  DeepEqual the whole report, TestRunDeterministicProvenanceAcrossRuns —
  fixed-clock DiscoveredAt + earliest-wins tool-name sources,
  TestRunPerSourceHostsSorted — scrambled tool output → sorted deduped
  per-source lists, malformed never counted); internal/pipeline/adapt/
  t4_determinism_test.go (2 tests: TestT4FullRunDeterminismWithRealDiscovery
  — THREE full ten-stage runs with the REAL discovery adapter at
  Concurrency 4 DeepEqual pairwise, provenance DiscoveredAt == fixedTime
  with sources, corpus shapes (0 domains, 3 hosts, 9 URLs, 12 surfaces,
  1 group anchored domain:example.com with 12 members, 1 attack path, 1
  finding, documents carry the synthetic key, report model bracket),
  TestT4FullRunCacheHitParity — warm run over a real FS cache DeepEquals
  the cold run, discovery executions 3 → 4 (assetfinder only re-executes;
  subfinder/amass served from cache), zero new dns queries / http probes /
  jsintel requests, gau runs once per run by design). CACHE-PARITY BUG
  FOUND + FIXED (the only production change; evidence-based, root-caused
  via a temporary field-level diff): the detect engine's cache-hit replay
  decoded stored findings WITHOUT re-normalization, so a finding whose
  RelatedAssets/Relationships were empty came back nil after the JSON
  round-trip (omitempty) while a freshly executed finding carried
  empty-but-non-nil slices (asset.NewFinding's dedupe normalizers always
  returned non-nil) — DeepEqual broke between cold and warm runs. FIX:
  dedupeFindingIdentities/dedupeFindingRelationships (internal/asset/
  finding.go) now return nil for empty input, matching the JSON round-trip
  representation at the normalization point; Regression test
  TestFindingEmptySetsAreNil (internal/asset/finding_test.go) pins nil
  normalization + byte-identical round-trip + MergeFindings parity. No
  existing test changed. Docs: internal/discovery/doc.go gained a
  Determinism section (selection-order mechanism, sorted lists, clock
  seam, cache parity, pool start-gating note); internal/pipeline/adapt/
  doc.go gained the T4 section (selection order, clock bridge, cache-hit
  parity incl. the asset finding normalization fix).
- T4 GATE RECORD (this session, verbatim, all commands actually run):
  gofmt -l $(find . -name '*.go' -type f) → clean (empty output). go test
  -count=1 ./internal/pipeline/... ./internal/discovery/... → ok (adapt
  incl. the two T4 tests; discovery incl. the three new pins — the
  determinism tests take ~2 s each by design; T4 fix round (FIND-1..4
  closed in a nit round: Rate 0 + runnerBarrier overlap proof +
  maxConcurrent>1 assertions + per-run model assertions + report.go
  comment; determinism tests now ~0 s / full-run ~1.1 s, not ~2 s; gates
  re-run green — reviewer closure APPROVE)). go vet ./... → ok. go build
  ./... → ok. go test -race -count=1 ./internal/pipeline/...
  ./internal/discovery/... ./internal/asset/... ./internal/detect/... →
  ok (no races; discovery 81.7s under race). Full suite go test -count=1
  ./... → ok. The T4 parity test failed pre-fix on the finding
  representation mismatch, passed after the internal/asset fix; the
  full-run determinism test passed from the first run. No new issues
  opened.
- T5 IMPLEMENTED (this session, builder; claimed IN PROGRESS at session
  start, never self-closed): hermetic full-run E2E across success,
  partial failure, and retry — WITH the REAL discovery stage, exactly per
  the orchestrator contract and its discovery-inclusion directive. The
  inherited working tree (from a cancelled session) excluded discovery by
  contract (t3dSeedStage under the discover name, mirroring T3d3); that
  exclusion was WRONG for T5 and has been REWORKED: all three T5 tests
  now drive the REAL NewDiscoveryStage over the T4 seam (scripted fake
  discovery.Runner + fake LookupFunc — t4_determinism_test.go's shapes,
  no barrier, plain fixed-output fakes). REUSE, not new code: the T4
  helpers (t4DiscoveryScript/t4DiscoveryExecutions/t4ScanConfig/t4JSLoopback/
  t4GauExecutions/t4HostNames) drive the discovery, JS, gau, and host-name
  assertions; only the failure-injection seam (resolver), run mode (fresh
  vs cache-warm), and per-test assertions differ from T4's wiring.
  REWORKED ASSERTIONS (corpus shapes follow T4's real-discovery pins, not
  T3d3's seed pins): Domains 0 (the discovery adapter reports hosts only —
  adapt/discovery.go) instead of 1; hosts in the engine's sorted merge
  order [admin, api, www] with injected-clock tool-name provenance
  (earliest-wins) instead of seed order; Surfaces 12 (= 3 hosts + 9 URLs,
  no domain surface) and group members 12 instead of 13; report model
  corpus 0/3/9 instead of 1/3/9; captured models 2 (one per run) instead
  of 1; discovery StageRecord pinned completed with ItemsProcessed 5
  (subfinder 2 + assetfinder 2 + amass 1) + 3 executions + host
  provenance; discovery executions counted through the retry runs exactly
  like T4's cache-parity pin (cold 3 → warm 4 — only the NON-CACHEABLE
  unknown-version assetfinder re-executes, internal/discovery/pipeline.go
  :418-426; subfinder/amass served from cache; the healed-cold third run
  adds 3 more → 7 total). UNCHANGED (verified correct in the inherited
  file): the failure-injection pattern (typed per-host resolver failure
  for exactly ONE discovered host on all of A/AAAA/CNAME → dns
  StatusFailed → stage partial with ItemsFailed 1 → run partial with
  ItemsFailed 1); failure ≠ truncation asserts (no sticky flags, no
  Truncated anywhere); honest retained sets (IPs = exactly the two
  surviving hosts' addresses; every surviving host's downstream work
  present — jsintel/secrentel document flow with the synthetic key,
  techintel technologies, urlintel parameters, detect finding, priority
  12-surface group/attack-path shapes); the report model complete and
  internally consistent; 20 stage events per run with the failing stage's
  finished payload mirroring its StageRecord field for field (plus a new
  discovery finished-payload completed assert) and the second run's event
  stream DeepEqual; the healing resolver (first-call-per-(host,type)
  fails, mutex-guarded) with 9 cold / 12 warm resolver-call counts, 3
  re-attempted admin wire queries, zero re-execution of succeeded work
  (http/jsintel counts flat, gau +1 by design) and the healed warm run
  DeepEqual a fresh cold healed run; the persistent-failure resolver with
  9 → 12 query counts, admin 3 → 6, surviving hosts flat 6, warm run
  same partial + ItemsFailed 1, and the two RunReports DeepEqual.
  Docs: adapt/doc.go T5 section rewritten (discovery INCLUDED via the T4
  seam; the exclusion rationale gone; failure-injection pattern; the
  observed cache contract for failed jobs with file:line evidence; the
  discovery NON-CACHEABLE re-execute note on the retry counts; the
  real-discovery corpus shapes); ROADMAP.md ticked "Pipeline runs are
  deterministic for the same input and config." (pinned by T4's
  TestT4FullRunDeterminismWithRealDiscovery + TestT4FullRunCacheHitParity,
  t4_determinism_test.go:278/443 — cited here in the board per the
  orchestrator directive, not in the roadmap). Production code: ZERO
  changes (no engine/adapter/cache/asset code touched; the inherited
  dns_test.go seenCount fixture helper kept). The cancelled session's
  surface was verified line-by-line against the brief before rework (see
  the gate record for what passed from the first run).
- T5 GATE RECORD (this session, verbatim, all commands actually run, in
  sequence): gofmt -l $(find . -name '*.go' -type f) → clean (empty
  output). go test -count=1 ./internal/pipeline/... ./internal/discovery/
  ... → ok (pipeline 0.160s, adapt 17.5s incl. the reworked T5 tests,
  discovery 75.7s; the T5 tests pass from the second run — one fix round
  for the model-count assertion placement, test-side only). go vet ./...
  → ok. go build ./... → ok. go test -race -count=1 ./internal/pipeline/
  ... ./internal/discovery/... → ok (no races; adapt 18.6s, discovery
  81.4s under race). Full suite go test -count=1 ./... → ok (25
  packages). No new issues opened; NEW-13 stays IN PROGRESS (owner:
  builder; orchestrator verifies and closes — never self-closed). No
  commits made (working tree left uncommitted per directive; .gitignore
  and .opencode/ untouched).
- T5 REVIEW FIX ROUND (this session, builder; claimed and completed, never
  self-closed): FIND-1 (LOW, T5 review round) — adapt/doc.go
  over-generalized: "The other engines follow the same Phase 3 convention
  (completed-only hits; partial/incomplete never served), which is what
  makes the full-run warm parity hold" implied every engine's FAILURE-path
  retry contract is pinned by T5, but only the dns engine's failed-job
  retry contract (stored-but-never-served: dns/run.go storeType, cache.go
  typeStatusToCache, cache evaluate — the file:line citations above
  storeType:558-601 / cache.go:133-143 / evaluate:207-209) is pinned HERE
  by the retry tests (TestT5FullRunRetryHealing / Persistent); the
  remaining engines' warm parity is pinned on the SUCCESS path by T4's
  cache-parity test (TestT4FullRunCacheHitParity, t4_determinism_test.go
  :443). REWORDED accordingly — the section's scope now matches what it
  actually pins; no other change, no new issues opened. Gates re-run
  verbatim below. T5 stays IN PROGRESS (owner: builder; orchestrator
  verifies and closes — never self-closed).

### NEW-15 (INFO) — T3c secrentel adapter: the JavaScript channel carries no document content (internal/asset)
- Status: RESOLVED (T3c session — decision: pipeline-internal document
  channel; no asset change)
- Reporter: builder (T3b round)
- Owner: (none)
- Problem: the T3b contract documents secrentel's T3c adapter as consuming
  the channel's `JavaScript` documents as its document source — but
  `asset.JavaScript` (internal/asset/javascript.go:25-77) retains
  OBSERVATIONS only: canonical URL identity, ContentHash (SHA-256 of the
  body), Size, ContentType, ETag, LastModified, StatusCode, FinalURL —
  never the body itself (jsintel's bounded fetch truncates honestly and
  retains no prefix). secrentel's Document seam is caller-composed
  bounded content (the engine never fetches); with no body in the
  channel, a T3c adapter has nothing to scan without re-fetching
  (violates the caller-composed contract) or a new content carrier.
- Resolution (implemented in T3c): a NEW pipeline-internal document
  channel (`internal/pipeline/document.go`) — `StageResult.Documents` /
  `StageInput.Documents` / `RunReport.Documents`, bounded retained script
  bodies (`pipeline.Document{Identity, URL, Content, Truncated}`, content
  ≤ `pipeline.MaxDocumentBytes` = 2 MiB = the secrentel engine's own
  ingest cap), merged by the runner exactly like the corpus/results
  channels (first-seen dedup keyed by the canonical identity string,
  deterministic order, per-stage MaxOutput cap → `documents_truncated`
  sticky flag + Truncated, hostile over-cap content dropped whole with
  the document marked Truncated — never a partial prefix). `asset.
  JavaScript` stays observation-only (NEW-15's original finding stands);
  the secrentel adapter (`internal/pipeline/adapt/secrentel.go`) consumes
  the document channel, never the Results.JavaScript field. Production is
  T3d (the jsintel stage family) — no adapter produces documents yet.
- Verification: full T3c gates (see the T3c IMPLEMENTED record below);
  `documents_truncated` flag, truncation-skip, and overflow-flag
  cache-hit regression pinned by tests.


### NEW-18 (HIGH) — v1.4 Live terminal observability: `ravenrecon scan --tui` (internal/cli)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20)
- Reporter: master
- Owner: builder
- Problem: v1.2's acceptance criterion "the TUI reconstructs a live run
  from events alone" has no CLI surface — `internal/tui` is a landed
  library nobody reaches; ROADMAP v1.4 (user-approved re-scope) is now
  live terminal observability for `scan`, with the per-engine standalone
  commands deferred until after v1.5 hardening.
- Fix (locked decisions): `--tui` + `--tui-compact` flags on
  `ravenrecon scan` (compact requires tui; tui and --verbose mutually
  exclusive — one event sink per run); in runScan, one
  `event.NewBus(nil)` + one bounded subscriber (64) + a controller
  goroutine (seam `tuiNew func(config.TUIConfig, *event.Subscriber,
  io.Writer) (tuiRunner, error)`, production adapter `newScanTUI`
  wrapping tui.NewController, injected at the cli.Run call site);
  `cfg.Observer = bus` on the --tui path (nil otherwise — zero change);
  TUIConfig {Enabled, Compact, Color=resolveTUIColor(os.Stderr)} with the
  rest zero → library defaults; defer after construction: sub.Close →
  `<-tuiDone` (bounded join) → bus.Close on EVERY return path; a non-nil
  Run result is a stderr "tui: %v" warning only — exit semantics + summary
  unchanged; construction errors return before the stages run.
- Verification: hermetic wiring tests (fake tuiRunner draining its
  subscriber: 20 events for 10 stages, sequence order, observer wired,
  summary byte-identical with/without --tui, failed-run semantics
  unchanged, pre-cancelled promptness + join, write-failure warning,
  Run-returned-before-runScan-returned ordering); parse rows; pipe → color
  "off"; gates (gofmt/test/vet/build/-race) + `scan --help` smoke;
  docs wave (ROADMAP re-scope + deferred list, README, ARCHITECTURE,
  AGENTS §2, version/UA 1.4.0). Fulfills v1.2's live-reconstruction
  acceptance note. Orchestrator verifies and closes — never self-closed.
- IMPLEMENTED (this session, builder; claimed IN PROGRESS at dispatch,
  never self-closed): the full locked-decision implementation landed —
  flags (`--tui`, `--tui-compact`; mutual exclusion with `--verbose`
  listing both flags; compact requires tui), `resolveTUIColor`
  (ModeCharDevice via Stat; pipe/file/non-*os.File → "off", TTY → "on"),
  the `tuiRunner` + `scanTUIFactory` seams with the production adapter
  `newScanTUI` (wraps tui.NewController; wired at the cli.Run scan call
  site) and a defensive nil-seam guard, and the runScan wiring: after
  parse → config → cache construction, `event.NewBus(nil)` + one bounded
  subscriber (64 — ~20 stage events per run documented) + controller
  goroutine (`go func(){ tuiDone <- ctl.Run(ctx) }()`, buffered result
  channel); `cfg.Observer = bus` on the --tui path (nil otherwise); a
  defer registered right after construction runs on EVERY return path:
  `sub.Close()` (deterministic termination — the controller's loop selects
  on Done) → `<-tuiDone` (bounded join) → warning `tui: %v` on stderr for
  any non-nil result (write failure OR the controller reporting
  ctx.Err() — exit semantics and summary never change) → `bus.Close()`.
  Construction errors return before the stages run. TUIConfig passed to
  the seam: {Enabled: true, Compact: <flag>, Color: resolveTUIColor(
  os.Stderr)} — all other fields zero → library defaults. NEW TESTS
  (internal/cli/scan_test.go, all hermetic, channels only — no sleeps, no
  TTY hacks): parse rows (tui, tui+compact, both exclusivity orders,
  compact-without-tui), TestResolveTUIColor (os.Pipe writer → "off"),
  TestRunScanTUIWiring (observer wired on the seam capture; 20 events in
  started/finished alternation with bus sequences 1..20; seam cfg
  Enabled/Compact from flags; writer == os.Stderr; summary byte-identical
  to the no-flag run; fake Run returned before runScan returned — the
  structural join assertion; compact variant), TestRunScanNoFlagObserverNil
  (zero behavior change), TestRunScanTUIOutcomeUnchanged (failed run:
  same error + honest summary + joined), TestRunScanTUIWriteFailureIsWarning
  (stderr captured via os.Pipe swap — no t.Parallel in this package —
  warning contains "tui:", exit nil, summary printed, joined),
  TestRunScanTUICancelled (pre-cancelled ctx: prompt return, cancelled
  summary, seam consulted exactly once, joined, the controller's ctx.Err()
  surfaced as the honest `tui:` stderr note), TestRunScanTUIRunnerRequired
  (nil seam + --tui errors before the stages run). Docs wave: ROADMAP v1.4
  re-scoped (goal + checklist + deferred per-engine commands line,
  Status stays planned; v1.2 table row notes the later wiring); README
  Status 1.4.0 + scan flags + TUI wiring paragraph; ARCHITECTURE
  Terminal-observability "CLI wiring" paragraph + reader's map + event-bus
  known-limitations + v0.3 boundary + scan-command bullet; AGENTS §2
  parenthetical + tui bullet; version.go → 1.4.0, config.go UA →
  RavenRecon/1.4.0 (doctor output coherent — verified). Forced test
  touch-up: the 9 pre-existing runScan call sites in scan_test.go gained
  the 5th seam arg (nil) — the only existing-test change, required by the
  locked signature growth; ALL pre-existing assertions unchanged and green.
- GATE RECORD (this session, verbatim, in sequence): gofmt -l $(find .
  -name '*.go' -type f) → clean (empty). go test -count=1
  ./internal/cli/... ./internal/tui/... ./internal/event/... → ok (cli
  0.534s, tui 0.036s, event 0.415s). go vet ./... → ok. go build ./... →
  ok. go build -o /tmp/opencode/ravenrecon ./cmd/ravenrecon && /tmp/
  opencode/ravenrecon scan --help → full usage incl. --tui/--tui-compact/
  exclusivity/exit-semantics note; binary smoke: `scan example.com --tui
  --verbose` → "scan: --tui and --verbose are mutually exclusive" exit 1;
  `--tui-compact` alone → "requires --tui" exit 1; `--tui --tui-compact`
  real run completed without hanging (subscriber close/join exercised in
  production); `version` → 1.4.0; `doctor` → User-Agent RavenRecon/1.4.0
  (coherent). go test -race -count=1 ./internal/cli/... ./internal/tui/...
  ./internal/event/... → ok (cli, tui, event all ok, no races). go test
  -count=1 ./... → ok (25 packages, discovery 75.6s, adapt 17.5s). No
  production behavior changes outside the locked decisions; working tree
  left uncommitted.
- REVIEW ROUND (this session, reviewer; APPROVE WITH NITS — no
  CRITICAL/HIGH/MEDIUM; 8 INFO findings): FIND-1 (TUI final frame renders
  after the stdout summary — defer placement; accepted: summary byte-
  identical + separate streams + strictly sequential writes), FIND-2
  (resolveTUIColor = char-device probe, canonical stdlib-only isatty
  approximation; accepted, /dev/null gets harmless color codes), FIND-3
  ("tui: context canceled" honest warning; accepted; 3a fix below),
  FIND-4 (nil-seam guard asymmetry vs --verbose; accepted, pinned by
  test), FIND-5 (FIXED), FIND-6 (join can block on a stuck stderr pipe
  writer — same exposure as --verbose; accepted), FIND-7/FIND-8 (buffer
  64 budget + future instrumented stages; accepted, documented drift).
  FIND-5 FIXED (nit round): bus.Subscribe error path now bus.Close()es
  before returning (uniform with the ctl-construction path; unreachable
  on the current API — consistency only). FIND-3a FIXED: scan usage
  prose now covers both `tui:` warning triggers ("a TUI write failure
  (for example a broken pipe) or shutdown reason (for example the run
  context's cancellation) is a 'tui:' warning on stderr only") — matches
  ARCHITECTURE. NIT-ROUND GATES (verbatim): gofmt clean; go test
  -count=1 ./internal/cli/... ./internal/tui/... ./internal/event/... →
  ok; go vet ./... → ok; go build ./... → ok; go build -o
  /tmp/opencode/ravenrecon ./cmd/ravenrecon → ok; go test -race -count=1
  ./internal/cli/... → ok. Diff: +3/−1 (scan.go only).
- ORCHESTRATOR: full-suite gate + field trial + commit + close sequence
  pending (see NEW-19). DO NOT self-close.


### NEW-19 (INFO) — Field trial: first real-target validation run (cmd/ravenrecon)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20)
- Reporter: master
- Owner: master (orchestrator-run validation; no implementation)
- Problem: the entire automated suite is hermetic by design (AGENTS §13) —
  no real-world validation (live DNS/TLS, real discovery tools, real
  cache behavior, live TUI) has ever been exercised. User requested a
  real-target taste (2026-08-20).
- Fix (locked): `scan example.com` (IANA-reserved smoke target), all 10
  stages, real subfinder/assetfinder/amass (installed); gau/waybackurls/
  waymore ABSENT → urlintel degrades honestly (adapt/source.go:508-510
  ErrExecutableNotFound, recorded per-source errors); fresh cache
  /tmp/opencode/ravenrecon-cache-example; --tui exercises the v1.4 wiring
  on a long real run; report → /tmp/opencode/ravenrecon-report-example;
  --timeout 10m per stage. Two passes: cold (population), then warm
  (cache-hit parity + zero re-execution — the T5 contract at real scale).
- Verification: cold log (summary/outcomes/errors/timing) + report files
  + warm-run comparison; any real-world defect found → file NEW-2x
  finding (severity + file:line + fix), do not fix silently.
- Status notes: cold run launched in background (binary at launch = pre-
  micro-fix image; reachable-path behavior identical to final — the
  micro-fix touched only an unreachable error path + usage prose).
- FINDING (28m in, user-flagged): NOT hung — pipeline progressing
  (discovery incl. ~20 min amass, then dns/httpprobe, then urlintel: gau
  child observed 7+ min in network I/O; cache entries growing). The TUI
  frames were empty because of NEW-21 (stage events ignored by the TUI
  state machine), not because the run stalled. Tools gau/waybackurls/
  waymore confirmed installed (user) — full-stack trial in progress.


### NEW-20 (HIGH) — v1.5 URL-hunting refinement (formerly v1.7): live attack-surface mapping (internal/httpprobe, internal/pipeline/adapt)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-21): all v1.5 P0 items landed and verified — OPT-P0-1 quality gate b46a110 (NEW-22), OPT-P0-2 JS→URL 2d06b94, OPT-P0-3 urllive 7fc7e4c, OPT-P0-4 per-tool+health f44cecc, OPT-P0-5 honest duration 593177a; plus Chaos 184796a, Dnsx brute 0a19d67, Katana early-preview 1ab2e99; field validation pending next real-target run (dispatch pending v1.4 close + field-trial evidence NEW-19)
- Reporter: master
- Owner: (unassigned) | builder at dispatch
- Problem: framework misses most bug-bounty-relevant URLs — httpprobe
  probes hosts never URLs (httpprobe.go:87-88); jsintel analyzer endpoints
  are results-only, zero corpus additions (jsintel.go:100-102); no
  per-URL liveness triage; URL corpus = 0 while gau/waybackurls/waymore
  absent. Full drafted milestone: ROADMAP v1.5 "Refinement deliverable —
  URL hunting" (2026-08-20, orchestrator).
- Fix: ProbeURLs engine + `urllive` stage (between secrentel and priority)
  + jsintel filtered URL additions + new results entity (not asset.URL
  field) + report URL-status section + AllStages/vocabulary/T4/T5/T6 pins
  + cache op + ops precondition (install the three urlintel binaries).
- Verification: as ROADMAP v1.5 acceptance (live statuses end-to-end,
  JS-extracted → corpus → urllive → priority → report, zero recursion,
  determinism/cache parity/race/gates, real-target field trial with tools
  installed).
- Execution priority: NEXT milestone after v1.4 closes (orchestrator
  decision 2026-08-20, user delegated "do what is best"); v1.5/v1.6 slide
  after, content unchanged.


### NEW-21 (HIGH) — TUI renders empty frame on real runs: pipeline stage events ignored by TUI state machine (internal/tui/state.go, internal/pipeline)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-20) — builder fix round records kept below
  adaptation implemented (state.go maps StageStarted/StageFinished with the
  event payload fields; render.go gates the worker/throughput sections on
  their data sources and adds the stage-feed line; summary gains the
  bounded stage list; render-content tests added in
  internal/tui/stages_test.go incl. a controller fake-clock live-frame
  test; internal/cli/scan_test.go gains an additive production-adapter
  type assertion). Pipeline/event vocabulary/CLI wiring untouched.
  Reviewer round + field-trial rerun + gates still required before close;
  fix NOT verified, do NOT self-close.
- Reporter: master (field-trial evidence)
- Owner: builder (fix round) | orchestrator (review + verification + close)
- Problem: field-trial evidence (NEW-19, cold run on example.com): the
  TUI rendered "phase —" in 7,024/7,024 frames across 28+ minutes while
  the pipeline progressed through discover → dns → httpprobe → urlintel
  (gau child observed; cache entries growing to 258 records). The
  pipeline emits ONLY KindStageStarted/KindStageFinished (T3a). The TUI's
  State.Apply (internal/tui/state.go:88-130) handles KindScanStarted/
  Stopped, KindPhaseTransition, KindRunMetadata, KindProgress, KindWorker*,
  KindTask* — NO case matches a stage event, so every consumed event is
  ignored: title stays "untitled run", phase —, worker/task/throughput
  widgets stay empty. Controller.finish also renders an empty final state.
  The v1.4 hermetic wiring tests asserted transport (event count/order at
  the subscriber, summary byte-identity) but never rendered frame CONTENT,
  so the gap was invisible to the suite. v1.4's acceptance ("the TUI
  reconstructs a live run from events alone") is NOT met in production.
- Fix (recommended direction): adapt the TUI side, keep the pipeline's
  stage-event vocabulary stable (it is pinned by T3a tests, event
  validation, wiring tests, docs): (a) State.Apply maps KindStageStarted →
  setPhase(stage name) + stage-start timing, KindStageFinished → stage
  progress/task counting; (b) the worker/throughput/queue widgets have NO
  data source in production (pipeline emits no task/worker events) —
  degrade honestly: omit/blank those sections when no task events exist
  instead of rendering misleading zeros; (c) NEW render-content assertion
  in the wiring tests: a fake stage-event stream must produce a frame
  whose phase/title/progress reflect the events (assert rendered text via
  the controller's writer buffer, not just transport counts). Reviewer
  round required before v1.4 can close as verified.
- Verification: TUI wiring test asserting rendered content from stage
  events; field-trial rerun shows a live phase/progress frame; gates
  (gofmt/test/vet/build/-race/full suite) green; v1.4 acceptance then
  VERIFIED → close.
- NIT ROUND (reviewer, APPROVE WITH NITS): FIND-1 LOW FIXED — summary
  stage block gate now symmetric (`StagesStarted > 0 || StagesCompleted
  > 0`, render.go); FIND-2 INFO FIXED — TestStateProgressOnlyKeepsRate
  GateClosed pins KindProgress-only streams keep the throughput gate
  closed (stages_test.go); FIND-3 INFO FIXED — docs wave (ARCHITECTURE
  terminal-observability section + reader's map, README TUI paragraph,
  ROADMAP v1.4 checklist line); FIND-4/FIND-5 INFO accepted as designed
  (sanitize preserves LF/CR/TAB by documented contract; lone
  stage_started renders "stages 0/unknown" under honest-unknown).
  NIT-ROUND GATES (verbatim): gofmt clean; tui+cli tests ok; vet ok;
  build ok; race tui ok; event ok; full suite ok (25 pkgs).
- ORCHESTRATOR DECISION (doc-drift candidates flagged by docs agent,
  accepted as non-issues): (a) README State-components paragraph reads
  always-present but describes the MODEL (the model tracks
  worker/throughput fields); the render-level gating is documented in
  the TUI paragraph — no change; (b) ARCHITECTURE resource-line
  ambiguity ("queue depth, active workers" among sampled values) —
  resources.go carries those fields, render shows heap/goroutines/fds —
  ambiguous-not-wrong, no change. Both recorded here for history.
- ORCHESTRATOR: warm-trial evidence (NEW-19) → final gates → v1.4
  commit → NEW-18/NEW-21 VERIFIED + archived. DO NOT self-close.


### NEW-22 (HIGH) — Discovery data-quality gate: passive-source pollution cascade (internal/discovery, internal/pipeline)
- Status: VERIFIED — gate landed (builder round 1 + nits, reviewer CHANGES REQUIRED → nits fixed, gates green, committed b46a110)
- ORCHESTRATOR NOTE (transport + scope incident): builder dispatch for
  the locked contract failed twice at the transport layer (decode error;
  resume session completed without report). The partial session wrote
  internal/discovery/quality.go (gate core — kept, tree does NOT compile
  until wiring lands) then produced an out-of-contract
  OPTIMIZATION.md audit backlog + ROADMAP status-table rewiring (OPT-P*
  IDs) and zero wiring. Both discarded (git checkout ROADMAP.md; rm
  OPTIMIZATION.md) 2026-08-20 by orchestrator — not on any board, not
  user-requested. Re-dispatch in progress with tightened constraints.
- Status history: OPEN (addressed in v1.5 refinement) → IN PROGRESS
  (builder round 1, 2026-08-20)
- Reporter: master (field-trial evidence, NEW-19 cold run)
- Owner: (unassigned) | builder at v1.5 dispatch
- Problem: cold trial on example.com — subfinder v2.15.0 (config clean;
  no bruteforce/wordlist/permutation settings) returned 37,248 wordlist-
  shaped hosts in one burst (0.0.1.example.com, 0000-forbidden.example.com,
  zzzzzzzzzzzz.example.com; 31,180 rows with 4-label names; all rows
  timestamped 13:58:01Z, source=subfinder; assetfinder: 2 rows, amass: 0
  after 20 min). The framework accepted the entire set → 12,366 probe URLs,
  1,024 priority groups (truncated flag fired), 32 attack paths, 755
  recommendations computed over garbage; jsintel 500/500 fetches failed
  (dead junk hosts). Passive-only contract likely violated at the tool/
  binary level OR a poisoned source — either way the framework gated
  nothing.
- Fix (v1.5 item): per-source output caps + burst-anomaly detection +
  suspicious-source decision point (flag/abort/continue) before corpus
  ingestion; hostname sanity validation where syntax-gated (RFC 1035
  checks); tool-identity verification (binary hash/version pin per
  discovery source); document per-source normality baselines. Include in
  the v1.5 checklist (ROADMAP) alongside URL hunting.
- Verification: reproduction test with a fake source returning wordlist
  junk → gate trips with an honest flag/abort; real-target rerun shows a
  sane host count for a 1-subdomain domain; gates green.
- Builder round 1 (2026-08-20): quality.go kept (verified: defaults, Normalize, over_cap, divergence, median, error); fixed pipeline.go compile (storedResult QualityIssues, runSource 3-ret, no double-store, sticky replay) and cache.go; wired adapter (discovery_quality_flagged, qualityConfigFromParams, abort) and cli doctor line; ROADMAP ticked; tests: quality_test.go (cap, divergence, median, old-schema, sticky, abort, determinism) + discovery_quality_test.go (poisoned flag, divergence, abort, pipeline E2E); gates: gofmt clean, go test ./... ok (discovery 78s adapt 17s), vet ok, build ok, race ok, doctor grep quality ok.


### NEW-23 (HIGH) — DNS brute timeout indistinguishable from a complete run (internal/pipeline/adapt/dns.go)
- Status: VERIFIED — fixed in b5aa88e (attempted-only counters, dns_brute_truncated flag, outcome downgrade to partial/cancelled, 3 hermetic subtests)
- Reporter: reviewer
- Owner: builder
- Problem: AGENTS §0.6 violation. In `runBrute` (adapt/dns.go:504-573), when `dns.BruteTimeout` fires mid-resolution, `dns.Resolve` returns nil error; cancelled candidates carry no IPs/Targets and the resolving filter silently drops them; `ItemsProcessed` counts `len(filtered)` (including never-attempted hosts); only per-type answer-cap `Truncated` flags propagate — no cancellation/timeout flag exists. A timeout-truncated brute is recorded `completed` with no sticky flag.
- Fix: inspect `rep.Results` host statuses for cancelled/timed-out; set `Truncated` + `StickyFlags["dns_brute_truncated"]`, count only attempted hosts, downgrade the outcome per the fold table.
- Verification: fake resolver stalling past BruteTimeout → flag fires, outcome != completed, attempted-only counters; regression fails pre-fix.


### NEW-24 (MED) — techintel cache key lacks observation-content digest: changed page serves stale detections (internal/techintel)
- Status: VERIFIED — fixed in 51abd2d (observationContentHash SHA-256 over Body/Headers/Cookies/TLS/DNS, ContentHash omitempty, decode 64 lower-hex, lookup self-heal, 5 hermetic tests)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: `techKey` (record.go:26-36) binds identity + schema + db_digest + sources mask only; `storedTech` carries no content hash. Siblings solve this: secrentel digests document content into its key (document.go:261), jsintel cross-validates `AnalyzedHash` at lookup and self-heals (record_analyze.go:155-166). Until TTL expiry, a materially changed page replays old detections as zero-analysis cache hits.
- Fix: adopt the jsintel pattern — store an observation payload hash (headers/body/cookies digest) in the record; reject+delete+recompute on mismatch.
- Verification: cross-engine conformance test "content change ⇒ no stale hit"; fails pre-fix for techintel.


### NEW-25 (MED) — validateHostname rejects leading-underscore labels: _dmarc/_domainkey/_acme-challenge hosts cannot become assets (internal/asset)
- Status: VERIFIED — fixed in 4c919d5 (leading underscore per label, rest [a-z0-9-] hyphen rules, mid-label _ still rejected, 23 tests)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: normalize.go:48-53 permits only `[a-z0-9-]`; underscore is rejected everywhere. RFC 8552-style service labels (`_dmarc.example.com`, `s1._domainkey.example.com`, `_acme-challenge.example.com`) are legitimate passive-discovery output and are dropped/error at the sole normalization point (rejection pinned by normalize_test.go:34).
- Fix: permit leading-underscore labels; keep mid-label underscores invalid; document the policy in doc.go.
- Verification: table tests — `_dmarc`/`s1._domainkey` accepted, `exa_mple` still rejected; discovery fixture with such hosts survives end-to-end.


### NEW-26 (LOW) — jsintel import window scans superlinear on adversarial input; Parse uncancellable (internal/jsintel)
- Status: VERIFIED — fixed in 74851fc (maxTotalScanSteps 100k + statement-boundary early exit; adversarial <100ms, truncated honest)
- Reporter: reviewer
- Owner: (unassigned)
- Problem: `findFromSpecifier` (parse.go:184-223) scans up to `maxLookaheadTokens` (1024) from every `import` keyword; input like `import x import x …` repeats gives O(tokens × 1024) (~5e8 steps at the 1M-token cap). `Parse` takes no context, so pool deadlines cannot interrupt it.
- Fix: cap total window-scan steps per parse (fold into `w.truncated`) or stop a scan at the next import/export keyword; thread ctx or accept an explicit step budget.
- Verification: adversarial corpus benchmark with the number pinned in parse.go's comment (§14); parse completes under pool deadline.


### NEW-27 (LOW) — secrentel anchor gate ASCII-lowercases but gated regexes match via Unicode simple fold: silent false negatives (internal/secrentel)
- Status: VERIFIED — fixed in 4803cf1 (unicode-fold fallback scan.go:90-152,
  foldRuneToASCIILower :479-497 matching RE2 (?i) simple-fold semantics;
  regression fails pre-fix); reviewer APPROVE this session
- Reporter: reviewer
- Owner: builder
- Problem: scan.go:82-86 builds the anchor haystack with `toLowerASCII`; anchors gate `(?i)` regexes (scan.go:101-112), which match through Unicode simple folding (ſ↔s, U+212A K↔k). A document containing e.g. `aws_ſecret_access_key=` passes the regex yet lacks the ASCII anchor → pattern skipped, violating the "anchor is a necessary substring" contract (patterns/types.go:124-131).
- Fix: fold-compare anchors (walk with `unicode.SimpleFold`) or restrict anchored families to ASCII-only matching explicitly.
- Implementation (2026-08-21): unicode-fold fallback in scanDocument — a lazy
  folded haystack (scan.go:94-102; buildFoldedHaystack/foldRuneToASCIILower at
  scan.go:469/481 map each rune through SimpleFold to its ASCII-lower form,
  matching RE2 (?i) semantics) consulted only when the ASCII fast path misses
  AND the document is non-ASCII (scan.go:136-150). Non-ASCII presence is
  memoized once per document (scan.go:104-115, call site scan.go:140 — review
  follow-up: an unmemoized check paid a full O(n) byte scan per anchored
  miss). Regression: TestScanAnchorHomoglyphRegression (scan_test.go:536) —
  ſ-homoglyph anchor rescued through a custom compiled pattern AND the
  production DB's own "secret" anchor. Gates this session, verbatim: gofmt -l
  clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/
  secrentel -run TestScanAnchorHomoglyphRegression -v ok; go test -race
  -count=1 ./internal/secrentel ok; go test -count=1 ./... ok (25 packages).
- Verification: homoglyph regression row demonstrates match-without-anchor today, correctly anchored after fix.


### NEW-28 (LOW) — secrentel dedup merge upgrades strength/family but not entropyOK (internal/secrentel)
- Status: VERIFIED — fixed in 4803cf1 (merge upgrade scan.go:219-224 +
  Phase-3 winner re-derivation :301-313 as defense-in-depth; both entropy
  directions pinned, vacuous-pass trap defused via creator-sorts-first ID
  ordering); reviewer APPROVE this session
- Reporter: reviewer
- Owner: builder
- Problem: scan.go:176-184 merges duplicate candidates by upgrading strength/family from the winning pattern; `entropyOK` stays the creating pattern's. Phase 3 scores with the creating pattern's entropy flag while hints use the winning pattern — the factor list can contradict the winning pattern's entropy requirement (both directions possible).
- Fix: recompute `entropyOK` from the winning pattern at merge time (or evaluate Phase 3 entropy from the winner).
- Implementation (2026-08-21): entropyOK+provider now sync at BOTH points —
  the dedup merge upgrade (scan.go:219-224: `p.Strength > c.strength` also
  overwrites entropyOK/provider) and a Phase-3 winner re-derivation that
  re-syncs strength/family/entropyOK/provider from the winning pattern (max
  strength, ID tie-break) as defense-in-depth (scan.go:303-314). Regression:
  TestScanDedupEntropyWinner (scan_test.go:585). REVIEW FOLLOW-UP fixed this
  round: every subtest previously passed pre-fix because patterns.compile
  sorts by ID (patterns/load.go:69-71), so the eventual winner ("aaa-") was
  always processed first and WAS the creator — the dedup merge never
  executed. IDs reordered so the LOSER sorts first (creator) and the winner
  merges second: Case 1 creator "aaa-loser-no-entropy" (0.5) / merger
  "zzz-winner-with-entropy" (0.9) upgrades entropyOK false→true
  (scan_test.go:595,605); Case 2 mirrored creator "aaa-loser-with-entropy"
  (0.5) / merger "zzz-winner-no-entropy" (0.9) overwrites true→false
  (scan_test.go:649,659 — the merger must carry the higher strength or the
  upgrade path never fires); Case 3 kept as an honest equal-strength
  determinism pin (under sorted processing the tie-break winner is always
  the creator, so it exercises only the Phase-3 re-derivation as
  defense-in-depth). Pre-fix proof: with the NEW-28 hunks reverted on a
  scratch copy, Case 1 fails (entropy factor absent, entropyOK false despite
  strength 0.9 proving the merge ran) and Case 2 fails (spurious
  {Name:entropy Weight:0.35} factor); both pass with the fix. Gates this
  session, verbatim: gofmt -l clean; go vet ./... ok; go build ./... ok;
  go test -count=1 ./internal/secrentel -run TestScanDedupEntropyWinner -v
  ok (3/3 subtests); go test -race -count=1 ./internal/secrentel ok;
  go test -count=1 ./... ok (25 packages).
- Verification: two-pattern same-type dedup case where winner requires entropy and loser does not (and vice versa); factor list matches winner.


### NEW-29 (LOW) — sortQuery collapses ?x= and ?x into one URL identity (internal/asset)
- Status: VERIFIED — fixed in 557a5cb (hasValue tracks strings.Cut found;
  "?x="→"x=" vs "?x"→"x" distinct; identity split is over-splitting only —
  no false cache hits possible); reviewer APPROVE this session
- Reporter: reviewer
- Owner: builder
- Problem: url.go:286-290 writes `=` only when the value is non-empty, so distinct raw forms `?x=` and `?x` serialize identically — contradicting the type doc's "distinct raw forms never collapse" principle (url.go:30-34).
- Fix: track whether each raw pair contained `=` and emit `key=` for present-but-empty values.
- Verification: pin `?a=1&x=` vs `?a=1&x` as distinct identities.
- Implementation (2026-08-21): sortQuery now records strings.Cut's found bool as
  param.hasValue (url.go:272, :284) and emits the '=' whenever the raw pair
  contained one, even for an empty value (`if prm.hasValue`, url.go:293), so
  "?x=" -> "x=" and "?x" -> "x" stay distinct. Type doc and sortQuery doc
  updated to state the rule. Regression pins: TestURLDistinctness case
  "empty value vs no value (NEW-29)" (?a=1&x= vs ?a=1&x) and four canonical-
  form rows in TestURLQueryRawKeyPreservation (url_identity_test.go:113,
  :161-166). Pre-fix proof: reverting only the emission condition on a scratch
  copy fails TestURLQueryRawKeyPreservation ("?x=" collapsed to "x"). Gates:
  gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./...
  ok (25 pkgs); go test -race -count=1 ./internal/asset ok.


### NEW-30 (LOW) — dns wildcard probe bypasses the central query limiter (internal/dns)
- Status: VERIFIED — fixed in 557a5cb (documented-exception route: doc.go:47-54
  scopes the limiter promise to Resolve pool jobs + states the IsWildcard
  exception with rationale; brute.go note matches; behavior verified
  unchanged); reviewer APPROVE this session
- Reporter: reviewer
- Owner: builder
- Problem: `IsWildcard` (brute.go:130-165) issues `resolver.Lookup` directly (brute.go:143), outside Resolve's env; dns/doc.go:40 promises every outbound query waits on the shared token-bucket limiter regardless of concurrency. Called per-run from adapt/dns.go:449.
- Fix: route the probe through the run limiter (accept a Limiter param) or document the exception in doc.go + brute.go.
- Verification: limiter-counting fake resolver asserts the probe consumes a token (or the doc drift is closed).
- Implementation (2026-08-21): took the documented-exception alternative. The
  limiter-param route would need a new exported config surface plus adapter
  wiring, and a separately constructed limiter shares no bucket state with
  Resolve's env (burst >= 1 -> zero wait), so it would pace nothing; for one
  opt-in query per domain, honest docs are the proportionate fix. doc.go
  "Concurrency and rate limiting" now scopes the promise to Resolve's own
  pool-job queries and states the IsWildcard exception with its rationale
  (doc.go:47-55); IsWildcard carries a matching rate-limiting note
  (brute.go:155-159). Behavior unchanged — no new test surface; existing
  TestIsWildcard* all pass. Gates this session: gofmt -l clean; go vet ./...
  ok; go build ./... ok; go test -count=1 ./... ok; go test -race -count=1
  ./internal/dns ok.


### NEW-31 (LOW) — dnsx_resolvers StageParam parsed then discarded; "validates shape" claim inaccurate (internal/pipeline/adapt/dns.go)
- Status: VERIFIED — fixed in 557a5cb (netip.ParseAddr shape validation +
  dns_brute_resolvers_ignored sticky flag on every brute-enabled path,
  traced incl. wildcard-abort/empty/full merges; "NOT honored" comments);
  reviewer APPROVE this session
- Reporter: reviewer
- Owner: builder
- Problem: `dnsBruteResolvers` (adapt/dns.go:416-438) result discarded at :464 (`_ =`); operator-supplied resolvers are silently ignored. The comment claims parsing validates shape but no IP validation occurs (comma split only).
- Fix: implement (thread resolvers into cfg), or warn-and-ignore with honest wording, or reject the param like other unknown params; fix the comment either way.
- Verification: param supplied → resolvers used or warning surfaced; comment matches behavior.
- Implementation (2026-08-21): warn-and-ignore. dnsBruteResolvers now really
  validates shape — every non-empty entry must parse via netip.ParseAddr,
  invalid entries counted in a second return value, never an error
  (adapt/dns.go:514-537) — and Run sets the new sticky flag
  dns_brute_resolvers_ignored when brute is enabled and anything was supplied
  (adapt/dns.go:169-183); the flag is set on baseRes before every brute path,
  so wildcard-abort/empty/full merges all preserve it. With brute disabled the
  param is inert like every other dnsx_* param and no flag is raised (pinned).
  The `_ =` discard in runBrute is gone; Run doc block and function comments
  state "NOT honored — native resolver always used". Tests:
  TestDNSBruteResolversParsing (shape table) and
  TestDNSBruteResolversIgnoredFlag (flag set for valid+invalid input, outcome
  not downgraded, native seam still used; no flag when absent or brute
  disabled), adapt/dns_test.go:980-1113. Gates this session: gofmt -l clean;
  go vet ./... ok; go build ./... ok; go test -count=1 ./... ok;
  go test -race -count=1 ./internal/pipeline/adapt ok.


### NEW-32 (LOW) — dns brute truncation flag false-positives at exactly-at-cap (internal/pipeline/adapt/dns.go)
- Status: VERIFIED — fixed in 557a5cb (GenerateBruteCandidates returns
  explicit cap-hit bool; exactly-at-cap → no flag, above-cap → flag;
  pre-fix proof by restoring the length-inference line); reviewer APPROVE
  this session
- Reporter: reviewer
- Owner: builder
- Problem: `candidateTruncated := len(candidates) >= dns.MaxBruteHostsPerDomain || wordlistTruncated` (:492) fires when generation produced exactly MaxBruteHostsPerDomain candidates without dropping anything (the generator truncates only above cap) → spurious `dns_brute_truncated` sticky flag.
- Fix: return an explicit cap-hit bool from GenerateBruteCandidates instead of inferring from length.
- Verification: wordlist of exactly the cap size → no flag; above cap → flag.
- Implementation (2026-08-21): GenerateBruteCandidates now returns
  ([]asset.Host, bool) — the bool is true iff a distinct valid candidate was
  actually DROPPED at the cap (brute.go:74-91; core extracted into
  buildBruteCandidates brute.go:95-131 so tests can exercise drop detection
  with small caps — with the current equal 5000/5000 constants the public
  path can never observe a drop). The adapter uses the explicit bool:
  `candidatesCapped` (:562) feeds `candidateTruncated := candidatesCapped ||
  wordlistTruncated` (:593); no length inference anywhere. Tests:
  TestBuildBruteCandidatesCapHit (above cap -> true; exactly at cap,
  duplicates beyond cap, invalid labels beyond cap -> false),
  TestGenerateBruteCandidatesCap now also pins capHit=false at exactly-cap;
  adapter level: TestDNSBruteExactlyAtCapNoTruncationFlag (5000 distinct
  labels -> completed, no flag, brute provably ran) and
  TestDNSBruteAboveCapTruncationFlag (5001 labels -> wordlistTruncated ->
  flag+Truncated), adapt/dns_test.go:1116-1167. Pre-fix proof: restoring the
  old inference line on a scratch copy fails
  TestDNSBruteExactlyAtCapNoTruncationFlag ("Truncated = true ... at exactly
  the cap"). Gates this session: gofmt -l clean; go vet ./... ok; go build
  ./... ok; go test -count=1 ./... ok; go test -race -count=1
  ./internal/dns ./internal/pipeline/adapt ./internal/asset ok.


### NEW-33 (LOW) — atomic writes never fsync the parent directory after rename (internal/cache, internal/report)
- Status: VERIFIED — fixed in 1f4b0c8 (dir fsync best-effort + Validate length checks; reviewer gates green)
- Reporter: reviewer
- Owner: builder
- Problem: cache Put syncs the temp file then renames (cache/cache.go:282-291) with no directory fsync; report writer same (writer.go:148 Sync, :334 Rename). After power loss the rename itself may be lost — degrades to a cache miss / missing report, never corruption, but weakens the documented crash-safe guarantee.
- Fix: best-effort open(dir)+Sync()+Close after rename in both writers, or scope the durability wording in docs.
- Verification: injectable sync hook asserts dir sync invoked; docs updated.
- Work note (builder): fsync fix implemented. Both packages gained `syncDirBestEffort(dir)` (open→Sync→Close; ENOSYS/EINVAL swallowed via `isUnsupportedDirSync` as "filesystem does not support dir fsync"; other errors returned for observability) and an injectable unexported `dirSync` field set at construction (same pattern as FS.beforeSelfHeal). cache/cache.go:104-109 (field), :135 (Open init), :305-311 (Put calls it after successful rename; failure never fails the Put), :314-345 (helper + errno filter). report/writer.go:171-179 (field), :198 (init), :351 (Commit syncs once after all renames), :355-387 (helper mirror — duplicated ~15 lines, no shared parent package). Put/Commit doc comments updated to state the best-effort semantics; README/ARCHITECTURE deliberately untouched (outside this task's allowed file list) — their existing "fsync + atomic rename" wording remains true and now understates the guarantee. Tests: TestPutFsyncsDirectoryAfterRename, TestPutSkipsDirSyncWhenRenameFails, TestPutSucceedsWhenDirSyncFails, TestSyncDirBestEffort (errno table) in cache_test.go; TestFileSinkCommitSyncsDirectory, TestFileSinkCommitSkipsDirSyncWhenCommitFails, TestFileSinkCommitToleratesDirSyncFailure, TestSyncDirBestEffort in writer_test.go. Gates this session: gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/cache ./internal/report ./internal/event ok; go test -race -count=1 (same three) ok; go test -count=1 ./... ok.


### NEW-34 (LOW) — event.Validate allocates a map literal per published event (internal/event)
- Status: VERIFIED — fixed in 1f4b0c8 (dir fsync best-effort + Validate length checks; reviewer gates green)
- Reporter: reviewer
- Owner: builder
- Problem: event.go:105-111 builds a 4-entry map per call; Validate runs on every publish — the hottest observability path.
- Fix: four explicit length checks.
- Verification: existing validation table passes unchanged; benchmark shows the allocation removed.
- Work note (builder): map range replaced with four explicit length checks in deterministic order phase→category→identity→value, identical error text (event/event.go:106-121); comment records why. BenchmarkValidate added (event/bench_test.go:13-29). Measured on go1.26.5/amd64: BEFORE 125.1-128.7 ns/op, 0 B/op 0 allocs/op (the compiler already elides ranging over a small map literal, so the allocation premise is stale on this toolchain); AFTER 6.6-8.8 ns/op, still 0 allocs — ~15x faster, allocation-freedom now guaranteed by construction instead of by compiler optimization, and check order deterministic. Existing validation table (TestValidateRejectsCoreContractViolations etc.) passes unchanged. Gates this session: gofmt -l clean; go vet ./... ok; go build ./... ok; go test -count=1 ./internal/cache ./internal/report ./internal/event ok; go test -race -count=1 (same three) ok; go test -count=1 ./... ok.


### NF-4 (INFO) — config comment cites a discover --timeout flag that does not exist (internal/config)
- Status: VERIFIED — fixed in 7f2f05a (config.go:168 comment corrected to Discovery.Timeout / scan --timeout)
- Reporter: reviewer
- Owner: docs


### NF-5 (INFO) — OPTIMIZATION.md status column stale: OPT-P0-1/P0-2 implemented+verified but marked OPEN
- Status: VERIFIED — fixed in 7f2f05a (OPTIMIZATION.md P0-1/P0-2 OPEN → VERIFIED)
- Reporter: reviewer
- Owner: docs


### NF-6 (INFO) — SECURITY.md gives no actual reporting contact
- Status: VERIFIED — fixed in 7f2f05a (SECURITY.md:9-11 Contact added)
- Reporter: reviewer
- Owner: docs


### NEW-36 (INFO) — Field trial 2: verily.com real-target validation (cmd/ravenrecon)
- Status: VERIFIED (orchestrator, 2026-08-21) — evidence recorded below
- Reporter: master
- Evidence (run: /tmp/opencode/fieldtrial-verily.log, report: /tmp/opencode/ravenrecon-report-verily, cache: ravenrecon-cache-verily):
  - Quality gate LIVE: subfinder 1036 hosts flagged divergence vs others [103,1] — discovery_quality_flagged fired BEFORE corpus ingestion (NEW-22 contract proven on real data; no junk cascade).
  - NEW-21 fix PROVEN live: TUI log shows phase crawl/jsintel/urllive etc. across 901 frames with stages N/unknown; final frame carried full 12-stage table with per-stage counters.
  - 12-stage pipeline incl. crawl (1044 hosts crawled, 36.7s) and urllive (2088 URLs triaged: 14×2xx, 254×3xx observed-not-followed, 174×4xx, 2×5xx, 1644 errors) — OPT-P0-3 working end-to-end.
  - jsintel health-relevant: 500 processed/262 failed truncated (js_fetch_truncated) — P0-4 caps visible.
  - Report honest: live_record_count=2088 in statistics; digest stable a6437a7c…; markdown/html Live URLs section rendered.
  - Known issues for follow-up: (1) urllive cancelled at stage deadline with 1644 errors — needs per-URL timeout tuning or higher concurrency for 2k-URL corpora; (2) amass failed after contributing 0 (known slow-source); (3) urlintel completed 0 (gau/wayback empty for this target — tools ran 0.2s); (4) summary duration_ms still 0 (pipeline bracket wiring deferred from P0-5 — model ready, adapt/report.go single-now pending).
- Verification: run outcome cancelled (urllive deadline), but all v1.5 deliverables demonstrated on an authorized real target.


### NEW-38 (INFO) — Field trial 3: verily.com post-chaos-fix validation (cmd/ravenrecon)
- Status: VERIFIED (orchestrator, 2026-08-21) — chaos fix proven; coverage delta recorded
- Evidence (/tmp/opencode/fieldtrial-verily2.log, report-verily2, fresh cache):
  - chaos now contributes 1,044 hosts (was 1); discover 2,183 processed → corpus 1,067 hosts (+23 net-new vs trial 2, all real: dev-v1.login, granular-uw-* GKE clusters, identity-playground…).
  - urlintel UNLOCKED: gau returned 6,120 URLs in 2m00s partial (per-tool timeout fired as designed — P0-4 working); trial 1 had 0.
  - urllive triaged 8,254 URLs: 182×2xx alive (13× net-new incl. dev-files.verily.com, page.verily.com), 2,370×3xx, 4,066×4xx — still cancelled at stage deadline (1,635 errors): per-URL concurrency tuning remains the open item.
  - Full-funnel proof: crawl 1,067 → techintel 8,254 → jsintel 500/267 truncated → secrentel 205 → priority 9,321 surfaces / 97 groups / 32 paths.
  - Remaining known items: urllive deadline tuning; duration_ms wiring (P0-5 deferred); amass opt-in.


### NEW-39 (MED) — urllive stage deadline starvation on large corpora (internal/httpprobe/urls.go, internal/pipeline/adapt/urllive.go)
- Status: VERIFIED — fixed in 990c810 (triage defaults 5s/20-concurrency; cut-short triage marks Truncated+urllive_truncated)
- Reporter: master (field trial 3, NEW-38)
- Problem: 8,254-URL corpus — 10s per dead host starved the shared stage budget; run cancelled with 1,635 errors and no truncation marker.
- Fix: ProbeURLs triage defaults (RequestTimeout 5s, Concurrency 20, QueueSize=Concurrency when unset; explicit config wins); adapter marks Truncated+flag when the budget fires mid-triage.
- Verification: TestProbeURLsTriageDefaults (blocking transport, ~5s cut), cancellation test asserts flag; all gates + race green.
- Post-fix field run 4 (verily.com, fresh cache): urllive still hits the shared stage deadline at 8,199-URL scale (1,587 errors) BUT now carries Truncated+urllive_truncated honestly; alive 172, 3xx 2,361, 4xx 4,078. The remaining lever is a dedicated urllive stage budget (StageBounds Timeout for urllive) or higher concurrency via StageParams — operator-tunable today: --stages with per-stage bounds. Not a defect; recorded as tuning guidance.


### NEW-40 (INFO) — OPT-P0-5 completion: honest duration verified on a real run
- Status: VERIFIED — pipeline bracket wired in 08861f0; field run 5 (verily.com, fresh cache) reports started_at 14:23:21 → ended_at 14:30:53, duration_ms 452249 (7m32s). Digest stable (timing excluded). The last P0-5 piece is closed.


### NEW-41 (INFO) — amass strategy decision: keep as-is (orchestrator, user directive)
- Status: WON'T FIX (user decision, 2026-08-21) — "just skip amass" / "leave it as is": no opt-in change, no removal. Amass remains a built-in source; operators who don't want its runtime cost can already exclude it via --sources subfinder,assetfinder,chaos. Field-trial evidence (20m→0 on example.com, failed on verily.com) recorded under NEW-36/38 for anyone tuning later.


### NEW-42 (LOW) — agent definitions underperforming: rewritten (.opencode/agents/*.md)
- Status: VERIFIED (orchestrator, 2026-08-21) — all five definitions reviewed:
  YAML frontmatter parses (python3 yaml), no dead placeholders, V2 permissions
  arrays correct (reviewer edit-deny; research edit+shell deny), real roster,
  self-contained delegation contract. Live evidence: this session's harness is
  running the new master.md verbatim (no TESTER/DOCS agents in prompt) and a
  reviewer dispatch behaved exactly per the new definition (read-only, evidence-
  based verdict). Operator service restart no longer outstanding.
- Reporter: ox-alpha (session ses_fdbf942d8ffeqwyIEwAF546Qfy)
- Owner: n/a (dev tooling, not engine code)
- Problem: builder/debugger/reviewer each mandated reading AGENTS+README+ARCHITECTURE+ROADMAP in full (~280KB / ~65-70k tokens per subagent spawn; ARCHITECTURE.md alone is 3487 lines / 190KB) before any task work — contradicting AGENTS.md §4 and starving task context. Rules duplicated AGENTS.md (auto-injected into every session) in drifted form: TODO.md board duty (§13) and tier classification (§1) missing from builder/debugger. master.md delegated to non-existent TESTER/DOCS agents, lacked a self-contained-prompt rule for fresh-context subagents, and omitted the orchestrator's TODO-closing duty. Dead template placeholders ([INSERT EXACT TASK HERE], [CAPABILITY], [PASTE BUG HERE]) sat in static prompts. research/reviewer used legacy V1 `permission:` frontmatter with the V1 `bash` action name.
- Fix: rewrote all five definitions per /home/raven/.opencode/plan/optimize-agents-plan.md — targeted grep/glob inspection instead of full-doc reads; AGENTS.md referenced by section, not re-read; placeholders removed; V2 `permissions` arrays (reviewer edit-deny; research edit+shell deny); master roster corrected to real agents (+ built-in explore) with self-contained delegation contract and TODO-closing duty; TODO duties restored to builder/debugger.
- Verification: YAML frontmatter of all five files parses (python3 yaml); net −320 prompt lines (git diff --stat). Remaining: restart the OpenCode service (`opencode2 service restart`) so new definitions load, then smoke-test each agent once (builder/debugger update TODO.md; master delegates only to real agents). Restart deferred to the operator — restarting the service hosting a live session risks killing it mid-work.


### NEW-43 (LOW) — TODO.md tail duplicated: NEW-37/39/40/41 blocks and an "Operational warnings" heading appear twice
- Status: VERIFIED (orchestrator, 2026-08-21) — duplicated tail deleted
  (lines 1733-1754: stray heading + second NEW-37/39/40/41 copies);
  `grep -c '^### NEW-41'` = 1, single `## Operational warnings` section,
  NEW list contiguous NEW-42→43→44.
- Reporter: ox-alpha (session ses_fdbf942d8ffeqwyIEwAF546Qfy)
- Problem: after the first NEW-41 entry, a stray `## Operational warnings (all agents)` heading is immediately followed by a second copy of the NEW-37, NEW-39, NEW-40 and NEW-41 blocks, then the real Operational warnings section repeats with its actual bullet list. `grep -n '^### NEW-41' TODO.md` returns two hits; both copies carry identical VERIFIED/WON'T FIX text. Agents scanning the board read every entry twice and the stray heading breaks the section structure.
- Fix: delete the duplicated tail (second NEW-37/39/40/41 copies + the stray heading), keeping one contiguous NEW list followed by a single Operational warnings section; then re-check the "next free NEW-n" pointer.
- Verification: `grep -c '^### NEW-4[01]' TODO.md` returns 2 (one each); only one `^## Operational warnings` remains.


### NEW-44 (LOW) — AGENTS.md rewritten: discipline over ceremony (AGENTS.md)
- Status: VERIFIED (orchestrator, 2026-08-21) — full diff reviewed: §0–§17
  headings and substance preserved, preamble added, cross-references resolve
  (ROADMAP §5/§0.4 checked; "Tier C" vocabulary retained deliberately for
  ARCHITECTURE.md reader map + master.md). Committed with this closure.
- Reporter: ox-alpha (session ses_fdbf942d8ffeqwyIEwAF546Qfy)
- Owner: n/a (governance doc, not engine code)
- Problem: AGENTS.md read as shackles, not discipline: §1 imposed a tier/reading matrix (meaningless since AGENTS.md auto-injects into every session — agents were told to "read" a doc already in their context); §13/§17 framed gates as ritual ("you may not describe a change as complete until…", an 11-item checklist re-listing other sections); §16 mandated a 10-item PR write-up; §12 duplicated §0.8. Nothing in the file told agents that judgment outranks procedure outside §0.
- Fix: rewrote in place preserving ALL §0–§17 numbers and meanings (≈50 cross-references in TODO/ROADMAP/ARCHITECTURE/.opencode/agents keep resolving — verified every referenced number has a heading). Changes: new preamble (guardrails-not-procedure; judgment wins except §0); §1 became "rigor scales with blast radius" — tier vocabulary kept (ARCHITECTURE.md reader map + master.md reference Tier C) but reading requirements deleted; §5 compressed to the ownership rule + stop-and-propose trigger; §7 12 items → 9 (merged redundancies); §13 reframed as know-don't-assume incl. explicit "if a check cannot run, say so" clause; §16 loosened to on-request/architectural; §17 11-item checklist → 5-line closure habit. §0 nine constraints unchanged in substance.
- Verification: heading set {0..17} covers every §N used elsewhere (grep cross-check); harness reloaded the file (new text active in-session). No Go code touched; gofmt/vet/build/test not runnable here (no toolchain on machine — see NEW-42 note).


### NEW-46 (INFO) — secrentel scan converts []byte→string three times per document (internal/secrentel)
- Status: VERIFIED — fixed in 4e31f8d (single strContent hoisted above the lazy
  closures; fast-path lower + folded haystack derive from it; memoization and
  laziness preserved exactly — reviewer-verified against HEAD); gates green
- Reporter: reviewer (NEW-27..32 closure review, 2026-08-21)
- Owner: (unassigned)
- Problem: scan.go:85/98/103 each convert `content` independently (fast-path
  lower, folded haystack, strContent); each conversion can allocate a
  document-sized copy on large inputs.
- Fix: hoist one `strContent` and derive `lower()`/`folded()` from it.
- Verification: existing secrentel tests pass unchanged; optional alloc
  benchmark before/after (§14).


### NEW-49 (HIGH) — v1.6 Robustness and hostile-input hardening (ROADMAP v1.6)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-21): all ROADMAP v1.6
  items landed and reviewer-gated — OPT-P1-5 9575e14, OPT-P1-4 d10d719,
  OPT-P1-3 3b21401 (incl. sortQuery idempotence crasher fix), OPT-P2-6
  4e31f8d (+F1/F2 fix round), OPT-P2-4 8c795eb; dns/resolver.go descope
  recorded; acceptance criteria met (fuzz targets per parser, triage,
  property tests, regressions, -race green, bench before/after recorded).
  Follow-ups live on: NEW-53 (mechanical migrations), NEW-54 (httpprobe
  race-flake family), NEW-55 (bench TLS/DNS branches), NEW-50/51/52.
- Reporter: master
- Owner: builder (per-task dispatches)
- Problem: ROADMAP v1.6 — parsers/ingestion paths treated as untrusted-input
  boundaries. Items: OPT-P1-3 fuzz harnesses (asset ParseURL, discovery
  parse, urlintel engine, jsintel lex/parse/fetch, secrentel scan, cache,
  report, dns resolver) + property tests; OPT-P1-4 silent-truncation flags
  (MergeTLSCertificates DNSNames cap drops silently per its own doc comment
  ~tls_certificate.go:334; finding.go evidence/related/relationship caps
  16/32); OPT-P1-5 jsintel TLS sentinel (fetch.go:678 strings.Contains
  "tls:" fallback — verified still present); OPT-P2-4 hot-path allocations;
  OPT-P2-6 scope/version dedup refactor.
- Fix: batched delegation — batch 1: OPT-P1-5 + OPT-P1-4; batch 2: fuzz
  harnesses + property tests; batch 3: parser hardening from fuzz results +
  OPT-P2-4 + OPT-P2-6. Acceptance per ROADMAP v1.6 criteria.
- Verification: each batch reviewer-gated; full gates + -race per landing;
  fuzz targets run as seed-corpus tests in CI-normal `go test` (actual
  fuzzing opt-in, evidence recorded).
- Batch 1 / Task A (OPT-P1-5) IMPLEMENTED (builder session
  ses_fdbccfbd8ffeJ414r7MFpHI19n; two transport-failed dispatches before the
  successful resume): internal/jsintel/fetch.go +95/−6 — unexported
  tlsHandshakeError sentinel (Error+Unwrap) mirroring httpprobe/run.go:360-429;
  newTransport() gains DialTLSContext (dials via the transport's own
  DialContext so refused/DNS/timeout stay untagged, TLSHandshakeTimeout
  bounded, any handshake error wrapped); isTLSError: errors.As sentinel →
  existing typed checks → NEW typed tls.RecordHeaderError check → text
  fallback REMOVED. Empirical ground truth (builder, verified by reviewer
  against go1.26 toolchain source): net/http surfaces raw value-form
  RecordHeaderError and pre-existing TLS tests passed SOLELY via the removed
  text fallback — the typed check is load-bearing parity. Deliberate
  documented deviation from httpprobe: ServerName assigned unconditionally
  when empty (httpprobe's ParseIP guard makes crypto/tls reject verifying
  configs outright → every https://IP-literal fetch becomes a fabricated
  completed/tls negative; see NEW-50). Hostile-string direction-of-change
  pinned: server-controlled "tls:" text previously misclassified
  completed/tls (cacheable fabricated negative), now failed/other.
  Tests: fetch_tls_test.go (~230 lines) — parity table with real stdlib
  values incl. *tls.CertificateVerificationError wraps, hostile rows unit+
  e2e, production-transport sentinel regression, and the reviewer-nit
  discriminating IP-SAN success test (proven failing under reverted guard,
  passing restored). Reviewer: APPROVE WITH NITS → nit closed this session;
  no CRITICAL/HIGH; -race clean. Gates: gofmt clean, build OK, vet OK,
  focused suites ok; orchestrator full-suite gates green post-change.
- Batch 1 / Task B (OPT-P1-4) IMPLEMENTED (builder session
  ses_fdba2ce4bffemTudTvFc3pd0VU; one transport-failed dispatch before the
  successful background resume): internal/asset — TLSCertificate.DNSNamesTruncated
  + Finding.Truncated (omitempty bools, output-only: probeKey/ruleKey verified
  to hash no asset payloads → no schema bump/key change); MergeTLSCertificates
  sets its flag iff the deduped DNSNames union was CUT at 32 (exactly-at-cap →
  false); MergeFindings sets Truncated on FOUR genuinely-silent union cuts —
  evidence>16, related>32, relationships>32, plus metadata>16 (fourth cut
  found by builder, confirmed silent pre-diff by reviewer); sticky across
  chained merges; NewFinding still rejects over-cap input (never truncates).
  Adapters — httpprobe buildResult ORs cert markers into
  probe_tls_dns_names_truncated; detect buildDetectResult ORs finding markers
  into detect_finding_lists_truncated; both accumulate with existing flags,
  outcome untouched, computed on every path incl. cache replay; adapt/doc.go
  documents vocabulary + §0.6 chain. Reviewer APPROVE WITH NITS: check 1
  VERIFIED — stage flags surface via CLI stage lines (scan.go:636-649) +
  RunReport.Truncated (run.go:336), exactly the priority_groups_truncated
  convention; two non-obvious replay hazards hunted and safe (detect
  validateFinding canonical round-trip survives because NewFinding normalizes
  in place preserving the marker; httpprobe storeProbe→replay copies TLSMeta
  verbatim into sticky-OR merge). Follow-ups filed: NEW-51 (doc wording),
  NEW-52 (engine-level warm-run pin); INFO notes: exported
  HTTPProbeTLSDNSNamesStickyFlag deviates from repo-wide unexported adapter
  pattern (matches its own file's precedent, unused externally — optional
  future cleanup alongside HTTPProbeStickyFlag); markers hand-settable on
  literals is out-of-contract usage, doc comments scope it accurately.
  Gates: gofmt clean, build/vet OK, asset+adapt suites ok incl. -race;
  orchestrator full-suite + race green post-change.

- Batch 2 (OPT-P1-3 fuzz harnesses + property tests) IMPLEMENTED (builders
  ses_fdb856014ffeclxaS731gQjYZT [2a: asset/discovery/urlintel] +
  ses_fdb856013ffeAd6ArIEaGT7kec [2b: jsintel/secrentel/cache/report]; one
  transport-failed dispatch each, recovered via session-resume):
  EIGHT native go fuzzing targets, all asserting real invariants inside the
  body (not no-panic-only), all passing as ordinary seed tests under plain
  `go test`: FuzzParseURL (22 seeds; re-parse→identical Identity + String()
  fixed point), FuzzParseHostLines (identity re-validation through
  asset.NewHost — no second normalizer; strictly-ascending output;
  determinism), FuzzParseRawURL (urlintel engine.go:554ff verified PURE;
  credential-redaction postcondition Original==canonical, no @ in hostport),
  FuzzParseSource (jsintel lexer/parser; maxParseInputBytes both directions;
  Truncated-honesty contrapositive; scan-budget termination),
  FuzzScanDocument (production patterns.Load; candidate cap; (type,value)
  dedup), FuzzStoredRecordDecode (cache readEntry/evaluate/self-heal:
  garbage never served valid, corrupt entries physically removed),
  FuzzRenderCSV (rectangular strict-reader output incl. formula-injection
  hostile strings; byte-determinism), FuzzErrorContext (fixed category
  vocabulary; normalize bounds). Property tests (asset/property_test.go):
  testing/quick parse→Identity→parse round-trip (2000 cases + 11-row
  fixed-point table), merge idempotence ×6 kinds (+commutativity where
  documented), dedup invariants with exact-value pins. Reviewer verified
  non-vacuous. FUZZ CRASHER → PRODUCTION FIX (see commit d10d719-successor):
  sortQuery sorted by decode of the RAW key, falling back to raw on invalid
  percent escapes while emission rewrote keys (' '→%20) → canonicalization
  NOT idempotent ("A://0? %0& 0" oscillated between two identities across
  parses) → MergeURLs refused merges of identical logical URLs. Fix: sort by
  decode of the EMITTED key form. Reviewer mechanically verified: brute-force
  over 4,146 adversarial keys — new sort key byte-identical to old whenever
  old decode succeeded; fixed-point convergence after ONE canonicalization
  for the buggy class (replica-proven); sibling-bug hunt clean (values never
  ordered; Identity() consumes canonical form; §0.5 intact); cache split is
  miss→recompute→self-heal only, false hits impossible. Crash input kept as
  regression corpus internal/asset/testdata/fuzz/FuzzParseURL/11c448db5136086d.
  Fuzz evidence: 20s/target campaigns post-fix all PASS (~94k-157k execs/s;
  FuzzErrorContext ~2.78M execs). dns/resolver.go descope note: its only
  boundary is network I/O behind net.Resolver — no pure parse function to
  fuzz; recorded here as the honest OPT-P1-3 disposition for that cited site.
  Reviewer APPROVE WITH NITS (zero findings above INFO: one non-discriminating
  fixed-point table row = coverage redundancy; equal-decode tie ordering
  pre-existing/documented). Gates: gofmt clean, build/vet OK, focused suites
  ok incl. -race; orchestrator full-suite + race green post-change.
- Batch 3 (OPT-P2-6 + NEW-46 + OPT-P2-4) IMPLEMENTED (builders
  ses_fdb52d166ffee3dqJAS5DZQ9um [3a] + ses_fdb39b8f1ffeoLygbCw6NMmjjf [3b];
  three transport-failed dispatches before 3a landed via reduced-scope retry;
  3b first-try): 3a — asset.InDomain + discovery.VersionPattern/ExtractVersion
  single homes (duplication verified real: inDomain x4 incl. one dead copy,
  versionPattern x3 byte-identical); validateScope triplicate deliberately NOT
  unified (pinned per-package error prefixes); NEW-46 conversion hoist;
  reviewer APPROVE WITH NITS → F1 (InDomain empty-input guard divergence from
  guarded copies) + F2 (doc tense) closed same session; remaining migrations
  filed NEW-53. 3b — techintel lowered-target cache (183→78 allocs/op on the
  match-indicator hot path, −4% ns/op; measured build-time tradeoff +2.7%
  HTMLParse); three §14 declines with benchmark evidence (priority
  marshalSurface rare-path tie-break; httpprobe TLS clone 112ns vs ms
  handshakes; event bus publish already 0 allocs and fan-out-under-lock IS
  the sequence-ordering guarantee — premise false); reviewer APPROVE WITH
  NITS after branch-by-branch verification. Also surfaced: httpprobe -race
  flake family reproduced on clean HEAD (3-of-4 stashed runs, varying tests)
  → NEW-54; bench TLS/DNS branch gap → NEW-55.

### NEW-37 (HIGH) — chaos adapter discarded 1,047 of 1,048 subdomains: v0.5+ output shape unhandled (internal/discovery/chaos.go)
- Status: VERIFIED — fixed in 0dc7611 (parseChaosLines expands subdomains array against queried domain; FQDN elements as-is; legacy shapes preserved; live-verified 1,044 hosts on verily.com). Entry restored to the archive 2026-08-21: both copies were lost in the NEW-43 duplication cleanup; text reconstructed from session records.
- Reporter: master (field trial 2, NEW-36)
- Problem: chaos v0.5.2 -json emits ONE object {"domain":"<apex>","subdomains":[...],"count":N}; the adapter read only "domain" → apex-only. Real cost: verily.com corpus was built from subfinder's 1,036 hosts alone; every unique chaos find (e.g. wildcard.verily.com, grudge-pandemic.verily.com) was missing from dns/probe/urllive.
- Fix: parse subdomains array; expand labels against domain; FQDN elements as-is; legacy + text fallbacks kept.
- Verification: TestChaosParseSubdomainsArray/FQDNNotDoubled/LegacyApexOnly hermetic; live chaos-only discover run = 1,044 hosts.

### NEW-50 (MED) — httpprobe DialTLSContext leaves ServerName empty for IP-literal targets: local config rejection recorded as a TLS negative without any handshake (internal/httpprobe/run.go)
- Status: VERIFIED — fixed in 5afda03 (ServerName unconditional when empty, net/http addTLS semantics; discriminating IP-SAN test proven failing pre-fix by builder AND independently reproduced by reviewer)
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

### NEW-54 (MED) — `go test -race ./internal/httpprobe/` intermittently fails on clean HEAD across varying tests (internal/httpprobe)
- Status: VERIFIED — root-caused to eager test fixtures (go1.26 readLoop Peek vs numExpectedResponses window), NOT production code; awaitClientRequest (16 KiB / 5 s bound) closes the window; baseline 3 FAIL/12 race runs → 10/10 full-package greens post-fix
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

### NEW-45 (LOW) — comma-only dnsx_resolvers value raises no ignored-flag (internal/pipeline/adapt/dns.go)
- Status: VERIFIED — fixed in 8dffa1c (dnsBruteResolvers third return `supplied`; comma-only rows pinned; end-to-end flag regression fails pre-fix)
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
- Status: VERIFIED — fixed in 8dffa1c (dns_brute_skipped_cancelled sticky flag on probe-ctx cancellation; flag-over-fold per doc.go conventions; merge-path completeness traced; outcome untouched pinned)
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
- Status: VERIFIED — fixed in 8dffa1c (scan --dry-run side-effect-free: no cache open, no output-dir creation; effective bounds via WithDefaults match runner enforcement; zero-invocation proven via seam counter; help documents Discovery.Timeout + --timeout + amass-via---sources per NEW-41)
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

### NEW-17 (INFO) — scan summary may list interrupted-render temp files (internal/cli scan.go reportFiles)
- Status: VERIFIED — fixed in 8dffa1c (reportFiles filters .ravenrecon-report- literal mirroring internal/report's unexported tmpPrefix; drift window documented in-code — see reviewer nit)
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

### NEW-16 (INFO) — a nil jsintel transport dials the network once httpprobe recorded probe targets; hermetic run-level tests must substitute the transport (internal/pipeline/adapt/httpprobe.go, jsintel.go, internal/cli/scan_test.go)
- Status: VERIFIED — resolved via documentation route in 8dffa1c (Network-hermeticity note in adapt/doc.go + NewJSIntelStage constructor comment; nil transport still dials — hermetic tests must substitute the RoundTripper seam)
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

### NEW-51 (LOW) — adapt/doc.go overstates marker exposure as "the report" (internal/pipeline/adapt/doc.go)
- Status: VERIFIED — fixed in 8dffa1c (doc.go exposure wording matches run.go/scan.go behavior)
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

### NEW-4 (INFO) — TestProbeCompletedHTTPS intermittent flake (internal/httpprobe)
- Status: VERIFIED — CLOSED 2026-08-21: family root-caused under NEW-54 (eager test fixtures vs go1.26 readLoop Peek window; production exonerated); fixture fix 5afda03; orchestrator ran the entry's own bar: 20/20 consecutive `go test -race -count=1 -run TestProbeCompletedHTTPS` green post-fix
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

### NEW-52 (LOW) — engine-level warm-run pin for marked assets missing (internal/detect, internal/httpprobe)
- Status: VERIFIED — fixed in 321c55d (test-only pins: detect crafted-record warm decode + full-chain zero-re-execution pin; httpprobe crafted TLSCertificate replay pin; both proven load-bearing via revert probes — reviewer verified the load-bearing link statically)
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

### NEW-53 (LOW) — remaining dedup migrations after OPT-P2-6 single homes landed (httpprobe/crawl/pipeline/urlintel-adapt/jsintel-adapt)
- Status: VERIFIED — fixed in 321c55d (all five mechanical copies migrated; single non-test definition per concept grep-verified; validateScope triplicate untouched per documented decision)
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

### NEW-55 (LOW) — BenchmarkMatchIndicatorAllKinds exercises no TLS/DNS branches (internal/techintel)
- Status: VERIFIED — fixed in 36d22ca (fixture TLS/DNS seams fire real DB indicators; runtime sanity gate enforces ≥1 match per family; workload change disclosed: 78→84 allocs/op is more measured work, not regression)
- Reporter: reviewer (OPT-P2-4 review, NEW-49 batch 3b)
- Owner: (unassigned)
- Problem: benchFullObservation sets no TLS/DNS block, so the TLS issuer/CN/
  ALPN and DNS-CNAME lowered-slice branches execute zero iterations — an
  allocation regression reintroduced only in those branches would not move
  the benchmark. Correctness remains covered by unit tests; coverage nicety.
- Fix: add a synthetic TLS/DNS block to the bench fixture.
- Verification: benchmark iterates those branches (assert ≥1 match fires from
  each family); numbers recorded.

### NEW-35 (note) — reviewer observations, non-mandated batch (mixed packages)
- Status: VERIFIED + CLOSED (orchestrator, 2026-08-21) — all six items
  addressed: #2/#3 in 5afda03 (bounded drain + stdlib pin); #1 declined-with-fix
  in f0ad0ca (WARN/new-status rejected on contract analysis — pipeline would
  execute chaos keyless; Reason enrichment applied instead); #4 f0ad0ca
  (maxParameterSources=64 + sticky SourcesTruncated); #5 f0ad0ca (direct
  WithTimeout); #6 f0ad0ca (dead line removed). Reviewer APPROVE per item.
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

### NEW-58 (LOW) — C-4 drift detectors missing for detect/report caps (internal/detect, internal/report)
- Status: VERIFIED — implemented (builder session ses_fda40ee7cffeIG9invXq9imvcA)
  and orchestrator-verified 2026-08-22: both in-package detectors follow the
  established exemplar pattern; constants verified code↔doc before pinning
  (detect.maxFindingsPerRun=4096 at engine.go:30 ↔ C-4 "detect 4096 findings";
  report.maxModelPerKind=100_000 at model.go:31 ↔ C-4 "report 100k/
  modelPerKind"); perturbation evidence shows each detector fails naming
  constant, actual value, expected value, and doc source; gofmt/vet/build/
  full test suite green.
- Reporter: builder (v1.7 batch D, NEW-56)
- Owner: builder
- Problem: every other C-4-documented cap gained an in-package bounds_c4_test.go
  drift detector in batch D; detect and report did not because those packages
  were scope-restricted mid-task. Their constants are unexported, so detectors
  must be in-package.
- Fix: add bounds_c4_test.go to both packages pinning the documented values.
- Verification: tests pass; constants drift would fail them.
