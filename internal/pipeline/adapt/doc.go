// Package adapt wraps the RavenRecon library engines into pipeline.Stage
// implementations (v1.3 T2b). Each adapter is a thin, honest translation
// layer: it consumes the shared corpus from StageInput, constructs the
// engine's Config from the resolved bounds, cache, and clock, invokes the
// engine, and maps the engine's report back onto the pipeline's fixed
// outcome vocabulary (AGENTS §0.6) and corpus Additions.
//
// Adapter contract (all adapters in this package follow it):
//
//   - Name returns the matching pipeline.StageName constant (discover, dns,
//     httpprobe, ...). Adapters are constructed explicitly — there is no
//     global registry (pipeline stages are always passed to Run as a slice).
//   - Engine config is derived from StageInput only: Concurrency/QueueSize/
//     Timeout/Rate/Burst from Bounds (0 meaning "engine default/disabled"
//     per the engine's own documented semantics — NOT pre-resolved
//     pipeline defaults, because the engines' zero semantics differ from
//     the pipeline's), Cache passed through (nil = caching disabled, which
//     every engine supports), Clock passed through.
//   - Discovery is the odd engine out: its time seam is func() time.Time,
//     not runtime.Clock. The adapter bridges it: Now = func() time.Time {
//     return in.Clock.Now() }.
//   - Test seams are carried as constructor hooks (nil = production
//     behavior): discovery's Runner/LookPath, dns's Resolver, httpprobe's
//     Transport. Tests inject hermetic fakes through these — never through
//     StageParams (params are operator configuration, not test plumbing).
//   - StageParams (in.Config) is read defensively: each adapter documents
//     its keys and ignores unknown ones.
//   - Boundary filtering is mandatory at BOTH sides of every adapter that
//     consumes or produces hosts: the engines validate the whole host list
//     against the target and reject the entire call on any out-of-domain
//     host, so input hosts are pre-filtered with pipeline.FilterHosts; and
//     out-of-domain hosts produced by an engine (e.g. cross-domain CNAME
//     targets) are filtered out of Additions before propagation. Filtering
//     uses pipeline.InDomain/FilterHosts on canonical names only — the
//     single normalization point stays in internal/asset.
//   - Outcome mapping is faithful and documented per adapter: the engine's
//     own status vocabulary maps onto the five-value pipeline vocabulary
//     (completed/partial/failed/cancelled/incomplete), and any engine-level
//     truncation/overflow marker maps to Truncated=true plus the engine's
//     documented sticky-flag name, never swallowed (AGENTS §0.6).
//   - ItemsProcessed/ItemsFailed are the engine report's honest counts.
//   - Errors: engine errors are wrapped with context ("stage %s: %w") and
//     returned; cancellation is reported through Outcome cancelled with the
//     context error, exactly as the pipeline contract documents.
//
// Unified outcome mapping (T2b review: MEDIUM-1 / LOW-3 / INFO-2). Every
// adapter in this package maps the engine's own status vocabulary onto the
// pipeline's five-value vocabulary (AGENTS §0.6) with exactly this shape —
// the ONE mapping table T2c copies:
//
//	discovery per-source status (discovery.SourceResult.Status):
//	  OutCompleted  → completed
//	  OutPartial    → partial   (+ Truncated + the discovery_truncated
//	                             sticky flag when the engine's Truncated
//	                             marker is set)
//	  OutFailed     → failed
//	  OutCancelled  → cancelled
//	  OutSkipped    → incomplete  (the ONLY adapter-incomplete: a source
//	                               never ran — the retained set is
//	                               incomplete by definition)
//
//	dns/httpprobe per-host status:
//	  StatusCompleted  → completed
//	  StatusIncomplete → partial   (+ Truncated + the engine-specific
//	                                sticky flag when the engine's
//	                                truncation marker is set)
//	  StatusFailed     → failed
//	  StatusCancelled  → cancelled
//
//	stage fold precedence (cancelled > failed&&!completed > completed >
//	partial): cancelled if any host/source was cancelled; else failed if any
//	failed and none completed; else completed if every host/source completed;
//	else partial. This is the pipeline runner's own foldOutcome shape
//	(run.go) with the incomplete bucket reserved for discovery's OutSkipped
//	and the runner's truncation downgrade — the adapters themselves never
//	emit incomplete.
//
// Sticky-flag naming convention: a truncation flag is <engine>_<what>_
// truncated — dns_answers_truncated (dns.go), probe_truncated (httpprobe.go),
// discovery_truncated (discovery.go), urlintel_parameters_truncated
// (urlintel.go) — never a bare generic like "truncated", which could collide
// across engines in the report's StickyFlags map.
//
// v1.3 note: IP assets are not part of the pipeline corpus, so the
// httpprobe adapter passes a nil ips map (the ip→port relationship edges
// that the engine derives from caller-provided addresses are deferred
// until the corpus carries IPs). The engine's own report still flows the
// resolved addresses, ports, services, TLS certificates, endpoints, and
// relationships through the results channel (T3d — see buildResult).
//
// T2c conventions (urlintel / techintel / jsintel):
//
//   - urlintel consumes the declared target (in.Target) and in.Domains,
//     selects its historical-URL tool via StageParams["tool"]
//     ("gau" | "waybackurls" | "waymore"; absent = the documented default),
//     ingests the tool's line stream, and produces Additions.URLs (in-domain
//     filtered). Parameter extraction (ParseParameters, default true) is
//     retained in the engine report; corpus propagation carries URLs only —
//     parameters, endpoints, and relationships flow through the results
//     channel (T3d, urlintelResults).
//   - techintel consumes in.URLs as observations (header/TLS/DNS metadata;
//     the pipeline never fetches bodies — D3) and produces NO corpus
//     additions: its technology/evidence/relationship outputs flow through
//     the results channel (T3d). Truncation/overflow flags are preserved
//     honestly (AGENTS §0.6).
//   - jsintel consumes in.URLs as candidates and produces bounded
//     Additions.URLs (jsintel → Additions.URLs feedback edge,
//     jsintel_url_overflow, via filterURLs) plus results/documents:
//     scripts/endpoints/secret candidates flow through the results channel,
//     and the retained bodies flow through the document channel (T3d — the
//     stage is the pipeline's document producer). Bounded truncated fetches
//     and URL overflow report truncation honestly.
//   - secrentel is NOT in this batch: the pipeline corpus carries no
//     document content, so a meaningful adapter requires the
//     results/document channel (T3); a no-op stage would violate the
//     no-placeholder rule (AGENTS §5).
//
// T3b conventions (the results channel):
//
//   - Stages ADD to the results channel through StageResult.Results —
//     nil/empty fields are legal and mean "nothing added". The runner
//     merges additions into the channel handed to the remaining stages
//     and the final report (first-seen dedup keyed by canonical identity
//     — the asset Identity() "kind:value" string, Relationship.ID(), and
//     the priority SurfaceAsset.Identity / Group.Anchor / AttackPath.Root
//     identities — deterministic first-seen order, merged even from
//     failed/partial stages, mirroring corpus Additions).
//   - MaxOutput is enforced per result channel per stage AT THE MERGE
//     (not inside the adapter): after each stage's merge every channel
//     holds at most MaxOutput entries, and every cut channel records its
//     <channel>_truncated sticky flag + report.Truncated (AGENTS §0.6
//     carve-out; flag vocabulary: ips, ports, services, endpoints,
//     javascript, parameters, technologies, secrets, evidence, findings,
//     tls_certificates, source_maps, relationships, surfaces, groups,
//     attack_paths). Adapters therefore do NOT cap their Results; an
//     adapter that cuts its OWN retained results (a different, stage-side
//     cut) keeps the existing discipline: outcome partial/incomplete or
//     its own sticky flag — never silently completed.
//   - StageInput.Results is read-only: the runner passes its live merged
//     slices, so an adapter that mutates them corrupts later stages and
//     the final report (identical contract to the corpus slices).
//   - The secrentel adapter (T3c) was the first Results producer — secret
//     candidates, evidence, and relationships (never rebuilt; the engine
//     report's canonical assets are copied into the channel). The remaining
//     producers and the report stage's consumption of the full Context are
//     wired in T3d (per-field producers documented on pipeline.Results).
//
// T3d conventions (adapter results production/consumption):
//
//   - Every producer adapter copies its engine report's canonical Phase 2
//     assets into the results channel through the report's own merged
//     accessors — never rebuilt (AGENTS §0.5). The per-adapter channel
//     sets are pinned by the adapters' tests and documented in the
//     adapters' build functions: dns → IPs; httpprobe → IPs, Ports,
//     Services, Endpoints, TLSCertificates, Relationships; urlintel →
//     Parameters, Endpoints, Relationships; techintel → Technologies,
//     Evidence, Relationships; jsintel → JavaScript, SourceMaps,
//     Relationships plus Endpoints/Secrets/Technologies/Evidence derived
//     from the per-entry lists (deduplicated by canonical identity and
//     sorted — the report exposes no merged accessors for those);
//     priority → Surfaces (one per completed asset result), Groups
//     (Correlate), AttackPaths (AttackPaths); detect → Findings. The
//     results-channel additions are computed on EVERY path — success and
//     engine-error — so a failed stage's honest retained results still
//     merge (mirroring the corpus/Additions semantics). The ONE exception
//     is the jsintel adapter's engine-error branches (mapResult): those
//     return a bare failed/cancelled StageResult — results AND documents
//     are dropped there (pre-existing T2c behavior, honestly documented on
//     buildJSResult), because the engine returned no usable report on those
//     paths.
//
//   - The jsintel stage is the pipeline's document-channel producer:
//     Config.RetainContent is always enabled, and the engine's retained
//     bodies (Report.RetainedContent — bounded per entry by the engine's
//     2 MiB default MaxJSBytes, equal to pipeline.MaxDocumentBytes, so the
//     pipeline's hostile-producer guard never fires on engine output)
//     become pipeline.Documents with the canonical JavaScript asset
//     identity (asset.Identity{Kind: KindJavaScript, Value: the canonical
//     URL string}) and Truncated always false — retention only ever
//     carries complete bodies. The identity is keyed to the URL, not to
//     the retained body's classification: a body that is not itself
//     JS-classified (e.g. fetched HTML) still yields a document with the
//     JavaScript-kind identity of its URL, so a document identity without
//     a corresponding Results.JavaScript asset (the engine records JS
//     assets only for JS-classified observations) is a documented
//     contract, not a surprise. The consumer adapters (secrentel) and the
//     report stage treat the document channel exactly as T3c documents.
//     External-host URL observations (entry.URLs values on CDN/external
//     hosts, e.g. wss://example.com/socket or http://cdn.example.net/x)
//     are deliberately NOT propagated: there is no Results URL channel,
//     the observations never become documents or JavaScript assets (the
//     document and JavaScript channels carry exactly the fetched files),
//     and only in-scope REST endpoint candidates are retained — pinned by
//     the jsintel results/documents production test.
//
//   - Channel production/consumption at a glance (producer → consumer;
//     "report" is the report stage's full-Context consumption):
//
//     channel           producer(s)                                   consumer(s)
//     IPs               dns, httpprobe                                report
//     Ports             httpprobe                                     report
//     Services          httpprobe                                     report
//     Endpoints         httpprobe, urlintel, jsintel                  detect, report
//     JavaScript        jsintel                                       detect, report
//     Parameters        urlintel                                      report
//     Technologies      techintel, jsintel                            detect, report
//     Secrets           jsintel, secrentel                            detect, report
//     Evidence          techintel, jsintel, secrentel                 detect, report
//     Findings          detect                                        report
//     TLSCertificates   httpprobe                                     report
//     SourceMaps        jsintel                                       report
//     Relationships     httpprobe, urlintel, techintel, jsintel,      detect, report
//     secrentel
//     Surfaces          priority                                      report
//     Groups            priority                                      report
//     AttackPaths       priority                                      report
//
//     (The document channel is the pipeline-internal jsintel → secrentel
//     flow; see T3c. The corpus edge is jsintel → Additions.URLs feedback edge
//     (bounded via filterURLs, jsintel_url_overflow); see T2c.)
//
//   - Consumer adapters apply NO additional scope filtering on the results
//     channels: results are pipeline-composed (each producer filtered its
//     own inputs), and relationship edges cannot be meaningfully
//     scope-filtered without corrupting the graph. The detect adapter
//     feeds the snapshot channels the engine consumes (relationships,
//     evidence, technologies, secrets, JavaScript, endpoints — findings
//     are the engine's own output, never re-consumed, and the remaining
//     channels have no snapshot counterpart), and its empty-input
//     short-circuit fires only when the corpus AND the snapshot-feeding
//     results channels are all empty. The report adapter composes the full
//     report.Context from the corpus plus the whole results channel
//     (error/runtime/cache/execution stats stay empty — no pipeline
//     counterparts).
//
//   - Priority truncation: the priority engine reports no scoring caps,
//     but Correlate's run-level truncation (groups beyond its fixed
//     maxCorrelationGroups) maps to Truncated + the priority_groups_
//     truncated sticky flag on the producing stage — the flag, never the
//     outcome alone, marks the retained set incomplete (AGENTS §0.6).
//     Group-level member truncation (Group.Truncated) rides on the group
//     values only. Dedup on the Groups/AttackPaths channels is first-seen
//     per anchor/root (pipeline.Results), never a truncation (FIND-2).
//
// T3c conventions (the document channel and the secrentel adapter):
//
//   - The pipeline-internal document channel (StageResult.Documents /
//     StageInput.Documents / RunReport.Documents) carries bounded retained
//     script bodies: Document{Identity, URL, Content, Truncated}, content
//     bounded by pipeline.MaxDocumentBytes (2 MiB, the secrentel engine's
//     own ingest cap), merged by the runner like the corpus/results
//     channels (first-seen dedup keyed by the canonical identity string,
//     deterministic order, per-stage MaxOutput cap; a cut records the
//     documents_truncated sticky flag + report.Truncated — AGENTS §0.6
//     carve-out). Content is merged BY REFERENCE, never copied, and is
//     never exposed on the report Context (only the derived secret
//     candidates/evidence are).
//   - Hostile-producer guard at the merge: over-cap content (>
//     MaxDocumentBytes) is dropped WHOLE — Content nil + Truncated — never
//     a partial prefix; the document still merges (identity/URL remain).
//   - No adapter produced documents until T3d: the jsintel stage family is
//     now the producer (NEW-15 resolved: a pipeline-internal document
//     channel, separate from the Results channel; secrentel consumes the
//     channel, never the Results.JavaScript field).
//   - secrentel (NewSecretIntelStage) consumes the document channel as
//     its document source: every pipeline document becomes one
//     secrentel.Document with Kind KindJS, Content/URL passed through,
//     SourceAsset = the pipeline document's canonical Identity (the
//     engine's jsintel dedup contract — candidates whose Source is that
//     identity deduplicate against jsintel's own), Source left "" (the
//     engine's default "secrentel"). Truncated and nil-content documents
//     are SKIPPED — nothing honest to scan (never silently completed).
//     No scope filtering: the channel is the pipeline's own, in-scope by
//     construction (contrast with the corpus-consuming adapters).
//   - Per-document analysis caps stay at the engine defaults (64
//     candidates, 8 evidence per candidate) — deliberately not
//     configurable. Overflow (a document with >= 64 candidates) maps to
//     Truncated + the secrentel_overflow sticky flag; the engine's
//     Truncated signal is unreachable through this adapter (bounded
//     pipeline content, truncated documents skipped) but maps to
//     secrentel_truncated anyway so no engine signal is ever swallowed.
//     The flags replay from cache hits end-to-end (the engine's §0.6
//     chain is verified intact: record write → replay → sticky merge →
//     report exposure), so completed + flag is the legal carve-out.
//   - Outcome/counters/error mapping mirrors the T2c adapters exactly
//     (fold: cancelled > failed&&!completed > incomplete&&!completed >
//     completed-vacuous > completed-mixed > unknown→failed; ItemsProcessed
//     = completed+incomplete+cancelled+failed; ItemsFailed =
//     failed+malformed). The engine's offline verification queue is never
//     executed and never propagated (T6). No events are emitted — the
//     runner owns stage events.
//
// T2d conventions (priority / detect / report):
//
//   - priority consumes the in-scope corpus (domains, hosts, URLs) as one
//     priority.Signal per asset — domains/hosts contribute their canonical
//     name as the hostname field, URLs contribute path, hostname, and the
//     parameter names derived from the canonical query string (the corpus
//     URL asset carries the query; the derivation is deterministic because
//     the canonical query's keys are sorted). Catalogs come from the
//     constructor seam: nil/nil = production tables; a single provided
//     catalog is completed with an explicit EMPTY counterpart (the engine
//     digests the pair and rejects a nil catalog). Produces NO corpus
//     additions: surfaces/groups/attack-paths flow through the results
//     channel (T3d — buildPriorityResult, with the correlation-cut flag).
//   - detect consumes the in-scope corpus as core-graph asset identities in
//     the engine snapshot (domains/hosts/URLs) plus the results channel's
//     snapshot values — relationships, evidence, technologies, secrets,
//     JavaScript, and endpoints (T3d; findings are the engine's own output,
//     never re-consumed). The registry comes from the constructor seam:
//     nil = the EMPTY registry (D2 — no rules ship with the framework).
//     The empty-input short-circuit fires only when the filtered corpus,
//     the snapshot-feeding results channels, AND the registry are all
//     empty: rules without RequiredAssetTypes genuinely execute against a
//     non-empty corpus, so an empty corpus alone never skips the engine.
//     Produces NO corpus additions: findings flow through the results
//     channel (T3d). FindingsTruncated (the engine's fixed
//     maxFindingsPerRun cap) maps to Truncated + the
//     detect_findings_truncated sticky flag; the engine reports the
//     truncated run's outcome as incomplete, so the stage reports partial
//     with the flag set.
//   - report consumes the in-scope corpus into the engine Context
//     (Target/StartedAt/EndedAt/Domains/Hosts/URLs — StartedAt and EndedAt
//     are both the stage's single honest clock "now", because the pipeline
//     tracks no run bracket yet) plus the whole results channel (T3d —
//     every data channel; the error/runtime/cache/execution stats channels
//     have no pipeline counterparts). The registry comes from the
//     constructor seam: nil = the engine's default registry (json, csv,
//     markdown, html). The stage NEVER short-circuits: rendering the
//     (possibly empty) report is its work, so the engine always runs.
//     OutputDir passes straight through (in.OutputDir); an empty OutputDir
//     is the engine's validation error → failed. The report engine has no
//     Rate/Burst configuration, so those bounds are unused by this stage.
//     Produces NO corpus additions (it writes files).
//   - Truncation absence, pinned: the report engine reports no
//     truncation/overflow signals through this adapter's input path (the
//     renderer has no retention caps), so that adapter never sets
//     Truncated or a sticky flag — a future engine cap must surface there
//     (AGENTS §0.6). The priority adapter's only truncation signal is the
//     correlation cut (priority_groups_truncated, T3d).
//   - The declared target itself is never added to any engine input: the
//     engines run over the corpus as the earlier stages produced it — the
//     target domain is scored/detected/reported only when the corpus
//     carries it.
//
// # T4 — determinism, discovery clock seam
//
// The full ten-stage pipeline with the REAL discovery adapter (T3d3 used a
// seed stage under the discover name by contract) is pinned deterministic:
//
//   - Per-source discovery result order is selection order at ANY pool
//     concurrency: the engine pre-allocates the Results slot array and each
//     job writes only its own slot (internal/discovery/pipeline.go) — never
//     pool-completion order. The merged corpus therefore is byte-identical
//     across racing runs, and the nine downstream stages consume it
//     identically. Proven by TestT4FullRunDeterminismWithRealDiscovery:
//     three identical runs (discovery at Concurrency 4) DeepEqual pairwise,
//     every corpus host's provenance DiscoveredAt is the injected clock
//     instant with the tool-name source (earliest-wins provenance merge;
//     ties resolve to the first-encountered source in selection order).
//   - The discovery stage's clock bridge is the ONLY clock the engine can
//     see: the adapter passes Now = in.Clock.Now, and the engine's
//     time.Now defaults fire only when the seam is nil (never, through
//     this adapter). No wall clock reaches the report; the pool's own
//     rate-limiter wall clock (runtime/pool.go) only gates job starts and
//     with the pipeline's default Timeout 0 never changes an outcome.
//   - Cache-hit vs execute parity holds end-to-end: a warm run over the
//     same filesystem cache serves the known-version discovery sources
//     (subfinder, amass) from cache — zero discovery executions — while
//     the NON-CACHEABLE unknown-version source (assetfinder, capability-
//     probed with -h) executes fresh; the RunReport DeepEquals the cold
//     run, with zero new dns queries, http probes, and jsintel fetches on
//     the warm run (each stage's own cache-before-execute). The urlintel
//     stage's tool invocation is NOT cached by design (its per-URL
//     extraction records are), so gau runs once per run.
//   - Cache parity regression fixed in T4: asset.NewFinding normalizes an
//     absent RelatedAssets/Relationships set to nil (never an
//     empty-but-non-nil slice), so a finding replayed from a detect cache
//     record (decoded, never re-normalized) DeepEquals a freshly
//     normalized one — the detect engine's cache-hit vs execute
//     representation mismatch the full-run parity test caught.
//
// # T5 — hermetic full-run E2E (partial failure and retry)
//
// The v1.3 acceptance criteria "End-to-end tests cover success, partial
// failure, and retry paths" (success pinned by T3d3) and "Intermediate
// failures do not corrupt the final report" are pinned at the FULL-RUN
// level in t5_hermetic_e2e_test.go, through the REAL adapters over
// hermetic fixtures — INCLUDING the real discovery stage (NewDiscoveryStage
// over the T4 seam: a scripted fake discovery.Runner plus the fake
// LookupFunc constructor hook, exactly t4_determinism_test.go's harness;
// no executables, no network). The T3d3 seed-stage exclusion is gone: the
// discovery stage genuinely runs on every T5 run, reports hosts-only
// additions (Additions.Domains stays empty — the declared target lives in
// StageInput.Target, adapt/discovery.go), and must report completed so the
// injected failure stays where the retry contract puts it: the dns
// per-host resolver failure for exactly ONE host.
//
//   - Failure injection (deterministic, hermetic): a typed per-host
//     resolver failure for exactly ONE of the three discovered hosts, on
//     every record type the dns engine queries (A/AAAA/CNAME). A plain
//     error classifies as TypeFailed (dns.applyAnswers default branch),
//     so all three types fail -> the host is dns.StatusFailed ("no
//     usable observations") -> the adapter folds partial
//     (anyFailed && anyCompleted) with ItemsFailed = 1 -> the runner
//     folds partial + 9 completed to a PARTIAL run (never failed, never
//     completed). The failure is a failure, never a truncation: no
//     Truncated marker, no sticky flags — asserted explicitly
//     (AGENTS §0.6).
//   - Corpus shapes with real discovery (T4-pinned): 0 domains, 3 hosts
//     (admin/api/www, merged in the discovery engine's sorted All()
//     order, with injected-clock tool-name provenance), 9 URLs (6 probed
//     roots + 3 urlintel additions), 12 priority surfaces (3 hosts + 9
//     URLs — discovery adds no domain surface), one group of 12 members
//     anchored at domain:example.com, one attack path. The failing host
//     stays in the corpus (a failed host is still a reported host); only
//     its observations disappear (IPs = 2).
//   - Partial-failure E2E (TestT5FullRunPartialFailure): run outcome
//     partial; the discovery stage's own record is completed (5 processed
//     per-source hosts, 3 executions); the failing stage's record is
//     honest (partial, ItemsFailed 1, nil Err — per-host failures fold
//     into the outcome); every later stage completes and the report is
//     produced; the retained sets are honest (the failed host contributes
//     no IP — the IPs channel carries exactly the two surviving hosts'
//     addresses — and every surviving host's downstream work is present
//     and complete); the captured report model is complete and internally
//     consistent; stage events fire for every stage with the failing
//     stage's finished payload mirroring its StageRecord; a second
//     identical run DeepEquals the first, including the event stream.
//   - Retry E2E (TestT5FullRunRetryHealing / TestT5FullRunRetryPersistent):
//     the healing scenario uses a stateful resolver fixture (first call
//     per (host, type) fails, later calls succeed — race-free via a
//     mutex), the persistent scenario a plain scripted per-host error.
//     Both run twice over the SAME filesystem cache and count resolver
//     invocations / transport requests / jsintel fetches / gau runs /
//     discovery executions to prove the split: succeeded units are served
//     from cache with ZERO re-execution, and the failed units are
//     RE-ATTEMPTED (exactly the failed host's 3 type queries — nothing
//     else). Discovery re-executes exactly its NON-CACHEABLE source on a
//     warm run (3 executions after the cold run, 4 after the warm run,
//     mirroring T4's cache-parity count — see below). The healed run
//     completes and DeepEquals a fresh cold run of the healed state; the
//     persistent-failure run repeats the same partial outcome and
//     DeepEquals run 1 (cache metadata is not part of RunReport).
//
// OBSERVED CACHE CONTRACT FOR FAILED JOBS (evidence; the retry
// assertions match it exactly): the dns engine stores EVERY terminal type
// classification as a statused Phase 3 record, failed ones included
// (internal/dns/run.go storeType:558-601; typeStatusToCache maps
// TypeFailed/TypeTimedOut -> cache.StatusFailed, internal/dns/cache.go
// :133-143), but the Phase 3 cache NEVER serves a non-completed record as
// a hit (internal/cache/cache.go evaluate:207-209 — anything whose Status
// is not StatusCompleted resolves to StateIncomplete), and the dns
// engine's lookupType (internal/dns/run.go:434-443) treats every non-hit
// as "execute". A failed job is therefore re-attempted on the next run —
// never cached as success, never skipped — while a completed job is
// served with zero queries. The dns engine's failed-job retry contract
// (stored-but-never-served: dns/run.go storeType, cache.go
// typeStatusToCache, cache evaluate — cited above) is pinned HERE by the
// retry tests; the remaining engines' warm parity is pinned on the
// success path only, by T4's cache-parity test (TestT4FullRunCacheHitParity).
//
// DISCOVERY NON-CACHEABLE NOTE (evidence; the retry execution counts
// match it exactly): a discovery tool whose version is unknown
// (det.Version == "") is never cached — no key, no Get, no Put — and
// executes fresh on every run (internal/discovery/pipeline.go:418-426).
// assetfinder's capability probe (-h) yields no version, so it is the ONE
// source that re-executes on a warm run; subfinder and amass (detected
// versions) are served from cache. The detection probes themselves
// ("-version"/"-h" argv forms) are detections, not discovery executions,
// and are never counted by T4's t4DiscoveryExecutions helper, which the
// T5 retry counts reuse.
package adapt
