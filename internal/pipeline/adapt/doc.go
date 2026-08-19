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
// v1.3 note: IP assets are not yet part of the pipeline corpus, so the
// httpprobe adapter passes a nil ips map (the ip→port relationship edges
// that the engine derives from caller-provided addresses are deferred
// until the corpus carries IPs).
//
// T2c conventions (urlintel / techintel / jsintel):
//
//   - urlintel consumes the declared target (in.Target) and in.Domains,
//     selects its historical-URL tool via StageParams["tool"]
//     ("gau" | "waybackurls" | "waymore"; absent = the documented default),
//     ingests the tool's line stream, and produces Additions.URLs (in-domain
//     filtered). Parameter extraction (ParseParameters, default true) is
//     retained in the engine report; corpus propagation carries URLs only —
//     results propagation is a separate milestone.
//   - techintel consumes in.URLs as observations (header/TLS/DNS metadata;
//     the pipeline never fetches bodies — D3) and produces NO corpus
//     additions: its technology/evidence outputs are results, propagated by
//     the results channel (separate milestone). Truncation/overflow flags
//     are preserved honestly (AGENTS §0.6).
//   - jsintel consumes in.URLs as candidates and produces NO corpus
//     additions (scripts/endpoints/secret candidates are results). Bounded
//     truncated fetches report truncation honestly.
//   - secrentel is NOT in this batch: the pipeline corpus carries no
//     document content, so a meaningful adapter requires the
//     results/document channel (T3); a no-op stage would violate the
//     no-placeholder rule (AGENTS §5).
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
//     additions: surfaces/groups/attack-paths are results (T3).
//   - detect consumes the in-scope corpus as core-graph asset identities in
//     the engine snapshot (domains/hosts/URLs only — every other snapshot
//     channel needs the results/document channel, T3). The registry comes
//     from the constructor seam: nil = the EMPTY registry (D2 — no rules
//     ship with the framework). The empty-input short-circuit fires only
//     when BOTH the filtered corpus AND the registry are empty: rules
//     without RequiredAssetTypes genuinely execute against an empty corpus,
//     so an empty corpus alone never skips the engine. Produces NO corpus
//     additions: findings are results (T3). FindingsTruncated (the engine's
//     fixed maxFindingsPerRun cap) maps to Truncated + the
//     detect_findings_truncated sticky flag; the engine reports the
//     truncated run's outcome as incomplete, so the stage reports partial
//     with the flag set.
//   - report consumes the in-scope corpus into the engine Context
//     (Target/StartedAt/EndedAt/Domains/Hosts/URLs — StartedAt and EndedAt
//     are both the stage's single honest clock "now", because the pipeline
//     tracks no run bracket yet; every other Context channel needs the
//     results/document channel, T3). The registry comes from the
//     constructor seam: nil = the engine's default registry (json, csv,
//     markdown, html). The stage NEVER short-circuits: rendering the
//     (possibly empty) report is its work, so the engine always runs.
//     OutputDir passes straight through (in.OutputDir); an empty OutputDir
//     is the engine's validation error → failed. The report engine has no
//     Rate/Burst configuration, so those bounds are unused by this stage.
//     Produces NO corpus additions (it writes files).
//   - Truncation absence, pinned: the priority and report engines report
//     no truncation/overflow signals through these adapters' input paths
//     (priority's report has no retention caps; the report renderer has
//     none either), so those two adapters never set Truncated or a sticky
//     flag — a future engine cap must surface there (AGENTS §0.6).
//   - The declared target itself is never added to any engine input: the
//     engines run over the corpus as the earlier stages produced it — the
//     target domain is scored/detected/reported only when the corpus
//     carries it.
package adapt
