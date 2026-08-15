// Package techintel implements the Phase 6.5 technology detection engine:
// technology detection is ROADMAP v0.6 (Active Infrastructure)'s final open
// bullet, landed as phase 6.5 after DNS (5A), HTTP probing (5B), and HTTP
// metadata normalization (the v0.7 milestone is URL intelligence). It is a
// library-level stage that consumes typed observations — headers, body,
// cookies, TLS metadata, DNS metadata — and produces typed
// technology assets, evidence records, and asset-graph edges against the
// compiled fingerprint database. It mirrors the urlintel pipeline shape
// (Config/DefaultConfig, a source seam, bounded runtime.Pool, cache-before-
// execute, merge-at-emit, bounded diagnostics, cancellation with honest
// statuses) and consumes the data-only fingerprints package — the engine
// NEVER compiles regular expressions; it only uses the compiled DB
// (MatchRe/VersionRe).
//
// # The observation model
//
// The engine never fetches. A caller composes an Observation (a canonical
// Phase 2 URL asset, an optional endpoint asset, the response status code,
// headers, body, cookies, TLS/DNS metadata, source name, observed time) and
// feeds it to Ingest. The observation's IDENTITY — the cache-key target and
// the report-merge key — is the endpoint identity when an endpoint is
// attached, otherwise the canonical URL identity. The status code is
// retained in entries and records but is deliberately NOT analyzed by any
// indicator kind, so it never enters a cache key. Body, header-value,
// cookie-, and TLS/DNS-list truncation happen at ingest with the
// observation's Truncated flag set (the result is honest); malformed input
// (a broken URL, a canonical URL longer than 32 KiB, an inconsistent
// endpoint, more than 128 header entries) is counted, never analyzed, and
// never panics.
//
// # Pipeline
//
// One bounded runtime.Pool owns all scheduling: exactly one job per
// observation, Config.Concurrency workers, bounded Config.QueueSize
// (backpressure, never unbounded memory), optional per-job deadlines and
// job-start rate limiting. The reader goroutine:
//
//  1. reads an observation (io.EOF ends the run; a source error stops it and
//     is reported);
//  2. validates and bounds it at ingest (malformed input is counted and the
//     run continues);
//  3. pre-registers a cancelled placeholder per observation identity, so a
//     forced shutdown's dropped jobs appear honestly as cancelled;
//  4. submits one bounded job.
//
// Each job: cache-before-execute (a completed hit serves the stored result
// with ZERO analysis — asserted via Metrics.Analyzed) -> analyze (cache
// miss, bounded) -> store the completed record -> merge into the entry
// accumulator -> call the optional Emit hook. Cancellation performs a
// bounded drain (per-job deadlines plus one grace period, or the force
// budget when deadlines are disabled): completed results are still persisted
// under a detached bounded store budget, queued jobs land as cancelled, and
// no worker leaks. The returned Report is deterministic: entries sorted by
// identity, every collection inside sorted.
//
// # Statuses
//
// completed, cancelled, failed (entries) and malformed (counted on the
// Report, never an entry, never cached). Only completed observations are
// stored as cache hits; failed/cancelled are never stored as success.
//
// # Analyzers
//
// One corpus extraction per observation (one HTML pass, one lowercase body
// copy, cookie parsing bounded at maxObservationCookies entries), then every
// fingerprint indicator matches against its kind's slots:
//
//	header          -> "Name: value" lines, case-insensitive substring
//	cookie          -> cookie name OR value, case-insensitive substring
//	html_regex      -> compiled regex search of the body
//	html_substring  -> case-insensitive substring of the body; the
//	                   evidence value is the matched span of the ORIGINAL
//	                   body (byte-aligned through per-rune case folding),
//	                   so non-ASCII bodies never tear evidence values
//	meta_name       -> meta tag name attribute values
//	generator       -> compiled regex search of generator meta content
//	script_name     -> script src basenames
//	script_path     -> script src values (full URL/path)
//	css_path        -> stylesheet href values
//	attribute       -> attribute names (version from the attribute value)
//	endpoint_path   -> the canonical URL path
//	tls_issuer/tls_cn/tls_alpn -> TLSInfo issuer/subject/ALPN entries
//	dns_cname       -> DNSInfo CNAME chain entries
//	sourcemap_path  -> sourceMappingURL tokens (presence-only extraction)
//
// Every match becomes one asset.Evidence (Method per the indicator kind,
// Indicator = the canonical "kind:match" key, Value bounded by
// asset.NewEvidence, Source = the observation identity) plus one weighted
// technology signal. Cookie session flags (HttpOnly/Secure/SameSite from
// Set-Cookie) are evidence-only records (indicator keys cookie_flag:*); they
// fire no technology and carry no technology edge. Set-Cookie parsing: the
// FIRST pair is the real cookie; later pairs are ingested only when they are
// REAL attributes (Path, Domain, Expires, Max-Age, SameSite, Secure,
// HttpOnly, Partitioned) — unknown directives are dropped. Flag extraction
// matches the real attributes by exact name on ';'-separated segments
// outside quoted values (both ";secure" and "; Secure" fire; a "; Secure"
// inside a quoted value never does). HTML extraction candidate
// lists are capped (scripts/css/metas 128, attributes 256, sourcemaps 32,
// generators 16); exceeding a cap flags the observation Truncated. Match
// caps: maxObservationCookies=256 (Overflow.Cookies),
// MaxIndicatorsPerObservation (evidence records, Overflow.Indicators),
// MaxTechnologiesPerObservation (Overflow.Technologies; retained in score
// desc, name asc order).
//
// # Confidence
//
// Level = High/Medium/Low/Unknown. Score = 1 − ∏(1 − wᵢ) over INDEPENDENT
// matches; independence is exactly: distinct indicator kinds OR distinct
// match slots (same kind+slot collapses to max weight). Caps: no structural
// indicator -> score capped at 0.59 (spoofable-only never exceeds Medium);
// High requires at least one structural indicator; a lone weak indicator
// (weight < 0.35) never exceeds Low. Thresholds: >=0.8 High, >=0.5 Medium,
// >=0.2 Low, else Unknown (still reported). Version comes from the
// highest-weight version-bearing matched indicator (ties: first in DB
// order); the compiled VersionRe applies to the matched value as observed
// (the attribute VALUE for attribute-kind indicators). Conflicts: n distinct
// fingerprints firing in one (kind, slot) group contribute n-1; each
// technology is retained at its own confidence; ties are deterministic
// (retention order: score desc, name asc; report-level merges walk
// entries in sorted-identity order). The conflict count is
// fingerprint-level: it includes fingerprints whose technologies were
// later dropped by MaxTechnologiesPerObservation (conflicts describe
// observed disagreement, not retention).
//
// # Cache
//
// Operation "tech.detect". Key = {operation, observation identity, the
// fingerprint database SchemaVersion, the sources bitmask (sorted letters:
// b body, c cookies, d DNS, e endpoint, h headers, t TLS)}. Bumping
// fingerprints.SchemaVersion invalidates every cached detection by
// construction. Timings, concurrency, the status code, and the fixed caps
// never enter keys; the analysis caps are bounded by decode re-checking
// retained counts against the current run's caps. On a cache HIT the
// entry's StatusCode comes from the stored record: it is never re-derived
// from the observation and never enters the key. Record CreatedAt is
// stamped from the RUN clock at store time — never from the observation's
// ObservedAt — so TTL (measured from CreatedAt) starts at store time and
// stale or future observation timestamps can neither expire a fresh
// record instantly nor make it immortal; the observation's own times stay
// in the payload (FirstSeen/LastSeen) and in asset provenance. Decode
// re-validation: identity containment (target/URL/endpoint vs the key),
// mask equality, parallel-array lengths (levels, version ordinals),
// timestamp ordering, canonical technology/evidence identities, score in
// [0,1], level never stronger than levelForScore(score), evidence methods
// possible given the mask (a body-less record can never carry HTML-derived
// evidence — the truncated-as-completed tamper class), tech->evidence links
// only to retained identities, counts within the run's caps. A rejected
// record is deleted and recomputed, never served.
//
// # Report and relationships
//
// The Report aggregates every observation: one merged Technology per
// technology identity (merged Prov.Confidence is the MAX score of the
// contributing observations; the merged level is the max-score
// contributor's, ties in entry order), evidence deduped by
// identity, relationships deduped by edge identity, per-status observation
// counts, total conflicts, sticky Truncated/Overflow flags, and the metrics
// snapshot. Per-observation entry merges (merge-at-emit) are
// merge-order-INDEPENDENT: on a technology score tie the merged contributor
// is the one winning the chain — a version-bearing contributor outranks a
// version-less one, then the earliest ObservedAt, then the lowest source
// name, then the first in DB order of the version-bearing indicator (the
// ordinal is persisted in cache records, so cache-served contributors
// tie-break identically to fresh ones), then the lowest version string,
// then the level; a failed entry's Err comes from the failed contributor
// with the earliest FirstSeen, then the lowest source name, then the
// lowest error text. Relationships: host_to_technology (hostname URLs
// only), url_to_technology, endpoint_to_technology (when attached), and
// technology_to_evidence for every match that fired the technology.
//
// # Bounds
//
// Per-observation: canonical URL 32 KiB (malformed beyond), body 1 MiB
// (truncated), 128 header entries (malformed beyond), 256 cookies (analyzer
// cap), 128/512 technology/indicator caps (config with defaults), bounded
// HTML candidates, evidence values capped by asset.NewEvidence. Per-run:
// bounded queue, bounded pool, bounded diagnostics, bounded per-entry
// errors. Everything is deterministic under any concurrency: retentions,
// merges, edges, and ordering never depend on scheduling.
//
// Cost note on html_substring: every match maps its folded span back to the
// ORIGINAL body via originalSpan, which walks the body from offset 0 —
// linear and allocation-free (runes decoded in place, never materialized),
// at most one full-body pass per walk at the 1 MiB body cap. There is one
// walk per html_substring match and the indicator budget caps the matches,
// so the worst case is ~512 full-body rune walks per observation (a
// bounded per-observation cost ceiling, not a leak; the DB's 37
// html_substring indicators make the practical maximum far smaller), and
// even that pathological case is bounded by the per-job deadline.
//
// # Known limitations
//
//   - HTML scanning is naive, by design: it walks raw markup (`<`...`>`
//     tag scans, sourceMappingURL token presence) rather than parsing a
//     document tree. Comment text and JavaScript string literals can
//     false-fire script/attribute/meta indicators (for example a JS string
//     containing `src="/app.js"`), and quoted attribute values inside tags
//     follow a simple quote model. The scan is bounded (candidate caps,
//     single pass) and fully deterministic — false positives are honest,
//     reproducible observations — but it is not a DOM parser.
//   - Ingest's cancellation unwinds the reader, pool, and drain — but only
//     if the ObservationSource honors ctx: a caller source whose Next
//     ignores cancellation and blocks forever can wedge Ingest. This is a
//     seam contract: sources must return promptly (io.EOF, or an error)
//     when ctx is done, exactly as SliceObservationSource does.
package techintel
