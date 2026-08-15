// Package urlintel implements the URL intelligence engine (roadmap v0.7,
// sub-milestone 6B): the canonical-URL streaming pipeline — parsing raw
// observed URLs into Phase 2 assets, extracting parameters and endpoints,
// classifying endpoints, caching per (URL, adapter), merging observations at
// emit time, and assembling the typed asset-graph edges — for historical
// URL sources. It is a library-level stage with no CLI command yet; tool
// adapters (external commands presented as line streams) live in the
// companion package internal/urlintel/adapt and feed this package's source
// seam. See ARCHITECTURE.md for the pipeline design context and the phase
// 5A/5B patterns this package mirrors.
//
// # The Source seam
//
// Raw strings exist only at the ingest boundary:
//
//	type LineSource interface { Next(ctx context.Context) (string, error) }
//
// Next returns io.EOF at end of stream. A line is immediately canonicalized
// into a Phase 2 asset.URL by the ingest loop — raw strings never travel
// beyond the parse stage; the pipeline, cache, report, and graph carry only
// typed assets. SliceSource wraps a []string for tests and static input.
// The companion package internal/urlintel/adapt presents external tools
// (gau, waybackurls, waymore) as LineSources over their stdout.
//
// # Pipeline
//
// One bounded runtime.Pool owns all scheduling: exactly one job per raw
// line, Config.Concurrency workers, a bounded Config.QueueSize (the reader
// blocks on a full queue — backpressure, never unbounded memory), optional
// per-job deadlines and job-start rate limiting. The reader goroutine:
//
//  1. reads a line (io.EOF ends the run; a source error stops it and is
//     reported);
//  2. rejects lines over maxRawURLLen (32 KiB) as malformed — counted,
//     reported, never cached, never fatal;
//  3. canonicalizes the line through asset.ParseURL — parse failures are
//     malformed, counted, and the run continues;
//  4. pre-registers a cancelled entry for the canonical URL (so a job
//     dropped by forced shutdown still appears honestly);
//  5. submits the per-line job: cache-before-execute (serve the stored
//     observation on a usable hit — a hit performs ZERO extraction work,
//     asserted by the benchmark harness), else extract endpoint +
//     parameters + graph, store a completed record, and merge at emit.
//
// # Cache key composition
//
// Operation "url.ingest"; target = canonical URL identity; configuration =
// adapter identity + the result-relevant ParseParameters flag. The adapter
// identity is part of the key (the user's spec): the same URL observed by
// two adapters is stored as two distinct records. Timings, timeouts,
// concurrency, and rate limits never enter a key, and the fixed caps are
// constants so records stay valid under any future caps that retain more.
//
// # Statuses
//
// Completed: canonical URL + GET endpoint + parameters + sources + first/
// last seen, stored as a completed record (Overflow flag when the parameter
// cap was hit — the record stays completed but honestly flagged).
// Malformed: raw line rejected — counted and reported, never cached.
// Failed / Cancelled: never stored as success; a second run re-works them
// (no partial record is written — there is no sub-work to resume).
// Truncated-incomplete: not a stored status in this pipeline — the caps
// (line length, parameter count) are enforced at ingest/extract time and
// flagged on completed records rather than stored as incomplete (unlike
// DNS answer caps and probe caps, an overflowed URL observation is a
// legitimate completed observation of the URL itself; only its parameter
// set is incomplete).
//
// # Merge at emit: the two-level design
//
// Level 1 (store): one cache record per (canonical URL, adapter). Level 2
// (emit): the Accumulator is keyed by canonical URL identity ONLY, so every
// observation of a URL — from any adapter, any run sharing the accumulator —
// merges into ONE report entry: sources unioned in first-observation order,
// FirstSeen = min / LastSeen = max, parameters merged via
// asset.MergeParameters, endpoints deduplicated by identity, relationships
// deduplicated by edge identity. IngestInto(ctx, cfg, src, acc) merges into
// a shared accumulator; successive calls (one per adapter, or repeated runs)
// produce the cross-adapter merged view. Ingest is the single-run wrapper.
//
// # Graph assembly
//
// Each URL entry carries typed edges: host -> url (RelationshipHostToURL,
// host derived canonically from the URL's host via asset.NewHost — IP
// literals are not hosts, so they carry no host asset and no host edge),
// url -> endpoint (RelationshipURLToEndpoint), url -> parameter
// (RelationshipURLToParameter), and endpoint -> parameter
// (RelationshipEndpointToParameter). Edges are deduplicated by identity and
// emitted sorted. Cached observations rebuild the identical graph at emit
// (host and edges are not stored; graphOf derives them deterministically).
//
// # Endpoint classification
//
// Every canonical URL classifies as exactly one endpoint: GET on the
// canonical URL (asset.NewEndpoint). The endpoint's identity is
// "endpoint:GET <canonical url>", so the query string is part of the
// endpoint. Methods beyond GET are not observable in 6B inputs — POST/PUT/
// DELETE arrivals are future-source work; the Phase 2 model already supports
// them (a future source only changes extraction, not the pipeline).
//
// # Parameter extraction rules
//
// Parameters are extracted from the canonical URL's query ONLY. The path and
// body locations are reserved by the Phase 6A model for future phases and
// are never extracted here. Names and values are taken AS-OBSERVED from the
// canonical raw query — never unescaped before identity use — so "a%20b",
// "a+b", and raw non-ASCII values remain distinct identities (the pinned
// Phase 6A semantics). Within one URL, repeated names merge via
// asset.WithValue (values deduplicated in first-seen order). Distinct
// parameters beyond maxParametersPerURL (256) are dropped and the entry is
// flagged Overflow; the Phase 2 per-parameter value cap (1024) bounds values
// inside each parameter. Query keys without an observed value ("?flag") are
// not representable in the Phase 2 model (it requires a non-empty first
// value) and are skipped.
//
// # Determinism
//
// Report entries are sorted by canonical URL string; every variable-length
// slice inside an entry is sorted by Phase 2 identity or edge ID; sources
// keep first-observation order. The report is deterministic for a given set
// of observations regardless of processing order.
//
// # Cancellation
//
// context.Context flows through everything. Cancelled mid-stream: the reader
// stops, submitted jobs are cancelled by the pool, pre-registered entries
// keep an honest cancelled status, and the pool's bounded shutdown budgets
// (timeout + 15 s grace, 30 s force) bound the drain. Lines not yet read
// from the source are never consumed and are not represented in the report.
// IngestInto returns only after every pool-owned goroutine has terminated
// (leak-tested).
//
// # Memory bounds
//
// The reader never buffers more than the pool queue (bounded); the
// Accumulator holds at most one entry per distinct canonical URL of the
// run(s), with each entry's payload bounded by the per-URL caps and its
// joined Err bounded by maxErrorsPerEntry errors plus a count tail (the cap
// applies at the merge site, so a URL repeated by any number of
// observations with persistently failing cache Puts can never grow the
// entry's error string without bound); cache records are bounded by the
// cache's own MaxRecordSize; raw lines are capped at maxRawURLLen before
// parsing. Consumers that must stream arbitrarily many distinct URLs
// without retention use Config.Emit — the report intentionally retains one
// entry per distinct URL.
//
// # Scope
//
// There is NO scope layer in 6B: urlintel accepts any canonical URL and has
// no notion of a declared target domain. Scope filtering is the CALLER'S
// obligation — exactly as the probing pipelines consume validated input, a
// caller feeds urlintel only the lines it has already scoped.
//
// # Known limitations
//
//   - GET-only classification: other HTTP methods are not observable in 6B
//     inputs (the model supports them; a future source changes extraction).
//   - Path/body parameter extraction is not performed (reserved by the
//     Phase 6A model for future phases).
//   - Value-less query keys ("?flag") are skipped: the Phase 2 Parameter
//     model requires a non-empty observed value.
//   - Raw lines over 32 KiB are rejected as malformed (not truncated).
//   - Cache keys include the adapter, so an observation with an
//     undetectable-or-missing adapter identity is never guessed: callers
//     must pass the same adapter name for the same tool across runs.
//   - Lines not read when the run is cancelled are not represented (the
//     source stream was never drained).
//   - Cache hits replay the stored record's FirstSeen/LastSeen: a zero-work
//     hit does not advance LastSeen, and TTL expiry (when the cache is
//     configured with one) bounds how stale a served record can become.
//   - Decode re-validates identity and bounds but does not re-derive
//     parameters from the query (the zero-work cache-hit design); local
//     tampering of the cache directory (created 0700) could inject
//     parameters into a served record.
//   - The companion package internal/urlintel/adapt implements exec-based
//     tool adapters (gau, waybackurls, waymore) as LineSources over their
//     stdout; SliceSource and custom LineSource implementations remain for
//     tests and static input.
//
// All tests are hermetic: synthetic input and a real filesystem-backed
// cache, never the public Internet.
package urlintel
