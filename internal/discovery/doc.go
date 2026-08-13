// Package discovery implements RavenRecon's passive subdomain discovery
// subsystem (roadmap v0.5): three external-tool adapters — subfinder,
// assetfinder, and amass (passive enumeration only) — orchestrated through
// the v0.3 runtime engine with Phase 3 cache-before-execute composition and
// Phase 2 asset normalization/deduplication.
//
// # Architecture
//
//	Runtime (one Pool per run)
//	  -> Discovery jobs (cache-before-execute)
//	    -> adapters (exec/parse via a Runner)
//	      -> Parse/Normalize (Phase 2 asset model, asset.NewHost)
//	        -> Deduplicate by asset identity (per source and across sources)
//	          -> Cache (Phase 3: statused records)
//
// The discovery layer creates exactly one runtime.Pool per Run. Scheduling,
// concurrency, cancellation, per-job deadlines, and job-start rate limiting
// are owned by that pool; discovery never spawns goroutines of its own. Each
// selected source runs as one pool job whose job function performs
// cache-before-execute: it derives the Phase 3 key, returns the stored
// result on a usable hit, and on a miss executes the adapter, classifies the
// outcome, and stores a statused record before returning.
//
// # Passive/active boundary
//
// Every adapter invokes only passive enumeration:
//
//	subfinder:   subfinder -d <domain> -silent
//	assetfinder: assetfinder <domain>
//	amass:       amass enum -passive -d <domain>
//
// No active, brute-force, intel, or other non-passive mode is ever passed.
// The exact argv is asserted in the adapter tests so the boundary cannot
// silently drift. amass is only ever invoked with -passive; the amass
// default active enumeration is never used.
//
// # Tool detection
//
// Detection distinguishes (1) executable existence (exec.LookPath), (2)
// that the executable actually runs, (3) that a version can be determined,
// and (4) that a capability check succeeds. The result is one of
// [OK]/[WARN]/[MISSING] with a reason. A failed or unsupported version flag
// is a WARN at worst, never a MISSING: existence and capability are separate
// concerns. subfinder and amass have a -version flag; assetfinder has none,
// so its capability is asserted by executing -h and observing output. A
// MISSING source is skipped with a clear warning, never a crash.
//
// # Execution safety
//
// Adapters execute through exec.CommandContext with arguments passed as
// separate argv values; there is no shell and target-derived strings can
// never become shell syntax or argument injection (tool flags are fixed, and
// the normalized target is validated to consist only of lowercase letters,
// digits, hyphens, and dots, and never starts with a hyphen). Every
// execution supports context cancellation — on unix the child's whole
// process group is killed, so a wrapper script or PATH shim that spawned a
// descendant holding the output pipes has that descendant terminated with
// the group (unless it escaped into its own session with setsid). The
// captured streams flow through pipes the runner owns itself (os.Pipe plus
// its own copy goroutines; see pipeCopies in runner.go), whose read ends are
// force-closed and copy goroutines joined before Run returns on every path,
// so even an escaped pipe-holder can pin no goroutine, file descriptor, or
// capture buffer past Run's return. On Windows only the direct child is
// killed; a wrapper-spawned descendant may itself outlive a cancelled run,
// but it can pin no runner resource and Run never blocks on it. A short wait
// bound (waitGrace) covers the single residual case of a child that cannot
// be killed at all (an unkillable D-state process) — per-job deadlines,
// structured errors for missing executables and non-zero exits, and bounded
// output: stdout and stderr are captured through size-limited readers
// (DefaultMaxOutput per stream) and oversize streams are truncated and
// diagnosed, never buffered without bound. A child killed because its
// context was cancelled or timed out is always classified by the context
// error (cancelled, never a clean exit-code failure).
//
// # Parsing, normalization, and deduplication
//
// Tool output is untrusted input. Each non-blank stdout line contributes its
// first whitespace-delimited token (which handles amass's historical
// "name (FQDN) --> 1.2.3.4" format); duplicate lines, blank lines, CRLF, and
// stray whitespace are handled; lines that do not normalize to a valid host
// are counted and skipped. Every candidate is normalized only through the
// Phase 2 asset model (asset.NewHost); there is no second normalization
// implementation, so API.Example.COM., api.example.com, and
// " api.example.com " produce the same identity. Duplicates are removed by
// Phase 2 identity both within one source and across sources (asset.MergeHosts
// semantics merge same-identity hosts, with the earliest observation's
// provenance winning).
//
// # Cache integration
//
// Cache keys (internal/cache.NewKey) are derived from the operation
// "passive-discovery", the canonical target identity ("domain:example.com"),
// the result-relevant configuration — today exactly {"mode": "passive"}; any
// future invocation mode that changes results must extend this map — and the
// tool identity (name plus detected version), because a tool version change
// can change results. Only a completed, unexpired record for the exact key
// is a usable hit; failed, cancelled, incomplete, expired, corrupt, or
// schema-incompatible entries are never treated as valid results (the cache
// layer surfaces them as misses with distinct states).
//
// # Partial result semantics
//
// An adapter that produced partial output and exited non-zero is stored as
// StatusIncomplete with the partial data attached (a later run can inspect
// it, though discovery has no sub-work units to resume, so a rerun reruns
// the source). Cancellation and timeouts are stored as StatusCancelled.
// Clean failure with no usable output is stored as StatusFailed. Only
// established success — exit code 0 with stdout within the capture cap — is
// stored as StatusCompleted; empty-but-successful output is a legitimate
// completed empty result. Truncated stdout (an oversized stream) is stored
// as StatusIncomplete: the captured set is incomplete by definition.
// Tool execution failures are never cached as successful discoveries.
//
// # Runtime integration and rate limiting
//
// The runtime pool rate-limits job STARTS only. RavenRecon's limiter does
// not rate-limit network requests made inside an external binary: subfinder
// and amass perform their own throttling, and no per-request limits are
// faked for external processes. Tool detection runs before the pool, once
// per selected source, each bounded by DetectTimeout.
//
// # Known limitations
//
//   - Discovery is passive and stdout-based; tools that write results only
//     to files or databases are unsupported by design.
//   - No Windows-specific retry of failed detection on .exe suffixes: binary
//     overrides must name an executable resolvable by exec.LookPath.
//   - IDN/Unicode targets are rejected by the Phase 2 asset model
//     (normalization is ASCII-only) and therefore unsupported.
//   - A per-run cache miss reruns the whole source; there are no sub-work
//     units to resume from a partial record.
package discovery
