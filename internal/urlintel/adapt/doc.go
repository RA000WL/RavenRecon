// Package adapt implements the historical-URL tool adapters (roadmap v0.7,
// sub-milestone 6C) for the URL intelligence engine: external commands
// presented as urlintel.LineSource streams. It is a library-level stage with
// no CLI command yet. See ARCHITECTURE.md ("URL intelligence —
// Historical-URL tool adapters") for the design context; internal/discovery
// supplies the hardened execution layer (Runner, Limits, Detection) and
// internal/urlintel the ingest engine.
//
// # Tools
//
// Three built-in tools, described as data (Tool descriptors; the pipeline
// never branches on tool names):
//
//	gau:         gau <host>            (# positional; version probe -version)
//	waybackurls: waybackurls <host>     (# positional; existence-only detection)
//	waymore:     waymore -i <host> -mode U   (# URL-only mode; --version probe)
//
// waymore runs in -mode U (URLs only): archived response downloading is
// never reachable from RavenRecon. All invocations are reconnaissance:
// historical-URL collection from public archives, nothing more.
//
// # Detection semantics
//
// Detection is tool-specific. Version-probed tools (gau, waymore) run their
// probe through the runner and require a recognizable semver-like token in
// the bounded capture (stdout first, then stderr); a broken, unsupported,
// garbled, or timing-out probe is at worst a WARN — existence and capability
// are separate concerns, and a correctly installed tool is never reported
// MISSING because its version flag misbehaved. Existence-only tools
// (waybackurls) have no probe at all: executable lookup IS the detection, so
// no probe can misreport them. Each tool is detected once per run,
// sequentially, before any execution, bounded by DetectTimeout (default 5 s).
//
// # Exec safety
//
// Every invocation goes through the discovery Runner: exec.CommandContext,
// arguments as separate argv values (never a shell, never concatenation —
// target-derived strings exist only as single argv elements), bounded
// capture (Limits.MaxOutput, default 4 MiB per stream; overflow is truncated
// and honestly reported as partial), and process-group kill on cancellation
// (unix) so a cancelled run leaves no child process behind. This package
// contains no os/exec usage of its own beyond the LookPath seam (pinned by
// test).
//
// # Adapter boundary
//
// The adapter stream is raw: lines are trimmed (CRLF and surrounding
// whitespace stripped), blank lines skipped, and EVERYTHING else passes
// through unchanged. Canonical-boundary rejection (non-URLs, oversized
// lines, control-character garbage) is the engine's Malformed accounting —
// never the adapter's — so garbage from a noisy tool is counted, never
// fatal and never silently dropped. Tool output is never trusted as a URL
// until asset.ParseURL has canonicalized it.
//
// # Adapter identity and cache keys
//
// The orchestration passes the tool NAME as the engine's adapter identity
// (urlintel.Config.Adapter), which enters per-(URL, adapter) cache keys and
// the provenance of every asset. The same URL observed by two tools is two
// cache records; the engine's accumulator merges them into one report entry
// with unioned sources. Callers must pass the same tool name across runs —
// the engine's key contract.
//
// # Orchestration
//
// Run() owns one bounded runtime.Pool: exactly one job per (tool, target),
// pool Concurrency bounds concurrent tool processes, the bounded queue
// applies backpressure, and an optional job-start rate limiter paces
// job starts (tool-internal network traffic is the tool's own
// responsibility — RavenRecon never fakes per-request limits for external
// processes). Each job executes its tool through a toolSource and feeds
// urlintel.IngestInto with a small inner pool (IngestWorkers workers; the
// composite bound is Concurrency x IngestWorkers ingest workers plus
// Concurrency tool processes, all bounded). The outer per-job deadline
// bounds the tool execution AND the ingest of its lines; job-start pacing,
// timings, and concurrency never enter cache keys.
//
// Every job slot reports an honest ToolResult: skipped (detection MISSING —
// never an error, never an execution attempt), completed (clean run, fully
// ingested), partial (non-zero exit with usable output, or stdout truncated
// at the capture cap), failed (no usable output), cancelled (run context
// cancelled), or timed-out (job deadline elapsed). A failing tool never
// aborts the run; errors and truncation are summarized per result; the run
// level keeps total Malformed on the merged report and joins only
// non-fatal diagnostics and shutdown failures on the returned error.
//
// # Cancellation and shutdown
//
// context.Context flows through everything: the runner kills the process
// group on cancellation, the source surfaces the context error, the job's
// IngestInto stops reading and drains its inner pool within bounded budgets
// (15 s grace + the per-job deadline; 30 s force when deadlines are
// disabled), and the outer Shutdown drains within the same budget chain.
// Run returns only after every pool-owned goroutine has terminated
// (leak-tested). Lines not yet read from a cancelled tool are not
// represented in the report, per the engine's contract.
//
// # Known limitations
//
//   - katana and paramspider are deliberately deferred: they are crawling /
//     active-discovery tools with heavier invocation shapes, scheduling, and
//     output formats; the three passive archive URL tools cover 6C's
//     historical-URL scope.
//   - waymore persists its own results file (waymore.txt) under its config
//     directory by upstream design; the adapter consumes stdout only, and
//     the file is a tool-internal side effect.
//   - Tool-results are reported per (tool, target); malformed-line counts
//     are run-level only (the engine's shared accumulator), never attributed
//     per tool.
//   - Lines from a run that never completed (cancellation, execution
//     failure) are not streamed: partial captures of a failed run are
//     discarded by the source, matching the discovery layer's contract.
//   - On Windows, cancellation kills only the direct child process (no
//     POSIX process groups); a wrapper-spawned descendant may outlive a
//     cancelled run, though it can pin no runner resource (the runner's own
//     pinned contract).
//
// All tests are hermetic: fake runners and executables on a temporary PATH,
// never real tools and never the public Internet.
package adapt
