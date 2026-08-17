// Package tui provides RavenRecon's Phase 12 terminal observability
// library: it consumes canonical events (internal/event) from a Bus and
// renders deterministic, human-readable frames of a running scan.
//
// # Observer-only contract
//
// The TUI is OBSERVER-ONLY. It consumes the event stream and renders it; it
// never calls an engine, never mutates execution state, and cannot change
// what a run does. There is no inbound path from the TUI to the pool, the
// cache, or any pipeline stage: a frame is a pure function of the events
// consumed so far, the current time, and the configuration
// (Render/RenderFinal take the state snapshot explicitly).
//
// # Architecture
//
//	instrumented code (pool, cache, stages)
//		-> Bus (internal/event)
//		-> Subscriber (bounded buffer)
//		-> Controller.Run (select on events / ticker / ctx / closed)
//		-> State.Apply (sanitize at ingestion, update components)
//		-> Render / RenderFinal (deterministic frame)
//		-> one whole Write to the caller's writer
//
// The State machine is single-consumer: exactly one goroutine (the
// Controller's Run loop, or a test) applies events and renders. The
// Subscriber is single-consumer by contract too, so the Controller owns both
// ends.
//
// # Components
//
//   - Progress manager: current phase (PhaseTransition), in-flight task
//     count, completed/remaining/total (Progress), elapsed and ETA. UNKNOWN
//     totals render honestly ("unknown"/"—"); a percentage is never faked.
//   - Worker dashboard: per-worker state transitions (idle -> waiting ->
//     running -> idle; stopped as completed/cancelled) from worker and task
//     events only, with the current task, its duration, and the last error.
//   - Throughput monitor: fixed-window rolling rates (assets, urls,
//     requests, js, rules, relationships, cache hits, cache misses — plus an
//     internal task rate backing the ETA) computed from event deltas over a
//     10 s window; the math is deterministic and unit-tested with
//     hand-computed windows.
//   - ETA estimator: remaining tasks / task rate. Unknown totals, a zero
//     rate, or no signal yield an honest "unknown"; there is no
//     divide-by-zero and no fabricated certainty.
//   - Resource monitor: heap bytes and goroutine count (the stdlib runtime
//     package), open file descriptors best-effort via /proc/self/fd on
//     Linux (documented unsupported elsewhere; stdlib only), queue depth
//     and active workers derived from pool events. Sampling happens only on
//     render ticks (bounded), and any failure degrades to "—".
//   - Interesting-asset feed: high-value observations (GraphQL/WS/SSE
//     endpoint classes, admin-ish paths, source maps, high-confidence
//     secrets, high-priority findings, technologies, high-value
//     recommendations) selected by display-only heuristics over REAL event
//     payload fields, rate-limited by the configured InterestingRate and
//     deduplicated by identity+kind, in a bounded ring.
//   - Error feed: KindWarning/KindError events grouped by category, with
//     count, latest example, and severity, in a bounded group table.
//   - Final run summary: duration, asset/relationship/finding/rule/cache
//     counters, warnings/errors, and the output directory (honest "—" when
//     the stream carried no RunMetadata) — derived ONLY from the consumed
//     event stream.
//   - Event history: a bounded replay ring (MaxEventHistory) in sequence
//     order; a fresh State can be reconstructed from it (the tail of the
//     stream is fully replayable).
//
// # Sanitization
//
// Every dynamic string (identities, values, evidence text, error messages,
// finding text, recommendations, output paths) passes through Sanitize at
// ingestion, before it can reach a frame: ESC sequences (CSI/OSC/two-byte),
// C0 controls except TAB/LF/CR, DEL, C1 controls, and invalid UTF-8 bytes
// are stripped. The renderer adds only its own fixed color codes, so a
// frame can never contain hostile terminal control bytes. See Sanitize.
//
// # Configuration
//
// The library consumes the existing internal/config TUIConfig (Enabled,
// Compact, Quiet, Color, RefreshInterval, MaxEventHistory,
// InterestingRate); OptionsFromConfig normalizes zero fields to the
// documented defaults. The library does not create its own configuration
// section and does not touch raw mode: it never puts the terminal into raw
// mode, never reads keys, and never manipulates signals. "auto" color is
// resolved by the CALLER (from the caller's own terminal detection); the
// library renders plain whenever the resolved mode is off, which is the
// natural plain mode for non-TTY writers.
//
// # Output contract
//
// A frame is built as one bounded buffer and written with a single Write
// call. A failed or partial write (including EPIPE) disables rendering for
// the rest of the run — the controller keeps consuming events and never
// panics. SIGPIPE behavior note: Go's runtime raises SIGPIPE for writes to
// file descriptors 1 and 2 by default, which terminates the process; the
// library does not change signal handling. Callers that write to stdout
// and want graceful EPIPE handling must ignore SIGPIPE themselves (for
// example signal.Ignore(syscall.SIGPIPE)); writes to other writers surface
// the error to the controller, which handles it without panicking.
//
// # Bounds
//
// Every structure is bounded: subscriber buffer (4096), history ring
// (MaxEventHistory <= 4096), throughput sample rings (128 samples per
// metric), interesting feed (64 items), error feed (32 groups), per-line
// display width (200 bytes), and the whole frame (64 KiB). Drop counters
// are exposed on the components that drop (History.Dropped,
// InterestingFeed.Dropped, ErrorFeed.Dropped, Subscriber.Drops,
// Bus.Drops), so loss beyond the documented policy is always measurable,
// never silent.
package tui
