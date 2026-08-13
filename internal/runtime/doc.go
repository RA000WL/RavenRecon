// Package runtime provides RavenRecon's v0.3 runtime engine: a bounded,
// cancellable, rate-limited job execution engine. It is generic
// infrastructure: jobs are plain functions from a context to a structured
// result, and the runtime knows nothing about discovery, tools, DNS, HTTP, or
// caching. Consumer stages (for example passive discovery) compose
// "cache-before-execute" around runtime jobs; this package does not import
// internal/cache and never will.
//
// # Execution model
//
// A Pool is constructed from a Config and a context. The context is the
// pool's lifetime signal: cancelling it cancels every queued and running job.
// The pool starts exactly Config.Concurrency worker goroutines; jobs are
// submitted through Submit, which enqueues into a channel of bounded capacity
// Config.QueueSize, and run inline inside workers. The pool never creates a
// goroutine per job, so at any instant at most Concurrency jobs are
// executing (plus at most Concurrency more parked on the rate limiter or on
// event delivery).
//
// # Jobs
//
// A job is a JobFunc: func(ctx context.Context) (any, error). The context is
// derived by the pool from the pool's own context and the job's deadline
// (Config.Timeout or a per-job Job.Timeout override). The deadline covers
// both the wait for a rate-limit token and the execution itself. Jobs return
// a structured result value and an error; results and errors travel through
// events (Subscription), never through globals or the pool state.
//
// # Cancellation and terminal classification
//
// Cancellation is context-based everywhere: pool context, Submit context,
// Shutdown drain context, subscription Next context, and the rate limiter's
// Wait all honor context.Context. A cancelled job is always reported as
// cancelled, never as failed and never as success. Terminal classification is
// deterministic, in priority order:
//
//  1. Deadline exceeded (errors.Is(err, context.DeadlineExceeded)) ->
//     EventTimedOut. Timeouts are surfaced distinctly from cancellation and
//     are never silently dropped.
//  2. Context cancelled for any other reason -> EventCancelled.
//  3. The job returned an error -> EventFailed.
//  4. Otherwise -> EventCompleted.
//
// A job that panics is caught and reported as EventFailed (the panic value,
// truncated), and the pool keeps running.
//
// # Graceful shutdown
//
// Shutdown(ctx) stops accepting new work (Submit returns ErrPoolClosed),
// drains the queue and in-flight jobs to completion, closes all
// subscriptions, and returns nil once every pool-owned goroutine has
// terminated. If the drain context is cancelled first, Shutdown forces the
// pool down: remaining queued and running jobs are cancelled, the pool still
// unwinds completely, and Shutdown returns an error wrapping ctx.Err(). All
// event delivery is lossless during normal operation and during a graceful
// shutdown; during a forced shutdown, terminal events may be dropped for
// subscribers whose buffers are full (the caller already observes the
// shutdown error).
//
// # Rate limiting
//
// Every job start acquires one token from the pool's single central token
// bucket (implemented in rate.go with the standard library only). The bucket
// holds Config.Burst tokens (default 1), starts full, and refills at
// Config.Rate tokens per second, so the first burst of job starts proceeds
// immediately and every start after that is spaced at least 1/Rate apart,
// regardless of concurrency. Token acquisition is serialized by the
// limiter's mutex and the limiter never holds the mutex while sleeping, so
// it cannot deadlock and honours context cancellation while waiting. Rates
// at or below zero disable the limiter entirely.
//
// # Events
//
// Subscribers receive every event (see Subscription and Event): jobs are
// reported as started, completed (with the result), failed (with the error),
// cancelled, or timed out, each with the job ID and pool-clock timestamps.
// Events for one job are delivered in order to each subscriber; ordering
// across jobs is unspecified. Event buffers are bounded per subscriber and
// delivery is blocking, so no event is ever silently dropped during normal
// operation: a subscriber that does not keep up slows the pool (backpressure)
// rather than losing events. The one exception is the forced-shutdown drop
// described above. Subscribers drain with Next(ctx); Next returns
// ErrSubscriptionClosed once the pool shuts down or Close is called.
//
// # Known limitations
//
//   - The pool cannot kill a goroutine. A job that ignores context
//     cancellation can delay Shutdown for up to its per-job deadline (or
//     indefinitely when deadlines are disabled, since the pool cannot force
//     the goroutine out). Jobs must honor ctx.
//   - During a forced shutdown, queued jobs that were never picked up are
//     dropped without a terminal event, and terminal events may be dropped
//     for subscribers whose buffers are full.
//   - If the pool's context is cancelled without calling Shutdown, the
//     workers unwind but the submission queue stays open and subscriptions
//     stay open; callers must call Shutdown to fully release the pool.
//   - Events are delivered in memory only; this package has no persistence
//     (that is the cache layer's concern) and no cross-process semantics.
//   - A subscriber that never drains can stall workers; use adequate buffers
//     or drain promptly (a forced shutdown always unwinds it).
package runtime
