// Package event provides RavenRecon's Phase 12 observability foundation:
// the canonical runtime event model and a concurrent, bounded, non-blocking
// event bus.
//
// # Role
//
// The event layer is OBSERVER-ONLY. It never owns scheduling, scanning,
// detection, ranking, caching, or reporting, and it never mutates execution
// state. Data flows one way: instrumented code (the runtime pool, the cache,
// the pipeline runner, and stage result bridges) -> Bus -> consumers (the
// TUI, loggers, replays).
// A consumer can never call an engine through this package and can never
// change what a run does.
//
// # Canonical event model
//
// Every observability event is a structured, typed Event: a canonical Kind,
// a monotonic bus-assigned Sequence, an injected-clock timestamp, a
// Severity, an optional phase/category context, an optional canonical
// identity/value pair, and a sealed, typed Payload. Payloads are never
// anonymous maps. Every payload field is a projection of a real field from
// the Phase 2 asset model, the runtime engine, the priority engine, the
// detection framework, the report framework, or the secret intelligence
// engine; the payload documentation names the exact source field for each
// field.
//
// # Bus semantics
//
// A Bus fans one Event out to any number of Subscribers, each with a bounded
// buffer. Publish never blocks the caller: delivery to a full buffer drops
// the event and increments the drop counters (per subscriber and aggregate).
// Sequence numbers are assigned by the bus at publish time and are strictly
// increasing; within one subscriber, events are always received in sequence
// order. Subscribers unsubscribe by Close, which is safe to call multiple
// times and from multiple goroutines. There is no global state: every Bus
// instance is explicit and independent.
//
// # Instrumentation contract
//
// Instrumented packages (internal/runtime, internal/cache,
// internal/pipeline) accept an optional Observer via their configuration.
// A nil observer is the default and means zero behavior change. Events are
// derived at pool-job boundaries from result types (see Deriving and
// Deriver); engine packages never emit events themselves.
//
// The Bus satisfies Observer, so instrumented code can publish straight
// into a bus: b.Publish and b.Observe are the same non-blocking operation.
package event
