package event

// Observer receives canonical events. Instrumented packages (the runtime
// pool, the cache, stage result bridges) accept an optional Observer via
// their configuration: a nil observer is the off switch and means zero
// behavior change, and the Bus satisfies Observer, so instrumented code can
// publish straight into a bus.
//
// Observe must be safe for concurrent use, must never block the caller
// beyond a bounded enqueue, and must never panic on a hostile or invalid
// event. The Bus satisfies all three: publish is non-blocking (full
// subscriber buffers drop and count), events are validated before delivery
// (invalid events are dropped and counted, never delivered), and delivery
// never calls back into emitter code. Consumers that re-validate events
// (see the package documentation) must treat invalid events as absent.
type Observer interface {
	// Observe receives one canonical event.
	Observe(ev Event)
}
