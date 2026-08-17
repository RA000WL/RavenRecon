package cache

import (
	"github.com/RA000WL/RavenRecon/internal/event"
)

// Phase 12 instrumentation (roadmap v1.2, "Cache instrumentation").
//
// The cache accepts an OPTIONAL observer through its Open options. A nil
// observer is the off switch: zero behavior change, zero measurable cost
// (the cache only ever performs a nil check per lookup). When set, every
// Get publishes exactly one canonical cache_hit / cache_miss event
// (internal/event) carrying the REAL outcome of the lookup.
//
// Every payload field is grounded in a real cache field:
//
//   - event.CacheAccess.Key   <- cache.Key (the 64-character lowercase hex
//     SHA-256 digest; by construction it encodes the schema version, the
//     operation, the normalized target, the result-relevant configuration,
//     and the tool identity — see key.go).
//   - event.CacheAccess.State <- cache.Outcome.State.String() ("hit",
//     "miss", "expired", "corrupt", "schema-incompatible", "incomplete",
//     "error").
//   - event.CacheAccess.Hit   <- cache.Outcome.IsHit() (true exactly for
//     StateHit).
//
// The kind is cache_hit exactly when Hit is true and cache_miss otherwise,
// so the payload can never contradict its kind (Event.Validate enforces
// that). The event timestamp comes from the cache's own injected clock
// (WithClock), so deterministic tests can pin it. The cache measures no
// lookup latency today, so none is reported.
//
// Emission never blocks a cache operation: the observer is invoked inline
// exactly like the runtime pool's, and the Observer contract
// (internal/event) bounds the call; with the canonical Bus observer,
// publish is a non-blocking enqueue that drops and counts on a full
// subscriber buffer.
//
// Only Get emits. Put/Delete/Clear/InvalidateIncompatible are not lookups
// and publish nothing; the eviction and self-healing paths are reported
// through the outcome of the Get that triggered them, never as separate
// events.

// WithObserver wires an optional observability sink (an internal/event
// Observer; the Bus satisfies it) into the cache. When non-nil, every Get
// publishes a canonical cache_hit/cache_miss event carrying the lookup's
// real outcome (see emitAccess for the field grounding). A nil observer
// (the default) means zero behavior change.
func WithObserver(obs event.Observer) Option {
	return func(o *options) { o.observer = obs }
}

// emitAccess publishes the outcome of one lookup as a canonical cache
// event when an observer is configured. A nil observer is the off switch:
// a single nil check, nothing else.
func (c *FS) emitAccess(key Key, out Outcome) {
	if c.observer == nil {
		return
	}
	kind := event.KindCacheMiss
	if out.IsHit() {
		kind = event.KindCacheHit
	}
	c.observer.Observe(event.New(kind, c.now(), event.CacheAccess{
		Key:   string(key),
		State: out.State.String(),
		Hit:   out.IsHit(),
	}))
}
