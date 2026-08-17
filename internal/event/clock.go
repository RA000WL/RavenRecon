package event

import "time"

// Clock abstracts the source of time so event timestamps and TUI refresh
// ticks can be driven deterministically in tests. It mirrors the runtime
// engine's Clock contract (internal/runtime): an implementation must be safe
// for concurrent use, Now returns the current time, and After returns a
// channel that receives the current time once d has elapsed (exactly once;
// a nil or never-firing implementation is not allowed).
//
// The runtime pool's clock satisfies this interface structurally, so a pool
// configured with a fake runtime.Clock produces fully deterministic events.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// After returns a channel that receives the current time once d has
	// elapsed. It mirrors time.After: the timer fires exactly once.
	After(d time.Duration) <-chan time.Time
}

// wallClock is the production Clock backed by time.Now and time.After.
type wallClock struct{}

// Now implements Clock.
func (wallClock) Now() time.Time { return time.Now() }

// After implements Clock.
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
