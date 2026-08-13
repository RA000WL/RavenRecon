package runtime

import "time"

// Clock abstracts the source of time so that rate limiting and event
// timestamps can be driven deterministically in tests. The production
// implementation is wallClock; tests inject a fake clock (see the test file)
// to make timing assertions exact instead of wall-clock-dependent.
//
// Implementations must be safe for concurrent use.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// After returns a channel that receives the current time once d has
	// elapsed. It mirrors time.After: the timer fires exactly once, and a
	// nil or never-firing implementation is not allowed.
	After(d time.Duration) <-chan time.Time
}

// wallClock is the production Clock backed by time.Now and time.After.
type wallClock struct{}

// Now implements Clock.
func (wallClock) Now() time.Time { return time.Now() }

// After implements Clock.
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
