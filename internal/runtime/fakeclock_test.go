package runtime

import (
	"sync"
	"time"
)

// fakeClock is a deterministic Clock for tests. Time only moves when the test
// advances it, and After timers fire as soon as the advanced time reaches
// their target, so rate-limiting and event-timestamp assertions are exact
// instead of wall-clock-dependent.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[chan time.Time]time.Time
}

// newFakeClock returns a fakeClock starting at t.
func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t, timers: make(map[chan time.Time]time.Time)}
}

// Now implements Clock.
func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After implements Clock: it returns a channel that receives once Advance has
// moved the clock past now+d. If the target is already reached at registration
// time (d <= 0, or the clock moved past now+d between the caller's snapshot
// and this call), the channel is ready immediately — mirroring the contract of
// the real time.After, so a waiter that registers a timer too late still wakes
// promptly instead of silently never firing.
func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	f.mu.Lock()
	target := f.now.Add(d)
	immediate := !target.After(f.now)
	if !immediate {
		f.timers[ch] = target
	}
	f.mu.Unlock()
	if immediate {
		ch <- f.now
	}
	return ch
}

// Advance moves the clock forward by d and fires every timer whose target
// has been reached.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	var fired []chan time.Time
	for ch, target := range f.timers {
		if !target.After(f.now) {
			fired = append(fired, ch)
			delete(f.timers, ch)
		}
	}
	f.mu.Unlock()
	for _, ch := range fired {
		select {
		case ch <- f.now:
		default:
		}
	}
}
