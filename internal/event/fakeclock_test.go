package event

import (
	"sync"
	"time"
)

// fakeClock is a deterministic Clock for tests: Now returns the current
// fake time (advance moves it) and After fires after the requested duration
// on the real clock with the fake time at firing. The bus uses only Now
// (zero-timestamp stamping); After exists to satisfy the Clock contract and
// is never used by the bus tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

// Now implements Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// advance moves the fake time forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// After implements Clock: it fires once after d on the real clock, carrying
// the fake time at firing.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	fireAt := c.t.Add(d)
	c.mu.Unlock()
	go func() {
		time.Sleep(d)
		ch <- fireAt
	}()
	return ch
}
