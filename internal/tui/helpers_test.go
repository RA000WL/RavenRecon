package tui

import (
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// testBase is the fixed deterministic clock base for every test stream.
// All timestamps derive from it, so renders are pure functions of the
// test data (no wall clock anywhere).
var testBase = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// waitFor polls cond until it holds or the deadline passes. It keeps the
// controller tests deterministic in outcome (bounded polling, no sleeps
// beyond a millisecond) while staying hermetic.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ev builds one canonical event at testBase+ms milliseconds.
func ev(kind event.Kind, ms int, payload event.Payload) event.Event {
	return event.New(kind, testBase.Add(time.Duration(ms)*time.Millisecond), payload)
}

// evAt builds one canonical event at the exact time.
func evAt(kind event.Kind, at time.Time, payload event.Payload) event.Event {
	return event.New(kind, at, payload)
}

// highRate is the feed admission rate used by tests that must not be
// limited by the interesting-feed token bucket (burst 1, refill 1e9/s:
// any gap of a microsecond or more refills the token).
const highRate = 1e9

// fakeClock is the deterministic controller tick source: After always
// returns the shared tick channel, so a test drives renders by sending.
// The interval argument is ignored, mirroring a test clock that decides
// itself when time has passed.
type fakeClock struct {
	now  time.Time
	tick chan time.Time
}

// Now implements event.Clock.
func (f *fakeClock) Now() time.Time { return f.now }

// After implements event.Clock.
func (f *fakeClock) After(time.Duration) <-chan time.Time { return f.tick }
