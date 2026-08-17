package tui

import (
	"testing"
	"time"
)

func TestProgressElapsed(t *testing.T) {
	var p progressState
	t0 := testBase
	if _, ok := p.elapsed(t0); ok {
		t.Fatal("elapsed must be unknown before the first event")
	}

	p.firstEvent = t0
	d, ok := p.elapsed(t0.Add(5 * time.Second))
	if !ok || d != 5*time.Second {
		t.Fatalf("elapsed = %v/%v, want 5s/true", d, ok)
	}

	// ScanStarted takes precedence over the first-event fallback.
	p.startedAt = t0.Add(time.Second)
	d, ok = p.elapsed(t0.Add(5 * time.Second))
	if !ok || d != 4*time.Second {
		t.Fatalf("elapsed = %v/%v, want 4s/true", d, ok)
	}

	// A clock before the start clamps to zero, never negative.
	if d, _ := p.elapsed(t0); d != 0 {
		t.Fatalf("elapsed before start = %v, want 0", d)
	}
}

func TestProgressRemaining(t *testing.T) {
	var p progressState
	if _, ok := p.remaining(); ok {
		t.Fatal("remaining must be unknown when the total is unknown")
	}
	p.totalKnown = true
	p.completed, p.total = 3, 10
	if r, ok := p.remaining(); !ok || r != 7 {
		t.Fatalf("remaining = %d/%v, want 7/true", r, ok)
	}
	p.completed, p.total = 12, 10
	if r, ok := p.remaining(); !ok || r != 0 {
		t.Fatalf("remaining must clamp at 0, got %d/%v", r, ok)
	}
}

func TestProgressInFlight(t *testing.T) {
	var p progressState
	p.taskStarted(1)
	p.taskStarted(2)
	p.taskStarted(2) // duplicate task_started for the same JobID counts once
	if p.inFlight != 2 {
		t.Fatalf("in-flight = %d, want 2", p.inFlight)
	}
	p.taskTerminal(3) // never-started JobID never became in-flight
	if p.inFlight != 2 {
		t.Fatalf("in-flight = %d, want 2 after never-started terminal", p.inFlight)
	}
	p.taskTerminal(1)
	if p.inFlight != 1 {
		t.Fatalf("in-flight = %d, want 1", p.inFlight)
	}
	p.taskTerminal(1) // repeated terminal for the same JobID drains once
	if p.inFlight != 1 {
		t.Fatalf("in-flight = %d, want 1 after repeated terminal", p.inFlight)
	}
	p.taskTerminal(2)
	if p.inFlight != 0 {
		t.Fatalf("in-flight = %d, want 0", p.inFlight)
	}
	if n, known := p.inFlightCount(); !known || n != 0 {
		t.Fatalf("inFlightCount = %d/%v, want 0/true", n, known)
	}
}

func TestProgressInFlightCap(t *testing.T) {
	var p progressState
	for i := 0; i < startedIDCap; i++ {
		p.taskStarted(uint64(i))
	}
	if n, known := p.inFlightCount(); !known || n != startedIDCap {
		t.Fatalf("inFlightCount = %d/%v, want %d/true", n, known, startedIDCap)
	}
	// One more distinct JobID than the cap: the count becomes honestly
	// unknown instead of growing without bound or wrapping.
	p.taskStarted(startedIDCap)
	if _, known := p.inFlightCount(); known {
		t.Fatal("in-flight must be unknown after the started-ID cap overflows")
	}
	p.taskStarted(0) // unknown is sticky; further events must not resurrect a count
	p.taskTerminal(0)
	if _, known := p.inFlightCount(); known {
		t.Fatal("in-flight must remain unknown after overflow")
	}
}

func TestProgressETA(t *testing.T) {
	var p progressState
	var rates Rates
	t0 := testBase
	// Unknown totals: honest unknown.
	if _, ok := p.eta(t0, &rates); ok {
		t.Fatal("eta must be unknown when totals are unknown")
	}

	p.totalKnown = true
	p.completed, p.total = 5, 10

	// No rate signal: unknown.
	if _, ok := p.eta(t0, &rates); ok {
		t.Fatal("eta must be unknown without a rate")
	}

	// One task per second.
	rates.recordCum(metricTasks, t0, 0)
	rates.recordCum(metricTasks, t0.Add(time.Second), 2)
	eta, ok := p.eta(t0.Add(2*time.Second), &rates)
	if !ok || eta != 5*time.Second {
		t.Fatalf("eta = %v/%v, want 5s/true", eta, ok)
	}

	// Complete run: zero, known.
	p.completed, p.total = 10, 10
	if eta, ok := p.eta(t0.Add(2*time.Second), &rates); !ok || eta != 0 {
		t.Fatalf("completed run eta = %v/%v, want 0/true", eta, ok)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0.0s"},
		{12300 * time.Millisecond, "12.3s"},
		{83 * time.Second, "1m23s"},
		{3900 * time.Second, "1h05m"},
		{-5 * time.Second, "0.0s"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.d); got != tc.want {
			t.Fatalf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
