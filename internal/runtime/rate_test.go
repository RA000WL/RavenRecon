package runtime

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestNewLimiterValidation(t *testing.T) {
	cases := []struct {
		name  string
		rate  float64
		burst float64
	}{
		{"zero rate", 0, 1},
		{"negative rate", -1, 1},
		{"NaN rate", math.NaN(), 1},
		{"+Inf rate", math.Inf(1), 1},
		{"-Inf rate", math.Inf(-1), 1},
		{"zero burst", 1, 0},
		{"NaN burst", 1, math.NaN()},
		{"+Inf burst", 1, math.Inf(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLimiter(tc.rate, tc.burst, WithClock(newFakeClock(time.Unix(0, 0)))); err == nil {
				t.Fatalf("NewLimiter(%v, %v): expected error", tc.rate, tc.burst)
			}
		})
	}
	if _, err := NewLimiter(5, 2, WithClock(newFakeClock(time.Unix(0, 0)))); err != nil {
		t.Fatalf("NewLimiter(5, 2): unexpected error: %v", err)
	}
}

func TestLimiterTokenSpacing(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	l, err := NewLimiter(2, 1, WithClock(fc)) // 2 tokens/s, burst 1
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}

	// Burst 1: the bucket starts full, so the first acquisition is immediate.
	if wait, ok := l.take(fc.Now()); !ok || wait != 0 {
		t.Fatalf("first take: want immediate grant, got ok=%v wait=%v", ok, wait)
	}
	// The bucket is empty: the next token needs 1/rate = 500ms.
	if wait, ok := l.take(fc.Now()); ok || wait != 500*time.Millisecond {
		t.Fatalf("second take: want wait 500ms, got ok=%v wait=%v", ok, wait)
	}
	// Exactly 500ms later the token is available and consumed immediately.
	fc.Advance(500 * time.Millisecond)
	if wait, ok := l.take(fc.Now()); !ok || wait != 0 {
		t.Fatalf("third take at +500ms: want immediate grant, got ok=%v wait=%v", ok, wait)
	}
}

func TestLimiterBurstCapacity(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	l, err := NewLimiter(1, 3, WithClock(fc)) // 1 token/s, burst 3
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	// Burst 3: three immediate grants, then the bucket is empty.
	for i := 0; i < 3; i++ {
		if wait, ok := l.take(fc.Now()); !ok || wait != 0 {
			t.Fatalf("take %d: want immediate grant, got ok=%v wait=%v", i, ok, wait)
		}
	}
	if wait, ok := l.take(fc.Now()); ok || wait != time.Second {
		t.Fatalf("fourth take: want wait 1s, got ok=%v wait=%v", ok, wait)
	}
	// The bucket never accumulates more than burst: leaving the limiter idle
	// for ten seconds yields only burst tokens.
	fc.Advance(10 * time.Second)
	got := 0
	for {
		if _, ok := l.take(fc.Now()); !ok {
			break
		}
		got++
	}
	if got != 3 {
		t.Fatalf("idle refill: want 3 tokens, got %d", got)
	}
}

func TestLimiterClockBackwards(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	l, err := NewLimiter(1, 1, WithClock(fc))
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	if wait, ok := l.take(fc.Now()); !ok || wait != 0 {
		t.Fatalf("take at t0: want immediate grant, got ok=%v wait=%v", ok, wait)
	}
	// Moving the clock backwards must not refund tokens.
	fc.now = start.Add(-time.Hour)
	if wait, ok := l.take(fc.Now()); ok || wait != time.Second {
		t.Fatalf("take after backwards jump: want wait 1s, got ok=%v wait=%v", ok, wait)
	}
}

func TestLimiterWaitHonorsCancellation(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	l, err := NewLimiter(1, 1, WithClock(fc))
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	// Consume the only token so Wait has to block.
	if _, ok := l.take(fc.Now()); !ok {
		t.Fatal("expected initial token")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Wait(ctx) }()

	select {
	case err := <-done:
		t.Fatalf("Wait returned before cancellation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Wait: want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after cancellation")
	}
}

// TestLimiterWaitHonorsDeadline verifies the deadline-only path (no explicit
// cancellation): when the context's deadline elapses before a token is
// available, Wait returns context.DeadlineExceeded. The limiter runs on the
// fake clock (whose tokens never become available without an Advance), so the
// real 100ms context deadline is the only way out.
func TestLimiterWaitHonorsDeadline(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	l, err := NewLimiter(1, 1, WithClock(fc))
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	if _, ok := l.take(fc.Now()); !ok {
		t.Fatal("expected initial token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Wait(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Wait: want context.DeadlineExceeded, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the deadline elapsed")
	}
}

func TestLimiterWaitAdvancesWithClock(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	l, err := NewLimiter(2, 1, WithClock(fc)) // 2 tokens/s, burst 1
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	// Consume the initial burst token so Wait must actually wait.
	if wait, ok := l.take(fc.Now()); !ok || wait != 0 {
		t.Fatalf("initial take: want immediate grant, got ok=%v wait=%v", ok, wait)
	}
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- l.Wait(ctx) }()

	select {
	case err := <-done:
		t.Fatalf("Wait returned before clock advance: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// The token becomes available exactly 500ms of fake time later.
	fc.Advance(500 * time.Millisecond)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after clock advance")
	}
}

// TestLimiterConcurrentWaiters verifies that concurrent Waiters receive
// tokens at exactly the configured spacing: the grants land at fake times
// t0, t0+500ms and t0+1000ms for rate 2/s burst 1, regardless of goroutine
// scheduling. The test advances the clock only after each grant is observed;
// Wait registers its timer for the *remaining* wait relative to a fresh clock
// read, so a waiter whose timer registration is delayed by an advance still
// wakes at exactly the intended target instead of one wait-interval late.
func TestLimiterConcurrentWaiters(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	l, err := NewLimiter(2, 1, WithClock(fc))
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}

	const n = 3
	ready := make(chan struct{}, n)
	starts := make(chan time.Time, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			if err := l.Wait(context.Background()); err != nil {
				t.Errorf("Wait: %v", err)
			}
			starts <- fc.Now()
		}()
	}
	// Let every goroutine reach Wait (its first take runs at fake t0 and the
	// initial burst token is consumed once, granting immediately).
	for i := 0; i < n; i++ {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("waiter did not become ready")
		}
	}
	// Grant one token at a time, advancing exactly one token's worth of fake
	// time between grants.
	var got []time.Time
	for i := 0; i < n; i++ {
		select {
		case s := <-starts:
			got = append(got, s)
		case <-time.After(5 * time.Second):
			t.Fatal("a waiter never received its token")
		}
		if i < n-1 {
			fc.Advance(500 * time.Millisecond)
		}
	}
	wg.Wait()

	for i, want := range []time.Time{start, start.Add(500 * time.Millisecond), start.Add(time.Second)} {
		if !got[i].Equal(want) {
			t.Fatalf("grant %d at %v, want %v (all: %v)", i, got[i], want, got)
		}
	}
}
