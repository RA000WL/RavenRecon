package runtime

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// maxWaitNs bounds a single Wait sleep. It exists so that a pathological
// (extremely small) rate cannot overflow when converting the token deficit to
// a time.Duration; the bound is far beyond any practical delay.
const maxWaitNs = 1 << 62

// limiterOptions configures a Limiter.
type limiterOptions struct {
	clock Clock
}

// Option customizes a Limiter created by NewLimiter.
type Option func(*limiterOptions)

// WithClock injects a clock for deterministic tests. Nil means wallClock.
func WithClock(c Clock) Option {
	return func(o *limiterOptions) { o.clock = c }
}

// Limiter is a token-bucket rate limiter implemented with the standard
// library only. The bucket holds up to burst tokens, is refilled at rate
// tokens per second, and starts full, so the first burst Tokens acquisitions
// succeed immediately and every acquisition after that is spaced at least
// 1/second of wall-clock (or injected-clock) time apart.
//
// The bucket state is protected by a single mutex: acquisitions are
// serialized, tokens are never oversold, and the mutex is never held while
// sleeping, so Wait can be called from many goroutines without deadlock and
// without unbounded memory growth (each waiter sleeps on one timer).
//
// The clock is allowed to move backwards: elapsed time is clamped to zero, so
// a backwards step cannot refund tokens.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // maximum accumulated tokens
	tokens float64 // current tokens
	last   time.Time
	clock  Clock
}

// NewLimiter returns a token-bucket limiter with the given refill rate
// (tokens per second) and burst capacity. rate must be a positive finite
// number and burst must be at least 1. The bucket starts full.
func NewLimiter(rate, burst float64, opts ...Option) (*Limiter, error) {
	if math.IsNaN(rate) || math.IsInf(rate, 0) {
		return nil, fmt.Errorf("runtime rate limiter: rate must be finite, got %v", rate)
	}
	if rate <= 0 {
		return nil, fmt.Errorf("runtime rate limiter: rate must be positive, got %v", rate)
	}
	if math.IsNaN(burst) || math.IsInf(burst, 0) {
		return nil, fmt.Errorf("runtime rate limiter: burst must be finite, got %v", burst)
	}
	if burst < 1 {
		return nil, fmt.Errorf("runtime rate limiter: burst must be at least 1, got %v", burst)
	}
	o := limiterOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	clock := o.clock
	if clock == nil {
		clock = wallClock{}
	}
	return &Limiter{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   clock.Now(),
		clock:  clock,
	}, nil
}

// take refills the bucket to t and attempts to consume one token. If a token
// was available it returns (0, true). Otherwise it returns the duration the
// caller should wait before trying again, given the current bucket state and
// the configured rate; the returned duration is at least one nanosecond.
func (l *Limiter) take(t time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.Before(l.last) {
		t = l.last // the clock moved backwards; treat as no elapsed time
	}
	elapsed := t.Sub(l.last).Seconds()
	l.tokens = math.Min(l.tokens+elapsed*l.rate, l.burst)
	l.last = t
	if l.tokens >= 1 {
		l.tokens--
		return 0, true
	}
	need := 1 - l.tokens // in (0, 1]
	ns := math.Ceil(need / l.rate * float64(time.Second))
	if math.IsInf(ns, 1) || ns > maxWaitNs {
		ns = maxWaitNs
	}
	return time.Duration(ns), false
}

// Wait blocks until a token is available or ctx is done. It returns nil once
// a token has been consumed, or ctx.Err() if the context is cancelled or its
// deadline elapses first. Wait is safe for concurrent use; concurrent waiters
// receive tokens one at a time in the order their buckets refill, never
// overselling the configured rate.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	for {
		now := l.clock.Now()
		wait, ok := l.take(now)
		if ok {
			return nil
		}
		// Pin an absolute wake target: the token becomes available at
		// now+wait. The clock may advance between the snapshot above, the
		// remaining computation, and the timer registration (another
		// goroutine's wake-up, or a test advancing an injected fake clock);
		// registering a stale duration would push the wake time up to one
		// full wait-interval past the token's availability, stalling the
		// caller until its context deadline.
		target := now.Add(wait)
		remaining := target.Sub(l.clock.Now())
		if remaining <= 0 {
			// The wait has already elapsed, so the bucket has refilled (or a
			// competing waiter consumed the token); re-check immediately.
			continue
		}
		ch := l.clock.After(remaining)
		if l.clock.Now().Sub(now) >= wait {
			// The clock reached the absolute target while the timer was being
			// registered; the registration above used a stale remaining
			// duration. Abandon it and re-check the bucket now.
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			// Wake up and re-check: another waiter may have consumed the
			// refilled token in the meantime.
		}
	}
}
