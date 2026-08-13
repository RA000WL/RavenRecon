package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrSubscriptionClosed is returned by Next once a subscription has been
// closed, either by the user calling Close or by the pool shutting down.
var ErrSubscriptionClosed = errors.New("runtime: subscription closed")

// Kind classifies an Event.
type Kind int

const (
	// EventStarted: a job acquired its rate-limit token and began executing.
	EventStarted Kind = iota
	// EventCompleted: a job returned a result and its context was not
	// cancelled.
	EventCompleted
	// EventFailed: a job returned an error from a healthy context.
	EventFailed
	// EventCancelled: a job (or a job waiting to start) was cancelled by the
	// pool's context or a forced shutdown. Never reported as success even if
	// the job returned a value.
	EventCancelled
	// EventTimedOut: a job exceeded its per-job deadline while waiting for a
	// token or while executing. Surfaced distinctly from Cancelled; never
	// reported as success, never silently dropped.
	EventTimedOut
)

// String returns a stable human-readable label for k.
func (k Kind) String() string {
	switch k {
	case EventStarted:
		return "started"
	case EventCompleted:
		return "completed"
	case EventFailed:
		return "failed"
	case EventCancelled:
		return "cancelled"
	case EventTimedOut:
		return "timed-out"
	default:
		return fmt.Sprintf("event-kind(%d)", int(k))
	}
}

// Event describes one transition in a job's lifecycle.
//
// Events are structured data: the machine-readable fields (Kind, JobID,
// StartedAt, At, Result, Err) are the API; Kind.String() exists only for
// human-readable logging and never replaces the structured fields.
type Event struct {
	// Kind classifies the event.
	Kind Kind

	// JobID is the ID assigned at Submit time.
	JobID JobID

	// StartedAt is the pool-clock time when the job actually began executing
	// (after acquiring its rate-limit token). It is zero for jobs that were
	// cancelled before they could start (for example a job that timed out
	// while waiting for a token).
	StartedAt time.Time

	// At is the pool-clock time when the event was created.
	At time.Time

	// Result is the job's structured return value, present only for a
	// successfully completed job (EventCompleted). It may be nil.
	Result any

	// Err carries the cause. It is set for EventFailed (the job's error),
	// EventTimedOut (context.DeadlineExceeded, wrapped), and EventCancelled
	// (context.Canceled or DeadlineExceeded, wrapped). It is never set for
	// EventStarted or EventCompleted.
	Err error
}

// Subscription is a per-consumer delivery channel for pool events.
//
// Its buffer is bounded (set at Subscribe time) and delivery is blocking:
// the pool delivers every event to every subscription and is slowed down by
// a subscriber that does not keep up, so events are never dropped or lost
// during normal operation. The only case in which events may be dropped is a
// forced shutdown (see the package documentation): once the pool's context
// or the shutdown drain context is cancelled, delivery to a subscriber whose
// buffer is full is abandoned so the pool can conclude.
//
// Subscription buffers are never closed; a closed subscription simply stops
// being delivered to. Next returns buffered events (draining whatever
// remains before reporting the closed signal) followed by
// ErrSubscriptionClosed once the subscription is closed.
type Subscription struct {
	ch   chan Event
	done chan struct{}
	once sync.Once
	pool *Pool
}

// Next returns the next event, blocking until an event is available, the
// subscription is closed, or ctx is done. It returns ErrSubscriptionClosed
// once the subscription has been closed (by Close or by pool shutdown) and
// ctx.Err() if ctx is cancelled first.
//
// Buffered events are never lost by closing: once the closed signal fires,
// Next drains whatever remains in the buffer before reporting
// ErrSubscriptionClosed, so every event that was already delivered to the
// subscription is returned by some Next call before, or interleaved with,
// the closed error.
func (s *Subscription) Next(ctx context.Context) (Event, error) {
	if ctx == nil {
		return Event{}, fmt.Errorf("runtime: context must not be nil")
	}
	// Drain any event that is immediately available before considering the
	// closed signal, so buffered events are never skipped by a race between
	// the two.
	select {
	case ev := <-s.ch:
		return ev, nil
	default:
	}
	select {
	case ev := <-s.ch:
		return ev, nil
	case <-s.done:
		// The subscription is closed. Drain the buffer to empty before
		// reporting the closed signal (again non-blocking): an event
		// buffered concurrently with the close must still be returned, not
		// skipped merely because the select happened to pick the done case.
		for {
			select {
			case ev := <-s.ch:
				return ev, nil
			default:
				return Event{}, ErrSubscriptionClosed
			}
		}
	case <-ctx.Done():
		return Event{}, ctx.Err()
	}
}

// Close unsubscribes, dropping any events not yet delivered to the buffer. It
// is safe to call multiple times and from multiple goroutines: closing the
// subscription itself happens exactly once (guarded by a sync.Once) and the
// follow-up deregistration from the pool is an idempotent map delete.
//
// The deregistration deliberately runs outside the Once closure: Close never
// holds the Once mutex while acquiring subsMu, so the two lock orderings that
// exist (Shutdown/closeSubscriptions: subsMu -> Once; user Close: Once alone,
// then subsMu after releasing it) are single-directional and cannot form the
// ABBA cycle that a removal inside the Once closure would create.
func (s *Subscription) Close() {
	s.once.Do(func() { close(s.done) })
	s.pool.removeSubscription(s)
}

// closeAndRemove is the pool's internal close path used during shutdown. It
// only closes the done signal (the caller performs the map removal, so it is
// safe to invoke while holding subsMu); the sync.Once keeps it from
// interfering with a concurrent user Close.
func (s *Subscription) closeAndRemove() {
	s.once.Do(func() { close(s.done) })
}

// deliver sends ev to the subscription, blocking while the buffer is full so
// events are never lost during normal operation. The select prioritizes an
// immediately available buffer slot; a full buffer falls back to a blocking
// send that also yields to the subscription being closed or the pool being
// forced down, so a never-draining subscriber can always be unwound.
func (s *Subscription) deliver(ev Event, abortCtx context.Context) {
	select {
	case s.ch <- ev:
	default:
		select {
		case s.ch <- ev:
		case <-s.done:
		case <-abortCtx.Done():
		}
	}
}
