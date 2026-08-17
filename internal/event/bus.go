package event

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ErrSubscriptionClosed is returned by Next once a subscription has been
// closed (by the user calling Close or by the bus shutting down).
var ErrSubscriptionClosed = errors.New("event: subscription closed")

// Bus is a concurrent, bounded, non-blocking event bus. Producers publish
// Events; each Subscriber receives every published event through its own
// bounded buffer. Publish never blocks the caller: when a subscriber's
// buffer is full the event is dropped for that subscriber and counted (both
// per subscriber and in the bus aggregate). Sequence numbers are assigned
// by the bus at publish time, strictly increasing, and every subscriber
// receives events in sequence order.
//
// The Bus implements Observer, so instrumented code (the runtime pool, the
// cache, stage result bridges) can publish straight into it with a nil
// observer as the off switch.
//
// There is no global state: every Bus instance is explicit and independent.
// The zero value is not usable; construct with NewBus. Subscribers must be
// closed with Close (the caller owns the lifecycle); a Bus with open
// subscribers retains them until closed.
type Bus struct {
	clock Clock

	mu     sync.Mutex
	subs   map[*Subscriber]struct{}
	next   atomic.Uint64
	closed bool

	invalid atomic.Uint64
	drops   atomic.Uint64
}

var _ Observer = (*Bus)(nil)

// NewBus returns a running Bus with the given clock (nil means the wall
// clock). The clock only timestamps events when emitters do not supply
// their own; in the canonical flow emitters construct events with their own
// injected clock and the bus preserves them.
func NewBus(clock Clock) *Bus {
	if clock == nil {
		clock = wallClock{}
	}
	return &Bus{clock: clock, subs: make(map[*Subscriber]struct{})}
}

// Subscribe returns a new subscriber with a bounded buffer of the given
// size (must be positive). The subscriber receives every event published
// after it subscribes, in sequence order, and must be released with Close.
func (b *Bus) Subscribe(buffer int) (*Subscriber, error) {
	if buffer <= 0 {
		return nil, fmt.Errorf("event: subscriber buffer must be positive, got %d", buffer)
	}
	s := &Subscriber{
		ch:   make(chan Event, buffer),
		done: make(chan struct{}),
		bus:  b,
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, fmt.Errorf("event: bus is closed")
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s, nil
}

// Publish delivers ev to every subscriber. Publish stamps an event whose
// timestamp is zero with the bus clock (emitters that do not track time can
// publish zero-timestamp events; consumers see the bus-assigned time), then
// validates it and drops invalid ones (counting them in Invalid so emitters
// can observe their own mistakes); valid events are assigned a sequence
// number and delivered to every subscriber under the publish lock, so
// every subscriber receives events in sequence order: a full buffer drops
// the event for that subscriber (per-subscriber and aggregate drop
// counters). A closed bus drops publishes and counts them without assigning
// a sequence number. Publish never blocks the caller: delivery is a
// non-blocking enqueue into bounded subscriber buffers.
func (b *Bus) Publish(ev Event) {
	if ev.At.IsZero() {
		ev.At = b.clock.Now()
	}
	if err := ev.Validate(); err != nil {
		b.invalid.Add(1)
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		b.drops.Add(1)
		return
	}
	ev.Sequence = b.next.Add(1)
	for s := range b.subs {
		if !s.tryDeliver(ev) {
			s.drops.Add(1)
			b.drops.Add(1)
		}
	}
	b.mu.Unlock()
}

// Observe implements Observer: it publishes ev into the bus. Instrumented
// code can therefore be configured with a Bus directly.
func (b *Bus) Observe(ev Event) { b.Publish(ev) }

// Close shuts the bus down: every open subscriber is closed and subsequent
// publishes are dropped (counted in Drops). Closing an already closed bus
// is a no-op. The bus cannot be reopened.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*Subscriber, 0, len(b.subs))
	for s := range b.subs {
		subs = append(subs, s)
	}
	b.subs = make(map[*Subscriber]struct{})
	b.mu.Unlock()
	for _, s := range subs {
		s.closeAndRemove()
	}
}

// Seq returns the highest sequence number assigned to a published event so
// far (0 before the first publish). Closed-bus publishes are dropped
// without a sequence number and never advance it.
func (b *Bus) Seq() uint64 { return b.next.Load() }

// Drops returns the aggregate number of events dropped across every
// subscriber (full buffers, closed-bus publishes).
func (b *Bus) Drops() uint64 { return b.drops.Load() }

// Invalid returns the number of events Publish rejected because they failed
// validation. Invalid events never reach subscribers and are never
// sequenced.
func (b *Bus) Invalid() uint64 { return b.invalid.Load() }

// removeSubscriber detaches s from the bus; called by Subscriber.Close.
func (b *Bus) removeSubscriber(s *Subscriber) {
	b.mu.Lock()
	delete(b.subs, s)
	b.mu.Unlock()
}

// Subscriber is one bounded delivery channel of a Bus. Its buffer is set at
// Subscribe time; full-buffer deliveries are dropped and counted, so a slow
// consumer can never stall a producer. Subscribers are single-consumer:
// exactly one goroutine should call Next or receive from Events at a time.
type Subscriber struct {
	ch   chan Event
	done chan struct{}
	once sync.Once
	bus  *Bus

	drops atomic.Uint64
}

// Events returns the subscriber's delivery channel. The channel is NEVER
// closed; a closed subscriber simply stops receiving. Consumers that select
// on it (the TUI controller) must also select on Done (or their own
// cancellation) so a closed subscriber cannot block them forever.
func (s *Subscriber) Events() <-chan Event { return s.ch }

// Done returns a channel that is closed when the subscriber is closed.
func (s *Subscriber) Done() <-chan struct{} { return s.done }

// Next returns the next event, blocking until one is available, the
// subscription is closed, or ctx is done. It returns ErrSubscriptionClosed
// once the subscriber is closed (after draining whatever remains in the
// buffer) and ctx.Err() if ctx is cancelled first.
func (s *Subscriber) Next(ctx context.Context) (Event, error) {
	if ctx == nil {
		return Event{}, fmt.Errorf("event: context must not be nil")
	}
	select {
	case ev := <-s.ch:
		return ev, nil
	default:
	}
	select {
	case ev := <-s.ch:
		return ev, nil
	case <-s.done:
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

// Close unsubscribes s from the bus, dropping any events not yet delivered
// to its buffer. It is safe to call multiple times and from multiple
// goroutines; the closed signal fires exactly once. Recv on a closed
// subscriber returns nothing; the caller must select on Done.
func (s *Subscriber) Close() {
	s.once.Do(func() { close(s.done) })
	s.bus.removeSubscriber(s)
}

// closeAndRemove is the bus's internal close path (Bus.Close): it only
// fires the closed signal; the caller performs the map removal. The
// sync.Once keeps it from interfering with a concurrent user Close.
func (s *Subscriber) closeAndRemove() {
	s.once.Do(func() { close(s.done) })
}

// Drops returns how many events were dropped for this subscriber because
// its buffer was full.
func (s *Subscriber) Drops() uint64 { return s.drops.Load() }

// tryDeliver sends ev without blocking. It reports whether the event was
// buffered (false = dropped due to a full buffer or a closed subscriber).
func (s *Subscriber) tryDeliver(ev Event) bool {
	select {
	case s.ch <- ev:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}
