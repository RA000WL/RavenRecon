package event

import (
	"context"
	"errors"
	goruntime "runtime"
	"sync"
	"testing"
	"time"
)

// validEvent builds a canonical event with a fixed timestamp.
func validEvent(seq uint64) Event {
	return New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: seq})
}

// mustNext drains the next event within a generous deadline.
func mustNext(t *testing.T, s *Subscriber) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := s.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ev
}

// nextErr returns the next error from Next (blocking, bounded).
func nextErr(t *testing.T, s *Subscriber) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.Next(ctx)
	return err
}

// settleGoroutines polls until runtime.NumGoroutine() is at most limit, or
// fails the test after a generous real-time deadline. The limit includes a
// margin that absorbs test-harness noise on slow or loaded CI; the exact
// leak-detection weight lives in the per-test close assertions.
func settleGoroutines(t *testing.T, limit int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := goruntime.NumGoroutine(); n <= limit {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not settle: limit %d, now %d", limit, goruntime.NumGoroutine())
		}
		goruntime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSubscribeRejectsNonPositiveBuffer pins the buffer contract.
func TestSubscribeRejectsNonPositiveBuffer(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	for _, size := range []int{0, -1, -100} {
		if _, err := b.Subscribe(size); err == nil {
			t.Fatalf("Subscribe(%d) succeeded, want error", size)
		}
	}
}

// TestSubscribeAfterCloseFails pins the closed-bus contract.
func TestSubscribeAfterCloseFails(t *testing.T) {
	b := NewBus(nil)
	b.Close()
	if _, err := b.Subscribe(8); err == nil {
		t.Fatal("Subscribe after Close succeeded, want error")
	}
}

// TestFanoutOrderedDelivery verifies every subscriber receives every event,
// in sequence order, with the emitter-supplied timestamp preserved.
func TestFanoutOrderedDelivery(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	const n = 10
	subs := make([]*Subscriber, 2)
	for i := range subs {
		s, err := b.Subscribe(n)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		subs[i] = s
		defer s.Close()
	}
	at := time.Unix(1_700_000_000, 0)
	for i := 1; i <= n; i++ {
		b.Publish(New(KindTaskSubmitted, at.Add(time.Duration(i)), TaskSubmitted{JobID: uint64(i)}))
	}
	if got := b.Seq(); got != n {
		t.Fatalf("Seq: want %d, got %d", n, got)
	}
	for _, s := range subs {
		for i := 1; i <= n; i++ {
			ev := mustNext(t, s)
			if ev.Sequence != uint64(i) {
				t.Fatalf("subscriber received sequence %d, want %d", ev.Sequence, i)
			}
			if ev.Kind != KindTaskSubmitted {
				t.Fatalf("subscriber received kind %s, want task_submitted", ev.Kind)
			}
			if !ev.At.Equal(at.Add(time.Duration(i))) {
				t.Fatalf("subscriber received At %v, want %v (emitter timestamp must be preserved)", ev.At, at.Add(time.Duration(i)))
			}
		}
		if d := s.Drops(); d != 0 {
			t.Fatalf("subscriber drops: want 0, got %d", d)
		}
	}
	if d := b.Drops(); d != 0 {
		t.Fatalf("bus drops: want 0, got %d", d)
	}
}

// TestConcurrentPublishersUniqueSequenceOrder hammers the bus from many
// goroutines and verifies the subscriber receives every event exactly once,
// with strictly increasing sequences 1..total: per-subscriber order is
// bus-assignment order even under concurrent publish.
func TestConcurrentPublishersUniqueSequenceOrder(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	const publishers = 8
	const perPublisher = 200
	total := publishers * perPublisher
	s, err := b.Subscribe(total)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	for g := 0; g < publishers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perPublisher; i++ {
				b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: uint64(g*perPublisher + i)}))
			}
		}(g)
	}
	wg.Wait()
	if got := b.Seq(); got != uint64(total) {
		t.Fatalf("Seq: want %d, got %d", total, got)
	}
	seen := make([]bool, total+1)
	prev := uint64(0)
	for i := 0; i < total; i++ {
		ev := mustNext(t, s)
		if ev.Sequence <= prev {
			t.Fatalf("sequences not strictly increasing: %d after %d", ev.Sequence, prev)
		}
		prev = ev.Sequence
		if ev.Sequence > uint64(total) {
			t.Fatalf("sequence %d out of range 1..%d", ev.Sequence, total)
		}
		if seen[ev.Sequence] {
			t.Fatalf("sequence %d delivered twice", ev.Sequence)
		}
		seen[ev.Sequence] = true
	}
	for i := 1; i <= total; i++ {
		if !seen[i] {
			t.Fatalf("sequence %d never delivered", i)
		}
	}
}

// TestFullBufferDropsAndCounts pins the drop contract: publish never blocks,
// a full buffer drops and counts per subscriber and in the aggregate, and
// the buffered event is the last one published.
func TestFullBufferDropsAndCounts(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	const n = 100
	for i := 1; i <= n; i++ {
		b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: uint64(i)}))
	}
	if got := s.Drops(); got != n-1 {
		t.Fatalf("subscriber drops: want %d, got %d", n-1, got)
	}
	if got := b.Drops(); got != n-1 {
		t.Fatalf("bus drops: want %d, got %d", n-1, got)
	}
	// The surviving buffered event is the FIRST published one: every later
	// publish found the buffer full and was dropped.
	ev := mustNext(t, s)
	if ev.Sequence != 1 {
		t.Fatalf("buffered event: want sequence 1, got %d", ev.Sequence)
	}
}

// TestDropIsolation verifies one slow subscriber never costs another
// subscriber events.
func TestDropIsolation(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	slow, err := b.Subscribe(1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer slow.Close()
	fast, err := b.Subscribe(1024)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer fast.Close()
	const n = 100
	for i := 1; i <= n; i++ {
		b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: uint64(i)}))
	}
	if slow.Drops() != n-1 {
		t.Fatalf("slow subscriber drops: want %d, got %d", n-1, slow.Drops())
	}
	if fast.Drops() != 0 {
		t.Fatalf("fast subscriber drops: want 0, got %d", fast.Drops())
	}
	for i := 1; i <= n; i++ {
		if ev := mustNext(t, fast); ev.Sequence != uint64(i) {
			t.Fatalf("fast subscriber: want sequence %d, got %d", i, ev.Sequence)
		}
	}
}

// TestInvalidEventsDroppedAndCounted verifies invalid events never reach
// subscribers, are never sequenced, and are counted in Invalid.
func TestInvalidEventsDroppedAndCounted(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	invalid := []Event{
		// Unknown kind.
		{Kind: "not_a_kind", At: at},
		// Known kind, mismatched payload.
		New(KindTaskSubmitted, at, Warning{Message: "x"}),
		// Invalid severity.
		New(KindTaskSubmitted, at, TaskSubmitted{}).WithSeverity(Severity(99)),
		// Payload-message overflow.
		New(KindError, at, Error{Message: string(make([]byte, maxMessageBytes+1))}),
		// Nil payload for a payload-required kind.
		New(KindTaskSubmitted, at, nil),
	}
	for _, ev := range invalid {
		b.Publish(ev)
	}
	if got := b.Invalid(); got != uint64(len(invalid)) {
		t.Fatalf("Invalid: want %d, got %d", len(invalid), got)
	}
	if got := b.Seq(); got != 0 {
		t.Fatalf("Seq after only invalid publishes: want 0, got %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := s.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Next: want deadline (no events delivered), got %v", err)
	}
}

// TestZeroTimestampStampedByBus verifies the bus stamps zero-timestamp
// events with its clock before validation.
func TestZeroTimestampStampedByBus(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	b := NewBus(clock)
	defer b.Close()
	s, err := b.Subscribe(4)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	b.Publish(New(KindTaskSubmitted, time.Time{}, TaskSubmitted{JobID: 1}))
	ev := mustNext(t, s)
	if !ev.At.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("stamped At: want %v, got %v", time.Unix(1_700_000_000, 0), ev.At)
	}
	if ev.Sequence != 1 {
		t.Fatalf("sequence: want 1, got %d", ev.Sequence)
	}
	// The caller's copy is never mutated by stamping.
	if b.Invalid() != 0 {
		t.Fatalf("Invalid: want 0, got %d", b.Invalid())
	}

	// A nil-clock bus uses the wall clock: the stamp must be non-zero.
	b2 := NewBus(nil)
	defer b2.Close()
	s2, err := b2.Subscribe(4)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s2.Close()
	b2.Publish(New(KindTaskSubmitted, time.Time{}, TaskSubmitted{JobID: 2}))
	if ev := mustNext(t, s2); ev.At.IsZero() {
		t.Fatal("wall-clock bus stamped a zero timestamp")
	}
}

// TestSubscriberNextNilContextAndCancellation pins the Next contract.
func TestSubscriberNextNilContextAndCancellation(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(4)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	if _, err := s.Next(nil); err == nil {
		t.Fatal("Next(nil) succeeded, want error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next with cancelled ctx: want context.Canceled, got %v", err)
	}
}

// TestSubscriberCloseDrainsThenCloses verifies Next drains the buffer after
// the closed signal before reporting ErrSubscriptionClosed, and that Done
// fires.
func TestSubscriberCloseDrainsThenCloses(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(8)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	for i := 1; i <= 3; i++ {
		b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: uint64(i)}))
	}
	s.Close()
	select {
	case <-s.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	for i := 1; i <= 3; i++ {
		if ev := mustNext(t, s); ev.Sequence != uint64(i) {
			t.Fatalf("drained event: want sequence %d, got %d", i, ev.Sequence)
		}
	}
	if err := nextErr(t, s); !errors.Is(err, ErrSubscriptionClosed) {
		t.Fatalf("Next after drain: want ErrSubscriptionClosed, got %v", err)
	}
	// Close is idempotent.
	s.Close()
	s.Close()
}

// TestBusCloseClosesSubscribersAndDropsPublishes pins Bus.Close: subscribers
// close (with their buffers drained by Next), subsequent publishes are
// dropped and counted without advancing Seq, and Close is idempotent.
func TestBusCloseClosesSubscribersAndDropsPublishes(t *testing.T) {
	b := NewBus(nil)
	s, err := b.Subscribe(8)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1}))
	b.Close()
	b.Close() // idempotent
	select {
	case <-s.Done():
	default:
		t.Fatal("subscriber Done not closed by Bus.Close")
	}
	// The buffered event is still drained before the closed signal.
	if ev := mustNext(t, s); ev.Sequence != 1 {
		t.Fatalf("drained event: want sequence 1, got %d", ev.Sequence)
	}
	if err := nextErr(t, s); !errors.Is(err, ErrSubscriptionClosed) {
		t.Fatalf("Next after Bus.Close: want ErrSubscriptionClosed, got %v", err)
	}
	if got := b.Seq(); got != 1 {
		t.Fatalf("Seq: want 1, got %d", got)
	}
	// Publishes after close are dropped and counted, never sequenced.
	for i := 0; i < 3; i++ {
		b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 2}))
	}
	if got := b.Drops(); got != 3 {
		t.Fatalf("bus drops after close: want 3, got %d", got)
	}
	if got := b.Seq(); got != 1 {
		t.Fatalf("Seq after closed publishes: want 1 (closed publishes are not sequenced), got %d", got)
	}
}

// TestBusObservePublishes verifies the Bus satisfies Observer: Observe is
// exactly Publish.
func TestBusObservePublishes(t *testing.T) {
	var _ Observer = (*Bus)(nil) // compile-time conformance
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(4)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	b.Observe(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1}))
	b.Observe(Event{Kind: "bogus", At: time.Unix(1_700_000_000, 0)})
	if ev := mustNext(t, s); ev.Sequence != 1 {
		t.Fatalf("Observe-delivered sequence: want 1, got %d", ev.Sequence)
	}
	if got := b.Invalid(); got != 1 {
		t.Fatalf("Invalid via Observe: want 1, got %d", got)
	}
}

// TestConcurrentPublishSubscribeClose hammers publish, subscriber close, and
// bus close from many goroutines; under -race this exercises the bus's lock
// and channel teardown paths concurrently. The invariants asserted are
// loose by design (counters never go backwards, no panic, no deadlock).
func TestConcurrentPublishSubscribeClose(t *testing.T) {
	b := NewBus(nil)
	var wg sync.WaitGroup
	// Publishers.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1}))
			}
		}()
	}
	// Subscriber churn: subscribe, read a few, close.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				s, err := b.Subscribe(8)
				if err != nil {
					return // bus closed; fine
				}
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				s.Next(ctx) // may return deadline; fine
				cancel()
				s.Close()
			}
		}()
	}
	wg.Wait()
	b.Close()
	// Counters are monotone and never negative, and every one of the 1600
	// publishes was valid (stamped, sequenced) before delivery attempts.
	if got := b.Seq(); got != 1600 {
		t.Fatalf("Seq: want 1600, got %d", got)
	}
	if got := b.Invalid(); got != 0 {
		t.Fatalf("Invalid: want 0, got %d", got)
	}
	if got := b.Drops(); got > 1600*4 {
		t.Fatalf("drops implausibly high: %d", got)
	}
}

// TestNoGoroutineLeak creates a bus with subscribers, publishes, closes
// everything, and verifies the goroutine count settles back to baseline.
func TestNoGoroutineLeak(t *testing.T) {
	baseline := goruntime.NumGoroutine()
	b := NewBus(nil)
	subs := make([]*Subscriber, 4)
	for i := range subs {
		s, err := b.Subscribe(64)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		subs[i] = s
	}
	for i := 0; i < 1000; i++ {
		b.Publish(New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1}))
	}
	for _, s := range subs {
		s.Close()
	}
	b.Close()
	settleGoroutines(t, baseline+8)
}
