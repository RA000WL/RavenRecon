package runtime

import (
	"context"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestPool(t *testing.T, cfg Config) *Pool {
	t.Helper()
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 4
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 64
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	p, err := NewPool(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return p
}

func shutdownPool(t *testing.T, p *Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// nextWithin returns the next event, failing the test if it does not arrive
// within d (a generous upper bound; tests never assert on short wall-clock
// intervals).
func nextWithin(t *testing.T, s *Subscription, d time.Duration) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	ev, err := s.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ev
}

func TestKindString(t *testing.T) {
	want := map[Kind]string{
		EventStarted:   "started",
		EventCompleted: "completed",
		EventFailed:    "failed",
		EventCancelled: "cancelled",
		EventTimedOut:  "timed-out",
	}
	for k, s := range want {
		if got := k.String(); got != s {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), got, s)
		}
	}
}

func TestSubscribeValidatesBuffer(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	if _, err := p.Subscribe(0); err == nil {
		t.Fatal("Subscribe(0): expected error")
	}
	if _, err := p.Subscribe(-1); err == nil {
		t.Fatal("Subscribe(-1): expected error")
	}
}

func TestSubscribeAfterShutdown(t *testing.T) {
	p := newTestPool(t, Config{})
	shutdownPool(t, p)
	if _, err := p.Subscribe(8); err != ErrPoolClosed {
		t.Fatalf("Subscribe after shutdown: want ErrPoolClosed, got %v", err)
	}
}

func TestSubscriptionClosedByUser(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(8)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	s.Close()
	s.Close() // idempotent, must not panic
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Next(ctx); err != ErrSubscriptionClosed {
		t.Fatalf("Next after Close: want ErrSubscriptionClosed, got %v", err)
	}
}

func TestSubscriptionClosedByPoolShutdown(t *testing.T) {
	p := newTestPool(t, Config{})
	s, err := p.Subscribe(8)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	shutdownPool(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Next(ctx); err != ErrSubscriptionClosed {
		t.Fatalf("Next after pool shutdown: want ErrSubscriptionClosed, got %v", err)
	}
}

func TestNextHonorsContext(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(8)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Next(ctx); err != context.Canceled {
		t.Fatalf("Next with cancelled ctx: want context.Canceled, got %v", err)
	}
}

// TestNextReturnsBufferedEventsAfterClose pins down the documented close
// semantics (F3): events already delivered to the buffer when the
// subscription is closed are returned by some Next call before, or
// interleaved with, ErrSubscriptionClosed — no buffered event is lost, and
// the closed signal is only reported once the buffer has been drained.
//
// The pre-fix code could report ErrSubscriptionClosed while buffered events
// remained (its second select is evaluated with both the buffer and the
// closed signal ready when events arrive concurrently with the close, and Go
// then picks among ready cases randomly); the fix drains the buffer after the
// closed signal fires. This test asserts the resulting guarantee
// deterministically: with a mix of pre-buffered counts, the closed signal
// must never be reported while events are still in the channel.
func TestNextReturnsBufferedEventsAfterClose(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	// A mix of buffered counts exercises both the "first select drains
	// everything" path and the path where the closed signal fires while
	// events remain in the buffer (the drain path).
	for _, buffered := range []int{1, 2, 3} {
		for iter := 0; iter < 20; iter++ {
			s, err := p.Subscribe(16)
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			jobID := JobID(iter*10 + buffered)
			want := make([]Event, 0, buffered)
			for j := 0; j < buffered; j++ {
				want = append(want, Event{Kind: EventStarted, JobID: jobID, Result: j})
			}
			for _, ev := range want {
				s.ch <- ev // buffer directly (same package: channel + Next/Close are the unit under test)
			}
			s.Close() // the closed signal fires with events already buffered

			var got []Event
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ev, err := s.Next(ctx)
				cancel()
				if err == ErrSubscriptionClosed {
					break
				}
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				got = append(got, ev)
			}
			// Every buffered event must have been returned before the
			// closed signal, in order.
			if len(got) != len(want) {
				t.Fatalf("buffered=%d iter=%d: want %d events returned before closed, got %d: %+v", buffered, iter, len(want), len(got), got)
			}
			for i, w := range want {
				if got[i].Kind != w.Kind || got[i].JobID != w.JobID {
					t.Fatalf("buffered=%d iter=%d: event %d: want %+v, got %+v", buffered, iter, i, w, got[i])
				}
			}
			// The closed signal must not have been reported while the
			// buffer still held events (nothing else sends here, so the
			// buffer is now stable and must be empty).
			select {
			case ev := <-s.ch:
				t.Fatalf("buffered=%d iter=%d: ErrSubscriptionClosed reported while %+v was still buffered (event lost by Close)", buffered, iter, ev)
			default:
			}
		}
	}
}

// TestEventDeliveryOrderPerJob verifies that events for one job are delivered
// to a subscriber in order (started before the terminal event) and that a
// completed job's result is attached to its completion event.
func TestEventDeliveryOrderPerJob(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	id, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		return "ok", nil
	}})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventStarted || ev.JobID != id || ev.StartedAt.IsZero() {
		t.Fatalf("first event: want started for job %d, got %+v", id, ev)
	}
	ev = nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventCompleted || ev.JobID != id || ev.Result != "ok" {
		t.Fatalf("second event: want completed for job %d with result ok, got %+v", id, ev)
	}
	if ev.Err != nil {
		t.Fatalf("completed event must not carry an error, got %v", ev.Err)
	}
}

// settleGoroutines polls until runtime.NumGoroutine() is at most limit, or
// fails the test after a generous real-time deadline. Used by leak tests;
// never asserts on short wall-clock intervals. The limit includes a margin
// that absorbs test-harness noise (the testing framework's own goroutines,
// background timers, and unrelated activity on a loaded machine), so the
// margin alone is a coarse signal: the exact leak-detection weight lives in
// assertPoolDrained, which pins down the pool's own state.
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

// waitWGZero blocks (bounded) until wg has no pending Add calls, i.e. every
// goroutine it accounts for has finished. It fails the test after a generous
// deadline instead of hanging, so a leaked pool-owned goroutine surfaces as
// a test failure rather than a stuck suite.
func waitWGZero(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s wait group did not reach zero after shutdown", what)
	}
}

// assertPoolDrained pins down the pool's own state after Shutdown has
// returned: every subscription must have been closed and removed, and both
// internal wait groups (in-flight Submits and worker goroutines) must be at
// zero. These are exact assertions — unlike the widened NumGoroutine margin,
// they cannot be fooled by unrelated goroutines on a loaded machine, so they
// carry the real weight of pool-leak detection.
func assertPoolDrained(t *testing.T, p *Pool) {
	t.Helper()
	p.subsMu.Lock()
	n := len(p.subs)
	p.subsMu.Unlock()
	if n != 0 {
		t.Fatalf("pool still tracks %d subscriptions after shutdown", n)
	}
	waitWGZero(t, &p.submitters, "submitters")
	waitWGZero(t, &p.workers, "workers")
}

// TestEventOverflowBackpressure documents the blocking overflow policy: a
// subscriber that does not drain applies backpressure to the emitting worker
// (and eventually to the whole single-worker pool), but draining the
// subscription unwinds everything: no deadlock, no lost events, no corrupted
// state. The assertions are causal, not wall-clock.
func TestEventOverflowBackpressure(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 1, Timeout: 5 * time.Second})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(1) // deliberately tiny buffer, never enough
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	var runCount atomic.Int32
	release := make(chan struct{})
	holder := func(ctx context.Context) (any, error) {
		<-release // hold the single worker
		runCount.Add(1)
		return "holder", nil
	}
	quick := func(ctx context.Context) (any, error) {
		runCount.Add(1)
		return "quick", nil
	}

	holderID, err := p.Submit(context.Background(), Job{Func: holder})
	if err != nil {
		t.Fatalf("Submit holder: %v", err)
	}
	// The holder's started event fills the subscription's single buffer slot.
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted || ev.JobID != holderID {
		t.Fatalf("want started for holder %d, got %+v", holderID, ev)
	}
	if _, err := p.Submit(context.Background(), Job{Func: quick}); err != nil {
		t.Fatalf("Submit quick: %v", err)
	}

	// Queue (capacity 1) is full and the worker is busy in the holder; a
	// third submission must block on the bounded queue.
	blocked := make(chan struct{})
	go func() {
		p.Submit(context.Background(), Job{Func: quick})
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("Submit returned while the queue was full and the worker stalled")
	case <-time.After(200 * time.Millisecond):
	}

	// Release the holder: the worker now stalls delivering the holder's
	// completion into the full buffer. Draining one event at a time releases
	// exactly one worker send, so the pool makes progress and no event is
	// lost.
	close(release)
	seenPerJob := map[JobID]bool{holderID: true} // S-holder was consumed above
	var started, completed int
	// Remaining events: C-holder, then started+completed for the two quick
	// jobs = 5 events total.
	for started+completed < 5 {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
			started++
			if seenPerJob[ev.JobID] {
				t.Fatalf("job %d: duplicate started event", ev.JobID)
			}
			seenPerJob[ev.JobID] = true
		case EventCompleted:
			completed++
			if !seenPerJob[ev.JobID] {
				t.Fatalf("job %d: completed before started", ev.JobID)
			}
		default:
			t.Fatalf("unexpected event kind %v", ev.Kind)
		}
	}
	if started != 2 || completed != 3 {
		t.Fatalf("want 2 started and 3 completed, got %d/%d", started, completed)
	}
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("blocked Submit did not complete during the drain")
	}
	if got := runCount.Load(); got != 3 {
		t.Fatalf("want 3 jobs executed, got %d", got)
	}

	// The pool is not corrupted: it still accepts and runs work, and a new
	// subscriber sees fresh events while the old one stays independent. The
	// old subscription has capacity 1, so its buffer must be drained
	// concurrently or the worker will stall delivering into it before it
	// reaches the new subscriber.
	s2, err := p.Subscribe(8)
	if err != nil {
		t.Fatalf("second Subscribe: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: quick}); err != nil {
		t.Fatalf("Submit after drain: %v", err)
	}
	seenOld, seenNew := 0, 0
	// Drain until the new subscription has seen the job's two events AND the
	// old capacity-1 buffer has been drained of the same two events; the
	// select between the two channels is random, so exiting on seenNew alone
	// can leave the old subscriber (and the worker blocked on its full
	// buffer) partially drained.
	for seenNew < 2 || seenOld < 2 { // the new job produces exactly two events on s2
		select {
		case <-s.ch: // keep the capacity-1 old buffer drained
			seenOld++
		case ev := <-s2.ch:
			if ev.Kind != EventStarted && ev.Kind != EventCompleted {
				t.Fatalf("unexpected event %+v", ev)
			}
			seenNew++
		}
	}
	if seenOld < 2 {
		t.Fatalf("old subscriber saw %d events, want at least 2", seenOld)
	}
	if got := runCount.Load(); got != 4 {
		t.Fatalf("want 4 jobs executed after the drain, got %d", got)
	}
}

// TestWedgedSubscriberForcedShutdown verifies that a subscriber that never
// drains cannot deadlock the pool: forcing shutdown cancels the pool, the
// worker abandons the blocked delivery, and Shutdown returns the drain
// context error with no goroutines left behind.
func TestWedgedSubscriberForcedShutdown(t *testing.T) {
	baseline := goruntime.NumGoroutine()
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 4, Timeout: time.Second})
	s, err := p.Subscribe(1) // never drained
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	_ = s
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		return "done", nil
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// The worker is now blocked delivering the completion event into the full
	// buffer. A graceful shutdown would wait forever; the drain context
	// forces it.
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = p.Shutdown(dctx)
	if err == nil {
		t.Fatal("Shutdown: want forced-shutdown error, got nil")
	}
	assertPoolDrained(t, p)
	// The widened margin absorbs test-harness noise; the exact
	// leak-detection weight is in assertPoolDrained above.
	settleGoroutines(t, baseline+8)
}
