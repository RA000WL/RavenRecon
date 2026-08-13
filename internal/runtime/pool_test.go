package runtime

import (
	"context"
	"errors"
	"fmt"
	"math"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// quickJob returns a constant result immediately.
func quickJob(ctx context.Context) (any, error) { return "quick", nil }

func TestPoolValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil context", Config{Concurrency: 1, QueueSize: 1}},
		{"zero concurrency", Config{Concurrency: 0, QueueSize: 1}},
		{"negative concurrency", Config{Concurrency: -1, QueueSize: 1}},
		{"zero queue", Config{Concurrency: 1, QueueSize: 0}},
		{"negative queue", Config{Concurrency: 1, QueueSize: -1}},
		{"negative timeout", Config{Concurrency: 1, QueueSize: 1, Timeout: -time.Second}},
		{"negative rate", Config{Concurrency: 1, QueueSize: 1, Rate: -1}},
		// NaN and infinities must be rejected, not silently accepted as
		// "rate disabled": math.NaN() < 0 is false, so without an explicit
		// finiteness check an NaN rate would slip past validation and
		// silently disable the central rate limiter.
		{"NaN rate", Config{Concurrency: 1, QueueSize: 1, Rate: math.NaN()}},
		{"+Inf rate", Config{Concurrency: 1, QueueSize: 1, Rate: math.Inf(1)}},
		{"-Inf rate", Config{Concurrency: 1, QueueSize: 1, Rate: math.Inf(-1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.name == "nil context" {
				ctx = nil
			}
			if _, err := NewPool(ctx, tc.cfg); err == nil {
				t.Fatal("NewPool: expected error")
			}
		})
	}
	// Valid configs must still succeed and be released (no leaked workers).
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"rate disabled", Config{Concurrency: 1, QueueSize: 1, Rate: 0}},
		{"positive finite rate", Config{Concurrency: 1, QueueSize: 1, Rate: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPool(context.Background(), tc.cfg)
			if err != nil {
				t.Fatalf("NewPool with %s: %v", tc.name, err)
			}
			if err := p.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
		})
	}
}

func TestSubmitValidatesArgs(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	if _, err := p.Submit(nil, Job{Func: quickJob}); err == nil {
		t.Fatal("Submit with nil context: expected error")
	}
	if _, err := p.Submit(context.Background(), Job{}); err == nil {
		t.Fatal("Submit with nil Func: expected error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Submit(ctx, Job{Func: quickJob}); err == nil {
		t.Fatal("Submit with cancelled context: expected error")
	}
}

func TestSuccessfulJob(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	id, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		return 42, nil
	}})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventStarted || ev.JobID != id {
		t.Fatalf("want started for job %d, got %+v", id, ev)
	}
	ev = nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventCompleted || ev.JobID != id || ev.Result != 42 {
		t.Fatalf("want completed with result 42 for job %d, got %+v", id, ev)
	}
	if ev.Err != nil {
		t.Fatalf("completed event must not carry an error, got %v", ev.Err)
	}
}

func TestFailedJob(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	boom := errors.New("boom")
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		return nil, boom
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventFailed {
		t.Fatalf("want failed, got %+v", ev)
	}
	if !errors.Is(ev.Err, boom) {
		t.Fatalf("failed event must wrap the job error, got %v", ev.Err)
	}
	if ev.Result != nil {
		t.Fatalf("failed event must not carry a result, got %v", ev.Result)
	}
}

// TestPoolContextCancellation verifies that cancelling the pool's context
// mid-job is reported as cancelled — never as failed, and never as success
// even if the job returns a value.
func TestPoolContextCancellation(t *testing.T) {
	pctx, cancel := context.WithCancel(context.Background())
	p, err := NewPool(pctx, Config{Concurrency: 2, QueueSize: 8, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	sawCancel := make(chan error, 1)
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		sawCancel <- ctx.Err()
		// Deliberately return success values: cancellation must still win.
		return "late", nil
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	cancel()
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventCancelled {
		t.Fatalf("want cancelled, got %+v", ev)
	}
	if !errors.Is(ev.Err, context.Canceled) {
		t.Fatalf("cancelled event must wrap context.Canceled, got %v", ev.Err)
	}
	select {
	case err := <-sawCancel:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("job context: want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("job did not observe cancellation")
	}
}

// TestCancellationBeatsJobError verifies the terminal-classification
// precedence when the job returns a non-nil error only after its context was
// cancelled: the event must be EventCancelled — the error must NOT surface
// as EventFailed, and the cancelled event must not carry the job's error.
func TestCancellationBeatsJobError(t *testing.T) {
	pctx, cancel := context.WithCancel(context.Background())
	p, err := NewPool(pctx, Config{Concurrency: 2, QueueSize: 8, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	jobErr := errors.New("late failure after cancellation")
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		return nil, jobErr
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	cancel()
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventCancelled {
		t.Fatalf("want cancelled (the job error must not surface as failed), got %+v", ev)
	}
	if !errors.Is(ev.Err, context.Canceled) {
		t.Fatalf("cancelled event must wrap context.Canceled, got %v", ev.Err)
	}
	if errors.Is(ev.Err, jobErr) {
		t.Fatalf("cancelled event must not carry the job's error, got %v", ev.Err)
	}
}

// TestPerJobTimeout verifies that a job exceeding its deadline is surfaced
// distinctly as timed-out, never as success and never as failed.
func TestPerJobTimeout(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 60 * time.Millisecond})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	jobErr := make(chan error, 1)
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		jobErr <- ctx.Err()
		return "late", nil // success values must not win against the deadline
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventTimedOut {
		t.Fatalf("want timed-out, got %+v", ev)
	}
	if !errors.Is(ev.Err, context.DeadlineExceeded) {
		t.Fatalf("timed-out event must wrap context.DeadlineExceeded, got %v", ev.Err)
	}
	if ev.Result != nil {
		t.Fatalf("timed-out event must not carry a result, got %v", ev.Result)
	}
	select {
	case err := <-jobErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("job context: want DeadlineExceeded, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("job did not observe its deadline")
	}
}

// TestTimeoutBeatsJobError verifies the terminal-classification precedence
// when the job exceeds its deadline and then returns a non-nil error: the
// event must be EventTimedOut — the error must NOT surface as EventFailed,
// and the timed-out event must not carry the job's error.
func TestTimeoutBeatsJobError(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 50 * time.Millisecond})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	jobErr := errors.New("late failure after timeout")
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		return nil, jobErr
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventTimedOut {
		t.Fatalf("want timed-out (the job error must not surface as failed), got %+v", ev)
	}
	if !errors.Is(ev.Err, context.DeadlineExceeded) {
		t.Fatalf("timed-out event must wrap context.DeadlineExceeded, got %v", ev.Err)
	}
	if errors.Is(ev.Err, jobErr) {
		t.Fatalf("timed-out event must not carry the job's error, got %v", ev.Err)
	}
}

// TestPerJobTimeoutOverride verifies that Job.Timeout overrides the pool
// default: a short override fires while the pool default is much longer.
func TestPerJobTimeoutOverride(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 10 * time.Second})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		return nil, nil
	}, Timeout: 50 * time.Millisecond}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}
	ev := nextWithin(t, s, 10*time.Second)
	if ev.Kind != EventTimedOut {
		t.Fatalf("want timed-out from per-job override, got %+v", ev)
	}
}

// TestTimeoutWhileWaitingForToken verifies that the per-job deadline covers
// the rate-limit token wait: a job that cannot obtain a start token within
// its deadline is reported as timed out, with no Started event.
func TestTimeoutWhileWaitingForToken(t *testing.T) {
	// rate 1/s, burst 1: the second job would need a full second, but its
	// deadline is 80ms.
	p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 80 * time.Millisecond, Rate: 1})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
			return i, nil
		}}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	// The first job starts and completes; the second times out waiting for a
	// token. Collect until we have one completed and one timed-out event.
	var completed, timedOut int
	for completed+timedOut < 2 {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
			// Ignore started events; only terminal kinds matter here.
		case EventCompleted:
			completed++
		case EventTimedOut:
			timedOut++
			if !ev.StartedAt.IsZero() {
				t.Fatalf("timed-out-before-start must have zero StartedAt, got %v", ev.StartedAt)
			}
			if !errors.Is(ev.Err, context.DeadlineExceeded) {
				t.Fatalf("want DeadlineExceeded, got %v", ev.Err)
			}
		default:
			t.Fatalf("unexpected event %+v", ev)
		}
	}
}

// TestBoundConcurrency verifies that at most Config.Concurrency jobs run in
// parallel, and that with concurrency 2 the parallelism is actually reached.
func TestBoundConcurrency(t *testing.T) {
	const concurrency = 2
	p := newTestPool(t, Config{Concurrency: concurrency, QueueSize: 64, Timeout: 5 * time.Second})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	var inFlight, maxInFlight atomic.Int32
	job := func(ctx context.Context) (any, error) {
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := maxInFlight.Load()
			if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		return nil, nil
	}
	const jobs = 8
	for i := 0; i < jobs; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: job}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	// Wait for all completions before asserting the peak.
	completed := 0
	for completed < jobs {
		ev := nextWithin(t, s, 10*time.Second)
		if ev.Kind == EventCompleted {
			completed++
		}
	}
	if got := maxInFlight.Load(); got != concurrency {
		t.Fatalf("max in-flight = %d, want exactly %d", got, concurrency)
	}
}

// TestSubmitBackpressure verifies that Submit blocks while the queue is full
// (bounded, never unbounded growth) and completes once capacity frees up.
func TestSubmitBackpressure(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 1, Timeout: 5 * time.Second})
	defer shutdownPool(t, p)

	release := make(chan struct{})
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-release // hold the single worker
		return nil, nil
	}}); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != nil {
		t.Fatalf("Submit 2: %v", err)
	}

	// The queue (capacity 1) is now full and the worker is busy: the third
	// Submit must block, not return an error and not grow memory.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Submit(ctx, Job{Func: quickJob})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Submit returned while the queue was full")
	case <-time.After(150 * time.Millisecond):
	}

	// Release the worker: the queued job runs, a slot frees, and the blocked
	// Submit completes.
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("blocked Submit did not complete after capacity freed")
	}
}

// TestSubmitCancelledWhileBlocked verifies that a blocked Submit returns the
// submit context's error instead of blocking forever.
func TestSubmitCancelledWhileBlocked(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 1, Timeout: 5 * time.Second})
	defer shutdownPool(t, p)
	release := make(chan struct{})
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-release
		return nil, nil
	}}); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != nil {
		t.Fatalf("Submit 2: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.Submit(ctx, Job{Func: quickJob})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the Submit block
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked Submit: want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Submit did not return after cancellation")
	}
	close(release)
}

// TestBlockedSubmitReleasedByShutdown verifies that a Submit blocked on a
// full queue is released by Shutdown's stopAccept signal: once the pool
// starts shutting down, the blocked Submit returns ErrPoolClosed instead of
// waiting forever for queue capacity that will never free up.
//
// The test is deterministic: the worker is held in a job until after the
// blocked Submit has returned, so the queue stays full for the whole wait and
// the Submit's select can only ever take the stopAccept path.
func TestBlockedSubmitReleasedByShutdown(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 1, Timeout: 5 * time.Second})
	release := make(chan struct{})
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-release // hold the single worker so the queue stays full
		return nil, nil
	}}); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != nil {
		t.Fatalf("Submit 2: %v", err)
	}

	// The queue (capacity 1) is full and the worker is busy in the holder:
	// this Submit must block.
	submitDone := make(chan error, 1)
	go func() {
		_, err := p.Submit(context.Background(), Job{Func: quickJob})
		submitDone <- err
	}()

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- p.Shutdown(ctx)
	}()

	// The blocked Submit can only exit via stopAccept (the queue is full and
	// stays full until release is closed, which happens only after this
	// receive). It must therefore return ErrPoolClosed once Shutdown marks
	// the pool closed.
	select {
	case err := <-submitDone:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("blocked Submit released by Shutdown: want ErrPoolClosed, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("blocked Submit did not return ErrPoolClosed after Shutdown")
	}

	// Now free the worker so the drain can complete and Shutdown can return.
	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return after the blocked Submit was released")
	}
}

// TestGracefulShutdownDrains verifies that Shutdown drains queued and
// in-flight jobs to completion, stops accepting new work, and returns nil.
func TestGracefulShutdownDrains(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 2, QueueSize: 16, Timeout: 5 * time.Second})
	s, err := p.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	const jobs = 3
	for i := 0; i < jobs; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
			time.Sleep(30 * time.Millisecond)
			return nil, nil
		}}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	shutdownPool(t, p) // must return nil: everything drained

	// Every job completed; nothing was cancelled.
	var completed int
	for completed < jobs {
		ev := nextWithin(t, s, 10*time.Second)
		if ev.Kind == EventCompleted {
			completed++
		} else if ev.Kind == EventCancelled || ev.Kind == EventTimedOut {
			t.Fatalf("graceful shutdown must not cancel jobs, got %+v", ev)
		}
	}
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != ErrPoolClosed {
		t.Fatalf("Submit after shutdown: want ErrPoolClosed, got %v", err)
	}
	if _, err := p.Subscribe(8); err != ErrPoolClosed {
		t.Fatalf("Subscribe after shutdown: want ErrPoolClosed, got %v", err)
	}
}

// TestShutdownIdempotent verifies that a second Shutdown returns ErrPoolClosed
// and that Shutdown with a cancelled drain context reports the error.
func TestShutdownIdempotent(t *testing.T) {
	p := newTestPool(t, Config{})
	shutdownPool(t, p)
	if err := p.Shutdown(context.Background()); err != ErrPoolClosed {
		t.Fatalf("second Shutdown: want ErrPoolClosed, got %v", err)
	}
}

// TestConcurrentShutdown verifies that two Shutdown calls racing from two
// goroutines both terminate: exactly one wins the closed flag and returns
// nil, the other sees the pool already closed and returns ErrPoolClosed —
// no hang, no panic, no corruption.
func TestConcurrentShutdown(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 5 * time.Second})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				results <- p.Shutdown(ctx)
			}()
		}
		nils, closed := 0, 0
		for i := 0; i < 2; i++ {
			select {
			case err := <-results:
				switch {
				case err == nil:
					nils++
				case errors.Is(err, ErrPoolClosed):
					closed++
				default:
					t.Fatalf("Shutdown: unexpected error %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("concurrent Shutdown did not return")
			}
		}
		if nils != 1 || closed != 1 {
			t.Fatalf("want exactly one nil and one ErrPoolClosed, got nils=%d closed=%d", nils, closed)
		}
	}
}

// TestShutdownDrainContextCancelled verifies the forced path: cancelling the
// drain context cancels the remaining job (reported as cancelled, never
// success) and Shutdown returns an error wrapping the context error once the
// pool is fully unwound.
func TestShutdownDrainContextCancelled(t *testing.T) {
	p := newTestPool(t, Config{Concurrency: 1, QueueSize: 4, Timeout: 5 * time.Second})
	s, err := p.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	jobErr := make(chan error, 1)
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		<-ctx.Done()
		jobErr <- ctx.Err()
		return "late", nil
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if ev := nextWithin(t, s, 10*time.Second); ev.Kind != EventStarted {
		t.Fatalf("want started, got %+v", ev)
	}

	dctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = p.Shutdown(dctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: want wrapped DeadlineExceeded, got %v", err)
	}

	// The job was cancelled, not completed.
	select {
	case err := <-jobErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("job context: want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("job did not observe cancellation")
	}
	// The terminal event may be delivered (the subscription was healthy and
	// had buffer) — accept either outcome, but never success.
	select {
	case ev := <-s.ch:
		if ev.Kind == EventCompleted {
			t.Fatalf("cancelled job reported as completed: %+v", ev)
		}
	default:
	}
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != ErrPoolClosed {
		t.Fatalf("Submit after forced shutdown: want ErrPoolClosed, got %v", err)
	}
}

// TestPanickingJob verifies that a panicking job is reported as failed and
// does not take the pool (or its siblings) down.
func TestPanickingJob(t *testing.T) {
	p := newTestPool(t, Config{})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(32)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
		panic("kaboom")
	}}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	var sawFailed bool
	for i := 0; i < 2; i++ {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
		case EventFailed:
			sawFailed = true
			if !strings.Contains(ev.Err.Error(), "kaboom") || !strings.Contains(ev.Err.Error(), "panicked") {
				t.Fatalf("panic error missing context: %v", ev.Err)
			}
		default:
			t.Fatalf("unexpected event %+v", ev)
		}
	}
	if !sawFailed {
		t.Fatal("want a failed event for the panicking job")
	}
	// The pool is still healthy.
	if _, err := p.Submit(context.Background(), Job{Func: quickJob}); err != nil {
		t.Fatalf("Submit after panic: %v", err)
	}
	for i := 0; i < 2; i++ {
		ev := nextWithin(t, s, 10*time.Second)
		if ev.Kind == EventFailed {
			t.Fatalf("post-panic job failed unexpectedly: %+v", ev)
		}
	}
}

// TestNoGoroutineLeak runs a batch of jobs through a subscribed pool and
// verifies the goroutine count returns to baseline after Shutdown.
func TestNoGoroutineLeak(t *testing.T) {
	baseline := goruntime.NumGoroutine()
	p := newTestPool(t, Config{Concurrency: 4, QueueSize: 64, Timeout: 5 * time.Second})
	s, err := p.Subscribe(512)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	const jobs = 200
	for i := 0; i < jobs; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
			return i, nil
		}}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	shutdownPool(t, p)

	// No events may be lost: the graceful drain delivered all of them.
	var completed int
	for completed < jobs {
		ev := nextWithin(t, s, 10*time.Second)
		if ev.Kind == EventCompleted {
			completed++
		}
	}
	// The subscription is closed once the pool is done.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Next(ctx); err != ErrSubscriptionClosed {
		t.Fatalf("Next after shutdown: want ErrSubscriptionClosed, got %v", err)
	}
	// Pool-owned state carries the real leak-detection weight (see
	// assertPoolDrained): every subscription removed and both internal wait
	// groups at zero are exact assertions. The goroutine-count margin below
	// is deliberately wider (baseline+8) to absorb test-harness noise on
	// slow or loaded CI while still catching leaks outside pool state.
	assertPoolDrained(t, p)
	settleGoroutines(t, baseline+8)
}

// TestConcurrentSubmissions hammers the pool from many goroutines and
// verifies every job produces exactly one started and one completed event
// with per-job ordering; run under -race this exercises Submit, Shutdown, and
// event delivery concurrently.
func TestConcurrentSubmissions(t *testing.T) {
	const submitters = 8
	const perSubmitter = 50
	p := newTestPool(t, Config{Concurrency: 4, QueueSize: 64, Timeout: 5 * time.Second})
	s, err := p.Subscribe(1024)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	var wg sync.WaitGroup
	for g := 0; g < submitters; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perSubmitter; i++ {
				id, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
					return fmt.Sprintf("g%d-i%d", g, i), nil
				}})
				if err != nil {
					t.Errorf("Submit: %v", err)
					return
				}
				if id == 0 {
					t.Error("Submit returned zero job ID")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	shutdownPool(t, p)

	const total = submitters * perSubmitter
	started := map[JobID]bool{}
	var startedCount, completedCount int
	for completedCount < total {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
			startedCount++
			if started[ev.JobID] {
				t.Fatalf("job %d: duplicate started", ev.JobID)
			}
			started[ev.JobID] = true
		case EventCompleted:
			completedCount++
			if !started[ev.JobID] {
				t.Fatalf("job %d: completed before started", ev.JobID)
			}
		default:
			t.Fatalf("unexpected event %+v", ev)
		}
	}
	if startedCount != total || completedCount != total {
		t.Fatalf("want %d started and %d completed, got %d/%d", total, total, startedCount, completedCount)
	}
}

// TestRateLimitedPoolSpacing verifies with an injected clock that job starts
// are spaced exactly according to the configured rate and that the documented
// burst semantics hold: with burst 1 the first job starts immediately and
// every later start is spaced 1/rate apart.
func TestRateLimitedPoolSpacing(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	p := newTestPool(t, Config{
		Concurrency: 2,
		QueueSize:   16,
		Timeout:     5 * time.Second,
		Rate:        2, // 2 starts/second -> 500ms spacing
		Burst:       1,
		Clock:       fc,
	})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	const jobs = 5
	for i := 0; i < jobs; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
			return i, nil
		}}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	var starts []time.Time
	var completed int
	for completed < jobs || len(starts) < jobs {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
			starts = append(starts, ev.At)
			if len(starts) < jobs {
				// Release exactly one token's worth of fake time: the next
				// start lands exactly 500ms later.
				fc.Advance(500 * time.Millisecond)
			}
		case EventCompleted:
			completed++
		default:
			t.Fatalf("unexpected event %+v", ev)
		}
	}
	if len(starts) != jobs {
		t.Fatalf("want %d starts, got %d", jobs, len(starts))
	}
	for i, got := range starts {
		want := start.Add(time.Duration(i) * 500 * time.Millisecond)
		if !got.Equal(want) {
			t.Fatalf("start %d at %v, want %v (spacing must be exactly 1/rate)", i, got, want)
		}
	}
	if completed != jobs {
		t.Fatalf("want %d completed, got %d", jobs, completed)
	}
}

// TestSubscribeRacingShutdown is a regression test for a Subscribe-vs-Shutdown
// race: a Subscribe that passed its closed-check could register its
// subscription after Shutdown had already closed every subscription,
// orphaning it — its Next would block forever instead of returning
// ErrSubscriptionClosed. The fix makes the closed-check and the map insertion
// atomic under the pool mutex. The test hammers Subscribe concurrently with
// Shutdown and asserts that every subscription obtained before shutdown is
// closed (Next returns ErrSubscriptionClosed) once Shutdown has returned.
func TestSubscribeRacingShutdown(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 5 * time.Second})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var subs []*Subscription
		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := p.Subscribe(4)
				if err == nil {
					mu.Lock()
					subs = append(subs, s)
					mu.Unlock()
				} else if err != ErrPoolClosed {
					t.Errorf("Subscribe: want ErrPoolClosed after shutdown, got %v", err)
				}
			}()
		}
		shutdownPool(t, p)
		wg.Wait()
		mu.Lock()
		got := subs
		mu.Unlock()
		for _, s := range got {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := s.Next(ctx)
			cancel()
			if err != ErrSubscriptionClosed {
				t.Fatalf("Next on subscription obtained while shutting down: want ErrSubscriptionClosed, got %v", err)
			}
		}
	}
}

// TestCloseRacingShutdown is a regression test for the ABBA lock inversion
// between Subscription.Close and Pool.Shutdown: the old Close held the
// subscription's sync.Once mutex while acquiring subsMu (via
// removeSubscription inside the Once closure), while Shutdown's
// closeSubscriptions held subsMu while acquiring the same Once mutex. When
// the two interleaved, both blocked forever and Shutdown never returned. The
// fix moved the map removal out of the Once closure, making the lock
// orderings single-directional (subsMu -> Once, never Once -> subsMu).
//
// The test hammers Close and Shutdown concurrently across several pools and
// asserts that Shutdown returns within a bounded deadline and that every
// subscription obtained before shutdown reaches ErrSubscriptionClosed.
func TestCloseRacingShutdown(t *testing.T) {
	const poolsPerIter = 4
	const subsPerPool = 8
	for iter := 0; iter < 50; iter++ {
		var pools []*Pool
		var allSubs []*Subscription
		for pi := 0; pi < poolsPerIter; pi++ {
			p := newTestPool(t, Config{Concurrency: 2, QueueSize: 8, Timeout: 5 * time.Second})
			pools = append(pools, p)
			for i := 0; i < subsPerPool; i++ {
				s, err := p.Subscribe(4)
				if err != nil {
					t.Fatalf("Subscribe: %v", err)
				}
				allSubs = append(allSubs, s)
			}
		}
		var wg sync.WaitGroup
		for _, p := range pools {
			wg.Add(1)
			go func(p *Pool) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := p.Shutdown(ctx); err != nil {
					t.Errorf("Shutdown: %v", err)
				}
			}(p)
		}
		for _, s := range allSubs {
			wg.Add(1)
			go func(s *Subscription) {
				defer wg.Done()
				s.Close()
			}(s)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			// On the pre-fix code Shutdown and the Closes deadlock here and
			// never complete.
			t.Fatal("Close/Shutdown did not complete: deadlock suspected (ABBA lock inversion between subsMu and the subscription Once)")
		}
		for _, s := range allSubs {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := s.Next(ctx)
			cancel()
			if err != ErrSubscriptionClosed {
				t.Fatalf("Next on subscription after Close/Shutdown: want ErrSubscriptionClosed, got %v", err)
			}
		}
	}
}

// TestRateLimitedPoolBurst verifies the documented burst semantics: with
// burst 3, the first three jobs start immediately and later starts are spaced
// 1/rate apart.
func TestRateLimitedPoolBurst(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fc := newFakeClock(start)
	p := newTestPool(t, Config{
		Concurrency: 2,
		QueueSize:   16,
		Timeout:     5 * time.Second,
		Rate:        2,
		Burst:       3,
		Clock:       fc,
	})
	defer shutdownPool(t, p)
	s, err := p.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	const jobs = 5
	for i := 0; i < jobs; i++ {
		if _, err := p.Submit(context.Background(), Job{Func: func(ctx context.Context) (any, error) {
			return i, nil
		}}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	var starts []time.Time
	var completed int
	for completed < jobs || len(starts) < jobs {
		ev := nextWithin(t, s, 10*time.Second)
		switch ev.Kind {
		case EventStarted:
			starts = append(starts, ev.At)
			// The first three starts need no fake time; the fourth and fifth
			// are each one token (500ms) later.
			if len(starts) == 3 || len(starts) == 4 {
				fc.Advance(500 * time.Millisecond)
			}
		case EventCompleted:
			completed++
		default:
			t.Fatalf("unexpected event %+v", ev)
		}
	}
	want := []time.Time{
		start,
		start,
		start,
		start.Add(500 * time.Millisecond),
		start.Add(time.Second),
	}
	for i, got := range starts {
		if !got.Equal(want[i]) {
			t.Fatalf("start %d at %v, want %v", i, got, want[i])
		}
	}
}

// TestTimedJobsDoNotRetainHeapObjects is a regression test for review finding
// N1: execute() used to derive the job context as
//
//	ctx, cancel := context.WithCancel(p.abortCtx)
//	if d > 0 {
//		ctx, cancel = context.WithTimeout(p.abortCtx, d)
//	}
//	defer cancel()
//
// so every timed job orphaned the WithCancel child: its cancel was
// overwritten by the WithTimeout call and never invoked, leaving one
// cancelCtx registered on p.abortCtx until pool shutdown. Retained heap
// objects therefore grew linearly with the number of timed jobs submitted to
// a long-lived pool (AGENTS.md rule 9: avoid unbounded memory growth).
//
// The test submits a large batch of timed no-op jobs to one small pool and
// asserts that the number of live heap objects stays bounded. The assertion
// happens while the pool is still alive, before Shutdown: the leak is
// anchored on the pool's abortCtx, so it is observable only while the pool
// is reachable. Measuring after Shutdown would miss it entirely — the test's
// last use of p is the Shutdown call itself, so the compiler marks p dead
// and the next GC collects the whole pool (abortCtx and leaked children
// together), hiding the retention.
//
// The allowance is deliberately generous for CI variance: 50,000 heap
// objects. The old code leaks at least one live object per timed job (the
// orphaned cancelCtx struct), i.e. well over 250,000 objects for this batch
// — five times the margin — while the fixed code retains nothing per job, so
// the measured growth is orders of magnitude below it. A warm-up batch runs
// before the baseline so the worker goroutine stacks and the runtime
// allocator have already reached their steady working size. Plain test: no
// t.Parallel (heap stats are process-global) and no subscriber or limiter,
// so each job is a minimal allocation path.
func TestTimedJobsDoNotRetainHeapObjects(t *testing.T) {
	const warmup = 20_000
	const batch = 250_000
	p := newTestPool(t, Config{
		Concurrency: 2,
		QueueSize:   4096,
		// Timeout > 0 puts every job on the deadline path under test; the
		// deadline itself is generously long because the assertion only
		// cares that contexts are released — a no-op must never actually
		// time out, even on a loaded CI under -race.
		Timeout: 5 * time.Second,
	})
	var executed atomic.Int64
	job := func(ctx context.Context) (any, error) {
		executed.Add(1)
		return nil, nil
	}
	submitBatch := func(n int) {
		for i := 0; i < n; i++ {
			if _, err := p.Submit(context.Background(), Job{Func: job}); err != nil {
				t.Fatalf("Submit %d: %v", i, err)
			}
		}
	}
	waitExecuted := func(want int64) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for executed.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("only %d of %d jobs executed before the deadline", executed.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	liveObjects := func() uint64 {
		var ms goruntime.MemStats
		goruntime.ReadMemStats(&ms)
		return ms.HeapObjects
	}

	submitBatch(warmup)
	waitExecuted(warmup)
	goruntime.GC() // collect the warm-up's garbage before the baseline
	goruntime.GC()
	baseline := liveObjects()

	submitBatch(batch)
	waitExecuted(warmup + batch)
	// The pool must still be alive here: p is used by shutdownPool below, so
	// the compiler keeps it live, and the (old-code) orphaned children are
	// still anchored on p.abortCtx and counted by the GC.
	goruntime.GC()
	goruntime.GC()
	got := liveObjects()
	shutdownPool(t, p)

	// Guarding the subtraction against an empty heap (impossible in a Go
	// test process, but keeps the arithmetic and message honest).
	growth := uint64(0)
	if got > baseline {
		growth = got - baseline
	}
	const allowance = uint64(50_000)
	if growth > allowance {
		t.Fatalf("retained heap objects grew by %d (%d -> %d) after %d timed jobs; want at most %d: per-job contexts must be released, not registered on the pool until shutdown",
			growth, baseline, got, batch, allowance)
	}
}
