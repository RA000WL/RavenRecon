package runtime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	goruntime "runtime"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recorder is a thread-safe Observer that records every event in order.
type recorder struct {
	mu  sync.Mutex
	evs []event.Event
}

func (r *recorder) Observe(ev event.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) events() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event.Event, len(r.evs))
	copy(out, r.evs)
	return out
}

// filter returns the recorded events of the given kind in order.
func (r *recorder) filter(k event.Kind) []event.Event {
	var out []event.Event
	for _, ev := range r.events() {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// drainSubscriber closes sub and returns every event it received, in
// sequence order. It must only be called once the pool has shut down: every
// publish happens-before Shutdown returns, so the subscriber's buffer is
// complete, and Subscriber.Next drains the buffer before reporting
// ErrSubscriptionClosed, so the returned slice is ordered and lossless.
func drainSubscriber(t *testing.T, sub *event.Subscriber) []event.Event {
	t.Helper()
	sub.Close()
	var evs []event.Event
	for {
		ev, err := sub.Next(context.Background())
		if err != nil {
			break
		}
		evs = append(evs, ev)
	}
	return evs
}

// TestPoolObserverScanStartedCarriesRealConfigFields pins the
// scan_started projection through the real pool→bus→subscriber wiring:
// every payload field is the pool's own Config, scan_started is the first
// sequenced event, and the final event is scan_stopped — with sequences
// exactly 1..N (no drops with a sufficiently large subscriber buffer).
func TestPoolObserverScanStartedCarriesRealConfigFields(t *testing.T) {
	bus := event.NewBus(nil)
	defer bus.Close()
	sub, err := bus.Subscribe(4096)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		Concurrency: 3,
		QueueSize:   7,
		Timeout:     time.Second,
		Rate:        2,
		Burst:       1,
		Clock:       newFakeClock(time.Unix(1_700_000_000, 0)),
		Observer:    bus,
	}
	p, err := NewPool(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Shutdown(context.Background())

	events := drainSubscriber(t, sub)
	if len(events) < 2 {
		t.Fatalf("want at least scan_started and scan_stopped, got %d events", len(events))
	}
	first := events[0]
	if first.Kind != event.KindScanStarted {
		t.Fatalf("first event = %s, want scan_started (emitted before workers start)", first.Kind)
	}
	if first.Sequence != 1 {
		t.Fatalf("scan_started must be the first sequenced event, got seq %d", first.Sequence)
	}
	pl, ok := first.Payload.(event.ScanStarted)
	if !ok {
		t.Fatalf("payload type = %T, want ScanStarted", first.Payload)
	}
	if pl.Concurrency != 3 || pl.QueueSize != 7 || pl.Timeout != time.Second || pl.Rate != 2 {
		t.Fatalf("scan_started carries %+v, want {3 7 1s 2}", pl)
	}
	if !first.At.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("scan_started timestamp = %s, want the pool clock time", first.At)
	}
	last := events[len(events)-1]
	if last.Kind != event.KindScanStopped {
		t.Fatalf("final event = %s, want scan_stopped", last.Kind)
	}
	for i, ev := range events {
		if ev.Sequence != uint64(i+1) {
			t.Fatalf("event %d: sequence %d, want %d (no drops, strict order)", i, ev.Sequence, i+1)
		}
	}
}

// TestPoolObserverWorkerLifecycleCarriesRealIndices pins the per-worker
// index on worker_started/worker_stopped and the graceful terminal state.
func TestPoolObserverWorkerLifecycleCarriesRealIndices(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 2, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Shutdown(context.Background())

	starts := rec.filter(event.KindWorkerStarted)
	stops := rec.filter(event.KindWorkerStopped)
	if len(starts) != 2 || len(stops) != 2 {
		t.Fatalf("want 2 worker_started and 2 worker_stopped, got %d/%d", len(starts), len(stops))
	}
	seen := map[int]bool{}
	for _, ev := range starts {
		pl := ev.Payload.(event.WorkerStarted)
		if pl.Worker < 0 || pl.Worker > 1 {
			t.Fatalf("worker index %d out of [0,1]", pl.Worker)
		}
		seen[pl.Worker] = true
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("worker indices seen = %v, want both 0 and 1", seen)
	}
	for _, ev := range stops {
		pl := ev.Payload.(event.WorkerStopped)
		if pl.State != event.WorkerCompleted {
			t.Fatalf("graceful shutdown worker state = %s, want completed", pl.State)
		}
	}
}

// TestPoolObserverTaskLifecycleFieldsGrounded pins the task lifecycle
// events: JobID, worker index, and StartedAt all come from the real pool
// job, and the terminal event precedes its runtime Event delivery.
func TestPoolObserverTaskLifecycleFieldsGrounded(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return "ok", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Shutdown(context.Background())

	submitted := rec.filter(event.KindTaskSubmitted)
	started := rec.filter(event.KindTaskStarted)
	running := rec.filter(event.KindTaskRunning)
	completed := rec.filter(event.KindTaskCompleted)
	if len(submitted) != 1 || len(started) != 1 || len(running) != 1 || len(completed) != 1 {
		t.Fatalf("lifecycle counts = s%d st%d r%d c%d, want 1 each", len(submitted), len(started), len(running), len(completed))
	}
	if got := submitted[0].Payload.(event.TaskSubmitted).JobID; got != uint64(id) {
		t.Fatalf("task_submitted JobID = %d, want %d", got, id)
	}
	if got := started[0].Payload.(event.TaskStarted).JobID; got != uint64(id) {
		t.Fatalf("task_started JobID = %d, want %d", got, id)
	}
	if w := started[0].Payload.(event.TaskStarted).Worker; w != 0 {
		t.Fatalf("task_started worker = %d, want 0", w)
	}
	if got := running[0].Payload.(event.TaskRunning).JobID; got != uint64(id) {
		t.Fatalf("task_running JobID = %d, want %d", got, id)
	}
	term := completed[0].Payload.(event.TaskCompleted)
	if term.JobID != uint64(id) || term.Worker != 0 {
		t.Fatalf("task_completed JobID/Worker = %d/%d, want %d/0", term.JobID, term.Worker, id)
	}
	if term.StartedAt.IsZero() {
		t.Fatal("task_completed StartedAt must be the real start time, got zero")
	}
	if term.Message != "" || term.Category != "" {
		t.Fatalf("completed task must carry no message/category, got %q/%q", term.Message, term.Category)
	}
	if res, ok := term.Result.(string); !ok || res != "ok" {
		t.Fatalf("task_completed Result = %v, want the raw job result \"ok\"", term.Result)
	}
}

// TestPoolObserverTerminalCategoryMapping pins the classification
// projection: timeout / cancellation / unknown, with the wrapped error text
// as the message and a zero StartedAt for jobs that never started.
func TestPoolObserverTerminalCategoryMapping(t *testing.T) {
	t.Run("failed", func(t *testing.T) {
		rec := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return nil, errBoom }})
		if err != nil {
			t.Fatal(err)
		}
		_ = p.Shutdown(context.Background())
		evs := rec.filter(event.KindTaskFailed)
		if len(evs) != 1 {
			t.Fatalf("want 1 task_failed, got %d", len(evs))
		}
		pl := evs[0].Payload.(event.TaskFailed)
		if pl.Category != "unknown" {
			t.Fatalf("failed category = %q, want \"unknown\"", pl.Category)
		}
		if !strings.Contains(pl.Message, "boom") {
			t.Fatalf("failed message = %q, want it to carry the job error", pl.Message)
		}
		if pl.StartedAt.IsZero() {
			t.Fatal("a running job's failure must carry its real StartedAt")
		}
	})

	t.Run("timed_out", func(t *testing.T) {
		rec := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Submit(ctx, Job{
			Timeout: 50 * time.Millisecond,
			Func:    func(ctx context.Context) (any, error) { <-ctx.Done(); return nil, ctx.Err() },
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = p.Shutdown(context.Background())
		evs := rec.filter(event.KindTaskTimedOut)
		if len(evs) != 1 {
			t.Fatalf("want 1 task_timed_out, got %d", len(evs))
		}
		pl := evs[0].Payload.(event.TaskTimedOut)
		if pl.Category != "timeout" {
			t.Fatalf("timed-out category = %q, want \"timeout\"", pl.Category)
		}
		if pl.Message == "" {
			t.Fatal("timed-out message must carry the deadline error text")
		}
	})

	t.Run("cancelled_never_started", func(t *testing.T) {
		rec := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// Two workers, one token (Rate 1, Burst 1): the first job to reach
		// the limiter starts and blocks; the other waits for a token that
		// never arrives. Cancelling the pool context then aborts the token
		// wait, so the waiting job is cancelled before it could start.
		p, err := NewPool(ctx, Config{
			Concurrency: 2,
			QueueSize:   4,
			Rate:        1,
			Burst:       1,
			Clock:       newFakeClock(time.Unix(1_700_000_000, 0)),
			Observer:    rec,
		})
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{}, 2)
		block := func(ctx context.Context) (any, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		id1, err := p.Submit(ctx, Job{Func: block})
		if err != nil {
			t.Fatal(err)
		}
		id2, err := p.Submit(ctx, Job{Func: block})
		if err != nil {
			t.Fatal(err)
		}
		// Wait until both workers picked their jobs up (task_started is
		// recorded for both): only then is one job guaranteed to be waiting
		// on the token instead of still queued.
		deadline := time.Now().Add(10 * time.Second)
		for len(rec.filter(event.KindTaskStarted)) < 2 {
			if time.Now().After(deadline) {
				t.Fatal("both jobs were not picked up before the deadline")
			}
			time.Sleep(time.Millisecond)
		}
		// One job now holds the single token and is running; the other is
		// waiting for it. Cancelling the pool context cancels both: the
		// waiting job never started.
		<-started
		cancel()
		if err := p.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown: %v", err)
		}

		evs := rec.filter(event.KindTaskCancelled)
		if len(evs) != 2 {
			t.Fatalf("want 2 task_cancelled (one running, one waiting), got %d", len(evs))
		}
		var zero, running *event.TaskCancelled
		for i := range evs {
			pl := evs[i].Payload.(event.TaskCancelled)
			if pl.StartedAt.IsZero() {
				zero = &pl
			} else {
				running = &pl
			}
		}
		if zero == nil || running == nil {
			t.Fatalf("want one cancelled-before-start and one cancelled-while-running, got zero=%v running=%v", zero != nil, running != nil)
		}
		if zero.JobID != uint64(id1) && zero.JobID != uint64(id2) {
			t.Fatalf("never-started cancelled JobID = %d, want one of %d/%d", zero.JobID, id1, id2)
		}
		if zero.Category != "cancellation" {
			t.Fatalf("cancelled category = %q, want \"cancellation\"", zero.Category)
		}
		if zero.Message == "" {
			t.Fatal("cancelled-before-start must carry the cancellation error text")
		}
		if running.JobID == zero.JobID {
			t.Fatal("the two cancelled events must belong to different jobs")
		}
		if running.StartedAt.IsZero() {
			t.Fatal("the running job's cancellation must carry its real StartedAt")
		}
	})
}

var errBoom = errors.New("boom")

// TestPoolObserverProgressHonestCounters pins the pool's progress events:
// Completed/Total are the pool's own terminated/submitted counters,
// TotalKnown is always true, the Completed wire is non-decreasing and never
// exceeds the run's true termination total, and the final event carries the
// exact totals. The wire contract — not a strict one-terminal-per-event 1..N
// shape — is what the pool promises: concurrent workers terminate out of
// order relative to their emissions, so the emission clamp (emitProgress in
// observer.go) guarantees monotonicity and the exact final total, which is
// what this test asserts (strict 1..N per event is an implementation detail
// of the serialized clamp, not part of the contract).
func TestPoolObserverProgressHonestCounters(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 2, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return nil, nil }}); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Shutdown(context.Background())

	progs := rec.filter(event.KindProgress)
	if len(progs) < 3 {
		t.Fatalf("want at least one progress event per terminal, got %d", len(progs))
	}
	last := progs[len(progs)-1].Payload.(event.Progress)
	if last.Completed != 3 || last.Total != 3 || !last.TotalKnown {
		t.Fatalf("final progress = %+v, want completed=3 total=3 totalKnown=true", last)
	}
	prev := 0
	for i, ev := range progs {
		pl := ev.Payload.(event.Progress)
		if pl.Completed < prev {
			t.Fatalf("progress %d completed = %d went backwards from %d (the wire must be non-decreasing)", i, pl.Completed, prev)
		}
		if pl.Completed > 3 {
			t.Fatalf("progress %d completed = %d, above the true total 3 (a clamp must never fabricate)", i, pl.Completed)
		}
		prev = pl.Completed
		if pl.Total < pl.Completed || pl.Total > 3 || !pl.TotalKnown {
			t.Fatalf("progress %d = %+v, want completed<=total<=3 totalKnown=true", i, pl)
		}
	}
}

// TestPoolObserverShutdownGraceful pins the graceful teardown events: phase
// draining, shutdown with reason graceful and zero dropped jobs, and
// scan_stopped completed — all after every worker unwound.
func TestPoolObserverShutdownGraceful(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	all := rec.events()
	var sawDraining, sawShutdown, sawStopped bool
	for _, ev := range all {
		switch ev.Kind {
		case event.KindPhaseTransition:
			if ev.Payload.(event.PhaseTransition).Phase == "draining" {
				sawDraining = true
			}
		case event.KindShutdown:
			sawShutdown = true
			pl := ev.Payload.(event.Shutdown)
			if pl.Reason != "graceful" || pl.Dropped != 0 {
				t.Fatalf("shutdown = %+v, want graceful with 0 dropped", pl)
			}
		case event.KindScanStopped:
			sawStopped = true
			if pl := ev.Payload.(event.ScanStopped); pl.State != "completed" {
				t.Fatalf("scan_stopped state = %q, want completed", pl.State)
			}
		}
	}
	if !sawDraining || !sawShutdown || !sawStopped {
		t.Fatalf("missing teardown events: draining=%v shutdown=%v stopped=%v", sawDraining, sawShutdown, sawStopped)
	}
	if last := all[len(all)-1]; last.Kind != event.KindScanStopped {
		t.Fatalf("scan_stopped must be the final event, got %s", last.Kind)
	}
}

// TestPoolObserverShutdownForced pins the forced teardown events: reason
// forced, the dropped-queue count (jobs never picked up), and scan_stopped
// cancelled.
func TestPoolObserverShutdownForced(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	block := func(ctx context.Context) (any, error) { <-ctx.Done(); return nil, ctx.Err() }
	// Job 1 is picked up and blocks; job 2 stays queued and is dropped.
	// The pool emits task_running before invoking the job body, so once the
	// body signals, the task_running event is already recorded.
	firstStarted := make(chan struct{})
	if _, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) {
		close(firstStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Submit(ctx, Job{Func: block}); err != nil {
		t.Fatal(err)
	}
	<-firstStarted

	drainCtx, drainCancel := context.WithCancel(context.Background())
	drainCancel()
	err = p.Shutdown(drainCtx)
	if err == nil {
		t.Fatal("forced shutdown must return the drain context error")
	}

	var sawShutdown bool
	for _, ev := range rec.events() {
		if ev.Kind != event.KindShutdown {
			continue
		}
		sawShutdown = true
		pl := ev.Payload.(event.Shutdown)
		if pl.Reason != "forced" {
			t.Fatalf("shutdown reason = %q, want forced", pl.Reason)
		}
		if pl.Dropped != 1 {
			t.Fatalf("shutdown dropped = %d, want 1 (the queued job never picked up)", pl.Dropped)
		}
	}
	if !sawShutdown {
		t.Fatal("no shutdown event on the forced path")
	}
	if evs := rec.filter(event.KindScanStopped); len(evs) != 1 || evs[0].Payload.(event.ScanStopped).State != "cancelled" {
		t.Fatalf("forced run must end scan_stopped cancelled, got %d events", len(evs))
	}
}

// assetStringDeriver converts "asset:<identity>" results into derived
// asset_discovered events at the boundary — the pool never emits them.
type assetStringDeriver struct{}

func (assetStringDeriver) Derive(ev event.Event, result any) []event.Event {
	s, ok := result.(string)
	if !ok || !strings.HasPrefix(s, "asset:") {
		return nil
	}
	pl := event.AssetDiscovered{Identity: strings.TrimPrefix(s, "asset:"), Kind: "host"}
	return []event.Event{event.New(event.KindAssetDiscovered, ev.At, pl)}
}

// TestPoolObserverDerivingSeamDerivesAtBoundary pins the Deriving bridge
// through the real pool→bus→subscriber wiring: the task_completed terminal
// is sequenced first, then the derived events from the caller-provided
// Deriver — engine results never emit on their own.
func TestPoolObserverDerivingSeamDerivesAtBoundary(t *testing.T) {
	bus := event.NewBus(nil)
	defer bus.Close()
	sub, err := bus.Subscribe(4096)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{
		Concurrency: 1,
		QueueSize:   4,
		Clock:       newFakeClock(time.Unix(1_700_000_000, 0)),
		Observer:    bus,
		Deriver:     assetStringDeriver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return "asset:host:example.com", nil }}); err != nil {
		t.Fatal(err)
	}
	_ = p.Shutdown(context.Background())

	events := drainSubscriber(t, sub)
	var completed, derived *event.Event
	for i := range events {
		switch events[i].Kind {
		case event.KindTaskCompleted:
			completed = &events[i]
		case event.KindAssetDiscovered:
			derived = &events[i]
		}
	}
	if completed == nil || derived == nil {
		t.Fatalf("want 1 completed + 1 derived, got completed=%v derived=%v", completed != nil, derived != nil)
	}
	if derived.Sequence != completed.Sequence+1 {
		t.Fatalf("derived seq %d must immediately follow terminal seq %d", derived.Sequence, completed.Sequence)
	}
	pl := derived.Payload.(event.AssetDiscovered)
	if pl.Identity != "host:example.com" || pl.Kind != "host" {
		t.Fatalf("derived payload = %+v, want identity host:example.com kind host", pl)
	}
	if pl.Confidence != 0 {
		t.Fatalf("derived confidence must default to 0, got %v", pl.Confidence)
	}
}

// TestPoolObserverNilObserverNoop pins the off switch: a pool without an
// observer runs and shuts down normally.
func TestPoolObserverNilObserverNoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 4, Clock: newFakeClock(time.Unix(1_700_000_000, 0))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Submit(ctx, Job{Func: func(ctx context.Context) (any, error) { return "ok", nil }}); err != nil {
		t.Fatal(err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestPoolProgressWireInvariantStress pins the submission-counter ordering
// (finding F1): the counter is incremented BEFORE the enqueue and
// compensated on rejection paths, so every progress event on the wire
// satisfies Completed <= Total and the final event carries the exact
// totals — even under concurrent submission where a worker can pick up and
// complete a fast job before the submitter resumes. Before the ordering
// fix a worker could terminate a just-enqueued job before the submitter's
// counter increment landed, putting Completed > Total (or a final Total of
// N-1) on the wire; the Gosched calls widen the submit window so the
// stress is meaningful without being timing-dependent.
func TestPoolProgressWireInvariantStress(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 4, QueueSize: 64, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	const submitters = 8
	const perSubmitter = 128
	const want = submitters * perSubmitter
	var wg sync.WaitGroup
	for s := 0; s < submitters; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perSubmitter; i++ {
				goruntime.Gosched() // widen the pre-fix submit window
				if _, err := p.Submit(ctx, Job{Func: func(context.Context) (any, error) { return nil, nil }}); err != nil {
					t.Errorf("submit: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	progs := rec.filter(event.KindProgress)
	if len(progs) == 0 {
		t.Fatal("no progress events")
	}
	for i, ev := range progs {
		pl := ev.Payload.(event.Progress)
		if pl.Completed > pl.Total {
			t.Fatalf("progress %d: completed=%d > total=%d (wire invariant violated)", i, pl.Completed, pl.Total)
		}
	}
	last := progs[len(progs)-1].Payload.(event.Progress)
	if last.Completed != want || last.Total != want {
		t.Fatalf("final progress = %+v, want completed=%d total=%d", last, want, want)
	}
}

// TestPoolSubmitRejectedCompensatesSubmissionCounter pins the rejection
// compensation (finding F1): a submission that fails after the counter
// increment (pool aborted while the submit is blocked on a full queue)
// must compensate, so the counter always equals the number of ACCEPTED
// jobs. Regression guard for the increment-before-enqueue construction:
// if the increment ever moved back after the send without compensation,
// this test fails.
func TestPoolSubmitRejectedCompensatesSubmissionCounter(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 2, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	// One blocking job occupies the single worker; two more fill the
	// size-2 queue. The next submit blocks with the send unready.
	release := make(chan struct{})
	if _, err := p.Submit(ctx, Job{Func: func(context.Context) (any, error) { <-release; return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := p.Submit(ctx, Job{Func: func(context.Context) (any, error) { return nil, nil }}); err != nil {
			t.Fatal(err)
		}
	}
	// Aborting the pool unblocks the blocked submit via the abortCtx
	// branch: it must compensate its counter increment.
	p.cancelAbort()
	if _, err := p.Submit(ctx, Job{Func: func(context.Context) (any, error) { return nil, nil }}); err == nil {
		t.Fatal("want submit error after pool abort")
	}
	if got := p.submitted.Load(); got != 3 {
		t.Fatalf("submitted counter = %d, want 3 (three accepted jobs; the rejected submit must compensate)", got)
	}
	close(release)
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestPoolProgressPhaseDuringDrain pins finding F3: progress events emitted
// after Shutdown begins carry the pool's real phase ("draining"), never a
// hardcoded "running", and no progress event regresses the phase once the
// draining transition is on the wire.
func TestPoolProgressPhaseDuringDrain(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPool(ctx, Config{Concurrency: 1, QueueSize: 2, Clock: newFakeClock(time.Unix(1_700_000_000, 0)), Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	if _, err := p.Submit(ctx, Job{Func: func(context.Context) (any, error) { <-release; return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	shDone := make(chan error, 1)
	go func() { shDone <- p.Shutdown(context.Background()) }()

	// Wait for the draining transition before releasing the job, so the
	// terminal's progress event is emitted after shutdown began.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if hasDrainingTransition(rec) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no draining phase transition observed")
		}
		goruntime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	if err := <-shDone; err != nil {
		t.Fatal(err)
	}

	drainingSeen := false
	for _, ev := range rec.filter(event.KindProgress) {
		pl := ev.Payload.(event.Progress)
		if drainingSeen && pl.Phase == "running" {
			t.Fatalf("progress phase regressed to running after draining")
		}
		if pl.Phase == "draining" {
			drainingSeen = true
		}
	}
	if !drainingSeen {
		t.Fatal("no progress event carried phase draining during shutdown")
	}
}

// hasDrainingTransition reports whether the recorder saw a draining phase
// transition.
func hasDrainingTransition(rec *recorder) bool {
	for _, ev := range rec.filter(event.KindPhaseTransition) {
		if pl, ok := ev.Payload.(event.PhaseTransition); ok && pl.Phase == "draining" {
			return true
		}
	}
	return false
}
