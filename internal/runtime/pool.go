package runtime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// ErrPoolClosed is returned by Submit and Subscribe once the pool has been
// shut down (or while a shutdown is in progress), and by Shutdown when it is
// called on a pool that is already shut down.
var ErrPoolClosed = errors.New("runtime: pool is closed")

// JobID identifies a submitted job within a pool. IDs are assigned by the
// pool at Submit time and are unique for practical lifetimes: the counter
// wraps only after 2^64 submissions, so a wrapped ID is indistinguishable
// from an old one and callers must not rely on uniqueness across a wrap.
// Within any pool that has not submitted 2^64 jobs, IDs are never reused.
type JobID uint64

// JobFunc is a unit of work. It receives the context the pool derived for the
// job and must honor its cancellation: the pool cannot forcibly stop a
// goroutine, so a job that ignores ctx can delay shutdown.
type JobFunc func(ctx context.Context) (any, error)

// Job is one unit of work submitted to a pool.
type Job struct {
	// Func is the work to run. It must not be nil.
	Func JobFunc

	// Timeout optionally overrides the pool-level default per-job deadline.
	// Zero or negative means "use the pool default". The deadline covers the
	// rate-limit token wait and the execution itself.
	Timeout time.Duration

	// ID is assigned by the pool at Submit time. Any value present here is
	// ignored and overwritten.
	ID JobID
}

// Config configures a Pool. All fields are validated by NewPool; invalid
// values are rejected with an error rather than silently normalized (Burst
// being the one exception: values below 1 are normalized to 1, which is the
// documented default).
type Config struct {
	// Concurrency is the exact number of worker goroutines (> 0). Jobs run
	// inline in workers; the pool never creates a goroutine per job.
	Concurrency int

	// QueueSize is the capacity of the bounded submission queue (> 0).
	// Submit blocks while the queue is full (backpressure); the queue never
	// grows without bound.
	QueueSize int

	// Timeout is the default per-job deadline (0 disables the default; a
	// negative value is rejected). A job's context is cancelled when its
	// deadline elapses and the job is reported as EventTimedOut, never as
	// success.
	Timeout time.Duration

	// Rate is the token refill rate of the pool's single central rate
	// limiter, in tokens per second (0 disables rate limiting; negative,
	// NaN, and infinite values are rejected — a non-finite rate must not be
	// silently accepted as "disabled"). Every job start acquires a token
	// from this one limiter, so the aggregate job start rate is bounded
	// regardless of concurrency.
	Rate float64

	// Burst is the token-bucket burst capacity (ignored when Rate <= 0).
	// Values below 1 are normalized to 1, the default: the bucket starts
	// full, so the first job starts immediately and every later start is
	// spaced at least 1/Rate apart.
	Burst int

	// Clock is the time source used for rate limiting and event timestamps.
	// Nil means the wall clock; tests inject a fake clock for deterministic
	// assertions.
	Clock Clock

	// Observer is the optional Phase 12 instrumentation sink (internal/event
	// Observer; the Bus satisfies it). When non-nil, the pool emits
	// canonical pool-boundary events: scan start/stop, worker start/stop,
	// task submitted/started/running/terminal, phase transitions, progress,
	// and shutdown (see observer.go for the exact field grounding). A nil
	// observer (the default) means zero behavior change.
	Observer event.Observer

	// Deriver is the optional pool-job-boundary derivation bridge: when
	// non-nil, the pool wraps Observer in event.Deriving, so the raw
	// results of completed jobs are handed to the Deriver for conversion
	// into derived canonical events (asset discovered, finding created,
	// ...) after each task_completed event. Engines never emit those events
	// themselves; a caller that does not want derived events leaves this
	// nil.
	Deriver event.Deriver
}

// Pool is a bounded, cancellable, rate-limited job execution engine. See the
// package documentation for the execution model, concurrency guarantees,
// cancellation, shutdown, and rate limiting semantics.
//
// A Pool must be created with NewPool and released with Shutdown: Shutdown
// stops new submissions, drains queued and in-flight jobs, and terminates
// every goroutine the pool owns. If the context passed to NewPool is
// cancelled, queued and running jobs are cancelled (reported as cancelled,
// never as failed) and the workers and event machinery unwind on their own;
// Shutdown is still required to close the submission queue and release
// subscriptions.
//
// The zero value is not usable.
type Pool struct {
	timeout time.Duration
	limiter *Limiter // nil when rate limiting is disabled
	clock   Clock

	jobQueue    chan Job
	stopAccept  chan struct{}
	abortCtx    context.Context
	cancelAbort context.CancelFunc

	mu     sync.Mutex
	closed bool
	nextID uint64

	submitters sync.WaitGroup
	workers    sync.WaitGroup

	subsMu sync.Mutex
	subs   map[*Subscription]struct{}

	// observer is the Phase 12 instrumentation sink (nil = off). It is the
	// configured Observer wrapped in the Deriving bridge when a Deriver is
	// present.
	observer event.Observer

	// submitted counts jobs successfully enqueued; terminated counts
	// terminal events emitted. They back the pool's honest progress events.
	submitted  atomic.Uint64
	terminated atomic.Uint64

	// progressMu serializes progress read-modify-emit and progressEmitted
	// is the watermark of the last Completed value put on the wire. They
	// enforce the progress wire contract (non-decreasing, never above the
	// true termination count, final value exact): concurrent workers can
	// terminate out of order relative to their progress emissions, and with
	// only an atomic counter a worker that increments early and emits late
	// could put a larger Completed before a smaller one (see emitProgress
	// in observer.go for the clamp and its correctness argument).
	progressMu      sync.Mutex
	progressEmitted uint64

	// phase is the pool's current lifecycle phase (an atomic.Value holding
	// a string: "running" after NewPool, "draining" once Shutdown begins).
	// Progress events carry it so the wire's Phase never regresses from
	// "draining" back to a hardcoded "running" (see emitPhase/emitProgress
	// in observer.go).
	phase atomic.Value
}

// NewPool validates cfg and returns a running pool bound to ctx: exactly
// cfg.Concurrency worker goroutines are started immediately, and the pool's
// single rate limiter (if any) is created. Cancelling ctx cancels every
// queued and running job and unwinds the workers; see Shutdown for the
// orderly path.
func NewPool(ctx context.Context, cfg Config) (*Pool, error) {
	if ctx == nil {
		return nil, fmt.Errorf("runtime: context must not be nil")
	}
	if cfg.Concurrency <= 0 {
		return nil, fmt.Errorf("runtime: concurrency must be positive, got %d", cfg.Concurrency)
	}
	if cfg.QueueSize <= 0 {
		return nil, fmt.Errorf("runtime: queue size must be positive, got %d", cfg.QueueSize)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("runtime: timeout must not be negative, got %s", cfg.Timeout)
	}
	if math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) {
		return nil, fmt.Errorf("runtime: rate must be finite, got %v", cfg.Rate)
	}
	if cfg.Rate < 0 {
		return nil, fmt.Errorf("runtime: rate must not be negative, got %v", cfg.Rate)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = wallClock{}
	}
	var lim *Limiter
	if cfg.Rate > 0 {
		burst := cfg.Burst
		if burst < 1 {
			burst = 1
		}
		l, err := NewLimiter(cfg.Rate, float64(burst), WithClock(clock))
		if err != nil {
			return nil, fmt.Errorf("runtime: create rate limiter: %w", err)
		}
		lim = l
	}
	abortCtx, cancelAbort := context.WithCancel(ctx)
	p := &Pool{
		timeout:     cfg.Timeout,
		limiter:     lim,
		clock:       clock,
		jobQueue:    make(chan Job, cfg.QueueSize),
		stopAccept:  make(chan struct{}),
		abortCtx:    abortCtx,
		cancelAbort: cancelAbort,
		subs:        make(map[*Subscription]struct{}),
		observer:    buildObserver(cfg),
	}
	p.emitScanStarted(cfg)
	p.workers.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		go p.workerLoop(i)
	}
	p.emitPhase("running")
	return p, nil
}

// Submit enqueues job for execution and returns its ID. Submit blocks while
// the submission queue is full (bounded backpressure); it returns ctx.Err()
// if ctx is cancelled while waiting, and ErrPoolClosed once the pool is
// shutting down or shut down. A job successfully enqueued before a graceful
// shutdown is still executed and drained.
func (p *Pool) Submit(ctx context.Context, job Job) (JobID, error) {
	if ctx == nil {
		return 0, fmt.Errorf("runtime: context must not be nil")
	}
	if job.Func == nil {
		return 0, fmt.Errorf("runtime: job function must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("runtime: submit: %w", err)
	}
	id, err := p.reserveID()
	if err != nil {
		return 0, err
	}
	defer p.submitters.Done()
	job.ID = id
	// The submission counter is incremented BEFORE the enqueue so that no
	// worker can terminate an accepted job before the counter records its
	// submission: the progress wire contract (Completed never exceeds
	// Total; the final Total is exact) holds even when a worker picks up
	// and completes a very fast job before the submitter resumes. The
	// three rejection paths below compensate the counter, so it always
	// equals the number of accepted jobs.
	//
	// The task_submitted EVENT is still emitted after the enqueue: the
	// observer stream's ordering guarantee is per-worker lifecycle (started
	// before running before terminal for one job), not a global wall-clock
	// order between submit and start.
	p.submitted.Add(1)
	select {
	case p.jobQueue <- job:
		p.emitTaskSubmitted(job)
		return id, nil
	case <-ctx.Done():
		p.submitted.Add(^uint64(0))
		return id, fmt.Errorf("runtime: submit %d: %w", id, ctx.Err())
	case <-p.stopAccept:
		p.submitted.Add(^uint64(0))
		return id, ErrPoolClosed
	case <-p.abortCtx.Done():
		p.submitted.Add(^uint64(0))
		return id, ErrPoolClosed
	}
}

// reserveID assigns the next job ID and registers the submission with the
// shutdown wait group. Callers must call submitters.Done exactly once after a
// successful reserveID.
func (p *Pool) reserveID() (JobID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, ErrPoolClosed
	}
	if p.abortCtx.Err() != nil {
		return 0, ErrPoolClosed
	}
	p.nextID++
	p.submitters.Add(1)
	return JobID(p.nextID), nil
}

// Shutdown stops accepting new work and drains the pool.
//
// Semantics, precisely:
//
//  1. The pool is marked closed: Submit and Subscribe now fail with
//     ErrPoolClosed, and Submit calls blocked on a full queue return
//     ErrPoolClosed instead of blocking forever.
//  2. Jobs already queued or in flight are given a chance to finish: the
//     queue is drained to completion and every in-flight job runs to its
//     natural end (bounded by its per-job deadline).
//  3. Shutdown blocks until the drain finishes, then closes all
//     subscriptions (Next reports ErrSubscriptionClosed) and returns nil.
//     Every goroutine the pool owns has terminated before Shutdown returns.
//  4. If ctx (the drain context) is cancelled or its deadline elapses before
//     the drain finishes, Shutdown instead cancels the remaining queued and
//     running jobs (their contexts), waits for the pool to unwind, closes
//     the subscriptions, and returns an error wrapping ctx.Err(). Events for
//     jobs cancelled this way may be dropped for subscribers whose buffers
//     are full (see Subscription); the caller already observes the shutdown
//     error. This is the "forced" path.
//  5. Calling Shutdown on a pool that is shut down (or currently shutting
//     down) returns ErrPoolClosed.
//
// A job that ignores context cancellation can delay shutdown even on the
// forced path for up to its per-job deadline (or indefinitely when deadlines
// are disabled); the pool cannot kill a goroutine. See the package
// documentation for the full statement of limitations.
func (p *Pool) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("runtime: context must not be nil")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrPoolClosed
	}
	p.closed = true
	close(p.stopAccept)
	p.mu.Unlock()

	p.emitPhase("draining")

	var forceErr error

	// Wait for in-flight Submits to finish enqueuing before closing the
	// queue: closing a channel while a goroutine may still send on it is a
	// race, and every blocked Submit is released by stopAccept.
	submittersDone := make(chan struct{})
	go func() {
		p.submitters.Wait()
		close(submittersDone)
	}()
	if err := p.wait(ctx, submittersDone); err != nil {
		forceErr = err
	}

	// No more senders: close the queue so workers drain it and exit.
	close(p.jobQueue)

	// Wait for the workers to finish every queued and in-flight job.
	workersDone := make(chan struct{})
	go func() {
		p.workers.Wait()
		close(workersDone)
	}()
	if err := p.wait(ctx, workersDone); err != nil {
		forceErr = err
	}

	// The wire's final progress event: every submitter has resolved (the
	// submittersDone wait above released blocked Submits and compensated
	// their rejections) and every worker has terminated, so the counters
	// read exact totals. Without it, a pending rejection compensation could
	// land after the last worker-emitted progress event, leaving a final
	// Total one above the true accepted count on the wire.
	p.emitProgress()

	// No more events can be emitted; release the subscribers.
	p.closeSubscriptions()

	p.emitShutdown(forceErr != nil, len(p.jobQueue))
	p.emitScanStopped(forceErr != nil)
	return forceErr
}

// wait blocks until ch closes. If ctx is cancelled first, the pool is forced
// down (all queued and running jobs are cancelled) and wait blocks until the
// wait group actually reaches zero before returning the context error, so
// the machinery is fully unwound before Shutdown returns.
func (p *Pool) wait(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		select {
		case <-ch:
			// The wait finished at the same instant the context fired;
			// report a clean drain.
			return nil
		default:
		}
		p.cancelAbort() // idempotent
		<-ch
		return fmt.Errorf("runtime: shutdown: %w", ctx.Err())
	}
}

// workerLoop runs one worker goroutine. Workers exit when the submission
// queue is closed and drained (graceful shutdown) or when the pool is forced
// down (abort). On abort, queued jobs that were never picked up are dropped
// without events; the Shutdown error already tells the caller the run was
// aborted.
func (p *Pool) workerLoop(i int) {
	defer p.workers.Done()
	p.emitWorkerStarted(i)
	state := event.WorkerCompleted
	defer func() { p.emitWorkerStopped(i, state) }()
	for {
		if p.abortCtx.Err() != nil {
			state = event.WorkerCancelled
			return
		}
		select {
		case job, ok := <-p.jobQueue:
			if !ok {
				return
			}
			p.execute(i, job)
		case <-p.abortCtx.Done():
			state = event.WorkerCancelled
			return
		}
	}
}

// execute runs one job: it derives the job's context (pool abort signal plus
// per-job deadline), acquires a rate-limit token, emits Started, runs the
// job inline, and emits exactly one terminal event.
//
// Terminal classification is deterministic and takes priority in this order:
//
//  1. Deadline exceeded (context.DeadlineExceeded) -> EventTimedOut.
//  2. Context cancelled for any other reason -> EventCancelled.
//  3. The job returned an error -> EventFailed.
//  4. Otherwise -> EventCompleted.
//
// A job whose context was cancelled never reports success, even if the job
// returns a value or a nil error.
func (p *Pool) execute(i int, job Job) {
	d := job.Timeout
	if d <= 0 {
		d = p.timeout
	}
	ctx, cancel := context.WithCancel(p.abortCtx)
	if d > 0 {
		cancel() // release the placeholder child; the timeout context replaces it
		ctx, cancel = context.WithTimeout(p.abortCtx, d)
	}
	defer cancel()

	if err := ctx.Err(); err != nil {
		// Cancelled before it could start (forced shutdown or pool context).
		fin := p.finishEvent(job, time.Time{}, p.clock.Now(), ctx, nil, nil)
		p.emitTaskTerminal(i, job, fin)
		p.emitProgress()
		p.deliver(fin)
		return
	}

	p.emitTaskStarted(i, job)

	if p.limiter != nil {
		if err := p.limiter.Wait(ctx); err != nil {
			// The deadline elapsed or the context was cancelled while
			// waiting for a start token: the job never started, but its
			// fate is still surfaced as a terminal event.
			fin := p.finishEvent(job, time.Time{}, p.clock.Now(), ctx, nil, nil)
			p.emitTaskTerminal(i, job, fin)
			p.emitProgress()
			p.deliver(fin)
			return
		}
	}

	startedAt := p.clock.Now()
	p.deliver(Event{Kind: EventStarted, JobID: job.ID, StartedAt: startedAt, At: startedAt})
	p.emitTaskRunning(i, job)

	result, jerr := runSafe(ctx, job)
	fin := p.finishEvent(job, startedAt, p.clock.Now(), ctx, result, jerr)
	p.emitTaskTerminal(i, job, fin)
	p.emitProgress()
	p.deliver(fin)
}

// finishEvent classifies a job's terminal event (see execute). It is also
// used for jobs cancelled before they started, in which case startedAt is
// zero.
func (p *Pool) finishEvent(job Job, startedAt, at time.Time, ctx context.Context, result any, jerr error) Event {
	base := Event{JobID: job.ID, StartedAt: startedAt, At: at}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		base.Kind = EventTimedOut
		base.Err = fmt.Errorf("runtime: job %d timed out: %w", job.ID, ctx.Err())
	case ctx.Err() != nil:
		base.Kind = EventCancelled
		base.Err = fmt.Errorf("runtime: job %d cancelled: %w", job.ID, ctx.Err())
	case jerr != nil:
		base.Kind = EventFailed
		base.Err = fmt.Errorf("runtime: job %d failed: %w", job.ID, jerr)
	default:
		base.Kind = EventCompleted
		base.Result = result
	}
	return base
}

// runSafe executes fn, converting a panic into a Failed-style error so one
// misbehaving job cannot take down the pool or starve its siblings of a
// terminal event.
func runSafe(ctx context.Context, job Job) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("runtime: job %d panicked: %s", job.ID, truncateForError(fmt.Sprintf("%v", r)))
		}
	}()
	return job.Func(ctx)
}

// deliver fans ev out to every subscription. Delivery is blocking and
// lossless during normal operation (see Subscription.deliver); a slow
// subscriber applies backpressure to the emitting worker only, and a forced
// shutdown always unwinds it.
func (p *Pool) deliver(ev Event) {
	p.subsMu.Lock()
	subs := make([]*Subscription, 0, len(p.subs))
	for s := range p.subs {
		subs = append(subs, s)
	}
	p.subsMu.Unlock()
	for _, s := range subs {
		s.deliver(ev, p.abortCtx)
	}
}

// Subscribe returns a new event subscription with a bounded buffer of the
// given size (must be positive). Events are delivered to every subscription;
// see Subscription for the delivery, overflow, and close semantics.
// Subscribing after the pool is shut down (or while a shutdown is in
// progress) returns ErrPoolClosed.
//
// The closed-check and the map insertion are atomic under p.mu: if the check
// passes, the subscription is in the map before Shutdown marks the pool
// closed, so Shutdown's closeSubscriptions is guaranteed to close it. A
// non-atomic check-then-insert would let a Subscribe that passed its check
// register its subscription after Shutdown had already closed every
// subscription, orphaning it: its Next would block forever instead of
// returning ErrSubscriptionClosed.
func (p *Pool) Subscribe(buffer int) (*Subscription, error) {
	if buffer <= 0 {
		return nil, fmt.Errorf("runtime: event buffer must be positive, got %d", buffer)
	}
	s := &Subscription{
		ch:   make(chan Event, buffer),
		done: make(chan struct{}),
		pool: p,
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	p.subsMu.Lock()
	p.subs[s] = struct{}{}
	p.subsMu.Unlock()
	p.mu.Unlock()
	return s, nil
}

// removeSubscription detaches s from the pool; called by Subscription.Close.
func (p *Pool) removeSubscription(s *Subscription) {
	p.subsMu.Lock()
	delete(p.subs, s)
	p.subsMu.Unlock()
}

// closeSubscriptions releases every subscription; called exactly once by
// Shutdown after the last event has been emitted.
func (p *Pool) closeSubscriptions() {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	for s := range p.subs {
		s.closeAndRemove()
		delete(p.subs, s)
	}
}

// maxErrorFieldLen bounds how many bytes of a possibly hostile panic value
// may be echoed into an error string.
const maxErrorFieldLen = 200

// truncationMarker marks the tail of a value truncated for error messages.
const truncationMarker = "...(truncated)"

// truncateForError limits s to maxErrorFieldLen bytes for inclusion in an
// error message, appending truncationMarker when it was cut.
func truncateForError(s string) string {
	if len(s) <= maxErrorFieldLen {
		return s
	}
	return s[:maxErrorFieldLen] + truncationMarker
}
