package runtime

import (
	"github.com/RA000WL/RavenRecon/internal/event"
)

// Phase 12 instrumentation (roadmap v1.2, "Structured runtime events").
//
// The pool accepts an OPTIONAL observer (and an optional deriver) in its
// Config. A nil observer is the off switch: zero behavior change, zero
// measurable cost (the pool only ever performs a nil check per emit point).
// When set, the pool emits canonical pool-boundary events (internal/event)
// for its lifecycle: scan start/stop, worker start/stop, task submitted/
// started/running/terminal, phase transitions, progress, and shutdown.
//
// Every payload field is grounded in a REAL pool field:
//
//   - event.ScanStarted.<Concurrency|QueueSize|Timeout|Rate>  <- Config.
//   - event.ScanStopped.State                                 <- outcome of
//     Shutdown (clean drain = "completed", forced = "cancelled").
//   - event.WorkerStarted/WorkerStopped.Worker                <- the worker
//     goroutine index (0 .. Concurrency-1).
//   - event.TaskSubmitted/TaskStarted/TaskRunning.JobID       <- Job.ID.
//   - event.TaskTerminal.JobID/StartedAt                      <- runtime
//     Event.JobID/Event.StartedAt (zero for tasks that never started).
//   - event.TaskTerminal.Category                             <- the pool's
//     terminal classification projected onto the report framework's
//     ErrorCategory vocabulary: "timeout", "cancellation", "unknown".
//   - event.TaskTerminal.Message                              <- the wrapped
//     runtime Event.Err text (empty for completed tasks).
//   - event.TaskCompleted.Result                              <- the raw job
//     result; the Deriving seam hands it to a caller-provided Deriver.
//   - event.Progress.<Completed|Total>                        <- the pool's
//     real counters (terminated tasks / submitted tasks).
//   - event.PhaseTransition.Phase                             <- "running"
//     (pool created) / "draining" (shutdown began).
//   - event.Shutdown.<Reason|Dropped>                         <- Shutdown
//     outcome; Dropped is the pool's remaining queue length after the
//     workers unwind (jobs never picked up).
//
// Task results are wired through the event.Deriving bridge: the pool wraps
// the configured observer in Deriving{Observer, Deriver}, so a caller that
// provides a Deriver converts engine result types into derived canonical
// events (asset discoveries, findings, relationships, ...) at the pool-job
// boundary. Engines never emit those events themselves.

// observe delivers ev to the pool's observer (nil observer: no-op).
//
// Panic containment (NEW-108): this is the single emission choke point for
// every event the pool publishes, including emissions from worker
// goroutines the pool spawned. A panicking Observer is recovered here and
// counted in observerPanics (surfaced by ObserverPanics) instead of
// crashing a worker — the same containment the Deriving bridge applies to
// panicking Derivers, so the threat model is symmetric: neither half of the
// observer seam can take down the process, and neither failure mode is
// silent (the bridge counts DeriverPanics; the pool counts
// ObserverPanics). A panic escaping through Submit or Shutdown (both run on
// the caller's goroutine) is likewise recovered AND counted, never
// swallowed without a trace.
func (p *Pool) observe(ev event.Event) {
	if p.observer == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.observerPanics.Add(1)
		}
	}()
	p.observer.Observe(ev)
}

// ObserverPanics returns how many times the configured Observer panicked
// inside Observe and was recovered by the pool. Zero for a well-behaved
// observer; anything above zero means the observer is losing events it was
// handed (the event itself is dropped with the panicked call).
func (p *Pool) ObserverPanics() uint64 { return p.observerPanics.Load() }

// buildObserver wraps the configured observer in the Deriving bridge when a
// deriver is present. NewDeriving installs the bridge's panic counter, so a
// hostile panicking deriver is recovered, its batch dropped, and counted
// (event.Deriving.DeriverPanics) instead of crashing the process.
//
// Surfacing note: on the pool path the bridge (and its panic counter) is
// built internally and is unreachable from the caller. A caller that needs
// to observe the counter must construct its own event.Deriving (wrapping
// its observer and deriver), pass THAT as Config.Observer, and leave
// Config.Deriver nil; the bridge-level DeriverPanics accessor is then
// reachable.
func buildObserver(cfg Config) event.Observer {
	if cfg.Deriver == nil {
		return cfg.Observer
	}
	return event.NewDeriving(cfg.Observer, cfg.Deriver)
}

// emitScanStarted publishes the pool-configuration projection. A negative
// Timeout is clamped to 0 ("none"): NewPool rejects negative timeouts
// today, so this is unreachable through the public constructor, but the
// wire contract (event.ScanStarted.Timeout, "0 = none"; Event.Validate
// rejects a negative value) must not depend on that upstream check — a
// future caller path that relaxes it would otherwise put an invalid event
// on the wire.
func (p *Pool) emitScanStarted(cfg Config) {
	timeout := cfg.Timeout
	if timeout < 0 {
		timeout = 0
	}
	p.observe(event.New(event.KindScanStarted, p.clock.Now(), event.ScanStarted{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     timeout,
		Rate:        cfg.Rate,
	}))
}

// emitWorkerStarted publishes one worker goroutine's start.
func (p *Pool) emitWorkerStarted(i int) {
	p.observe(event.New(event.KindWorkerStarted, p.clock.Now(), event.WorkerStarted{Worker: i}))
}

// emitWorkerStopped publishes one worker goroutine's exit with its real
// terminal state: completed for a graceful drain, cancelled for an abort.
func (p *Pool) emitWorkerStopped(i int, state event.WorkerState) {
	p.observe(event.New(event.KindWorkerStopped, p.clock.Now(), event.WorkerStopped{Worker: i, State: state}))
}

// emitTaskSubmitted publishes a successfully enqueued job. It is emitted by
// the submitter AFTER the enqueue, so a fast worker can pick the job up (and
// even terminate it) before this event reaches the wire: the observer
// stream's ordering guarantee is per-worker lifecycle, not a global
// wall-clock order between submit and start.
func (p *Pool) emitTaskSubmitted(job Job) {
	p.observe(event.New(event.KindTaskSubmitted, p.clock.Now(), event.TaskSubmitted{JobID: uint64(job.ID)}))
}

// emitTaskStarted publishes that worker i picked the job up (it may still be
// waiting for its rate-limit token).
func (p *Pool) emitTaskStarted(i int, job Job) {
	p.observe(event.New(event.KindTaskStarted, p.clock.Now(), event.TaskStarted{JobID: uint64(job.ID), Worker: i}))
}

// emitTaskRunning publishes that the job's function body began executing
// (after the rate-limit wait).
func (p *Pool) emitTaskRunning(i int, job Job) {
	p.observe(event.New(event.KindTaskRunning, p.clock.Now(), event.TaskRunning{JobID: uint64(job.ID), Worker: i}))
}

// emitTaskTerminal publishes the terminal event for job. The payload
// fields mirror the runtime Event exactly: JobID and StartedAt come from
// ev, the category is the classification projection, and the message is the
// wrapped error text (truncated and marked by the event constructors).
// It also advances the pool's terminated counter (the backing of the
// honest progress events); the counter only exists to serve the observer,
// so it is skipped entirely when no observer is configured.
func (p *Pool) emitTaskTerminal(i int, job Job, ev Event) {
	term := event.NewTaskTerminal(uint64(job.ID), i, ev.StartedAt, terminalCategory(ev.Kind), eventErrorMessage(ev))
	var payload event.Payload
	switch ev.Kind {
	case EventCompleted:
		payload = event.NewTaskCompleted(term, ev.Result)
	case EventCancelled:
		payload = event.NewTaskCancelled(term)
	case EventFailed:
		payload = event.NewTaskFailed(term)
	case EventTimedOut:
		payload = event.NewTaskTimedOut(term)
	default:
		// Unreachable: every terminal path classifies into one of the four
		// kinds above. Guard so a future kind can never panic the emitter.
		return
	}
	if p.observer != nil {
		p.terminated.Add(1)
	}
	p.observe(event.New(eventTerminalKind(ev.Kind), p.clock.Now(), payload))
}

// eventTerminalKind maps a runtime terminal Kind to the canonical event
// kind of the same classification.
func eventTerminalKind(k Kind) event.Kind {
	switch k {
	case EventCompleted:
		return event.KindTaskCompleted
	case EventCancelled:
		return event.KindTaskCancelled
	case EventFailed:
		return event.KindTaskFailed
	case EventTimedOut:
		return event.KindTaskTimedOut
	default:
		return ""
	}
}

// terminalCategory projects the pool's terminal classification onto the
// report framework's ErrorCategory vocabulary (report.ErrorCategory): the
// runtime emits "timeout", "cancellation", and "unknown" — and the empty
// category for completed tasks, which carry no error.
func terminalCategory(k Kind) string {
	switch k {
	case EventCompleted:
		return ""
	case EventCancelled:
		return "cancellation"
	case EventTimedOut:
		return "timeout"
	case EventFailed:
		return "unknown"
	default:
		return "unknown"
	}
}

// eventErrorMessage renders the wrapped error text for the terminal event.
// It mirrors the runtime Event.Err shape; the event constructors bound it.
func eventErrorMessage(ev Event) string {
	if ev.Err == nil {
		return ""
	}
	return ev.Err.Error()
}

// emitProgress publishes the pool's honest task counters: Completed is the
// number of terminal events emitted, Total the number of jobs submitted.
// TotalKnown is always true here: the pool counts its own submits.
//
// The wire contract: the Completed values a consumer sees are
// non-decreasing, never exceed the true termination count at the moment of
// emission, never exceed Total (TotalKnown makes a Completed>Total event
// invalid — Event.Validate rejects it and the bus would drop it), and the
// final progress event carries the exact total. The terminated counter
// alone cannot guarantee that — concurrent workers terminate out of order
// relative to their emissions, so a worker that increments the counter
// early and emits late could otherwise put a larger Completed before a
// smaller one. The emission is therefore serialized under progressMu and
// clamped to min(actual, watermark+1) (clampProgress), then clamped once
// more to the submission count: both counters are non-decreasing and read
// under the same lock, so the min stays non-decreasing and the second
// clamp can only delay honesty, never fabricate or regress it.
//
// The Observe call happens under progressMu deliberately: the wire order is
// the order the observer sees, so only emitting while holding the lock
// makes the clamp's ordering real (a bare CAS loop would let two winners
// publish in reverse order).
func (p *Pool) emitProgress() {
	if p.observer == nil {
		return
	}
	p.progressMu.Lock()
	total := int(p.submitted.Load())
	completed := p.clampProgress(int(p.terminated.Load()))
	if completed > total {
		// Defensive: Event.Validate rejects a Progress whose Completed
		// exceeds its TotalKnown total, so emitting one past the submission
		// counter would get the event dropped at the bus instead of being
		// observed. Hold at Total; the next emission reports the truth.
		completed = total
	}
	// The phase comes from the pool's stored lifecycle phase, never a
	// hardcoded value: once Shutdown has put "draining" on the wire, no
	// progress event may regress it to "running" (see emitPhase).
	phase := "running"
	if v := p.phase.Load(); v != nil {
		phase = v.(string)
	}
	p.observe(event.New(event.KindProgress, p.clock.Now(), event.Progress{
		Phase:      phase,
		Completed:  completed,
		Total:      total,
		TotalKnown: true,
	}))
	p.progressMu.Unlock()
}

// clampProgress computes the Completed value to emit for the current
// termination count: min(actual, watermark+1), where watermark is the last
// value put on the wire.
//
// Honesty properties (all under progressMu, so serialized):
//
//   - Never above the truth: the emitted value is min(actual, watermark+1)
//     and actual is the real termination count, so a clamp can only delay
//     honesty, never fabricate a count above true completion.
//   - Non-decreasing wire: watermark only grows, and this emission's value
//     is either watermark (no new termination to report) or watermark+1.
//   - Final value exact: the watermark advances at most one step per
//     emission, every terminal emit is followed by exactly one progress
//     emit, and the i-th emission (in lock order) reads actual >= i (its
//     own increment plus those of every earlier emission, all of whose
//     increments precede their emissions), so after all N terminals the
//     watermark has caught up to exactly N.
//
// int-wrap note: actual comes from terminated.Load() bounded by submitted
// count (fits int on both 32- and 64-bit); progressEmitted mirrors it. If
// actual were to wrap negative (2^31 on 32-bit, impossible for real runs),
// the clamp degrades honestly: actual <= last returns last (non-decreasing,
// never above truth), so overflow cannot fabricate progress.
func (p *Pool) clampProgress(actual int) int {
	last := int(p.progressEmitted)
	if actual <= last {
		return last
	}
	if actual > last+1 {
		actual = last + 1
	}
	p.progressEmitted = uint64(actual)
	return actual
}

// emitPhase publishes a lifecycle phase transition and records the phase so
// progress events can carry it (see emitProgress). The store and observe
// happen under progressMu so the transition serializes with progress
// emissions: a progress event cannot be recorded after the phase transition
// while carrying the previous phase.
func (p *Pool) emitPhase(phase string) {
	p.progressMu.Lock()
	p.phase.Store(phase)
	p.observe(event.New(event.KindPhaseTransition, p.clock.Now(), event.PhaseTransition{Phase: phase}))
	p.progressMu.Unlock()
}

// emitShutdown publishes the shutdown conclusion: the reason (graceful when
// the drain context survived, forced otherwise) and the number of queued
// jobs that were never picked up (the remaining queue length once every
// worker has unwound; no senders remain by then, so the count is stable).
func (p *Pool) emitShutdown(forced bool, dropped int) {
	reason := "graceful"
	if forced {
		reason = "forced"
	}
	p.observe(event.New(event.KindShutdown, p.clock.Now(), event.Shutdown{Reason: reason, Dropped: dropped}))
}

// emitScanStopped publishes the run's conclusion: completed for a graceful
// drain, cancelled for a forced one.
func (p *Pool) emitScanStopped(forced bool) {
	state := "completed"
	if forced {
		state = "cancelled"
	}
	p.observe(event.New(event.KindScanStopped, p.clock.Now(), event.ScanStopped{State: state}))
}
