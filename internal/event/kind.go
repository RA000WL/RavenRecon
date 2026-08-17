package event

import "fmt"

// Kind classifies an Event. Values are canonical lowercase forms; unknown
// values are rejected by Event.Validate and dropped by the bus.
type Kind string

// Canonical event kinds. The list is the Phase 12 minimum plus the
// accounting kinds the observability components derive state from (task
// submission pickup/running phases, request/rule counting, run metadata).
const (
	// KindScanStarted: a run's execution backbone began. The runtime pool
	// emits it at pool creation (the pool's lifetime brackets the observed
	// run); the payload carries the pool configuration.
	KindScanStarted Kind = "scan_started"

	// KindScanStopped: the run's execution backbone concluded. The runtime
	// pool emits it at shutdown completion with the honest outcome
	// vocabulary (completed for a graceful drain, cancelled for a forced
	// one).
	KindScanStopped Kind = "scan_stopped"

	// KindWorkerStarted: one pool worker goroutine began its loop.
	KindWorkerStarted Kind = "worker_started"

	// KindWorkerStopped: one pool worker goroutine exited its loop, with
	// the worker state (completed = graceful drain, cancelled = forced
	// abort).
	KindWorkerStopped Kind = "worker_stopped"

	// KindTaskSubmitted: a job was enqueued (queued, not yet picked up).
	KindTaskSubmitted Kind = "task_submitted"

	// KindTaskStarted: a worker picked the task up; it may still be waiting
	// for its rate-limit token. The worker is "waiting".
	KindTaskStarted Kind = "task_started"

	// KindTaskRunning: the task's function body actually began executing
	// (after the rate-limit wait). The worker is "running".
	KindTaskRunning Kind = "task_running"

	// KindTaskCompleted: a task returned a result from a healthy context.
	// The payload carries the raw job result for boundary-side derivation.
	KindTaskCompleted Kind = "task_completed"

	// KindTaskCancelled: a task was cancelled (pool context or forced
	// shutdown), never reported as success.
	KindTaskCancelled Kind = "task_cancelled"

	// KindTaskFailed: a task returned an error from a healthy context
	// (including a recovered panic).
	KindTaskFailed Kind = "task_failed"

	// KindTaskTimedOut: a task exceeded its deadline while waiting for a
	// token or while executing. Surfaced distinctly from cancellation.
	KindTaskTimedOut Kind = "task_timed_out"

	// KindCacheHit: a cache lookup returned a usable completed record.
	KindCacheHit Kind = "cache_hit"

	// KindCacheMiss: a cache lookup returned no usable record (any non-hit
	// OutcomeState; the payload carries the precise state).
	KindCacheMiss Kind = "cache_miss"

	// KindAssetDiscovered: a canonical Phase 2 asset was observed.
	KindAssetDiscovered Kind = "asset_discovered"

	// KindRelationshipCreated: a typed asset relationship edge was created.
	KindRelationshipCreated Kind = "relationship_created"

	// KindEvidenceCreated: an evidence record was created.
	KindEvidenceCreated Kind = "evidence_created"

	// KindFindingCreated: a detection finding was produced.
	KindFindingCreated Kind = "finding_created"

	// KindRecommendationCreated: a reconnaissance recommendation was
	// projected from a scored surface.
	KindRecommendationCreated Kind = "recommendation_created"

	// KindRequestObserved: one observed HTTP request (probe or fetch,
	// including followed redirect hops).
	KindRequestObserved Kind = "request_observed"

	// KindRuleExecuted: one detection rule execution (fresh or cached).
	KindRuleExecuted Kind = "rule_executed"

	// KindWarning: a non-fatal warning observation.
	KindWarning Kind = "warning"

	// KindError: an error observation (task failures are carried by their
	// own task kinds; KindError is for stage-level and external errors).
	KindError Kind = "error"

	// KindProgress: an honest progress update from an emitter that knows
	// totals. When total work is unknown, emitters must leave TotalKnown
	// false; consumers never fake a percentage.
	KindProgress Kind = "progress"

	// KindPhaseTransition: the run entered a new phase. The runtime pool
	// emits its own lifecycle phases ("running", "draining"); stage
	// orchestrators emit stage phases.
	KindPhaseTransition Kind = "phase_transition"

	// KindShutdown: an execution backbone concluded its teardown, with the
	// reason (graceful/forced) and the number of queued jobs dropped.
	KindShutdown Kind = "shutdown"

	// KindRunMetadata: optional run-level metadata (declared target,
	// output directory) emitted by the orchestration caller that knows it.
	// Absent => consumers show "unknown"/"—".
	KindRunMetadata Kind = "run_metadata"

	// KindSummaryReady: a final run summary was produced. Emitted by the
	// component that renders the run's conclusion (for example the TUI
	// controller) as a notification for other bus consumers.
	KindSummaryReady Kind = "summary_ready"
)

// Valid reports whether k is a known event kind.
func (k Kind) Valid() bool {
	switch k {
	case KindScanStarted, KindScanStopped, KindWorkerStarted, KindWorkerStopped,
		KindTaskSubmitted, KindTaskStarted, KindTaskRunning, KindTaskCompleted,
		KindTaskCancelled, KindTaskFailed, KindTaskTimedOut,
		KindCacheHit, KindCacheMiss, KindAssetDiscovered,
		KindRelationshipCreated, KindEvidenceCreated, KindFindingCreated,
		KindRecommendationCreated, KindRequestObserved, KindRuleExecuted,
		KindWarning, KindError, KindProgress, KindPhaseTransition,
		KindShutdown, KindRunMetadata, KindSummaryReady:
		return true
	}
	return false
}

// String returns the canonical lowercase kind value.
func (k Kind) String() string { return string(k) }

// Severity classifies how loudly an event should be surfaced. The zero
// value is SeverityInfo.
type Severity int

// Severity levels.
const (
	// SeverityInfo: routine progress and observations.
	SeverityInfo Severity = iota
	// SeverityWarning: notable but non-fatal (cancellations, warnings).
	SeverityWarning
	// SeverityError: failures and errors.
	SeverityError
)

// String returns a stable human-readable label.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityError:
		return true
	}
	return false
}

// WorkerState is the per-worker state vocabulary of the worker dashboard.
// The runtime pool emits WorkerStopped with completed (graceful drain) or
// cancelled (forced abort); failed is reserved for manual emitters (a
// panicking job fails the task, never the worker — the pool isolates it).
type WorkerState string

// Worker states.
const (
	WorkerIdle      WorkerState = "idle"
	WorkerWaiting   WorkerState = "waiting"
	WorkerRunning   WorkerState = "running"
	WorkerCancelled WorkerState = "cancelled"
	WorkerFailed    WorkerState = "failed"
	WorkerCompleted WorkerState = "completed"
)

// Valid reports whether s is a known worker state.
func (s WorkerState) Valid() bool {
	switch s {
	case WorkerIdle, WorkerWaiting, WorkerRunning, WorkerCancelled,
		WorkerFailed, WorkerCompleted:
		return true
	}
	return false
}

// String returns the canonical lowercase state value.
func (s WorkerState) String() string { return string(s) }
