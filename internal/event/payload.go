package event

import "time"

// Payload is the sealed, typed payload of an Event. Every concrete payload
// is a struct with documented fields; anonymous maps are never payloads.
// The marker method keeps the set closed: events can only carry the
// canonical payloads of this package.
type Payload interface {
	isPayload()
}

// ScanStarted carries the pool configuration of the run's execution
// backbone. Field grounding: all four fields are projections of the runtime
// engine's Config (internal/runtime).
type ScanStarted struct {
	// Concurrency: runtime.Config.Concurrency (exact worker count).
	Concurrency int `json:"concurrency"`
	// QueueSize: runtime.Config.QueueSize (bounded submission queue).
	QueueSize int `json:"queue_size"`
	// Timeout: runtime.Config.Timeout (default per-job deadline; 0 = none).
	Timeout time.Duration `json:"timeout"`
	// Rate: runtime.Config.Rate (central rate limiter tokens/second; 0 =
	// disabled).
	Rate float64 `json:"rate"`
}

func (ScanStarted) isPayload() {}

// ScanStopped carries how the run's execution backbone ended. Field
// grounding: State is the runtime engine's outcome vocabulary for shutdown
// (a clean drain is completed; a cancelled drain context is cancelled).
type ScanStopped struct {
	// State: "completed" (graceful drain) or "cancelled" (forced shut
	// down); vocabulary: runtime outcome vocabulary.
	State string `json:"state"`
}

func (ScanStopped) isPayload() {}

// StageStarted identifies one pipeline stage entry invocation. Field
// grounding: Name is the pipeline StageName of the stage (the selection
// entry in ScanConfig.Stages order), emitted by the pipeline runner
// (internal/pipeline).
type StageStarted struct {
	// Name: the stage name (pipeline StageName string).
	Name string `json:"name"`
}

func (StageStarted) isPayload() {}

// StageFinished carries one pipeline stage entry's recorded outcome. Field
// grounding: every field mirrors the recorded pipeline.StageRecord:
// Name/Outcome/Truncated/ItemsProcessed/ItemsFailed/Duration come straight
// from the record (Outcome is the fixed AGENTS §0.6 vocabulary;
// ItemsProcessed/ItemsFailed are >= 0; Duration is >= 0), and Err is the
// record's error message (empty when the record carries none), bounded to
// the message bound.
type StageFinished struct {
	// Name: the stage name (pipeline StageName string).
	Name string `json:"name"`
	// Outcome: the fixed run-outcome vocabulary (AGENTS §0.6):
	// "completed", "partial", "failed", "cancelled", "incomplete".
	Outcome string `json:"outcome"`
	// Truncated: the stage cut its retained set at a cap.
	Truncated bool `json:"truncated"`
	// ItemsProcessed: the stage's recorded processed count (>= 0).
	ItemsProcessed int `json:"items_processed"`
	// ItemsFailed: the stage's recorded failed count (>= 0).
	ItemsFailed int `json:"items_failed"`
	// Duration: the stage's recorded duration (>= 0).
	Duration time.Duration `json:"duration"`
	// Err: the recorded error's message (empty when none), bounded.
	Err string `json:"err,omitempty"`
}

func (StageFinished) isPayload() {}

// WorkerStarted identifies one pool worker.
type WorkerStarted struct {
	// Worker: the worker index (0 .. Concurrency-1).
	Worker int `json:"worker"`
}

func (WorkerStarted) isPayload() {}

// WorkerStopped carries how one pool worker ended. Field grounding: State
// is the WorkerState vocabulary; the runtime pool emits completed (queue
// drained) or cancelled (forced abort).
type WorkerStopped struct {
	// Worker: the worker index (0 .. Concurrency-1).
	Worker int `json:"worker"`
	// State: "completed" or "cancelled" from the runtime pool.
	State WorkerState `json:"state"`
}

func (WorkerStopped) isPayload() {}

// TaskSubmitted records that a job was enqueued. Field grounding: JobID is
// runtime.JobID (assigned at Submit); Worker is unset (the task has not
// been picked up).
type TaskSubmitted struct {
	// JobID: runtime.JobID of the submitted job.
	JobID uint64 `json:"job_id"`
}

func (TaskSubmitted) isPayload() {}

// TaskStarted records that a worker picked a task up; the task may still be
// waiting for its rate-limit token (worker state "waiting").
type TaskStarted struct {
	// JobID: runtime.JobID of the task.
	JobID uint64 `json:"job_id"`
	// Worker: the worker index executing it.
	Worker int `json:"worker"`
}

func (TaskStarted) isPayload() {}

// TaskRunning records that a task's function body began executing (after
// the rate-limit wait); the worker state is "running".
type TaskRunning struct {
	// JobID: runtime.JobID of the task.
	JobID uint64 `json:"job_id"`
	// Worker: the worker index executing it.
	Worker int `json:"worker"`
}

func (TaskRunning) isPayload() {}

// TaskTerminal carries the shared fields of every terminal task event.
// Field grounding: JobID/StartedAt mirror runtime.Event.JobID/StartedAt
// (StartedAt is zero for tasks cancelled before they could start);
// Category is a projection of the report framework's ErrorCategory
// vocabulary ("timeout", "cancellation", "unknown" from the runtime pool;
// stage emitters may attach a more precise category).
type TaskTerminal struct {
	// JobID: runtime.JobID of the task.
	JobID uint64 `json:"job_id"`
	// Worker: the worker index executing it.
	Worker int `json:"worker"`
	// StartedAt: runtime.Event.StartedAt (zero if never started).
	StartedAt time.Time `json:"started_at,omitempty"`
	// Category: report.ErrorCategory projection ("timeout", "cancellation",
	// "unknown", or a stage category).
	Category string `json:"category,omitempty"`
	// Message is the bounded terminal message (the error text for failed,
	// cancelled, and timed-out tasks; empty for completed ones).
	Message string `json:"message,omitempty"`
}

// TaskCompleted: the task returned a result from a healthy context. Field
// grounding: Result mirrors runtime.Event.Result (the raw job result); it
// is the pool-job-boundary hand-off that caller-provided Deriver
// implementations convert into derived events (asset discovered, finding
// created, ...). Engines never emit those themselves.
type TaskCompleted struct {
	TaskTerminal

	// Result: runtime.Event.Result of the completed job (may be nil).
	Result any `json:"result,omitempty"`
}

func (TaskCompleted) isPayload() {}

// TaskCancelled: the task was cancelled and is never reported as success.
type TaskCancelled struct{ TaskTerminal }

func (TaskCancelled) isPayload() {}

// TaskFailed: the task returned an error (or panicked and was recovered).
type TaskFailed struct{ TaskTerminal }

func (TaskFailed) isPayload() {}

// TaskTimedOut: the task exceeded its deadline.
type TaskTimedOut struct{ TaskTerminal }

func (TaskTimedOut) isPayload() {}

// CacheAccess is the payload of cache hit/miss events. Field grounding:
// Key is the cache.Key digest string, State is the cache OutcomeState
// (cache.Outcome.State.String()), Hit is cache.Outcome.IsHit().
type CacheAccess struct {
	// Key: internal/cache Key (64-char lowercase hex digest).
	Key string `json:"key"`
	// State: cache.OutcomeState.String() ("hit", "miss", "expired",
	// "corrupt", "schema-incompatible", "incomplete", "error").
	State string `json:"state"`
	// Hit: cache.Outcome.IsHit().
	Hit bool `json:"hit"`
}

func (CacheAccess) isPayload() {}

// AssetDiscovered identifies one canonical Phase 2 asset observation. Field
// grounding: Identity is the canonical identity string
// (asset.Identity{Kind, Value}.String()); Kind is asset.Kind; Method is
// asset.Endpoint.Method when the asset is an endpoint (the jsintel/urlintel
// endpoint classes "GET"/"WS"/"SSE"/"GQL"); Path is asset.URL.Path when the
// asset carries a canonical path.
type AssetDiscovered struct {
	// Identity: canonical asset identity string, e.g. "url:https://…".
	Identity string `json:"identity"`
	// Kind: asset.Kind of the identity ("host", "url", "endpoint",
	// "technology", "secret_candidate", "source_map", ...).
	Kind string `json:"kind"`
	// Method: asset.Endpoint.Method for endpoint assets ("" otherwise).
	Method string `json:"method,omitempty"`
	// Path: asset.URL.Path for URL/endpoint assets ("" otherwise).
	Path string `json:"path,omitempty"`
	// Confidence: asset.Provenance.Confidence of the observation (e.g. the
	// secret engine's confidence for secret candidates); 0 when unknown.
	Confidence float64 `json:"confidence,omitempty"`
}

func (AssetDiscovered) isPayload() {}

// RelationshipCreated identifies a new typed asset edge. Field grounding:
// From/To are the canonical identity strings of asset.Relationship.From /
// asset.Relationship.To; Kind is asset.Relationship.Kind (asset.
// RelationshipKind, e.g. "host_to_ip").
type RelationshipCreated struct {
	// From: asset.Relationship.From identity string.
	From string `json:"from"`
	// To: asset.Relationship.To identity string.
	To string `json:"to"`
	// Kind: asset.RelationshipKind ("host_to_ip", "url_to_endpoint", ...).
	Kind string `json:"kind"`
}

func (RelationshipCreated) isPayload() {}

// EvidenceCreated identifies one evidence record. Field grounding:
// Identity is asset.Evidence.Identity().String(); Source is
// asset.Evidence.Source identity string; Method is asset.Evidence.Method
// (asset.DetectionMethod, e.g. "header", "js", "secret", "detect").
type EvidenceCreated struct {
	// Identity: canonical evidence identity string.
	Identity string `json:"identity"`
	// Source: identity string of the source asset the observation came from.
	Source string `json:"source"`
	// Method: asset.DetectionMethod of the evidence record.
	Method string `json:"method"`
}

func (EvidenceCreated) isPayload() {}

// FindingCreated identifies one detection finding. Field grounding: all
// fields are projections of asset.Finding fields and the detection
// framework's typed vocabularies: RuleID <- asset.Finding.RuleID, Subject
// <- asset.Finding.Subject (identity string), Priority <- asset.Finding.
// Priority (detect.FindingPriority: info/low/medium/high/critical),
// Category <- asset.Finding.Category (detect.Category), Confidence <-
// asset.Finding.Confidence.
type FindingCreated struct {
	// Identity: canonical finding identity ("finding:ruleID@subject").
	Identity string `json:"identity"`
	// RuleID: asset.Finding.RuleID.
	RuleID string `json:"rule_id"`
	// Subject: asset.Finding.Subject identity string.
	Subject string `json:"subject"`
	// Priority: detect.FindingPriority label.
	Priority string `json:"priority"`
	// Category: detect.Category label.
	Category string `json:"category"`
	// Confidence: asset.Finding.Confidence (0..1).
	Confidence float64 `json:"confidence"`
}

func (FindingCreated) isPayload() {}

// RecommendationCreated identifies one projected reconnaissance
// recommendation. Field grounding: Identity is priority.SurfaceAsset.
// Identity (identity string), Text is the rendered factor recommendation
// (priority.Factor.Recommendation, preserved verbatim), Level is
// priority.SurfaceAsset.Level (priority.PriorityLevel), Weight is the
// factor's weight (priority.Factor.Weight).
type RecommendationCreated struct {
	// Identity: canonical identity of the scored surface.
	Identity string `json:"identity"`
	// Text: priority.Factor.Recommendation (verbatim guidance).
	Text string `json:"text"`
	// Level: priority.PriorityLevel of the surface ("high", "medium", ...).
	Level string `json:"level"`
	// Weight: priority.Factor.Weight (0..1).
	Weight float64 `json:"weight"`
}

func (RecommendationCreated) isPayload() {}

// RequestObserved counts one observed HTTP request. Field grounding:
// Identity is the canonical URL identity of the request target
// (asset.URL.Identity().String()); Method is the request method. Stage
// result bridges emit one event per dispatched request, including followed
// redirect hops.
type RequestObserved struct {
	// Identity: canonical URL identity of the request target.
	Identity string `json:"identity"`
	// Method: HTTP request method (e.g. "GET").
	Method string `json:"method,omitempty"`
}

func (RequestObserved) isPayload() {}

// RuleExecuted counts one detection rule execution. Field grounding:
// RuleID is the registered rule ID (detect.Rule.ID); Executions is the
// number of executions this event accounts for (detect metrics count
// fresh executions; cached results may be reported as executions too when
// the bridge records them).
type RuleExecuted struct {
	// RuleID: detect.Rule.ID.
	RuleID string `json:"rule_id"`
	// Executions: number of executions accounted for (>= 1).
	Executions int `json:"executions"`
}

func (RuleExecuted) isPayload() {}

// Warning carries a non-fatal warning. Field grounding: Category is the
// report framework's ErrorCategory vocabulary (or a stage label); Message
// is the bounded warning text.
type Warning struct {
	// Category: report.ErrorCategory label or stage label.
	Category string `json:"category,omitempty"`
	// Message: bounded warning text.
	Message string `json:"message"`
}

func (Warning) isPayload() {}

// Error carries an error observation. Field grounding: Category is the
// report framework's ErrorCategory vocabulary (report.ErrorRecord.Category
// or report.ClassifyError's structural classification); Message is the
// bounded error text (report.ErrorRecord.Message shape).
type Error struct {
	// Category: report.ErrorCategory label.
	Category string `json:"category,omitempty"`
	// Message: bounded error text.
	Message string `json:"message"`
}

func (Error) isPayload() {}

// Progress is an honest progress update. Field grounding: Phase is the
// stage/phase label the totals belong to; Completed/Total are the emitter's
// real task counts. TotalKnown must be false when the emitter cannot
// declare a total — consumers then show unknown progress and never fake a
// percentage.
type Progress struct {
	// Phase: label of the phase the totals belong to.
	Phase string `json:"phase,omitempty"`
	// Completed: tasks completed (emitter-declared).
	Completed int `json:"completed"`
	// Total: total tasks when TotalKnown; meaningless otherwise.
	Total int `json:"total"`
	// TotalKnown: whether Total is a real number.
	TotalKnown bool `json:"total_known"`
}

func (Progress) isPayload() {}

// PhaseTransition records entering a new phase. Phase is a bounded
// free-form stage label ("running", "draining" from the runtime pool;
// stage names from orchestrators).
type PhaseTransition struct {
	// Phase: the phase the run entered.
	Phase string `json:"phase"`
}

func (PhaseTransition) isPayload() {}

// Shutdown records an execution backbone's teardown. Field grounding:
// Reason follows the runtime engine's shutdown semantics ("graceful" when
// Shutdown drained cleanly, "forced" when the drain context was cancelled);
// Dropped is the number of queued jobs that were never picked up (the
// runtime pool counts its remaining queue after the workers unwind).
type Shutdown struct {
	// Reason: "graceful" or "forced".
	Reason string `json:"reason"`
	// Dropped: queued jobs dropped without a terminal event.
	Dropped int `json:"dropped"`
}

func (Shutdown) isPayload() {}

// RunMetadata carries run-level metadata known only to the orchestration
// caller. Field grounding: Target is report.Context.Target (the declared
// target string); OutputDir is the report writer's output directory (the
// directory report file sinks write into). Absent events => consumers show
// honest "unknown"/"—".
type RunMetadata struct {
	// Target: report.Context.Target ("" = unset).
	Target string `json:"target,omitempty"`
	// OutputDir: the run's report output directory ("" = unset).
	OutputDir string `json:"output_dir,omitempty"`
}

func (RunMetadata) isPayload() {}

// SummaryReady marks the production of a final run summary; it carries no
// data (the summary itself is rendered by the emitting component).
type SummaryReady struct{}

func (SummaryReady) isPayload() {}

// Bounded payload constructors.
//
// The bus drops events whose payload fields exceed their bounds, so
// constructors bound message and category fields at construction time
// (rune-safe, with the explicit truncation marker) — a well-behaved emitter
// never produces an event the bus must reject.

// NewWarning builds a bounded Warning payload: the category is bounded as a
// label and the message as a message.
func NewWarning(category, message string) Warning {
	return Warning{Category: truncateLabel(category), Message: truncateMessage(message)}
}

// NewError builds a bounded Error payload: the category is bounded as a
// label and the message as a message.
func NewError(category, message string) Error {
	return Error{Category: truncateLabel(category), Message: truncateMessage(message)}
}

// NewTaskTerminal builds a bounded TaskTerminal: the category is bounded as
// a label and the message as a message. startedAt mirrors
// runtime.Event.StartedAt (zero for tasks cancelled before they could
// start).
func NewTaskTerminal(jobID uint64, worker int, startedAt time.Time, category, message string) TaskTerminal {
	return TaskTerminal{
		JobID:     jobID,
		Worker:    worker,
		StartedAt: startedAt,
		Category:  truncateLabel(category),
		Message:   truncateMessage(message),
	}
}

// NewTaskCompleted builds a TaskCompleted payload from a bounded terminal
// and the raw job result.
func NewTaskCompleted(term TaskTerminal, result any) TaskCompleted {
	return TaskCompleted{TaskTerminal: term, Result: result}
}

// NewTaskCancelled builds a TaskCancelled payload from a bounded terminal.
func NewTaskCancelled(term TaskTerminal) TaskCancelled {
	return TaskCancelled{TaskTerminal: term}
}

// NewTaskFailed builds a TaskFailed payload from a bounded terminal.
func NewTaskFailed(term TaskTerminal) TaskFailed {
	return TaskFailed{TaskTerminal: term}
}

// NewTaskTimedOut builds a TaskTimedOut payload from a bounded terminal.
func NewTaskTimedOut(term TaskTerminal) TaskTimedOut {
	return TaskTimedOut{TaskTerminal: term}
}

// NewStageFinished builds a bounded StageFinished payload: the error text
// is bounded as a message. errMsg is the recorded error's message (empty
// when the stage recorded no error).
func NewStageFinished(name, outcome string, truncated bool, itemsProcessed, itemsFailed int, duration time.Duration, errMsg string) StageFinished {
	return StageFinished{
		Name:           name,
		Outcome:        outcome,
		Truncated:      truncated,
		ItemsProcessed: itemsProcessed,
		ItemsFailed:    itemsFailed,
		Duration:       duration,
		Err:            truncateMessage(errMsg),
	}
}
