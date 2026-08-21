package event

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Event bounds (fixed constants). They keep hostile or buggy emitters from
// inflating event memory or render sizes; constructors truncate with an
// explicit marker, and Event.Validate re-checks every field so hand-built
// events cannot smuggle oversized values past consumers.
const (
	// maxLabelBytes bounds Phase, Category, Identity, and Value.
	maxLabelBytes = 512
	// maxMessageBytes bounds payload message fields. It mirrors the report
	// framework's error-message bound (report.maxErrorMessageBytes = 512)
	// so event-derived error text has the same shape as report error
	// records.
	maxMessageBytes = 512
	// messageTruncationMarker marks a truncated message or label.
	messageTruncationMarker = "…"
)

// Event is one canonical observability event. It is structured, typed, and
// deterministic: Kind classifies it, Sequence is assigned by the bus at
// publish time (strictly increasing), At is the injected-clock timestamp,
// Severity is the surfacing level, Phase/Category are the context, and
// Identity/Value are the canonical identity/value the event is about.
// Payload is the sealed, typed payload (never an anonymous map).
//
// Events are immutable by convention: construct with New (or a literal) and
// derive variants with the With* methods; never mutate a published or shared
// event. String() is the standardized deterministic text form for tests and
// logs; machine consumers must read the fields, never the string.
type Event struct {
	// Kind classifies the event.
	Kind Kind `json:"kind"`

	// Sequence is assigned by the Bus at publish time (0 before publish).
	Sequence uint64 `json:"sequence"`

	// At is the injected-clock time the event was created.
	At time.Time `json:"at"`

	// Severity is the surfacing level (default SeverityInfo).
	Severity Severity `json:"severity"`

	// Phase is the run phase context (bounded label).
	Phase string `json:"phase,omitempty"`

	// Category is the event category context (bounded label or report
	// ErrorCategory value).
	Category string `json:"category,omitempty"`

	// Identity is the canonical identity the event is about (bounded), e.g.
	// "url:https://example.com/x" or "job 42".
	Identity string `json:"identity,omitempty"`

	// Value is a bounded human-visible value for the event.
	Value string `json:"value,omitempty"`

	// Payload is the typed payload (nil for none).
	Payload Payload `json:"payload"`
}

// New builds a canonical event of the given kind at the given clock time
// with the given typed payload. Payload must match kind (Validate checks);
// nil is allowed only for kinds without a payload.
func New(kind Kind, at time.Time, payload Payload) Event {
	return Event{Kind: kind, At: at, Payload: payload}
}

// WithSeverity returns a copy with the severity set.
func (e Event) WithSeverity(s Severity) Event { e.Severity = s; return e }

// WithPhase returns a copy with the phase context set (bounded).
func (e Event) WithPhase(phase string) Event { e.Phase = truncateLabel(phase); return e }

// WithCategory returns a copy with the category context set (bounded).
func (e Event) WithCategory(category string) Event { e.Category = truncateLabel(category); return e }

// WithIdentity returns a copy with the canonical identity set (bounded).
func (e Event) WithIdentity(identity string) Event { e.Identity = truncateLabel(identity); return e }

// WithValue returns a copy with the display value set (bounded).
func (e Event) WithValue(value string) Event { e.Value = truncateLabel(value); return e }

// Validate checks the canonical-event contract: a known kind, a non-zero
// timestamp, a valid severity, bounded context fields, and a payload that
// matches the kind. The bus validates before publishing (invalid events are
// dropped and counted), and consumers re-validate so hand-built hostile
// events cannot panic or inflate renderers.
func (e Event) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("event: unknown kind %q", string(e.Kind))
	}
	if e.At.IsZero() {
		return fmt.Errorf("event: kind %s carries no timestamp", e.Kind)
	}
	if !e.Severity.Valid() {
		return fmt.Errorf("event: kind %s carries invalid severity %d", e.Kind, int(e.Severity))
	}
	// Label bounds are plain length checks rather than a range over a map
	// literal: Validate runs on every publish (the hottest observability
	// path), explicit comparisons cost a few nanoseconds instead of a
	// 4-entry map walk, the check order is deterministic, and no toolchain
	// optimization is needed to keep the path allocation-free.
	if len(e.Phase) > maxLabelBytes {
		return fmt.Errorf("event: kind %s phase field is %d bytes over bound %d", e.Kind, len(e.Phase), maxLabelBytes)
	}
	if len(e.Category) > maxLabelBytes {
		return fmt.Errorf("event: kind %s category field is %d bytes over bound %d", e.Kind, len(e.Category), maxLabelBytes)
	}
	if len(e.Identity) > maxLabelBytes {
		return fmt.Errorf("event: kind %s identity field is %d bytes over bound %d", e.Kind, len(e.Identity), maxLabelBytes)
	}
	if len(e.Value) > maxLabelBytes {
		return fmt.Errorf("event: kind %s value field is %d bytes over bound %d", e.Kind, len(e.Value), maxLabelBytes)
	}
	return validatePayload(e.Kind, e.Payload)
}

// validatePayload checks that the payload matches the kind and that the
// payload's own bounded fields stay within bounds.
func validatePayload(kind Kind, p Payload) error {
	// Optional payloads first.
	switch kind {
	case KindSummaryReady:
		if _, ok := p.(SummaryReady); p != nil && !ok {
			return fmt.Errorf("event: kind %s requires a SummaryReady payload, got %T", kind, p)
		}
		return nil
	}
	if p == nil {
		return fmt.Errorf("event: kind %s requires a payload, got nil", kind)
	}
	switch p := p.(type) {
	case ScanStarted:
		if kind != KindScanStarted {
			return payloadMismatch(kind, p)
		}
	case ScanStopped:
		if kind != KindScanStopped {
			return payloadMismatch(kind, p)
		}
		if p.State != "completed" && p.State != "cancelled" {
			return fmt.Errorf("event: scan_stopped carries invalid state %q", p.State)
		}
	case StageStarted:
		if kind != KindStageStarted {
			return payloadMismatch(kind, p)
		}
		if p.Name == "" {
			return fmt.Errorf("event: stage_started carries an empty name")
		}
	case StageFinished:
		if kind != KindStageFinished {
			return payloadMismatch(kind, p)
		}
		if p.Name == "" {
			return fmt.Errorf("event: stage_finished carries an empty name")
		}
		if !stageOutcomeValid(p.Outcome) {
			return fmt.Errorf("event: stage_finished carries invalid outcome %q (vocabulary: completed/partial/failed/cancelled/incomplete)", p.Outcome)
		}
		if p.ItemsProcessed < 0 || p.ItemsFailed < 0 {
			return fmt.Errorf("event: stage_finished carries negative counts (processed=%d failed=%d)", p.ItemsProcessed, p.ItemsFailed)
		}
		if p.Duration < 0 {
			return fmt.Errorf("event: stage_finished carries negative duration %s", p.Duration)
		}
		if len(p.Err) > maxMessageBytes {
			return fmt.Errorf("event: stage_finished err is %d bytes over bound %d", len(p.Err), maxMessageBytes)
		}
	case WorkerStarted:
		if kind != KindWorkerStarted {
			return payloadMismatch(kind, p)
		}
	case WorkerStopped:
		if kind != KindWorkerStopped {
			return payloadMismatch(kind, p)
		}
		if !p.State.Valid() {
			return fmt.Errorf("event: worker_stopped carries invalid state %q", string(p.State))
		}
	case TaskSubmitted:
		if kind != KindTaskSubmitted {
			return payloadMismatch(kind, p)
		}
	case TaskStarted:
		if kind != KindTaskStarted {
			return payloadMismatch(kind, p)
		}
	case TaskRunning:
		if kind != KindTaskRunning {
			return payloadMismatch(kind, p)
		}
	case TaskCompleted:
		if kind != KindTaskCompleted {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_completed message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskCancelled:
		if kind != KindTaskCancelled {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_cancelled message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskFailed:
		if kind != KindTaskFailed {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_failed message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskTimedOut:
		if kind != KindTaskTimedOut {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_timed_out message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case CacheAccess:
		if kind != KindCacheHit && kind != KindCacheMiss {
			return payloadMismatch(kind, p)
		}
		if (kind == KindCacheHit) != p.Hit {
			return fmt.Errorf("event: cache payload contradicts its kind (hit=%v)", p.Hit)
		}
	case AssetDiscovered:
		if kind != KindAssetDiscovered {
			return payloadMismatch(kind, p)
		}
		if p.Identity == "" {
			return fmt.Errorf("event: asset_discovered carries an empty identity")
		}
		if p.Confidence < 0 || p.Confidence > 1 {
			return fmt.Errorf("event: asset_discovered confidence %v out of [0,1]", p.Confidence)
		}
	case RelationshipCreated:
		if kind != KindRelationshipCreated {
			return payloadMismatch(kind, p)
		}
	case EvidenceCreated:
		if kind != KindEvidenceCreated {
			return payloadMismatch(kind, p)
		}
	case FindingCreated:
		if kind != KindFindingCreated {
			return payloadMismatch(kind, p)
		}
		if p.Confidence < 0 || p.Confidence > 1 {
			return fmt.Errorf("event: finding_created confidence %v out of [0,1]", p.Confidence)
		}
	case RecommendationCreated:
		if kind != KindRecommendationCreated {
			return payloadMismatch(kind, p)
		}
		if p.Weight < 0 || p.Weight > 1 {
			return fmt.Errorf("event: recommendation_created weight %v out of [0,1]", p.Weight)
		}
	case RequestObserved:
		if kind != KindRequestObserved {
			return payloadMismatch(kind, p)
		}
	case RuleExecuted:
		if kind != KindRuleExecuted {
			return payloadMismatch(kind, p)
		}
		if p.Executions <= 0 {
			return fmt.Errorf("event: rule_executed executions must be positive, got %d", p.Executions)
		}
	case Warning:
		if kind != KindWarning {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: warning message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case Error:
		if kind != KindError {
			return payloadMismatch(kind, p)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: error message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case Progress:
		if kind != KindProgress {
			return payloadMismatch(kind, p)
		}
		if p.Completed < 0 || p.Total < 0 {
			return fmt.Errorf("event: progress counts must not be negative (completed=%d total=%d)", p.Completed, p.Total)
		}
	case PhaseTransition:
		if kind != KindPhaseTransition {
			return payloadMismatch(kind, p)
		}
		if p.Phase == "" {
			return fmt.Errorf("event: phase_transition carries an empty phase")
		}
	case Shutdown:
		if kind != KindShutdown {
			return payloadMismatch(kind, p)
		}
		if p.Reason != "graceful" && p.Reason != "forced" {
			return fmt.Errorf("event: shutdown carries invalid reason %q", p.Reason)
		}
	case RunMetadata:
		if kind != KindRunMetadata {
			return payloadMismatch(kind, p)
		}
	default:
		return fmt.Errorf("event: kind %s carries unvalidated payload type %T", kind, p)
	}
	return nil
}

func payloadMismatch(kind Kind, p Payload) error {
	return fmt.Errorf("event: kind %s carries mismatched payload %T", kind, p)
}

// stageOutcomeValid reports whether s is one of the fixed run-outcome
// vocabulary values (AGENTS.md §0.6: completed/partial/failed/cancelled/
// incomplete). The literal strings are kept here deliberately: internal/
// event must not import internal/pipeline, whose Outcome constants define
// the same vocabulary.
func stageOutcomeValid(s string) bool {
	switch s {
	case "completed", "partial", "failed", "cancelled", "incomplete":
		return true
	}
	return false
}

// String returns the standardized deterministic text form for tests and
// logs: "kind seq at [phase=..] [category=..] [identity=..] [value=..]
// payload(T)" with every string quoted. Logging code may use it; machine
// consumers must read the structured fields instead.
func (e Event) String() string {
	var b strings.Builder
	b.WriteString(string(e.Kind))
	fmt.Fprintf(&b, " seq=%d", e.Sequence)
	fmt.Fprintf(&b, " at=%q", e.At.Format(time.RFC3339Nano))
	fmt.Fprintf(&b, " severity=%s", e.Severity)
	if e.Phase != "" {
		fmt.Fprintf(&b, " phase=%q", e.Phase)
	}
	if e.Category != "" {
		fmt.Fprintf(&b, " category=%q", e.Category)
	}
	if e.Identity != "" {
		fmt.Fprintf(&b, " identity=%q", e.Identity)
	}
	if e.Value != "" {
		fmt.Fprintf(&b, " value=%q", e.Value)
	}
	if e.Payload != nil {
		fmt.Fprintf(&b, " payload(%T)", e.Payload)
	}
	return b.String()
}

// truncateLabel bounds a context label to maxLabelBytes bytes, rune-safe,
// with an explicit marker.
func truncateLabel(s string) string {
	return truncateBytes(s, maxLabelBytes)
}

// truncateMessage bounds a message to maxMessageBytes bytes, rune-safe,
// with an explicit marker.
func truncateMessage(s string) string {
	return truncateBytes(s, maxMessageBytes)
}

// truncateBytes bounds s to max bytes, trimming a torn trailing UTF-8
// sequence so the marker never follows a partial rune.
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	prefix := s[:max-len(messageTruncationMarker)]
	for len(prefix) > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix)
		if r != utf8.RuneError || size > 1 {
			break
		}
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + messageTruncationMarker
}
