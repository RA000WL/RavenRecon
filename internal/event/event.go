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

	// Payload string-field bounds, checked by validatePayload so hand-built
	// events cannot smuggle unbounded strings past consumers. Every bound
	// is derived from what the codebase's own producers can legitimately
	// emit today (see each comment).

	// maxIdentityStringBytes bounds payload fields carrying canonical asset
	// identity strings (AssetDiscovered.Identity/Kind-namespace strings,
	// RelationshipCreated.From/To, EvidenceCreated.Identity/Source,
	// FindingCreated.Identity/Subject, RecommendationCreated.Identity,
	// RequestObserved.Identity). The widest legitimate producer is the URL
	// identity: ParseURL (internal/asset/url.go) accepts raw inputs of at
	// most maxRawURLBytes = 8 KiB, and canonical query emission can expand
	// each raw byte into a three-byte percent escape, so 32 KiB covers
	// every identity string the codebase can produce today with headroom.
	maxIdentityStringBytes = 32 * 1024
	// maxPayloadPathBytes bounds AssetDiscovered.Path: asset.URL.Path, the
	// canonical ESCAPED path (removeDotSegments over url.URL.EscapedPath).
	// The derivation is NOT "ParseURL's 8 KiB raw-input cap": percent-
	// escaping can expand a raw path byte to three bytes (" " -> "%20"),
	// so an 8 KiB raw input's escaped path may exceed this bound. No
	// production emitter publishes this payload today; when one exists it
	// must pass a Path that fits this bound — truncating or skipping an
	// oversized asset at emission time, never relying on the input cap.
	maxPayloadPathBytes = 8 * 1024
	// maxKindLabelBytes bounds short vocabulary labels: AssetDiscovered.
	// Kind (asset.Kind values, longest "secret_candidate"),
	// RelationshipCreated.Kind (asset.RelationshipKind, bounded by
	// NewRelationship at 64), RecommendationCreated.Level
	// (priority.PriorityLevel), and Shutdown.Reason.
	maxKindLabelBytes = 64
	// maxMethodBytes bounds method-like labels: endpoint methods
	// (asset.validateMethod allows at most 16 bytes), HTTP request methods,
	// and evidence detection methods (a short fixed vocabulary:
	// "header", "js", "secret", ...).
	maxMethodBytes = 64
	// maxCacheKeyBytes bounds CacheAccess.Key: an internal/cache Key is a
	// 64-character lowercase hex digest; doubled for headroom.
	maxCacheKeyBytes = 128
	// maxCacheStateBytes bounds CacheAccess.State: the cache outcome-state
	// vocabulary ("hit", "miss", ..., longest "schema-incompatible").
	maxCacheStateBytes = 64
	// maxRuleIDBytes bounds RuleExecuted.RuleID and FindingCreated.RuleID,
	// mirroring the finding layer's rule-ID bound
	// (asset.maxFindingRuleIDBytes = 128).
	maxRuleIDBytes = 128
	// maxRecommendationTextBytes bounds RecommendationCreated.Text: the
	// rendered recommendation from the priority catalog, whose compile-time
	// template bound guarantees rendered text of at most 256 bytes
	// (priority.maxRecommendationBytes).
	maxRecommendationTextBytes = 256
	// maxFindingLabelBytes bounds FindingCreated.Priority and .Category:
	// detection-framework vocabulary labels, mirroring the finding layer's
	// category bound (asset.maxFindingCategoryBytes = 64).
	maxFindingLabelBytes = 64
	// maxStageNameBytes bounds StageStarted.Name, StageFinished.Name,
	// Progress.Phase, and PhaseTransition.Phase: pipeline stage names and
	// lifecycle phase labels ("running", "draining", "import" — all fixed
	// short literals in today's emitters), with the same headroom as the
	// context-label bound.
	maxStageNameBytes = 512
	// maxMetadataBytes bounds RunMetadata.Target and RunMetadata.OutputDir:
	// a declared target string and a filesystem output directory, both of
	// which comfortably fit within a PATH_MAX-sized path.
	maxMetadataBytes = 4096
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
		// Stage names are pipeline stage labels; today's emitters pass
		// fixed short literals, and 512 bytes leaves the same headroom as
		// the context-label bound.
		if len(p.Name) > maxStageNameBytes {
			return fmt.Errorf("event: stage_started name is %d bytes over bound %d", len(p.Name), maxStageNameBytes)
		}
	case StageFinished:
		if kind != KindStageFinished {
			return payloadMismatch(kind, p)
		}
		if p.Name == "" {
			return fmt.Errorf("event: stage_finished carries an empty name")
		}
		if len(p.Name) > maxStageNameBytes {
			return fmt.Errorf("event: stage_finished name is %d bytes over bound %d", len(p.Name), maxStageNameBytes)
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
		// Category is bounded at construction by NewTaskTerminal; Validate
		// re-checks so hand-built terminals cannot bypass the bound.
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: task_completed category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_completed message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskCancelled:
		if kind != KindTaskCancelled {
			return payloadMismatch(kind, p)
		}
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: task_cancelled category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_cancelled message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskFailed:
		if kind != KindTaskFailed {
			return payloadMismatch(kind, p)
		}
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: task_failed category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_failed message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case TaskTimedOut:
		if kind != KindTaskTimedOut {
			return payloadMismatch(kind, p)
		}
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: task_timed_out category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: task_timed_out message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case CacheAccess:
		if kind != KindCacheHit && kind != KindCacheMiss {
			return payloadMismatch(kind, p)
		}
		// Key is a cache.Key digest (64-char lowercase hex); State is the
		// short cache outcome-state vocabulary.
		if len(p.Key) > maxCacheKeyBytes {
			return fmt.Errorf("event: cache key is %d bytes over bound %d", len(p.Key), maxCacheKeyBytes)
		}
		if len(p.State) > maxCacheStateBytes {
			return fmt.Errorf("event: cache state is %d bytes over bound %d", len(p.State), maxCacheStateBytes)
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
		// Identity is the canonical identity string; the widest legitimate
		// producer is a URL identity derived from an 8 KiB raw input whose
		// query can triple under percent-escaping.
		if len(p.Identity) > maxIdentityStringBytes {
			return fmt.Errorf("event: asset_discovered identity is %d bytes over bound %d", len(p.Identity), maxIdentityStringBytes)
		}
		if len(p.Kind) > maxKindLabelBytes {
			return fmt.Errorf("event: asset_discovered kind is %d bytes over bound %d", len(p.Kind), maxKindLabelBytes)
		}
		if len(p.Method) > maxMethodBytes {
			return fmt.Errorf("event: asset_discovered method is %d bytes over bound %d", len(p.Method), maxMethodBytes)
		}
		if len(p.Path) > maxPayloadPathBytes {
			return fmt.Errorf("event: asset_discovered path is %d bytes over bound %d", len(p.Path), maxPayloadPathBytes)
		}
		if p.Confidence < 0 || p.Confidence > 1 {
			return fmt.Errorf("event: asset_discovered confidence %v out of [0,1]", p.Confidence)
		}
	case RelationshipCreated:
		if kind != KindRelationshipCreated {
			return payloadMismatch(kind, p)
		}
		// From/To are canonical identity strings; Kind is a
		// RelationshipKind label bounded by NewRelationship at 64 bytes.
		if len(p.From) > maxIdentityStringBytes {
			return fmt.Errorf("event: relationship_created from-identity is %d bytes over bound %d", len(p.From), maxIdentityStringBytes)
		}
		if len(p.To) > maxIdentityStringBytes {
			return fmt.Errorf("event: relationship_created to-identity is %d bytes over bound %d", len(p.To), maxIdentityStringBytes)
		}
		if len(p.Kind) > maxKindLabelBytes {
			return fmt.Errorf("event: relationship_created kind is %d bytes over bound %d", len(p.Kind), maxKindLabelBytes)
		}
	case EvidenceCreated:
		if kind != KindEvidenceCreated {
			return payloadMismatch(kind, p)
		}
		// Identity/Source are canonical identity strings; Method is a
		// DetectionMethod vocabulary label ("header", "js", "secret", ...).
		if len(p.Identity) > maxIdentityStringBytes {
			return fmt.Errorf("event: evidence_created identity is %d bytes over bound %d", len(p.Identity), maxIdentityStringBytes)
		}
		if len(p.Source) > maxIdentityStringBytes {
			return fmt.Errorf("event: evidence_created source is %d bytes over bound %d", len(p.Source), maxIdentityStringBytes)
		}
		if len(p.Method) > maxMethodBytes {
			return fmt.Errorf("event: evidence_created method is %d bytes over bound %d", len(p.Method), maxMethodBytes)
		}
	case FindingCreated:
		if kind != KindFindingCreated {
			return payloadMismatch(kind, p)
		}
		// Identity is the canonical finding identity string, bounded like
		// every sibling identity field (AssetDiscovered/EvidenceCreated).
		if len(p.Identity) > maxIdentityStringBytes {
			return fmt.Errorf("event: finding_created identity is %d bytes over bound %d", len(p.Identity), maxIdentityStringBytes)
		}
		// RuleID mirrors the finding layer's rule-ID bound
		// (asset.maxFindingRuleIDBytes = 128); Priority and Category are
		// detection-framework vocabulary labels (finding layer bounds its
		// category at 64).
		if len(p.RuleID) > maxRuleIDBytes {
			return fmt.Errorf("event: finding_created rule ID is %d bytes over bound %d", len(p.RuleID), maxRuleIDBytes)
		}
		if len(p.Subject) > maxIdentityStringBytes {
			return fmt.Errorf("event: finding_created subject is %d bytes over bound %d", len(p.Subject), maxIdentityStringBytes)
		}
		if len(p.Priority) > maxFindingLabelBytes {
			return fmt.Errorf("event: finding_created priority is %d bytes over bound %d", len(p.Priority), maxFindingLabelBytes)
		}
		if len(p.Category) > maxFindingLabelBytes {
			return fmt.Errorf("event: finding_created category is %d bytes over bound %d", len(p.Category), maxFindingLabelBytes)
		}
		if p.Confidence < 0 || p.Confidence > 1 {
			return fmt.Errorf("event: finding_created confidence %v out of [0,1]", p.Confidence)
		}
	case RecommendationCreated:
		if kind != KindRecommendationCreated {
			return payloadMismatch(kind, p)
		}
		// Identity is the canonical scored-surface identity string, bounded
		// like every sibling identity field.
		if len(p.Identity) > maxIdentityStringBytes {
			return fmt.Errorf("event: recommendation_created identity is %d bytes over bound %d", len(p.Identity), maxIdentityStringBytes)
		}
		// Text is the rendered catalog recommendation; priority's
		// compile-time template bound keeps rendered text within 256 bytes.
		if len(p.Text) > maxRecommendationTextBytes {
			return fmt.Errorf("event: recommendation_created text is %d bytes over bound %d", len(p.Text), maxRecommendationTextBytes)
		}
		if len(p.Level) > maxKindLabelBytes {
			return fmt.Errorf("event: recommendation_created level is %d bytes over bound %d", len(p.Level), maxKindLabelBytes)
		}
		if p.Weight < 0 || p.Weight > 1 {
			return fmt.Errorf("event: recommendation_created weight %v out of [0,1]", p.Weight)
		}
	case RequestObserved:
		if kind != KindRequestObserved {
			return payloadMismatch(kind, p)
		}
		if len(p.Identity) > maxIdentityStringBytes {
			return fmt.Errorf("event: request_observed identity is %d bytes over bound %d", len(p.Identity), maxIdentityStringBytes)
		}
		if len(p.Method) > maxMethodBytes {
			return fmt.Errorf("event: request_observed method is %d bytes over bound %d", len(p.Method), maxMethodBytes)
		}
	case RuleExecuted:
		if kind != KindRuleExecuted {
			return payloadMismatch(kind, p)
		}
		if len(p.RuleID) > maxRuleIDBytes {
			return fmt.Errorf("event: rule_executed rule ID is %d bytes over bound %d", len(p.RuleID), maxRuleIDBytes)
		}
		if p.Executions <= 0 {
			return fmt.Errorf("event: rule_executed executions must be positive, got %d", p.Executions)
		}
	case Warning:
		if kind != KindWarning {
			return payloadMismatch(kind, p)
		}
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: warning category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: warning message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case Error:
		if kind != KindError {
			return payloadMismatch(kind, p)
		}
		if len(p.Category) > maxLabelBytes {
			return fmt.Errorf("event: error category is %d bytes over bound %d", len(p.Category), maxLabelBytes)
		}
		if len(p.Message) > maxMessageBytes {
			return fmt.Errorf("event: error message is %d bytes over bound %d", len(p.Message), maxMessageBytes)
		}
	case Progress:
		if kind != KindProgress {
			return payloadMismatch(kind, p)
		}
		// Phase is a lifecycle/stage label ("running", "draining",
		// "import"); all current emitters pass short literals.
		if len(p.Phase) > maxStageNameBytes {
			return fmt.Errorf("event: progress phase is %d bytes over bound %d", len(p.Phase), maxStageNameBytes)
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
		if len(p.Phase) > maxStageNameBytes {
			return fmt.Errorf("event: phase_transition phase is %d bytes over bound %d", len(p.Phase), maxStageNameBytes)
		}
	case Shutdown:
		if kind != KindShutdown {
			return payloadMismatch(kind, p)
		}
		if len(p.Reason) > maxKindLabelBytes {
			return fmt.Errorf("event: shutdown reason is %d bytes over bound %d", len(p.Reason), maxKindLabelBytes)
		}
		if p.Reason != "graceful" && p.Reason != "forced" {
			return fmt.Errorf("event: shutdown carries invalid reason %q", p.Reason)
		}
	case RunMetadata:
		if kind != KindRunMetadata {
			return payloadMismatch(kind, p)
		}
		// Target is the declared target string; OutputDir is the report
		// output directory. Both fit comfortably within a PATH_MAX-sized
		// path.
		if len(p.Target) > maxMetadataBytes {
			return fmt.Errorf("event: run_metadata target is %d bytes over bound %d", len(p.Target), maxMetadataBytes)
		}
		if len(p.OutputDir) > maxMetadataBytes {
			return fmt.Errorf("event: run_metadata output dir is %d bytes over bound %d", len(p.OutputDir), maxMetadataBytes)
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
