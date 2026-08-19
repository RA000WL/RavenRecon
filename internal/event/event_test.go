package event

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// validPayloadFor returns a payload that validates for the given kind.
func validPayloadFor(kind Kind) Payload {
	switch kind {
	case KindScanStarted:
		return ScanStarted{Concurrency: 4, QueueSize: 64, Timeout: 30 * time.Second, Rate: 1}
	case KindScanStopped:
		return ScanStopped{State: "completed"}
	case KindStageStarted:
		return StageStarted{Name: "discover"}
	case KindStageFinished:
		return StageFinished{Name: "discover", Outcome: "completed", ItemsProcessed: 1}
	case KindWorkerStarted:
		return WorkerStarted{Worker: 0}
	case KindWorkerStopped:
		return WorkerStopped{Worker: 0, State: WorkerCompleted}
	case KindTaskSubmitted:
		return TaskSubmitted{JobID: 1}
	case KindTaskStarted:
		return TaskStarted{JobID: 1, Worker: 0}
	case KindTaskRunning:
		return TaskRunning{JobID: 1, Worker: 0}
	case KindTaskCompleted:
		return TaskCompleted{TaskTerminal: TaskTerminal{JobID: 1, Worker: 0}, Result: "ok"}
	case KindTaskCancelled:
		return TaskCancelled{TaskTerminal: TaskTerminal{JobID: 1, Worker: 0, Category: "cancellation"}}
	case KindTaskFailed:
		return TaskFailed{TaskTerminal: TaskTerminal{JobID: 1, Worker: 0, Category: "unknown", Message: "boom"}}
	case KindTaskTimedOut:
		return TaskTimedOut{TaskTerminal: TaskTerminal{JobID: 1, Worker: 0, Category: "timeout"}}
	case KindCacheHit, KindCacheMiss:
		return CacheAccess{Key: strings.Repeat("a", 64), State: "hit", Hit: kind == KindCacheHit}
	case KindAssetDiscovered:
		return AssetDiscovered{Identity: "host:example.com", Kind: "host"}
	case KindRelationshipCreated:
		return RelationshipCreated{From: "host:example.com", To: "ip:192.0.2.1", Kind: "host_to_ip"}
	case KindEvidenceCreated:
		return EvidenceCreated{Identity: "evidence:…", Source: "host:example.com", Method: "header"}
	case KindFindingCreated:
		return FindingCreated{Identity: "finding:r@s", RuleID: "r", Subject: "s", Priority: "high", Category: "xss", Confidence: 0.5}
	case KindRecommendationCreated:
		return RecommendationCreated{Identity: "url:https://example.com", Text: "investigate", Level: "high", Weight: 0.5}
	case KindRequestObserved:
		return RequestObserved{Identity: "url:https://example.com/", Method: "GET"}
	case KindRuleExecuted:
		return RuleExecuted{RuleID: "r", Executions: 1}
	case KindWarning:
		return Warning{Category: "tool", Message: "warn"}
	case KindError:
		return Error{Category: "timeout", Message: "err"}
	case KindProgress:
		return Progress{Phase: "dns", Completed: 1, Total: 2, TotalKnown: true}
	case KindPhaseTransition:
		return PhaseTransition{Phase: "running"}
	case KindShutdown:
		return Shutdown{Reason: "graceful", Dropped: 0}
	case KindRunMetadata:
		return RunMetadata{Target: "example.com", OutputDir: "/tmp/out"}
	case KindSummaryReady:
		return SummaryReady{}
	default:
		return nil
	}
}

// TestValidateAcceptsEveryKind builds one valid event per kind and verifies
// Validate accepts it.
func TestValidateAcceptsEveryKind(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	for _, kind := range []Kind{
		KindScanStarted, KindScanStopped, KindStageStarted, KindStageFinished,
		KindWorkerStarted, KindWorkerStopped,
		KindTaskSubmitted, KindTaskStarted, KindTaskRunning, KindTaskCompleted,
		KindTaskCancelled, KindTaskFailed, KindTaskTimedOut,
		KindCacheHit, KindCacheMiss, KindAssetDiscovered,
		KindRelationshipCreated, KindEvidenceCreated, KindFindingCreated,
		KindRecommendationCreated, KindRequestObserved, KindRuleExecuted,
		KindWarning, KindError, KindProgress, KindPhaseTransition,
		KindShutdown, KindRunMetadata, KindSummaryReady,
	} {
		if !kind.Valid() {
			t.Fatalf("kind %s must be Valid", kind)
		}
		ev := New(kind, at, validPayloadFor(kind))
		if err := ev.Validate(); err != nil {
			t.Fatalf("kind %s: Validate: %v", kind, err)
		}
	}
}

// TestValidateRejectsCoreContractViolations pins the base contract: unknown
// kinds, zero timestamps, invalid severities, and oversized labels are
// rejected no matter the payload.
func TestValidateRejectsCoreContractViolations(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	oversized := strings.Repeat("x", maxLabelBytes+1)
	cases := []struct {
		name string
		ev   Event
	}{
		{"unknown kind", Event{Kind: "bogus", At: at, Payload: TaskSubmitted{}}},
		{"zero timestamp", New(KindTaskSubmitted, time.Time{}, TaskSubmitted{})},
		{"invalid severity", New(KindTaskSubmitted, at, TaskSubmitted{}).WithSeverity(Severity(99))},
		// Oversized context fields must be rejected even when hand-built
		// (the With* constructors bound them, so only a struct literal can
		// smuggle them).
		{"oversized phase", Event{Kind: KindTaskSubmitted, At: at, Payload: TaskSubmitted{}, Phase: oversized}},
		{"oversized category", Event{Kind: KindTaskSubmitted, At: at, Payload: TaskSubmitted{}, Category: oversized}},
		{"oversized identity", Event{Kind: KindTaskSubmitted, At: at, Payload: TaskSubmitted{}, Identity: oversized}},
		{"oversized value", Event{Kind: KindTaskSubmitted, At: at, Payload: TaskSubmitted{}, Value: oversized}},
		{"nil payload required", New(KindTaskSubmitted, at, nil)},
		{"stage_started nil payload", New(KindStageStarted, at, nil)},
		{"stage_finished nil payload", New(KindStageFinished, at, nil)},
	}
	for _, tc := range cases {
		if err := tc.ev.Validate(); err == nil {
			t.Fatalf("%s: Validate succeeded, want error", tc.name)
		}
	}
}

// TestValidateRejectsPayloadMismatches verifies every kind rejects a payload
// of the wrong type. SummaryReady is the canonical foreign payload: it is
// valid only for KindSummaryReady, so it is wrong for every kind in the
// list; KindSummaryReady itself is then probed with a different foreign
// payload.
func TestValidateRejectsPayloadMismatches(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	foreign := func() Payload { return SummaryReady{} }
	for _, kind := range []Kind{
		KindScanStarted, KindScanStopped, KindStageStarted, KindStageFinished,
		KindWorkerStarted, KindWorkerStopped,
		KindTaskSubmitted, KindTaskStarted, KindTaskRunning, KindTaskCompleted,
		KindTaskCancelled, KindTaskFailed, KindTaskTimedOut,
		KindCacheHit, KindCacheMiss, KindAssetDiscovered,
		KindRelationshipCreated, KindEvidenceCreated, KindFindingCreated,
		KindRecommendationCreated, KindRequestObserved, KindRuleExecuted,
		KindWarning, KindError, KindProgress, KindPhaseTransition,
		KindShutdown, KindRunMetadata,
	} {
		ev := New(kind, at, foreign())
		if err := ev.Validate(); err == nil {
			t.Fatalf("kind %s with mismatched payload: Validate succeeded, want error", kind)
		}
	}
	// SummaryReady is the optional-payload kind: a wrong non-nil payload is
	// rejected, nil is accepted.
	if err := New(KindSummaryReady, at, TaskSubmitted{JobID: 1}).Validate(); err == nil {
		t.Fatal("summary_ready with mismatched payload: Validate succeeded, want error")
	}
	if err := New(KindSummaryReady, at, nil).Validate(); err != nil {
		t.Fatalf("summary_ready with nil payload: Validate: %v", err)
	}
}

// TestValidateAcceptsEveryStageOutcome pins the acceptance side of the
// stage_finished outcome vocabulary: every one of the five fixed AGENTS
// §0.6 values (completed/partial/failed/cancelled/incomplete) validates.
// The rejection tests above cover the other side (empty, unknown, and
// structurally invalid outcomes); together they freeze the vocabulary so
// a stage emitting any of the five can never be dropped by the bus.
func TestValidateAcceptsEveryStageOutcome(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	for _, outcome := range []string{"completed", "partial", "failed", "cancelled", "incomplete"} {
		t.Run(outcome, func(t *testing.T) {
			ev := New(KindStageFinished, at, NewStageFinished("discover", outcome, false, 1, 0, time.Second, ""))
			if err := ev.Validate(); err != nil {
				t.Fatalf("stage_finished outcome %q must validate: %v", outcome, err)
			}
		})
	}
}

// TestValidateRejectsPayloadFieldRules pins the per-payload field contracts.
func TestValidateRejectsPayloadFieldRules(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	big := strings.Repeat("m", maxMessageBytes+1)
	term := func(msg string) TaskTerminal {
		return TaskTerminal{JobID: 1, Worker: 0, Message: msg}
	}
	cases := []struct {
		name string
		ev   Event
	}{
		{"scan_stopped bad state", New(KindScanStopped, at, ScanStopped{State: "partial"})},
		{"stage_started empty name", New(KindStageStarted, at, StageStarted{Name: ""})},
		{"stage_finished empty name", New(KindStageFinished, at, StageFinished{Name: "", Outcome: "completed"})},
		{"stage_finished invalid outcome", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: "skipped"})},
		{"stage_finished empty outcome", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: ""})},
		{"stage_finished negative processed", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: "completed", ItemsProcessed: -1})},
		{"stage_finished negative failed", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: "completed", ItemsFailed: -1})},
		{"stage_finished negative duration", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: "completed", Duration: -time.Second})},
		{"stage_finished oversized err", New(KindStageFinished, at, StageFinished{Name: "discover", Outcome: "failed", Err: big})},
		{"worker_stopped bad state", New(KindWorkerStopped, at, WorkerStopped{Worker: 0, State: WorkerState("bogus")})},
		{"task_completed oversized message", New(KindTaskCompleted, at, TaskCompleted{TaskTerminal: term(big)})},
		{"task_cancelled oversized message", New(KindTaskCancelled, at, TaskCancelled{TaskTerminal: term(big)})},
		{"task_failed oversized message", New(KindTaskFailed, at, TaskFailed{TaskTerminal: term(big)})},
		{"task_timed_out oversized message", New(KindTaskTimedOut, at, TaskTimedOut{TaskTerminal: term(big)})},
		{"cache hit contradiction", New(KindCacheHit, at, CacheAccess{Key: strings.Repeat("a", 64), State: "hit", Hit: false})},
		{"cache miss contradiction", New(KindCacheMiss, at, CacheAccess{Key: strings.Repeat("a", 64), State: "miss", Hit: true})},
		{"asset empty identity", New(KindAssetDiscovered, at, AssetDiscovered{Identity: "", Kind: "host"})},
		{"asset confidence high", New(KindAssetDiscovered, at, AssetDiscovered{Identity: "host:example.com", Kind: "host", Confidence: 1.5})},
		{"asset confidence low", New(KindAssetDiscovered, at, AssetDiscovered{Identity: "host:example.com", Kind: "host", Confidence: -0.1})},
		{"finding confidence high", New(KindFindingCreated, at, FindingCreated{Identity: "finding:r@s", RuleID: "r", Subject: "s", Confidence: 2})},
		{"recommendation weight high", New(KindRecommendationCreated, at, RecommendationCreated{Identity: "url:https://example.com", Weight: 1.1})},
		{"rule_executed zero executions", New(KindRuleExecuted, at, RuleExecuted{RuleID: "r", Executions: 0})},
		{"warning oversized message", New(KindWarning, at, Warning{Message: big})},
		{"error oversized message", New(KindError, at, Error{Message: big})},
		{"progress negative completed", New(KindProgress, at, Progress{Completed: -1, Total: 1})},
		{"progress negative total", New(KindProgress, at, Progress{Completed: 0, Total: -1})},
		{"phase_transition empty", New(KindPhaseTransition, at, PhaseTransition{Phase: ""})},
		{"shutdown bad reason", New(KindShutdown, at, Shutdown{Reason: "abrupt"})},
	}
	for _, tc := range cases {
		if err := tc.ev.Validate(); err == nil {
			t.Fatalf("%s: Validate succeeded, want error", tc.name)
		}
	}
}

// TestWithMethodsTruncate verifies the With* constructors bound labels
// rune-safe with the explicit marker.
func TestWithMethodsTruncate(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ev := New(KindTaskSubmitted, at, TaskSubmitted{})
	// ASCII overflow.
	ev = ev.
		WithPhase(strings.Repeat("p", maxLabelBytes+50)).
		WithCategory(strings.Repeat("c", maxLabelBytes+50)).
		WithIdentity(strings.Repeat("i", maxLabelBytes+50)).
		WithValue(strings.Repeat("v", maxLabelBytes+50))
	for name, v := range map[string]string{
		"phase": ev.Phase, "category": ev.Category, "identity": ev.Identity, "value": ev.Value,
	} {
		if len(v) > maxLabelBytes {
			t.Fatalf("%s truncated to %d bytes, over bound %d", name, len(v), maxLabelBytes)
		}
		if !strings.HasSuffix(v, messageTruncationMarker) {
			t.Fatalf("%s must end with the truncation marker", name)
		}
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("truncated event must validate: %v", err)
	}
	// Rune-safe truncation: a multi-byte rune torn at the bound must not
	// leave a partial sequence behind the marker.
	runes := strings.Repeat("€", maxLabelBytes) // 3 bytes each
	trunc := truncateLabel(runes)
	if !strings.HasSuffix(trunc, messageTruncationMarker) {
		t.Fatal("rune-heavy label must still be marked")
	}
	if strings.Contains(trunc[:len(trunc)-len(messageTruncationMarker)], "\uFFFD") {
		t.Fatal("truncation produced a replacement rune (torn UTF-8)")
	}
	// Under-bound strings pass through untouched.
	if got := truncateLabel("short"); got != "short" {
		t.Fatalf("short label altered: %q", got)
	}
}

// TestPayloadConstructorsBound verifies the bounded payload constructors
// truncate message and category fields with the marker.
func TestPayloadConstructorsBound(t *testing.T) {
	big := strings.Repeat("m", maxMessageBytes+50)
	w := NewWarning("cat", big)
	if len(w.Message) > maxMessageBytes || !strings.HasSuffix(w.Message, messageTruncationMarker) {
		t.Fatalf("NewWarning message not bounded: %d bytes", len(w.Message))
	}
	e := NewError("cat", big)
	if len(e.Message) > maxMessageBytes || !strings.HasSuffix(e.Message, messageTruncationMarker) {
		t.Fatalf("NewError message not bounded: %d bytes", len(e.Message))
	}
	term := NewTaskTerminal(1, 0, time.Time{}, strings.Repeat("c", maxLabelBytes+10), big)
	if len(term.Message) > maxMessageBytes || !strings.HasSuffix(term.Message, messageTruncationMarker) {
		t.Fatalf("NewTaskTerminal message not bounded: %d bytes", len(term.Message))
	}
	if len(term.Category) > maxLabelBytes || !strings.HasSuffix(term.Category, messageTruncationMarker) {
		t.Fatalf("NewTaskTerminal category not bounded: %d bytes", len(term.Category))
	}
	fin := NewStageFinished("discover", "failed", true, 1, 1, time.Second, big)
	if len(fin.Err) > maxMessageBytes || !strings.HasSuffix(fin.Err, messageTruncationMarker) {
		t.Fatalf("NewStageFinished err not bounded: %d bytes", len(fin.Err))
	}
	if got := NewStageFinished("discover", "completed", false, 0, 0, 0, "").Err; got != "" {
		t.Fatalf("NewStageFinished empty err altered: %q", got)
	}
	// Constructed payloads validate under their kinds.
	at := time.Unix(1_700_000_000, 0)
	for _, ev := range []Event{
		New(KindWarning, at, w),
		New(KindError, at, e),
		New(KindTaskFailed, at, NewTaskFailed(term)),
		New(KindTaskCancelled, at, NewTaskCancelled(term)),
		New(KindTaskTimedOut, at, NewTaskTimedOut(term)),
		New(KindTaskCompleted, at, NewTaskCompleted(term, "result")),
		New(KindStageStarted, at, StageStarted{Name: "discover"}),
		New(KindStageFinished, at, NewStageFinished("discover", "completed", false, 1, 0, time.Second, "")),
	} {
		if err := ev.Validate(); err != nil {
			t.Fatalf("constructed event %s: Validate: %v", ev.Kind, err)
		}
	}
}

// TestStringDeterministic pins the standardized text form.
func TestStringDeterministic(t *testing.T) {
	at := time.Unix(1_700_000_000, 123_456_789)
	ev := New(KindTaskFailed, at, NewTaskFailed(NewTaskTerminal(42, 3, at, "unknown", "boom"))).
		WithSeverity(SeverityError).
		WithPhase("dns").
		WithCategory("timeout").
		WithIdentity("host:example.com").
		WithValue("A record")
	want := fmt.Sprintf(
		"task_failed seq=0 at=%q severity=error phase=\"dns\" category=\"timeout\" identity=\"host:example.com\" value=\"A record\" payload(event.TaskFailed)",
		at.Format(time.RFC3339Nano),
	)
	if got := ev.String(); got != want {
		t.Fatalf("String:\n got %s\nwant %s", got, want)
	}
	// Reformatting the same event yields the identical string.
	if ev.String() != ev.String() {
		t.Fatal("String must be deterministic")
	}
}

// TestKindSeverityWorkerStateVocabularies pins the vocabulary strings.
func TestKindSeverityWorkerStateVocabularies(t *testing.T) {
	if KindTaskSubmitted.String() != "task_submitted" {
		t.Fatalf("kind string: %s", KindTaskSubmitted)
	}
	if SeverityInfo.String() != "info" || SeverityWarning.String() != "warning" || SeverityError.String() != "error" {
		t.Fatal("severity strings drifted")
	}
	if !SeverityInfo.Valid() || !SeverityWarning.Valid() || !SeverityError.Valid() {
		t.Fatal("severity values must be valid")
	}
	if Severity(7).Valid() {
		t.Fatal("unknown severity must be invalid")
	}
	if WorkerState("running").String() != "running" || !WorkerState("completed").Valid() {
		t.Fatal("worker state vocabulary drifted")
	}
	if WorkerState("bogus").Valid() {
		t.Fatal("unknown worker state must be invalid")
	}
	if !KindWarning.Valid() || Kind("bogus").Valid() {
		t.Fatal("kind validity drifted")
	}
}
