package pipeline

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe Observer that appends every event
// it receives. Run emits synchronously in the caller's goroutine, so the
// recorded order is the emission order; the mutex keeps the recorder honest
// under -race if a future emitter ever calls it concurrently.
type recordingObserver struct {
	mu     sync.Mutex
	events []event.Event
}

func (o *recordingObserver) Observe(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *recordingObserver) snapshot() []event.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]event.Event, len(o.events))
	copy(out, o.events)
	return out
}

// kindNames flattens a recorded event stream to its kinds, for exact
// sequence assertions.
func kindNames(events []event.Event) []event.Kind {
	names := make([]event.Kind, len(events))
	for i, ev := range events {
		names[i] = ev.Kind
	}
	return names
}

// finishedPayload asserts ev is a stage_finished event and returns its
// payload.
func finishedPayload(t *testing.T, ev event.Event) event.StageFinished {
	t.Helper()
	pl, ok := ev.Payload.(event.StageFinished)
	if !ok {
		t.Fatalf("payload type = %T, want event.StageFinished", ev.Payload)
	}
	return pl
}

// startedPayload asserts ev is a stage_started event and returns its
// payload.
func startedPayload(t *testing.T, ev event.Event) event.StageStarted {
	t.Helper()
	pl, ok := ev.Payload.(event.StageStarted)
	if !ok {
		t.Fatalf("payload type = %T, want event.StageStarted", ev.Payload)
	}
	return pl
}

// TestRunStageEventsOrderAndPayloads proves the emission contract: exactly
// one stage_started before each stage entry and one stage_finished after
// its StageRecord is finalized, in stage order (started_i, finished_i,
// started_{i+1}), with the finished payload mirroring the recorded
// StageRecord field for field, Identity = stage name, Phase = "stage",
// default severity, the injected clock's timestamp, and Sequence 0 (the
// bus assigns sequence numbers at publish time).
func TestRunStageEventsOrderAndPayloads(t *testing.T) {
	clk := newFakeClock(testTime)
	obs := &recordingObserver{}
	stages := []Stage{
		&fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeFailed, ItemsProcessed: 2, ItemsFailed: 1}, errors.New("discover failed")
		}},
		recordStage(StageDNS, new([]StageName)),
		&fakeStage{name: StageHTTPProbe, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomePartial, Truncated: true, ItemsProcessed: 5}, nil
		}},
	}
	cfg := validConfig(t, StageDiscover, StageDNS, StageHTTPProbe)
	cfg.Observer = obs
	report, err := Run(context.Background(), cfg, nil, clk, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := obs.snapshot()
	wantKinds := []event.Kind{
		event.KindStageStarted, event.KindStageFinished, // discover
		event.KindStageStarted, event.KindStageFinished, // dns
		event.KindStageStarted, event.KindStageFinished, // httpprobe
	}
	if !reflect.DeepEqual(kindNames(events), wantKinds) {
		t.Fatalf("event kinds = %v, want %v", kindNames(events), wantKinds)
	}

	at := clk.Now()
	for i, ev := range events {
		if ev.Sequence != 0 {
			t.Errorf("events[%d].Sequence = %d, want 0 (the bus assigns on publish)", i, ev.Sequence)
		}
		if !ev.At.Equal(at) {
			t.Errorf("events[%d].At = %v, want %v (injected clock at emission)", i, ev.At, at)
		}
		if ev.Phase != "stage" {
			t.Errorf("events[%d].Phase = %q, want \"stage\"", i, ev.Phase)
		}
		if ev.Severity != event.SeverityInfo {
			t.Errorf("events[%d].Severity = %v, want the default info", i, ev.Severity)
		}
	}

	// started_i carries the stage name as Identity and payload Name;
	// finished_i mirrors the recorded StageRecord exactly.
	wantNames := []StageName{StageDiscover, StageDNS, StageHTTPProbe}
	for i, name := range wantNames {
		st := startedPayload(t, events[2*i])
		if st.Name != string(name) {
			t.Errorf("started[%d].Name = %q, want %q", i, st.Name, name)
		}
		if events[2*i].Identity != string(name) {
			t.Errorf("started[%d].Identity = %q, want %q", i, events[2*i].Identity, name)
		}

		fin := finishedPayload(t, events[2*i+1])
		sr := report.Stages[i]
		if fin.Name != string(sr.Name) {
			t.Errorf("finished[%d].Name = %q, want %q", i, fin.Name, sr.Name)
		}
		if fin.Outcome != string(sr.Outcome) {
			t.Errorf("finished[%d].Outcome = %q, want the recorded %q", i, fin.Outcome, sr.Outcome)
		}
		if fin.Truncated != sr.Truncated {
			t.Errorf("finished[%d].Truncated = %v, want the recorded %v", i, fin.Truncated, sr.Truncated)
		}
		if fin.ItemsProcessed != sr.ItemsProcessed {
			t.Errorf("finished[%d].ItemsProcessed = %d, want the recorded %d", i, fin.ItemsProcessed, sr.ItemsProcessed)
		}
		if fin.ItemsFailed != sr.ItemsFailed {
			t.Errorf("finished[%d].ItemsFailed = %d, want the recorded %d", i, fin.ItemsFailed, sr.ItemsFailed)
		}
		if fin.Duration != sr.Duration {
			t.Errorf("finished[%d].Duration = %s, want the recorded %s", i, fin.Duration, sr.Duration)
		}
		wantErr := ""
		if sr.Err != nil {
			wantErr = sr.Err.Error()
		}
		if fin.Err != wantErr {
			t.Errorf("finished[%d].Err = %q, want the recorded error text %q", i, fin.Err, wantErr)
		}
		if events[2*i+1].Identity != string(name) {
			t.Errorf("finished[%d].Identity = %q, want %q", i, events[2*i+1].Identity, name)
		}
	}
}

// TestRunStageEventsPreCancelled proves every never-invoked entry (the run
// context was already cancelled) still emits started + finished, with the
// finished payload carrying the recorded cancelled outcome and the context
// error's message.
func TestRunStageEventsPreCancelled(t *testing.T) {
	obs := &recordingObserver{}
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.Observer = obs
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Run(ctx, cfg, nil, newFakeClock(testTime), []Stage{
		recordStage(StageDiscover, new([]StageName)),
		recordStage(StageDNS, new([]StageName)),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := obs.snapshot()
	wantKinds := []event.Kind{
		event.KindStageStarted, event.KindStageFinished, // discover: never invoked
		event.KindStageStarted, event.KindStageFinished, // dns: never invoked
	}
	if !reflect.DeepEqual(kindNames(events), wantKinds) {
		t.Fatalf("event kinds = %v, want %v", kindNames(events), wantKinds)
	}
	for i, sr := range report.Stages {
		if sr.Outcome != OutcomeCancelled {
			t.Errorf("Stages[%d].Outcome = %q, want cancelled", i, sr.Outcome)
		}
		fin := finishedPayload(t, events[2*i+1])
		if fin.Outcome != string(OutcomeCancelled) {
			t.Errorf("finished[%d].Outcome = %q, want cancelled", i, fin.Outcome)
		}
		if fin.Err != context.Canceled.Error() {
			t.Errorf("finished[%d].Err = %q, want the context error message %q", i, fin.Err, context.Canceled.Error())
		}
		if fin.Duration != 0 || fin.ItemsProcessed != 0 || fin.ItemsFailed != 0 {
			t.Errorf("finished[%d] carries nonzero counters for a never-invoked stage: %+v", i, fin)
		}
	}
}

// TestRunStageEventsStageTimeout proves a stage cancelled by its own
// Timeout still emits finished with its recorded outcome, and the run
// continues with the next stage (existing semantics untouched).
func TestRunStageEventsStageTimeout(t *testing.T) {
	obs := &recordingObserver{}
	blocker := &fakeStage{
		name: StageDiscover,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			<-ctx.Done()
			return StageResult{Outcome: OutcomeCancelled}, nil
		},
	}
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.Observer = obs
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Timeout: 50 * time.Millisecond}}
	report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{blocker, recordStage(StageDNS, new([]StageName))})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := obs.snapshot()
	wantKinds := []event.Kind{
		event.KindStageStarted, event.KindStageFinished, // discover: timed out
		event.KindStageStarted, event.KindStageFinished, // dns: completed
	}
	if !reflect.DeepEqual(kindNames(events), wantKinds) {
		t.Fatalf("event kinds = %v, want %v", kindNames(events), wantKinds)
	}
	fin := finishedPayload(t, events[1])
	if fin.Outcome != string(OutcomeCancelled) || fin.Err != "" {
		t.Errorf("discover finished = %+v, want cancelled with no error text", fin)
	}
	if got := finishedPayload(t, events[3]); got.Outcome != string(OutcomeCompleted) {
		t.Errorf("dns finished outcome = %q, want completed (stage-local timeout, run continues)", got.Outcome)
	}
	if report.Stages[1].Outcome != OutcomeCompleted {
		t.Errorf("Stages[1].Outcome = %q, want completed", report.Stages[1].Outcome)
	}
}

// TestRunStageEventsPanickingObserver proves a hostile observer is
// contained: its panics never crash the run, dropped events are skipped,
// and later events still flow once the observer stops panicking.
func TestRunStageEventsPanickingObserver(t *testing.T) {
	obs := &panicThenRecordObserver{panicUntil: 2, inner: &recordingObserver{}}
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.Observer = obs
	var order []StageName
	report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{recordStage(StageDiscover, &order), recordStage(StageDNS, &order)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The run outcome is untouched by the hostile observer.
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", report.Outcome)
	}
	if !reflect.DeepEqual(order, []StageName{StageDiscover, StageDNS}) {
		t.Errorf("run order = %v, want both stages", order)
	}
	if report.ItemsProcessed != 2 {
		t.Errorf("ItemsProcessed = %d, want 2", report.ItemsProcessed)
	}

	// The discover pair was dropped (panicked); the dns pair flowed.
	events := obs.inner.snapshot()
	wantKinds := []event.Kind{event.KindStageStarted, event.KindStageFinished}
	if !reflect.DeepEqual(kindNames(events), wantKinds) {
		t.Fatalf("recorded kinds = %v, want %v (events after the panic must still flow)", kindNames(events), wantKinds)
	}
	if got := startedPayload(t, events[0]).Name; got != string(StageDNS) {
		t.Errorf("first recorded started name = %q, want %q", got, StageDNS)
	}
}

// panicThenRecordObserver panics on the first panicUntil events, then
// forwards to inner.
type panicThenRecordObserver struct {
	panicUntil int
	inner      *recordingObserver
}

func (o *panicThenRecordObserver) Observe(ev event.Event) {
	if o.panicUntil > 0 {
		o.panicUntil--
		panic("hostile observer")
	}
	o.inner.Observe(ev)
}

// TestRunStageEventsNilObserver proves a nil observer (the zero value) is
// zero behavior change: the report is identical with and without one.
func TestRunStageEventsNilObserver(t *testing.T) {
	stages := func() []Stage {
		var order []StageName
		return []Stage{recordStage(StageDiscover, &order), recordStage(StageDNS, &order)}
	}
	cfg := validConfig(t, StageDiscover, StageDNS)
	base, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("baseline Run: %v", err)
	}
	cfg.Observer = nil // explicit: the default zero value
	withNil, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("Run with nil observer: %v", err)
	}
	if !reflect.DeepEqual(base, withNil) {
		t.Errorf("report differs with a nil observer:\n%+v\n%+v", base, withNil)
	}
}

// TestRunStageEventsErrTruncated proves the finished payload's error text
// is bounded by the event package's message bound even when the recorded
// error message is longer: the payload stays valid for the bus.
func TestRunStageEventsErrTruncated(t *testing.T) {
	obs := &recordingObserver{}
	longErr := errors.New(strings.Repeat("e", 600))
	st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeFailed}, longErr
	}}
	cfg := validConfig(t, StageDiscover)
	cfg.Observer = obs
	report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{st})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	events := obs.snapshot()
	fin := finishedPayload(t, events[1])
	if fin.Err == longErr.Error() {
		t.Fatalf("Err = full %d-byte message, want bounded", len(fin.Err))
	}
	if len(fin.Err) > 512 {
		t.Fatalf("Err = %d bytes, over the event message bound 512", len(fin.Err))
	}
	if !strings.HasSuffix(fin.Err, "…") {
		t.Errorf("Err = %q, want the event truncation marker suffix", fin.Err)
	}
	if report.Stages[0].Err != longErr {
		t.Errorf("recorded Err lost: %v", report.Stages[0].Err)
	}
	// The bounded payload must validate under its kind (the bus would
	// reject an unbounded one).
	ev := event.New(event.KindStageFinished, events[1].At, fin).WithPhase("stage")
	if err := ev.Validate(); err != nil {
		t.Fatalf("finished event must validate after truncation: %v", err)
	}
}

// TestRunStageEventsUnresolvableEntry proves an entry whose provided stage
// could not be resolved (Name() panicked during resolution) still emits
// started + finished with the recorded failed outcome.
func TestRunStageEventsUnresolvableEntry(t *testing.T) {
	obs := &recordingObserver{}
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.Observer = obs
	report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{
		&panickyNameStage{run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted}, nil
		}},
		recordStage(StageDNS, new([]StageName)),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	events := obs.snapshot()
	wantKinds := []event.Kind{
		event.KindStageStarted, event.KindStageFinished, // discover: unresolvable, never invoked
		event.KindStageStarted, event.KindStageFinished, // dns: completed
	}
	if !reflect.DeepEqual(kindNames(events), wantKinds) {
		t.Fatalf("event kinds = %v, want %v", kindNames(events), wantKinds)
	}
	if report.Stages[0].Outcome != OutcomeFailed {
		t.Errorf("Stages[0].Outcome = %q, want failed", report.Stages[0].Outcome)
	}
	fin := finishedPayload(t, events[1])
	if fin.Outcome != string(OutcomeFailed) {
		t.Errorf("finished outcome = %q, want failed", fin.Outcome)
	}
	if fin.Err != report.Stages[0].Err.Error() {
		t.Errorf("finished Err = %q, want the recorded %q", fin.Err, report.Stages[0].Err.Error())
	}
	if got := startedPayload(t, events[0]).Name; got != string(StageDiscover) {
		t.Errorf("started name = %q, want %q", got, StageDiscover)
	}
}

// TestRunStageEventsNegativeCounters proves negative counters are a
// stage-contract violation handled like the other violations: the stage
// is recorded failed with a structured error, the counters are clamped to
// 0 (on every outcome path), and the emitted stage_finished event
// validates — the event layer rejects negative counts by design, so a
// record and its mirrored event must never carry them.
func TestRunStageEventsNegativeCounters(t *testing.T) {
	t.Run("negative counters alone are a contract violation", func(t *testing.T) {
		obs := &recordingObserver{}
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, ItemsProcessed: -3, ItemsFailed: -2}, nil
		}}
		cfg := validConfig(t, StageDiscover)
		cfg.Observer = obs
		report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		sr := report.Stages[0]
		if sr.Outcome != OutcomeFailed {
			t.Errorf("Stages[0].Outcome = %q, want failed (negative counters are a contract violation)", sr.Outcome)
		}
		if sr.Err == nil || !strings.Contains(sr.Err.Error(), "negative counters") {
			t.Errorf("Stages[0].Err = %v, want the negative-counter violation error", sr.Err)
		}
		if sr.ItemsProcessed != 0 || sr.ItemsFailed != 0 {
			t.Errorf("Stages[0] counters = %d/%d, want clamped to 0/0", sr.ItemsProcessed, sr.ItemsFailed)
		}
		if report.ItemsProcessed != 0 || report.ItemsFailed != 0 {
			t.Errorf("report counters = %d/%d, want 0/0 (sums of clamped counters)", report.ItemsProcessed, report.ItemsFailed)
		}
		fin := finishedPayload(t, obs.snapshot()[1])
		if fin.Outcome != string(OutcomeFailed) || fin.ItemsProcessed != 0 || fin.ItemsFailed != 0 {
			t.Errorf("finished payload = %+v, want failed with clamped 0/0", fin)
		}
		ev := event.New(event.KindStageFinished, newFakeClock(testTime).Now(), fin).WithPhase("stage")
		if err := ev.Validate(); err != nil {
			t.Fatalf("finished event must validate after the clamp: %v", err)
		}
	})

	t.Run("error-return path still clamps", func(t *testing.T) {
		// The error return already forces failed; the clamp must still
		// keep the record and its event valid (the invariant spans every
		// outcome path).
		obs := &recordingObserver{}
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCancelled, ItemsProcessed: -1}, errors.New("boom")
		}}
		cfg := validConfig(t, StageDiscover)
		cfg.Observer = obs
		report, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed || report.Stages[0].ItemsProcessed != 0 {
			t.Errorf("Stages[0] = outcome %q processed %d, want failed with clamped 0", report.Stages[0].Outcome, report.Stages[0].ItemsProcessed)
		}
		fin := finishedPayload(t, obs.snapshot()[1])
		ev := event.New(event.KindStageFinished, newFakeClock(testTime).Now(), fin).WithPhase("stage")
		if err := ev.Validate(); err != nil {
			t.Fatalf("finished event must validate on the error-return path: %v", err)
		}
	})
}

// TestStageFinishedVocabulariesDriftPin maps every pipeline.Outcome
// constant through the event payload: each constant's string value must be
// accepted by event.Validate for KindStageFinished. This pins the two
// vocabularies together (the Outcome constants in stage.go and the event
// package's stage_finished literals, which are deliberately kept as
// strings because internal/event cannot import internal/pipeline) — a
// drift in either direction fails here.
func TestStageFinishedVocabulariesDriftPin(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	for _, o := range []Outcome{OutcomeCompleted, OutcomePartial, OutcomeFailed, OutcomeCancelled, OutcomeIncomplete} {
		t.Run(string(o), func(t *testing.T) {
			ev := event.New(event.KindStageFinished, at,
				event.NewStageFinished("discover", string(o), false, 1, 0, time.Second, ""))
			if err := ev.Validate(); err != nil {
				t.Fatalf("outcome %q must validate through the event payload: %v", o, err)
			}
		})
	}
}

// TestRunStageEventsCrossRunDeterminism proves the emitted stream is a
// pure function of (cfg, clock, stages): two runs of the same inputs
// record identical event streams — kinds, order, timestamps, context
// fields, and payloads all DeepEqual — so a consumer observing a run
// replays the same events every time.
func TestRunStageEventsCrossRunDeterminism(t *testing.T) {
	cfg := validConfig(t, StageDiscover, StageDNS, StageHTTPProbe)
	stages := func() []Stage {
		return []Stage{
			&fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeFailed, ItemsProcessed: 2, ItemsFailed: 1}, errors.New("discover failed")
			}},
			recordStage(StageDNS, new([]StageName)),
			&fakeStage{name: StageHTTPProbe, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomePartial, Truncated: true, ItemsProcessed: 5}, nil
			}},
		}
	}
	clk := newFakeClock(testTime)
	run := func() []event.Event {
		obs := &recordingObserver{}
		cfg.Observer = obs
		if _, err := Run(context.Background(), cfg, nil, clk, stages()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return obs.snapshot()
	}
	first, second := run(), run()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("event streams differ across identical runs:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
