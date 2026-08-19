package pipeline

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testTime is the fixed start instant for the deterministic fake clock.
var testTime = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// fakeClock is a deterministic runtime.Clock: time only moves when the
// test advances it, and After timers fire as soon as the advanced time
// reaches their target. Tests never sleep.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[chan time.Time]time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t, timers: make(map[chan time.Time]time.Time)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	f.mu.Lock()
	target := f.now.Add(d)
	immediate := !target.After(f.now)
	if !immediate {
		f.timers[ch] = target
	}
	f.mu.Unlock()
	if immediate {
		ch <- f.now
	}
	return ch
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	var fired []chan time.Time
	for ch, target := range f.timers {
		if !target.After(f.now) {
			fired = append(fired, ch)
			delete(f.timers, ch)
		}
	}
	f.mu.Unlock()
	for _, ch := range fired {
		select {
		case ch <- f.now:
		default:
		}
	}
}

// fakeStage is a Stage whose Run behavior is a plain function.
type fakeStage struct {
	name StageName
	run  func(ctx context.Context, in StageInput) (StageResult, error)
}

func (s *fakeStage) Name() StageName { return s.name }

func (s *fakeStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	return s.run(ctx, in)
}

// recordStage returns a stage that appends its name to order when run and
// completes with one item processed.
func recordStage(name StageName, order *[]StageName) *fakeStage {
	return &fakeStage{
		name: name,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			*order = append(*order, name)
			return StageResult{Outcome: OutcomeCompleted, ItemsProcessed: 1}, nil
		},
	}
}

// panickyNameStage is a Stage whose Name() always panics, for
// panic-isolation tests.
type panickyNameStage struct {
	run func(ctx context.Context, in StageInput) (StageResult, error)
}

func (s *panickyNameStage) Name() StageName { panic("name bug") }

func (s *panickyNameStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	return s.run(ctx, in)
}

// flakyNameStage is a Stage whose Name() succeeds once (resolution) and
// panics on the second call (the runStage recover handler's name lookup).
type flakyNameStage struct {
	nameCalls int
	run       func(ctx context.Context, in StageInput) (StageResult, error)
}

func (s *flakyNameStage) Name() StageName {
	s.nameCalls++
	if s.nameCalls == 2 {
		panic("name bug on second call")
	}
	return StageDiscover
}

func (s *flakyNameStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	return s.run(ctx, in)
}

func mustDomain(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

func mustHost(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// validConfig returns a minimal valid ScanConfig with the given ordered
// stage selection.
func validConfig(t *testing.T, stages ...StageName) ScanConfig {
	t.Helper()
	return ScanConfig{Target: mustDomain(t, "example.com"), Stages: stages}
}

// run executes Run with a background context, a nil cache (caching
// disabled), and the deterministic fake clock.
func run(t *testing.T, cfg ScanConfig, stages []Stage) (RunReport, error) {
	t.Helper()
	return Run(context.Background(), cfg, nil, newFakeClock(testTime), stages)
}

func TestRunEmptyStagesCompletes(t *testing.T) {
	clk := newFakeClock(testTime)
	report, err := Run(context.Background(), validConfig(t), nil, clk, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want %q", report.Outcome, OutcomeCompleted)
	}
	if len(report.Stages) != 0 {
		t.Errorf("Stages = %d entries, want 0", len(report.Stages))
	}
	want := clk.Now()
	if !report.StartAt.Equal(want) || !report.EndAt.Equal(want) {
		t.Errorf("StartAt/EndAt = %v/%v, want %v", report.StartAt, report.EndAt, want)
	}
	if report.ItemsProcessed != 0 || report.ItemsFailed != 0 || report.Truncated {
		t.Errorf("counts/truncated = %d/%d/%v, want 0/0/false", report.ItemsProcessed, report.ItemsFailed, report.Truncated)
	}
}

func TestRunStagesInOrder(t *testing.T) {
	var order []StageName
	cfg := validConfig(t, StageDiscover, StageDNS, StageHTTPProbe)
	stages := []Stage{
		recordStage(StageDiscover, &order),
		recordStage(StageDNS, &order),
		recordStage(StageHTTPProbe, &order),
	}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantOrder := []StageName{StageDiscover, StageDNS, StageHTTPProbe}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("run order = %v, want %v", order, wantOrder)
	}
	for i, want := range wantOrder {
		if report.Stages[i].Name != want {
			t.Errorf("Stages[%d].Name = %q, want %q", i, report.Stages[i].Name, want)
		}
		if report.Stages[i].Outcome != OutcomeCompleted {
			t.Errorf("Stages[%d].Outcome = %q, want completed", i, report.Stages[i].Outcome)
		}
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", report.Outcome)
	}
	if report.ItemsProcessed != 3 || report.ItemsFailed != 0 {
		t.Errorf("counts = %d/%d, want 3/0", report.ItemsProcessed, report.ItemsFailed)
	}
}

func TestRunExtraProvidedStageSkipped(t *testing.T) {
	var order []StageName
	cfg := validConfig(t, StageDNS)
	stages := []Stage{
		recordStage(StageDiscover, &order), // not in the selection: skipped
		recordStage(StageDNS, &order),
	}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(order, []StageName{StageDNS}) {
		t.Errorf("run order = %v, want [dns]", order)
	}
	if len(report.Stages) != 1 || report.Stages[0].Name != StageDNS {
		t.Errorf("Stages = %+v, want exactly [dns]", report.Stages)
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", report.Outcome)
	}
}

func TestRunFailContinue(t *testing.T) {
	var order []StageName
	failing := &fakeStage{
		name: StageDiscover,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			order = append(order, StageDiscover)
			return StageResult{Outcome: OutcomeFailed, ItemsProcessed: 2, ItemsFailed: 1, Err: errors.New("discover failed")}, nil
		},
	}
	cfg := validConfig(t, StageDiscover, StageDNS)
	stages := []Stage{failing, recordStage(StageDNS, &order)}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stages[0].Outcome != OutcomeFailed {
		t.Errorf("Stages[0].Outcome = %q, want failed", report.Stages[0].Outcome)
	}
	if report.Stages[0].Err == nil || report.Stages[0].Err.Error() != "discover failed" {
		t.Errorf("Stages[0].Err = %v, want the stage error", report.Stages[0].Err)
	}
	if report.Stages[1].Outcome != OutcomeCompleted {
		t.Errorf("Stages[1].Outcome = %q, want completed (fail-continue)", report.Stages[1].Outcome)
	}
	if !reflect.DeepEqual(order, []StageName{StageDiscover, StageDNS}) {
		t.Errorf("run order = %v, want both stages run", order)
	}
	if report.Outcome != OutcomePartial {
		t.Errorf("Outcome = %q, want partial", report.Outcome)
	}
	if report.ItemsProcessed != 3 || report.ItemsFailed != 1 {
		t.Errorf("counts = %d/%d, want 3/1", report.ItemsProcessed, report.ItemsFailed)
	}
}

func TestRunAllFailed(t *testing.T) {
	fail := func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeFailed, Err: errors.New("boom")}, nil
	}
	cfg := validConfig(t, StageDiscover, StageDNS)
	stages := []Stage{
		&fakeStage{name: StageDiscover, run: fail},
		&fakeStage{name: StageDNS, run: fail},
	}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Outcome != OutcomeFailed {
		t.Errorf("Outcome = %q, want failed", report.Outcome)
	}
}

func TestRunPartialWithCompleted(t *testing.T) {
	cfg := validConfig(t, StageDiscover, StageDNS)
	stages := []Stage{
		&fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomePartial, ItemsProcessed: 5}, nil
		}},
		recordStage(StageDNS, new([]StageName)),
	}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Outcome != OutcomePartial {
		t.Errorf("Outcome = %q, want partial", report.Outcome)
	}
}

func TestRunCancellation(t *testing.T) {
	t.Run("pre-cancelled context", func(t *testing.T) {
		var order []StageName
		cfg := validConfig(t, StageDiscover, StageDNS)
		stages := []Stage{recordStage(StageDiscover, &order), recordStage(StageDNS, &order)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report, err := Run(ctx, cfg, nil, newFakeClock(testTime), stages)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(order) != 0 {
			t.Errorf("stages ran despite cancelled context: %v", order)
		}
		for i, sr := range report.Stages {
			if sr.Outcome != OutcomeCancelled {
				t.Errorf("Stages[%d].Outcome = %q, want cancelled", i, sr.Outcome)
			}
			if !errors.Is(sr.Err, context.Canceled) {
				t.Errorf("Stages[%d].Err = %v, want context.Canceled", i, sr.Err)
			}
		}
		if report.Outcome != OutcomeCancelled {
			t.Errorf("Outcome = %q, want cancelled", report.Outcome)
		}
	})

	t.Run("cancelled mid-run", func(t *testing.T) {
		started := make(chan struct{})
		blocker := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				close(started)
				<-ctx.Done() // blocks on the context — no sleeps
				return StageResult{Outcome: OutcomeCancelled}, nil
			},
		}
		var order []StageName
		cfg := validConfig(t, StageDiscover, StageDNS)
		stages := []Stage{blocker, recordStage(StageDNS, &order)}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; cancel() }()
		report, err := Run(ctx, cfg, nil, newFakeClock(testTime), stages)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeCancelled {
			t.Errorf("Stages[0].Outcome = %q, want cancelled", report.Stages[0].Outcome)
		}
		if report.Stages[1].Outcome != OutcomeCancelled {
			t.Errorf("Stages[1].Outcome = %q, want cancelled (never ran)", report.Stages[1].Outcome)
		}
		if len(order) != 0 {
			t.Errorf("dns ran after cancellation: %v", order)
		}
		if report.Outcome != OutcomeCancelled {
			t.Errorf("Outcome = %q, want cancelled", report.Outcome)
		}
	})
}

func TestRunStageTimeout(t *testing.T) {
	blocker := &fakeStage{
		name: StageDiscover,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			<-ctx.Done()
			return StageResult{Outcome: OutcomeCancelled}, nil
		},
	}
	var order []StageName
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Timeout: 50 * time.Millisecond}}
	stages := []Stage{blocker, recordStage(StageDNS, &order)}
	report, err := run(t, cfg, stages)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stages[0].Outcome != OutcomeCancelled {
		t.Errorf("Stages[0].Outcome = %q, want cancelled (stage deadline elapsed)", report.Stages[0].Outcome)
	}
	if report.Stages[1].Outcome != OutcomeCompleted {
		t.Errorf("Stages[1].Outcome = %q, want completed (stage-local timeout, run continues)", report.Stages[1].Outcome)
	}
	if !reflect.DeepEqual(order, []StageName{StageDNS}) {
		t.Errorf("run order = %v, want [dns]", order)
	}
	if report.Outcome != OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", report.Outcome)
	}
}

func TestRunTruncationDiscipline(t *testing.T) {
	t.Run("completed+truncated without flags downgraded to incomplete", func(t *testing.T) {
		trunc := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeCompleted, Truncated: true}, nil
			},
		}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{trunc})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeIncomplete {
			t.Errorf("Stages[0].Outcome = %q, want incomplete (downgraded)", report.Stages[0].Outcome)
		}
		if !report.Stages[0].Truncated {
			t.Error("Truncated must propagate")
		}
		if report.Outcome != OutcomeIncomplete {
			t.Errorf("Outcome = %q, want incomplete", report.Outcome)
		}
	})

	t.Run("carve-out: sticky flags preserve completed", func(t *testing.T) {
		trunc := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{
					Outcome:     OutcomeCompleted,
					Truncated:   true,
					StickyFlags: map[string]bool{"corpus_capped": true},
				}, nil
			},
		}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{trunc})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeCompleted {
			t.Errorf("Stages[0].Outcome = %q, want completed (documented carve-out)", report.Stages[0].Outcome)
		}
		if !report.Stages[0].StickyFlags["corpus_capped"] {
			t.Errorf("StickyFlags = %v, want corpus_capped", report.Stages[0].StickyFlags)
		}
		if !report.Truncated {
			t.Error("Truncated must propagate")
		}
		if report.Outcome != OutcomeCompleted {
			t.Errorf("Outcome = %q, want completed", report.Outcome)
		}
	})

	t.Run("incomplete with truncation stays incomplete", func(t *testing.T) {
		trunc := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeIncomplete, Truncated: true, StickyFlags: map[string]bool{"corpus_capped": true}}, nil
			},
		}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{trunc})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeIncomplete {
			t.Errorf("Stages[0].Outcome = %q, want incomplete", report.Stages[0].Outcome)
		}
		if report.Outcome != OutcomeIncomplete {
			t.Errorf("Outcome = %q, want incomplete", report.Outcome)
		}
	})
}

func TestRunStageContractViolations(t *testing.T) {
	t.Run("empty outcome recorded as failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{}, nil
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !strings.Contains(report.Stages[0].Err.Error(), "invalid outcome") {
			t.Errorf("Err = %v, want contract-violation error", report.Stages[0].Err)
		}
		if report.Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Outcome)
		}
	})

	t.Run("error return forces failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted}, errors.New("stage crashed")
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || report.Stages[0].Err.Error() != "stage crashed" {
			t.Errorf("Err = %v, want the returned error", report.Stages[0].Err)
		}
	})

	t.Run("panic isolated as failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			panic("stage bug")
		}}
		var order []StageName
		cfg := validConfig(t, StageDiscover, StageDNS)
		stages := []Stage{st, recordStage(StageDNS, &order)}
		report, err := run(t, cfg, stages)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !strings.Contains(report.Stages[0].Err.Error(), "panicked") {
			t.Errorf("Err = %v, want panic error", report.Stages[0].Err)
		}
		if report.Stages[1].Outcome != OutcomeCompleted {
			t.Errorf("Stages[1].Outcome = %q, want completed (fail-continue after panic)", report.Stages[1].Outcome)
		}
		if report.Outcome != OutcomePartial {
			t.Errorf("Outcome = %q, want partial", report.Outcome)
		}
	})

	t.Run("cancelled with unrelated error recorded as failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCancelled}, errors.New("not a context error")
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed (only context errors preserve cancelled)", report.Stages[0].Outcome)
		}
		if report.Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Outcome)
		}
	})

	t.Run("failed outcome with returned context error stays failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeFailed}, context.DeadlineExceeded
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !errors.Is(report.Stages[0].Err, context.DeadlineExceeded) {
			t.Errorf("Err = %v, want the deadline error preserved", report.Stages[0].Err)
		}
		if report.Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed (a context error only preserves cancelled when the stage claimed cancelled)", report.Outcome)
		}
	})

	t.Run("failed outcome with attached context error stays failed", func(t *testing.T) {
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeFailed, Err: context.Canceled}, nil
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !errors.Is(report.Stages[0].Err, context.Canceled) {
			t.Errorf("Err = %v, want the context error preserved", report.Stages[0].Err)
		}
		if report.Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Outcome)
		}
	})
}

func TestRunResolutionErrors(t *testing.T) {
	t.Run("selected stage not provided", func(t *testing.T) {
		var order []StageName
		_, err := run(t, validConfig(t, StageDiscover), []Stage{recordStage(StageDNS, &order)})
		if err == nil || !strings.Contains(err.Error(), "no matching stage provided") {
			t.Fatalf("Run error = %v, want missing-stage error", err)
		}
		if len(order) != 0 {
			t.Errorf("stages ran despite resolution error: %v", order)
		}
	})

	t.Run("duplicate provided stage name", func(t *testing.T) {
		var order []StageName
		_, err := run(t, validConfig(t, StageDiscover), []Stage{
			recordStage(StageDiscover, &order),
			recordStage(StageDiscover, &order),
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate stage") {
			t.Fatalf("Run error = %v, want duplicate-stage error", err)
		}
	})

	t.Run("nil provided stage", func(t *testing.T) {
		_, err := run(t, validConfig(t, StageDiscover), []Stage{nil})
		if err == nil || !strings.Contains(err.Error(), "nil stage") {
			t.Fatalf("Run error = %v, want nil-stage error", err)
		}
	})
}

func TestRunCancelledWithCtxErrorStaysCancelled(t *testing.T) {
	t.Run("deadline exceeded after stage timeout", func(t *testing.T) {
		st := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				<-ctx.Done()
				return StageResult{Outcome: OutcomeCancelled}, ctx.Err()
			},
		}
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Timeout: 50 * time.Millisecond}}
		report, err := run(t, cfg, []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeCancelled {
			t.Errorf("Stages[0].Outcome = %q, want cancelled (not failed)", report.Stages[0].Outcome)
		}
		if !errors.Is(report.Stages[0].Err, context.DeadlineExceeded) {
			t.Errorf("Stages[0].Err = %v, want context.DeadlineExceeded recorded", report.Stages[0].Err)
		}
		if report.Outcome != OutcomeCancelled {
			t.Errorf("Outcome = %q, want cancelled", report.Outcome)
		}
	})

	t.Run("context canceled mid-run", func(t *testing.T) {
		started := make(chan struct{})
		blocker := &fakeStage{
			name: StageDiscover,
			run: func(ctx context.Context, in StageInput) (StageResult, error) {
				close(started)
				<-ctx.Done()
				return StageResult{Outcome: OutcomeCancelled}, ctx.Err()
			},
		}
		var order []StageName
		cfg := validConfig(t, StageDiscover, StageDNS)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; cancel() }()
		report, err := Run(ctx, cfg, nil, newFakeClock(testTime), []Stage{blocker, recordStage(StageDNS, &order)})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeCancelled {
			t.Errorf("Stages[0].Outcome = %q, want cancelled (not failed)", report.Stages[0].Outcome)
		}
		if !errors.Is(report.Stages[0].Err, context.Canceled) {
			t.Errorf("Stages[0].Err = %v, want context.Canceled recorded", report.Stages[0].Err)
		}
		if report.Stages[1].Outcome != OutcomeCancelled {
			t.Errorf("Stages[1].Outcome = %q, want cancelled (never ran)", report.Stages[1].Outcome)
		}
		if report.Outcome != OutcomeCancelled {
			t.Errorf("Outcome = %q, want cancelled", report.Outcome)
		}
	})
}

func TestFoldOutcomePrecedenceTable(t *testing.T) {
	// All 5×5 ordered pairs of the vocabulary, plus the empty set,
	// pinning the documented precedence: cancelled beats everything;
	// failed requires ≥1 failed and zero completed; incomplete beats the
	// completed/partial fallback; completed only when every stage
	// completed (vacuous for the empty set); partial otherwise.
	cases := []struct {
		a, b Outcome
		want Outcome
	}{
		// cancelled beats everything.
		{OutcomeCancelled, OutcomeCancelled, OutcomeCancelled},
		{OutcomeCancelled, OutcomeCompleted, OutcomeCancelled},
		{OutcomeCancelled, OutcomePartial, OutcomeCancelled},
		{OutcomeCancelled, OutcomeFailed, OutcomeCancelled},
		{OutcomeCancelled, OutcomeIncomplete, OutcomeCancelled},
		{OutcomeCompleted, OutcomeCancelled, OutcomeCancelled},
		{OutcomePartial, OutcomeCancelled, OutcomeCancelled},
		{OutcomeFailed, OutcomeCancelled, OutcomeCancelled},
		{OutcomeIncomplete, OutcomeCancelled, OutcomeCancelled},
		// failed: needs ≥1 failed and zero completed (rule 2 before rule 3).
		{OutcomeFailed, OutcomeFailed, OutcomeFailed},
		{OutcomeFailed, OutcomePartial, OutcomeFailed},
		{OutcomePartial, OutcomeFailed, OutcomeFailed},
		{OutcomeFailed, OutcomeIncomplete, OutcomeFailed},
		{OutcomeIncomplete, OutcomeFailed, OutcomeFailed},
		{OutcomeCompleted, OutcomeFailed, OutcomePartial},
		{OutcomeFailed, OutcomeCompleted, OutcomePartial},
		// incomplete beats the completed/partial fallback.
		{OutcomeIncomplete, OutcomeIncomplete, OutcomeIncomplete},
		{OutcomeIncomplete, OutcomeCompleted, OutcomeIncomplete},
		{OutcomeCompleted, OutcomeIncomplete, OutcomeIncomplete},
		{OutcomeIncomplete, OutcomePartial, OutcomeIncomplete},
		{OutcomePartial, OutcomeIncomplete, OutcomeIncomplete},
		// completed only when everything completed.
		{OutcomeCompleted, OutcomeCompleted, OutcomeCompleted},
		// partial otherwise.
		{OutcomePartial, OutcomePartial, OutcomePartial},
		{OutcomePartial, OutcomeCompleted, OutcomePartial},
		{OutcomeCompleted, OutcomePartial, OutcomePartial},
	}
	for _, tc := range cases {
		t.Run(string(tc.a)+"+ "+string(tc.b), func(t *testing.T) {
			got := foldOutcome([]StageRecord{{Outcome: tc.a}, {Outcome: tc.b}})
			if got != tc.want {
				t.Errorf("foldOutcome(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
	t.Run("empty set folds to completed (vacuous)", func(t *testing.T) {
		if got := foldOutcome(nil); got != OutcomeCompleted {
			t.Errorf("foldOutcome(empty) = %q, want completed", got)
		}
	})
}

func TestRunNamePanicIsolated(t *testing.T) {
	t.Run("Name() panic during resolution records failed and continues", func(t *testing.T) {
		var order []StageName
		cfg := validConfig(t, StageDiscover, StageDNS)
		stages := []Stage{
			&panickyNameStage{run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeCompleted}, nil
			}},
			recordStage(StageDNS, &order),
		}
		report, err := run(t, cfg, stages)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Stages[0].Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !strings.Contains(report.Stages[0].Err.Error(), "could not resolve: no matching stage provided (note: a provided stage's Name() panicked during resolution)") {
			t.Errorf("Stages[0].Err = %v, want the documented Name() panic resolution message", report.Stages[0].Err)
		}
		if report.Stages[1].Outcome != OutcomeCompleted {
			t.Errorf("Stages[1].Outcome = %q, want completed (run continues)", report.Stages[1].Outcome)
		}
		if !reflect.DeepEqual(order, []StageName{StageDNS}) {
			t.Errorf("run order = %v, want [dns]", order)
		}
		if report.Outcome != OutcomePartial {
			t.Errorf("Outcome = %q, want partial", report.Outcome)
		}
	})

	t.Run("Name() panic inside the runStage recover handler is absorbed", func(t *testing.T) {
		st := &flakyNameStage{run: func(ctx context.Context, in StageInput) (StageResult, error) {
			panic("run bug")
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Stages[0].Outcome)
		}
		if report.Stages[0].Err == nil || !strings.Contains(report.Stages[0].Err.Error(), "panicked") {
			t.Errorf("Err = %v, want panic error", report.Stages[0].Err)
		}
		if report.Outcome != OutcomeFailed {
			t.Errorf("Outcome = %q, want failed", report.Outcome)
		}
	})
}

func TestRunPreCancelledEmptySelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Run(ctx, validConfig(t), nil, newFakeClock(testTime), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Stages) != 0 {
		t.Errorf("Stages = %d entries, want 0", len(report.Stages))
	}
	if report.Outcome != OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled (pre-cancelled empty selection)", report.Outcome)
	}
}

func TestRunStageParams(t *testing.T) {
	var got map[string]string
	st := &fakeStage{
		name: StageDiscover,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			got = in.Config
			return StageResult{Outcome: OutcomeCompleted}, nil
		},
	}
	cfg := validConfig(t, StageDiscover)
	cfg.StageParams = map[StageName]map[string]string{
		StageDiscover: {"tool": "subfinder", "mode": "passive"},
		StageDNS:      {"tool": "dig"},
	}
	report, err := run(t, cfg, []Stage{st})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := map[string]string{"tool": "subfinder", "mode": "passive"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("in.Config = %v, want %v", got, want)
	}
	// The runner must not alias the caller's map: mutating the received
	// copy cannot change the config.
	got["tool"] = "mutated"
	if cfg.StageParams[StageDiscover]["tool"] != "subfinder" {
		t.Error("stage mutated the caller's StageParams (alias)")
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", report.Outcome)
	}

	t.Run("stage without params receives nil", func(t *testing.T) {
		var got map[string]string
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			got = in.Config
			return StageResult{Outcome: OutcomeCompleted}, nil
		}}
		if _, err := run(t, validConfig(t, StageDiscover), []Stage{st}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got != nil {
			t.Errorf("in.Config = %v, want nil", got)
		}
	})
}

func TestRunNilClock(t *testing.T) {
	_, err := Run(context.Background(), validConfig(t), nil, nil, nil)
	if err == nil {
		t.Fatal("Run with nil clock succeeded, want error")
	}
	var ce ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want ConfigError", err)
	}
	if ce.Field != "clock" {
		t.Errorf("Field = %q, want clock", ce.Field)
	}
}

func TestRunDeterministic(t *testing.T) {
	cfg := validConfig(t, StageDiscover, StageDNS, StageHTTPProbe)
	stages := func() []Stage {
		var order []StageName
		return []Stage{
			recordStage(StageDiscover, &order),
			recordStage(StageDNS, &order),
			recordStage(StageHTTPProbe, &order),
		}
	}
	report1, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	report2, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !reflect.DeepEqual(report1, report2) {
		t.Errorf("runs differ:\n%+v\n%+v", report1, report2)
	}
}

func TestRunCorpusPropagation(t *testing.T) {
	t.Run("merge order and first-seen dedup across stages", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			if len(in.Domains) != 0 || len(in.Hosts) != 0 || len(in.URLs) != 0 {
				t.Errorf("discover received non-empty corpus: %d domains %d hosts %d urls", len(in.Domains), len(in.Hosts), len(in.URLs))
			}
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Domains: []asset.Domain{mustDomain(t, "api.example.com")},
				Hosts:   []asset.Host{mustHost(t, "api.example.com")},
			}}, nil
		}}
		dns := &fakeStage{name: StageDNS, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			if len(in.Domains) != 1 || in.Domains[0].Name != "api.example.com" {
				t.Errorf("dns input domains = %v, want [api.example.com]", in.Domains)
			}
			if len(in.Hosts) != 1 || in.Hosts[0].Name != "api.example.com" {
				t.Errorf("dns input hosts = %v, want [api.example.com]", in.Hosts)
			}
			// api.example.com is a first-seen duplicate (dropped); www
			// appends in stage order.
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{mustHost(t, "api.example.com"), mustHost(t, "www.example.com")},
			}}, nil
		}}
		probe := &fakeStage{name: StageHTTPProbe, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			if len(in.Hosts) != 2 || in.Hosts[0].Name != "api.example.com" || in.Hosts[1].Name != "www.example.com" {
				t.Errorf("probe input hosts = %v, want [api.example.com www.example.com] (first-seen order)", in.Hosts)
			}
			u, err := asset.ParseURL("https://api.example.com/x", asset.Provenance{})
			if err != nil {
				t.Fatalf("ParseURL: %v", err)
			}
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				URLs: []asset.URL{u},
			}}, nil
		}}
		report, err := run(t, validConfig(t, StageDiscover, StageDNS, StageHTTPProbe), []Stage{discover, dns, probe})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Domains) != 1 || report.Domains[0].Name != "api.example.com" {
			t.Errorf("report.Domains = %v, want [api.example.com]", report.Domains)
		}
		if len(report.Hosts) != 2 || report.Hosts[0].Name != "api.example.com" || report.Hosts[1].Name != "www.example.com" {
			t.Errorf("report.Hosts = %v, want [api.example.com www.example.com]", report.Hosts)
		}
		if len(report.URLs) != 1 || report.URLs[0].String() != "https://api.example.com/x" {
			t.Errorf("report.URLs = %v, want [https://api.example.com/x]", report.URLs)
		}
		if report.Outcome != OutcomeCompleted {
			t.Errorf("Outcome = %q, want completed", report.Outcome)
		}
	})

	t.Run("defensive copy: mutating a stage's additions cannot reach the report", func(t *testing.T) {
		var res StageResult
		st := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			res = StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{mustHost(t, "api.example.com")},
			}}
			return res, nil
		}}
		report, err := run(t, validConfig(t, StageDiscover), []Stage{st})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		// Mutate the stage's returned slice after Run returned; the
		// report corpus must be unaffected (the merge copied it).
		res.Additions.Hosts[0] = asset.Host{Name: "evil.example.com"}
		if len(report.Hosts) != 1 || report.Hosts[0].Name != "api.example.com" {
			t.Errorf("report corpus aliased the stage's additions: %+v", report.Hosts)
		}
	})

	t.Run("empty additions are a no-op", func(t *testing.T) {
		var order []StageName
		report, err := run(t, validConfig(t, StageDiscover), []Stage{recordStage(StageDiscover, &order)})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Domains) != 0 || len(report.Hosts) != 0 || len(report.URLs) != 0 {
			t.Errorf("corpus not empty after a no-additions stage: %d/%d/%d", len(report.Domains), len(report.Hosts), len(report.URLs))
		}
		if len(report.StickyFlags) != 0 {
			t.Errorf("StickyFlags = %v, want empty", report.StickyFlags)
		}
	})

	t.Run("deterministic corpus across runs", func(t *testing.T) {
		cfg := validConfig(t, StageDiscover)
		stages := func() []Stage {
			return []Stage{&fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
					Hosts: []asset.Host{mustHost(t, "b.example.com"), mustHost(t, "a.example.com"), mustHost(t, "b.example.com")},
				}}, nil
			}}}
		}
		r1, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
		if err != nil {
			t.Fatalf("first Run: %v", err)
		}
		r2, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
		if err != nil {
			t.Fatalf("second Run: %v", err)
		}
		if !reflect.DeepEqual(r1, r2) {
			t.Errorf("runs differ (corpus must be deterministic):\n%+v\n%+v", r1, r2)
		}
	})

	t.Run("failed stage additions still merge (honest retained output)", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeFailed, Err: errors.New("tool crashed mid-run"), Additions: StageAdditions{
				Hosts: []asset.Host{mustHost(t, "api.example.com")},
			}}, nil
		}}
		dns := &fakeStage{name: StageDNS, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			if len(in.Hosts) != 1 {
				t.Errorf("dns input hosts = %d, want the failed stage's retained output", len(in.Hosts))
			}
			return StageResult{Outcome: OutcomeCompleted}, nil
		}}
		report, err := run(t, validConfig(t, StageDiscover, StageDNS), []Stage{discover, dns})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if report.Stages[0].Outcome != OutcomeFailed || report.Outcome != OutcomePartial {
			t.Errorf("outcomes = %q/%q, want failed stage + partial fold", report.Stages[0].Outcome, report.Outcome)
		}
		if len(report.Hosts) != 1 {
			t.Errorf("report.Hosts = %v, want the failed stage's additions retained", report.Hosts)
		}
	})
}

func TestRunCorpusCap(t *testing.T) {
	u, err := asset.ParseURL("https://h1.example.com/", asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
			Hosts: []asset.Host{
				mustHost(t, "h1.example.com"), mustHost(t, "h2.example.com"), mustHost(t, "h3.example.com"),
			},
			URLs: []asset.URL{u},
		}}, nil
	}}
	var dnsInputHosts, dnsInputURLs int
	dns := &fakeStage{name: StageDNS, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		dnsInputHosts = len(in.Hosts)
		dnsInputURLs = len(in.URLs)
		return StageResult{Outcome: OutcomeCompleted}, nil
	}}
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: 3}}
	report, err := run(t, cfg, []Stage{discover, dns})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Cap 3, hosts kept first (3 fill the cap), URLs tail-dropped.
	if len(report.Hosts) != 3 || len(report.URLs) != 0 {
		t.Errorf("corpus after cap = %d hosts %d urls, want 3/0", len(report.Hosts), len(report.URLs))
	}
	if dnsInputHosts != 3 || dnsInputURLs != 0 {
		t.Errorf("dns input = %d hosts %d urls, want the capped corpus 3/0", dnsInputHosts, dnsInputURLs)
	}
	if !report.Truncated {
		t.Error("report.Truncated must be set when the corpus was capped")
	}
	if !report.StickyFlags["corpus_capped"] {
		t.Errorf("report.StickyFlags = %v, want corpus_capped set", report.StickyFlags)
	}
	// The stage's own outcome is untouched: completed + flag is the
	// AGENTS §0.6 carve-out (consumers treat the flagged run as an
	// incomplete retained set), not a silent completed.
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed with the corpus_capped flag (carve-out)", report.Outcome)
	}

	t.Run("hosts-cut branch: cap smaller than the host count", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{mustHost(t, "h1.example.com"), mustHost(t, "h2.example.com"), mustHost(t, "h3.example.com")},
			}}, nil
		}}
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: 2}}
		report, err := run(t, cfg, []Stage{discover})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Hosts) != 2 || report.Hosts[0].Name != "h1.example.com" || report.Hosts[1].Name != "h2.example.com" {
			t.Errorf("hosts after cap = %v, want [h1.example.com h2.example.com]", report.Hosts)
		}
		if !report.StickyFlags["corpus_capped"] {
			t.Error("corpus_capped not set on the hosts-cut branch")
		}
	})

	t.Run("domains survive a cap (scope, not corpus entries)", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Domains: []asset.Domain{mustDomain(t, "api.example.com")},
				Hosts:   []asset.Host{mustHost(t, "h1.example.com"), mustHost(t, "h2.example.com"), mustHost(t, "h3.example.com")},
			}}, nil
		}}
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: 2}}
		report, err := run(t, cfg, []Stage{discover})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Domains) != 1 || report.Domains[0].Name != "api.example.com" {
			t.Errorf("domains must survive the cap: %v", report.Domains)
		}
		if len(report.Hosts) != 2 {
			t.Errorf("hosts after cap = %d, want 2", len(report.Hosts))
		}
	})

	t.Run("capped-away entries cannot re-enter through a larger later cap", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{
					mustHost(t, "a.example.com"), mustHost(t, "b.example.com"),
					mustHost(t, "c.example.com"), mustHost(t, "d.example.com"),
				},
			}}, nil
		}}
		dns := &fakeStage{name: StageDNS, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			// Re-emits the capped-away entries plus one new host: the
			// cut entries remain first-seen and cannot re-enter.
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{
					mustHost(t, "c.example.com"), mustHost(t, "d.example.com"),
					mustHost(t, "e.example.com"),
				},
			}}, nil
		}}
		cfg := validConfig(t, StageDiscover, StageDNS)
		cfg.StageBounds = map[StageName]StageConfig{
			StageDiscover: {MaxCorpusSize: 2},
			StageDNS:      {MaxCorpusSize: 100000},
		}
		report, err := run(t, cfg, []Stage{discover, dns})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []string{"a.example.com", "b.example.com", "e.example.com"}
		if len(report.Hosts) != len(want) {
			t.Fatalf("hosts = %v, want %v (cut entries stay first-seen)", report.Hosts, want)
		}
		for i, w := range want {
			if report.Hosts[i].Name != w {
				t.Errorf("hosts[%d] = %q, want %q", i, report.Hosts[i].Name, w)
			}
		}
		if !report.StickyFlags["corpus_capped"] {
			t.Error("corpus_capped must be set (discover's cap cut the corpus)")
		}
	})

	t.Run("cap larger than the total is a no-cut no-flag", func(t *testing.T) {
		discover := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
				Hosts: []asset.Host{mustHost(t, "h1.example.com"), mustHost(t, "h2.example.com")},
			}}, nil
		}}
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: 100}}
		report, err := run(t, cfg, []Stage{discover})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Hosts) != 2 {
			t.Errorf("hosts = %v, want both hosts", report.Hosts)
		}
		if report.Truncated {
			t.Error("Truncated must be false when the cap did not cut")
		}
		if len(report.StickyFlags) != 0 {
			t.Errorf("StickyFlags = %v, want empty", report.StickyFlags)
		}
	})
}

func TestRunValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		cfg     func(t *testing.T) ScanConfig
		wantSub string
	}{
		{
			"missing target",
			func(t *testing.T) ScanConfig { return ScanConfig{Stages: []StageName{StageDiscover}} },
			"target",
		},
		{
			"non-canonical target",
			func(t *testing.T) ScanConfig {
				return ScanConfig{Target: asset.Domain{Name: "Example.COM"}, Stages: []StageName{StageDiscover}}
			},
			"not canonical",
		},
		{
			"unknown stage",
			func(t *testing.T) ScanConfig { return validConfig(t, StageDiscover, "bogus") },
			"stages[1]",
		},
		{
			"empty stage name",
			func(t *testing.T) ScanConfig { return validConfig(t, StageDiscover, "") },
			"stages[1]",
		},
		{
			"duplicate stage",
			func(t *testing.T) ScanConfig { return validConfig(t, StageDiscover, StageDiscover) },
			"duplicate",
		},
		{
			"inverted concurrency",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxConcurrency: -1}}
				return cfg
			},
			"bounds[discover].MaxConcurrency",
		},
		{
			"inverted queue",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {QueueSize: -1}}
				return cfg
			},
			"bounds[discover].QueueSize",
		},
		{
			"inverted timeout",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Timeout: -time.Second}}
				return cfg
			},
			"bounds[discover].Timeout",
		},
		{
			"inverted rate",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Rate: -1}}
				return cfg
			},
			"bounds[discover].Rate",
		},
		{
			"non-finite rate",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Rate: math.NaN()}}
				return cfg
			},
			"finite",
		},
		{
			"negative burst with positive rate",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Rate: 10, Burst: -1}}
				return cfg
			},
			"bounds[discover].Burst",
		},
		{
			"inverted burst",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Burst: -1}}
				return cfg
			},
			"bounds[discover].Burst",
		},
		{
			"inverted corpus size",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: -1}}
				return cfg
			},
			"bounds[discover].MaxCorpusSize",
		},
		{
			"inverted output cap",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: -1}}
				return cfg
			},
			"bounds[discover].MaxOutput",
		},
		{
			"unknown bounds key",
			func(t *testing.T) ScanConfig {
				cfg := validConfig(t, StageDiscover)
				cfg.StageBounds = map[StageName]StageConfig{"bogus": {MaxOutput: 1}}
				return cfg
			},
			"bounds[bogus]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg(t).Validate()
			if err == nil {
				t.Fatalf("Validate returned nil, want failure mentioning %q", tc.wantSub)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error type = %T, want *ValidationError", err)
			}
			if len(ve.Problems) == 0 {
				t.Fatal("ValidationError with zero problems")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}

	t.Run("valid configs pass", func(t *testing.T) {
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{
			StageDiscover: {MaxConcurrency: 8, QueueSize: 16, Timeout: 30 * time.Second, Rate: 10, Burst: 5, MaxCorpusSize: 1000, MaxOutput: 500},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid config rejected: %v", err)
		}
		if err := validConfig(t).Validate(); err != nil {
			t.Errorf("empty-selection config rejected: %v", err)
		}
	})

	t.Run("positive rate with burst zero is valid and resolves to the default burst", func(t *testing.T) {
		cfg := validConfig(t, StageDiscover)
		cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {Rate: 10, Burst: 0}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Rate>0 with Burst:0 rejected: %v", err)
		}
		eff := effectiveConfig(cfg, StageDiscover)
		if eff.Rate != 10 {
			t.Errorf("eff.Rate = %v, want 10", eff.Rate)
		}
		if eff.Burst != DefaultBurst {
			t.Errorf("eff.Burst = %d, want the default %d", eff.Burst, DefaultBurst)
		}
	})

	t.Run("stage params with nil inner map are valid", func(t *testing.T) {
		cfg := validConfig(t, StageDiscover)
		cfg.StageParams = map[StageName]map[string]string{StageDiscover: nil}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("nil inner StageParams rejected: %v", err)
		}
	})

	t.Run("unknown stage params key", func(t *testing.T) {
		cfg := validConfig(t, StageDiscover)
		cfg.StageParams = map[StageName]map[string]string{"bogus": {"tool": "subfinder"}}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "params[bogus]") {
			t.Fatalf("Validate error = %v, want params[bogus] rejection", err)
		}
	})
}

func TestScopeFilterMatrix(t *testing.T) {
	declared := mustDomain(t, "example.com")

	inDomain := []string{
		"example.com",     // bare host = the declared domain itself
		"api.example.com", // one-level subdomain
		"a.b.example.com", // deep subdomain
	}
	outOfDomain := []string{
		"other.com",
		"notexample.com",       // suffix without a label boundary
		"evil-example.com",     // label prefix, not a subdomain
		"example.com.evil.com", // ends with the declared name but is not under it
		"com",                  // parent of the declared domain
	}
	for _, name := range inDomain {
		if !InDomain(declared, mustHost(t, name)) {
			t.Errorf("InDomain(%q) = false, want true", name)
		}
	}
	for _, name := range outOfDomain {
		if InDomain(declared, mustHost(t, name)) {
			t.Errorf("InDomain(%q) = true, want false", name)
		}
	}
	if InDomain(asset.Domain{}, mustHost(t, "example.com")) {
		t.Error("empty declared domain must never match")
	}
	if InDomain(declared, asset.Host{}) {
		t.Error("empty host must never match")
	}

	t.Run("FilterHosts preserves order and keeps only in-domain hosts", func(t *testing.T) {
		hosts := []asset.Host{
			mustHost(t, "a.example.com"),
			mustHost(t, "evil.com"),
			mustHost(t, "example.com"),
			mustHost(t, "b.example.com"),
		}
		got := FilterHosts(declared, hosts)
		want := []asset.Host{hosts[0], hosts[2], hosts[3]}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("FilterHosts = %v, want %v", got, want)
		}
	})

	t.Run("operates on canonical forms only, never normalizes", func(t *testing.T) {
		// The asset builders already canonicalized; the filter needs no
		// normalizer of its own.
		if !InDomain(mustDomain(t, "EXAMPLE.com"), mustHost(t, "API.Example.COM")) {
			t.Error("canonical forms must match")
		}
		// A hand-built non-canonical Domain is not matched: the filter is
		// comparison over canonical names, never a second normalizer.
		if InDomain(asset.Domain{Name: "Example.COM"}, mustHost(t, "example.com")) {
			t.Error("non-canonical declared domain must not match")
		}
	})

	t.Run("empty input yields empty output", func(t *testing.T) {
		if got := FilterHosts(declared, nil); len(got) != 0 {
			t.Errorf("FilterHosts(nil) = %v, want empty", got)
		}
	})
}
