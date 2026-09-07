package report

import (
	"context"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// observerRecorder is a thread-safe event.Observer that records every event
// in arrival order (the render pool emits from worker goroutines, so the
// mutex keeps the recorder honest under -race).
type observerRecorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (o *observerRecorder) Observe(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *observerRecorder) snapshot() []event.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]event.Event(nil), o.events...)
}

func countKind(evs []event.Event, k event.Kind) int {
	n := 0
	for _, ev := range evs {
		if ev.Kind == k {
			n++
		}
	}
	return n
}

func attempted(res RunResult) int {
	n := 0
	for _, r := range res.Reports {
		if r.Status != ReportStatusSkipped {
			n++
		}
	}
	return n
}

// TestRunObserverEmitsRenderFanOut pins the observer wiring end to end: the
// engine renders every active report on one bounded pool — exactly one job
// per report — so the task terminal events prove the concurrent render
// fan-out is observable through the configured EngineConfig.Observer, and
// every recorded event is valid.
func TestRunObserverEmitsRenderFanOut(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	rec := &observerRecorder{}
	cfg := DefaultEngineConfig(reg, t.TempDir())
	cfg.Observer = rec

	res, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed: %+v", res.Outcome, res.Reports)
	}

	evs := rec.snapshot()
	if len(evs) == 0 {
		t.Fatal("observer recorded no events; the render pool must emit its lifecycle")
	}
	for _, ev := range evs {
		if err := ev.Validate(); err != nil {
			t.Errorf("invalid event %+v: %v", ev, err)
		}
	}
	if got := countKind(evs, event.KindScanStarted); got != 1 {
		t.Errorf("scan_started events = %d, want 1", got)
	}
	// One task per attempted report: the fan-out itself is what the
	// terminal count proves.
	if want := attempted(res); countKind(evs, event.KindTaskCompleted) != want {
		t.Errorf("task_completed events = %d, want %d (one per attempted report)",
			countKind(evs, event.KindTaskCompleted), want)
	}
	if got := countKind(evs, event.KindScanStopped); got != 1 {
		t.Errorf("scan_stopped events = %d, want 1", got)
	}
}

// TestRunNilObserverPreservesBehavior pins the off switch: the default nil
// observer run produces the same outcome, digest, and report set as a run
// with a recording observer — instrumentation is purely additive.
func TestRunNilObserverPreservesBehavior(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	run := func(obs *observerRecorder) RunResult {
		t.Helper()
		cfg := DefaultEngineConfig(reg, t.TempDir())
		if obs != nil {
			cfg.Observer = obs
		}
		res, err := Run(context.Background(), cfg, testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return res
	}

	plain := run(nil)
	observed := run(&observerRecorder{})

	if plain.Outcome != observed.Outcome || plain.Digest != observed.Digest {
		t.Fatalf("run differs: outcome %q/%q digest %q/%q",
			plain.Outcome, observed.Outcome, plain.Digest, observed.Digest)
	}
	if len(plain.Reports) != len(observed.Reports) {
		t.Fatalf("report counts differ: %d vs %d", len(plain.Reports), len(observed.Reports))
	}
	for i := range plain.Reports {
		if plain.Reports[i].Status != observed.Reports[i].Status ||
			plain.Reports[i].ReporterID != observed.Reports[i].ReporterID {
			t.Fatalf("report %d differs: %+v vs %+v", i, plain.Reports[i], observed.Reports[i])
		}
	}
}
