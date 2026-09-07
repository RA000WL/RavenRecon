package priority

import (
	"context"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// observerRecorder is a thread-safe event.Observer that records every event
// in arrival order (the pool may emit from worker goroutines, so the mutex
// keeps the recorder honest under -race).
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

// TestScoreObserverEmitsTaskEvents pins the observer wiring end to end: one
// pool job per signal, so every pool-boundary event the runtime pool emits
// (scan start/stop, one task terminal per signal) reaches the configured
// EngineConfig.Observer, and every recorded event is valid.
func TestScoreObserverEmitsTaskEvents(t *testing.T) {
	rec := &observerRecorder{}
	cfg := engineCfg()
	cfg.Clock = newEngineClock()
	cfg.Observer = rec

	rep, err := Score(context.Background(), cfg, feedSignals(engineSignals()))
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %s, want completed", rep.Outcome)
	}

	evs := rec.snapshot()
	if len(evs) == 0 {
		t.Fatal("observer recorded no events; the pool must emit its lifecycle")
	}
	for _, ev := range evs {
		if err := ev.Validate(); err != nil {
			t.Errorf("invalid event %+v: %v", ev, err)
		}
	}
	if got := countKind(evs, event.KindScanStarted); got != 1 {
		t.Errorf("scan_started events = %d, want 1", got)
	}
	if got := countKind(evs, event.KindTaskCompleted); got != len(engineSignals()) {
		t.Errorf("task_completed events = %d, want %d (one job per signal)", got, len(engineSignals()))
	}
	if got := countKind(evs, event.KindScanStopped); got != 1 {
		t.Errorf("scan_stopped events = %d, want 1", got)
	}
}

// TestScoreNilObserverPreservesBehavior pins the off switch: the default
// nil observer run reports the same asset counts as a run with a recording
// observer — instrumentation is purely additive.
func TestScoreNilObserverPreservesBehavior(t *testing.T) {
	run := func(obs *observerRecorder) Report {
		t.Helper()
		cfg := engineCfg()
		cfg.Clock = newEngineClock()
		if obs != nil {
			cfg.Observer = obs
		}
		rep, err := Score(context.Background(), cfg, feedSignals(engineSignals()))
		if err != nil {
			t.Fatalf("Score: %v", err)
		}
		return rep
	}

	plain := run(nil)
	observed := run(&observerRecorder{})

	if plain.Outcome != observed.Outcome ||
		plain.Completed != observed.Completed ||
		plain.Failed != observed.Failed ||
		plain.Cancelled != observed.Cancelled {
		t.Fatalf("run counts differ: %+v vs %+v", plain, observed)
	}
	if len(plain.Assets) != len(observed.Assets) {
		t.Fatalf("asset counts differ: %d vs %d", len(plain.Assets), len(observed.Assets))
	}
}
