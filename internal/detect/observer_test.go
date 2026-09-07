package detect

import (
	"context"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe event.Observer that appends every
// event it receives. Pool emission is synchronous, so the recorded order is
// the emission order; the mutex keeps the recorder honest under -race
// (rules run on worker goroutines).
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

// TestRunObserverReceivesTaskEvents proves the engine forwards
// EngineConfig.Observer into its worker pool: a hermetic run over one rule
// delivers pool task events (submitted plus a terminal event) to the
// observer. Rules run inside pool jobs, so their task events flow through
// this sink; rule_executed events travel the separate rule path and are not
// asserted here. A nil Observer (the default) stays zero behavior change —
// every other engine test runs without one.
func TestRunObserverReceivesTaskEvents(t *testing.T) {
	reg := newTestRegistry(t, makeRule(t, "a.b", nil))
	cfg := DefaultEngineConfig(reg)
	obs := &recordingObserver{}
	cfg.Observer = obs
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := countStatus(rep, RuleStatusCompleted); got != 1 {
		t.Fatalf("completed = %d, want 1", got)
	}

	var submitted, terminal int
	for _, ev := range obs.snapshot() {
		switch ev.Kind {
		case event.KindTaskSubmitted:
			submitted++
		case event.KindTaskCompleted, event.KindTaskFailed, event.KindTaskCancelled, event.KindTaskTimedOut:
			terminal++
		}
	}
	if submitted == 0 {
		t.Error("observer received no task_submitted event; EngineConfig.Observer must reach the worker pool")
	}
	if terminal == 0 {
		t.Error("observer received no terminal task event; EngineConfig.Observer must reach the worker pool")
	}
}
