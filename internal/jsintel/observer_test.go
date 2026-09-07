package jsintel

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe event.Observer that appends every
// event it receives. Pool emission is synchronous, so the recorded order is
// the emission order; the mutex keeps the recorder honest under -race
// (jobs run on worker goroutines).
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

// TestRunObserverReceivesTaskEvents proves the engine forwards Config.Observer
// into its worker pool: a hermetic run over one candidate delivers pool task
// events (submitted plus a terminal event) to the observer. A nil Observer
// (the default) stays zero behavior change — every other engine test runs
// without one.
func TestRunObserverReceivesTaskEvents(t *testing.T) {
	body := []byte("var app = {x: 1};\nconsole.log(\"hi\");\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	obs := &recordingObserver{}
	cfg.Observer = obs
	rep, err := Run(context.Background(), cfg, SliceSource([]Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
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
		t.Error("observer received no task_submitted event; Config.Observer must reach the worker pool")
	}
	if terminal == 0 {
		t.Error("observer received no terminal task event; Config.Observer must reach the worker pool")
	}
}
