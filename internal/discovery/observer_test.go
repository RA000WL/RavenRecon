package discovery

import (
	"context"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe event.Observer that records every
// event it receives. The pool emits synchronously, so by the time Run
// returns every event has been delivered; the mutex keeps the recorder
// honest under -race (workers emit concurrently).
type recordingObserver struct {
	mu     sync.Mutex
	events []event.Event
}

func (o *recordingObserver) Observe(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *recordingObserver) count(k event.Kind) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, ev := range o.events {
		if ev.Kind == k {
			n++
		}
	}
	return n
}

// TestRunObserverReceivesTaskEvents proves the engine forwards its configured
// Observer to the run's worker pool: a single scripted source surfaces one
// task_submitted and one task_completed. Sources are external binaries, but
// each source is one pool job, so pool task events still flow.
func TestRunObserverReceivesTaskEvents(t *testing.T) {
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("api.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Sources = []string{"subfinder"}
	rec := &recordingObserver{}
	cfg.Observer = rec
	rep, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(rep.Results))
	}
	if got := rec.count(event.KindTaskSubmitted); got != 1 {
		t.Fatalf("task_submitted = %d, want 1 (one per executed source)", got)
	}
	if got := rec.count(event.KindTaskCompleted); got != 1 {
		t.Fatalf("task_completed = %d, want 1 (one per executed source)", got)
	}
}
