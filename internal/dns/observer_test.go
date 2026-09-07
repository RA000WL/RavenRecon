package dns

import (
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// observerRecorder is a hermetic event.Observer: it records every event the
// run's pool emits behind a mutex (pool workers emit concurrently).
type observerRecorder struct {
	mu  sync.Mutex
	evs []event.Event
}

func (r *observerRecorder) Observe(ev event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *observerRecorder) kindCounts() map[event.Kind]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[event.Kind]int, len(r.evs))
	for _, ev := range r.evs {
		out[ev.Kind]++
	}
	return out
}

// TestResolveObserverReceivesTaskEvents pins the Observer sink threading: a
// Resolve run with a recording observer delivers pool task-lifecycle events.
// The pool owns emission; this test only proves the sink is forwarded.
func TestResolveObserverReceivesTaskEvents(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	rec := &observerRecorder{}
	cfg := testConfig(f)
	cfg.Observer = rec

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	if hr := hostByName(t, rep, "www.example.com"); hr.Status != StatusCompleted {
		t.Fatalf("host status = %s, want completed", hr.Status)
	}

	counts := rec.kindCounts()
	if counts[event.KindTaskSubmitted] < 1 {
		t.Fatalf("task_submitted events = %d, want >= 1 (got kinds %v)", counts[event.KindTaskSubmitted], counts)
	}
	if counts[event.KindTaskCompleted] < 1 {
		t.Fatalf("task_completed events = %d, want >= 1 (got kinds %v)", counts[event.KindTaskCompleted], counts)
	}
}
