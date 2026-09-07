package httpprobe

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

// TestProbeObserverReceivesTaskEvents pins the Observer sink threading: a
// Probe run with a recording observer delivers pool task-lifecycle events.
// The pools own emission; this test only proves the sink is forwarded.
func TestProbeObserverReceivesTaskEvents(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	rec := &observerRecorder{}
	cfg := testConfig()
	cfg.Observer = rec

	var rep Report
	mustFinish(t, "Probe", func() {
		rep = probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, cfg)
	})
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
