package techintel

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

// TestIngestObserverEmitsTaskEvents pins the observer wiring end to end:
// one pool job per observation, so every pool-boundary event the runtime
// pool emits (scan start/stop, one task terminal per observation) reaches
// the configured Config.Observer, and every recorded event is valid.
func TestIngestObserverEmitsTaskEvents(t *testing.T) {
	var rep Report
	var err error
	mustFinish(t, "observed ingest", func() {
		rec := &observerRecorder{}
		cfg := testConfig(t)
		cfg.Observer = rec

		obs := newObs(t, "https://ok.example/")
		obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
		obs.Body = "It works!"
		src := SliceObservationSource{obs}

		rep, err = Ingest(context.Background(), cfg, &src)
		if err != nil {
			t.Errorf("Ingest: %v", err)
			return
		}
		if rep.Observations.Completed != 1 {
			t.Errorf("completed = %d, want 1", rep.Observations.Completed)
		}

		evs := rec.snapshot()
		if len(evs) == 0 {
			t.Error("observer recorded no events; the pool must emit its lifecycle")
			return
		}
		for _, ev := range evs {
			if verr := ev.Validate(); verr != nil {
				t.Errorf("invalid event %+v: %v", ev, verr)
			}
		}
		if got := countKind(evs, event.KindScanStarted); got != 1 {
			t.Errorf("scan_started events = %d, want 1", got)
		}
		if got := countKind(evs, event.KindTaskCompleted); got != 1 {
			t.Errorf("task_completed events = %d, want 1 (one job per observation)", got)
		}
		if got := countKind(evs, event.KindScanStopped); got != 1 {
			t.Errorf("scan_stopped events = %d, want 1", got)
		}
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	_ = rep
}

// TestIngestNilObserverPreservesBehavior pins the off switch: the default
// nil observer run reports the same observation counts as a run with a
// recording observer — instrumentation is purely additive.
func TestIngestNilObserverPreservesBehavior(t *testing.T) {
	run := func(obs *observerRecorder) Report {
		t.Helper()
		var rep Report
		mustFinish(t, "ingest run", func() {
			cfg := testConfig(t)
			if obs != nil {
				cfg.Observer = obs
			}
			src := SliceObservationSource{newObs(t, "https://ok.example/")}
			var err error
			rep, err = Ingest(context.Background(), cfg, &src)
			if err != nil {
				t.Errorf("Ingest: %v", err)
			}
		})
		return rep
	}

	plain := run(nil)
	observed := run(&observerRecorder{})

	if plain.Observations != observed.Observations {
		t.Fatalf("observation counts differ: %+v vs %+v", plain.Observations, observed.Observations)
	}
	if len(plain.Technologies) != len(observed.Technologies) {
		t.Fatalf("technology counts differ: %d vs %d", len(plain.Technologies), len(observed.Technologies))
	}
}
