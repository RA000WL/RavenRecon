package secrentel

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

// TestIngestObserverEmitsTaskEvents pins the observer wiring end to end: one
// pool job per document, so every pool-boundary event the runtime pool emits
// (scan start/stop, one task terminal per document) reaches the configured
// Config.Observer, and every recorded event is valid.
func TestIngestObserverEmitsTaskEvents(t *testing.T) {
	rec := &observerRecorder{}
	cfg := baseCfg()
	cfg.Clock = newFakeClock()
	cfg.Observer = rec

	rep, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if rep.Documents.Completed != 4 {
		t.Fatalf("completed = %d, want 4", rep.Documents.Completed)
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
	if got := countKind(evs, event.KindTaskCompleted); got != 4 {
		t.Errorf("task_completed events = %d, want 4 (one job per document)", got)
	}
	if got := countKind(evs, event.KindScanStopped); got != 1 {
		t.Errorf("scan_stopped events = %d, want 1", got)
	}
}

// TestIngestNilObserverPreservesBehavior pins the off switch: the default
// nil observer runs byte-identically (same document counts, same secrets)
// to a run with a recording observer — instrumentation is purely additive.
func TestIngestNilObserverPreservesBehavior(t *testing.T) {
	run := func(obs *observerRecorder) Report {
		t.Helper()
		cfg := baseCfg()
		cfg.Clock = newFakeClock()
		if obs != nil {
			cfg.Observer = obs
		}
		rep, err := Ingest(context.Background(), cfg, sliceSource(testDocuments()))
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		return rep
	}

	plain := run(nil)
	observed := run(&observerRecorder{})

	if plain.Documents != observed.Documents {
		t.Fatalf("document counts differ: %+v vs %+v", plain.Documents, observed.Documents)
	}
	if len(plain.Secrets) != len(observed.Secrets) {
		t.Fatalf("secret counts differ: %d vs %d", len(plain.Secrets), len(observed.Secrets))
	}
}
