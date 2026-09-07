package urlintel

import (
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe event.Observer that records every
// event it receives. The pool emits synchronously, so by the time Ingest
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

// TestIngestObserverReceivesTaskEvents proves the engine forwards its
// configured Observer to the run's worker pool: a tiny two-line ingest
// surfaces one task_submitted and one task_completed per line.
func TestIngestObserverReceivesTaskEvents(t *testing.T) {
	cfg := testConfig()
	rec := &recordingObserver{}
	cfg.Observer = rec
	rep := runIngest(t, cfg, []string{"http://example.com/a", "http://example.com/b"})
	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rep.Entries))
	}
	if got := rec.count(event.KindTaskSubmitted); got != 2 {
		t.Fatalf("task_submitted = %d, want 2 (one per ingested line)", got)
	}
	if got := rec.count(event.KindTaskCompleted); got != 2 {
		t.Fatalf("task_completed = %d, want 2 (one per ingested line)", got)
	}
}
