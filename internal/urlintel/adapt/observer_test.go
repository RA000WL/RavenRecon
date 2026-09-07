package adapt

import (
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// recordingObserver is a concurrency-safe event.Observer that records every
// event it receives. Both pools emit synchronously, so by the time Run
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

// TestRunObserverReceivesTaskEvents proves the adapter forwards its configured
// Observer to the outer execution pool AND threads it through to each inner
// ingest pool: one tool over one target with a two-URL capture surfaces one
// outer task (the tool slot) plus two inner tasks (one per ingested line).
func TestRunObserverReceivesTaskEvents(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	rec := &recordingObserver{}
	cfg.Observer = rec
	rep := runOnce(t, cfg)
	if len(rep.Report.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rep.Report.Entries))
	}
	if got := rec.count(event.KindTaskSubmitted); got != 3 {
		t.Fatalf("task_submitted = %d, want 3 (1 outer slot + 2 inner lines)", got)
	}
	if got := rec.count(event.KindTaskCompleted); got != 3 {
		t.Fatalf("task_completed = %d, want 3 (1 outer slot + 2 inner lines)", got)
	}
}
