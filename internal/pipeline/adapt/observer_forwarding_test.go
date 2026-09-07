package adapt

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// forwardingObserver is a concurrency-safe event.Observer recording every
// event (the engine pools emit from worker goroutines, so the mutex keeps
// the recorder honest under -race).
type forwardingObserver struct {
	mu     sync.Mutex
	events []event.Event
}

func (o *forwardingObserver) Observe(ev event.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
}

func (o *forwardingObserver) snapshot() []event.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]event.Event(nil), o.events...)
}

// terminalKinds are the pool's per-job terminal event kinds: exactly one is
// emitted per submitted job, whatever the job's outcome.
var terminalKinds = []event.Kind{
	event.KindTaskCompleted,
	event.KindTaskCancelled,
	event.KindTaskFailed,
	event.KindTaskTimedOut,
}

func countTerminals(evs []event.Event) int {
	n := 0
	for _, ev := range evs {
		for _, k := range terminalKinds {
			if ev.Kind == k {
				n++
				break
			}
		}
	}
	return n
}

// assertForwarded pins the adapter contract: the stage ran, every recorded
// event is valid, the pool lifecycle brackets the run (scan_started /
// scan_stopped), and the per-job terminal count proves StageInput.Observer
// reached the engine's worker pool.
func assertForwarded(t *testing.T, stage string, res pipeline.StageResult, err error, evs []event.Event, wantTerminals int) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: Run: %v", stage, err)
	}
	if len(evs) == 0 {
		t.Fatalf("%s: observer recorded no events; StageInput.Observer must reach the engine pool", stage)
	}
	for _, ev := range evs {
		if verr := ev.Validate(); verr != nil {
			t.Errorf("%s: invalid event %+v: %v", stage, ev, verr)
		}
	}
	seen := map[event.Kind]int{}
	for _, ev := range evs {
		seen[ev.Kind]++
	}
	if seen[event.KindScanStarted] != 1 {
		t.Errorf("%s: scan_started events = %d, want 1", stage, seen[event.KindScanStarted])
	}
	if got := countTerminals(evs); got != wantTerminals {
		t.Errorf("%s: terminal events = %d, want %d (one job per unit of work)", stage, got, wantTerminals)
	}
	if seen[event.KindScanStopped] != 1 {
		t.Errorf("%s: scan_stopped events = %d, want 1", stage, seen[event.KindScanStopped])
	}
	_ = res
}

// TestAdaptObserverForwarding proves every engine adapter forwards
// StageInput.Observer into its worker pool: each stage runs over a small
// hermetic corpus with a recording observer, and the pool's task terminals
// (one per document / observation / signal / report / file) reach it.
func TestAdaptObserverForwarding(t *testing.T) {
	t.Run("secrentel", func(t *testing.T) {
		d1 := scriptDocument(t, "https://cdn.example.com/app.js", `var k1 = "`+awsKey(1)+`";`)
		d2 := scriptDocument(t, "https://cdn.example.com/vendor.js", `var k2 = "`+awsKey(2)+`";`)
		in := secretInput(t, d1, d2)
		rec := &forwardingObserver{}
		in.Observer = rec
		res, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), in)
		assertForwarded(t, "secrentel", res, err, rec.snapshot(), 2)
	})

	t.Run("techintel", func(t *testing.T) {
		target := mustDomain(t, "example.com")
		urls := []asset.URL{techURL(t, "https://example.com/admin")}
		in := techintelInput(target, urls, nil, nil)
		rec := &forwardingObserver{}
		in.Observer = rec
		res, err := techStage(t).Run(context.Background(), in)
		assertForwarded(t, "techintel", res, err, rec.snapshot(), 1)
	})

	t.Run("priority", func(t *testing.T) {
		interesting, risk := priorityCatalogs(t)
		domains, hosts, urls := priorityCorpus(t)
		in := priorityInput(mustDomain(t, "example.com"), domains, hosts, urls, nil)
		rec := &forwardingObserver{}
		in.Observer = rec
		res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
		// 1 domain + 2 hosts + 1 URL = 4 signals = 4 jobs.
		assertForwarded(t, "priority", res, err, rec.snapshot(), 4)
	})

	t.Run("report", func(t *testing.T) {
		domains, hosts, urls := reportCorpus(t)
		dir := t.TempDir()
		in := reportInput(mustDomain(t, "example.com"), domains, hosts, urls, dir, nil)
		rec := &forwardingObserver{}
		in.Observer = rec
		res, err := NewReportStage(nil).Run(context.Background(), in)
		// The default registry renders 4 reporters concurrently: the
		// terminal count proves the render fan-out is observable.
		assertForwarded(t, "report", res, err, rec.snapshot(), res.ItemsProcessed)
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("report: outcome = %q, want completed (err=%v)", res.Outcome, res.Err)
		}
	})

	t.Run("ingest", func(t *testing.T) {
		_, urlsPath, httpxPath := ingestFixtures(t)
		clk := fixedClock{now: fixedTime}
		in := ingestInput(t, clk, nil,
			strings.Join([]string{urlsPath, httpxPath}, "\n"), nil)
		rec := &forwardingObserver{}
		in.Observer = rec
		res, err := NewIngestStage().Run(context.Background(), in)
		// One pool job per file.
		assertForwarded(t, "ingest", res, err, rec.snapshot(), 2)
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("ingest: outcome = %q, want completed (err=%v)", res.Outcome, res.Err)
		}
	})
}
