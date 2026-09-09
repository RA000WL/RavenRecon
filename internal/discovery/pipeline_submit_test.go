package discovery

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// sourceCollector is a thread-safe OnSource sink: submit-failure emissions
// happen on the Run goroutine while job emissions happen on pool workers,
// so collection is mutex-guarded (race-covered).
type sourceCollector struct {
	mu     sync.Mutex
	events []SourceResult
}

func (c *sourceCollector) onSource(res SourceResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, res)
}

func (c *sourceCollector) snapshot() []SourceResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SourceResult(nil), c.events...)
}

// TestSubmitFailureEmitsCancelledResult pins the submit-failure merge
// path: when a pool Submit fails (here the run context is cancelled while
// the third submission blocks behind one running and one queued job), the
// failed source still finalizes through emitResult — observers see its
// cancelled result exactly like any other finalized source — and the
// report carries the submit cause. Sources never submitted after the
// break appear only in the report.
func TestSubmitFailureEmitsCancelledResult(t *testing.T) {
	setChaosKey(t)
	r := newFakeRunner(t, fullScript())
	r.blockKeys = map[string]bool{"subfinder -d example.com -silent": true}
	r.blockStarted = make(chan struct{})
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1 // deterministic: subfinder runs, assetfinder queues, amass blocks in Submit
	cfg.QueueSize = 1
	col := &sourceCollector{}
	cfg.OnSource = col.onSource
	ctx, cancel := context.WithCancel(context.Background())
	var rep Report
	var runErr error
	done := make(chan struct{})
	go func() {
		rep, runErr = Run(ctx, mustDomain(t, "example.com"), cfg)
		close(done)
	}()
	<-r.blockStarted
	cancel()
	<-done
	if runErr != nil {
		t.Fatalf("Run error: %v", runErr)
	}

	// The submit-failed source is amass: third in submission order, behind
	// the running subfinder job and the queued assetfinder job.
	var amass *SourceResult
	for i := range rep.Results {
		if rep.Results[i].Source == "amass" {
			amass = &rep.Results[i]
		}
	}
	if amass == nil {
		t.Fatalf("amass missing from report: %+v", rep.Results)
	}
	if amass.Status != OutCancelled {
		t.Fatalf("amass status = %s, want cancelled", amass.Status)
	}
	if amass.Err == nil || !strings.Contains(amass.Err.Error(), "submit") {
		t.Fatalf("amass must carry the submit cause, got %+v", amass.Err)
	}

	// The failed submission still emitted: observers saw amass finalize
	// with the same cancelled status the report carries.
	var emitted *SourceResult
	amassEvents := 0
	for _, ev := range col.snapshot() {
		if ev.Source == "amass" {
			amassEvents++
			ev := ev
			emitted = &ev
		}
	}
	if amassEvents != 1 {
		t.Fatalf("want exactly one OnSource event for submit-failed amass, got %d (events: %+v)", amassEvents, col.snapshot())
	}
	if emitted == nil {
		t.Fatalf("no OnSource event for submit-failed amass (events: %+v)", col.snapshot())
	}
	if emitted.Status != OutCancelled {
		t.Fatalf("emitted amass status = %s, want cancelled", emitted.Status)
	}
	if emitted.Err == nil || !strings.Contains(emitted.Err.Error(), "submit") {
		t.Fatalf("emitted amass must carry the submit cause, got %+v", emitted.Err)
	}

	// Chaos was never submitted after the break: no event, report-only.
	for _, ev := range col.snapshot() {
		if ev.Source == "chaos" {
			t.Fatalf("chaos was never submitted yet emitted: %+v", ev)
		}
	}
}
