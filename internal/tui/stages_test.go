package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// stageStarted mirrors the pipeline runner's stage_started emission
// (internal/pipeline/run.go emitStageStarted): a StageStarted payload with
// Phase "stage" and the stage name as Identity, at testBase+ms.
func stageStarted(ms int, name string) event.Event {
	return ev(event.KindStageStarted, ms, event.StageStarted{Name: name}).
		WithPhase("stage").WithIdentity(name)
}

// stageFinished mirrors the pipeline runner's stage_finished emission
// (internal/pipeline/run.go emitStageFinished): a StageFinished payload
// (via event.NewStageFinished) with Phase "stage" and the stage name as
// Identity, at testBase+ms.
func stageFinished(ms int, name, outcome string, truncated bool, processed, failed int, dur time.Duration, errMsg string) event.Event {
	return ev(event.KindStageFinished, ms,
		event.NewStageFinished(name, outcome, truncated, processed, failed, dur, errMsg)).
		WithPhase("stage").WithIdentity(name)
}

// stageStream is the canonical production stage-event stream: the ten
// pipeline stages (discover → report) in order, each an alternating
// started/finished pair, exactly as pipeline.Run emits them on a healthy
// full run. The outcome/counter values are scenario data; the event SHAPE
// (kinds, payload types, context fields) is the pinned contract.
func stageStream() []event.Event {
	return []event.Event{
		stageStarted(0, "discover"),
		stageFinished(5, "discover", "completed", false, 5, 0, 10*time.Second, ""),
		stageStarted(10, "dns"),
		stageFinished(15, "dns", "completed", false, 2, 0, 20*time.Second, ""),
		stageStarted(20, "httpprobe"),
		stageFinished(25, "httpprobe", "completed", false, 4, 1, 30*time.Second, ""),
		stageStarted(30, "urlintel"),
		stageFinished(35, "urlintel", "failed", false, 7, 2, 40*time.Second, "waymore failed"),
		stageStarted(40, "techintel"),
		stageFinished(45, "techintel", "completed", false, 3, 0, 50*time.Second, ""),
		stageStarted(50, "jsintel"),
		stageFinished(55, "jsintel", "completed", false, 1, 0, 60*time.Second, ""),
		stageStarted(60, "secrentel"),
		stageFinished(65, "secrentel", "partial", true, 2, 0, 70*time.Second, ""),
		stageStarted(70, "priority"),
		stageFinished(75, "priority", "completed", false, 2, 0, 80*time.Second, ""),
		stageStarted(80, "detect"),
		stageFinished(85, "detect", "completed", false, 0, 0, 90*time.Second, ""),
		stageStarted(90, "report"),
		stageFinished(95, "report", "completed", false, 0, 0, 100*time.Second, ""),
	}
}

// TestStateStageProjection pins the stage-event projection: starting a
// stage sets the phase and the stage-start time, finishing one advances
// the completed counter and appends the ordered record — and the last
// started stage survives its finished event as the phase, so the final
// frame (rendered after the stream ends, typically right after the last
// stage_finished) names the last stage instead of falling back to "phase
// —". A stage-only stream must also leave the task/worker/rate widgets
// untouched (their gates stay closed) and must not fabricate a stage
// total.
func TestStateStageProjection(t *testing.T) {
	s := NewState(highRate)
	for _, e := range stageStream() {
		s.Apply(e)
	}
	if s.progress.phase != "report" {
		t.Fatalf("phase = %q, want report (the last started stage survives its finished)", s.progress.phase)
	}
	if s.stages.startedCount != 10 || s.stages.completedCount != 10 {
		t.Fatalf("stage counters = %d/%d, want 10/10", s.stages.startedCount, s.stages.completedCount)
	}
	if s.stages.current != "report" {
		t.Fatalf("current = %q, want report", s.stages.current)
	}
	if !s.stages.startedAt.Equal(testBase.Add(90 * time.Millisecond)) {
		t.Fatalf("current stage start = %v, want t0+90ms", s.stages.startedAt)
	}
	if len(s.stages.records) != 10 {
		t.Fatalf("finished list = %d entries, want 10", len(s.stages.records))
	}
	first, last := s.stages.records[0], s.stages.records[9]
	if first.name != "discover" || first.outcome != "completed" || first.itemsProcessed != 5 || first.duration != 10*time.Second {
		t.Fatalf("first finished record = %+v", first)
	}
	if last.name != "report" || last.outcome != "completed" || last.itemsFailed != 0 {
		t.Fatalf("last finished record = %+v", last)
	}
	u := s.stages.records[3]
	if u.name != "urlintel" || u.outcome != "failed" || u.itemsProcessed != 7 || u.itemsFailed != 2 || u.err != "waymore failed" {
		t.Fatalf("urlintel record = %+v (failure fields must survive)", u)
	}
	if s.taskEvents || s.rateEvents {
		t.Fatalf("a stage-only stream must not open the task/rate gates (task=%v rate=%v)", s.taskEvents, s.rateEvents)
	}
	if s.progress.completed != 0 || s.progress.total != 0 || s.progress.totalKnown {
		t.Fatalf("task progress must stay untouched by stage events: %+v", s.progress)
	}
}

// TestStateProgressOnlyKeepsRateGateClosed: a Progress-only stream must
// not open the throughput gate — the frame carries no throughput line.
func TestStateProgressOnlyKeepsRateGateClosed(t *testing.T) {
	s := NewState(highRate)
	for i := 0; i < 5; i++ {
		s.Apply(ev(event.KindProgress, i*10, event.Progress{Phase: "dns", Completed: i + 1, Total: 10, TotalKnown: true}))
	}
	if s.rateEvents {
		t.Fatal("KindProgress alone must not open the throughput gate")
	}
	frame := Render(s, testBase.Add(5*time.Second), Options{})
	if strings.Contains(frame, "throughput") {
		t.Fatalf("frame must not render a throughput line without a rate-recording event:\n%s", frame)
	}
}

// TestStateStageEventsThroughConsume pins the production ingestion path:
// the real stage-event stream through the controller's consume (sanitize
// → history → Apply) produces the same projections as direct Apply and
// advances the consumed counter.
func TestStateStageEventsThroughConsume(t *testing.T) {
	c, _, _ := newTestController(t, &syncWriter{})
	for _, e := range stageStream() {
		c.consume(e)
	}
	if c.consumed != 20 {
		t.Fatalf("consumed = %d, want 20", c.consumed)
	}
	if c.state.progress.phase != "report" {
		t.Fatalf("phase = %q, want report", c.state.progress.phase)
	}
	if c.state.stages.completedCount != 10 || c.state.stages.startedCount != 10 {
		t.Fatalf("stage counters = %d/%d, want 10/10", c.state.stages.startedCount, c.state.stages.completedCount)
	}
	if got := c.state.Summary(); len(got.Stages) != 10 || got.StagesCompleted != 10 || got.CurrentStage != "" {
		t.Fatalf("summary stage projection = %+v", got)
	}
}

// TestStateStageSanitization pins that hostile stage payloads are
// sanitized at ingestion: control bytes in a stage name, outcome, or error
// can never reach the phase, the stage list, or a frame.
func TestStateStageSanitization(t *testing.T) {
	c, _, _ := newTestController(t, &syncWriter{})
	c.consume(ev(event.KindStageStarted, 0, event.StageStarted{Name: "discover\x1b[31m"}).WithPhase("stage"))
	c.consume(ev(event.KindStageFinished, 5,
		event.NewStageFinished("dns\x1b[31m", "completed\x00", false, 1, 0, time.Second, "err\x1b[2J")).
		WithPhase("stage"))
	if strings.ContainsAny(c.state.progress.phase, "\x1b\x00") {
		t.Fatalf("phase must be sanitized, got %q", c.state.progress.phase)
	}
	for _, r := range c.state.stages.records {
		if strings.ContainsAny(r.name+r.outcome+r.err, "\x1b\x00") {
			t.Fatalf("stage records must be sanitized: %+v", r)
		}
	}
	if strings.ContainsAny(c.state.Summary().CurrentStage, "\x1b\x00") {
		t.Fatal("summary current stage must be sanitized")
	}
}

// TestStateStageListBound pins the stage-list bound: a hostile or replayed
// stream with unbounded stage events caps the retained list at
// maxStageRecords while the counters stay exact (loss is bounded and
// measurable, never silent growth).
func TestStateStageListBound(t *testing.T) {
	s := NewState(highRate)
	for i := 0; i < maxStageRecords+10; i++ {
		name := twoDigit(i)
		s.Apply(stageStarted(i*2, name))
		s.Apply(stageFinished(i*2+1, name, "completed", false, 0, 0, time.Second, ""))
	}
	if s.stages.completedCount != maxStageRecords+10 || s.stages.startedCount != maxStageRecords+10 {
		t.Fatalf("counters must stay exact: started=%d completed=%d", s.stages.startedCount, s.stages.completedCount)
	}
	if len(s.stages.records) != maxStageRecords {
		t.Fatalf("finished list = %d entries, want the bound %d", len(s.stages.records), maxStageRecords)
	}
	if s.stages.records[0].name != "00" {
		t.Fatalf("the list must keep the run's beginning, got first entry %q", s.stages.records[0].name)
	}
}

// TestRenderStageFrameHonestDegradation pins the honest degradation (the
// acceptance criterion): a stage-only stream — the production shape —
// renders a live stage feed (title, phase naming the current stage, stage
// progress, tasks in the honest unknown form, elapsed, resources) and
// OMITS the worker and throughput sections entirely instead of rendering a
// fabricated zero dashboard, a fabricated queue, or all-zero rates. A
// percentage and a stage total are never faked.
func TestRenderStageFrameHonestDegradation(t *testing.T) {
	s := NewState(highRate)
	// Mid-run: five stages concluded, jsintel in flight.
	for _, e := range stageStream()[:11] {
		s.Apply(e)
	}
	fixedResources(s)
	frame := Render(s, testBase.Add(5*time.Second), Options{})

	for _, want := range []string{
		"ravenrecon — untitled run",
		"phase jsintel",
		"stages 5/unknown",
		"tasks 0/unknown",
		"elapsed 5.0s",
		"resources heap",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame must contain %q:\n%s", want, frame)
		}
	}
	for _, forbidden := range []string{"workers running", "queue depth", "throughput"} {
		if strings.Contains(frame, forbidden) {
			t.Fatalf("frame must not contain %q (no data source; never fabricated zeros):\n%s", forbidden, frame)
		}
	}
	if strings.Contains(frame, "%") || strings.Contains(frame, "stages 5/10") {
		t.Fatalf("frame must never fake a percentage or a stage total:\n%s", frame)
	}
}

// TestRenderStageFinalSummary pins the final frame of a stage-only run:
// the live part keeps the last stage as the phase, and the summary carries
// the bounded stage list in pipeline order with honest outcomes, counters,
// truncation markers, and errors — while the outcome lane stays the
// stream's own (the production pipeline emits no scan_stopped, so it must
// render "—", never a fabricated completion).
func TestRenderStageFinalSummary(t *testing.T) {
	s := applyScript(t, stageStream())
	fixedResources(s)
	frame := RenderFinal(s, testBase.Add(5*time.Second), Options{})

	if !strings.Contains(frame, "phase report") {
		t.Fatalf("final frame must keep the last stage as the phase:\n%s", frame)
	}
	if !strings.Contains(frame, "stages 10/unknown") {
		t.Fatalf("final frame must show the completed stage progress:\n%s", frame)
	}
	for _, want := range []string{
		"── summary ──",
		"stages completed 10 · current —",
		"  discover completed · 5 processed · 0 failed · 10.0s",
		"  dns completed · 2 processed · 0 failed · 20.0s",
		"  urlintel failed · 7 processed · 2 failed · 40.0s · err: waymore failed",
		"  secrentel partial · 2 processed · 0 failed · 1m10s · truncated",
		"  report completed · 0 processed · 0 failed · 1m40s",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("final frame must contain %q:\n%s", want, frame)
		}
	}
	if !strings.Contains(frame, "outcome —") {
		t.Fatalf("final frame must keep the honest unknown outcome (no scan_stopped was consumed):\n%s", frame)
	}
}

// TestRenderStagePlusTaskStreamMixed pins the mixed stream — the section
// gates' hard case: when BOTH stage events and task/worker/rate events
// exist, the live stage feed AND the worker/throughput sections all
// render. The gates open on their own data sources, never on the absence
// of data elsewhere.
func TestRenderStagePlusTaskStreamMixed(t *testing.T) {
	s := NewState(highRate)
	for _, e := range scriptedRun() {
		s.Apply(e)
	}
	for _, e := range stageStream() {
		s.Apply(e)
	}
	fixedResources(s)
	frame := Render(s, testBase.Add(10*time.Second), Options{})

	for _, want := range []string{
		"ravenrecon — example.com",
		"phase report", // the stage stream's last started stage wins the phase
		"stages 10/unknown",
		"workers running 0", // the scriptedRun's worker events open the dashboard
		"queue depth 0",
		"throughput assets",
		"worker 0 completed (2 tasks)",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("mixed frame must contain %q:\n%s", want, frame)
		}
	}
}

// TestControllerStageStreamLiveFrame is the controller-level render-content
// test (the missing coverage in the v1.4 wiring tests, which asserted
// transport only): a real stage-event stream through the bus with
// fake-clock ticks produces live frames whose phase names the current
// stage and whose worker/throughput sections are absent, and the concluded
// run's final frame carries the stage summary with the in-flight stage
// named honestly.
func TestControllerStageStreamLiveFrame(t *testing.T) {
	buf := &syncWriter{}
	c, bus, sub := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// Publish the full production stage stream, then end the run with
	// the secrentel stage in flight (started, not finished).
	for _, e := range stageStream() {
		bus.Publish(e)
	}
	bus.Publish(stageStarted(60, "secrentel"))
	for i := 0; i < 21; i++ {
		waitConsumed(t, c)
	}

	c.clock.(*fakeClock).tick <- testBase.Add(5 * time.Second)
	waitFor(t, 2*time.Second, "live frame rendered", func() bool { return buf.frameCount() == 1 })

	if !strings.Contains(buf.text(), "phase secrentel") {
		t.Fatalf("live frame must name the current stage:\n%s", buf.text())
	}
	if !strings.Contains(buf.text(), "stages 10/unknown") {
		t.Fatalf("live frame must show the completed stage progress:\n%s", buf.text())
	}
	for _, forbidden := range []string{"workers running", "queue depth", "throughput"} {
		if strings.Contains(buf.text(), forbidden) {
			t.Fatalf("live frame must not render %q with no task/worker events:\n%s", forbidden, buf.text())
		}
	}

	// Conclude: closing the subscriber ends the loop; finish drains and
	// renders the final summary frame from the populated state.
	sub.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run must return nil on subscriber close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the subscriber closed")
	}
	if c.consumed != 21 {
		t.Fatalf("consumed = %d, want 21", c.consumed)
	}
	final := buf.text()
	if !strings.Contains(final, "── summary ──") {
		t.Fatalf("final frame must carry the summary:\n%s", final)
	}
	if !strings.Contains(final, "stages completed 10 · current secrentel") {
		t.Fatalf("final frame must report the in-flight stage honestly:\n%s", final)
	}
	if !strings.Contains(final, "  dns completed · 2 processed · 0 failed · 20.0s") {
		t.Fatalf("final frame must carry the stage list:\n%s", final)
	}
}
