package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// scriptedRun is the canonical full-run stream used across state and
// render tests. Every timestamp is derived from testBase, so renders are
// deterministic.
func scriptedRun() []event.Event {
	return []event.Event{
		ev(event.KindScanStarted, 0, event.ScanStarted{Concurrency: 2, QueueSize: 16}),
		ev(event.KindRunMetadata, 1, event.RunMetadata{Target: "example.com", OutputDir: "/tmp/out"}),
		ev(event.KindPhaseTransition, 2, event.PhaseTransition{Phase: "discovery"}),
		ev(event.KindWorkerStarted, 3, event.WorkerStarted{Worker: 0}),
		ev(event.KindWorkerStarted, 3, event.WorkerStarted{Worker: 1}),
		ev(event.KindTaskSubmitted, 4, event.TaskSubmitted{JobID: 1}),
		ev(event.KindTaskSubmitted, 4, event.TaskSubmitted{JobID: 2}),
		ev(event.KindTaskSubmitted, 4, event.TaskSubmitted{JobID: 3}),
		ev(event.KindTaskStarted, 5, event.TaskStarted{JobID: 1, Worker: 0}),
		ev(event.KindTaskRunning, 5, event.TaskRunning{JobID: 1, Worker: 0}),
		ev(event.KindProgress, 6, event.Progress{Phase: "discovery", Completed: 0, Total: 3, TotalKnown: true}),
		ev(event.KindTaskCompleted, 7, event.TaskCompleted{TaskTerminal: event.NewTaskTerminal(1, 0, testBase.Add(5*time.Millisecond), "", "")}),
		ev(event.KindTaskStarted, 8, event.TaskStarted{JobID: 2, Worker: 1}),
		ev(event.KindAssetDiscovered, 9, event.AssetDiscovered{Identity: "host:example.com", Kind: "host"}),
		ev(event.KindAssetDiscovered, 10, event.AssetDiscovered{Identity: "url:https://example.com", Kind: "url", Path: "/"}),
		ev(event.KindAssetDiscovered, 11, event.AssetDiscovered{Identity: "endpoint:https://example.com/graphql", Kind: "endpoint", Method: "GQL", Path: "/graphql"}),
		ev(event.KindProgress, 12, event.Progress{Phase: "discovery", Completed: 1, Total: 3, TotalKnown: true}),
		ev(event.KindRequestObserved, 13, event.RequestObserved{Identity: "url:https://example.com", Method: "GET"}),
		ev(event.KindCacheHit, 14, event.CacheAccess{Key: "abc", State: "hit", Hit: true}),
		ev(event.KindCacheMiss, 15, event.CacheAccess{Key: "def", State: "miss", Hit: false}),
		ev(event.KindRuleExecuted, 16, event.RuleExecuted{RuleID: "r1", Executions: 2}),
		ev(event.KindRelationshipCreated, 17, event.RelationshipCreated{From: "host:example.com", To: "ip:1.2.3.4", Kind: "host_to_ip"}),
		ev(event.KindFindingCreated, 18, event.FindingCreated{
			Identity: "finding:r1@url:https://example.com", RuleID: "r1",
			Subject: "url:https://example.com", Priority: "high", Category: "misconfig", Confidence: 0.9,
		}),
		ev(event.KindRecommendationCreated, 19, event.RecommendationCreated{
			Identity: "host:example.com", Text: "investigate admin surface", Level: "high", Weight: 0.8,
		}),
		ev(event.KindWarning, 20, event.NewWarning("timeout", "slow")).WithSeverity(event.SeverityWarning),
		ev(event.KindError, 21, event.NewError("dns", "nxdomain")).WithSeverity(event.SeverityError),
		ev(event.KindTaskStarted, 22, event.TaskStarted{JobID: 3, Worker: 0}),
		ev(event.KindTaskRunning, 23, event.TaskRunning{JobID: 2, Worker: 1}),
		ev(event.KindProgress, 24, event.Progress{Phase: "discovery", Completed: 2, Total: 3, TotalKnown: true}),
		ev(event.KindTaskCompleted, 25, event.TaskCompleted{TaskTerminal: event.NewTaskTerminal(2, 1, testBase.Add(8*time.Millisecond), "", "")}),
		ev(event.KindTaskCompleted, 26, event.TaskCompleted{TaskTerminal: event.NewTaskTerminal(3, 0, testBase.Add(22*time.Millisecond), "", "")}),
		ev(event.KindProgress, 27, event.Progress{Phase: "discovery", Completed: 3, Total: 3, TotalKnown: true}),
		ev(event.KindWorkerStopped, 28, event.WorkerStopped{Worker: 0, State: event.WorkerCompleted}),
		ev(event.KindWorkerStopped, 28, event.WorkerStopped{Worker: 1, State: event.WorkerCompleted}),
		ev(event.KindShutdown, 29, event.Shutdown{Reason: "graceful", Dropped: 0}),
		ev(event.KindScanStopped, 10000, event.ScanStopped{State: "completed"}),
	}
}

// applyScript applies a stream to a fresh state and returns it.
func applyScript(t *testing.T, stream []event.Event) *State {
	t.Helper()
	s := NewState(highRate)
	for _, e := range stream {
		s.Apply(e)
	}
	return s
}

// TestStateInFlightSkipsNeverStartedCancellations pins the cancelled-
// before-start case: a terminal task event whose StartedAt is zero
// describes a job that never started (the runtime pool's terminal events
// carry zero StartedAt for exactly that case), so it must not decrement
// the in-flight counter — a job that never became in-flight cannot be
// taken out of it. Before the fix, such terminals under-reported
// in-flight work on every cancelled-before-start job.
func TestStateInFlightSkipsNeverStartedCancellations(t *testing.T) {
	s := NewState(highRate)

	// A cancelled-before-start terminal with a zero StartedAt: in-flight
	// stays 0 (never started, never in flight).
	s.Apply(ev(event.KindTaskCancelled, 0, event.TaskCancelled{
		TaskTerminal: event.NewTaskTerminal(7, 0, time.Time{}, "cancellation", "cancelled before start"),
	}))
	if s.progress.inFlight != 0 {
		t.Fatalf("in-flight = %d, want 0 (a never-started job must not decrement)", s.progress.inFlight)
	}

	// A real started task: in-flight rises on start...
	s.Apply(ev(event.KindTaskStarted, 1, event.TaskStarted{JobID: 1, Worker: 0}))
	if s.progress.inFlight != 1 {
		t.Fatalf("in-flight = %d, want 1 after a real start", s.progress.inFlight)
	}
	// ...and a never-started cancellation while it runs leaves it at 1.
	s.Apply(ev(event.KindTaskCancelled, 2, event.TaskCancelled{
		TaskTerminal: event.NewTaskTerminal(8, 1, time.Time{}, "cancellation", "cancelled before start"),
	}))
	if s.progress.inFlight != 1 {
		t.Fatalf("in-flight = %d, want 1 (a never-started terminal must not decrement a real one)", s.progress.inFlight)
	}
	// The real task's own terminal (with its real StartedAt) decrements it.
	s.Apply(ev(event.KindTaskCompleted, 3, event.TaskCompleted{
		TaskTerminal: event.NewTaskTerminal(1, 0, testBase.Add(time.Millisecond), "", ""),
	}))
	if s.progress.inFlight != 0 {
		t.Fatalf("in-flight = %d, want 0 after the real terminal", s.progress.inFlight)
	}
}

// TestStateApplyCounters pins every counter projection of the scripted
// run.
func TestStateApplyCounters(t *testing.T) {
	s := applyScript(t, scriptedRun())
	c := s.counts

	if c.assets != 3 {
		t.Fatalf("assets = %d, want 3", c.assets)
	}
	if c.byKind["host"] != 1 || c.byKind["url"] != 1 || c.byKind["endpoint"] != 1 {
		t.Fatalf("byKind = %v", c.byKind)
	}
	if c.findings != 1 || c.rules != 2 || c.relationships != 1 || c.requests != 1 {
		t.Fatalf("findings/rules/relationships/requests = %d/%d/%d/%d, want 1/2/1/1",
			c.findings, c.rules, c.relationships, c.requests)
	}
	if c.cacheHits != 1 || c.cacheMisses != 1 {
		t.Fatalf("cache hits/misses = %d/%d, want 1/1", c.cacheHits, c.cacheMisses)
	}
	if c.warnings != 1 || c.errors != 1 {
		t.Fatalf("warnings/errors = %d/%d, want 1/1", c.warnings, c.errors)
	}
	if c.submitted != 3 || c.started != 3 {
		t.Fatalf("submitted/started = %d/%d, want 3/3", c.submitted, c.started)
	}

	// Progress projections.
	if s.progress.phase != "discovery" {
		t.Fatalf("phase = %q, want discovery", s.progress.phase)
	}
	if s.progress.completed != 3 || s.progress.total != 3 || !s.progress.totalKnown {
		t.Fatalf("progress = %d/%d known=%v", s.progress.completed, s.progress.total, s.progress.totalKnown)
	}
	if s.progress.outcome != "completed" {
		t.Fatalf("outcome = %q, want completed", s.progress.outcome)
	}
	if s.progress.target != "example.com" || s.progress.outputDir != "/tmp/out" {
		t.Fatalf("target/outputDir = %q/%q", s.progress.target, s.progress.outputDir)
	}
	if s.progress.inFlight != 0 {
		t.Fatalf("in-flight = %d, want 0", s.progress.inFlight)
	}
	if s.queueDepth() != 0 {
		t.Fatalf("queue depth = %d, want 0", s.queueDepth())
	}

	// The interesting feed admitted the GQL endpoint, the high finding,
	// and the high recommendation.
	if got := s.feed.snapshot(); len(got) != 3 {
		t.Fatalf("feed len = %d, want 3", len(got))
	}
	// The error feed grouped both observations.
	if got := s.errors.snapshot(); len(got) != 2 {
		t.Fatalf("error feed len = %d, want 2", len(got))
	}
}

// TestStateQueueDepthClamp pins that a hostile or replayed stream can
// never drive the queue depth negative.
func TestStateQueueDepthClamp(t *testing.T) {
	s := NewState(highRate)
	s.Apply(ev(event.KindTaskStarted, 0, event.TaskStarted{JobID: 1, Worker: 0}))
	if d := s.queueDepth(); d != 0 {
		t.Fatalf("queue depth = %d, want clamped 0", d)
	}
	s.Apply(ev(event.KindTaskSubmitted, 0, event.TaskSubmitted{JobID: 1}))
	s.Apply(ev(event.KindTaskSubmitted, 0, event.TaskSubmitted{JobID: 2}))
	if d := s.queueDepth(); d != 1 {
		t.Fatalf("queue depth = %d, want 1 (one submit slot was already started)", d)
	}
}

// TestStateSampleResources pins the render-time sampler seam: the state's
// own queue depth and active-worker count override the injected sampler.
func TestStateSampleResources(t *testing.T) {
	s := NewState(highRate)
	s.sample = func() Resources {
		return Resources{HeapBytes: 12 << 20, Goroutines: 42, OpenFDs: 17, QueueDepth: 99, ActiveWorkers: 99}
	}
	s.Apply(ev(event.KindTaskSubmitted, 0, event.TaskSubmitted{JobID: 1}))
	s.Apply(ev(event.KindTaskStarted, 1, event.TaskStarted{JobID: 1, Worker: 0}))

	res := s.SampleResources(testBase)
	if res.HeapBytes != 12<<20 || res.Goroutines != 42 || res.OpenFDs != 17 {
		t.Fatalf("sampler values not preserved: %+v", res)
	}
	if res.QueueDepth != 0 || res.ActiveWorkers != 1 {
		t.Fatalf("derived values not applied: %+v", res)
	}
}

// TestStateSummary pins the final run summary of the scripted run.
func TestStateSummary(t *testing.T) {
	s := applyScript(t, scriptedRun())
	sum := s.Summary()
	if sum.Assets != 3 || sum.Hosts != 1 || sum.URLs != 1 || sum.Endpoints != 1 {
		t.Fatalf("asset summary = %+v", sum)
	}
	if sum.Technologies != 0 || sum.Secrets != 0 || sum.SourceMaps != 0 {
		t.Fatalf("per-kind summary = %+v", sum)
	}
	if sum.Findings != 1 || sum.Rules != 2 || sum.Relationships != 1 || sum.Requests != 1 {
		t.Fatalf("finding/rule summary = %+v", sum)
	}
	if sum.CacheHits != 1 || sum.CacheMisses != 1 || sum.Warnings != 1 || sum.Errors != 1 {
		t.Fatalf("cache/warning summary = %+v", sum)
	}
	if !sum.StartedAt.Equal(testBase) || !sum.EndedAt.Equal(testBase.Add(10*time.Second)) {
		t.Fatalf("time bounds = %v..%v", sum.StartedAt, sum.EndedAt)
	}
	if sum.Duration != 10*time.Second {
		t.Fatalf("duration = %v, want 10s", sum.Duration)
	}
	if sum.Outcome != "completed" || sum.Target != "example.com" || sum.OutputDir != "/tmp/out" {
		t.Fatalf("outcome/target/output = %+v", sum)
	}
}

// TestStateSummaryUnknowns pins the honest unknowns of an empty stream.
func TestStateSummaryUnknowns(t *testing.T) {
	s := NewState(highRate)
	sum := s.Summary()
	if sum.Outcome != "" || sum.Duration != 0 || !sum.StartedAt.IsZero() {
		t.Fatalf("empty stream summary must be all unknowns: %+v", sum)
	}
}

// TestStateApplyHostileEvents pins that Apply never panics on hostile or
// mismatched events and sanitizes every dynamic string at ingestion.
func TestStateApplyHostileEvents(t *testing.T) {
	s := NewState(highRate)
	hostile := []event.Event{
		// Mismatched payload types are guarded by type assertions.
		ev(event.KindAssetDiscovered, 0, event.ScanStarted{}),
		ev(event.KindWarning, 0, event.TaskFailed{TaskTerminal: event.NewTaskTerminal(1, 0, testBase, "c", "m")}),
		// An unknown kind falls through the switch.
		{Kind: event.Kind("bogus"), At: testBase},
		// A nil payload cannot panic the type switches.
		{Kind: event.KindCacheHit, At: testBase},
		// Hostile control bytes are stripped from context and payload.
		ev(event.KindAssetDiscovered, 0, event.AssetDiscovered{
			Identity: "url:\x1b[31mhttps://example.com", Kind: "url\x00", Path: "/x\x1b]0;t\x07",
		}).WithPhase("phase\x1b[1m").WithIdentity("id\x1b").WithValue("v\x1b"),
		ev(event.KindError, 0, event.NewError("cat\x1b[31m", "msg\x1b[2J")).WithCategory("cat\x1b"),
	}
	for _, e := range hostile {
		s.Apply(e) // must not panic
	}
	// The hostile strings never reach the state.
	if strings.ContainsAny(s.progress.phase, "\x1b\x00") {
		t.Fatalf("phase must be sanitized, got %q", s.progress.phase)
	}
	if got := s.errors.snapshot(); len(got) > 0 {
		for _, g := range got {
			if strings.Contains(g.category+g.latestMsg, "\x1b") {
				t.Fatalf("error feed must be sanitized: %+v", g)
			}
		}
	}
	// Hostile asset events with the right payload type still count.
	if s.counts.assets != 1 {
		t.Fatalf("assets = %d, want 1 (mismatched payloads must be ignored)", s.counts.assets)
	}
}

// TestSanitizeEventPins the per-payload sanitization coverage of every
// string field the state renders.
func TestSanitizeEvent(t *testing.T) {
	hostile := "\x1b[31m"
	ev := event.New(event.KindRunMetadata, testBase, event.RunMetadata{
		Target: "target" + hostile, OutputDir: "/out" + hostile,
	}).WithPhase("p" + hostile).WithCategory("c" + hostile).WithIdentity("i" + hostile).WithValue("v" + hostile)
	clean := sanitizeEvent(ev)
	for _, s := range []string{clean.Phase, clean.Category, clean.Identity, clean.Value} {
		if strings.Contains(s, "\x1b") {
			t.Fatalf("context field must be sanitized, got %q", s)
		}
	}
	meta := clean.Payload.(event.RunMetadata)
	if strings.Contains(meta.Target, "\x1b") || strings.Contains(meta.OutputDir, "\x1b") {
		t.Fatalf("payload fields must be sanitized, got %+v", meta)
	}
}

// TestStateApplyOutOfOrder pins robustness to replayed or reordered
// streams: a terminal task event for a job no worker is running is
// ignored by the dashboard and cannot drive the in-flight counter
// negative.
func TestStateApplyOutOfOrder(t *testing.T) {
	s := NewState(highRate)
	s.Apply(ev(event.KindTaskCompleted, 0, event.TaskCompleted{
		TaskTerminal: event.NewTaskTerminal(1, 0, testBase, "", ""),
	}))
	if s.progress.inFlight != 0 {
		t.Fatalf("in-flight must stay 0, got %d", s.progress.inFlight)
	}
	if w := s.workers.workers[0]; w == nil || w.state != event.WorkerIdle || w.tasks != 0 {
		t.Fatalf("unknown job terminal must not touch the worker: %+v", w)
	}
}
