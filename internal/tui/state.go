package tui

import (
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// Counts holds the run's cumulative counters, all derived from the consumed
// event stream. They back the final summary and the throughput deltas.
type Counts struct {
	assets        int
	byKind        map[string]int // asset.Kind projections of assets
	findings      int
	rules         int // sum of RuleExecuted.Executions
	relationships int
	requests      int
	cacheHits     int
	cacheMisses   int
	warnings      int
	errors        int
	submitted     int // TaskSubmitted
	started       int // TaskStarted (picked up)
}

// State is the TUI's observable run state: the single deterministic
// projection of the consumed event stream. Every component is a field; the
// renderer is a pure function of (State, now, config).
//
// State is single-consumer: exactly one goroutine applies events and
// renders (the Controller's Run loop, or a test). It is not safe for
// concurrent use and needs no locking.
//
// Every dynamic string is sanitized at ingestion (sanitizeEvent), so the
// state can never hold terminal-corruption bytes.
type State struct {
	progress progressState
	workers  *WorkerDashboard
	rates    *Rates
	counts   Counts
	feed     *InterestingFeed
	errors   *ErrorFeed

	// sample is the resource sampler seam (production: sampleResources;
	// tests inject a fixed sampler for deterministic frames).
	sample func() Resources

	lastCompleted int // Progress.Completed seen so far (task-rate deltas)
}

// NewState returns an empty state with the given interesting-feed admission
// rate (tokens per second).
func NewState(interestingRate float64) *State {
	s := &State{
		workers: newWorkerDashboard(),
		rates:   &Rates{},
		feed:    newInterestingFeed(interestingRate),
		errors:  newErrorFeed(),
		sample:  sampleResources,
	}
	s.counts.byKind = make(map[string]int)
	return s
}

// Apply consumes one event: it sanitizes every dynamic string, routes the
// event to the affected components, and advances the counters. Apply never
// panics on hostile or unexpected payloads (type assertions are guarded);
// the bus already validated the event, and consumers treat invalid events
// as absent.
//
// There is no post-apply re-validation pass: every component enforces its
// own invariants at mutation time (the in-flight and queue-depth clamps,
// the remaining-task clamp, the history/feed/error bounds, the worker
// table bound), so a hostile or replayed stream can at worst produce the
// honest clamped values and never an internally inconsistent state. A
// re-validation pass after apply would re-derive those same clamps by
// construction and add no guarantee, so the invariants are documented here
// instead of re-checked.
func (s *State) Apply(ev event.Event) {
	ev = sanitizeEvent(ev)
	p := s.progress
	if p.firstEvent.IsZero() {
		p.firstEvent = ev.At
	}
	p.lastEventAt = ev.At
	s.progress = p

	switch ev.Kind {
	case event.KindScanStarted:
		s.progress.startedAt = ev.At
	case event.KindScanStopped:
		if pl, ok := ev.Payload.(event.ScanStopped); ok {
			s.progress.outcome = pl.State
		}
		s.progress.endedAt = ev.At
	case event.KindPhaseTransition:
		if pl, ok := ev.Payload.(event.PhaseTransition); ok {
			s.progress.setPhase(pl.Phase)
		}
	case event.KindRunMetadata:
		if pl, ok := ev.Payload.(event.RunMetadata); ok {
			s.progress.target = pl.Target
			s.progress.outputDir = pl.OutputDir
		}
	case event.KindProgress:
		if pl, ok := ev.Payload.(event.Progress); ok {
			s.progress.setProgress(pl.Phase, pl.Completed, pl.Total, pl.TotalKnown)
			if pl.Completed > s.lastCompleted {
				s.rates.recordCum(metricTasks, ev.At, pl.Completed)
				s.lastCompleted = pl.Completed
			}
		}
	case event.KindWorkerStarted:
		if pl, ok := ev.Payload.(event.WorkerStarted); ok {
			s.workers.started(pl.Worker)
		}
	case event.KindWorkerStopped:
		if pl, ok := ev.Payload.(event.WorkerStopped); ok {
			s.workers.stopped(pl.Worker, pl.State)
		}
	case event.KindTaskSubmitted:
		s.counts.submitted++
	case event.KindTaskStarted:
		if pl, ok := ev.Payload.(event.TaskStarted); ok {
			s.workers.taskStarted(pl.Worker, pl.JobID, ev.At)
			s.progress.taskStarted(pl.JobID)
			s.counts.started++
		}
	case event.KindTaskRunning:
		if pl, ok := ev.Payload.(event.TaskRunning); ok {
			s.workers.taskRunning(pl.Worker, pl.JobID)
		}
	case event.KindTaskCompleted:
		if pl, ok := ev.Payload.(event.TaskCompleted); ok {
			s.taskTerminal(pl.Worker, pl.JobID, ev.At, false, "", pl.StartedAt)
		}
	case event.KindTaskCancelled:
		if pl, ok := ev.Payload.(event.TaskCancelled); ok {
			s.taskTerminal(pl.Worker, pl.JobID, ev.At, true, pl.Message, pl.StartedAt)
		}
	case event.KindTaskFailed:
		if pl, ok := ev.Payload.(event.TaskFailed); ok {
			s.taskTerminal(pl.Worker, pl.JobID, ev.At, true, pl.Message, pl.StartedAt)
		}
	case event.KindTaskTimedOut:
		if pl, ok := ev.Payload.(event.TaskTimedOut); ok {
			s.taskTerminal(pl.Worker, pl.JobID, ev.At, true, pl.Message, pl.StartedAt)
		}
	case event.KindAssetDiscovered:
		if pl, ok := ev.Payload.(event.AssetDiscovered); ok {
			s.counts.assets++
			s.counts.byKind[pl.Kind]++
			s.rates.record(metricAssets, ev.At)
			if pl.Kind == "url" {
				s.rates.record(metricURLs, ev.At)
			}
			if pl.Kind == "javascript" {
				s.rates.record(metricJS, ev.At)
			}
			s.feed.add(ev)
		}
	case event.KindRelationshipCreated:
		s.counts.relationships++
		s.rates.record(metricRelationships, ev.At)
	case event.KindFindingCreated:
		s.counts.findings++
		s.feed.add(ev)
	case event.KindRecommendationCreated:
		s.feed.add(ev)
	case event.KindRequestObserved:
		s.counts.requests++
		s.rates.record(metricRequests, ev.At)
	case event.KindRuleExecuted:
		if pl, ok := ev.Payload.(event.RuleExecuted); ok {
			s.counts.rules += pl.Executions
			s.rates.record(metricRules, ev.At)
		}
	case event.KindCacheHit:
		s.counts.cacheHits++
		s.rates.record(metricCacheHits, ev.At)
	case event.KindCacheMiss:
		s.counts.cacheMisses++
		s.rates.record(metricCacheMisses, ev.At)
	case event.KindWarning:
		if pl, ok := ev.Payload.(event.Warning); ok {
			s.counts.warnings++
			s.errors.add(pl.Category, pl.Message, ev.Severity, ev.At)
		}
	case event.KindError:
		if pl, ok := ev.Payload.(event.Error); ok {
			s.counts.errors++
			s.errors.add(pl.Category, pl.Message, ev.Severity, ev.At)
		}
	case event.KindSummaryReady:
		// Notification only; nothing to project.
	}
}

// taskTerminal routes one terminal task event through the shared paths:
// the worker dashboard, the in-flight counter, and the queue-depth
// accounting.
//
// The in-flight counter decrements iff the terminal's JobID was started:
// the runtime emits task_started before the rate-limiter wait, so a
// token-wait-cancelled job terminates with a zero StartedAt yet WAS in
// flight and must decrement, while a never-started job (terminal with no
// prior task_started) never became in-flight and must not. progressState
// tracks the started JobIDs to distinguish the two; the worker dashboard
// already ignores unmatched terminals through its job-mismatch guard.
func (s *State) taskTerminal(worker int, jobID uint64, at time.Time, failed bool, message string, startedAt time.Time) {
	s.workers.taskTerminal(worker, jobID, at, failed, message)
	s.progress.taskTerminal(jobID)
}

// queueDepth is the submitted-but-not-started pool queue depth (pool stats
// derived from task events; clamped at 0 — a hostile or replayed stream can
// never drive it negative).
func (s *State) queueDepth() int {
	d := s.counts.submitted - s.counts.started
	if d < 0 {
		d = 0
	}
	return d
}

// SampleResources takes one resource sample (called at render time only;
// never per event). The sampler seam lets tests inject fixed values.
func (s *State) SampleResources(now time.Time) Resources {
	res := s.sample()
	res.QueueDepth = s.queueDepth()
	res.ActiveWorkers = s.workers.active
	return res
}

// sanitizeEvent strips terminal-corruption vectors from every dynamic
// string of an event (context fields and payload fields), so the state,
// the feeds, and therefore every rendered frame only ever contain clean
// text. The raw job Result of a completed task is deliberately NOT
// sanitized: it is arbitrary engine data that the TUI never renders (only
// the Deriver's canonical events reach the stream, and those are payloads
// handled here).
func sanitizeEvent(ev event.Event) event.Event {
	ev.Phase = Sanitize(ev.Phase)
	ev.Category = Sanitize(ev.Category)
	ev.Identity = Sanitize(ev.Identity)
	ev.Value = Sanitize(ev.Value)
	switch p := ev.Payload.(type) {
	case event.ScanStopped:
		p.State = Sanitize(p.State)
		ev.Payload = p
	case event.WorkerStopped:
		p.State = event.WorkerState(Sanitize(string(p.State)))
		ev.Payload = p
	case event.TaskCompleted:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.TaskCancelled:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.TaskFailed:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.TaskTimedOut:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.CacheAccess:
		p.Key = Sanitize(p.Key)
		p.State = Sanitize(p.State)
		ev.Payload = p
	case event.AssetDiscovered:
		p.Identity = Sanitize(p.Identity)
		p.Kind = Sanitize(p.Kind)
		p.Method = Sanitize(p.Method)
		p.Path = Sanitize(p.Path)
		ev.Payload = p
	case event.RelationshipCreated:
		p.From = Sanitize(p.From)
		p.To = Sanitize(p.To)
		p.Kind = Sanitize(p.Kind)
		ev.Payload = p
	case event.EvidenceCreated:
		p.Identity = Sanitize(p.Identity)
		p.Source = Sanitize(p.Source)
		p.Method = Sanitize(p.Method)
		ev.Payload = p
	case event.FindingCreated:
		p.Identity = Sanitize(p.Identity)
		p.RuleID = Sanitize(p.RuleID)
		p.Subject = Sanitize(p.Subject)
		p.Priority = Sanitize(p.Priority)
		p.Category = Sanitize(p.Category)
		ev.Payload = p
	case event.RecommendationCreated:
		p.Identity = Sanitize(p.Identity)
		p.Text = Sanitize(p.Text)
		p.Level = Sanitize(p.Level)
		ev.Payload = p
	case event.RequestObserved:
		p.Identity = Sanitize(p.Identity)
		p.Method = Sanitize(p.Method)
		ev.Payload = p
	case event.RuleExecuted:
		p.RuleID = Sanitize(p.RuleID)
		ev.Payload = p
	case event.Warning:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.Error:
		p.Category = Sanitize(p.Category)
		p.Message = Sanitize(p.Message)
		ev.Payload = p
	case event.Progress:
		p.Phase = Sanitize(p.Phase)
		ev.Payload = p
	case event.PhaseTransition:
		p.Phase = Sanitize(p.Phase)
		ev.Payload = p
	case event.Shutdown:
		p.Reason = Sanitize(p.Reason)
		ev.Payload = p
	case event.RunMetadata:
		p.Target = Sanitize(p.Target)
		p.OutputDir = Sanitize(p.OutputDir)
		ev.Payload = p
	}
	return ev
}
