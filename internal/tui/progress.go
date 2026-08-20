package tui

import (
	"fmt"
	"time"
)

// progressState is the progress manager: the current phase, the honest task
// totals (completed/remaining/total), the in-flight task count, the run's
// time bounds, and the outcome. UNKNOWN totals are represented by
// totalKnown=false and are rendered as "unknown"/"—"; a percentage is
// never faked.
//
// Event sources: PhaseTransition or StageStarted (phase — the pipeline's
// stage events name the current stage), Progress (totals), TaskStarted /
// terminal task events (in-flight count), ScanStarted / ScanStopped (run
// bounds and outcome), RunMetadata (target).
type progressState struct {
	phase     string // last PhaseTransition.Phase; "" = none yet
	outcome   string // ScanStopped.State; "" = run not concluded
	target    string // RunMetadata.Target; "" = unset
	outputDir string // RunMetadata.OutputDir; "" = unset

	completed  int  // Progress.Completed (last)
	total      int  // Progress.Total (last)
	totalKnown bool // Progress.TotalKnown (last)

	// inFlight is the number of started-but-not-terminated tasks, derived
	// from a bounded set of started JobIDs rather than a bare counter: the
	// runtime emits task_started before the rate-limiter wait, so a
	// token-wait-cancelled job terminates with a zero StartedAt yet WAS in
	// flight and must decrement, while a never-started job (terminal with
	// no prior task_started) never became in-flight and must not.
	// startedIDs is bounded (startedIDCap); a hostile or replayed stream
	// that overflows it flips inFlightUnknown, after which in-flight
	// renders honestly as unknown rather than fabricating a number. A real
	// pool stream normally stays far below the cap — started-but-not-
	// terminated tasks are bounded by the pool's worker count — but a
	// lagging subscriber whose terminal events are dropped (bus drop
	// semantics) can accumulate started IDs beyond that bound, so the cap
	// degrades to honest unknown by design.
	inFlight        int
	startedIDs      map[uint64]struct{}
	inFlightUnknown bool

	startedAt   time.Time // first ScanStarted.At
	firstEvent  time.Time // first observed event (fallback bound)
	endedAt     time.Time // ScanStopped.At
	lastEventAt time.Time
}

// startedIDCap bounds the started-JobID set behind the in-flight counter.
// It is far above any real pool's in-flight bound (worker count) and only
// a hostile or replayed stream can reach it.
const startedIDCap = 4096

// setPhase records a phase transition.
func (p *progressState) setPhase(phase string) { p.phase = phase }

// setProgress records the latest honest progress update.
func (p *progressState) setProgress(phase string, completed, total int, totalKnown bool) {
	p.phase = phase
	p.completed, p.total, p.totalKnown = completed, total, totalKnown
}

// taskStarted records one started task (by JobID): it becomes in-flight.
// A duplicate task_started for the same JobID is counted once.
func (p *progressState) taskStarted(jobID uint64) {
	if p.inFlightUnknown {
		return
	}
	if p.startedIDs == nil {
		p.startedIDs = make(map[uint64]struct{}, 64)
	}
	if _, dup := p.startedIDs[jobID]; dup {
		return
	}
	if len(p.startedIDs) >= startedIDCap {
		// Hostile/replayed stream: refuse to grow; in-flight becomes
		// honestly unknown instead of a wrong number.
		p.inFlightUnknown = true
		p.startedIDs = nil // release the memory; the count is meaningless now
		p.inFlight = 0
		return
	}
	p.startedIDs[jobID] = struct{}{}
	p.inFlight++
}

// taskTerminal records one terminal task (by JobID): a task whose JobID was
// started leaves in-flight; a never-started terminal (no prior
// task_started) never became in-flight and leaves it untouched. The zero
// StartedAt case needs no special casing here: the runtime's
// token-wait-cancelled path emits task_started before the limiter wait, so
// its JobID IS in the set.
func (p *progressState) taskTerminal(jobID uint64) {
	if p.inFlightUnknown {
		return
	}
	if _, ok := p.startedIDs[jobID]; !ok {
		return
	}
	delete(p.startedIDs, jobID)
	if p.inFlight > 0 {
		p.inFlight--
	}
}

// inFlightCount returns the in-flight task count and whether it is known.
// A hostile stream that overflowed the started-ID set makes it unknown,
// rendered honestly as "unknown" rather than a fabricated number.
func (p *progressState) inFlightCount() (int, bool) {
	if p.inFlightUnknown {
		return 0, false
	}
	return p.inFlight, true
}

// remaining returns the remaining task count when the total is known.
func (p *progressState) remaining() (int, bool) {
	if !p.totalKnown {
		return 0, false
	}
	r := p.total - p.completed
	if r < 0 {
		r = 0
	}
	return r, true
}

// elapsed returns the run's elapsed duration at now and whether a start
// bound is known. Before the first event there is no run yet ("—").
func (p *progressState) elapsed(now time.Time) (time.Duration, bool) {
	if p.startedAt.IsZero() && p.firstEvent.IsZero() {
		return 0, false
	}
	start := p.startedAt
	if start.IsZero() {
		start = p.firstEvent
	}
	if now.Before(start) {
		now = start
	}
	return now.Sub(start), true
}

// eta estimates the remaining wall time: remaining tasks divided by the
// rolling task completion rate. Insufficient signal (unknown total, no
// rate, zero rate) yields an honest unknown; a run that is already complete
// yields zero. The estimator never divides by zero and never fabricates
// certainty: the returned duration is a point estimate of "at the current
// rate".
func (p *progressState) eta(now time.Time, rates *Rates) (time.Duration, bool) {
	remaining, ok := p.remaining()
	if !ok {
		return 0, false
	}
	if remaining <= 0 {
		return 0, true
	}
	r := rates.rate(metricTasks, now)
	if r <= 0 {
		return 0, false
	}
	return time.Duration(float64(remaining) / r * float64(time.Second)), true
}

// formatDuration renders a duration deterministically: sub-minute values
// as "12.3s", minutes as "1m23s", hours as "1h05m". The golden render
// tests pin the exact forms.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := d.Seconds()
	switch {
	case secs < 60:
		return fmt.Sprintf("%.1fs", secs)
	case secs < 3600:
		m := int(secs) / 60
		s := int(secs) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		h := int(secs) / 3600
		m := (int(secs) / 60) % 60
		return fmt.Sprintf("%dh%02dm", h, m)
	}
}
