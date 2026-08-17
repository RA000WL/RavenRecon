package tui

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// workerState is the worker dashboard's per-worker record. The state
// vocabulary is the canonical WorkerState set (idle, waiting, running,
// cancelled, failed, completed) and every transition is derived from worker
// and task events ONLY — never from guesses.
//
// Event sources:
//
//   - WorkerStarted -> idle (the worker exists and waits for work)
//   - TaskStarted {Worker} -> waiting (picked up; may still wait for a
//     rate-limit token)
//   - TaskRunning {Worker} -> running (the job body executes)
//   - any terminal task event {Worker, JobID} -> idle again, with the
//     task's real duration (now - task start) and, for failed/timed-out/
//     cancelled tasks, the last error message
//   - WorkerStopped {Worker, State} -> completed / cancelled (terminal:
//     the worker will never pick up another task)
type workerState struct {
	idx       int
	state     event.WorkerState
	jobID     uint64 // current task (0 = none)
	taskStart time.Time
	tasks     int // tasks this worker finished
	lastError string
}

// WorkerDashboard holds every worker's state plus the aggregate counts.
// The worker table is bounded by the pool's real Concurrency (workers
// outside 0..Concurrency-1 are ignored; hostile emitters cannot inflate
// the table).
type WorkerDashboard struct {
	workers map[int]*workerState
	active  int // workers whose state is waiting or running (derived)
}

const maxWorkers = 1 << 16 // hard table bound against hostile worker indices

func newWorkerDashboard() *WorkerDashboard {
	return &WorkerDashboard{workers: make(map[int]*workerState)}
}

// worker returns the record for index i, creating it lazily (bounded by
// maxWorkers; beyond the bound the index is ignored — the pool's own
// concurrency is the real bound).
func (d *WorkerDashboard) worker(i int) *workerState {
	if i < 0 || i >= maxWorkers {
		return nil
	}
	w, ok := d.workers[i]
	if !ok {
		w = &workerState{idx: i, state: event.WorkerIdle}
		d.workers[i] = w
	}
	return w
}

// started marks a worker alive (WorkerStarted).
func (d *WorkerDashboard) started(i int) {
	if w := d.worker(i); w != nil {
		w.state = event.WorkerIdle
	}
}

// taskStarted moves worker i to waiting on job.
func (d *WorkerDashboard) taskStarted(i int, jobID uint64, at time.Time) {
	if w := d.worker(i); w != nil {
		w.state = event.WorkerWaiting
		w.jobID = jobID
		w.taskStart = at
		d.recount()
	}
}

// taskRunning moves worker i to running.
func (d *WorkerDashboard) taskRunning(i int, jobID uint64) {
	if w := d.worker(i); w != nil && w.jobID == jobID {
		w.state = event.WorkerRunning
		d.recount()
	}
}

// taskTerminal returns worker i to idle, recording the task's duration and
// (for failed/timed-out/cancelled tasks) the last error message. Terminal
// events for a job the worker is not currently running are ignored (they
// can only arrive out of order for jobs cancelled before start, which carry
// the same worker index — the guard keeps the table consistent).
func (d *WorkerDashboard) taskTerminal(i int, jobID uint64, at time.Time, failed bool, message string) {
	w := d.worker(i)
	if w == nil || w.jobID != jobID {
		return
	}
	w.tasks++
	w.jobID = 0
	w.taskStart = time.Time{}
	if failed && message != "" {
		w.lastError = message
	}
	w.state = event.WorkerIdle
	d.recount()
}

// stopped records a WorkerStopped terminal state.
func (d *WorkerDashboard) stopped(i int, state event.WorkerState) {
	if w := d.worker(i); w != nil {
		w.state = state
		w.jobID = 0
		w.taskStart = time.Time{}
		d.recount()
	}
}

// recount recomputes the aggregate active count.
func (d *WorkerDashboard) recount() {
	n := 0
	for _, w := range d.workers {
		if w.state == event.WorkerWaiting || w.state == event.WorkerRunning {
			n++
		}
	}
	d.active = n
}

// counts returns the aggregate state counts in the canonical order
// running, waiting, idle, cancelled, failed, completed.
func (d *WorkerDashboard) counts() (running, waiting, idle, cancelled, failed, completed int) {
	for _, w := range d.workers {
		switch w.state {
		case event.WorkerRunning:
			running++
		case event.WorkerWaiting:
			waiting++
		case event.WorkerIdle:
			idle++
		case event.WorkerCancelled:
			cancelled++
		case event.WorkerFailed:
			failed++
		case event.WorkerCompleted:
			completed++
		}
	}
	return
}

// snapshot returns the per-worker rows sorted by worker index (deterministic
// render order).
func (d *WorkerDashboard) snapshot() []workerState {
	out := make([]workerState, 0, len(d.workers))
	for _, w := range d.workers {
		out = append(out, *w)
	}
	// Insertion sort is fine: the table is bounded by the pool's
	// concurrency (small in practice). Deterministic order is the contract.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].idx < out[j-1].idx; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// formatWorkerState renders one worker row deterministically:
// "worker 2 running job 7 3.1s".
func formatWorkerRow(w workerState, now time.Time) string {
	if w.state == event.WorkerIdle || w.state == event.WorkerCompleted ||
		w.state == event.WorkerCancelled || w.state == event.WorkerFailed {
		return fmt.Sprintf("worker %d %s (%d tasks)", w.idx, w.state, w.tasks)
	}
	dur := now.Sub(w.taskStart)
	if dur < 0 {
		dur = 0
	}
	return fmt.Sprintf("worker %d %s job %d %s", w.idx, w.state, w.jobID, formatDuration(dur))
}
