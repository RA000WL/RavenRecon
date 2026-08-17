package tui

import (
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// TestWorkerLifecycle pins the full idle -> waiting -> running -> idle
// transition plus the terminal worker states.
func TestWorkerLifecycle(t *testing.T) {
	d := newWorkerDashboard()
	t0 := testBase

	d.started(0)
	if d.workers[0].state != event.WorkerIdle {
		t.Fatalf("started worker must be idle, got %s", d.workers[0].state)
	}

	d.taskStarted(0, 7, t0)
	w := d.workers[0]
	if w.state != event.WorkerWaiting || w.jobID != 7 || !w.taskStart.Equal(t0) {
		t.Fatalf("task start must move the worker to waiting on job 7: %+v", w)
	}
	if d.active != 1 {
		t.Fatalf("active = %d, want 1", d.active)
	}

	d.taskRunning(0, 7)
	if d.workers[0].state != event.WorkerRunning {
		t.Fatalf("task running must move the worker to running, got %s", d.workers[0].state)
	}

	// A stale terminal event for a different job is ignored.
	d.taskTerminal(0, 99, t0.Add(time.Second), true, "stale")
	if d.workers[0].state != event.WorkerRunning {
		t.Fatalf("stale terminal must be ignored, got %s", d.workers[0].state)
	}

	d.taskTerminal(0, 7, t0.Add(time.Second), false, "")
	w = d.workers[0]
	if w.state != event.WorkerIdle || w.jobID != 0 || w.tasks != 1 {
		t.Fatalf("terminal must return the worker to idle: %+v", w)
	}
	if w.lastError != "" {
		t.Fatalf("clean completion must not record an error, got %q", w.lastError)
	}
	if d.active != 0 {
		t.Fatalf("active = %d, want 0", d.active)
	}

	// A failed task records the error and the duration is not stored (it
	// is derived at render time).
	d.taskStarted(0, 8, t0.Add(2*time.Second))
	d.taskTerminal(0, 8, t0.Add(3*time.Second), true, "boom")
	w = d.workers[0]
	if w.state != event.WorkerIdle || w.tasks != 2 || w.lastError != "boom" {
		t.Fatalf("failed task must return to idle with the error: %+v", w)
	}
}

func TestWorkerStoppedStates(t *testing.T) {
	d := newWorkerDashboard()
	d.started(0)
	d.started(1)
	d.stopped(0, event.WorkerCompleted)
	d.stopped(1, event.WorkerCancelled)

	running, waiting, idle, cancelled, failed, completed := d.counts()
	if running != 0 || waiting != 0 || idle != 0 || cancelled != 1 || failed != 0 || completed != 1 {
		t.Fatalf("counts = %d/%d/%d/%d/%d/%d, want 0/0/0/1/0/1",
			running, waiting, idle, cancelled, failed, completed)
	}
}

func TestWorkerOutOfRangeIndexIgnored(t *testing.T) {
	d := newWorkerDashboard()
	d.started(-1)
	d.started(maxWorkers)
	if len(d.workers) != 0 {
		t.Fatalf("out-of-range worker indices must be ignored, table has %d entries", len(d.workers))
	}
}

func TestWorkerSnapshotSorted(t *testing.T) {
	d := newWorkerDashboard()
	d.started(2)
	d.started(0)
	d.started(1)
	got := d.snapshot()
	if len(got) != 3 || got[0].idx != 0 || got[1].idx != 1 || got[2].idx != 2 {
		t.Fatalf("snapshot must be sorted by worker index: %+v", got)
	}
}

func TestFormatWorkerRow(t *testing.T) {
	t0 := testBase
	// Idle/completed rows show the task count, no job.
	idle := workerState{idx: 3, state: event.WorkerIdle, tasks: 4}
	if got := formatWorkerRow(idle, t0); got != "worker 3 idle (4 tasks)" {
		t.Fatalf("idle row = %q", got)
	}
	// Running rows show the job and the elapsed duration at now.
	running := workerState{idx: 1, state: event.WorkerRunning, jobID: 9, taskStart: t0}
	if got := formatWorkerRow(running, t0.Add(5*time.Second)); got != "worker 1 running job 9 5.0s" {
		t.Fatalf("running row = %q", got)
	}
	// A clock before the task start clamps to zero.
	if got := formatWorkerRow(running, t0.Add(-time.Second)); got != "worker 1 running job 9 0.0s" {
		t.Fatalf("clamped row = %q", got)
	}
}
