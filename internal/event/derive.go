package event

import "sync/atomic"

// Deriver converts the raw result of a completed pool job into canonical
// derived events (asset discovered, finding created, relationship created,
// ...). Engine packages never emit derived events themselves: the
// pool-job-boundary bridge (Deriving) holds the Deriver and derives at the
// boundary, so engines stay observer-free while the event stream stays
// canonical.
//
// Implementations must:
//
//   - return nil (or an empty slice) for results they do not recognize;
//   - never mutate the terminal event they are given;
//   - construct only valid events (Event.Validate), since the bus drops and
//     counts invalid ones; and
//   - never panic — the bridge recovers a panicking Derive call as
//     defense-in-depth (the batch is dropped and counted in
//     DeriverPanics), but a panicking deriver is a bug in the deriver, and
//     the contract is that the job boundary stays intact either way.
type Deriver interface {
	// Derive converts the raw result of a completed pool job into derived
	// events. ev is the task_completed terminal event carrying the result
	// (already validated and sequenced by the bus), and result is the raw
	// job result (TaskCompleted.Result; nil when the job returned none).
	Derive(ev Event, result any) []Event
}

// Deriving is the pool-job-boundary bridge: an Observer wrapper that
// forwards every observed event untouched and derives canonical events from
// the raw results of task_completed events. It is the single construction
// point for derived events; engines never emit them.
//
// The terminal event is always forwarded first, followed by the derived
// events in the order the Deriver returned them. Derived events are
// forwarded exactly as returned: when the Observer is a Bus they are
// validated, sequenced, and fanned out like any other publish (invalid
// derived events are dropped and counted there), and a derived event with a
// zero timestamp is stamped by the bus's clock.
//
// A panicking Derive call cannot take down the consumer: the bridge
// recovers, drops the whole derived batch, counts it (DeriverPanics), and
// continues forwarding (the terminal event was already delivered, and
// later events flow normally). Build the bridge with NewDeriving to have
// the count recorded; the zero value (a plain struct literal) recovers
// identically but counts nothing.
//
// A nil Deriver forwards events untouched; a nil Observer drops everything
// (the bridge is inert, matching the nil-observer off switch).
type Deriving struct {
	// Observer receives the forwarded and derived events (may be nil).
	Observer Observer

	// Deriver converts task_completed results into derived events (may be
	// nil).
	Deriver Deriver

	// panics counts recovered Derive panics. It is a heap-allocated
	// counter shared by every copy of the bridge, so value copies made by
	// the Observer interface all count into the same total. Nil when the
	// bridge was built as a plain struct literal (recovery without
	// counting).
	panics *atomic.Uint64
}

// NewDeriving returns the Deriving bridge with its panic counter
// installed: DeriverPanics reports how many hostile Derive calls were
// recovered and dropped. Plain struct literals (Deriving{Observer: ...,
// Deriver: ...}) recover identically but count nothing.
func NewDeriving(observer Observer, deriver Deriver) Deriving {
	return Deriving{Observer: observer, Deriver: deriver, panics: new(atomic.Uint64)}
}

// DeriverPanics returns how many Derive calls panicked and had their
// derived batch dropped. It is 0 when the bridge was built as a plain
// struct literal without a counter.
func (d Deriving) DeriverPanics() uint64 {
	if d.panics == nil {
		return 0
	}
	return d.panics.Load()
}

// Observe implements Observer.
func (d Deriving) Observe(ev Event) {
	if d.Observer != nil {
		d.Observer.Observe(ev)
	}
	if d.Deriver == nil {
		return
	}
	completed, ok := ev.Payload.(TaskCompleted)
	if !ok {
		return
	}
	derived, ok := deriveSafe(d.Deriver, ev, completed.Result)
	if !ok {
		// The deriver panicked: the batch is dropped and counted; the
		// stream continues (the terminal event was already forwarded).
		if d.panics != nil {
			d.panics.Add(1)
		}
		return
	}
	for _, de := range derived {
		if d.Observer != nil {
			d.Observer.Observe(de)
		}
	}
}

// deriveSafe invokes d.Derive under panic recovery. A panicking deriver is
// a hostile batch, never a process crash: the whole batch is dropped and
// reported false so the caller can count it.
func deriveSafe(d Deriver, ev Event, result any) (derived []Event, ok bool) {
	defer func() {
		if recover() != nil {
			derived, ok = nil, false
		}
	}()
	return d.Derive(ev, result), true
}
