package event

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeDeriver converts a string result into three asset_discovered events,
// so the derivation order is deterministic.
type fakeDeriver struct{}

// Derive implements Deriver.
func (fakeDeriver) Derive(ev Event, result any) []Event {
	s, ok := result.(string)
	if !ok {
		return nil
	}
	out := make([]Event, 0, 3)
	for i := 0; i < 3; i++ {
		out = append(out, New(
			KindAssetDiscovered,
			ev.At.Add(time.Duration(i)),
			AssetDiscovered{Identity: s, Kind: "host"},
		))
	}
	return out
}

// bogusDeriver returns one invalid event per result (hostile deriver probe).
type bogusDeriver struct{}

// Derive implements Deriver.
func (bogusDeriver) Derive(ev Event, result any) []Event {
	return []Event{{Kind: "bogus", At: ev.At}}
}

// TestDerivingForwardsAllEvents verifies the bridge forwards every event
// untouched, including non-task events.
func TestDerivingForwardsAllEvents(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: fakeDeriver{}}
	bridge.Observe(New(KindScanStarted, at, ScanStarted{Concurrency: 4}))
	bridge.Observe(New(KindWarning, at, NewWarning("tool", "warn")))
	if ev := mustNext(t, s); ev.Kind != KindScanStarted {
		t.Fatalf("event 1: want scan_started, got %s", ev.Kind)
	}
	if ev := mustNext(t, s); ev.Kind != KindWarning {
		t.Fatalf("event 2: want warning, got %s", ev.Kind)
	}
}

// TestDerivingDerivesFromTaskCompleted verifies the bridge converts the raw
// result of a task_completed event into derived events, forwarded after the
// terminal event in Deriver order, with the derived timestamps preserved.
func TestDerivingDerivesFromTaskCompleted(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: fakeDeriver{}}
	term := New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(7, 2, at, "", ""), "host:example.com"))
	bridge.Observe(term)

	// Terminal first, then the three derived events.
	ev := mustNext(t, s)
	if ev.Kind != KindTaskCompleted || ev.Sequence != 1 {
		t.Fatalf("terminal: want task_completed seq 1, got %s seq %d", ev.Kind, ev.Sequence)
	}
	for i := 0; i < 3; i++ {
		ev := mustNext(t, s)
		if ev.Kind != KindAssetDiscovered {
			t.Fatalf("derived %d: want asset_discovered, got %s", i, ev.Kind)
		}
		payload, ok := ev.Payload.(AssetDiscovered)
		if !ok {
			t.Fatalf("derived %d: payload %T, want AssetDiscovered", i, ev.Payload)
		}
		if payload.Identity != "host:example.com" {
			t.Fatalf("derived %d: identity %q, want host:example.com", i, payload.Identity)
		}
		if !ev.At.Equal(at.Add(time.Duration(i))) {
			t.Fatalf("derived %d: At %v, want %v (deriver timestamp preserved)", i, ev.At, at.Add(time.Duration(i)))
		}
		if ev.Sequence != uint64(2+i) {
			t.Fatalf("derived %d: sequence %d, want %d (bus-assigned after the terminal)", i, ev.Sequence, 2+i)
		}
	}
	if got := b.Seq(); got != 4 {
		t.Fatalf("Seq: want 4, got %d", got)
	}
}

// TestDerivingIgnoresUnrecognizedResults verifies the bridge calls the
// Deriver with the raw result and forwards nothing when the Deriver returns
// nil (unrecognized result or nil result).
func TestDerivingIgnoresUnrecognizedResults(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: fakeDeriver{}}
	// Unrecognized result type.
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), 42)))
	// Nil result.
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(2, 0, at, "", ""), nil)))
	for i := 1; i <= 2; i++ {
		if ev := mustNext(t, s); ev.Kind != KindTaskCompleted {
			t.Fatalf("event %d: want task_completed, got %s", i, ev.Kind)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Next(ctx); err == nil {
		t.Fatal("expected no derived events, got one")
	}
}

// TestDerivingNilParts verifies a nil Deriver forwards untouched and a nil
// Observer is inert (never panics).
func TestDerivingNilParts(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	ev := New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), "host:example.com"))

	// Nil Deriver: the terminal event is forwarded, nothing derived.
	Deriving{Observer: b}.Observe(ev)
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("nil-deriver forward: want task_completed, got %s", got.Kind)
	}

	// Nil Observer: inert, no panic, no delivery.
	Deriving{Observer: nil, Deriver: fakeDeriver{}}.Observe(ev)
	Deriving{}.Observe(ev)
	if got := b.Seq(); got != 1 {
		t.Fatalf("Seq: want 1 (nil-observer bridge publishes nothing), got %d", got)
	}
}

// TestDerivingInvalidDerivedEventsDroppedByBus verifies invalid derived
// events are dropped and counted by the bus while the terminal event still
// arrives.
func TestDerivingInvalidDerivedEventsDroppedByBus(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: bogusDeriver{}}
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), "x")))
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("terminal: want task_completed, got %s", got.Kind)
	}
	if got := b.Invalid(); got != 1 {
		t.Fatalf("Invalid: want 1 (bogus derived event), got %d", got)
	}
}

// panicDeriver is the hostile probe: it panics on every Derive call.
type panicDeriver struct{}

// Derive implements Deriver.
func (panicDeriver) Derive(ev Event, result any) []Event {
	panic("hostile deriver")
}

// TestDerivingRecoversPanickingDeriver pins the process-crash defense: a
// deriver that panics must not take down the consumer — the whole derived
// batch is dropped, the panic is counted (DeriverPanics), and normal events
// still flow afterward.
func TestDerivingRecoversPanickingDeriver(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := NewDeriving(b, panicDeriver{})

	// A hostile result: the terminal arrives, the derived batch does not.
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), "hostile")))
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("terminal: want task_completed, got %s", got.Kind)
	}
	if got := bridge.DeriverPanics(); got != 1 {
		t.Fatalf("DeriverPanics = %d, want 1", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Next(ctx); err == nil {
		t.Fatal("expected no derived events after the panic, got one")
	}

	// Normal events still flow afterward.
	bridge.Observe(New(KindWarning, at, NewWarning("tool", "warn")))
	if ev := mustNext(t, s); ev.Kind != KindWarning {
		t.Fatalf("post-panic event: want warning, got %s", ev.Kind)
	}
	// ...and the counter keeps accumulating.
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(2, 0, at, "", ""), "hostile")))
	if got := bridge.DeriverPanics(); got != 2 {
		t.Fatalf("DeriverPanics = %d, want 2", got)
	}
}

// TestDerivingLiteralBridgeRecoversWithoutCounting pins that a plain
// struct-literal bridge (no counter installed) recovers a panicking
// deriver identically and simply reports zero panics.
func TestDerivingLiteralBridgeRecoversWithoutCounting(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: panicDeriver{}}
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), "hostile")))
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("terminal: want task_completed, got %s", got.Kind)
	}
	if got := bridge.DeriverPanics(); got != 0 {
		t.Fatalf("literal bridge DeriverPanics = %d, want 0 (no counter installed)", got)
	}
}

// TestDerivingConcurrentUse verifies the bridge is safe for concurrent
// Observe calls (the Bus behind it serializes publishes); run under -race.
func TestDerivingConcurrentUse(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(4096)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()
	at := time.Unix(1_700_000_000, 0)
	bridge := Deriving{Observer: b, Deriver: fakeDeriver{}}
	var wg sync.WaitGroup
	const publishers = 8
	const perPublisher = 100
	for g := 0; g < publishers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perPublisher; i++ {
				bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(
					NewTaskTerminal(uint64(g*perPublisher+i), 0, at, "", ""),
					"host:example.com",
				)))
			}
		}(g)
	}
	wg.Wait()
	// Every terminal plus 3 derived events: 800 terminals + 2400 derived.
	want := uint64(publishers*perPublisher) * 4
	if got := b.Seq(); got != want {
		t.Fatalf("Seq: want %d, got %d", want, got)
	}
	if got := b.Invalid(); got != 0 {
		t.Fatalf("Invalid: want 0, got %d", got)
	}
}
