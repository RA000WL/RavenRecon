package event

import (
	"strings"
	"testing"
	"time"
)

// r2PanicDeriver panics with a configurable message so the test can pin
// LastPanic value capture and overwrite semantics.
type r2PanicDeriver struct {
	msg string
}

func (d r2PanicDeriver) Derive(ev Event, result any) []Event {
	panic(d.msg)
}

// TestDerivingLastPanicCapturesValueAndStack pins R2-M7: the panicSlot capture
// and LastPanic() accessor. It must PASS with the fix and FAIL if deriveSafe
// is reverted to discard the panic value/stack.
func TestDerivingLastPanicCapturesValueAndStack(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)

	// NewDeriving bridge: LastPanic must capture value and stack.
	b := NewBus(nil)
	defer b.Close()
	s, err := b.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer s.Close()

	bridge := NewDeriving(b, r2PanicDeriver{msg: "test-panic-value-42"})

	// Before any panic both parts are empty.
	if v, st := bridge.LastPanic(); v != "" || st != "" {
		t.Fatalf("LastPanic before panic: want empty, got value %q stack %q", v, st)
	}

	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(1, 0, at, "", ""), "hostile")))
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("terminal: want task_completed, got %s", got.Kind)
	}
	if got := bridge.DeriverPanics(); got != 1 {
		t.Fatalf("DeriverPanics after first panic: want 1, got %d", got)
	}
	v, st := bridge.LastPanic()
	if v == "" {
		t.Fatal("LastPanic value empty after panic, want non-empty")
	}
	if !strings.Contains(v, "test-panic-value-42") {
		t.Fatalf("LastPanic value %q does not contain %q", v, "test-panic-value-42")
	}
	if st == "" {
		t.Fatal("LastPanic stack empty after panic, want non-empty")
	}
	if !strings.Contains(st, "goroutine") {
		t.Fatalf("LastPanic stack does not contain %q: %q", "goroutine", st)
	}
	// Stack must correspond to a real Go stack; deriveSafe/debug.Stack
	// always includes the panicking deriver frame or test name.
	if !strings.Contains(st, "TestDerivingLastPanicCapturesValueAndStack") && !strings.Contains(st, "deriveSafe") && !strings.Contains(st, "r2PanicDeriver") {
		t.Fatalf("LastPanic stack missing expected frame (test/deriveSafe/deriver): %q", st)
	}

	// Second panic must overwrite the first.
	bridge.Deriver = r2PanicDeriver{msg: "second-panic-99"}
	bridge.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(2, 0, at, "", ""), "hostile2")))
	if got := mustNext(t, s); got.Kind != KindTaskCompleted {
		t.Fatalf("second terminal: want task_completed, got %s", got.Kind)
	}
	if got := bridge.DeriverPanics(); got != 2 {
		t.Fatalf("DeriverPanics after second panic: want 2, got %d", got)
	}
	v2, st2 := bridge.LastPanic()
	if v2 == "" {
		t.Fatal("LastPanic value empty after second panic, want non-empty")
	}
	if !strings.Contains(v2, "second-panic-99") {
		t.Fatalf("LastPanic value after second panic %q does not contain %q", v2, "second-panic-99")
	}
	if v2 == v {
		t.Fatalf("LastPanic value not overwritten: still %q", v2)
	}
	if st2 == "" {
		t.Fatal("LastPanic stack empty after second panic, want non-empty")
	}
	if !strings.Contains(st2, "goroutine") {
		t.Fatalf("LastPanic stack after second panic does not contain %q: %q", "goroutine", st2)
	}

	// Literal bridge recovers identically but LastPanic stays empty.
	b2 := NewBus(nil)
	defer b2.Close()
	s2, err := b2.Subscribe(16)
	if err != nil {
		t.Fatalf("Subscribe b2: %v", err)
	}
	defer s2.Close()
	lit := Deriving{Observer: b2, Deriver: r2PanicDeriver{msg: "test-panic-value-42"}}
	lit.Observe(New(KindTaskCompleted, at, NewTaskCompleted(NewTaskTerminal(3, 0, at, "", ""), "hostile")))
	if got := mustNext(t, s2); got.Kind != KindTaskCompleted {
		t.Fatalf("literal terminal: want task_completed, got %s", got.Kind)
	}
	if got := lit.DeriverPanics(); got != 0 {
		t.Fatalf("literal DeriverPanics: want 0, got %d", got)
	}
	if vL, stL := lit.LastPanic(); vL != "" || stL != "" {
		t.Fatalf("literal LastPanic: want empty, got value %q stack %q", vL, stL)
	}
}
