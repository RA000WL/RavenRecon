package tui

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

func TestHistoryCapacityValidation(t *testing.T) {
	for _, n := range []int{0, -1, maxHistoryLimit + 1, 1 << 20} {
		if _, err := NewHistory(n); err == nil {
			t.Fatalf("capacity %d must be rejected", n)
		}
	}
	for _, n := range []int{1, maxHistoryLimit} {
		h, err := NewHistory(n)
		if err != nil {
			t.Fatalf("capacity %d is valid: %v", n, err)
		}
		if h.Cap() != n {
			t.Fatalf("Cap() = %d, want %d", h.Cap(), n)
		}
	}
}

func TestHistoryAppendOrderAndEviction(t *testing.T) {
	h, err := NewHistory(3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		h.Append(ev(event.KindTaskSubmitted, i, event.TaskSubmitted{JobID: uint64(i)}))
	}
	if h.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", h.Len())
	}
	if h.Dropped() != 7 {
		t.Fatalf("Dropped() = %d, want 7", h.Dropped())
	}
	got := h.Events()
	if len(got) != 3 {
		t.Fatalf("Events() len = %d, want 3", len(got))
	}
	// The ring holds the newest events in sequence order (7, 8, 9).
	for i, e := range got {
		want := uint64(7 + i)
		p, ok := e.Payload.(event.TaskSubmitted)
		if !ok || p.JobID != want {
			t.Fatalf("Events()[%d] = JobID %d, want %d", i, p.JobID, want)
		}
	}
}

func TestHistoryAppendWithinCapacity(t *testing.T) {
	h, err := NewHistory(5)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		h.Append(ev(event.KindTaskSubmitted, i, event.TaskSubmitted{JobID: uint64(i)}))
	}
	if h.Len() != 3 || h.Dropped() != 0 {
		t.Fatalf("Len/Dropped = %d/%d, want 3/0", h.Len(), h.Dropped())
	}
	if got := h.Events(); len(got) != 3 {
		t.Fatalf("Events() len = %d, want 3", len(got))
	}
}

func TestHistoryEventsReturnsFreshCopy(t *testing.T) {
	h, err := NewHistory(4)
	if err != nil {
		t.Fatal(err)
	}
	h.Append(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	got := h.Events()
	got[0].Phase = "mutated"
	if h.Events()[0].Phase != "" {
		t.Fatal("Events() must return a fresh copy")
	}
}

func TestHistoryReplayReconstructsTailState(t *testing.T) {
	// A fresh State replayed over the history reproduces the same tail
	// state (the replay contract of the package doc).
	stream := []event.Event{
		ev(event.KindScanStarted, 0, event.ScanStarted{}),
		ev(event.KindRunMetadata, 1, event.RunMetadata{Target: "example.com", OutputDir: "/out"}),
		ev(event.KindPhaseTransition, 2, event.PhaseTransition{Phase: "discovery"}),
		ev(event.KindAssetDiscovered, 3, event.AssetDiscovered{Identity: "host:example.com", Kind: "host"}),
		ev(event.KindAssetDiscovered, 4, event.AssetDiscovered{Identity: "url:https://example.com", Kind: "url"}),
		ev(event.KindProgress, 5, event.Progress{Phase: "discovery", Completed: 4, Total: 10, TotalKnown: true}),
		ev(event.KindScanStopped, 6, event.ScanStopped{State: "completed"}),
	}

	original := NewState(highRate)
	history, err := NewHistory(len(stream))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range stream {
		history.Append(e)
		original.Apply(e)
	}

	replay := NewState(highRate)
	for _, e := range history.Events() {
		replay.Apply(e)
	}

	a, b := original.Summary(), replay.Summary()
	if a != b {
		t.Fatalf("replayed state diverges:\n original %+v\n replay  %+v", a, b)
	}
}
