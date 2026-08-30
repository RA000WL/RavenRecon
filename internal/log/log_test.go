package log

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/replay"
	"github.com/RA000WL/RavenRecon/internal/tui"
)

// syntheticRun returns a deterministic event stream (same as tui/scriptedRun but local).
func syntheticRun(base time.Time) []event.Event {
	ev := func(kind event.Kind, ms int, payload event.Payload) event.Event {
		return event.New(kind, base.Add(time.Duration(ms)*time.Millisecond), payload)
	}
	return []event.Event{
		ev(event.KindScanStarted, 0, event.ScanStarted{Concurrency: 2, QueueSize: 16}),
		ev(event.KindRunMetadata, 1, event.RunMetadata{Target: "example.com", OutputDir: "/tmp/out"}),
		ev(event.KindStageStarted, 2, event.StageStarted{Name: "discover"}),
		ev(event.KindStageFinished, 3, event.NewStageFinished("discover", "completed", false, 3, 0, time.Second, "")),
		ev(event.KindAssetDiscovered, 4, event.AssetDiscovered{Identity: "host:example.com", Kind: "host"}),
		ev(event.KindAssetDiscovered, 5, event.AssetDiscovered{Identity: "url:https://example.com", Kind: "url", Path: "/"}),
		ev(event.KindFindingCreated, 6, event.FindingCreated{Identity: "finding:r@s", RuleID: "r", Subject: "s", Priority: "high", Category: "xss", Confidence: 0.9}),
		ev(event.KindWarning, 7, event.NewWarning("tool", "warn")),
		ev(event.KindError, 8, event.NewError("dns", "nxdomain")),
		ev(event.KindScanStopped, 100, event.ScanStopped{State: "completed"}),
	}
}

// collectingObserver records events for replay contract verification.
type collectingObserver struct {
	events []event.Event
}

func (c *collectingObserver) Observe(ev event.Event) { c.events = append(c.events, ev) }

// panickingObserver panics on every Observe, to pin containment.
type panickingObserver struct{}

func (p panickingObserver) Observe(ev event.Event) { panic("boom") }

func TestLogReplaysDeterministically(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	events := syntheticRun(base)

	// Nil Bus is the off switch: zero behavior change.
	if l, err := NewLogger(nil, filepath.Join(t.TempDir(), "nil.jsonl")); err != nil || l != nil {
		t.Fatalf("NewLogger(nil) = %v %v, want (nil, nil)", l, err)
	}
	var nilLogger *Logger
	if err := nilLogger.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}

	bus := event.NewBus(nil)
	path := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := NewLogger(bus, path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if logger == nil {
		t.Fatal("logger is nil")
	}
	// Observer panics are contained: publish via a Deriving bridge that panics should not crash logger.
	// Instead we test replay's containment directly (same symmetry).
	for _, ev := range events {
		bus.Publish(ev)
	}
	// Publish an invalid event: the bus drops it, logger never sees it.
	bus.Publish(event.Event{Kind: event.Kind("bogus"), At: base})
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// File perms 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 0600", fi.Mode().Perm())
	}
	// Per-event timestamps preserved and JSONL lines equal to published count (invalid dropped).
	replayed, err := replay.ReplayEvents(path)
	if err != nil {
		t.Fatalf("ReplayEvents: %v", err)
	}
	if len(replayed) != len(events) {
		t.Fatalf("replayed %d events, want %d (invalid must be dropped)", len(replayed), len(events))
	}
	for i, ev := range events {
		got := replayed[i]
		if got.Kind != ev.Kind {
			t.Fatalf("event %d kind = %s, want %s", i, got.Kind, ev.Kind)
		}
		if !got.At.Equal(ev.At) {
			t.Fatalf("event %d At = %v, want %v", i, got.At, ev.At)
		}
		// Sequence is bus-assigned: strictly increasing 1..n.
		if got.Sequence != uint64(i+1) {
			t.Fatalf("event %d sequence = %d, want %d", i, got.Sequence, i+1)
		}
		// Payload type must survive round-trip.
		if reflect.TypeOf(got.Payload) != reflect.TypeOf(ev.Payload) {
			t.Fatalf("event %d payload type = %T, want %T", i, got.Payload, ev.Payload)
		}
	}
	// Replay through Observer contract produces identical summary (byte-equal).
	render := func(evs []event.Event) string {
		s := tui.NewState(1e9)
		for _, ev := range evs {
			s.Apply(ev)
		}
		// The final frame's clock is last event's At (controller finish contract).
		// Use Compact to hide the resource section (heap/goroutines/fd) which
		// is sampled from the live runtime and therefore non-deterministic
		// across two sequential renders; the remaining sections are pure
		// functions of the event stream.
		last := evs[len(evs)-1].At
		return tui.RenderFinal(s, last, tui.Options{Compact: true})
	}
	origFrame := render(events)
	replayFrame := render(replayed)
	if origFrame != replayFrame {
		t.Fatalf("replay frame differs:\norig:\n%s\nreplay:\n%s", origFrame, replayFrame)
	}
	// Replay via Observer contract: collecting observer receives same events.
	coll := &collectingObserver{}
	if err := replay.Replay(path, coll); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(coll.events) != len(events) {
		t.Fatalf("collecting replay got %d, want %d", len(coll.events), len(events))
	}
	// Panicking observer is contained: replay must not panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Replay with panicking observer must not panic, got %v", r)
			}
		}()
		if err := replay.Replay(path, panickingObserver{}); err != nil {
			t.Fatalf("Replay panicking: %v", err)
		}
	}()
	// Nil observer is zero change.
	if err := replay.Replay(path, nil); err != nil {
		t.Fatalf("Replay nil observer: %v", err)
	}
	if err := replay.Replay("", nil); err != nil {
		t.Fatalf("Replay empty path nil observer must not error, got %v", err)
	}
	// Verify JSONL is line-delimited and each line is valid JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(events) {
		t.Fatalf("lines = %d, want %d", len(lines), len(events))
	}
}
