package replay

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/log"
	"github.com/RA000WL/RavenRecon/internal/tui"
)

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
		ev(event.KindScanStopped, 100, event.ScanStopped{State: "completed"}),
	}
}

type collectingObserver struct {
	events []event.Event
}

func (c *collectingObserver) Observe(ev event.Event) { c.events = append(c.events, ev) }

type panickingObserver struct{}

func (p panickingObserver) Observe(ev event.Event) { panic("boom") }

func TestReplayDeterministic(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	events := syntheticRun(base)

	bus := event.NewBus(nil)
	path := filepath.Join(t.TempDir(), "events.jsonl")
	logger, err := log.NewLogger(bus, path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	for _, ev := range events {
		bus.Publish(ev)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	replayed, err := ReplayEvents(path)
	if err != nil {
		t.Fatalf("ReplayEvents: %v", err)
	}
	if len(replayed) != len(events) {
		t.Fatalf("replayed %d, want %d", len(replayed), len(events))
	}
	render := func(evs []event.Event) string {
		s := tui.NewState(1e9)
		for _, ev := range evs {
			s.Apply(ev)
		}
		last := evs[len(evs)-1].At
		return tui.RenderFinal(s, last, tui.Options{Compact: true})
	}
	if got, want := render(replayed), render(events); got != want {
		t.Fatalf("replay frame differs:\n got %q\nwant %q", got, want)
	}
	coll := &collectingObserver{}
	if err := Replay(path, coll); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(coll.events) != len(events) {
		t.Fatalf("collecting replay %d, want %d", len(coll.events), len(events))
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Replay with panicking observer must not panic")
			}
		}()
		_ = Replay(path, panickingObserver{})
	}()
	if err := Replay(path, nil); err != nil {
		t.Fatalf("nil observer: %v", err)
	}
}
