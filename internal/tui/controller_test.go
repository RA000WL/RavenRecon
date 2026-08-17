package tui

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// newTestController builds a controller over a fresh bus subscriber with
// a fake clock, the given writer, and the consumedCh test seam installed
// (generous capacity: back-to-back publishes can never drop a
// notification, keeping the tests deterministic).
func newTestController(t *testing.T, w io.Writer) (*Controller, *event.Bus, *event.Subscriber) {
	t.Helper()
	bus := event.NewBus(nil)
	sub, err := bus.Subscribe(256)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.TUIConfig{RefreshInterval: time.Millisecond, MaxEventHistory: 64, InterestingRate: highRate}
	c, err := NewController(cfg, sub, w)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeClock{now: testBase, tick: make(chan time.Time, 1)}
	c.clock = fake
	c.consumedCh = make(chan struct{}, 256)
	t.Cleanup(func() {
		sub.Close()
		bus.Close()
	})
	return c, bus, sub
}

// waitConsumed blocks until the Run goroutine consumes one event,
// synchronized through the controller's consumedCh test seam (no polling
// of Run-owned fields).
func waitConsumed(t *testing.T, c *Controller) {
	t.Helper()
	if c.consumedCh == nil {
		t.Fatal("waitConsumed requires the consumedCh test seam")
	}
	select {
	case <-c.consumedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an event to be consumed")
	}
}

// syncWriter is a mutex-protected test writer: the Run goroutine writes
// to it while the test goroutine polls it, so every accessor takes the
// lock (no data race under -race). It can also model write failures
// (failAt) and partial writes (short) like the controller's writer
// contract expects.
type syncWriter struct {
	mu      sync.Mutex
	frames  []string
	calls   int
	lastErr error
	failAt  int // fail this call (1-based); 0 = never
	short   int // if > 0, write only this many bytes (partial write)
	shorts  int // partial writes performed
}

// Write implements io.Writer.
func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.failAt > 0 && w.calls == w.failAt {
		w.lastErr = errors.New("boom: writer failed")
		return 0, w.lastErr
	}
	if w.short > 0 && len(p) > w.short {
		w.shorts++
		return w.short, nil
	}
	w.frames = append(w.frames, string(p))
	return len(p), nil
}

func (w *syncWriter) frameCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.frames)
}

func (w *syncWriter) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.frames, "")
}

func (w *syncWriter) callCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func (w *syncWriter) writeErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *syncWriter) shortCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.shorts
}

// TestControllerRendersFramesOnTicks pins the tick loop: one whole frame
// per refresh tick, reflecting all events consumed so far.
func TestControllerRendersFramesOnTicks(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	bus.Publish(ev(event.KindRunMetadata, 1, event.RunMetadata{Target: "example.com"}))
	waitConsumed(t, c)
	waitConsumed(t, c)

	c.clock.(*fakeClock).tick <- testBase.Add(time.Second)
	waitFor(t, 2*time.Second, "first frame", func() bool { return buf.frameCount() == 1 })

	bus.Publish(ev(event.KindProgress, 2, event.Progress{Phase: "dns", Completed: 1, Total: 2, TotalKnown: true}))
	waitConsumed(t, c)

	c.clock.(*fakeClock).tick <- testBase.Add(2 * time.Second)
	waitFor(t, 2*time.Second, "second frame", func() bool { return buf.frameCount() == 2 })

	if !strings.Contains(buf.text(), "ravenrecon — example.com") {
		t.Fatalf("frame must render the target:\n%s", buf.text())
	}
	if strings.Count(buf.text(), "ravenrecon — example.com") != 2 {
		t.Fatalf("expected exactly two frames, got:\n%s", buf.text())
	}
	// The second frame reflects the progress event consumed before it.
	if !strings.Contains(buf.text(), "tasks 1/2") {
		t.Fatalf("second frame must reflect the consumed progress:\n%s", buf.text())
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run must return context.Canceled on cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestControllerConcludesOnScanStopped pins the conclusion contract:
// ScanStopped ends the loop, the remaining buffered events are drained,
// and exactly one final frame (with the summary) is written. Everything
// is published before Run starts, so the buffer order is fixed: the
// drain must pick up the event buffered after ScanStopped.
func TestControllerConcludesOnScanStopped(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	bus.Publish(ev(event.KindAssetDiscovered, 1, event.AssetDiscovered{Identity: "host:a", Kind: "host"}))
	bus.Publish(ev(event.KindAssetDiscovered, 2, event.AssetDiscovered{Identity: "host:b", Kind: "host"}))
	bus.Publish(ev(event.KindScanStopped, 3, event.ScanStopped{State: "completed"}))
	// Published after the concluding event: it sits in the subscriber
	// buffer behind ScanStopped and must be consumed by the drain.
	bus.Publish(ev(event.KindAssetDiscovered, 4, event.AssetDiscovered{Identity: "host:c", Kind: "host"}))

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concluded run must return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not conclude on ScanStopped")
	}

	if c.consumed != 5 {
		t.Fatalf("consumed = %d, want 5 (drain must include events after ScanStopped)", c.consumed)
	}
	if c.rendered != 1 {
		t.Fatalf("rendered = %d, want exactly 1 final frame", c.rendered)
	}
	frame := buf.text()
	if !strings.Contains(frame, "── summary ──") || !strings.Contains(frame, "outcome completed") {
		t.Fatalf("final frame must carry the summary:\n%s", frame)
	}
	if !strings.Contains(frame, "assets 3 · hosts 3") {
		t.Fatalf("final frame must reflect the drained events:\n%s", frame)
	}
}

// TestControllerContextCancellation pins that a cancelled context ends
// the loop with ctx.Err() after draining and rendering the final frame.
func TestControllerContextCancellation(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	bus.Publish(ev(event.KindAssetDiscovered, 1, event.AssetDiscovered{Identity: "host:a", Kind: "host"}))
	waitConsumed(t, c)
	waitConsumed(t, c)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run must return context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if c.rendered != 1 {
		t.Fatalf("rendered = %d, want the final frame", c.rendered)
	}
	if !strings.Contains(buf.text(), "── summary ──") {
		t.Fatalf("final frame must be rendered on cancellation:\n%s", buf.text())
	}
}

// TestControllerAlreadyCancelledContext pins that Run returns promptly
// with ctx.Err() when the context is already cancelled, even though a
// concluding ScanStopped is buffered: the cancellation precedes the
// stream, so it wins (draining and rendering whatever is buffered).
func TestControllerAlreadyCancelledContext(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	bus.Publish(ev(event.KindScanStopped, 1, event.ScanStopped{State: "cancelled"}))

	start := time.Now()
	err := c.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run must return context.Canceled, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Run must return promptly on an already-cancelled context")
	}
	if c.consumed != 2 || c.rendered != 1 {
		t.Fatalf("consumed/rendered = %d/%d, want 2/1 (drain still applies)", c.consumed, c.rendered)
	}
	if !strings.Contains(buf.text(), "outcome cancelled") {
		t.Fatalf("final frame must reflect the cancelled outcome:\n%s", buf.text())
	}
}

// TestControllerSubscriberClosed pins that a closed subscriber ends the
// loop with nil after draining and rendering the final frame.
func TestControllerSubscriberClosed(t *testing.T) {
	buf := &syncWriter{}
	c, bus, sub := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	waitConsumed(t, c)
	sub.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("closed subscriber must end the loop with nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the subscriber closed")
	}
	if c.rendered != 1 || !strings.Contains(buf.text(), "── summary ──") {
		t.Fatalf("final frame must be rendered on subscriber close:\n%s", buf.text())
	}
}

// TestControllerNoEventsNoFrames pins that a run that consumed nothing
// renders nothing (no empty frames, no fabricated summary).
func TestControllerNoEventsNoFrames(t *testing.T) {
	buf := &syncWriter{}
	c, _, sub := newTestController(t, buf)
	sub.Close()
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run must return nil on a closed empty subscriber, got %v", err)
	}
	if buf.frameCount() != 0 || c.rendered != 0 {
		t.Fatalf("no events must mean no frames, got %d frames", buf.frameCount())
	}
}

// TestControllerWriteFailureDisablesRendering pins the failure contract:
// a failed write disables rendering for the rest of the run (events keep
// flowing), the error is returned by Run, and no further writes happen.
func TestControllerWriteFailureDisablesRendering(t *testing.T) {
	w := &syncWriter{failAt: 2}
	c, bus, _ := newTestController(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	waitConsumed(t, c)

	fake := c.clock.(*fakeClock)
	fake.tick <- testBase.Add(time.Second)
	waitFor(t, 2*time.Second, "first frame", func() bool { return w.callCount() == 1 })

	// The second write fails; rendering is disabled.
	fake.tick <- testBase.Add(2 * time.Second)
	waitFor(t, 2*time.Second, "write failure recorded", func() bool { return w.writeErr() != nil })

	// A further tick must not reach the writer (the final assertion on
	// the call count proves it; give the loop a moment to process it).
	fake.tick <- testBase.Add(3 * time.Second)
	time.Sleep(20 * time.Millisecond)

	// Events keep flowing, and the conclusion returns the write error.
	bus.Publish(ev(event.KindAssetDiscovered, 1, event.AssetDiscovered{Identity: "host:a", Kind: "host"}))
	bus.Publish(ev(event.KindScanStopped, 2, event.ScanStopped{State: "completed"}))
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "writer failed") {
			t.Fatalf("Run must return the first write error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ScanStopped")
	}
	if w.callCount() != 2 {
		t.Fatalf("writer calls = %d, want 2 (no writes after the failure)", w.callCount())
	}
	if c.consumed != 3 {
		t.Fatalf("consumed = %d, want 3 (events must keep flowing)", c.consumed)
	}
}

// TestControllerShortWrite pins that a partial write with a nil error is
// treated as a failure (io.ErrShortWrite), disabling rendering.
func TestControllerShortWrite(t *testing.T) {
	w := &syncWriter{short: 10}
	c, bus, _ := newTestController(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	waitConsumed(t, c)
	c.clock.(*fakeClock).tick <- testBase.Add(time.Second)
	waitFor(t, 2*time.Second, "short write performed", func() bool { return w.shortCount() > 0 })

	bus.Publish(ev(event.KindScanStopped, 1, event.ScanStopped{State: "completed"}))
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("Run must return io.ErrShortWrite, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ScanStopped")
	}
}

// TestControllerFinishDrainsAndRendersFinal pins finish directly (no run
// loop race): everything buffered is consumed and exactly one final frame
// is written.
func TestControllerFinishDrainsAndRendersFinal(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	bus.Publish(ev(event.KindAssetDiscovered, 1, event.AssetDiscovered{Identity: "host:a", Kind: "host"}))
	bus.Publish(ev(event.KindAssetDiscovered, 2, event.AssetDiscovered{Identity: "host:b", Kind: "host"}))
	bus.Publish(ev(event.KindAssetDiscovered, 3, event.AssetDiscovered{Identity: "host:c", Kind: "host"}))

	if err := c.finish(nil); err != nil {
		t.Fatalf("finish must return nil without write errors, got %v", err)
	}
	if c.consumed != 4 {
		t.Fatalf("consumed = %d, want 4", c.consumed)
	}
	if c.rendered != 1 {
		t.Fatalf("rendered = %d, want exactly 1 final frame", c.rendered)
	}
	if !strings.Contains(buf.text(), "assets 3 · hosts 3") {
		t.Fatalf("final frame must reflect the drained stream:\n%s", buf.text())
	}
}

// TestControllerFinishEmptyStream pins that finish renders nothing when
// nothing was consumed.
func TestControllerFinishEmptyStream(t *testing.T) {
	buf := &syncWriter{}
	c, _, _ := newTestController(t, buf)
	if err := c.finish(nil); err != nil {
		t.Fatalf("finish on an empty stream must return nil, got %v", err)
	}
	if buf.frameCount() != 0 {
		t.Fatalf("empty stream must render nothing, got %d frames", buf.frameCount())
	}
}

// TestNewControllerValidation pins the constructor contract: nil inputs
// error, zero config fields normalize to the documented defaults, and an
// over-bounded history is rejected.
func TestNewControllerValidation(t *testing.T) {
	bus := event.NewBus(nil)
	sub, err := bus.Subscribe(8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sub.Close(); bus.Close() }()

	if _, err := NewController(config.TUIConfig{}, nil, io.Discard); err == nil {
		t.Fatal("nil subscriber must be rejected")
	}
	if _, err := NewController(config.TUIConfig{}, sub, nil); err == nil {
		t.Fatal("nil writer must be rejected")
	}
	if _, err := NewController(config.TUIConfig{MaxEventHistory: 5000}, sub, io.Discard); err == nil {
		t.Fatal("history above the hard bound must be rejected")
	}

	c, err := NewController(config.TUIConfig{}, sub, io.Discard)
	if err != nil {
		t.Fatalf("zero config must normalize, got %v", err)
	}
	if c.interval != defaultRefreshInterval {
		t.Fatalf("interval = %v, want default %v", c.interval, defaultRefreshInterval)
	}
	if c.history.Cap() != defaultEventHistory {
		t.Fatalf("history cap = %d, want default %d", c.history.Cap(), defaultEventHistory)
	}
	if c.opts.Compact || c.opts.Quiet || c.opts.Color {
		t.Fatalf("zero config must yield default options: %+v", c.opts)
	}
}

// TestNewControllerNaNInterestingRateDefersToDefault pins the NaN-proof
// contract: NaN compares false against EVERYTHING, so a bare "rate <= 0"
// guard lets it through, and its NaN arithmetic in the token bucket then
// silently rejects every feed candidate after the first — the interesting
// feed starves without ever reporting a misconfiguration. The controller
// must defer a NaN rate to the documented default instead.
func TestNewControllerNaNInterestingRateDefersToDefault(t *testing.T) {
	bus := event.NewBus(nil)
	sub, err := bus.Subscribe(8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sub.Close(); bus.Close() }()

	c, err := NewController(config.TUIConfig{InterestingRate: math.NaN()}, sub, io.Discard)
	if err != nil {
		t.Fatalf("NaN rate must normalize, got %v", err)
	}
	if got := c.state.feed.limiter.rate; got != defaultInterestingRate {
		t.Fatalf("feed rate = %v, want the default %v", got, defaultInterestingRate)
	}
	// The normalized bucket actually admits properly-spaced candidates at
	// the default rate (10/s, burst 1: 100 ms apart refills the token); a
	// NaN bucket would admit only the first and starve every later one.
	c.state.feed.add(ev(event.KindAssetDiscovered, 0, event.AssetDiscovered{Identity: "endpoint:https://example.com/gql", Kind: "endpoint", Method: "GQL"}))
	c.state.feed.add(ev(event.KindAssetDiscovered, 100, event.AssetDiscovered{Identity: "endpoint:https://example.com/gql2", Kind: "endpoint", Method: "GQL"}))
	if c.state.feed.admitted != 2 {
		t.Fatalf("admitted = %d, want 2 (NaN must defer to the default rate, not starve the feed)", c.state.feed.admitted)
	}
}

// TestControllerRunNilContext pins that Run rejects a nil context.
func TestControllerRunNilContext(t *testing.T) {
	buf := &syncWriter{}
	c, _, _ := newTestController(t, buf)
	if err := c.Run(nil); err == nil {
		t.Fatal("nil context must be rejected")
	}
}

// TestControllerRunDoesNotLeak pins that Run returns promptly when the
// loop is idle and the context is cancelled (no goroutine leak: Run
// spawns nothing and must unwind).
func TestControllerRunDoesNotLeak(t *testing.T) {
	buf := &syncWriter{}
	c, bus, _ := newTestController(t, buf)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	bus.Publish(ev(event.KindScanStarted, 0, event.ScanStarted{}))
	waitConsumed(t, c)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run must return context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run leaked: it did not return after cancellation")
	}
}
