package tui

import (
	"context"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// Documented library defaults, mirroring config.DefaultTUI. Zero
// configuration fields are normalized to these (NewController,
// OptionsFromConfig); the config package's own Validate enforces the
// stricter contract for callers that want to reject non-default values.
const (
	defaultRefreshInterval = 250 * time.Millisecond
	defaultEventHistory    = 1024
	defaultInterestingRate = 10.0
)

// Controller drives the terminal observability loop: it consumes the
// canonical event stream from a Subscriber, applies every event to the
// State (sanitized at the boundary, once), appends it to the bounded
// replay History, and renders frames to the writer on the configured
// refresh interval.
//
// The controller is single-goroutine by contract: Run owns the State,
// the History, and the writer for its whole lifetime and spawns no
// goroutines. Exactly one goroutine may call Run at a time.
//
// # Termination
//
// Run returns when the run concludes:
//
//   - a ScanStopped event is consumed (the run's execution backbone
//     ended; the pool emits it last, after shutdown);
//   - the subscriber closes (the stream ended);
//   - or the context is cancelled.
//
// Before returning, Run drains whatever remains buffered on the
// subscriber (non-blocking), so the final frame reflects the whole
// stream consumed so far, and renders the final summary frame once
// (RenderFinal) whenever at least one event was consumed and rendering
// is still enabled. The final frame's clock is the timestamp of the last
// consumed event, so it is a pure function of the stream.
//
// # Write failures
//
// A failed or partial write (including EPIPE) disables rendering for the
// rest of the run: the controller keeps consuming events, never panics,
// and the first write error is what Run returns. Every frame is written
// with a single Write call.
//
// # Return value
//
// Run returns the first write error when a write failed; otherwise
// ctx.Err() when the context cancelled the loop; otherwise nil (the
// stream concluded on its own).
//
// # Cancellation precedence
//
// An already-cancelled context is detected before the loop starts:
// cancellation precedes the stream, so it wins over any buffered events,
// and the buffered events are still drained and rendered into the final
// frame. What is NOT deterministic is a cancellation racing a
// simultaneously-ready ScanStopped event (or a simultaneously closed
// subscriber): Go's select picks uniformly at random among ready cases,
// so the run may conclude with either the event or ctx.Err() — only the
// already-cancelled-before-the-loop case is deterministic. Callers that
// need a deterministic outcome must cancel before Run starts.
type Controller struct {
	sub      *event.Subscriber
	state    *State
	history  *History
	opts     Options
	interval time.Duration
	w        io.Writer

	// clock drives the refresh ticks (nil = the wall clock; tests inject
	// a fake event.Clock for deterministic frames).
	clock event.Clock

	// Run-owned bookkeeping (single goroutine; no locking).
	disabled bool  // a write failed; stop rendering for the rest of the run
	writeErr error // the first write error (also the Run return value)
	rendered int   // frames written so far
	consumed int   // events applied so far

	// consumedCh is a test seam (nil in production): when non-nil,
	// consume performs one best-effort, non-blocking notify per consumed
	// event, so tests can synchronize on the loop's progress without
	// polling Run-owned fields. The notification never stalls the loop.
	consumedCh chan struct{}
}

// NewController returns a controller over sub that renders frames to w.
// Configuration fields are normalized like OptionsFromConfig: a zero or
// non-positive RefreshInterval defers to 250 ms, a non-positive
// MaxEventHistory defers to 1024 (a value above 4096 is rejected — the
// replay ring cannot grow past its documented bound), a non-positive or
// NaN InterestingRate defers to 10/s, and Color renders only when it is
// exactly "on" (the caller resolves "auto"). sub and w must be non-nil.
func NewController(cfg config.TUIConfig, sub *event.Subscriber, w io.Writer) (*Controller, error) {
	if sub == nil {
		return nil, fmt.Errorf("tui: controller: nil subscriber")
	}
	if w == nil {
		return nil, fmt.Errorf("tui: controller: nil writer")
	}
	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	historyCap := cfg.MaxEventHistory
	if historyCap < 1 {
		historyCap = defaultEventHistory
	}
	history, err := NewHistory(historyCap)
	if err != nil {
		return nil, fmt.Errorf("tui: controller: %w", err)
	}
	rate := cfg.InterestingRate
	// NaN must not slip past "rate <= 0": NaN compares false against
	// everything, so it would otherwise reach the token bucket unchanged,
	// where its NaN arithmetic silently rejects every candidate after the
	// first — the interesting feed would starve without ever admitting it
	// was misconfigured. A non-finite rate defers to the default like a
	// non-positive one.
	if rate <= 0 || math.IsNaN(rate) {
		rate = defaultInterestingRate
	}
	return &Controller{
		sub:      sub,
		state:    NewState(rate),
		history:  history,
		opts:     OptionsFromConfig(cfg),
		interval: interval,
		w:        w,
	}, nil
}

// Run consumes and renders the event stream until the run concludes (see
// the type documentation for the termination and write-failure
// contracts). Run returns the first write error when one occurred,
// ctx.Err() when the context cancelled the loop, and nil when the stream
// concluded on its own. An already-cancelled context is detected before
// the loop starts: cancellation precedes the stream, so it wins, and the
// buffered events are still drained and rendered into the final frame. A
// cancellation racing a simultaneously-ready ScanStopped event or a
// simultaneously closed subscriber is NOT deterministic (Go's select
// resolves ties uniformly at random; see the type documentation);
// only the already-cancelled-before-the-loop case is. Run never panics.
func (c *Controller) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("tui: controller: nil context")
	}
	// An already-cancelled context is unambiguous: the cancellation
	// precedes the loop, so it wins over any concurrently buffered
	// events. The buffered events are still drained and rendered into
	// the final frame by finish.
	if err := ctx.Err(); err != nil {
		return c.finish(err)
	}
	clock := c.clock
	if clock == nil {
		clock = wallClock{}
	}
	tick := clock.After(c.interval)
	for {
		select {
		case ev := <-c.sub.Events():
			c.consume(ev)
			if ev.Kind == event.KindScanStopped {
				return c.finish(nil)
			}
		case <-c.sub.Done():
			return c.finish(nil)
		case <-ctx.Done():
			return c.finish(ctx.Err())
		case now := <-tick:
			c.render(now)
			tick = clock.After(c.interval) // re-arm for the next interval
		}
	}
}

// consume ingests one event: sanitized once at the controller boundary,
// then appended to the replay history and applied to the state (Apply
// re-checks sanitization internally with an allocation-free fast path).
func (c *Controller) consume(ev event.Event) {
	ev = sanitizeEvent(ev)
	c.history.Append(ev)
	c.state.Apply(ev)
	c.consumed++
	if c.consumedCh != nil {
		select {
		case c.consumedCh <- struct{}{}:
		default:
		}
	}
}

// render writes one live frame at time now (a single Write call). After
// the first write failure rendering stays disabled for the rest of the
// run; events keep flowing through consume.
func (c *Controller) render(now time.Time) {
	if c.disabled {
		return
	}
	frame := Render(c.state, now, c.opts)
	if frame == "" {
		return
	}
	c.write(frame)
}

// finish drains whatever remains buffered on the subscriber (non-blocking),
// renders the final summary frame once (when any event was consumed and
// rendering is enabled), and returns the loop's end error: the first write
// error if a write failed, endErr otherwise (nil when the stream concluded
// on its own, ctx.Err() when the context cancelled the loop).
func (c *Controller) finish(endErr error) error {
drain:
	for {
		select {
		case ev := <-c.sub.Events():
			c.consume(ev)
		default:
			break drain
		}
	}
	if c.consumed > 0 && !c.disabled {
		// The final frame's clock is the last consumed event's timestamp:
		// deterministic, and the honest end of the stream.
		now := c.state.progress.lastEventAt
		c.write(RenderFinal(c.state, now, c.opts))
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	return endErr
}

// write performs the one whole Write of a frame and records the failure
// bookkeeping: a failed or partial write (including EPIPE) disables
// rendering for the rest of the run and is remembered as the first write
// error. Partial writes are treated as failures (io.ErrShortWrite).
func (c *Controller) write(frame string) {
	n, err := io.WriteString(c.w, frame)
	if err == nil && n < len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.disabled = true
		c.writeErr = err
		return
	}
	c.rendered++
}

// wallClock is the production tick source (a new After per interval;
// time.After delivers exactly once, so the controller re-arms after each
// tick).
type wallClock struct{}

// Now implements event.Clock.
func (wallClock) Now() time.Time { return time.Now() }

// After implements event.Clock.
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
