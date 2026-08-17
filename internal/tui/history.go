package tui

import (
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxHistoryLimit is the hard upper bound of the replay buffer, mirroring
// config.TUIConfig's MaxEventHistory validation range.
const maxHistoryLimit = 4096

// History is the bounded event replay buffer: the most recent
// MaxEventHistory events in deterministic (sequence) order. It is the basis
// for rendering and summary reconstruction — a fresh State replayed over
// the history reproduces the same tail state — and it never grows without
// bound: past the cap the oldest events are dropped and counted.
//
// Events are stored post-sanitization (the controller applies Sanitize
// before both State.Apply and History.Append), so a replay can never
// reintroduce hostile bytes.
type History struct {
	buf     []event.Event // ring
	start   int
	len     int
	cap     int
	dropped uint64
}

// NewHistory returns an empty replay buffer bounded to capacity (must be in
// [1, maxHistoryLimit]).
func NewHistory(capacity int) (*History, error) {
	if capacity < 1 || capacity > maxHistoryLimit {
		return nil, fmt.Errorf("tui: history capacity must be in [1, %d], got %d", maxHistoryLimit, capacity)
	}
	return &History{buf: make([]event.Event, capacity), cap: capacity}, nil
}

// Append stores one event, evicting the oldest past the cap (counted in
// Dropped).
func (h *History) Append(ev event.Event) {
	if h.len == h.cap {
		h.start = (h.start + 1) % h.cap
		h.len--
		h.dropped++
	}
	h.buf[(h.start+h.len)%h.cap] = ev
	h.len++
}

// Len returns the number of buffered events.
func (h *History) Len() int { return h.len }

// Cap returns the configured capacity.
func (h *History) Cap() int { return h.cap }

// Dropped returns how many events were evicted past the cap.
func (h *History) Dropped() uint64 { return h.dropped }

// Events returns a copy of the buffered events in sequence order (oldest
// first). The copy is fresh; callers may mutate it freely.
func (h *History) Events() []event.Event {
	out := make([]event.Event, h.len)
	for i := 0; i < h.len; i++ {
		out[i] = h.buf[(h.start+i)%h.cap]
	}
	return out
}
