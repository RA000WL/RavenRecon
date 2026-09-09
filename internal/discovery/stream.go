package discovery

import (
	"encoding/json"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// HostEvent is one streamed host observation (NEW-138). It is emitted from
// the existing job-finalization path — the same point where OnSource fires —
// so streaming never bypasses the pool's concurrency, cancellation, or
// deadline bounds: no new goroutines, no queues, no second worker system.
type HostEvent struct {
	// Source is the tool that observed the host (the result's source name).
	Source string
	// Host is the normalized host with its provenance (source + timestamp).
	Host asset.Host
	// Status is the finalized outcome of the source that observed it
	// (completed / partial / failed / cancelled). Skipped sources never
	// execute and therefore never stream.
	Status Out
	// Cached reports whether the observation was served from cache.
	Cached bool
}

// streamLine is the single pinned wire form of a HostEvent: one JSON object
// per line with exactly these keys. Keys marshal in declaration order, so
// the rendered line is byte-stable for identical inputs.
type streamLine struct {
	Host         string `json:"host"`
	Source       string `json:"source"`
	DiscoveredAt string `json:"discovered_at"`
	Status       string `json:"status"`
	Cached       bool   `json:"cached"`
}

// Line renders the event as one stream line: a single JSON object
// (no trailing newline) carrying the host name, the observing source, the
// provenance timestamp (RFC 3339, UTC), the source's finalized outcome, and
// the cache flag. It cannot fail: every field marshals as a string or bool.
func (e HostEvent) Line() string {
	b, _ := json.Marshal(streamLine{
		Host:         e.Host.Name,
		Source:       e.Source,
		DiscoveredAt: e.Host.Prov.DiscoveredAt.UTC().Format(time.RFC3339),
		Status:       e.Status.String(),
		Cached:       e.Cached,
	})
	return string(b)
}
