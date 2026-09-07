package discovery

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps how many canonical events one job result may derive.
// Excess hosts are dropped: derivation is an observation aid for the live
// TUI feed only, and reports never read the bus — the Report (per-source
// results) remains the complete record regardless of this cap.
const maxDerivedPerJob = 512

// Deriver converts per-source job results into canonical events at the
// pool-job boundary. Engines never emit events themselves; the runtime pool
// wraps the configured observer in event.Deriving, which hands each
// task_completed result to Derive after forwarding the terminal event.
//
// Every retained host derives one asset_discovered event, regardless of the
// source's engine-level status: a killed enumeration's parsed partial
// capture (NEW-94) is still a real observation. Sources with no hosts (and
// unrecognized result types) derive nothing (nil).
//
// Confidence is provenance-flavored 0 (unknown): discovery provenance names
// the tool, not a scored estimate, so no confidence is asserted. Only
// identity metadata enters events (canonical identity strings and kinds).
type Deriver struct{}

// Compile-time check that Deriver satisfies the boundary contract.
var _ event.Deriver = Deriver{}

// Derive implements event.Deriver.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	res, ok := result.(SourceResult)
	if !ok {
		return nil
	}
	if len(res.Hosts) == 0 {
		return nil
	}
	out := make([]event.Event, 0, len(res.Hosts))
	for _, h := range res.Hosts {
		if len(out) >= maxDerivedPerJob {
			break
		}
		id := h.Identity()
		if id.IsZero() {
			continue
		}
		out = append(out, event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity: id.String(),
			Kind:     string(asset.KindHost),
		}))
	}
	return out
}
