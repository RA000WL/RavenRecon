package urlintel

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps how many canonical events one job result may derive.
// Excess observations are dropped: derivation is an observation aid for the
// live TUI feed only, and reports never read the bus — the merged Report
// (Accumulator) remains the complete record regardless of this cap.
const maxDerivedPerJob = 512

// Deriver converts completed per-URL job results into canonical events at
// the pool-job boundary. Engines never emit events themselves; the runtime
// pool wraps the configured observer in event.Deriving, which hands each
// task_completed result to Derive after forwarding the terminal event.
//
// Only StatusCompleted entries derive anything: cancelled and failed entries
// carry no trustworthy observation (their honest status lives in the report,
// never on the bus). Unrecognized result types derive nothing (nil).
//
// Secret handling: only identity metadata enters events (canonical identity
// strings, kinds, endpoint methods, URL paths, provenance confidence).
// Parameter observed VALUES never enter events — the parameter identity
// (location:name) is metadata, the values are not emitted.
type Deriver struct{}

// Compile-time check that Deriver satisfies the boundary contract.
var _ event.Deriver = Deriver{}

// Derive implements event.Deriver.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	entry, ok := result.(URLEntry)
	if !ok {
		return nil
	}
	if entry.Status != StatusCompleted {
		return nil
	}
	out := make([]event.Event, 0, 8)
	emit := func(e event.Event) bool {
		if len(out) >= maxDerivedPerJob {
			return false
		}
		out = append(out, e)
		return true
	}

	urlID := entry.URL.Identity()
	if !urlID.IsZero() {
		if !emit(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   urlID.String(),
			Kind:       string(asset.KindURL),
			Path:       entry.URL.Path,
			Confidence: entry.URL.Prov.Confidence,
		})) {
			return out
		}
	}
	if !hostIsZero(entry.Host) {
		hostID := entry.Host.Identity()
		if !emit(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   hostID.String(),
			Kind:       string(asset.KindHost),
			Confidence: entry.Host.Prov.Confidence,
		})) {
			return out
		}
	}
	for _, ep := range entry.Endpoints {
		epID := ep.Identity()
		if epID.IsZero() {
			continue
		}
		if !emit(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   epID.String(),
			Kind:       string(asset.KindEndpoint),
			Method:     ep.Method,
			Path:       ep.URL.Path,
			Confidence: ep.Prov.Confidence,
		})) {
			return out
		}
	}
	for _, p := range entry.Parameters {
		pID := p.Identity()
		if pID.IsZero() {
			continue
		}
		if !emit(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   pID.String(),
			Kind:       string(asset.KindParameter),
			Confidence: p.Prov.Confidence,
		})) {
			return out
		}
	}
	for _, r := range entry.Relationships {
		if r.From.IsZero() || r.To.IsZero() || r.Kind == "" {
			continue
		}
		if !emit(event.New(event.KindRelationshipCreated, ev.At, event.RelationshipCreated{
			From: r.From.String(),
			To:   r.To.String(),
			Kind: string(r.Kind),
		})) {
			return out
		}
	}
	return out
}
