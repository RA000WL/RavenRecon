package adapt

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps how many canonical events one ingest file outcome
// may derive. Excess assets are dropped: derivation is an observation aid
// for the live TUI feed only, and reports never read the bus — the stage
// result remains the complete record regardless of this cap.
const maxDerivedPerJob = 512

// ingestDeriver converts per-file import outcomes into canonical events at
// the pool-job boundary. Engines never emit events themselves; the runtime
// pool wraps the configured observer in event.Deriving, which hands each
// task_completed result to Derive after forwarding the terminal event.
//
// Every retained canonical asset derives one asset_discovered event;
// retained findings derive finding_created events. Provenance sidecars and
// CIDR strings are not assets and derive nothing. Only identity metadata
// enters events. Unrecognized results (and outcomes without a sink)
// derive nothing (nil).
type ingestDeriver struct{}

// Compile-time check that ingestDeriver satisfies the boundary contract.
var _ event.Deriver = ingestDeriver{}

// Derive implements event.Deriver.
func (ingestDeriver) Derive(ev event.Event, result any) []event.Event {
	out, ok := result.(ingestFileOutcome)
	if !ok || out.sink == nil {
		return nil
	}
	sink := out.sink
	var events []event.Event
	emit := func(id asset.Identity, kind asset.Kind) bool {
		if id.IsZero() {
			return true
		}
		events = append(events, event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity: id.String(),
			Kind:     string(kind),
		}))
		return len(events) < maxDerivedPerJob
	}
	for _, d := range sink.Domains {
		if !emit(d.Identity(), asset.KindDomain) {
			return events
		}
	}
	for _, h := range sink.Hosts {
		if !emit(h.Identity(), asset.KindHost) {
			return events
		}
	}
	for _, u := range sink.URLs {
		if !emit(u.Identity(), asset.KindURL) {
			return events
		}
	}
	for _, ip := range sink.IPs {
		if !emit(ip.Identity(), asset.KindIP) {
			return events
		}
	}
	for _, j := range sink.JS {
		if !emit(j.Identity(), asset.KindJavaScript) {
			return events
		}
	}
	for _, f := range sink.Findings {
		if len(events) >= maxDerivedPerJob {
			return events
		}
		events = append(events, event.New(event.KindFindingCreated, ev.At, event.FindingCreated{
			Identity:   f.Identity().String(),
			RuleID:     f.RuleID,
			Subject:    f.Subject.String(),
			Priority:   f.Priority,
			Category:   f.Category,
			Confidence: f.Confidence,
		}))
	}
	return events
}
