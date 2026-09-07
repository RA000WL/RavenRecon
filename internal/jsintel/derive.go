// Derivation bridge: completed pool-job JSEntry results become canonical
// Phase 2 asset observations in the event stream.
//
// Engines never emit derived events themselves: the runtime pool wraps the
// configured Observer in an event.Deriving bridge holding this Deriver, so
// raw JSEntry job results are converted at the pool-job boundary. A nil
// Observer stays the off switch (the bridge is inert); unknown or
// placeholder results derive nothing.
package jsintel

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps the derived events of one pool job. JSEntry slices
// are already per-entry bounded, but the union (assets + evidence + edges)
// is re-capped here so one hostile job result can never inflate the stream.
const maxDerivedPerJob = 512

// Deriver converts completed pool-job JSEntry results into canonical
// derived events: AssetDiscovered for the JavaScript and SourceMap assets
// and the derived Endpoint / SecretCandidate (type + confidence + identity
// only — secret values never leave the entry) / Technology observations,
// EvidenceCreated for the entry's evidence records, and
// RelationshipCreated for the entry's typed edges.
type Deriver struct{}

// Compile-time seam check: the runtime pool consumes Deriver as an
// event.Deriver.
var _ event.Deriver = Deriver{}

// Derive implements event.Deriver. It accepts JSEntry (and *JSEntry, the
// pointer form some callers hold); every other result — including nil —
// yields nil. Placeholder and zero-identity entries carry no observation
// and yield nil.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	var entry JSEntry
	switch r := result.(type) {
	case JSEntry:
		entry = r
	case *JSEntry:
		if r == nil {
			return nil
		}
		entry = *r
	default:
		return nil
	}
	if entry.URL.Identity().IsZero() || isPlaceholder(entry) {
		return nil
	}
	at := ev.At
	var out []event.Event
	appendDerive := func(e event.Event) bool {
		if len(out) >= maxDerivedPerJob {
			return false
		}
		out = append(out, e)
		return true
	}
	if entry.JS != nil && !entry.JS.Identity().IsZero() {
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity: entry.JS.ID(),
			Kind:     string(asset.KindJavaScript),
		})) {
			return out
		}
	}
	for _, sm := range entry.SourceMaps {
		if sm.Identity().IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity: sm.ID(),
			Kind:     string(asset.KindSourceMap),
		})) {
			return out
		}
	}
	for _, ep := range entry.Endpoints {
		if ep.Identity().IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity: ep.ID(),
			Kind:     string(asset.KindEndpoint),
			Method:   ep.Method,
			Path:     ep.URL.Path,
		})) {
			return out
		}
	}
	for _, sec := range entry.Secrets {
		if sec.Identity().IsZero() {
			continue
		}
		// Secret observations carry type (in the kind + identity) and
		// confidence only: the raw value is never copied into a top-level
		// event field.
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity:   sec.ID(),
			Kind:       string(asset.KindSecretCandidate),
			Confidence: clampConfidence(sec.Prov.Confidence),
		})) {
			return out
		}
	}
	for _, tech := range entry.Technologies {
		if tech.Identity().IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity:   tech.ID(),
			Kind:       string(asset.KindTechnology),
			Confidence: clampConfidence(tech.Prov.Confidence),
		})) {
			return out
		}
	}
	for _, e := range entry.Evidence {
		if e.Identity().IsZero() || e.Source.IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindEvidenceCreated, at, event.EvidenceCreated{
			Identity: e.ID(),
			Source:   e.Source.String(),
			Method:   string(e.Method),
		})) {
			return out
		}
	}
	for _, rel := range entry.Relationships {
		if rel.From.IsZero() || rel.To.IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindRelationshipCreated, at, event.RelationshipCreated{
			From: rel.From.String(),
			To:   rel.To.String(),
			Kind: string(rel.Kind),
		})) {
			return out
		}
	}
	return out
}

// clampConfidence maps a provenance confidence into the event payload's
// [0,1] contract: NaN and out-of-range values become 0 (unknown), the
// documented AssetDiscovered zero value.
func clampConfidence(c float64) float64 {
	if c != c || c < 0 || c > 1 {
		return 0
	}
	return c
}
