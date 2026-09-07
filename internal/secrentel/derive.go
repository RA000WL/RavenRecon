// Derivation bridge: completed pool-job ReportEntry results become
// canonical secret observations in the event stream.
//
// Engines never emit derived events themselves: the runtime pool wraps the
// configured Observer in an event.Deriving bridge holding this Deriver, so
// raw ReportEntry job results are converted at the pool-job boundary. A nil
// Observer stays the off switch (the bridge is inert); unknown results
// derive nothing.
//
// §0 secrecy: secret VALUES never enter the event stream. Each candidate
// derives exactly one AssetDiscovered carrying the candidate TYPE (in the
// kind and the canonical identity), the composed confidence, and the
// identity — and nothing else. The entry's MethodSecret evidence records
// carry raw matched values, so they are deliberately NOT derived; likewise
// only source→candidate edges are derived, never candidate→evidence edges
// (whose evidence identities embed those raw values). Related pair
// siblings have no RelationshipKind in the asset vocabulary, so they stay
// out too — inventing an edge kind is prohibited.
package secrentel

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps the derived events of one pool job. Entries are
// already per-document bounded, but the union (candidates + edges) is
// re-capped here so one hostile job result can never inflate the stream.
const maxDerivedPerJob = 512

// Deriver converts completed pool-job ReportEntry results into canonical
// derived events: one AssetDiscovered per secret candidate (type +
// confidence + identity only) and one RelationshipCreated per
// source→candidate edge present in the entry.
type Deriver struct{}

// Compile-time seam check: the runtime pool consumes Deriver as an
// event.Deriver.
var _ event.Deriver = Deriver{}

// Derive implements event.Deriver. It accepts ReportEntry (and *ReportEntry,
// the pointer form the accumulator holds); every other result — including
// nil — yields nil.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	var entry ReportEntry
	switch r := result.(type) {
	case ReportEntry:
		entry = r
	case *ReportEntry:
		if r == nil {
			return nil
		}
		entry = *r
	default:
		return nil
	}
	if entry.ID.IsZero() {
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
	for _, c := range entry.Secrets {
		if c.cand.Identity().IsZero() {
			continue
		}
		if !appendDerive(event.New(event.KindAssetDiscovered, at, event.AssetDiscovered{
			Identity:   c.cand.ID(),
			Kind:       string(asset.KindSecretCandidate),
			Confidence: clampConfidence(c.confidence.Score),
		})) {
			return out
		}
	}
	for _, rel := range entry.Relationships {
		// Source→candidate edges only (url_to_secret_candidate,
		// javascript_to_secret_candidate): candidate→evidence edges
		// reference MethodSecret evidence identities that embed raw
		// matched values, so they never enter the stream.
		switch rel.Kind {
		case asset.RelationshipURLToSecretCandidate, asset.RelationshipJavaScriptToSecretCandidate:
		default:
			continue
		}
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

// clampConfidence maps a composed confidence score into the event payload's
// [0,1] contract: NaN and out-of-range values become 0 (unknown), the
// documented AssetDiscovered zero value.
func clampConfidence(c float64) float64 {
	if c != c || c < 0 || c > 1 {
		return 0
	}
	return c
}
