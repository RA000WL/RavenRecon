package techintel

import (
	"math"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps how many events one job result may derive. The cap
// is an observation aid only: derived events feed the live bus stream (TUI,
// logs), never the reports — no report ever reads the bus, so dropping
// excess derivation cannot change a report. Engine collections are already
// bounded by the analysis caps, so legitimate entries never approach it;
// only a hostile or hand-built result can.
const maxDerivedPerJob = 512

// Deriver converts a completed pool job's raw result into derived canonical
// events at the pool-job boundary (see event.Deriving). Engines never emit
// these events themselves.
//
// One completed ReportEntry derives, in deterministic entry order
// (technologies score-desc, evidence and relationships by identity — the
// job normalizes before returning):
//
//   - one asset_discovered per detected technology (the technology identity,
//     carried with its detection score as confidence);
//   - one evidence_created per indicator record (identity, source, method);
//   - one relationship_created per asset-graph edge (from, to, kind).
//
// The observation identity itself (URL/endpoint) is the job's INPUT, not
// its product — whoever discovered it already emitted it — so it is never
// re-emitted here. Non-completed entries (failed, cancelled) produced no
// assets and derive nothing. Unknown or nil results derive nothing.
type Deriver struct{}

// Derive implements event.Deriver.
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
	if entry.Status != StatusCompleted {
		return nil
	}
	out := make([]event.Event, 0, len(entry.Technologies)+len(entry.Evidence)+len(entry.Relationships))
	appendCapped := func(e event.Event) {
		if len(out) >= maxDerivedPerJob {
			return
		}
		out = append(out, e)
	}
	for _, tr := range entry.Technologies {
		appendCapped(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   tr.Technology.Identity().String(),
			Kind:       string(asset.KindTechnology),
			Confidence: validConfidence(tr.Score),
		}))
	}
	for _, e := range entry.Evidence {
		appendCapped(event.New(event.KindEvidenceCreated, ev.At, event.EvidenceCreated{
			Identity: e.Identity().String(),
			Source:   e.Source.String(),
			Method:   string(e.Method),
		}))
	}
	for _, rel := range entry.Relationships {
		appendCapped(event.New(event.KindRelationshipCreated, ev.At, event.RelationshipCreated{
			From: rel.From.String(),
			To:   rel.To.String(),
			Kind: string(rel.Kind),
		}))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validConfidence sanitizes a score for the Confidence field: 0 means
// unknown (per the payload contract), so anything outside [0,1] — including
// NaN, which would otherwise slip past the bus's range check — degrades to
// unknown instead of emitting an invalid event. Engine-produced scores are
// always finite and in range; this only guards hand-built results.
func validConfidence(c float64) float64 {
	if math.IsNaN(c) || c < 0 || c > 1 {
		return 0
	}
	return c
}
