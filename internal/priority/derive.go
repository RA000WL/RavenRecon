package priority

import (
	"math"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps how many events one job result may derive. The cap
// is an observation aid only: derived events feed the live bus stream (TUI,
// logs), never the reports — no report ever reads the bus, so dropping
// excess derivation cannot change a report. A surface carries a bounded
// factor list, so a legitimate result never approaches it; only a hostile
// or hand-built result can.
const maxDerivedPerJob = 512

// maxDerivedTextBytes bounds a factor recommendation carried in a derived
// event. It mirrors the bus's RecommendationCreated.Text bound
// (event.maxRecommendationTextBytes = 256), which the engine's own
// maxRecommendationBytes already respects: engine-rendered recommendations
// always fit, so only a hand-built factor can exceed it — and an overlong
// recommendation is skipped, never truncated, because the payload contract
// carries the rendered text verbatim.
const maxDerivedTextBytes = 256

// Deriver converts a completed pool job's raw result into derived canonical
// events at the pool-job boundary (see event.Deriving). Engines never emit
// these events themselves.
//
// One completed AssetResult derives, in deterministic surface order:
//
//   - one asset_discovered for the scored surface identity (kind mirrored
//     from the surface, confidence carried as the surface confidence);
//   - one recommendation_created per factor carrying a rendered
//     recommendation (the factor text verbatim, the surface level, the
//     factor weight). Confidence factors carry no recommendation and
//     derive nothing beyond the surface asset itself.
//
// Non-completed results (failed, cancelled) and results without a surface
// produced no score and derive nothing. Unknown or nil results derive
// nothing.
type Deriver struct{}

// Derive implements event.Deriver.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	var res AssetResult
	switch r := result.(type) {
	case AssetResult:
		res = r
	case *AssetResult:
		if r == nil {
			return nil
		}
		res = *r
	default:
		return nil
	}
	if res.Status != StatusCompleted || res.Surface == nil {
		return nil
	}
	s := res.Surface
	out := make([]event.Event, 0, len(s.Factors)+1)
	appendCapped := func(e event.Event) {
		if len(out) >= maxDerivedPerJob {
			return
		}
		out = append(out, e)
	}
	appendCapped(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
		Identity:   s.Identity.String(),
		Kind:       string(s.Kind),
		Confidence: validConfidence(s.Confidence),
	}))
	for _, f := range s.Factors {
		if f.Recommendation == "" {
			continue
		}
		if len(f.Recommendation) > maxDerivedTextBytes {
			continue
		}
		appendCapped(event.New(event.KindRecommendationCreated, ev.At, event.RecommendationCreated{
			Identity: s.Identity.String(),
			Text:     f.Recommendation,
			Level:    string(s.Level),
			Weight:   validConfidence(f.Weight),
		}))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validConfidence sanitizes a score for a Confidence/Weight field: 0 means
// unknown (per the payload contract), so anything outside [0,1] —
// including NaN, which would otherwise slip past the bus's range check —
// degrades to unknown instead of emitting an invalid event. Engine-produced
// values are always finite and in range; this only guards hand-built
// results.
func validConfidence(c float64) float64 {
	if math.IsNaN(c) || c < 0 || c > 1 {
		return 0
	}
	return c
}
