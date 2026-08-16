package priority

import (
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestRecommendProjection pins the Recommend contract: a pure projection
// of the emitted factor list — every indicator factor yields exactly one
// recommendation in factor order, carrying the factor's evidence and
// weight verbatim; confidence factors yield none; repeated calls are
// identical; a zero-factor surface yields none.
func TestRecommendProjection(t *testing.T) {
	ic, rc := mustCatalogs(t)
	sig := baseSignal()
	sig.Technologies = []TechSignal{{Name: "auth0", Category: "authentication", Confidence: 0.9, Identity: "authentication/auth0"}}
	sig.Secrets = []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: 0.8, Identity: "secret_candidate:aws/x/y"}}
	sig.Observations = 3
	out, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}

	recs := Recommend(out)
	if len(recs) == 0 {
		t.Fatal("expected recommendations from an indicator-carrying surface")
	}
	// The projection follows the surface's factor order and skips
	// confidence factors (their Recommendation is empty by construction).
	var indicatorFactors []Factor
	for _, f := range out.Factors {
		if strings.HasPrefix(f.Name, "confidence") {
			continue
		}
		indicatorFactors = append(indicatorFactors, f)
	}
	if len(recs) != len(indicatorFactors) {
		t.Fatalf("recommendations = %d, want one per indicator factor (%d)", len(recs), len(indicatorFactors))
	}
	for i, r := range recs {
		f := indicatorFactors[i]
		if r.Factor != f.Name || r.Text != f.Recommendation || r.Weight != f.Weight || !reflect.DeepEqual(r.Evidence, f.Evidence) {
			t.Errorf("recommendation %d (%+v) does not mirror its factor %+v", i, r, f)
		}
		if len(r.Evidence) == 0 {
			t.Errorf("recommendation %d carries no evidence", i)
		}
		if strings.Contains(r.Text, "%s") || strings.Contains(r.Text, "%q") {
			t.Errorf("recommendation %d carries a raw format verb: %q", i, r.Text)
		}
	}

	// Determinism: the projection is stable across calls.
	if !reflect.DeepEqual(recs, Recommend(out)) {
		t.Error("Recommend must be deterministic across calls")
	}

	// A zero-factor surface yields no recommendations, not a panic.
	empty := SurfaceAsset{Identity: sig.Identity, Kind: sig.Kind}
	if got := Recommend(empty); got != nil {
		t.Errorf("zero-factor surface recommends %v, want none", got)
	}
}

// TestIndicatorFactorsCarryRecommendations pins the score-time side of the
// chosen mechanism: every indicator factor a production scoring run emits
// carries a non-empty rendered recommendation (term-substituted where the
// entry is a term matcher), and no confidence factor ever does.
func TestIndicatorFactorsCarryRecommendations(t *testing.T) {
	ic, rc := mustCatalogs(t)
	sig := baseSignal()
	sig.Technologies = []TechSignal{{Name: "kibana", Category: "monitoring", Confidence: 0.7, Identity: "monitoring/kibana"}}
	sig.Secrets = []SecretSignal{{Type: asset.SecretTypeStripe, Confidence: 0.8, Identity: "secret_candidate:stripe/x/y"}}
	sig.Port = 9090
	sig.Headers = []string{"x-powered-by: express"}
	out, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	var indicator, confidence int
	for _, f := range out.Factors {
		if strings.HasPrefix(f.Name, "confidence") {
			confidence++
			if f.Recommendation != "" {
				t.Errorf("confidence factor %q must not carry a recommendation", f.Name)
			}
			continue
		}
		indicator++
		if f.Recommendation == "" {
			t.Errorf("indicator factor %q carries no recommendation", f.Name)
		}
		if len(f.Recommendation) > maxRecommendationBytes {
			t.Errorf("indicator factor %q recommendation is %d bytes over bound %d", f.Name, len(f.Recommendation), maxRecommendationBytes)
		}
	}
	if indicator < 3 || confidence < 2 {
		t.Errorf("fixture covers too few factors: %d indicator, %d confidence", indicator, confidence)
	}
}
