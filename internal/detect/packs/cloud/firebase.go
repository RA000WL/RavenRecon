package cloud

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// firebaseConfidence rates heuristic Firebase indicators (see the rule's
// conservative carrier split below): observed, never verified.
const firebaseConfidence = 0.6

// firebaseIndicatorDetector reports Firebase service indicators observed in
// the corpus. Informational only — an indicator says a Firebase project is
// referenced by in-scope material, never that its databases or config are
// exposed or readable (§0.1). Conservative carriers: endpoint URLs whose
// host/path mentions Firebase; technology names containing "firebase";
// evidence whose structured INDICATOR mentions firebase, or whose VALUE
// cites one of the specific Firebase service hosts (plain "firebase" inside
// free-text values is too false-positive-prone to fire on alone).
func firebaseIndicatorDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleFirebaseIndicator+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	carrier := make(map[asset.Identity]string)
	var subjects []asset.Identity
	add := func(id asset.Identity, via string) {
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		carrier[id] = via
	}
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// "firebase" covers the service hosts (firebaseio.com,
		// firebaseapp.com) and Firebase console/hosting paths alike.
		if strings.Contains(strings.ToLower(ep.URL.String()), "firebase") {
			add(ep.Identity(), "endpoint")
		}
	}
	for _, t := range dctx.Technologies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToLower(t.Name), "firebase") {
			add(t.Identity(), "technology")
		}
	}
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ev.Source.IsZero() {
			continue
		}
		lowInd := strings.ToLower(ev.Indicator)
		lowVal := strings.ToLower(ev.Value)
		if strings.Contains(lowInd, "firebase") ||
			strings.Contains(lowVal, "firebaseio.com") || strings.Contains(lowVal, "firebaseapp.com") {
			add(ev.Source, "evidence")
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= maxFindingsPerRule {
			break
		}
		f, err := cloudFinding(dctx, ruleFirebaseIndicator, "Firebase Indicator", firebaseConfidence, s,
			map[string]string{"signal": "firebase_indicator", "carrier": carrier[s]})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleFirebaseIndicator)
	return out, nil
}
