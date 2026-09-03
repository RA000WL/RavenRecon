package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleJWTNoneAlg = "auth.jwt.none-alg"
)

// Rules returns the auth pack's single SDK v2 demonstration rule.
// The API compatibility check runs first, so an incompatible SDK level
// surfaces as a load-time error before any rule is handed out. Every
// returned rule passes detect.ValidateRule, and the whole pack passes a
// registry's Register + Validate (the dependency graph is empty — a single
// level-0 rule — but the detector still proves PriorFindings/GraphView are
// visible on v2 and inexpressible on v1).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	rules := []detect.Rule{
		newAuthRule(ruleJWTNoneAlg, "JWT None Alg",
			"Stateless demonstration of SDK v2 inter-rule dataflow: reads Context.PriorFindings (findings from completed levels, deterministically sorted) and Context.GraphView (Neighbors/Path over Snapshot relationships). Reports an informational finding per host that has an outgoing edge in the observed graph; when PriorFindings is non-empty the finding carries prior_seen metadata. On SDK v1 the detector would not compile (no PriorFindings/GraphView). Per §0.1 this is a shape indicator over the observed corpus only — it never claims exploitability and never performs live verification.",
			detect.CategoryAuthentication,
			[]detect.RuleInput{detect.InputAssets, detect.InputRelationships},
			jwtNoneAlgDetector, "1.0.0"),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	return rules, nil
}

func newAuthRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
	return detect.Rule{
		ID:            id,
		Name:          name,
		Description:   description,
		Category:      category,
		Version:       version,
		Inputs:        inputs,
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Dependencies:  deps,
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "RavenRecon Auth Pack",
		Enabled:       true,
		Detector:      det,
	}
}

// jwtNoneAlgDetector is the SDK v2 probe: it exercises both new views.
//
//   - PriorFindings: deterministically sorted findings from completed
//     levels (empty for this level-0 rule, but the field is now visible —
//     inexpressible on v1). The detector logs the count and, when
//     non-empty, carries prior_seen metadata on findings it emits (a
//     level-1 dependent would see it; the log proves the view is wired
//     even at level 0).
//   - GraphView: read-only Neighbors/Path over Snapshot relationships. The
//     detector exercises Neighbors per host and Path between the first two
//     assets when at least two exist, then emits one informational finding
//     per host that has an outgoing edge.
//
// All findings are bounded at 256 and cite only observed assets (the
// observed-corpus rule) via asset.NewFinding; timestamps come from the
// injected Clock for determinism.
func jwtNoneAlgDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// PriorFindings is now visible on SDK v2 — log its size (deterministically sorted by the engine).
	if dctx.PriorFindings != nil {
		dctx.Logger.Log(detect.LevelInfo, ruleJWTNoneAlg, fmt.Sprintf("prior findings visible: %d", len(dctx.PriorFindings)))
		// Defensive determinism check: PriorFindings must be sorted by identity when non-empty.
		for i := 1; i < len(dctx.PriorFindings); i++ {
			if dctx.PriorFindings[i-1].Identity().String() > dctx.PriorFindings[i].Identity().String() {
				return nil, fmt.Errorf("prior findings not sorted")
			}
		}
	}
	// GraphView is the read-only graph index built once per Run.
	if dctx.GraphView == nil {
		// Outside the engine (hand-constructed Context) GraphView may be nil — no findings, no panic.
		return nil, nil
	}
	if len(dctx.Assets) >= 2 {
		if path := dctx.GraphView.Path(dctx.Assets[0], dctx.Assets[1]); len(path) > 0 {
			dctx.Logger.Log(detect.LevelInfo, ruleJWTNoneAlg, fmt.Sprintf("path %s → %s length %d", dctx.Assets[0], dctx.Assets[1], len(path)))
		}
	}
	var out []asset.Finding
	for _, id := range dctx.Assets {
		if id.Kind != asset.KindHost {
			continue
		}
		neigh := dctx.GraphView.Neighbors(id)
		if len(neigh) == 0 {
			continue
		}
		meta := map[string]string{}
		if len(dctx.PriorFindings) > 0 {
			meta["prior_seen"] = "true"
			meta["prior_count"] = strconv.Itoa(len(dctx.PriorFindings))
		}
		f, err := authFinding(dctx, ruleJWTNoneAlg, "JWT None Alg", detect.CategoryAuthentication, id, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
		if len(out) >= 256 {
			break
		}
	}
	return out, nil
}

// authFinding builds one canonical auth-pack finding.
func authFinding(dctx *detect.Context, ruleID, ruleName string, cat detect.Category, subject asset.Identity, related []asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "auth pack signal: "+ruleID, subject, asset.Provenance{Source: "auth"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:        ruleID,
		RuleName:      ruleName,
		Category:      cat.String(),
		Subject:       subject,
		Confidence:    0.6,
		Evidence:      []asset.Evidence{ev},
		RelatedAssets: related,
		Metadata:      meta,
		Priority:      detect.PriorityInfo.String(),
		Status:        detect.StatusOpen.String(),
		Created:       dctx.Clock.Now().UTC(),
	})
}
