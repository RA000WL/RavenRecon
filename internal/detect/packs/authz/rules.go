package authz

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleIDORInsecureDirectObject = "authz.idor.insecure-direct-object"
	ruleIDORPathObject           = "authz.idor.path-object"

	// depTriageIDOR is the rule's single dependency: the level-0 triage
	// classifier whose findings carry the IDOR-flagged param names (params
	// metadata) this rule correlates. The registry Validate graph fails
	// when triage.idor is not registered alongside this pack, and the
	// engine dep-skip gate keeps this rule honest (skipped with a
	// dependency reason, never executed blind) when triage.idor does not
	// complete.
	depTriageIDOR = "triage.idor"

	// depApisRestIDOR is Rule 2's single dependency: the level-0 apis
	// classifier whose findings mark the endpoints carrying numeric/UUID
	// path segments (exact registered ID
	// "api.rest.idor-indicator" — internal/detect/packs/apis/rules.go).
	// The registry Validate graph fails when api.rest.idor-indicator is
	// not registered alongside this pack, and the engine dep-skip gate
	// keeps Rule 2 honest (skipped with a dependency reason, never
	// executed blind) when api.rest.idor-indicator does not complete.
	depApisRestIDOR = "api.rest.idor-indicator"
)

// Rules returns the authz pack's two authorization-signal rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule; the whole pack passes a registry's Register +
// Validate only alongside the triage pack (for Rule 1's triage.idor edge)
// and the apis pack (for Rule 2's api.rest.idor-indicator edge).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("authz: %w", err)
	}
	rules := []detect.Rule{
		newAuthzRule(ruleIDORInsecureDirectObject, "IDOR Insecure Direct Object",
			"Flags unauthenticated endpoints sharing a triage-flagged IDOR query param with an authenticated peer on a different host of the same domain (cross-host same-domain auth divergence). Subject is the unauthenticated endpoint; the peer rides metadata. Verdict candidate-surface only — a researcher-review candidate, never proof of unauthorized access (AGENTS §0.1). Medium/info split: reflection-backed pairs carry medium, name-only pairs info.",
			detect.CategoryAuthorization,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputRelationships, detect.InputEvidence, detect.InputTechnology},
			idorInsecureDirectObjectDetector, "1.0.0",
			depTriageIDOR),
		newAuthzRule(ruleIDORPathObject, "IDOR Path Object",
			"Flags unauthenticated endpoints sharing a numeric/UUID path object segment (api.rest.idor-indicator signal, year/pagination exclusions apply) with an authenticated peer on a different host of the same domain (cross-host same-domain auth divergence). Subject is the unauthenticated endpoint; the peer rides metadata. Verdict candidate-surface only — a researcher-review candidate, never proof of unauthorized access (AGENTS §0.1). Fixed info/0.5: the apis signal carries no reflection marker to split on — never medium or higher.",
			detect.CategoryAuthorization,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputRelationships, detect.InputEvidence, detect.InputTechnology},
			idorPathObjectDetector, "1.0.0",
			depApisRestIDOR),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	return rules, nil
}

func newAuthzRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon AuthZ Pack",
		Enabled:       true,
		Detector:      det,
	}
}
