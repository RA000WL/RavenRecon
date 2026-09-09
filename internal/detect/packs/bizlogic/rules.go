package bizlogic

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleWorkflowStateTransition = "bizlogic.workflow.state-transition"

	// depAuthzIDOR is the rule's single dependency: the level-1 authz
	// rule whose candidate findings mark the auth-divergent member of a
	// candidate flow. The registry Validate graph fails when
	// authz.idor.insecure-direct-object is not registered alongside this
	// pack, and the engine dep-skip gate keeps this rule honest (skipped
	// with a dependency reason, never executed blind) when authz does
	// not complete. Triage (T1 token signals) and apis/web (opportunistic
	// class signals) findings are read from PriorFindings when their
	// packs ran — they are never hard dependencies (minimal gating).
	depAuthzIDOR = "authz.idor.insecure-direct-object"

	// depTriageIDOR is the T1 token source: the level-0 triage
	// classifier whose findings carry the IDOR-flagged param names
	// (params metadata) this rule correlates. Read opportunistically
	// from PriorFindings — never a declared dependency.
	depTriageIDOR = "triage.idor"
)

// Rules returns the bizlogic pack's single workflow-signal rule. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule; the whole pack passes a registry's Register +
// Validate only alongside the authz pack (the dependency graph carries the
// authz.idor.insecure-direct-object edge, so validation is the acyclicity
// check plus the registered-dependency check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("bizlogic: %w", err)
	}
	rules := []detect.Rule{
		newBizlogicRule(ruleWorkflowStateTransition, "Workflow State Transition",
			"Flags same-host endpoint sets sharing one triage-flagged IDOR query param where the observed graph co-locates every step and one step carries an authz IDOR candidate: a researcher-review candidate multi-step workflow. Subject is the identity-smallest step; peers ride metadata. Verdict candidate-flow only — a correlation over observed signals, never a confirmed transition (AGENTS §0.1). Info only: confidence 0.5 for 2-step flows, 0.6 for 3+ steps — never medium or higher.",
			detect.CategoryBusinessLogic,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputRelationships},
			workflowStateTransitionDetector, "1.0.0",
			depAuthzIDOR),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	return rules, nil
}

func newBizlogicRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon BizLogic Pack",
		Enabled:       true,
		Detector:      det,
	}
}
