package apis

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 1
	requiredAPIMinor = 0

	ruleOpenAPIExposed       = "api.openapi.exposed"
	ruleRestIDORIndicator    = "api.rest.idor-indicator"
	ruleGraphQLIntrospection = "api.graphql.introspection"
)

// Rules returns the apis pack's three API security rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule, and the whole pack passes a registry's
// Register + Validate (the dependency graph is empty, so validation is the
// acyclicity check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("apis: %w", err)
	}
	rules := []detect.Rule{
		newApisRule(ruleOpenAPIExposed, "OpenAPI Exposed",
			"Detects OpenAPI/Swagger doc endpoints (/openapi.json, /swagger.json, /api-docs) via endpoint URL path or technology/evidence corpus containing openapi/swagger. Informational, per-endpoint/tech finding.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputEvidence, detect.InputTechnology},
			openapiExposedDetector, "1.0.0"),
		newApisRule(ruleRestIDORIndicator, "REST IDOR Indicator",
			"Detects REST endpoint path containing numeric or UUID-like identifier segment indicating potential IDOR surface (heuristic, not exploit). Informational, per-endpoint finding.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputEndpoints},
			restIDORIndicatorDetector, "1.0.0"),
		newApisRule(ruleGraphQLIntrospection, "GraphQL Introspection",
			"Detects GraphQL endpoint with introspection enabled indicator or /graphql path present via endpoint URL or evidence/technology corpus. Informational, per-endpoint finding.",
			detect.CategoryAPI,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputEvidence, detect.InputTechnology},
			graphqlIntrospectionDetector, "1.0.0"),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[2].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	return rules, nil
}

func newApisRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon APIs Pack",
		Enabled:       true,
		Detector:      det,
	}
}
