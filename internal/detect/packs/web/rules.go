package web

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleCSPMissing       = "web.csp.missing"
	ruleHSTSMissing      = "web.hsts.missing"
	ruleCORSWildcard     = "web.cors.wildcard"
	ruleRobotsExposed    = "web.robots.exposed"
	ruleSourceMapExposed = "web.sourcemap.exposed"
)

// Rules returns the web pack's five web-security rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule, and the whole pack passes a registry's
// Register + Validate (the dependency graph is empty, so validation is the
// acyclicity check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	rules := []detect.Rule{
		newWebRule(ruleCSPMissing, "CSP Missing",
			"Detects absence of Content-Security-Policy via evidence/technology corpus — no Technology named csp/content-security-policy and no Evidence with header:content-security-policy indicator. Per-host informational finding when absent.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputAssets, detect.InputEvidence, detect.InputTechnology},
			cspMissingDetector, "1.0.0"),
		newWebRule(ruleHSTSMissing, "HSTS Missing",
			"Detects absence of Strict-Transport-Security via header evidence — no Evidence with header:strict-transport-security indicator. Per-host informational finding when absent.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputAssets, detect.InputEvidence},
			hstsMissingDetector, "1.0.0"),
		newWebRule(ruleCORSWildcard, "CORS Wildcard",
			"Detects Access-Control-Allow-Origin == \"*\" wildcard via header evidence indicator header:access-control-allow-origin with value \"*\". Per-source misconfiguration finding.",
			detect.CategoryMisconfig,
			[]detect.RuleInput{detect.InputEvidence},
			corsWildcardDetector, "1.0.0"),
		newWebRule(ruleRobotsExposed, "Robots Exposed",
			"Detects exposed /robots.txt via endpoint URL path /robots.txt or evidence indicator/value naming robots.txt. Informational, per-endpoint/source finding.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputEvidence, detect.InputTechnology},
			robotsExposedDetector, "1.0.0"),
		newWebRule(ruleSourceMapExposed, "Source Map Exposed",
			"Detects exposed JavaScript source maps via JavaScript URL ending in .map, discovery source sourcemap, or evidence method sourcemap. Informational, per-script finding.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript, detect.InputEvidence},
			sourcemapExposedDetector, "1.0.0"),
	}
	// RequiredAssetTypes gates (NEW-108 single-kind-gate sweep). Each rule
	// declares ONE primary kind because the census gate is conjunctive —
	// listing every input domain would skip the rule whenever ANY domain is
	// absent (cloud pack precedent). The documented tradeoff: a multi-domain
	// rule is skipped even when its OTHER domains carry legitimate carriers
	// (e.g. robots.txt evidence without any endpoint asset), but the engine
	// records the honest skip reason naming the missing kind (engine.go
	// missingRequiredKind → SkipReason), so the drop is never silent.
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	rules[2].RequiredAssetTypes = []asset.Kind{asset.KindEvidence}
	rules[3].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[4].RequiredAssetTypes = []asset.Kind{asset.KindJavaScript}
	return rules, nil
}

func newWebRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon Web Pack",
		Enabled:       true,
		Detector:      det,
	}
}
