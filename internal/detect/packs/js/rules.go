package js

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 1
	requiredAPIMinor = 0

	ruleDomXSS       = "js.dom.xss"
	rulePostMessage  = "js.postmessage.no-origin-check"
	ruleProtoPollute = "js.prototype.pollution"
)

// Rules returns the js pack's three JavaScript security rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule, and the whole pack passes a registry's
// Register + Validate (the dependency graph is empty, so validation is the
// acyclicity check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("js: %w", err)
	}
	rules := []detect.Rule{
		newJsRule(ruleDomXSS, "DOM XSS",
			"Detects DOM XSS sinks innerHTML/outerHTML/document.write assignment via jsintel parse tree over synthetic script content derived from observed JavaScript URL (whole-token heuristic, informational). Per-script finding when sink present.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			domXSSDetector, "1.0.0"),
		newJsRule(rulePostMessage, "PostMessage No Origin Check",
			"Detects window.addEventListener(\"message\", handler) without origin check (no event.origin comparison in handler body) via jsintel parse tree (whole-token heuristic, informational). Per-script finding when handler lacks origin guard.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			postMessageDetector, "1.0.0"),
		newJsRule(ruleProtoPollute, "Prototype Pollution",
			"Detects assignment to __proto__/constructor.prototype via jsintel parse tree. Informational, per-script finding.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			protoPollutionDetector, "1.0.0"),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindJavaScript}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindJavaScript}
	rules[2].RequiredAssetTypes = []asset.Kind{asset.KindJavaScript}
	return rules, nil
}

func newJsRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon JS Pack",
		Enabled:       true,
		Detector:      det,
	}
}
