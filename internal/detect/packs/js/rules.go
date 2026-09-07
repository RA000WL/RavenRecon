package js

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	// requiredAPIMinor is 1: every rule in this pack reads the SDK v2.1
	// retained-script-body channel (Context.JavaScriptContent) — without
	// it the detectors are silent by construction, so the pack refuses
	// to load on a 2.0 surface rather than run blind.
	requiredAPIMinor = 1

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
			"Detects DOM XSS sinks in code via a token-aware structural scan over retained bodies (NEW-123): innerHTML/outerHTML as dotted property writes with an assignment operator, document.write as an identifier-bounded call. Comment/string/template mentions, bare reads, and comparisons stay quiet. Informational, per-script finding on the first code sink; scripts without a retained body are silent.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			domXSSDetector, "1.3.0"),
		newJsRule(rulePostMessage, "PostMessage No Origin Check",
			"Detects postMessage handlers without origin checks via a token-aware structural scan over retained bodies (NEW-123): fires when a code addEventListener call carries the static event-type argument \"message\" (handler scope — a \"message\" literal elsewhere does not count) and no .origin read occurs in code (a comment-only origin mention does not suppress). Informational, per-script finding; scripts without a retained body are silent.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			postMessageDetector, "1.3.0"),
		newJsRule(ruleProtoPollute, "Prototype Pollution",
			"Detects prototype-pollution writes in code via a token-aware structural scan over retained bodies (NEW-123): __proto__/constructor.prototype as dotted property access with a statement-bounded code assignment. Comment/string mentions and bare reads stay quiet. Informational, per-script finding; scripts without a retained body are silent.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputJavaScript},
			protoPollutionDetector, "1.3.0"),
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
