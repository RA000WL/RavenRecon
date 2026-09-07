package triage

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleRedirect     = "triage.redirect"
	ruleIDOR         = "triage.idor"
	ruleSQLi         = "triage.sqli"
	ruleLFI          = "triage.lfi"
	ruleSSRF         = "triage.ssrf"
	ruleCMDi         = "triage.cmdi"
	ruleSSTI         = "triage.ssti"
	ruleXSSReflected = "triage.xss_reflected"
)

// Rules returns the triage pack's eight endpoint-triage rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule, and the whole pack passes a registry's
// Register + Validate (the dependency graph is empty, so validation is the
// acyclicity check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("triage: %w", err)
	}
	rules := []detect.Rule{
		newTriageRule(ruleRedirect, "Triage Redirect",
			"Classifies endpoints for open-redirect testing when a query param name matches the curated redirect wordlist (62). Informational testing assignment, per-endpoint, precedence-aware; multi-class params report under primary only. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			redirectDetector, "1.1.0"),
		newTriageRule(ruleIDOR, "Triage IDOR",
			"Classifies endpoints for IDOR testing when a query param name matches the curated IDOR wordlist (37). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			idorDetector, "1.1.0"),
		newTriageRule(ruleSQLi, "Triage SQLi",
			"Classifies endpoints for SQL injection testing when a query param name matches the curated SQLi wordlist (29 core). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			sqliDetector, "1.1.0"),
		newTriageRule(ruleLFI, "Triage LFI",
			"Classifies endpoints for LFI testing when a query param name matches the curated LFI wordlist (33). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			lfiDetector, "1.1.0"),
		newTriageRule(ruleSSRF, "Triage SSRF",
			"Classifies endpoints for SSRF testing when a query param name matches the curated SSRF wordlist (62). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			ssrfDetector, "1.1.0"),
		newTriageRule(ruleCMDi, "Triage CMDi",
			"Classifies endpoints for command-injection testing when a query param name matches the curated RCE wordlist (32). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			cmdiDetector, "1.1.0"),
		newTriageRule(ruleSSTI, "Triage SSTI",
			"Classifies endpoints for SSTI testing when a query param name matches the curated SSTI wordlist (68). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			sstiDetector, "1.1.0"),
		newTriageRule(ruleXSSReflected, "Triage XSS Reflected",
			"Classifies endpoints for reflected XSS testing when a query param name matches the curated XSS wordlist (52). Informational testing assignment, per-endpoint, precedence-aware. Subjects whose every flagged param verdicts not-reflected in urllive canary evidence are dropped; endpoints without verdicts are kept (fail-open).",
			xssDetector, "1.1.0"),
	}
	for i := range rules {
		rules[i].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	}
	return rules, nil
}

func newTriageRule(id, name, description string, det detect.Detector, version string, deps ...string) detect.Rule {
	return detect.Rule{
		ID:            id,
		Name:          name,
		Description:   description,
		Category:      detect.CategoryInformation,
		Version:       version,
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Dependencies:  deps,
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "RavenRecon Triage Pack",
		Enabled:       true,
		Detector:      det,
	}
}
