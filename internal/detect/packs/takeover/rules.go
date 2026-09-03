package takeover

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleCNAMEUnclaimed = "takeover.cname.unclaimed"
	ruleCNAMEDangling  = "takeover.cname.dangling"
	ruleS3Bucket       = "takeover.s3.bucket"
)

// Rules returns the takeover pack's three recon rules. The API compatibility
// check runs first, so an incompatible SDK level surfaces as a load-time
// error before any rule is registered. Every returned rule passes
// detect.ValidateRule, and the whole pack passes a registry's Register +
// Validate (dependency graph empty, so validation is acyclicity check).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("takeover: %w", err)
	}
	rules := []detect.Rule{
		newTakeoverRule(ruleCNAMEUnclaimed, "Takeover CNAME Unclaimed",
			"Detects dangling CNAME to unclaimed provider fingerprint (curated suffix list: github.io, herokuapp.com, amazonaws.com, azurewebsites.net, cloudfront.net, etc) with no A/AAAA for the CNAME target at depth 1. Per-host informational observation — never claims exploitability (AGENTS §0.1).",
			[]detect.RuleInput{detect.InputAssets, detect.InputRelationships},
			cnameUnclaimedDetector, "1.0.0"),
		newTakeoverRule(ruleCNAMEDangling, "Takeover CNAME Dangling",
			"Detects dangling CNAME generically (any target with no A/AAAA) excluding provider-matched hosts handled by cname.unclaimed. Per-host informational orphan signal — never claims exploitability.",
			[]detect.RuleInput{detect.InputAssets, detect.InputRelationships},
			cnameDanglingDetector, "1.0.0"),
		newTakeoverRule(ruleS3Bucket, "Takeover S3 Bucket",
			"Detects S3 bucket endpoint via URL host shape (.s3.amazonaws.com, s3.amazonaws.com, .s3-website variants). Per-endpoint informational indicator via techintel endpoint shape — never claims bucket existence or exploitability.",
			[]detect.RuleInput{detect.InputEndpoints},
			s3BucketDetector, "1.0.0"),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	rules[2].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	return rules, nil
}

func newTakeoverRule(id, name, description string, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
	return detect.Rule{
		ID:            id,
		Name:          name,
		Description:   description,
		Category:      detect.CategoryInformation,
		Version:       version,
		Inputs:        inputs,
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Dependencies:  deps,
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "RavenRecon Takeover Pack",
		Enabled:       true,
		Detector:      det,
	}
}
