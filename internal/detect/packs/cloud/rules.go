package cloud

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 1
	requiredAPIMinor = 0

	ruleAWSKeyIndicator   = "cloud.aws.key-indicator"
	ruleBucketURL         = "cloud.bucket.url"
	ruleFirebaseIndicator = "cloud.firebase.indicator"
)

// Rules returns the cloud pack's three informational cloud-surface rules
// (v2.0 Batch 5, research Q5: indicators only — no live verification, no
// exploitability claims). The API compatibility check runs first, so an
// incompatible SDK level surfaces as a load-time error before any rule is
// registered. Every returned rule passes detect.ValidateRule, and the whole
// pack passes a registry's Register + Validate (the dependency graph is
// empty, so validation is the acyclicity check).
//
// RequiredAssetTypes names each rule's SINGLE primary kind because the
// census gate is conjunctive (every declared kind must be present): gating a
// multi-domain rule on all of its domains would skip it whenever any one is
// absent, losing true positives from the domains that ARE present. The
// choice follows the apis-pack precedent (multi-domain rules gated on their
// dominant kind); the detectors still scan every domain they declare.
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("cloud: %w", err)
	}
	rules := []detect.Rule{
		newCloudRule(ruleAWSKeyIndicator, "AWS Key Indicator",
			"Detects AWS credential INDICATORS: secret candidates typed aws whose value carries an AKIA/ASIA access-key-ID shape (providers' EXAMPLE-convention values suppressed), or evidence records carrying that shape (subject: the evidence source). Informational observation only — never claims the credential is valid, usable, or exploitable; candidate values are never copied into findings.",
			detect.CategoryCloud,
			[]detect.RuleInput{detect.InputSecrets, detect.InputEvidence},
			awsKeyIndicatorDetector, "1.0.0"),
		newCloudRule(ruleBucketURL, "Cloud Bucket URL",
			"Detects endpoints whose URL host is a known cloud storage endpoint shape: s3.amazonaws.com (path-style and <bucket>. virtual-hosted), storage.googleapis.com, blob.core.windows.net (<account>.-prefixed). Informational per-endpoint finding naming the provider — an observed bucket URL is recon surface, never a claim that the bucket is public or listable.",
			detect.CategoryCloud,
			[]detect.RuleInput{detect.InputEndpoints},
			bucketURLDetector, "1.0.0"),
		newCloudRule(ruleFirebaseIndicator, "Firebase Indicator",
			"Detects Firebase service indicators: endpoint URLs referencing firebase hosts/paths, technology detections named Firebase, evidence whose structured indicator mentions firebase or whose value cites firebaseio.com/firebaseapp.com. Informational per-subject finding — never a claim that Firebase databases or config are exposed.",
			detect.CategoryCloud,
			[]detect.RuleInput{detect.InputEndpoints, detect.InputEvidence, detect.InputTechnology},
			firebaseIndicatorDetector, "1.0.0"),
	}
	rules[0].RequiredAssetTypes = []asset.Kind{asset.KindSecretCandidate}
	rules[1].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[2].RequiredAssetTypes = []asset.Kind{asset.KindEvidence}
	return rules, nil
}

func newCloudRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon Cloud Pack",
		Enabled:       true,
		Detector:      det,
	}
}
