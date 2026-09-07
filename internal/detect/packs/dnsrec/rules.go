package dnsrec

import (
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

const (
	requiredAPIMajor = 2
	requiredAPIMinor = 0

	ruleNSDangling   = "dnsrec.ns.dangling-delegation"
	ruleMXDangling   = "dnsrec.mx.dangling"
	ruleSPFWeak      = "dnsrec.spf.weak"
	ruleDMARCMissing = "dnsrec.dmarc.missing"
	ruleSRVExposure  = "dnsrec.srv.exposure"
)

// Rules returns the dnsrec pack's five recon rules. The API compatibility
// check runs first, so an incompatible SDK level surfaces as a load-time
// error before any rule is registered. Every returned rule passes
// detect.ValidateRule, and the whole pack passes a registry's Register +
// Validate (dependency graph empty, so validation is acyclicity check).
// All rules are new in this change, so each starts at 1.0.0 per the
// rule content-bump contract (Rule.Version enters the rule result cache
// key: a detector or metadata change without a bump can serve stale cached
// findings).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("dnsrec: %w", err)
	}
	rules := []detect.Rule{
		newDNSRecRule(ruleNSDangling, "DNSRec NS Dangling Delegation",
			"Observes dangling NS delegation shape: a host_to_ns edge whose nameserver target has no host_to_ip (no A/AAAA observed). Per-source-host informational observation — never claims exploitability or unclaimed status. There is no provider-suffix list for nameservers; the orphan shape alone is the signal.",
			[]detect.RuleInput{detect.InputAssets, detect.InputRelationships},
			nsDanglingDetector, "1.0.0"),
		newDNSRecRule(ruleMXDangling, "DNSRec MX Dangling",
			"Observes dangling MX shape: a host_to_mx edge whose exchanger target has no host_to_ip (no A/AAAA observed), mirroring the dangling-CNAME signal. Per-source-host informational observation — never claims exploitability or mail non-deliverability.",
			[]detect.RuleInput{detect.InputAssets, detect.InputRelationships},
			mxDanglingDetector, "1.0.0"),
		newDNSRecRule(ruleSPFWeak, "DNSRec SPF Weak",
			"Observes weak SPF policy: a complete (unclipped) dns:txt record starting v=spf1 with neither -all nor ~all among its whitespace-separated mechanisms. Clipped values are skipped for every SPF claim and never support a negative finding. Per-host informational observation — never claims spoofability.",
			[]detect.RuleInput{detect.InputAssets, detect.InputEvidence},
			spfWeakDetector, "1.0.0"),
		newDNSRecRule(ruleDMARCMissing, "DNSRec DMARC Missing",
			"Observes absent DMARC record: a host with a non-empty dns:txt set, no clipped values, and no record starting v=DMARC1. Any clipped value makes the TXT set incomplete and the host stays silent. Reports only the queried host's own observed TXT set, never a standards-compliant DMARC evaluation. Per-host informational observation — never claims the domain lacks mail protection.",
			[]detect.RuleInput{detect.InputAssets, detect.InputEvidence},
			dmarcMissingDetector, "1.0.0"),
		newDNSRecRule(ruleSRVExposure, "DNSRec SRV Exposure",
			"Observes advertised services: complete (unclipped) dns:srv evidence citing target:port for the queried host. Clipped values are skipped; a host with only clipped SRV values stays silent. Per-host informational observation — never claims reachability.",
			[]detect.RuleInput{detect.InputAssets, detect.InputEvidence},
			srvExposureDetector, "1.0.0"),
	}
	// RequiredAssetTypes gates (single-kind-gate precedent): each rule
	// declares ONE primary kind because the census gate is conjunctive —
	// listing every input domain would skip the rule whenever ANY domain is
	// absent. All five are per-host observations, so KindHost throughout.
	for i := range rules {
		rules[i].RequiredAssetTypes = []asset.Kind{asset.KindHost}
	}
	return rules, nil
}

func newDNSRecRule(id, name, description string, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
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
		Author:        "RavenRecon DNSRec Pack",
		Enabled:       true,
		Detector:      det,
	}
}
