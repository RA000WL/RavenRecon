package takeover

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// takeoverFinding builds one canonical takeover-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "takeover". Category is information, priority info,
// confidence 0.6 (heuristic observation, not a vulnerability claim), status
// open, timestamps from injected Clock for determinism.
func takeoverFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "takeover pack signal: "+ruleID, subject, asset.Provenance{Source: "takeover"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.6,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    dctx.Clock.Now().UTC(),
	})
}

// sortedKeys returns map keys in deterministic sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}

// hostsWithIP returns the set of host identities that have a host->IP relationship.
func hostsWithIP(dctx *detect.Context) map[asset.Identity]struct{} {
	m := make(map[asset.Identity]struct{})
	for _, rel := range dctx.Relationships {
		if rel.Kind == asset.RelationshipHostToIP {
			m[rel.From] = struct{}{}
		}
	}
	return m
}

// unclaimedProviderSuffixes is the curated provider fingerprint list for
// takeover.cname.unclaimed. Lowercased, sorted for determinism. Suffix match
// uses dot-boundary: target == suffix or HasSuffix(target, "."+suffix).
var unclaimedProviderSuffixes = []string{
	"amazonaws.com",
	"azurewebsites.net",
	"blob.core.windows.net",
	"cloudapp.azure.com",
	"cloudapp.net",
	"cloudfront.net",
	"elb.amazonaws.com",
	"fastly.net",
	"github.io",
	"herokuapp.com",
	"herokudns.com",
	"shopify.com",
	"trafficmanager.net",
}

// isUnclaimedProvider reports whether host (lowercased) matches any curated
// unclaimed provider suffix.
func isUnclaimedProvider(host string) bool {
	h := strings.ToLower(host)
	for _, s := range unclaimedProviderSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// providerForHost returns the matched suffix for host, or "".
func providerForHost(host string) string {
	h := strings.ToLower(host)
	for _, s := range unclaimedProviderSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return s
		}
	}
	return ""
}

// isS3Endpoint reports whether endpoint host is an S3 bucket shape.
// Conservative: host contains ".s3." and suffix amazonaws.com, or equals
// s3.amazonaws.com, or suffix ".s3.amazonaws.com" or ".s3-website" variant.
func isS3Endpoint(ep asset.Endpoint) bool {
	host := strings.ToLower(ep.URL.HostPort)
	// Strip port if present.
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	// Remove brackets for IPv6 (not relevant but safe).
	host = strings.Trim(host, "[]")
	if host == "s3.amazonaws.com" {
		return true
	}
	if strings.HasSuffix(host, ".s3.amazonaws.com") {
		return true
	}
	if strings.Contains(host, ".s3.") && strings.HasSuffix(host, ".amazonaws.com") {
		return true
	}
	if strings.Contains(host, ".s3-website") && strings.HasSuffix(host, ".amazonaws.com") {
		return true
	}
	if strings.HasSuffix(host, ".s3-external-1.amazonaws.com") {
		return true
	}
	// Technology path also handled separately, but endpoint shape is primary.
	return false
}
