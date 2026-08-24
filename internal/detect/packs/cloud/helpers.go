package cloud

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// cloudFinding builds one canonical cloud-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "cloud". Priority is info, status open, timestamps come
// from the injected Clock for determinism. Confidence is passed per rule:
// exact provider-host shapes rate higher than heuristic indicators, and the
// pack never claims more than observation.
func cloudFinding(dctx *detect.Context, ruleID, ruleName string, confidence float64, subject asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "cloud pack signal: "+ruleID, subject, asset.Provenance{Source: "cloud"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryCloud.String(),
		Subject:    subject,
		Confidence: confidence,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    dctx.Clock.Now().UTC(),
	})
}

// sortedKeys returns the map keys in deterministic sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling demo.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}
