package js

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// jsFinding builds one canonical js-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "js". Priority is info (heuristic URL-substring
// downgraded per NEW-97), status open, timestamps come from the injected
// Clock for determinism. Confidence 0.5 reflects heuristic nature.
func jsFinding(dctx *detect.Context, ruleID, ruleName string, cat detect.Category, subject asset.Identity, related []asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "js pack signal: "+ruleID, subject, asset.Provenance{Source: "js"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:        ruleID,
		RuleName:      ruleName,
		Category:      cat.String(),
		Subject:       subject,
		Confidence:    0.5,
		Evidence:      []asset.Evidence{ev},
		RelatedAssets: related,
		Metadata:      meta,
		Priority:      detect.PriorityInfo.String(),
		Status:        detect.StatusOpen.String(),
		Created:       dctx.Clock.Now().UTC(),
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
