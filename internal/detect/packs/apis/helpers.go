package apis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// apisFinding builds one canonical apis-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "apis". Priority is info, status open, timestamps
// come from the injected Clock for determinism.
func apisFinding(dctx *detect.Context, ruleID, ruleName string, cat detect.Category, subject asset.Identity, related []asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "apis pack signal: "+ruleID, subject, asset.Provenance{Source: "apis"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:        ruleID,
		RuleName:      ruleName,
		Category:      cat.String(),
		Subject:       subject,
		Confidence:    0.9,
		Evidence:      []asset.Evidence{ev},
		RelatedAssets: related,
		Metadata:      meta,
		Priority:      detect.PriorityInfo.String(),
		Status:        detect.StatusOpen.String(),
		Created:       dctx.Clock.Now().UTC(),
	})
}

// capSubjects retains at most 256 subjects under the NEW-135 score-ordered
// truncation contract: score descending, then subject identity ascending
// (single-detector invocation, so the rule is fixed; nil scorer ⇒ pure
// identity order, byte-identical to the pre-NEW-135 prefix cut). It returns the
// kept subjects and the dropped count (0 when under the bound); callers
// surface a nonzero dropped via subjects_dropped + truncated metadata on
// every retained finding and a LevelWarn log — never silent.
func capSubjects(subjects []asset.Identity, scoreFor func(asset.Identity) float64) (kept []asset.Identity, dropped int) {
	sort.Slice(subjects, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if scoreFor != nil {
			si, sj = scoreFor(subjects[i]), scoreFor(subjects[j])
		}
		if si != sj {
			return si > sj
		}
		return subjects[i].String() < subjects[j].String()
	})
	if len(subjects) > 256 {
		return subjects[:256], len(subjects) - 256
	}
	return subjects, 0
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
