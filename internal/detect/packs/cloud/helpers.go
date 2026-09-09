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

// capSubjects retains at most maxFindingsPerRule subjects under the NEW-135
// score-ordered truncation contract: score descending, then subject identity
// ascending (single-detector invocation, so the rule is fixed; nil scorer
// ⇒ pure identity order, byte-identical to the pre-NEW-135 prefix cut). It returns the kept subjects and the dropped count (0 when
// under the bound); callers surface a nonzero dropped via subjects_dropped
// + truncated metadata on every retained finding and a LevelWarn log —
// never silent.
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
	if len(subjects) > maxFindingsPerRule {
		return subjects[:maxFindingsPerRule], len(subjects) - maxFindingsPerRule
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
