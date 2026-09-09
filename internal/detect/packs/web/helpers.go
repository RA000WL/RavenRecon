package web

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// webFinding builds one canonical web-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "web". Priority is info, status open, timestamps
// come from the injected Clock for determinism.
func webFinding(dctx *detect.Context, ruleID, ruleName string, cat detect.Category, subject asset.Identity, related []asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "web pack signal: "+ruleID, subject, asset.Provenance{Source: "web"})
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

// hasCSP reports whether the evidence/technology corpus contains a CSP
// indicator: technology name containing "csp" or "content-security-policy",
// or evidence indicator/value containing that header name.
func hasCSP(dctx *detect.Context) bool {
	for _, t := range dctx.Technologies {
		n := strings.ToLower(t.Name)
		if strings.Contains(n, "csp") || strings.Contains(n, "content-security-policy") {
			return true
		}
	}
	for _, ev := range dctx.Evidence {
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "content-security-policy") || strings.Contains(ind, "csp") {
			return true
		}
		if strings.Contains(val, "content-security-policy") {
			return true
		}
	}
	return false
}

// hostHasCSP reports whether a specific host has CSP evidence.
func hostHasCSP(dctx *detect.Context, host asset.Identity) bool {
	for _, t := range dctx.Technologies {
		n := strings.ToLower(t.Name)
		if strings.Contains(n, "csp") || strings.Contains(n, "content-security-policy") {
			return true
		}
	}
	for _, ev := range dctx.Evidence {
		if ev.Source != host {
			continue
		}
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "content-security-policy") || strings.Contains(ind, "csp") {
			return true
		}
		if strings.Contains(val, "content-security-policy") {
			return true
		}
	}
	return false
}

// hasHSTS reports whether the corpus contains an HSTS indicator.
func hasHSTS(dctx *detect.Context) bool {
	for _, ev := range dctx.Evidence {
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "strict-transport-security") || strings.Contains(val, "strict-transport-security") {
			return true
		}
	}
	for _, t := range dctx.Technologies {
		if strings.Contains(strings.ToLower(t.Name), "hsts") {
			return true
		}
	}
	return false
}

// hostHasHSTS reports whether a specific host has HSTS evidence.
func hostHasHSTS(dctx *detect.Context, host asset.Identity) bool {
	for _, t := range dctx.Technologies {
		if strings.Contains(strings.ToLower(t.Name), "hsts") {
			return true
		}
	}
	for _, ev := range dctx.Evidence {
		if ev.Source != host {
			continue
		}
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "strict-transport-security") || strings.Contains(val, "strict-transport-security") {
			return true
		}
	}
	return false
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling demo.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	// Keep message bounded and deterministic.
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}
