package cloud

import (
	"context"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// maxFindingsPerRule is the deterministic per-rule emission cap shared by
// the cloud rules: beyond the cap, further subjects are dropped in sorted
// order (the engine would fail the rule past its own bound otherwise).
const maxFindingsPerRule = 256

// awsKeyConfidence rates heuristic AWS credential indicators: shape-shaped
// and suppressed against documented examples, but never verified (§0.1).
const awsKeyConfidence = 0.6

// awsKeyIndicatorDetector reports AWS credential INDICATORS observed in the
// corpus: secret candidates typed aws whose value carries an access-key-ID
// shape, or evidence records whose indicator/value carries that shape
// (subject: the evidence's source asset). Informational only — the finding
// names an observation, never a valid or usable credential. Values are
// never copied into findings, metadata, logs, or errors.
func awsKeyIndicatorDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleAWSKeyIndicator+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	carrier := make(map[asset.Identity]string)
	var subjects []asset.Identity
	for _, sec := range dctx.Secrets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sec.Type != asset.SecretTypeAWS || !awsCredentialIndicator(sec.Value) {
			continue
		}
		id := sec.Identity()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		carrier[id] = "secret_candidate"
	}
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ev.Source.IsZero() {
			continue
		}
		if !awsCredentialIndicator(ev.Indicator) && !awsCredentialIndicator(ev.Value) {
			continue
		}
		id := ev.Source
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		carrier[id] = "evidence"
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= maxFindingsPerRule {
			break
		}
		f, err := cloudFinding(dctx, ruleAWSKeyIndicator, "AWS Key Indicator", awsKeyConfidence, s,
			map[string]string{"signal": "aws_credential_indicator", "observed_in": carrier[s]})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleAWSKeyIndicator)
	return out, nil
}
