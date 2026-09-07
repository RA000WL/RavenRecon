package js

import (
	"context"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// protoPollutionDetector detects per-script prototype pollution
// assignments in retained script bodies (SDK v2.1 content channel):
// token-aware structural scan (NEW-123) — __proto__/
// constructor.prototype as dotted property access with a
// statement-bounded code assignment. Comment/string mentions and bare
// reads stay quiet. Scripts without a retained body are silent
// (fail-open).
//
// Bounded (AGENTS.md §10): inputs are pre-bounded snapshot bodies (2 MiB)
// or 512 KiB chunk windows; the scan is one linear codeMask pass plus
// bounded finder walks (each proto occurrence costs at most one 4 KiB
// statement-window search, ctx-checked every 128 occurrences) — no
// per-parse timeout beyond the rule's 2s Timeout.
func protoPollutionDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.prototype.pollution.disabled"] == "true" {
		return nil, nil
	}
	var cands []jsCandidate
	for _, jc := range dctx.JavaScriptContent {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		low := strings.ToLower(jc.Body)
		local, err := protoCodeSinkCtx(ctx, low, codeMask(low))
		if err != nil {
			return nil, err
		}
		if local < 0 {
			continue
		}
		subject, span := fileSubjectOfContent(jc.Identity)
		cands = append(cands, jsCandidate{subject: subject, offset: int64(local) + span})
	}
	out, err := emitJSCandidates(ctx, dctx, ruleProtoPollute, "Prototype Pollution", detect.CategoryInformation, "prototype_pollution", cands)
	if err != nil {
		return nil, err
	}
	formatConfigKeys(dctx, ruleProtoPollute)
	return out, nil
}
