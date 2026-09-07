package js

import (
	"context"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// domXSSDetector detects per-script DOM XSS sinks in retained script
// bodies (SDK v2.1 content channel): token-aware structural scan over the
// code mask (NEW-123) — innerHTML/outerHTML as dotted property writes with
// an assignment operator, document.write as an identifier-bounded call.
// Comment/string/template mentions, bare reads, and comparisons stay
// quiet. Scripts without a retained body are silent (fail-open).
//
// Bounded (AGENTS.md §10): inputs are pre-bounded snapshot bodies (2 MiB)
// or 512 KiB chunk windows; the scan is one linear codeMask pass plus
// bounded finder walks (ctx-checked every 128 occurrences) — no per-parse
// timeout beyond the rule's 2s Timeout.
func domXSSDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.dom.xss.disabled"] == "true" {
		return nil, nil
	}
	var cands []jsCandidate
	for _, jc := range dctx.JavaScriptContent {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		low := strings.ToLower(jc.Body)
		local, err := domXSSCodeSinkCtx(ctx, low, codeMask(low))
		if err != nil {
			return nil, err
		}
		if local < 0 {
			continue
		}
		subject, span := fileSubjectOfContent(jc.Identity)
		cands = append(cands, jsCandidate{subject: subject, offset: int64(local) + span})
	}
	out, err := emitJSCandidates(ctx, dctx, ruleDomXSS, "DOM XSS", detect.CategoryInformation, "dom_xss", cands)
	if err != nil {
		return nil, err
	}
	formatConfigKeys(dctx, ruleDomXSS)
	return out, nil
}
