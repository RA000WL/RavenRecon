package js

import (
	"context"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// postMessageDetector detects per-script postMessage handlers without
// origin checks in retained script bodies (SDK v2.1 content channel):
// token-aware structural scan (NEW-123) — a code addEventListener call
// whose first argument is the static string "message" (handler scope: a
// "message" literal elsewhere does not count) with no `.origin` read in
// code (a comment-only origin mention does not suppress).
// Scripts without a retained body are silent (fail-open).
//
// Bounded (AGENTS.md §10): inputs are pre-bounded snapshot bodies (2 MiB)
// or 512 KiB chunk windows; the scan is one linear codeMask pass plus
// bounded finder walks (each addEventListener occurrence costs at most one
// 4 KiB literal scan plus O(gap) next-code skips — linear overall,
// ctx-checked every 128 occurrences) — no per-parse timeout beyond the
// rule's 2s Timeout.
//
// Origin scope is file-global by design (known-FN limitation): any code
// `.origin` in the body suppresses the rule, even for a different handler
// (see hasCodeOrigin; pinned by
// TestJSFPPostMessageFileGlobalOriginLimitation).
func postMessageDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.postmessage.no-origin-check.disabled"] == "true" {
		return nil, nil
	}
	var cands []jsCandidate
	for _, jc := range dctx.JavaScriptContent {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		low := strings.ToLower(jc.Body)
		mask := codeMask(low)
		// The locator: the predicate guarantees a static-"message"
		// addEventListener call in code, so the handler offset always lands.
		local, err := postMessageCodeHandlerCtx(ctx, low, mask)
		if err != nil {
			return nil, err
		}
		if local < 0 {
			continue
		}
		hasOrigin, err := hasCodeOriginCtx(ctx, low, mask)
		if err != nil {
			return nil, err
		}
		if hasOrigin {
			continue
		}
		subject, span := fileSubjectOfContent(jc.Identity)
		cands = append(cands, jsCandidate{subject: subject, offset: int64(local) + span})
	}
	out, err := emitJSCandidates(ctx, dctx, rulePostMessage, "PostMessage No Origin Check", detect.CategoryInformation, "postmessage_no_origin", cands)
	if err != nil {
		return nil, err
	}
	formatConfigKeys(dctx, rulePostMessage)
	return out, nil
}
