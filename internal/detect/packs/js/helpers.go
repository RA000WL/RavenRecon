package js

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// jsFinding builds one canonical js-pack finding. Subject must be
// observed (always the FILE identity — see fileSubjectOfContent);
// evidence is a MethodDetection record on the subject with provenance
// Source "js" whose value cites the file-relative sink offset, so two
// windows observing the same sink at the same file offset carry
// identical evidence. Priority is info (heuristic body-scan over retained
// bodies — never a URL substring — informational per rules.go), status
// open, timestamps come from the injected
// Clock for determinism. Confidence 0.5 reflects heuristic nature.
func jsFinding(dctx *detect.Context, ruleID, ruleName string, cat detect.Category, subject asset.Identity, related []asset.Identity, meta map[string]string, fileOffset int64) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "js pack signal: "+ruleID+" @"+fmt.Sprint(fileOffset), subject, asset.Provenance{Source: "js"})
	if err != nil {
		return asset.Finding{}, err
	}
	if meta == nil {
		meta = map[string]string{}
	}
	// The file-relative sink offset, queryable without parsing the
	// evidence value. Chunk-agnostic by construction (chunk-local facts
	// never enter): overlap-identical signals share metadata exactly,
	// so the engine's MergeFindings collapses them to one finding.
	// When same-file findings at different offsets merge, the evidence
	// union keeps every offset; this key keeps the last-merged one.
	meta["offset"] = fmt.Sprint(fileOffset)
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

// jsCandidate is one fired retained body reduced to its finding subject
// (always the FILE identity) and file-relative sink offset.
type jsCandidate struct {
	subject asset.Identity
	offset  int64
}

// fileSubjectOfContent normalizes one retained-body identity to its
// finding subject and span start (NEW-129 Slice 3): chunk identities
// parse through asset.ParseChunkIdentity — never ad-hoc string
// splitting — and contribute their window's span start; file identities
// are already files and contribute span 0. The subject is therefore
// always the FILE identity: two windows observing the same sink share
// finding identity and the engine's MergeFindings collapses them.
func fileSubjectOfContent(id asset.Identity) (asset.Identity, int64) {
	if file, _, _, start, _, _, _, err := asset.ParseChunkIdentity(id); err == nil {
		return asset.Identity{Kind: asset.KindJavaScript, Value: file.String()}, start
	}
	return id, 0
}

// capCandidates retains at most 256 candidates under the NEW-135
// score-ordered truncation contract: score descending, then subject
// identity ascending (single-detector invocation, so the rule is fixed).
// JS findings carry uniform confidence (0.5) under one detector, so the
// effective order is the tie-break tail — (subject identity, file offset) ascending —
// byte-identical to the pre-NEW-135 prefix cut. Identical pairs
// deduplicate first (overlap-identical windows collapse here; the
// engine's MergeFindings is the backstop), so dropped counts only
// distinct candidates. It returns the kept candidates and the dropped
// count (0 when under the bound); callers surface a nonzero dropped via
// subjects_dropped + truncated metadata on every retained finding and a
// LevelWarn log — never silent. Emission order is deterministic for any
// input multiset.
func capCandidates(cands []jsCandidate) (kept []jsCandidate, dropped int) {
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].subject.String() != cands[j].subject.String() {
			return cands[i].subject.String() < cands[j].subject.String()
		}
		return cands[i].offset < cands[j].offset
	})
	deduped := cands[:0]
	for _, c := range cands {
		if n := len(deduped); n > 0 && deduped[n-1] == c {
			continue
		}
		deduped = append(deduped, c)
	}
	cands = deduped
	if len(cands) > 256 {
		return cands[:256], len(cands) - 256
	}
	return cands, 0
}

// emitJSCandidates reduces fired pairs to findings: sorted by (subject,
// offset), identical pairs deduplicated (overlap-identical windows
// collapse here; the engine's MergeFindings is the backstop), capped at
// 256 pairs with the pack's overflow pattern preserved
// (subjects_dropped + truncated metadata on every finding, warn log).
// Emission order is deterministic for any input multiset.
func emitJSCandidates(ctx context.Context, dctx *detect.Context, ruleID, ruleName string, cat detect.Category, signal string, cands []jsCandidate) ([]asset.Finding, error) {
	cands, dropped := capCandidates(cands)
	var out []asset.Finding
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": signal}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := jsFinding(dctx, ruleID, ruleName, cat, c.subject, nil, meta, c.offset)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleID, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	return out, nil
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
