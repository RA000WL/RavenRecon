package pipeline

import "github.com/RA000WL/RavenRecon/internal/asset"

// MaxDocumentBytes is the fixed per-document content bound (2 MiB,
// mirroring secrentel's ingest cap). Content over the bound is dropped
// whole and the document marked Truncated — never a partial prefix
// (mirrors jsintel's honest truncation).
const MaxDocumentBytes = 2 << 20

// Document is one bounded retained script body: the pipeline-internal
// document channel. Produced by the jsintel stage (T3d), consumed by
// the secrentel stage. Not an asset: content is pipeline-internal
// currency and never reaches the report Context (only the derived
// secrets/evidence do).
type Document struct {
	// Identity is the canonical identity of the source asset (a
	// JavaScript asset identity) — the dedup key.
	Identity asset.Identity

	// URL is the canonical URL the content came from (nil allowed).
	URL *asset.URL

	// Content is the retained body, bounded by MaxDocumentBytes; nil
	// when the fetch was truncated or the bound was exceeded (never a
	// partial prefix).
	Content []byte

	// Truncated reports the content could not be fully retained.
	Truncated bool
}

// mergeDocuments appends one stage's document additions to the run's
// accumulated document channel, dropping entries whose canonical identity
// already appeared (first-seen wins, stable order — identical to the corpus
// and results merges), then enforces the per-stage cap: after the merge the
// channel holds at most cap entries, first-seen order kept, tail dropped.
// Cut entries remain first-seen — the run-wide seen map is never pruned —
// so they cannot re-enter the channel, even through a later stage with a
// larger cap; a smaller later cap re-cuts (mirror mergeChannel exactly).
//
// Dedup keys are the canonical identity strings: the "kind:value" form of
// Identity.String(), exactly how the corpus and results merges derive their
// keys, namespaced by the channel name ("documents") in the shared seen map
// (same keying as mergeResults).
//
// Defensive re-bound (hostile-producer guard): any added document whose
// content exceeds MaxDocumentBytes has its content dropped WHOLE — Content
// = nil and Truncated = true — never a partial prefix. The document still
// merges: its identity and URL remain, so the cut is honest and visible to
// every consumer. The re-bound runs before dedup and never mutates the
// caller's slice (a fresh normalized copy is built only when a document
// needs it). Content is NEVER copied into the channel beyond that: the
// merge is by reference like the corpus — producers hand over ownership and
// consumers must treat Content as read-only.
//
// It returns the names of the cut channels from the documented vocabulary
// (exactly "documents" when the cap cut, nil otherwise); the runner records
// the "documents_truncated" sticky flag and report.Truncated for it
// (AGENTS §0.6 carve-out, mirroring corpus_capped and the results
// channels).
//
// The merge runs regardless of the stage's outcome — a failed stage's
// retained documents are still merged (mirroring the corpus Additions and
// results semantics; the merge consumes the stage's raw StageResult,
// exactly like the other merges). The returned slice never aliases add;
// when add is empty the destination slice is returned without copying (the
// cap may still re-slice it).
func mergeDocuments(dst []Document, add []Document, seen map[string]struct{}, cap int) ([]Document, []string) {
	// Defensive re-bound first: content over the fixed bound is dropped
	// whole (never a partial prefix), the document marked Truncated, and
	// merged anyway — identity and URL remain. The caller's slice is never
	// mutated; a fresh copy is built only when a document needs the cut.
	rebound := false
	for _, d := range add {
		if len(d.Content) > MaxDocumentBytes {
			rebound = true
			break
		}
	}
	if rebound {
		norm := make([]Document, len(add))
		for i, d := range add {
			norm[i] = d
			if len(d.Content) > MaxDocumentBytes {
				norm[i].Content = nil
				norm[i].Truncated = true
			}
		}
		add = norm
	}
	out, cut := mergeChannel(dst, add, seen, "documents", cap, func(d Document) string {
		return d.Identity.String()
	})
	if cut {
		return out, []string{"documents"}
	}
	return out, nil
}
