package adapt

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// TestJSChunkDocumentsOrdering pins jsDocuments: grouped-by-file in index
// order plus sentinel, deterministic (so the runner's MaxOutput tail-cut is
// deterministic). No per-file chunk cut below the produced windows.
func TestJSChunkDocumentsOrdering(t *testing.T) {
	rep := chunkReportFixture(t)
	docs := jsDocuments(rep)
	// Fixture: a.js windowed (2 chunks) + b.js complete (1 doc) + c.js
	// windowed (1 chunk). Sorted file order: a.js, b.js, c.js.
	// Expected: a0, a1, a-sentinel, b-doc, c0, c-sentinel = 6 docs.
	if len(docs) != 6 {
		t.Fatalf("documents = %d, want 6 (grouped-by-file ordering)", len(docs))
	}
	for i := 0; i < 2; i++ {
		if _, ci, total, _, _, _, _, err := asset.ParseChunkIdentity(docs[i].Identity); err != nil || ci != i || total != 2 {
			t.Fatalf("doc %d identity %q: index/total err %v (want %d/2)", i, docs[i].Identity, err, i)
		}
		if docs[i].Truncated || docs[i].Content == nil {
			t.Fatalf("doc %d must be a chunk (false/non-nil)", i)
		}
	}
	if s := docs[2]; !s.Truncated || s.Content != nil || s.Identity.String() != "javascript:http://www.example.com/a.js" {
		t.Fatalf("doc 2 sentinel = %+v, want file a.js nil/true", s)
	}
	if d := docs[3]; d.Truncated || string(d.Content) != "tiny" || d.Identity.String() != "javascript:http://www.example.com/b.js" {
		t.Fatalf("doc 3 complete = %+v, want b.js tiny/false", d)
	}
	if _, ci, total, _, _, _, _, err := asset.ParseChunkIdentity(docs[4].Identity); err != nil || ci != 0 || total != 1 {
		t.Fatalf("doc 4 chunk c0: %v (want 0/1)", err)
	}
	if s := docs[5]; !s.Truncated || s.Identity.String() != "javascript:http://www.example.com/c.js" {
		t.Fatalf("doc 5 sentinel = %+v, want file c.js", s)
	}
	// Deterministic tail-cut head: the first 4 are the deterministic head
	// the runner keeps under MaxOutput 4 (tail dropped).
	wantHead := []string{
		docs[0].Identity.String(), docs[1].Identity.String(),
		docs[2].Identity.String(), docs[3].Identity.String(),
	}
	head := docs[:4]
	for i, d := range head {
		if d.Identity.String() != wantHead[i] {
			t.Fatalf("head %d = %q, want %q", i, d.Identity, wantHead[i])
		}
	}
}

// TestJSChunkMergeNoCollisions pins that chunk + sentinel identities never
// collide (distinct dedup keys, all merge).
func TestJSChunkMergeNoCollisions(t *testing.T) {
	rep := chunkReportFixture(t)
	docs := jsDocuments(rep)
	byID := make(map[string]int)
	for i, d := range docs {
		k := d.Identity.String()
		if _, dup := byID[k]; dup {
			t.Fatalf("collision on %q", k)
		}
		byID[k] = i
	}
	if len(byID) != len(docs) {
		t.Fatalf("distinct = %d, want %d", len(byID), len(docs))
	}
}

// TestSecrentelFilterChunksPins filterDocuments passes chunks, skips the
// file sentinel (already the Truncated/nil rule — pinned for Slice 1).
func TestSecrentelFilterChunksPins(t *testing.T) {
	rep := chunkReportFixture(t)
	docs := jsDocuments(rep)
	filtered := filterDocuments(docs)
	// 3 chunks pass (a0,a1,c0) + complete b.js passes → 4 pass, 2 sentinels skipped.
	if len(filtered) != 4 {
		t.Fatalf("filtered = %d, want 4 (3 chunks + complete b.js; sentinels skipped)", len(filtered))
	}
	for _, d := range filtered {
		if d.Truncated || d.Content == nil {
			t.Fatalf("filtered doc %+v must be non-truncated with content", d.Identity)
		}
	}
}

// TestChunkSourceAssetCitesFile pins SourceAsset=file for chunk docs: the
// secrentel mapping cites the file, so overlap-duplicate secrets dedup by
// (type,value,source=file) first-seen-wins in index order.
func TestChunkSourceAssetCitesFile(t *testing.T) {
	rep := chunkReportFixture(t)
	docs := jsDocuments(rep)
	sdocs := toSecretDocuments(filterDocuments(docs))
	// Filtered docs are 3 chunks + b.js; all chunk-derived secrentel docs
	// must cite files, never chunks.
	for _, sd := range sdocs {
		if sd.SourceAsset == nil {
			t.Fatalf("SourceAsset nil")
		}
		if _, _, _, _, _, _, _, err := asset.ParseChunkIdentity(*sd.SourceAsset); err == nil {
			t.Fatalf("SourceAsset %q is a chunk, want the FILE", sd.SourceAsset)
		}
	}
	// a.js chunks cite a.js.
	foundA := 0
	for _, sd := range sdocs {
		if sd.SourceAsset.String() == "javascript:http://www.example.com/a.js" {
			foundA++
		}
	}
	if foundA != 2 {
		t.Fatalf("a.js citations = %d, want 2 (both windows cite the file)", foundA)
	}
}

// chunkReportFixture builds a deterministic jsintel.Report with: a.js
// windowed (2 aliased windows), b.js complete ("tiny"), c.js windowed
// (1 window). Hand-built so jsDocuments ordering is pinned without network.
func chunkReportFixture(t *testing.T) jsintel.Report {
	t.Helper()
	aURL := jsMustURL(t, "http://www.example.com/a.js")
	bURL := jsMustURL(t, "http://www.example.com/b.js")
	cURL := jsMustURL(t, "http://www.example.com/c.js")
	aPrefix := []byte(strings.Repeat("a", 600<<10))
	aW0 := aPrefix[:512<<10]
	aW1 := aPrefix[512<<10:]
	cW := []byte("c-window")
	mkManifest := func(prefix []byte, windows [][]byte) *jsintel.FetchManifest {
		m := &jsintel.FetchManifest{TilingTag: "w512-o8-v1", PrefixLen: int64(len(prefix)), Cause: "cap"}
		off := 0
		// Offsets mirror production tiling for this fixture: aW0 at 0,
		// aW1 at 512 KiB (snapping is identity for 'a' filler).
		for i, w := range windows {
			var s int
			if i == 0 {
				s = 0
			} else {
				s = 512 << 10
				off = s
			}
			sum := sha256.Sum256(w)
			m.Chunks = append(m.Chunks, jsintel.ChunkInfo{
				Index: i, Start: int64(s), End: int64(s + len(w)),
				SHA256Hex: hex.EncodeToString(sum[:]),
			})
			off += len(w)
		}
		_ = off
		return m
	}
	aManifest := mkManifest(aPrefix, [][]byte{aW0, aW1})
	cManifest := mkManifest(cW, [][]byte{cW})
	// Fix c.js single-window span (0..8).
	cManifest.Chunks[0].Start = 0
	cManifest.Chunks[0].End = int64(len(cW))
	entries := []jsintel.JSEntry{
		{URL: aURL, Status: jsintel.StatusIncomplete, Chunks: [][]byte{aW0, aW1}, ChunkManifest: aManifest},
		{URL: bURL, Status: jsintel.StatusCompleted, Content: []byte("tiny")},
		{URL: cURL, Status: jsintel.StatusIncomplete, Chunks: [][]byte{cW}, ChunkManifest: cManifest},
	}
	// JS assets: windowed files carry sizeless assets (Slice 1 honesty);
	// b.js carries none here (document-only fixture — jsDocuments needs no
	// Results.JavaScript for chunk docs).
	return jsintel.Report{Entries: entries}
}
