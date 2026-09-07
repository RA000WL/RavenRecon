package detect

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// chunkScript builds a chunk-carrying script asset the way the jsintel
// stage does: the chunk URL parsed from the constructor-built chunk
// identity (fragment cites the window, Identity() stays the file).
func chunkScript(t testing.TB, file asset.URL, index, total int, start, end int64, hashPrefix string) (asset.JavaScript, asset.Identity) {
	t.Helper()
	cid, err := asset.ChunkJavaScriptIdentity(file, index, total, start, end, hashPrefix, "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	curl, err := asset.ParseURL(cid.Value, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL chunk: %v", err)
	}
	return asset.JavaScript{URL: curl, Prov: asset.Provenance{Source: "test"}}, cid
}

// TestNormalizeSnapshotChunkScriptsAccepts pins the Slice 3 observed-JS
// linkage: a snapshot carrying the file script, its chunk scripts, and
// bodies for all three normalizes — chunk identities present in the
// snapshot JavaScript set, chunk bodies linked, nothing collapsed.
func TestNormalizeSnapshotChunkScriptsAccepts(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/bundle.js")
	c0, cid0 := chunkScript(t, js.URL, 0, 2, 0, 100, "abcdef12")
	c1, cid1 := chunkScript(t, js.URL, 1, 2, 100, 200, "12345678")
	snap := Snapshot{
		JavaScript: []asset.JavaScript{c1, js, c0}, // shuffled: normalization orders
		JavaScriptContent: []JavaScriptContent{
			{Identity: cid1, Body: "window one"},
			{Identity: js.Identity(), Body: "file body"},
			{Identity: cid0, Body: "window zero"},
		},
	}
	c, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	// All three bodies linked.
	if len(c.context.JavaScriptContent) != 3 {
		t.Fatalf("contents = %d, want 3 (file + 2 chunks)", len(c.context.JavaScriptContent))
	}
	// Chunk identities present in the observed set (file included).
	for _, want := range []asset.Identity{js.Identity(), cid0, cid1} {
		if _, ok := c.observed[want]; !ok {
			t.Fatalf("observed set missing %s", want)
		}
	}
	// No collapse: the file plus both windows survive as distinct
	// observations, files first in chunk-identity order.
	if len(c.context.JavaScript) != 3 {
		t.Fatalf("scripts = %d, want 3 (file + 2 chunks, never merged)", len(c.context.JavaScript))
	}
	if c.context.JavaScript[0].Identity() != js.Identity() || c.context.JavaScript[0].URL.Fragment != "" {
		t.Fatalf("scripts[0] = %+v, want the file first", c.context.JavaScript[0])
	}
}

// TestNormalizeSnapshotChunkFileFallback pins the production linkage:
// chunk bodies link via their file when the snapshot carries no chunk
// scripts (the pipeline's corpus merge keeps the file and drops chunk
// scripts sharing its Identity).
func TestNormalizeSnapshotChunkFileFallback(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/bundle.js")
	_, cid0 := chunkScript(t, js.URL, 0, 2, 0, 100, "abcdef12")
	snap := Snapshot{
		JavaScript:        []asset.JavaScript{js},
		JavaScriptContent: []JavaScriptContent{{Identity: cid0, Body: "window zero"}},
	}
	c, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	if len(c.context.JavaScriptContent) != 1 || c.context.JavaScriptContent[0].Identity != cid0 {
		t.Fatalf("contents = %+v, want the chunk body linked via its file", c.context.JavaScriptContent)
	}
}

// TestNormalizeSnapshotChunkRejections pins the loud boundaries: a
// non-chunk fragment on a script is a caller bug (rejected, never
// stripped), and a chunk body whose file was never observed is
// rejected like any unattributed content.
func TestNormalizeSnapshotChunkRejections(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/bundle.js")
	badURL, err := asset.ParseURL("https://www.example.com/bundle.js#not-a-chunk", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if _, err := normalizeSnapshot(Snapshot{
		JavaScript: []asset.JavaScript{{URL: badURL}},
	}); err == nil {
		t.Fatal("normalizeSnapshot accepted a non-chunk fragment (want rejection)")
	}
	other := mustContentJS(t, "https://www.example.com/other.js")
	_, cidOther := chunkScript(t, other.URL, 0, 1, 0, 50, "abcdef12")
	if _, err := normalizeSnapshot(Snapshot{
		JavaScript:        []asset.JavaScript{js},
		JavaScriptContent: []JavaScriptContent{{Identity: cidOther, Body: "x"}},
	}); err == nil {
		t.Fatal("normalizeSnapshot accepted a chunk body whose file was never observed (want rejection)")
	}
}

// TestMergeSortedScriptsNumericWindowOrder pins the Slice 3 review F2
// sort key: with 11 windows the chunks must order 0,1,2,...,10 —
// string order would emit 0,1,10,2,...,9 ("10/.." < "2/.."). The file
// still sorts first; the input is reversed to prove the order comes
// from the sorter, not the caller.
func TestMergeSortedScriptsNumericWindowOrder(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/many.js")
	const total = 11
	var list []asset.JavaScript
	for i := 0; i < total; i++ {
		c, _ := chunkScript(t, js.URL, i, total, int64(i*100), int64(i*100+100), "abcdef12")
		list = append(list, c)
	}
	list = append(list, js)
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	got := mergeSortedScripts(list)
	if len(got) != total+1 {
		t.Fatalf("scripts = %d, want %d (file + %d chunks, never merged)", len(got), total+1, total)
	}
	if got[0].Identity() != js.Identity() || got[0].URL.Fragment != "" {
		t.Fatalf("scripts[0] = %+v, want the file first", got[0])
	}
	for pos, j := range got[1:] {
		cid, ok := ChunkIdentityOfScript(j)
		if !ok {
			t.Fatalf("chunk at position %d carries no chunk identity", pos)
		}
		_, index, _, _, _, _, _, err := asset.ParseChunkIdentity(cid)
		if err != nil {
			t.Fatalf("chunk at position %d does not parse: %v", pos, err)
		}
		if index != pos {
			t.Fatalf("chunk at position %d carries window index %d, want numeric order 0..%d", pos, index, total-1)
		}
	}
}
