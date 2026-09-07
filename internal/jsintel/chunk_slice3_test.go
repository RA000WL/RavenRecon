package jsintel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestAllChunkJavaScriptExposesSizelessChunkAssets pins the Slice 3
// snapshot contract: the engine exposes one JavaScript asset per
// retained window — sizeless (Size 0, empty hashes, like the windowed
// file asset), chunk URLs parsed from the constructor-built chunk
// identity (fragment cites the window, Identity() stays the file), and
// AllJavaScript stays file-only (no leak either direction).
func TestAllChunkJavaScriptExposesSizelessChunkAssets(t *testing.T) {
	file := mustURL(t, "http://example.com/bundle.js")
	prefix := []byte(strings.Repeat("x", 600<<10))
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(windows) != 2 {
		t.Fatalf("windows = %d, want 2 (600 KiB tiles to 2)", len(windows))
	}
	manifest := buildFetchManifest(prefix, windows)
	js, err := asset.NewJavaScript(file.String(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	rep := Report{Entries: []JSEntry{{
		URL: file, Status: StatusIncomplete, JS: &js,
		Chunks: windows, ChunkManifest: manifest,
	}}}

	chunks := rep.AllChunkJavaScript()
	if len(chunks) != 2 {
		t.Fatalf("chunk assets = %d, want 2 (one per window)", len(chunks))
	}
	for i, c := range chunks {
		// Sizeless like the file asset: a window is never the file.
		if c.Size != 0 || c.Hash != "" || c.ContentHash != "" {
			t.Fatalf("chunk %d size/hash = %d/%q/%q, want 0/empty/empty", i, c.Size, c.Hash, c.ContentHash)
		}
		// Chunk URL from the constructor: parses through ParseChunkIdentity
		// and cites this file with the manifest span.
		got, gi, total, gs, ge, ph, tag, perr := asset.ParseChunkIdentity(asset.Identity{Kind: asset.KindJavaScript, Value: c.URL.String() + "#" + c.URL.Fragment})
		if perr != nil {
			t.Fatalf("chunk %d identity does not parse: %v", i, perr)
		}
		if got.String() != file.String() {
			t.Fatalf("chunk %d file = %q, want %q", i, got, file)
		}
		want := manifest.Chunks[i]
		if gi != i || total != 2 || gs != want.Start || ge != want.End || ph != want.SHA256Hex[:8] || tag != fetchTilingTag {
			t.Fatalf("chunk %d = %d/%d/%d-%d/%s/%s, want %d/2/%d-%d/%s/%s",
				i, gi, total, gs, ge, ph, tag, i, want.Start, want.End, want.SHA256Hex[:8], fetchTilingTag)
		}
		// Identity() stays the FILE identity (fragment excluded): chunk
		// assets link to their file by Identity, to their window by
		// fragment.
		if c.Identity() != js.Identity() {
			t.Fatalf("chunk %d Identity() = %q, want the file %q", i, c.Identity(), js.Identity())
		}
		if c.URL.Fragment == "" {
			t.Fatalf("chunk %d URL carries no fragment (window uncited)", i)
		}
		if c.Prov != js.Prov {
			t.Fatalf("chunk %d Prov = %+v, want the file asset's %+v", i, c.Prov, js.Prov)
		}
	}
	// Sorted by full chunk identity string (index order here).
	if chunks[0].URL.Fragment > chunks[1].URL.Fragment {
		t.Fatalf("chunk assets not in window order: %q vs %q", chunks[0].URL.Fragment, chunks[1].URL.Fragment)
	}

	// AllJavaScript stays file-only: exactly the sizeless file asset, no
	// chunk identity leaks in.
	all := rep.AllJavaScript()
	if len(all) != 1 {
		t.Fatalf("AllJavaScript = %d, want 1 (file only)", len(all))
	}
	if _, _, _, _, _, _, _, perr := asset.ParseChunkIdentity(all[0].Identity()); perr == nil {
		t.Fatalf("chunk identity %q leaked into AllJavaScript", all[0].Identity())
	}

	// Empty reports expose nothing (nil-safe, no empty-but-non-nil).
	if got := (Report{}).AllChunkJavaScript(); len(got) != 0 {
		t.Fatalf("empty report chunk assets = %d, want 0", len(got))
	}
}

// TestAllChunkJavaScriptNumericWindowOrder pins the Slice 3 review F2
// sort key: with 11 windows the assets must order 0,1,2,...,10 —
// string order would emit 0,1,10,2,...,9 ("10/.." < "2/.."). The
// hand-built entry (no manifest — the defensive test-only path) keeps
// the fixture small and hermetic; production manifests tile the same
// identities through the same sorter.
func TestAllChunkJavaScriptNumericWindowOrder(t *testing.T) {
	file := mustURL(t, "http://example.com/many.js")
	js, err := asset.NewJavaScript(file.String(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	const total = 11
	windows := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		windows = append(windows, []byte(fmt.Sprintf("window-%02d:", i)+strings.Repeat("x", 64)))
	}
	rep := Report{Entries: []JSEntry{{
		URL: file, Status: StatusIncomplete, JS: &js, Chunks: windows,
	}}}

	chunks := rep.AllChunkJavaScript()
	if len(chunks) != total {
		t.Fatalf("chunk assets = %d, want %d (one per window)", len(chunks), total)
	}
	for pos, c := range chunks {
		cid := asset.Identity{Kind: asset.KindJavaScript, Value: c.URL.String() + "#" + c.URL.Fragment}
		_, got, _, _, _, _, _, perr := asset.ParseChunkIdentity(cid)
		if perr != nil {
			t.Fatalf("chunk %d identity does not parse: %v", pos, perr)
		}
		if got != pos {
			t.Fatalf("chunk at position %d carries window index %d, want numeric order 0..%d", pos, got, total-1)
		}
	}
}
