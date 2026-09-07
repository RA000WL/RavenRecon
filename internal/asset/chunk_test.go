package asset

import (
	"strings"
	"testing"
)

// TestChunkIdentityRoundTrip pins OD-1: chunk identities build through the
// single constructor and round-trip through the single parser, with the file
// part re-parsing canonically (the normalizeSnapshot re-parse check).
func TestChunkIdentityRoundTrip(t *testing.T) {
	file, err := ParseURL("https://example.com/app.js?v=2", Provenance{})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	id, err := ChunkJavaScriptIdentity(file, 2, 5, 1032192, 1556480, "1a2b3c4d", "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	wantPrefix := "javascript:https://example.com/app.js?v=2#rr-chunk=2/5/span=1032192-1556480/ph=1a2b3c4d/t=w512-o8-v1"
	if id.String() != wantPrefix {
		t.Fatalf("chunk identity = %q, want %q", id.String(), wantPrefix)
	}
	if id.Kind != KindJavaScript {
		t.Fatalf("kind = %q, want javascript", id.Kind)
	}
	gotFile, gi, total, gs, ge, ph, tag, perr := ParseChunkIdentity(id)
	if perr != nil {
		t.Fatalf("ParseChunkIdentity: %v", perr)
	}
	if gotFile.String() != file.String() || gotFile.Identity() != file.Identity() {
		t.Fatalf("file = %q, want %q (canonical round-trip)", gotFile.String(), file.String())
	}
	if gi != 2 || total != 5 || gs != 1032192 || ge != 1556480 || ph != "1a2b3c4d" || tag != "w512-o8-v1" {
		t.Fatalf("params = %d/%d/%d-%d/%s/%s, want 2/5/1032192-1556480/1a2b3c4d/w512-o8-v1", gi, total, gs, ge, ph, tag)
	}
	// Re-parse check mirroring detect normalizeSnapshot: the file part must
	// re-parse to its own identity.
	re, err := ParseURL(gotFile.String(), Provenance{})
	if err != nil || re.Identity() != gotFile.Identity() {
		t.Fatalf("file re-parse failed: %v (identity %q)", err, gotFile.Identity())
	}
}

// TestChunkFileIdentitiesNeverCarryFragments pins OD-1's file side: file JS
// identities never contain a fragment, so the first '#' in a chunk identity
// always delimits the chunk suffix.
func TestChunkFileIdentitiesNeverCarryFragments(t *testing.T) {
	j, err := NewJavaScript("https://example.com/app.js?v=1#main", Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	if strings.Contains(j.Identity().Value, "#") {
		t.Fatalf("file identity %q carries a fragment", j.Identity())
	}
	if _, _, _, _, _, _, _, err := ParseChunkIdentity(j.Identity()); err == nil {
		t.Fatalf("file identity must not parse as a chunk")
	}
	// A fragmented file URL cannot seed a chunk identity.
	frag, err := ParseURL("https://example.com/app.js#frag", Provenance{})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if _, err := ChunkJavaScriptIdentity(frag, 0, 1, 0, 100, "abcdef12", "w512-o8-v1"); err == nil {
		t.Fatalf("ChunkJavaScriptIdentity must reject a fragmented file URL")
	}
}

// TestChunkIdentityRejection pins malformed chunk strings never parse.
func TestChunkIdentityRejection(t *testing.T) {
	file, _ := ParseURL("https://example.com/a.js", Provenance{})
	for _, tc := range []struct {
		name string
		id   Identity
	}{
		{"wrong kind", Identity{Kind: KindURL, Value: "https://example.com/a.js#rr-chunk=0/1/span=0-10/ph=abcdef12/t=w512-o8-v1"}},
		{"missing marker", Identity{Kind: KindJavaScript, Value: "https://example.com/a.js"}},
		{"bad index", Identity{Kind: KindJavaScript, Value: "https://example.com/a.js#rr-chunk=x/1/span=0-10/ph=abcdef12/t=w512-o8-v1"}},
		{"index over total", Identity{Kind: KindJavaScript, Value: "https://example.com/a.js#rr-chunk=1/1/span=0-10/ph=abcdef12/t=w512-o8-v1"}},
		{"bad hash", Identity{Kind: KindJavaScript, Value: "https://example.com/a.js#rr-chunk=0/1/span=0-10/ph=ZZZZZZZZ/t=w512-o8-v1"}},
		{"bad tag", Identity{Kind: KindJavaScript, Value: "https://example.com/a.js#rr-chunk=0/1/span=0-10/ph=abcdef12/t=bogus"}},
		{"non-canonical file", Identity{Kind: KindJavaScript, Value: "HTTPS://example.com/a.js#rr-chunk=0/1/span=0-10/ph=abcdef12/t=w512-o8-v1"}},
	} {
		if _, _, _, _, _, _, _, err := ParseChunkIdentity(tc.id); err == nil {
			t.Errorf("%s: ParseChunkIdentity(%q) must fail", tc.name, tc.id)
		}
	}
	_ = file
}
