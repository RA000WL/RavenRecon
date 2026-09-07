package jsintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

var errTestRead = errors.New("test read error")

// TestSplitWindowsDeterministic pins OD-4's free half: the tiling is
// deterministic (same bytes always tile identically) and the 8 KiB overlap
// covers the secrentel maximum (800-byte values) with margin — no resize.
func TestSplitWindowsDeterministic(t *testing.T) {
	prefix := bytes.Repeat([]byte("a"), 2<<20)
	w1 := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	w2 := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(w1) != 5 || len(w2) != 5 {
		t.Fatalf("windows = %d/%d, want 5/5 for the 2 MiB prefix (pipeline path ≤5)", len(w1), len(w2))
	}
	for i := range w1 {
		if !bytes.Equal(w1[i], w2[i]) {
			t.Fatalf("window %d differs across tilings (non-deterministic)", i)
		}
	}
	// OD-4 measurement: longest secrentel retained value is 800 bytes
	// (aws session token MaxLen 800; max Trail 120 already bounded by its
	// MaxLen), overlap 8192 gives 7392 bytes margin — document + pin.
	const secrentelMaxSpan = 800
	if fetchWindowOverlapBytes <= secrentelMaxSpan {
		t.Fatalf("overlap %d must exceed secrentel max span %d", fetchWindowOverlapBytes, secrentelMaxSpan)
	}
	if got := fetchTilingTag; got != "w512-o8-v1" {
		t.Fatalf("tiling tag = %q, want w512-o8-v1", got)
	}
	if maxWindowedChunks != 32 {
		t.Fatalf("maxWindowedChunks = %d, want 32 (margin over the 17-window 8 MiB maximum)", maxWindowedChunks)
	}
}

// TestMaxTilingWindowBound pins the store-writes-what-decode-rejects
// inconsistency: the 8 MiB maximum tiles to 17 windows, and the produced
// manifest must decode under maxWindowedChunks (the bound keeps margin at
// 32 so the widest producible tiling is accepted while tampered records
// with unbounded counts are still rejected).
func TestMaxTilingWindowBound(t *testing.T) {
	prefix := bytes.Repeat([]byte("a"), 8<<20)
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(windows) != 17 {
		t.Fatalf("windows = %d, want 17 for the 8 MiB maximum", len(windows))
	}
	manifest := buildFetchManifest(prefix, windows)
	if manifest == nil || len(manifest.Chunks) != 17 {
		t.Fatalf("manifest chunks = %v, want 17", manifest)
	}
	u := mustURL(t, "http://example.com/max.js")
	stored := storedFetch{
		Target: u.Identity().String(), URL: u, Truncated: true,
		TruncCause: truncCauseCap, TilingTag: manifest.TilingTag, PrefixLen: manifest.PrefixLen,
		Sources: []string{"s"}, FirstSeen: fixedTime, LastSeen: fixedTime,
	}
	for _, c := range manifest.Chunks {
		stored.Chunks = append(stored.Chunks, storedChunk{Index: c.Index, Start: c.Start, End: c.End, SHA256Hex: c.SHA256Hex})
	}
	if _, err := decodeStoredFetch(mustMarshal(t, stored), u); err != nil {
		t.Fatalf("8 MiB manifest must decode under maxWindowedChunks=%d: %v", maxWindowedChunks, err)
	}
}

// TestSplitWindowsRuneSnap pins OD-5: boundaries snap to rune starts via a
// deterministic pure function of bytes (no copy, aliasing preserved).
func TestSplitWindowsRuneSnap(t *testing.T) {
	// Build a prefix where a 3-byte rune (U+20AC €) straddles the first
	// window end (524288). Fill with 'a', then place € at 524287..524289.
	prefix := bytes.Repeat([]byte("a"), 600<<10)
	copy(prefix[524287:], []byte("€")) // 3 bytes: E2 82 AC
	if !utf8.Valid(prefix[:600<<10]) {
		t.Fatalf("fixture must be valid UTF-8")
	}
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(windows) < 2 {
		t.Fatalf("windows = %d, want >=2", len(windows))
	}
	// Every window except possibly the last must end on a rune boundary.
	for i, w := range windows {
		if i == len(windows)-1 {
			continue
		}
		// The window's end offset in prefix: find via length math is not
		// exact under snapping, so validate the bytes directly: the byte
		// after the window in prefix must be a rune start (or end).
		// Windows alias prefix; the end byte is prefix[s+len(w)].
		// Recover s by locating w: first window starts at 0.
		if len(w) == 0 || len(w) > maxFetchWindowBytes {
			t.Fatalf("window %d length %d out of range", i, len(w))
		}
		if !utf8.Valid(w) {
			t.Fatalf("window %d is not valid UTF-8 (boundary split a rune)", i)
		}
	}
	// Determinism: re-tiling yields identical windows.
	again := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(again) != len(windows) {
		t.Fatalf("re-tile count %d != %d", len(again), len(windows))
	}
	for i := range windows {
		if !bytes.Equal(windows[i], again[i]) {
			t.Fatalf("window %d differs on re-tile", i)
		}
	}
	// Pure function: snap depends only on bytes.
	if got := snapToRuneStart(prefix, 524288); got == 524288 {
		// 524288 is inside the € (524287..524289): E2 at 524287, 82 at
		// 524288, AC at 524289 — 524288 is a continuation, must back up.
		t.Fatalf("snap(524288) = 524288, want 524287 (continuation backup)")
	}
}

// TestChunkContentAliased pins the no-copy contract: chunk document bytes
// share the prefix backing array (mutating the prefix is visible in the
// window — the test's proof of aliasing, never done in production).
func TestChunkContentAliased(t *testing.T) {
	prefix := []byte(strings.Repeat("b", 600<<10))
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(windows) < 2 {
		t.Fatalf("windows = %d, want >=2", len(windows))
	}
	// Shared backing array: write through the prefix, read through a window.
	prefix[10] = 'Z'
	if windows[0][10] != 'Z' {
		t.Fatalf("window does not alias prefix (write not visible)")
	}
	windows[0][20] = 'Y'
	if prefix[20] != 'Y' {
		t.Fatalf("prefix does not alias window (write not visible)")
	}
}

// errBody fails mid-read after n bytes (hermetic read-error truncation).
type errBody struct {
	n    int
	fail error
}

func (e *errBody) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, e.fail
	}
	if len(p) > e.n {
		p = p[:e.n]
	}
	for i := range p {
		p[i] = 'e'
	}
	e.n -= len(p)
	if e.n == 0 {
		return len(p), e.fail
	}
	return len(p), nil
}

func (e *errBody) Close() error { return nil }

// TestFetchManifestCapVsRead pins the manifest contract: cap-truncated
// carries a well-formed manifest, read-error truncated carries none.
func TestFetchManifestCapVsRead(t *testing.T) {
	body := bytes.Repeat([]byte("c"), 100<<10)
	u := mustURL(t, "http://example.com/a.js")
	// Cap path via readTerminal with a small cap.
	cfg := testFetchConfig()
	cfg.MaxJSBytes = 64 << 10
	res := readTerminal(u, u, &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/javascript"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}, 0, cfg)
	if res.Status != FetchTruncated || res.Manifest == nil {
		t.Fatalf("cap-truncated must carry a manifest (status %s manifest %v)", res.Status, res.Manifest)
	}
	m := res.Manifest
	if m.TilingTag != fetchTilingTag || m.Cause != truncCauseCap || m.PrefixLen != 64<<10 {
		t.Fatalf("manifest = %+v, want tag %q cause cap prefix %d", m, fetchTilingTag, 64<<10)
	}
	if len(m.Chunks) != 1 {
		t.Fatalf("chunks = %d, want 1 (64 KiB prefix fits one window)", len(m.Chunks))
	}
	c := m.Chunks[0]
	if c.Index != 0 || c.Start != 0 || c.End != 64<<10 || len(c.SHA256Hex) != 64 {
		t.Fatalf("chunk = %+v, want 0/0-65536/64hex", c)
	}
	sum := sha256.Sum256(res.Windows[0])
	if c.SHA256Hex != hex.EncodeToString(sum[:]) {
		t.Fatalf("chunk hash does not match window bytes")
	}
	// Read-error path carries none.
	res2 := readTerminal(u, u, &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/javascript"}},
		Body: &errBody{n: 1024, fail: errTestRead}, ContentLength: 100 << 10,
	}, 0, cfg)
	if res2.Status != FetchTruncated {
		t.Fatalf("read-error status = %s, want incomplete", res2.Status)
	}
	if res2.Manifest != nil || len(res2.Windows) != 0 {
		t.Fatalf("read-error must carry no manifest/windows (got %+v/%d)", res2.Manifest, len(res2.Windows))
	}
}

// TestStoredFetchManifestGates pins decode: cap requires well-formed
// manifest (else delete+recompute via error), read carries none, tag
// mismatch recomputes, completed never carries one.
func TestStoredFetchManifestGates(t *testing.T) {
	u := mustURL(t, "http://example.com/a.js")
	goodCap := storedFetch{
		Target: u.Identity().String(), URL: u, Truncated: true,
		TruncCause: truncCauseCap, TilingTag: fetchTilingTag, PrefixLen: 64 << 10,
		Chunks:  []storedChunk{{Index: 0, Start: 0, End: 64 << 10, SHA256Hex: strings.Repeat("a", 64)}},
		Sources: []string{"s"}, FirstSeen: fixedTime, LastSeen: fixedTime,
	}
	if _, err := decodeStoredFetch(mustMarshal(t, goodCap), u); err != nil {
		t.Fatalf("well-formed cap manifest must decode: %v", err)
	}
	// Missing manifest for cap → error.
	badCap := goodCap
	badCap.Chunks = nil
	if _, err := decodeStoredFetch(mustMarshal(t, badCap), u); err == nil {
		t.Fatalf("cap without chunks must fail decode")
	}
	// Tag mismatch → error.
	tagBad := goodCap
	tagBad.TilingTag = "w256-o4-v9"
	if _, err := decodeStoredFetch(mustMarshal(t, tagBad), u); err == nil {
		t.Fatalf("tag mismatch must fail decode")
	}
	// Read with manifest → error; read without → ok.
	readGood := storedFetch{
		Target: u.Identity().String(), URL: u, Truncated: true,
		TruncCause: truncCauseRead, Sources: []string{"s"}, FirstSeen: fixedTime, LastSeen: fixedTime,
	}
	if _, err := decodeStoredFetch(mustMarshal(t, readGood), u); err != nil {
		t.Fatalf("read-error without manifest must decode: %v", err)
	}
	readBad := readGood
	readBad.TilingTag = fetchTilingTag
	if _, err := decodeStoredFetch(mustMarshal(t, readBad), u); err == nil {
		t.Fatalf("read-error with manifest must fail decode")
	}
	// Completed with manifest → error.
	compBad := storedFetch{
		Target: u.Identity().String(), URL: u, Content: []byte("x"), Size: 1,
		Hash:      func() string { s := sha256.Sum256([]byte("x")); return hex.EncodeToString(s[:]) }(),
		TilingTag: fetchTilingTag, Sources: []string{"s"}, FirstSeen: fixedTime, LastSeen: fixedTime,
	}
	if _, err := decodeStoredFetch(mustMarshal(t, compBad), u); err == nil {
		t.Fatalf("completed with manifest must fail decode")
	}
	// Legacy truncated without cause → error (delete+recompute).
	legacy := storedFetch{
		Target: u.Identity().String(), URL: u, Truncated: true,
		Sources: []string{"s"}, FirstSeen: fixedTime, LastSeen: fixedTime,
	}
	if _, err := decodeStoredFetch(mustMarshal(t, legacy), u); err == nil {
		t.Fatalf("legacy truncated without cause must fail decode")
	}
}

// TestFetchIncompleteNeverServed pins StatusIncomplete always (never served):
// a stored truncated record is StateIncomplete, never a hit, under the same
// js.fetch key.
func TestFetchIncompleteNeverServed(t *testing.T) {
	c := openTestCache(t)
	u := mustURL(t, "http://example.com/big.js")
	cfg := testFetchConfig()
	// Store a cap-truncated observation directly.
	prefix := bytes.Repeat([]byte("d"), 64<<10)
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	manifest := buildFetchManifest(prefix, windows)
	res := FetchResult{URL: u, FinalURL: u, StatusCode: 200, Truncated: true, Status: FetchTruncated, Windows: windows, Manifest: manifest}
	if err := storeFetch(context.Background(), cfg, c, newFakeClock(fixedTime), res, []string{"s"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeFetch truncated: %v", err)
	}
	key, _ := fetchKey(u, "")
	out := c.Get(context.Background(), key)
	if out.IsHit() {
		t.Fatalf("truncated record must never be a hit (State %s)", out.State)
	}
	if out.State != cache.StateIncomplete {
		t.Fatalf("State = %s, want StateIncomplete", out.State)
	}
	if lk := lookupFetch(context.Background(), u, cfg, c, newFakeClock(fixedTime), "s"); lk.Hit {
		t.Fatalf("lookupFetch must never serve a truncated record")
	}
}

// TestFetchShrinkRecovery pins same-key shrink-recovery: a complete Put
// overwrites the manifest away (replace-whole).
func TestFetchShrinkRecovery(t *testing.T) {
	c := openTestCache(t)
	u := mustURL(t, "http://example.com/shrink.js")
	cfg := testFetchConfig()
	clk := newFakeClock(fixedTime)
	prefix := bytes.Repeat([]byte("e"), 64<<10)
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	trunc := FetchResult{URL: u, FinalURL: u, StatusCode: 200, Truncated: true, Status: FetchTruncated, Windows: windows, Manifest: buildFetchManifest(prefix, windows)}
	if err := storeFetch(context.Background(), cfg, c, clk, trunc, []string{"s"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("store truncated: %v", err)
	}
	complete := FetchResult{URL: u, FinalURL: u, StatusCode: 200, Status: FetchCompleted, Content: []byte("var x=1;")}
	if err := storeFetch(context.Background(), cfg, c, clk, complete, []string{"s"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("store complete: %v", err)
	}
	key, _ := fetchKey(u, "")
	out := c.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("complete record must be a hit (State %s)", out.State)
	}
	st, err := decodeStoredFetch(out.Record.Data, u)
	if err != nil {
		t.Fatalf("decode complete: %v", err)
	}
	if st.Truncated || st.TilingTag != "" || len(st.Chunks) != 0 || st.TruncCause != "" {
		t.Fatalf("shrink-recovery must overwrite manifest away (got %+v)", st)
	}
}

// TestRetainedChunksAccessor pins RetainedChunks: windowed entries expose
// aliased windows with manifest spans, complete entries do not overlap.
func TestRetainedChunksAccessor(t *testing.T) {
	body := windowedBody(t, 65536, map[int]string{100: "var a = \"/api/a\";\n"})
	srv := windowedServer(t, body)
	cfg := testEngineConfig(t, srv.srv)
	cfg.RetainContent = true
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: srv.url() + "/big.js"}})
	chunks := rep.RetainedChunks()
	if len(chunks) != 5 {
		t.Fatalf("chunks = %d, want 5 (2 MiB prefix, pipeline path ≤5)", len(chunks))
	}
	for i, c := range chunks {
		if c.Index != i || c.Total != 5 || c.TilingTag != fetchTilingTag || len(c.HashPrefix) != 8 {
			t.Fatalf("chunk %d = %+v, want index %d total 5 tag %q 8hex", i, c, i, fetchTilingTag)
		}
		if c.Content == nil || len(c.Content) == 0 || len(c.Content) > maxFetchWindowBytes {
			t.Fatalf("chunk %d content length %d out of range", i, len(c.Content))
		}
		if _, _, _, _, _, ph, tag, err := asset.ParseChunkIdentity(mustChunkID(t, c)); err != nil || ph != c.HashPrefix || tag != c.TilingTag {
			t.Fatalf("chunk %d identity round-trip failed: %v", i, err)
		}
	}
	if got := rep.RetainedContent(); len(got) != 0 {
		t.Fatalf("RetainedContent must be empty for a windowed file (got %d)", len(got))
	}
}

// TestEngineWindowedWarmRecomputes pinned the Slice 1 deferral (warm runs
// re-fetch and recompute — no chunk-analyze cache). Slice 2 supersedes it:
// warm runs still re-fetch (the windowed fetch is never served) but skip
// parsing via js.analyze.chunk hits. The full warm contract (ZERO Parse
// delta + byte-identical merged analysis) is pinned by
// TestEngineWindowedWarmSkipsParse (chunk_slice2_test.go); this test keeps
// the fetch-behavior half (re-fetch warm) so the Slice 1 fetch pin stays
// green under Slice 2.
func TestEngineWindowedWarmRecomputes(t *testing.T) {
	body := windowedBody(t, 65536, map[int]string{100: "var a = \"/api/a\";\n"})
	srv := windowedServer(t, body)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	shared := openTestCache(t)
	mkcfg := func() Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Transport = &counting
		cfg.Cache = shared
		cfg.RetainContent = true
		return cfg
	}
	items := []Item{{Kind: ItemLine, Line: srv.url() + "/big.js"}}
	rep1 := runEngine(t, mkcfg(), items)
	rep2 := runEngine(t, mkcfg(), items)
	if counting.calls() != 2 {
		t.Fatalf("round trips = %d, want 2 (truncated fetch re-runs warm)", counting.calls())
	}
	m1, m2 := rep1.Metrics(), rep2.Metrics()
	if m1.Parses == 0 {
		t.Fatalf("cold parses = 0, want >0 (baseline: one per window)")
	}
	if m2.Parses != 0 {
		t.Fatalf("warm parses = %d, want 0 (Slice 2: chunk hits skip parsing — see TestEngineWindowedWarmSkipsParse)", m2.Parses)
	}
	if m2.Fetches != 1 || m2.Reads < 1 {
		t.Fatalf("warm metrics = %+v, want 1 fetch (re-fetch) and ≥1 read", m2)
	}
}

func mustMarshal(t *testing.T, v storedFetch) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func mustChunkID(t *testing.T, c RetainedChunk) asset.Identity {
	t.Helper()
	id, err := asset.ChunkJavaScriptIdentity(c.URL, c.Index, c.Total, c.Start, c.End, c.HashPrefix, c.TilingTag)
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	return id
}
