package jsintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// chunkFixture builds one synthetic chunk identity + hash for fileURL: the
// chunk bytes are synthetic (never fetched), the span covers them, and the
// hash prefix cites them — the same construction the engine uses for fresh
// windows (span from the manifest, prefix from the fresh bytes).
func chunkFixture(t *testing.T, file asset.URL, index, total int, chunkBytes []byte) (asset.Identity, string) {
	t.Helper()
	if len(chunkBytes) == 0 {
		t.Fatalf("chunk bytes must not be empty")
	}
	sum := sha256.Sum256(chunkBytes)
	full := hex.EncodeToString(sum[:])
	cid, err := asset.ChunkJavaScriptIdentity(file, index, total, 0, int64(len(chunkBytes)), full[:8], fetchTilingTag)
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	return cid, full
}

// chunkAnalyzeFixture builds a complete, valid per-chunk analysis payload
// for the FILE url (secret/evidence sources are the file JS identity —
// chunk extraction runs under the file asset, which stays sizeless).
func chunkAnalyzeFixture(t *testing.T, file asset.URL) analysisData {
	t.Helper()
	return analyzeFixture(t, file)
}

// TestChunkAnalyzeKeyDistinctness pins the Slice 2 key contract: op
// js.analyze.chunk + chunk identity + parser/tiling/session config; caps,
// timings, and concurrency excluded like file-level.
func TestChunkAnalyzeKeyDistinctness(t *testing.T) {
	file := mustURL(t, "http://example.com/app.js")
	cid, _ := chunkFixture(t, file, 0, 5, []byte("var a=1;"))

	// Canonical construction: operation + chunk identity + parser + tiling.
	canon, err := cache.NewKey(cache.KeyParts{
		Operation: ChunkAnalyzeOperation,
		Target:    cid.String(),
		Config:    map[string]string{"parser": "1:eimst", "tiling": "w512-o8-v1"},
	})
	if err != nil {
		t.Fatalf("canonical key: %v", err)
	}
	got, err := chunkAnalyzeKey(cid, "")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey: %v", err)
	}
	if got != canon {
		t.Errorf("key %s != canonical %s", got, canon)
	}
	if ChunkAnalyzeOperation != "js.analyze.chunk" {
		t.Errorf("op = %q, want js.analyze.chunk (fresh namespace)", ChunkAnalyzeOperation)
	}
	if len(got) != 64 {
		t.Errorf("key = %q, want a 64-char digest", got)
	}

	// Chunk vs file key: different op + different target → different key.
	fileKey, err := analyzeKey(file, "")
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	if got == fileKey {
		t.Error("chunk key equals file key (must differ: fresh namespace + chunk target)")
	}

	// Tiling-tag change → different key (keys differ — old key unreachable).
	otherTiling, err := cache.NewKey(cache.KeyParts{
		Operation: ChunkAnalyzeOperation,
		Target:    cid.String(),
		Config:    map[string]string{"parser": "1:eimst", "tiling": "w256-o4-v9"},
	})
	if err != nil {
		t.Fatalf("other tiling key: %v", err)
	}
	if otherTiling == got {
		t.Error("tiling-tag change produced the same key (must differ)")
	}

	// Session change → different key; anonymous keys byte-identical (NEW-125 parity).
	again, err := chunkAnalyzeKey(cid, "")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey again: %v", err)
	}
	if again != got {
		t.Error("same chunk + empty session produced different keys (anonymous must be byte-identical)")
	}
	sess, err := chunkAnalyzeKey(cid, "digest123")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey session: %v", err)
	}
	if sess == got {
		t.Error("session change produced the same key (must differ)")
	}

	// Cap change excluded by construction: the key builder takes only the
	// chunk identity + session (no Config caps, no timings) — a stored
	// record stays valid under any cap configuration (pinned by the
	// warm-vs-cold cap test in TestChunkUnionThenCapOnce and by the
	// round-trip under lowered caps below).
	if strings.Contains(string(got), "MaxEndpoints") || strings.Contains(string(got), "MaxSecrets") {
		t.Error("key must not embed configurable caps")
	}

	// Distinct chunks → distinct keys (different span/ph → different target).
	cid2, _ := chunkFixture(t, file, 1, 5, []byte("var b=2;"))
	k2, err := chunkAnalyzeKey(cid2, "")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey 2: %v", err)
	}
	if k2 == got {
		t.Error("different chunks produced the same key")
	}
}

// TestChunkAnalyzeRoundTrip pins per-chunk store then lookup hit with
// identical payload.
func TestChunkAnalyzeRoundTrip(t *testing.T) {
	file := mustURL(t, "https://example.com/app.js")
	cid, hash := chunkFixture(t, file, 2, 5, []byte("var roundtrip = \"/api/rt\";\n"))
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := chunkAnalyzeFixture(t, file)

	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cid, file, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeChunkAnalyze: %v", err)
	}
	lu := lookupChunkAnalyze(context.Background(), cid, file, hash, Config{}, c, clock)
	if !lu.Hit {
		t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
	}
	if !reflect.DeepEqual(lu.Result, data) {
		t.Errorf("restored payload differs:\n%+v\nvs\n%+v", lu.Result, data)
	}
	if !lu.FirstSeen.Equal(fixedTime) || !lu.LastSeen.Equal(fixedTime) {
		t.Errorf("window = %v/%v, want %v", lu.FirstSeen, lu.LastSeen, fixedTime)
	}
}

// putChunkRecord writes a completed chunk record carrying st under key.
func putChunkRecord(t *testing.T, c cache.Cache, key cache.Key, st storedAnalyze) {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("encode tampered chunk record: %v", err)
	}
	if err := c.Put(context.Background(), key, cache.Record{
		Operation: ChunkAnalyzeOperation,
		Target:    st.Target,
		Status:    cache.StatusCompleted,
		Data:      raw,
	}); err != nil {
		t.Fatalf("put tampered chunk record: %v", err)
	}
}

// TestChunkAnalyzeTamperTable pins decode gates: every mutation is refused,
// deleted (self-healing), and never served.
func TestChunkAnalyzeTamperTable(t *testing.T) {
	file := mustURL(t, "https://example.com/app.js")
	cid, hash := chunkFixture(t, file, 0, 3, []byte("var tamper = 1;\n"))
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := chunkAnalyzeFixture(t, file)

	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cid, file, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("base storeChunkAnalyze: %v", err)
	}
	key, err := chunkAnalyzeKey(cid, "")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey: %v", err)
	}
	baseOut := c.Get(context.Background(), key)
	if !baseOut.IsHit() {
		t.Fatalf("base record: state %v, want hit", baseOut.State)
	}
	var base storedAnalyze
	if err := json.Unmarshal(baseOut.Record.Data, &base); err != nil {
		t.Fatalf("decode base: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*storedAnalyze)
	}{
		{"wrong target", func(s *storedAnalyze) {
			s.Target = "javascript:https://example.com/other.js#rr-chunk=0/1/span=0-10/ph=abcdef12/t=w512-o8-v1"
		}},
		{"wrong parser version", func(s *storedAnalyze) { s.ParserVersion++ }},
		{"wrong mask", func(s *storedAnalyze) { s.Mask = "eim" }},
		{"empty analyzed hash", func(s *storedAnalyze) { s.AnalyzedHash = "" }},
		{"malformed analyzed hash", func(s *storedAnalyze) { s.AnalyzedHash = "zz" + strings.Repeat("0", 62) }},
		{"non-canonical import url", func(s *storedAnalyze) { s.Imports[0].URL = asset.URL{} }},
		{"unknown import kind", func(s *storedAnalyze) { s.Imports[0].Kind = "bogus" }},
		{"foreign secret source", func(s *storedAnalyze) {
			s.Secrets[0].Source = asset.Identity{Kind: asset.KindHost, Value: "other.example"}
		}},
		{"chunk secret source (must be file, never chunk)", func(s *storedAnalyze) {
			s.Secrets[0].Source = cid
		}},
		{"non-js evidence method", func(s *storedAnalyze) { s.Evidence[0].Method = asset.MethodHTML }},
		{"duplicate endpoints", func(s *storedAnalyze) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) }},
		{"inverted timestamps", func(s *storedAnalyze) { s.LastSeen = s.FirstSeen.Add(-time.Hour) }},
		{"zero timestamps", func(s *storedAnalyze) { s.LastSeen = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base
			tc.mutate(&mut)
			putChunkRecord(t, c, key, mut)
			lu := lookupChunkAnalyze(context.Background(), cid, file, hash, Config{}, c, clock)
			if lu.Hit {
				t.Fatal("tampered chunk record served as a hit")
			}
			if lu.Err == nil {
				t.Fatal("lookup err = nil, want the rejection diagnostic")
			}
			if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
				t.Fatalf("state after rejection = %v, want miss (deleted)", out.State)
			}
		})
	}

	// Recompute after the last rejection heals under the same key.
	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cid, file, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("recompute storeChunkAnalyze: %v", err)
	}
	if lu := lookupChunkAnalyze(context.Background(), cid, file, hash, Config{}, c, clock); !lu.Hit {
		t.Fatalf("recomputed chunk record not served (err %v)", lu.Err)
	}
}

// TestChunkAnalyzeHashMismatchHeals pins the chunk content binding: a record
// bound to different chunk bytes is never served — deleted under the SAME
// key (self-healing, no orphans from the mismatch path) and rebound by the
// fresh store. A well-formed hash of different content is routine lifecycle,
// not tamper (silent miss, no diagnostic).
func TestChunkAnalyzeHashMismatchHeals(t *testing.T) {
	file := mustURL(t, "https://example.com/app.js")
	chunkBytesA := []byte("var version = \"a\";\n")
	cidA, hashA := chunkFixture(t, file, 1, 4, chunkBytesA)
	// A different chunk content with the SAME span but different bytes would
	// normally change the hash prefix (hence the key). For the same-key
	// mismatch path, use a well-formed different hash (simulating a record
	// whose binding no longer matches the fresh bytes, e.g. tampered hash
	// or a 4B-prefix collision): the lookup must delete + miss silently.
	hashB := analyzeHash(0x22)
	if hashB == hashA {
		t.Fatalf("hashes must differ for the mismatch test")
	}
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := chunkAnalyzeFixture(t, file)

	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cidA, file, hashA, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeChunkAnalyze(A): %v", err)
	}
	if lu := lookupChunkAnalyze(context.Background(), cidA, file, hashA, Config{}, c, clock); !lu.Hit {
		t.Fatalf("lookup with A's bytes = hit false (err %v), want a hit", lu.Err)
	}
	lu := lookupChunkAnalyze(context.Background(), cidA, file, hashB, Config{}, c, clock)
	if lu.Hit {
		t.Fatal("stale chunk analysis served for different chunk content")
	}
	if lu.Err != nil {
		t.Fatalf("lookup err = %v, want nil (content change is a routine miss)", lu.Err)
	}
	key, err := chunkAnalyzeKey(cidA, "")
	if err != nil {
		t.Fatalf("chunkAnalyzeKey: %v", err)
	}
	if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
		t.Fatalf("state after stale rejection = %v, want miss (deleted, no orphans)", out.State)
	}
	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cidA, file, hashB, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeChunkAnalyze(B): %v", err)
	}
	if lu := lookupChunkAnalyze(context.Background(), cidA, file, hashB, Config{}, c, clock); !lu.Hit {
		t.Fatalf("lookup with B's bytes = hit false (err %v), want a hit", lu.Err)
	}
	if lu := lookupChunkAnalyze(context.Background(), cidA, file, hashA, Config{}, c, clock); lu.Hit {
		t.Fatal("rebound chunk record served for the old chunk content")
	}
}

// TestChunkAnalyzeTilingMismatchRecomputes pins tiling-tag mismatch:
// different tilings derive different keys (old key unreachable from the new
// lookup, no crash); the old record lingers as a bounded orphan until
// TTL/Clear (existing policy — only shrink-to-complete deletes eagerly).
func TestChunkAnalyzeTilingMismatchRecomputes(t *testing.T) {
	file := mustURL(t, "https://example.com/app.js")
	chunkBytes := []byte("var tiling = 1;\n")
	sum := sha256.Sum256(chunkBytes)
	full := hex.EncodeToString(sum[:])
	cid, err := asset.ChunkJavaScriptIdentity(file, 0, 2, 0, int64(len(chunkBytes)), full[:8], fetchTilingTag)
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	otherTag := "w256-o4-v9"
	cidOther, err := asset.ChunkJavaScriptIdentity(file, 0, 2, 0, int64(len(chunkBytes)), full[:8], otherTag)
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity other tag: %v", err)
	}
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := chunkAnalyzeFixture(t, file)

	if err := storeChunkAnalyze(context.Background(), Config{}, c, clock, cid, file, full, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeChunkAnalyze: %v", err)
	}
	// Lookup under the other tiling's identity: different Target → different
	// key → clean miss (no crash, no diagnostic beyond the miss).
	lu := lookupChunkAnalyze(context.Background(), cidOther, file, full, Config{}, c, clock)
	if lu.Hit {
		t.Fatal("other-tiling lookup served the current-tiling record")
	}
	// Old key still holds its record (bounded orphan — tiling changes are
	// rare, findings-only, reclaimed by TTL/Clear).
	oldKey, _ := chunkAnalyzeKey(cid, "")
	if out := c.Get(context.Background(), oldKey); !out.IsHit() {
		t.Fatalf("old tiling record state = %v, want hit (bounded orphan, not deleted by a key-mismatch lookup)", out.State)
	}
	// Current tiling still hits.
	if lu := lookupChunkAnalyze(context.Background(), cid, file, full, Config{}, c, clock); !lu.Hit {
		t.Fatalf("current-tiling lookup = hit false (err %v)", lu.Err)
	}
}

// warmFixtureBody builds a deterministic over-cap JS body exercising every
// merged family: endpoints, secrets, technologies (+evidence), imports,
// exports, and a source map reference. Markers must end with "\n".
func warmFixtureBody(t *testing.T) []byte {
	t.Helper()
	return windowedBody(t, 65536, map[int]string{
		100:   "var early = \"/api/early\";\n",
		101:   "var awskey = \"AKIAIOSFODNN7EXAMPLE\";\n",
		102:   "var reactmark = \"react-dom React.createElement\";\n",
		103:   "import \"./lib.js\";\n",
		104:   "export const warmed = 1;\n",
		105:   "var sm = 1; //# sourceMappingURL=/app.js.map\n",
		22000: "var deep = \"/api/deep\";\n",
		22001: "var awskey2 = \"AKIAIOSFODNN7EXAMPLE\";\n",
	})
}

// entryPayloadEqual reports whether two entries carry byte-identical merged
// analysis (every family the warm path must preserve).
func entryPayloadEqual(a, b JSEntry) bool {
	return reflect.DeepEqual(a.Endpoints, b.Endpoints) &&
		reflect.DeepEqual(a.URLs, b.URLs) &&
		reflect.DeepEqual(a.Secrets, b.Secrets) &&
		reflect.DeepEqual(a.Technologies, b.Technologies) &&
		reflect.DeepEqual(a.Evidence, b.Evidence) &&
		reflect.DeepEqual(a.Imports, b.Imports) &&
		reflect.DeepEqual(a.BareImports, b.BareImports) &&
		reflect.DeepEqual(a.Exports, b.Exports) &&
		reflect.DeepEqual(a.SourceMaps, b.SourceMaps) &&
		reflect.DeepEqual(a.Relationships, b.Relationships)
}

// TestEngineWindowedWarmSkipsParse pins the Slice 2 warm path: the cold run
// parses (baseline), the warm run re-fetches (truncated fetch never served)
// but shows ZERO Parse delta, with byte-identical merged analysis.
func TestEngineWindowedWarmSkipsParse(t *testing.T) {
	body := warmFixtureBody(t)
	srv := windowedServer(t, body)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	shared := openTestCache(t)
	mkcfg := func() Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Transport = &counting
		cfg.Cache = shared
		cfg.RetainContent = true
		// Single-file run: the fixture's resolved import is recorded as
		// an edge but its expansion target is cap-dropped (MaxScripts 1
		// admits only big.js — no expansion fetch/parses, so the 5-parse
		// baseline stays one file, one tiling).
		cfg.MaxScripts = 1
		return cfg
	}
	items := []Item{{Kind: ItemLine, Line: srv.url() + "/big.js"}}
	rep1 := runEngine(t, mkcfg(), items)
	m1 := rep1.Metrics()
	if m1.Parses == 0 {
		t.Fatalf("cold parses = 0, want >0 (baseline: one per window)")
	}
	if m1.Parses != 5 {
		t.Fatalf("cold parses = %d, want 5 (2 MiB prefix tiles to 5 windows)", m1.Parses)
	}
	rep2 := runEngine(t, mkcfg(), items)
	m2 := rep2.Metrics()
	if counting.calls() != 2 {
		t.Fatalf("round trips = %d, want 2 (truncated fetch re-runs warm)", counting.calls())
	}
	if m2.Fetches != 1 {
		t.Fatalf("warm fetches = %d, want 1 (re-fetch, never served)", m2.Fetches)
	}
	if m2.Parses != 0 {
		t.Fatalf("warm parses = %d, want 0 (ZERO Parse delta — chunk hits skip parsing)", m2.Parses)
	}
	if m2.Reads < 1 {
		t.Fatalf("warm reads = %d, want ≥1 (chunk lookups)", m2.Reads)
	}
	e1 := entryByURL(t, rep1, srv.url()+"/big.js")
	e2 := entryByURL(t, rep2, srv.url()+"/big.js")
	if e1.Status != StatusIncomplete || e2.Status != StatusIncomplete {
		t.Fatalf("status cold/warm = %s/%s, want incomplete/incomplete", e1.Status, e2.Status)
	}
	if e1.JS == nil || e2.JS == nil {
		t.Fatalf("JS asset missing cold/warm (%v/%v)", e1.JS, e2.JS)
	}
	if e1.JS.Size != 0 || e1.JS.ContentHash != "" || e2.JS.Size != 0 || e2.JS.ContentHash != "" {
		t.Fatalf("windowed JS must stay sizeless (cold %+v warm %+v)", e1.JS, e2.JS)
	}
	if !entryPayloadEqual(e1, e2) {
		t.Fatalf("warm merged analysis differs from cold:\ncold endpoints %v secrets %d techs %d evidence %d imports %d\nwarm endpoints %v secrets %d techs %d evidence %d imports %d",
			endpointsOf(e1), len(e1.Secrets), len(e1.Technologies), len(e1.Evidence), len(e1.Imports),
			endpointsOf(e2), len(e2.Secrets), len(e2.Technologies), len(e2.Evidence), len(e2.Imports))
	}
	// Summed run counters: Skipped (cap-drops + the single entry-boundary
	// cut) and Truncated (fetch truncation) match cold vs warm. Malformed
	// differs by design (cold counts per-window extraction skips — e.g.
	// endpoint extraction skipping the secret/tech literals — while warm
	// hits contribute no extraction counters, mirroring the file-level
	// analyze-hit path); the merged payload above is byte-identical either
	// way.
	s1, s2 := rep1.Metrics(), rep2.Metrics()
	if s1.Skipped != s2.Skipped || s1.Truncated != s2.Truncated {
		t.Fatalf("summed counters cold %+v vs warm %+v differ (want identical skipped/truncated)", s1, s2)
	}
	// The merged set actually exercises every pinned family.
	if len(e1.Endpoints) == 0 || len(e1.Secrets) == 0 || len(e1.Technologies) == 0 || len(e1.Evidence) == 0 || len(e1.Imports) == 0 {
		t.Fatalf("fixture must populate endpoints/secrets/techs/evidence/imports (got %d/%d/%d/%d/%d)",
			len(e1.Endpoints), len(e1.Secrets), len(e1.Technologies), len(e1.Evidence), len(e1.Imports))
	}
	got := map[string]bool{}
	for _, u := range endpointsOf(e1) {
		got[u] = true
	}
	for _, want := range []string{srv.url() + "/api/early", srv.url() + "/api/deep"} {
		if !got[want] {
			t.Errorf("endpoint %s missing (got %v)", want, endpointsOf(e1))
		}
	}
}

// TestChunkUnionThenCapOnce pins union-then-cap-once: per-chunk payloads
// union by identity in index order (overlap duplicates collapse to one),
// then applyAnalysis caps ONCE — never cap-per-chunk then re-cap. Warm and
// cold agree byte-identically.
func TestChunkUnionThenCapOnce(t *testing.T) {
	// Three distinct endpoints across windows plus one duplicate value in
	// two windows (same endpoint identity twice → collapses to one).
	body := windowedBody(t, 65536, map[int]string{
		100:   "var a = \"/api/keep-a\";\n",
		101:   "var b = \"/api/keep-b\";\n",
		102:   "var c = \"/api/keep-c\";\n",
		103:   "var d = \"/api/dup\";\n",
		22000: "var e = \"/api/dup\";\n",
	})
	srv := windowedServer(t, body)
	shared := openTestCache(t)
	mkcfg := func() Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Cache = shared
		cfg.RetainContent = true
		cfg.MaxEndpointsPerFile = 2
		return cfg
	}
	items := []Item{{Kind: ItemLine, Line: srv.url() + "/big.js"}}
	rep1 := runEngine(t, mkcfg(), items)
	e1 := entryByURL(t, rep1, srv.url()+"/big.js")
	if len(e1.Endpoints) != 2 {
		t.Fatalf("cold endpoints = %d (%v), want 2 (single entry-boundary cap over the union)", len(e1.Endpoints), endpointsOf(e1))
	}
	// Overlap-duplicate collapse: /api/dup appears in two windows but the
	// union holds it once — count it in the UNCAPPED union via a high-cap
	// cold run on a fresh cache (same body, no cap cut).
	fresh := openTestCache(t)
	high := testEngineConfig(t, srv.srv)
	high.Cache = fresh
	high.RetainContent = true
	high.MaxEndpointsPerFile = 64
	repHigh := runEngine(t, high, items)
	eHigh := entryByURL(t, repHigh, srv.url()+"/big.js")
	seen := map[string]int{}
	for _, u := range endpointsOf(eHigh) {
		seen[u]++
	}
	if seen[srv.url()+"/api/dup"] != 1 {
		t.Fatalf("/api/dup count = %d in %v, want exactly 1 (union by identity)", seen[srv.url()+"/api/dup"], endpointsOf(eHigh))
	}
	if len(eHigh.Endpoints) != 4 {
		t.Fatalf("uncapped endpoints = %d (%v), want 4 unique (a/b/c/dup)", len(eHigh.Endpoints), endpointsOf(eHigh))
	}
	// Warm under the same low cap: byte-identical to cold (proves no
	// double-cut — a cap-per-chunk-then-re-cap bug would keep fewer or
	// different items than the single union-then-cap).
	rep2 := runEngine(t, mkcfg(), items)
	e2 := entryByURL(t, rep2, srv.url()+"/big.js")
	if !reflect.DeepEqual(e1.Endpoints, e2.Endpoints) {
		t.Fatalf("warm endpoints %v != cold %v (must be byte-identical)", endpointsOf(e2), endpointsOf(e1))
	}
	if m := rep2.Metrics(); m.Parses != 0 {
		t.Fatalf("warm parses = %d, want 0 (chunk hits)", m.Parses)
	}
}

// TestFetchShrinkDeletesChunkOrphans pins OD-3a: a shrink-to-complete run
// (big windowed → small complete, same URL, same cache) deletes exactly the
// listed chunk keys when the complete fetch stores over the manifest.
func TestFetchShrinkDeletesChunkOrphans(t *testing.T) {
	bigBody := windowedBody(t, 65536, map[int]string{100: "var a = \"/api/a\";\n"})
	smallBody := []byte("var small = \"/api/small\";\n")
	var bigMode int32 = 1
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if bigMode == 1 {
			rest := bigBody
			for len(rest) > 0 {
				n := 32 << 10
				if n > len(rest) {
					n = len(rest)
				}
				w.Write(rest[:n])
				w.(http.Flusher).Flush()
				rest = rest[n:]
			}
			return
		}
		w.Write(smallBody)
	})
	shared := openTestCache(t)
	mkcfg := func() Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Cache = shared
		cfg.RetainContent = true
		return cfg
	}
	url := srv.url() + "/shrink.js"
	repBig := runEngine(t, mkcfg(), []Item{{Kind: ItemLine, Line: url}})
	eBig := entryByURL(t, repBig, url)
	if eBig.Status != StatusIncomplete {
		t.Fatalf("big status = %s, want incomplete", eBig.Status)
	}
	if len(eBig.Chunks) == 0 || eBig.ChunkManifest == nil {
		t.Fatalf("big run must retain windows + manifest")
	}
	// List the chunk keys the big run stored (via retained manifest).
	fileURL := mustURL(t, url)
	manifest := eBig.ChunkManifest
	var oldKeys []cache.Key
	for _, ch := range manifest.Chunks {
		cid, err := asset.ChunkJavaScriptIdentity(fileURL, ch.Index, len(manifest.Chunks), ch.Start, ch.End, ch.SHA256Hex[:8], manifest.TilingTag)
		if err != nil {
			t.Fatalf("ChunkJavaScriptIdentity: %v", err)
		}
		k, err := chunkAnalyzeKey(cid, "")
		if err != nil {
			t.Fatalf("chunkAnalyzeKey: %v", err)
		}
		oldKeys = append(oldKeys, k)
		if out := shared.Get(context.Background(), k); !out.IsHit() {
			t.Fatalf("chunk key %d not stored after big run (state %v)", ch.Index, out.State)
		}
	}
	// Shrink: same URL now serves a small complete body.
	bigMode = 0
	repSmall := runEngine(t, mkcfg(), []Item{{Kind: ItemLine, Line: url}})
	eSmall := entryByURL(t, repSmall, url)
	if eSmall.Status != StatusCompleted {
		t.Fatalf("small status = %s, want completed", eSmall.Status)
	}
	// The complete Put overwrote the manifest away (existing
	// shrink-recovery) AND deleted exactly the listed chunk keys (OD-3a).
	fkey, _ := fetchKey(fileURL, "")
	if out := shared.Get(context.Background(), fkey); !out.IsHit() {
		t.Fatalf("complete fetch record state = %v, want hit", out.State)
	} else if st, err := decodeStoredFetch(out.Record.Data, fileURL); err != nil {
		t.Fatalf("decode complete fetch: %v", err)
	} else if st.Truncated || st.TilingTag != "" || len(st.Chunks) != 0 {
		t.Fatalf("shrink-recovery must overwrite manifest away (got %+v)", st)
	}
	for i, k := range oldKeys {
		if out := shared.Get(context.Background(), k); out.State != cache.StateMiss {
			t.Fatalf("chunk key %d state = %v, want miss (OD-3a must delete exactly the listed keys)", i, out.State)
		}
	}
	// No stale serve: the small analysis is fresh (its endpoint, not big's).
	foundSmall, foundBig := false, false
	for _, u := range endpointsOf(eSmall) {
		if u == srv.url()+"/api/small" {
			foundSmall = true
		}
		if u == srv.url()+"/api/a" {
			foundBig = true
		}
	}
	if !foundSmall || foundBig {
		t.Fatalf("small endpoints = %v, want only /api/small (no stale chunk serve)", endpointsOf(eSmall))
	}
}

// TestFetchRegrowthNoStale pins regrowth with the existing TTL policy: a
// small complete run followed (after TTL expiry) by a big windowed run
// re-fetches and never serves the small file-level analysis as chunk
// analysis (fresh namespace — chunk assets stay withheld from
// Results.JavaScript per Slice 3 deferral), and vice versa.
func TestFetchRegrowthNoStale(t *testing.T) {
	smallBody := []byte("var small = \"/api/small\";\n")
	bigBody := windowedBody(t, 65536, map[int]string{
		100:   "var a = \"/api/a\";\n",
		22000: "var b = \"/api/deep-regrow\";\n",
	})
	var bigMode int32
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if bigMode == 1 {
			rest := bigBody
			for len(rest) > 0 {
				n := 32 << 10
				if n > len(rest) {
					n = len(rest)
				}
				w.Write(rest[:n])
				w.(http.Flusher).Flush()
				rest = rest[n:]
			}
			return
		}
		w.Write(smallBody)
	})
	clk := newFakeClock(fixedTime)
	c, err := cache.Open(t.TempDir(), cache.WithTTL(10*time.Second), cache.WithClock(func() time.Time { return clk.Now() }))
	if err != nil {
		t.Fatalf("cache open: %v", err)
	}
	mkcfg := func() Config {
		cfg := testEngineConfig(t, srv.srv)
		cfg.Cache = c
		cfg.Clock = clk
		cfg.RetainContent = true
		return cfg
	}
	url := srv.url() + "/regrow.js"
	repSmall := runEngine(t, mkcfg(), []Item{{Kind: ItemLine, Line: url}})
	eSmall := entryByURL(t, repSmall, url)
	if eSmall.Status != StatusCompleted {
		t.Fatalf("small status = %s, want completed", eSmall.Status)
	}
	// Expire the small records via the existing TTL policy (no new
	// revalidation invented — the cache's own expiry).
	clk.advance(11 * time.Second)
	bigMode = 1
	repBig := runEngine(t, mkcfg(), []Item{{Kind: ItemLine, Line: url}})
	eBig := entryByURL(t, repBig, url)
	if eBig.Status != StatusIncomplete {
		t.Fatalf("big status = %s, want incomplete (re-fetched windowed after TTL expiry)", eBig.Status)
	}
	// No stale serve either direction: big shows big literals, never small's.
	for _, u := range endpointsOf(eBig) {
		if u == srv.url()+"/api/small" {
			t.Fatalf("big endpoints %v serve small content (stale)", endpointsOf(eBig))
		}
	}
	found := map[string]bool{}
	for _, u := range endpointsOf(eBig) {
		found[u] = true
	}
	if !found[srv.url()+"/api/a"] || !found[srv.url()+"/api/deep-regrow"] {
		t.Fatalf("big endpoints = %v, want big literals", endpointsOf(eBig))
	}
	// AllJavaScript stays file-only by design (Slice 3 exposes chunk
	// observations through AllChunkJavaScript instead — merging windows
	// here would collapse them into one asset): no chunk identity leaks
	// into the file accessor.
	for _, js := range repBig.AllJavaScript() {
		if _, _, _, _, _, _, _, perr := asset.ParseChunkIdentity(js.Identity()); perr == nil {
			t.Fatalf("chunk asset %q leaked into AllJavaScript (file-only accessor)", js.Identity())
		}
	}
}

// failDeleteCache fails every Delete with a synthetic IO error while counting
// attempts and delegating everything else to the wrapped cache.
type failDeleteCache struct {
	cache.Cache
	deletes *int
	err     error
}

func (f *failDeleteCache) Delete(ctx context.Context, key cache.Key) error {
	*f.deletes = *f.deletes + 1
	return f.err
}

// TestFetchShrinkDeleteErrorStillStoresComplete pins the OD-3a best-effort
// contract: a transient Delete IO error while shrinking to complete stashes
// the first failure, attempts every listed chunk key, still executes the
// complete Put, and reports the stashed error as a diagnostic.
func TestFetchShrinkDeleteErrorStillStoresComplete(t *testing.T) {
	inner := openTestCache(t)
	u := mustURL(t, "http://example.com/shrink-delerr.js")
	cfg := testFetchConfig()
	clk := newFakeClock(fixedTime)
	prefix := bytes.Repeat([]byte("e"), 600<<10)
	windows := splitWindows(prefix, maxFetchWindowBytes, fetchWindowOverlapBytes)
	if len(windows) < 2 {
		t.Fatalf("windows = %d, want >=2 (need multiple listed keys to pin continuation)", len(windows))
	}
	manifest := buildFetchManifest(prefix, windows)
	trunc := FetchResult{URL: u, FinalURL: u, StatusCode: 200, Truncated: true, Status: FetchTruncated, Windows: windows, Manifest: manifest}
	if err := storeFetch(context.Background(), cfg, inner, clk, trunc, []string{"s"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("store truncated: %v", err)
	}
	key, err := fetchKey(u, "")
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if out := inner.Get(context.Background(), key); out.State != cache.StateIncomplete {
		t.Fatalf("truncated record state = %v, want StateIncomplete", out.State)
	}
	wantDeletes := len(manifest.Chunks)
	if wantDeletes < 2 {
		t.Fatalf("manifest chunks = %d, want >=2 (need multiple listed keys to pin continuation)", wantDeletes)
	}
	synthetic := errors.New("synthetic delete IO error")
	var deletes int
	failing := &failDeleteCache{Cache: inner, deletes: &deletes, err: synthetic}
	complete := FetchResult{URL: u, FinalURL: u, StatusCode: 200, Status: FetchCompleted, Content: []byte("var small=1;")}
	serr := storeFetch(context.Background(), cfg, failing, clk, complete, []string{"s"}, fixedTime, fixedTime)
	if serr == nil {
		t.Fatal("store complete with failing deletes = nil, want the stashed delete diagnostic")
	}
	if !errors.Is(serr, synthetic) {
		t.Fatalf("store err = %v, want it to wrap the synthetic delete error", serr)
	}
	if !strings.Contains(serr.Error(), "delete orphaned chunk analyze") {
		t.Fatalf("store err = %v, want the orphan-delete diagnostic", serr)
	}
	if deletes != wantDeletes {
		t.Fatalf("Deletes = %d, want %d (every listed chunk key attempted despite the first failure)", deletes, wantDeletes)
	}
	// The complete Put still executed: the manifest is healed away and the
	// record decodes complete.
	out := inner.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("complete record state = %v, want hit (Put must execute despite delete errors)", out.State)
	}
	st, err := decodeStoredFetch(out.Record.Data, u)
	if err != nil {
		t.Fatalf("decode complete: %v", err)
	}
	if st.Truncated || st.TilingTag != "" || len(st.Chunks) != 0 {
		t.Fatalf("shrink must overwrite manifest away despite delete errors (got %+v)", st)
	}
	// A subsequent fresh-cache lookup serves the complete record.
	if lk := lookupFetch(context.Background(), u, cfg, inner, clk, "s"); !lk.Hit {
		t.Fatalf("lookup after failed deletes = hit false (err %v), want the stored complete", lk.Err)
	}
}
