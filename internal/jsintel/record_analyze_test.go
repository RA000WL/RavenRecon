// The js.analyze cache operation tests: round-trip, incomplete-never-hit,
// tamper rejection with self-healing, and key stability.
package jsintel

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// analyzeFixture builds a complete, valid analysis payload for u: every
// family populated with assets that satisfy decodeStoredAnalyze.
func analyzeFixture(t *testing.T, u asset.URL) analysisData {
	t.Helper()
	prov := asset.Provenance{Source: "test-src", DiscoveredAt: fixedTime}
	jsID := asset.Identity{Kind: asset.KindJavaScript, Value: u.String()}

	ep, err := asset.NewEndpoint("GET", "https://example.com/api/v1", prov)
	if err != nil {
		t.Fatalf("fixture endpoint: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "AKIAIOSFODNN7EXAMPLE", jsID, prov)
	if err != nil {
		t.Fatalf("fixture secret: %v", err)
	}
	tech, err := asset.NewTechnology("react", asset.CategoryFramework, prov)
	if err != nil {
		t.Fatalf("fixture technology: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodJS, "js_content:react-dom", "react-dom", jsID, prov)
	if err != nil {
		t.Fatalf("fixture evidence: %v", err)
	}
	sm, err := asset.NewSourceMap("https://example.com/app.js.map", prov)
	if err != nil {
		t.Fatalf("fixture source map: %v", err)
	}
	return analysisData{
		Imports:      []analysisImport{{Specifier: "./lib.js", URL: mustURL(t, "https://example.com/lib.js"), Kind: ImportStatic}},
		BareImports:  []string{"react"},
		Exports:      []string{"App"},
		SourceMaps:   []asset.SourceMap{sm},
		Endpoints:    []asset.Endpoint{ep},
		URLs:         []asset.URL{mustURL(t, "https://cdn.example.net/lib.js")},
		Secrets:      []asset.SecretCandidate{sec},
		Technologies: []asset.Technology{tech},
		Evidence:     []asset.Evidence{ev},
	}
}

// analyzeHash returns a deterministic 64-character lowercase hex content
// hash for tests — the exact form the fetch layer produces for real
// content (readTerminal) and the JS asset's ContentHash carries.
func analyzeHash(seed byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func TestAnalyzeCacheRoundTrip(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := analyzeFixture(t, u)
	hash := analyzeHash(0x11)

	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeAnalyze: %v", err)
	}
	lu := lookupAnalyze(context.Background(), u, hash, Config{}, c, clock)
	if !lu.Hit {
		t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
	}
	if !reflect.DeepEqual(lu.Result, data) {
		t.Errorf("restored payload differs from the stored one:\n%+v\nvs\n%+v", lu.Result, data)
	}
	if !lu.FirstSeen.Equal(fixedTime) || !lu.LastSeen.Equal(fixedTime) {
		t.Errorf("window = %v/%v, want %v", lu.FirstSeen, lu.LastSeen, fixedTime)
	}
}

func TestAnalyzeIncompleteNeverHit(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := analyzeFixture(t, u)
	hash := analyzeHash(0x11)

	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hash, data, true, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeAnalyze: %v", err)
	}
	lu := lookupAnalyze(context.Background(), u, hash, Config{}, c, clock)
	if lu.Hit {
		t.Fatal("a truncated analysis must never be served as a hit")
	}
	if lu.Err != nil {
		t.Errorf("lookup err = %v, want nil (a clean incomplete miss)", lu.Err)
	}
}

// putAnalyzeRecord writes a completed record carrying the given storedAnalyze
// payload under key.
func putAnalyzeRecord(t *testing.T, c cache.Cache, key cache.Key, st storedAnalyze) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("encode tampered record: %v", err)
	}
	if err := c.Put(context.Background(), key, cache.Record{
		Operation: AnalyzeOperation,
		Target:    st.Target,
		Status:    cache.StatusCompleted,
		Data:      data,
	}); err != nil {
		t.Fatalf("put tampered record: %v", err)
	}
}

func TestAnalyzeCacheTamperTable(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	key, err := analyzeKey(u)
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	data := analyzeFixture(t, u)
	hash := analyzeHash(0x11)

	// The valid base record every mutation starts from.
	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("base storeAnalyze: %v", err)
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
		{"wrong target", func(s *storedAnalyze) { s.Target = "url:http://other.example/x.js" }},
		{"wrong parser version", func(s *storedAnalyze) { s.ParserVersion++ }},
		{"wrong mask", func(s *storedAnalyze) { s.Mask = "eim" }},
		{"empty analyzed hash", func(s *storedAnalyze) { s.AnalyzedHash = "" }},
		{"malformed analyzed hash", func(s *storedAnalyze) { s.AnalyzedHash = "zz" + strings.Repeat("0", 62) }},
		// NOTE: a well-formed hash of DIFFERENT content is NOT a tamper —
		// it is the routine lifecycle case (content changed between runs;
		// fetch and analyze records have independent lifecycles), pinned by
		// TestAnalyzeHashMismatchHeals as a silent miss.
		{"non-canonical import url", func(s *storedAnalyze) { s.Imports[0].URL = asset.URL{} }},
		{"unknown import kind", func(s *storedAnalyze) { s.Imports[0].Kind = "bogus" }},
		{"empty import specifier", func(s *storedAnalyze) { s.Imports[0].Specifier = "" }},
		{"non-printable import specifier", func(s *storedAnalyze) { s.Imports[0].Specifier = "bad\x01spec" }},
		{"non-canonical source map url", func(s *storedAnalyze) { s.SourceMaps[0].URL = asset.URL{} }},
		{"non-reparseable endpoint", func(s *storedAnalyze) { s.Endpoints[0].Method = "GE T" }},
		{"unknown secret type", func(s *storedAnalyze) { s.Secrets[0].Type = "bogus" }},
		{"empty secret value", func(s *storedAnalyze) { s.Secrets[0].Value = "" }},
		{"foreign secret source", func(s *storedAnalyze) {
			s.Secrets[0].Source = asset.Identity{Kind: asset.KindHost, Value: "other.example"}
		}},
		{"unknown technology", func(s *storedAnalyze) { s.Technologies[0].Name = "" }},
		{"non-js evidence method", func(s *storedAnalyze) { s.Evidence[0].Method = asset.MethodHTML }},
		{"foreign evidence source", func(s *storedAnalyze) {
			s.Evidence[0].Source = asset.Identity{Kind: asset.KindHost, Value: "other.example"}
		}},
		{"evidence value mismatch", func(s *storedAnalyze) { s.Evidence[0].Value = "other" }},
		{"duplicate endpoints", func(s *storedAnalyze) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) }},
		{"duplicate secrets", func(s *storedAnalyze) { s.Secrets = append(s.Secrets, s.Secrets[0]) }},
		{"inverted timestamps", func(s *storedAnalyze) { s.LastSeen = s.FirstSeen.Add(-time.Hour) }},
		{"zero timestamps", func(s *storedAnalyze) { s.LastSeen = time.Time{} }},
		{"oversized imports", func(s *storedAnalyze) {
			imp := s.Imports[0]
			for i := 0; i <= maxStoredAnalysisItems; i++ {
				s.Imports = append(s.Imports, storedImport{Specifier: imp.Specifier, URL: imp.URL, Kind: imp.Kind})
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base
			tc.mutate(&mut)
			putAnalyzeRecord(t, c, key, mut)

			lu := lookupAnalyze(context.Background(), u, hash, Config{}, c, clock)
			if lu.Hit {
				t.Fatal("tampered record served as a hit")
			}
			if lu.Err == nil {
				t.Fatal("lookup err = nil, want the rejection diagnostic")
			}
			// Self-healing: the unusable record was deleted, and the next
			// lookup falls through to a fresh analysis.
			if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
				t.Fatalf("state after rejection = %v, want miss (deleted)", out.State)
			}
		})
	}

	// A fresh store after the last rejection recomputes a valid record
	// (self-healing in the same run).
	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hash, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("recompute storeAnalyze: %v", err)
	}
	if lu := lookupAnalyze(context.Background(), u, hash, Config{}, c, clock); !lu.Hit {
		t.Fatalf("recomputed record not served (err %v)", lu.Err)
	}
}

func TestAnalyzeKeyStability(t *testing.T) {
	ua := mustURL(t, "http://example.com/app.js")
	ub := mustURL(t, "http://example.com/other.js")
	uc := mustURL(t, "https://example.com/app.js")

	ka1, err := analyzeKey(ua)
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	ka2, err := analyzeKey(mustURL(t, "http://example.com/app.js"))
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	if ka1 != ka2 {
		t.Errorf("same URL produced different keys")
	}
	if ka1 == "" || len(ka1) != 64 {
		t.Errorf("key = %q, want a 64-char digest", ka1)
	}
	// The key equals the canonical construction: operation + identity +
	// parser contract (schema version and family mask).
	canon, err := cache.NewKey(cache.KeyParts{
		Operation: AnalyzeOperation,
		Target:    ua.Identity().String(),
		Config:    map[string]string{"parser": "1:eimst"},
	})
	if err != nil {
		t.Fatalf("canonical key: %v", err)
	}
	if ka1 != canon {
		t.Errorf("key %s != canonical construction %s", ka1, canon)
	}
	// Distinct URLs produce distinct keys.
	if kb, _ := analyzeKey(ub); kb == ka1 {
		t.Error("different path produced the same key")
	}
	if kc, _ := analyzeKey(uc); kc == ka1 {
		t.Error("different scheme produced the same key")
	}
	// Per-file caps are not part of the key by construction: analyzeKey
	// takes only the URL. Documented, not asserted mechanically beyond the
	// signature (a stored record stays valid under any cap configuration).
	// The content hash is likewise NOT part of the key: it lives in the
	// record payload (storedAnalyze.AnalyzedHash) and is cross-validated at
	// lookup — a content change deletes the stale record under the same
	// key instead of orphaning one key per content version.
	if strings.Contains(string(ka1), "MaxEndpoints") {
		t.Error("key must not embed configurable caps")
	}
}

// TestAnalyzeHashMismatchHeals pins the M-5 content binding: a record
// derived from content A must never serve the analysis for content B. The
// lookup cross-validates the stored hash against the CURRENT content's
// hash, deletes the stale record (self-healing under the same key), and
// falls through to a fresh analysis; the fresh store rebinds the key.
func TestAnalyzeHashMismatchHeals(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	data := analyzeFixture(t, u)
	hashA := analyzeHash(0x11)
	hashB := analyzeHash(0x22)

	// Content A analyzed: the record is bound to A's hash.
	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hashA, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeAnalyze(A): %v", err)
	}
	if lu := lookupAnalyze(context.Background(), u, hashA, Config{}, c, clock); !lu.Hit {
		t.Fatalf("lookup with A's content = hit false (err %v), want a hit", lu.Err)
	}

	// The content changed (hash B): the stale record must not serve. The
	// record is well-formed and legitimate — only outdated — so the
	// mismatch is a routine lifecycle event (fetch and analyze records
	// have independent lifecycles), NOT an anomaly: the lookup falls
	// through as a silent miss with no diagnostic, exactly like a plain
	// cache miss.
	lu := lookupAnalyze(context.Background(), u, hashB, Config{}, c, clock)
	if lu.Hit {
		t.Fatal("stale analysis served for different content")
	}
	if lu.Err != nil {
		t.Fatalf("lookup err = %v, want nil (a content change is a routine miss, not a diagnostic)", lu.Err)
	}
	key, err := analyzeKey(u)
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
		t.Fatalf("state after stale rejection = %v, want miss (the stale record was deleted)", out.State)
	}

	// The fresh analysis of B stores under the SAME key, bound to B.
	if err := storeAnalyze(context.Background(), Config{}, c, clock, u, hashB, data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
		t.Fatalf("storeAnalyze(B): %v", err)
	}
	if lu := lookupAnalyze(context.Background(), u, hashB, Config{}, c, clock); !lu.Hit {
		t.Fatalf("lookup with B's content = hit false (err %v), want a hit", lu.Err)
	}
	// The rebound record must not serve A either: binding is bidirectional.
	if lu := lookupAnalyze(context.Background(), u, hashA, Config{}, c, clock); lu.Hit {
		t.Fatal("rebound record served for the old content")
	}
}

// TestAnalyzeStoreHashValidation pins the store-side hash contract: an
// analysis of EMPTY content (the only content whose SHA-256 is empty under
// the fetch layer's convention) is never cached — the lookup falls through
// to a fresh analysis — and a malformed hash is a store error, so a record
// this layer writes always satisfies its own decode.
func TestAnalyzeStoreHashValidation(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	data := analyzeFixture(t, u)

	t.Run("empty content is never cached", func(t *testing.T) {
		c := openTestCache(t)
		clock := newFakeClock(fixedTime)
		if err := storeAnalyze(context.Background(), Config{}, c, clock, u, "", data, false, []string{"test-src"}, fixedTime, fixedTime); err != nil {
			t.Fatalf("storeAnalyze(empty hash): %v", err)
		}
		key, err := analyzeKey(u)
		if err != nil {
			t.Fatalf("analyzeKey: %v", err)
		}
		if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
			t.Fatalf("state = %v, want miss (empty-content analysis is never stored)", out.State)
		}
		if lu := lookupAnalyze(context.Background(), u, "", Config{}, c, clock); lu.Hit {
			t.Fatal("empty-content analysis served as a hit")
		}
	})

	t.Run("malformed hash rejected", func(t *testing.T) {
		c := openTestCache(t)
		clock := newFakeClock(fixedTime)
		if err := storeAnalyze(context.Background(), Config{}, c, clock, u, "zz"+strings.Repeat("0", 62), data, false, []string{"test-src"}, fixedTime, fixedTime); err == nil {
			t.Error("storeAnalyze accepted a malformed content hash")
		}
	})
}
