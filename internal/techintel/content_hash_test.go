package techintel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// TestObservationContentHashDeterministic pins that the same observation
// always produces the same hash.
func TestObservationContentHashDeterministic(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	o.Body = "hello world"
	o.Cookies = []CookieEntry{{Name: "sid", Value: "abc"}}
	o.TLS = &TLSInfo{Issuer: "CN=Test", ALPN: []string{"h2"}}
	o.DNS = &DNSInfo{CNAMEChain: []string{"a.example.net"}}
	h1 := observationContentHash(o)
	h2 := observationContentHash(o)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 || !lowerHex(h1) {
		t.Fatalf("hash %q is not 64 lower hex", h1)
	}
}

// TestObservationContentHashSensitive ensures material content changes alter the hash.
func TestObservationContentHashSensitive(t *testing.T) {
	base := newObs(t, "https://ok.example/")
	base.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	base.Body = "hello"
	base.Cookies = []CookieEntry{{Name: "sid", Value: "abc"}}
	base.TLS = &TLSInfo{Issuer: "CN=Test", ALPN: []string{"h2"}}
	base.DNS = &DNSInfo{CNAMEChain: []string{"a.example.net"}}
	baseHash := observationContentHash(base)

	cases := []struct {
		name string
		mut  func(Observation) Observation
	}{
		{"body", func(o Observation) Observation { o.Body = "world"; return o }},
		{"header value", func(o Observation) Observation {
			h := make([]HeaderEntry, len(o.Headers))
			copy(h, o.Headers)
			h[0].Value = "Apache"
			o.Headers = h
			return o
		}},
		{"header add", func(o Observation) Observation {
			h := append([]HeaderEntry(nil), o.Headers...)
			h = append(h, HeaderEntry{Name: "X-Powered-By", Value: "PHP"})
			o.Headers = h
			return o
		}},
		{"cookie value", func(o Observation) Observation {
			c := make([]CookieEntry, len(o.Cookies))
			copy(c, o.Cookies)
			c[0].Value = "xyz"
			o.Cookies = c
			return o
		}},
		{"cookie add", func(o Observation) Observation {
			c := append([]CookieEntry(nil), o.Cookies...)
			c = append(c, CookieEntry{Name: "extra", Value: "1"})
			o.Cookies = c
			return o
		}},
		{"tls issuer", func(o Observation) Observation { c := *o.TLS; c.Issuer = "CN=Other"; o.TLS = &c; return o }},
		{"tls alpn", func(o Observation) Observation { c := *o.TLS; c.ALPN = []string{"h3"}; o.TLS = &c; return o }},
		{"dns cname", func(o Observation) Observation {
			c := *o.DNS
			c.CNAMEChain = []string{"b.example.net"}
			o.DNS = &c
			return o
		}},
		{"tls nil vs present", func(o Observation) Observation { o.TLS = nil; return o }},
		{"dns nil vs present", func(o Observation) Observation { o.DNS = nil; return o }},
		{"body empty vs present", func(o Observation) Observation { o.Body = ""; return o }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := tc.mut(base)
			h := observationContentHash(mut)
			if h == baseHash {
				t.Errorf("hash unchanged after %s: base %q mut %q", tc.name, baseHash, h)
			}
		})
	}

	// Status code and source must NOT affect the hash (status is observation
	// material but never analyzed). Use a fresh copy to avoid interference
	// from the table-driven mutations above (which copy slices but base
	// itself must remain pristine).
	fresh := newObs(t, "https://ok.example/")
	fresh.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	fresh.Body = "hello"
	fresh.Cookies = []CookieEntry{{Name: "sid", Value: "abc"}}
	fresh.TLS = &TLSInfo{Issuer: "CN=Test", ALPN: []string{"h2"}}
	fresh.DNS = &DNSInfo{CNAMEChain: []string{"a.example.net"}}
	freshHash := observationContentHash(fresh)
	mod := fresh
	mod.StatusCode = 404
	mod.Source = "other"
	if h := observationContentHash(mod); h != freshHash {
		t.Errorf("status/source must not enter hash: base %q vs mod %q", freshHash, h)
	}
}

// TestDecodeStoredTechRejectsMissingContentHash ensures legacy records without
// a content hash are rejected (self-heal).
func TestDecodeStoredTechRejectsMissingContentHash(t *testing.T) {
	o := canonicalObs(t)
	entry := testCompletedEntry(t, o)
	mask := sourcesMask(o)
	rec, err := encodeStoredTech(o, entry, mask, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	// Strip the content_hash field to simulate a legacy record.
	var s storedTech
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		t.Fatal(err)
	}
	s.ContentHash = ""
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	rec.Data = data

	if _, err := decodeStoredTech(rec, o, mask, 128, 512); err == nil || !strings.Contains(err.Error(), "content hash") {
		t.Errorf("legacy record without hash must be rejected, got %v", err)
	}

	// Tampered hash (wrong length / non-hex) must also be rejected.
	for _, bad := range []string{"nothex", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("A", 64)} {
		label := bad
		if len(label) > 8 {
			label = label[:8]
		}
		t.Run("bad hash "+label, func(t *testing.T) {
			s2 := s
			s2.ContentHash = bad
			// Restore a valid hash first, then corrupt it.
			valid, _ := encodeStoredTech(o, entry, mask, fixedTime)
			var tmp storedTech
			_ = json.Unmarshal(valid.Data, &tmp)
			tmp.ContentHash = bad
			badData, _ := json.Marshal(tmp)
			valid.Data = badData
			if _, err := decodeStoredTech(valid, o, mask, 128, 512); err == nil || !strings.Contains(err.Error(), "content hash") {
				t.Errorf("bad hash %q must be rejected, got %v", bad, err)
			}
		})
	}
}

// TestIngestContentChangeSelfHeal is the cross-engine conformance test:
// same URL identity, same sources mask, different body => cache miss and recompute.
func TestIngestContentChangeSelfHeal(t *testing.T) {
	// First observation: body "hello" — contains no strong marker, but still cached.
	obsHello := newObs(t, "https://ok.example/")
	obsHello.Body = "hello"
	obsHello.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}

	cfg := testConfig(t)
	cfg.Metrics = &Metrics{}

	// Fresh run stores hello.
	if _, err := Ingest(context.Background(), cfg, &SliceObservationSource{obsHello}); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	if got := cfg.Metrics.Snapshot(); got.Analyzed != 1 || got.Stored != 1 {
		t.Fatalf("first run metrics = %+v, want analyzed 1 stored 1", got)
	}
	// Verify the stored record carries the hello hash.
	key, err := techKey(obsHello, fingerprints.SchemaVersion, techDigest(t))
	if err != nil {
		t.Fatal(err)
	}
	// Need to compute expected key using the normalized observation as stored.
	// The key uses identity + schema/digest/sources, which are identical for
	// both bodies (both have same headers, same body presence).
	// We fetch via cache directly to inspect.
	out := cfg.Cache.Get(context.Background(), key)
	if out.State != cache.StateHit {
		t.Fatalf("state = %v, want hit after first store", out.State)
	}

	// Second observation: same URL, same headers, different body "world".
	obsWorld := newObs(t, "https://ok.example/")
	obsWorld.Body = "world"
	obsWorld.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}

	cfg2 := testConfig(t)
	// Reuse the SAME underlying cache directory as cfg (so second run sees hello's record).
	// testConfig creates a fresh temp dir per call; we must share.
	cfg2.Cache = cfg.Cache
	cfg2.Clock = cfg.Clock
	cfg2.Metrics = &Metrics{}
	// Need to share DB/digest? testConfig loads fresh DB each time — same digest.
	cfg2.DB = cfg.DB

	if _, err := Ingest(context.Background(), cfg2, &SliceObservationSource{obsWorld}); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}
	got2 := cfg2.Metrics.Snapshot()
	// Content changed => must NOT be a hit: analyzed 1, stored 1, reads 1.
	if got2.Reads != 1 || got2.Analyzed != 1 || got2.Stored != 1 {
		t.Errorf("content-changed run metrics = %+v, want reads 1 analyzed 1 stored 1 (no stale hit)", got2)
	}
	// Verify the cache now holds the world hash, not hello's.
	obsWorldHash := observationContentHash(mustPrepare(t, obsWorld))
	out2 := cfg2.Cache.Get(context.Background(), key)
	if out2.State != cache.StateHit {
		t.Fatalf("post-recompute state = %v, want hit", out2.State)
	}
	var s storedTech
	if err := json.Unmarshal(out2.Record.Data, &s); err != nil {
		t.Fatal(err)
	}
	if s.ContentHash != obsWorldHash {
		t.Errorf("stored hash = %q, want world hash %q (stale hello hash would be %q)", s.ContentHash, obsWorldHash, observationContentHash(mustPrepare(t, obsHello)))
	}

	// Third run: same world body again => should be a hit (zero analysis).
	cfg3 := testConfig(t)
	cfg3.Cache = cfg.Cache
	cfg3.Clock = cfg.Clock
	cfg3.DB = cfg.DB
	cfg3.Metrics = &Metrics{}
	if _, err := Ingest(context.Background(), cfg3, &SliceObservationSource{obsWorld}); err != nil {
		t.Fatalf("third Ingest: %v", err)
	}
	got3 := cfg3.Metrics.Snapshot()
	if got3.Reads != 1 || got3.Analyzed != 0 || got3.Stored != 0 {
		t.Errorf("same-content re-run metrics = %+v, want hit (reads 1 analyzed 0 stored 0)", got3)
	}
}

// TestIngestLegacyRecordSelfHeal ensures a record stored by a pre-hash build
// (simulated by stripping content_hash) is treated as stale and recomputed.
func TestIngestLegacyRecordSelfHeal(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Body = "hello"
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}

	cfg := testConfig(t)
	// Manually store a legacy record without content_hash.
	entry := func() ReportEntry {
		prov := asset.Provenance{Source: obs.Source, DiscoveredAt: obs.ObservedAt}
		return completedEntry(obs, analyze(obs, loadedDB(t), 128, 512, prov), prov)
	}()
	mask := sourcesMask(obs)
	rec, err := encodeStoredTech(obs, entry, mask, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	var s storedTech
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		t.Fatal(err)
	}
	s.ContentHash = "" // strip for legacy
	data, _ := json.Marshal(s)
	rec.Data = data
	key, _ := techKey(obs, fingerprints.SchemaVersion, techDigest(t))
	if err := cfg.Cache.Put(context.Background(), key, rec); err != nil {
		t.Fatal(err)
	}

	// Now run Ingest with the same observation: legacy hit must be rejected
	// and recomputed (analyzed 1, stored 1). The rejected hit surfaces as a
	// run diagnostic (hit rejected: content hash) but the run still completes.
	cfg.Metrics = &Metrics{}
	rep, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
	if err == nil || !strings.Contains(err.Error(), "content hash") {
		t.Fatalf("Ingest err = %v, want diagnostic containing content hash", err)
	}
	if rep.Observations.Completed != 1 {
		t.Fatalf("completed = %d, want 1", rep.Observations.Completed)
	}
	got := cfg.Metrics.Snapshot()
	if got.Reads != 1 || got.Analyzed != 1 || got.Stored != 1 {
		t.Errorf("legacy record run metrics = %+v, want miss+recompute (reads 1 analyzed 1 stored 1)", got)
	}
}

// mustPrepare normalizes an observation via prepareObservation using fixedTime.
func mustPrepare(t *testing.T, o Observation) Observation {
	t.Helper()
	p, _, err := prepareObservation(o, fixedTime)
	if err != nil {
		t.Fatalf("prepareObservation: %v", err)
	}
	return p
}
