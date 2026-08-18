package techintel

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// techDigest returns the content digest of the production fingerprint
// database — the exact value the engine computes once at env construction —
// so key assertions reproduce the engine's keys.
func techDigest(t *testing.T) string {
	t.Helper()
	db, err := fingerprints.Load()
	if err != nil {
		t.Fatal(err)
	}
	return db.Digest()
}

// testCompletedEntry builds a completed entry for a small observation using
// the production fingerprint database, so the record round-trips real data.
func testCompletedEntry(t *testing.T, o Observation) ReportEntry {
	t.Helper()
	prov := asset.Provenance{Source: o.Source, DiscoveredAt: o.ObservedAt}
	out := analyze(o, loadedDB(t), 128, 512, prov)
	return completedEntry(o, out, prov)
}

// loadedDB loads the production fingerprint database once per test process
// (the DB is immutable; Fingerprints returns deep copies).
func loadedDB(t *testing.T) []fingerprints.Fingerprint {
	t.Helper()
	db, err := fingerprints.Load()
	if err != nil {
		t.Fatal(err)
	}
	return db.Fingerprints()
}

// canonicalObs returns an observation exercising every sources-mask channel.
func canonicalObs(t *testing.T) Observation {
	t.Helper()
	ep, err := asset.NewEndpoint("GET", "https://ok.example/api", asset.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	o := newObs(t, "https://ok.example/api")
	o.Endpoint = &ep
	o.StatusCode = 200
	o.Headers = []HeaderEntry{
		{Name: "Server", Value: "nginx/1.25.3"},
		{Name: "Set-Cookie", Value: "sid=abc; HttpOnly"},
	}
	o.Body = `<div ng-app ng-version="17.2.0">`
	o.Cookies = []CookieEntry{{Name: "phx_session", Value: "x"}}
	o.TLS = &TLSInfo{ALPN: []string{"h3"}, Issuer: "CN=WR2,O=Google Trust Services"}
	o.DNS = &DNSInfo{CNAMEChain: []string{"edge.example.cloudflare.net"}}
	return o
}

func TestTechKeyDeterministicAndSensitive(t *testing.T) {
	o := canonicalObs(t)
	dig := techDigest(t)
	k1, err := techKey(o, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := techKey(o, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Error("same observation must produce the same key")
	}

	// Schema sensitivity: a bumped schema version changes the key.
	otherSchema, err := techKey(o, 2, dig)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == otherSchema {
		t.Error("schema version must enter the key")
	}

	// Database-content sensitivity: ANY data-only edit to the fingerprint
	// tables changes the content digest and therefore the key — a table
	// edit that never bumps the schema must still invalidate every cached
	// detection.
	base, err := fingerprints.Load()
	if err != nil {
		t.Fatal(err)
	}
	entries := base.Fingerprints()
	mut := entries[0]
	mut.Indicators = append([]fingerprints.Indicator(nil), entries[0].Indicators...)
	w := mut.Indicators[0].Weight
	if math.Abs(w-0.42) < 1e-9 {
		w = 0.43
	} else {
		w = 0.42
	}
	mut.Indicators[0].Weight = w
	entries[0] = mut
	modDB, err := fingerprints.CompileForTest(entries)
	if err != nil {
		t.Fatal(err)
	}
	modDigest := modDB.Digest()
	if modDigest == dig {
		t.Fatal("a mutated table must change the content digest")
	}
	if k, err := techKey(o, 1, modDigest); err != nil || k == k1 {
		t.Errorf("database content digest must enter the key (err=%v)", err)
	}

	// Sources sensitivity: a body-ful observation must not share a key with
	// a headers-only observation of the same target.
	headersOnly := newObs(t, "https://ok.example/api")
	headersOnly.Headers = o.Headers
	headersOnly.StatusCode = o.StatusCode
	ko, err := techKey(headersOnly, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == ko {
		t.Error("sources mask must enter the key")
	}

	// Status-code independence: the status code is observation material,
	// never part of the key.
	withStatus := newObs(t, "https://ok.example/api")
	withStatus.Headers = o.Headers
	ks, err := techKey(withStatus, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	if ko != ks {
		t.Error("status code must not enter the key")
	}

	// Target sensitivity: a different URL yields a different key.
	other, err := techKey(newObs(t, "https://other.example/api"), 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == other {
		t.Error("target identity must enter the key")
	}

	// Endpoint identity: attaching an endpoint narrows the key.
	withEndpoint := canonicalObs(t)
	withoutEndpoint := canonicalObs(t)
	withoutEndpoint.Endpoint = nil
	ke, err := techKey(withEndpoint, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	kn, err := techKey(withoutEndpoint, 1, dig)
	if err != nil {
		t.Fatal(err)
	}
	if ke == kn {
		t.Error("endpoint attachment must narrow the key")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	o := canonicalObs(t)
	o.ObservedAt = fixedTime.Add(5 * time.Minute)
	entry := testCompletedEntry(t, o)
	mask := sourcesMask(o)

	rec, err := encodeStoredTech(o, entry, mask, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Operation != Operation || rec.Target != o.identity().String() ||
		rec.Status != cache.StatusCompleted || rec.SchemaVersion != cache.SchemaVersion {
		t.Errorf("record envelope = %+v", rec)
	}

	dec, err := decodeStoredTech(rec, o, mask, 128, 512)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Sources != mask {
		t.Errorf("sources = %q, want %q", dec.Sources, mask)
	}
	if len(dec.Technologies) != len(entry.Technologies) {
		t.Fatalf("technologies = %d, want %d", len(dec.Technologies), len(entry.Technologies))
	}
	for i, t0 := range entry.Technologies {
		t1 := dec.Technologies[i]
		if t1.Name != t0.Technology.Name || t1.Category != t0.Technology.Category ||
			t1.Version != t0.Technology.Version {
			t.Errorf("technology[%d] = %v, want %v", i, t1, t0.Technology)
		}
		if t1.Prov.Confidence != t0.Score {
			t.Errorf("technology[%d] score = %v, want %v", i, t1.Prov.Confidence, t0.Score)
		}
		if lvl := ConfidenceLevel(dec.Levels[i]); lvl != t0.Level {
			t.Errorf("technology[%d] level = %q, want %q", i, lvl, t0.Level)
		}
	}
	if len(dec.Evidence) != len(entry.Evidence) {
		t.Errorf("evidence = %d, want %d", len(dec.Evidence), len(entry.Evidence))
	}
	for i, ev := range entry.Evidence {
		if dec.Evidence[i].ID() != ev.ID() {
			t.Errorf("evidence[%d] = %v, want %v", i, dec.Evidence[i], ev)
		}
	}
	if dec.Conflicts != entry.Conflicts || dec.Truncated != entry.Truncated {
		t.Errorf("conflicts/truncated = %d/%v, want %d/%v",
			dec.Conflicts, dec.Truncated, entry.Conflicts, entry.Truncated)
	}
	if !dec.FirstSeen.Equal(entry.FirstSeen) || !dec.LastSeen.Equal(entry.LastSeen) {
		t.Errorf("timestamps = %v..%v, want %v..%v",
			dec.FirstSeen, dec.LastSeen, entry.FirstSeen, entry.LastSeen)
	}
}

// TestEncodeStoredTechCreatedAtIsStoreTime is the L3 record-level regression
// test (the engine-level path is pinned end-to-end by
// TestIngestRecordCreatedAtIsStoreTime): encodeStoredTech stamps the
// envelope's CreatedAt from the STORE time — the `now` the runner passes —
// never from the observation's ObservedAt, while the payload keeps the
// observation's own times (FirstSeen/LastSeen). TTL is measured from
// CreatedAt, so a stale ObservedAt must not expire a fresh record instantly
// and a future ObservedAt must not make it immortal.
func TestEncodeStoredTechCreatedAtIsStoreTime(t *testing.T) {
	stale := fixedTime.Add(-48 * time.Hour) // observation made long ago
	storeAt := fixedTime                    // the run clock at store time

	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	o.ObservedAt = stale
	prov := asset.Provenance{Source: o.Source, DiscoveredAt: stale}
	entry := completedEntry(o, analyze(o, loadedDB(t), 128, 512, prov), prov)

	rec, err := encodeStoredTech(o, entry, sourcesMask(o), storeAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.CreatedAt; !got.Equal(storeAt) {
		t.Errorf("record CreatedAt = %v, want the store time %v (never ObservedAt %v)", got, storeAt, stale)
	}

	// The payload keeps the observation's own times untouched.
	dec, err := decodeStoredTech(rec, o, sourcesMask(o), 128, 512)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.FirstSeen.Equal(stale) || !dec.LastSeen.Equal(stale) {
		t.Errorf("payload times = %v..%v, want the observation's own %v..%v",
			dec.FirstSeen, dec.LastSeen, stale, stale)
	}
}

// TestEncodeStoredTechCreatedAtIsStoreTimeFutureObservedAt is the
// future-time twin of TestEncodeStoredTechCreatedAtIsStoreTime: an
// observation stamped in the FUTURE must not make its record immortal.
// encodeStoredTech stamps the envelope's CreatedAt from the STORE time —
// the `now` the runner passes — never from the observation's ObservedAt,
// so TTL (measured from CreatedAt) still starts at store time and the
// record expires within the normal TTL window, never at the observation's
// future timestamp.
func TestEncodeStoredTechCreatedAtIsStoreTimeFutureObservedAt(t *testing.T) {
	future := fixedTime.Add(1 * time.Hour) // observation stamped in the future
	storeAt := fixedTime                   // the run clock at store time

	o := newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	o.ObservedAt = future
	prov := asset.Provenance{Source: o.Source, DiscoveredAt: future}
	entry := completedEntry(o, analyze(o, loadedDB(t), 128, 512, prov), prov)

	rec, err := encodeStoredTech(o, entry, sourcesMask(o), storeAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.CreatedAt; !got.Equal(storeAt) {
		t.Errorf("record CreatedAt = %v, want the store time %v (never ObservedAt %v)", got, storeAt, future)
	}

	// The payload keeps the observation's own times untouched.
	dec, err := decodeStoredTech(rec, o, sourcesMask(o), 128, 512)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.FirstSeen.Equal(future) || !dec.LastSeen.Equal(future) {
		t.Errorf("payload times = %v..%v, want the observation's own %v..%v",
			dec.FirstSeen, dec.LastSeen, future, future)
	}
}

// tamperPayload decodes a stored record's payload, applies mutate, and
// re-encodes it into the record.
func tamperPayload(t *testing.T, rec cache.Record, mutate func(*storedTech)) cache.Record {
	t.Helper()
	var s storedTech
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		t.Fatal(err)
	}
	mutate(&s)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	rec.Data = data
	return rec
}

func TestDecodeStoredTechRejectsInvalid(t *testing.T) {
	o := canonicalObs(t)
	entry := testCompletedEntry(t, o)
	mask := sourcesMask(o)
	valid, err := encodeStoredTech(o, entry, mask, fixedTime)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		obs     *Observation // alternate observation; nil means the canonical one
		capTech int
		capInd  int
		mut     func(cache.Record) cache.Record
		want    string
	}{
		{name: "not completed status", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			r.Status = cache.StatusCancelled
			return r
		}, want: "not completed"},
		{name: "wrong schema version", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			r.SchemaVersion = 99
			return r
		}, want: "schema version"},
		{name: "wrong operation", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			r.Operation = "other.op"
			return r
		}, want: "operation"},
		{name: "empty payload", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			r.Data = nil
			return r
		}, want: "empty"},
		{name: "wrong target", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			r.Target = "url:https://other.example/"
			return r
		}, want: "target"},
		{name: "sources mismatch", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) { s.Sources = "h" })
		}, want: "sources"},
		{name: "levels count mismatch", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) { s.Levels = s.Levels[:len(s.Levels)-1] })
		}, want: "technologies but"},
		{name: "technology count over cap", capTech: 0, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				s.Technologies = append(s.Technologies, s.Technologies[0])
				s.Levels = append(s.Levels, s.Levels[0])
				// VersionOrdinals is a parallel array; keep the lengths in
				// step so the ordinal check cannot fire before the cap check.
				s.VersionOrdinals = append(s.VersionOrdinals, s.VersionOrdinals[0])
			})
		}, want: "over run cap"},
		{name: "evidence count over cap", capTech: 128, capInd: 0, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) { s.Evidence = append(s.Evidence, s.Evidence[0]) })
		}, want: "over run cap"},
		{name: "zero timestamps", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) { s.LastSeen = time.Time{} })
		}, want: "timestamps"},
		{name: "backwards timestamps", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				// The canned record has FirstSeen == LastSeen; widen first so
				// the swap provably inverts the order.
				if s.LastSeen.Equal(s.FirstSeen) {
					s.LastSeen = s.FirstSeen.Add(time.Hour)
				}
				s.FirstSeen, s.LastSeen = s.LastSeen, s.FirstSeen
			})
		}, want: "timestamps"},
		{name: "score out of range", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				s.Technologies[0].Prov.Confidence = 1.5
			})
		}, want: "out of [0,1]"},
		{name: "unknown level", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) { s.Levels[0] = "bogus" })
		}, want: "level"},
		{name: "level stronger than score allows", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				// Every level forced to high: at least one technology's
				// score cannot justify it.
				for i := range s.Levels {
					s.Levels[i] = "high"
				}
			})
		}, want: "stronger than score"},
		{name: "non-canonical technology", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				s.Technologies[0].Name = " NGINX "
			})
		}, want: "diverges from canonical"},
		{name: "evidence impossible for sources", obs: func() *Observation {
			ho := newObs(t, "https://ok.example/")
			ho.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}
			return &ho
		}(), capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			// A headers-only observation's record cannot carry HTML-derived
			// evidence; build that record from its own observation so every
			// other tamper guard stays satisfied.
			ho := newObs(t, "https://ok.example/")
			ho.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}
			prov := asset.Provenance{Source: ho.Source, DiscoveredAt: ho.ObservedAt}
			entry := completedEntry(ho, analyze(ho, loadedDB(t), 128, 512, prov), prov)
			hr, err := encodeStoredTech(ho, entry, sourcesMask(ho), fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			return tamperPayload(t, hr, func(s *storedTech) {
				s.Evidence[0].Method = asset.MethodHTML // mask "h" carries no 'b'
			})
		}, want: "impossible for sources"},
		{name: "tech links missing evidence", capTech: 128, capInd: 512, mut: func(r cache.Record) cache.Record {
			return tamperPayload(t, r, func(s *storedTech) {
				s.TechEvidence["tech:missing"] = []string{"evidence:nonexistent"}
			})
		}, want: "links missing evidence"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.mut(valid)
			obs := o
			if tt.obs != nil {
				obs = *tt.obs
			}
			_, err := decodeStoredTech(tampered, obs, sourcesMask(obs), tt.capTech, tt.capInd)
			if err == nil {
				t.Fatal("tampered record must be rejected")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}

	// The untampered record still decodes within the same caps.
	if _, err := decodeStoredTech(valid, o, mask, 128, 512); err != nil {
		t.Fatalf("valid record must decode: %v", err)
	}
}

// TestValidateStoredScoreRejectsNaN pins the decode-side score guard
// directly with Go-constructed values. encoding/json can neither marshal
// nor unmarshal a NaN float, so the NaN branch is unreachable through a
// stored record's JSON payload — the guard is defense in depth against a
// tampered in-memory payload or a future non-JSON storage format. Without
// the guard a NaN score would pass both `score < 0` and `score > 1` and
// reach levelForScore, where it silently falls through every threshold to
// LevelUnknown.
func TestValidateStoredScoreRejectsNaN(t *testing.T) {
	if err := validateStoredScore("tech", math.NaN()); err == nil || !strings.Contains(err.Error(), "NaN") {
		t.Errorf("NaN score must be rejected, got %v", err)
	}
	if err := validateStoredScore("tech", 1.5); err == nil || !strings.Contains(err.Error(), "out of [0,1]") {
		t.Errorf("1.5 must be rejected, got %v", err)
	}
	if err := validateStoredScore("tech", -0.01); err == nil || !strings.Contains(err.Error(), "out of [0,1]") {
		t.Errorf("-0.01 must be rejected, got %v", err)
	}
	for _, ok := range []float64{0, 0.2, 1} {
		if err := validateStoredScore("tech", ok); err != nil {
			t.Errorf("score %v must be accepted, got %v", ok, err)
		}
	}
}

// TestStoredTechJSONCannotRepresentNaN documents the defense-in-depth
// rationale: a stored record's payload can never carry a NaN score, because
// encoding/json rejects NaN in both directions — marshal fails on a NaN
// float field and unmarshal fails on a NaN literal.
func TestStoredTechJSONCannotRepresentNaN(t *testing.T) {
	o := canonicalObs(t)
	entry := testCompletedEntry(t, o)
	rec, err := encodeStoredTech(o, entry, sourcesMask(o), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	var s storedTech
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Technologies) == 0 {
		t.Fatal("canonical observation must detect at least one technology")
	}
	s.Technologies[0].Prov.Confidence = math.NaN()
	if _, err := json.Marshal(s); err == nil {
		t.Error("json.Marshal must refuse a NaN score (records on disk can never carry one)")
	}
	var s2 storedTech
	if err := json.Unmarshal([]byte(`{"technologies":[{"prov":{"confidence":NaN}}]}`), &s2); err == nil {
		t.Error("json.Unmarshal must refuse a NaN literal")
	}
}

func TestMethodPossible(t *testing.T) {
	cases := []struct {
		mask   string
		method asset.DetectionMethod
		want   bool
	}{
		{"h", asset.MethodHeader, true},
		{"bh", asset.MethodHeader, true},
		// Cookie evidence fires from caller-provided cookies ('c') or from
		// Cookie/Set-Cookie headers ('h'), which the cookie analyzer parses:
		// either family alone can produce it.
		{"h", asset.MethodCookie, true},
		{"c", asset.MethodCookie, true},
		{"b", asset.MethodCookie, false},
		{"b", asset.MethodHTML, true},
		{"b", asset.MethodGenerator, true},
		{"b", asset.MethodMeta, true},
		{"b", asset.MethodScript, true},
		{"b", asset.MethodCSS, true},
		{"b", asset.MethodAttribute, true},
		{"b", asset.MethodSourceMap, true},
		{"h", asset.MethodHTML, false},
		{"", asset.MethodHTML, false},
		// endpoint_path matches the observation URL's path, which every
		// observation carries: endpoint-derived evidence is always possible.
		{"h", asset.MethodEndpoint, true},
		{"", asset.MethodEndpoint, true},
		{"t", asset.MethodTLS, true},
		{"h", asset.MethodTLS, false},
		{"d", asset.MethodDNS, true},
		{"h", asset.MethodDNS, false},
		{"c", asset.MethodCookie, true},
		{"h", asset.MethodCookie, true},
		{"h", asset.DetectionMethod("bogus"), false},
	}
	for _, tt := range cases {
		if got := methodPossible(tt.mask, tt.method); got != tt.want {
			t.Errorf("methodPossible(%q, %q) = %v, want %v", tt.mask, tt.method, got, tt.want)
		}
	}
}
