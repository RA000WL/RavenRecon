package secrentel

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// scanOnce runs one document through processDocument with a real cache and
// returns the prepared document, the entry, and the cache key.
func scanOnce(t *testing.T, fs cache.Cache, d Document) (scannedDocument, ReportEntry, cache.Key) {
	t.Helper()
	sd, err := prepareDocument(d, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{db: loadDB(t), cache: fs, clock: newFakeClock(), limits: defaultScanLimits()}
	entry := processDocument(context.Background(), sd, e)
	key, err := secretKey(sd, e.db.Version())
	if err != nil {
		t.Fatal(err)
	}
	return sd, entry, key
}

func TestRecordRoundTripThroughCache(t *testing.T) {
	fs := openTestCache(t)
	doc := Document{Kind: KindJS, Content: []byte("k=" + awsKeyID), Filename: "app.js"}
	sd, entry, key := scanOnce(t, fs, doc)

	if entry.Status != StatusCompleted {
		t.Fatalf("entry status = %s", entry.Status)
	}
	out := fs.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("expected cache hit, got %s (%v)", out.State, out.Err)
	}
	s, err := decodeStoredScan(*out.Record, sd, defaultScanLimits())
	if err != nil {
		t.Fatalf("decodeStoredScan: %v", err)
	}
	if len(s.Secrets) != len(entry.Secrets) {
		t.Fatalf("stored secrets = %d, want %d", len(s.Secrets), len(entry.Secrets))
	}

	// The rebuilt entry equals the fresh one in every derived field.
	rebuilt := entryFromStored(sd, s)
	if rebuilt.Status != StatusCompleted || !rebuilt.Cached {
		t.Errorf("rebuilt entry status/cached = %s/%v", rebuilt.Status, rebuilt.Cached)
	}
	if len(rebuilt.Secrets) != len(entry.Secrets) ||
		rebuilt.Secrets[0].id != entry.Secrets[0].id ||
		rebuilt.Secrets[0].confidence.Score != entry.Secrets[0].confidence.Score {
		t.Errorf("rebuilt candidates diverge")
	}
	if len(rebuilt.Evidence) != len(entry.Evidence) {
		t.Errorf("rebuilt evidence = %d, want %d", len(rebuilt.Evidence), len(entry.Evidence))
	}
	if len(rebuilt.Relationships) != len(entry.Relationships) {
		t.Errorf("rebuilt relationships = %d, want %d", len(rebuilt.Relationships), len(entry.Relationships))
	}
	for i := range entry.Relationships {
		if entry.Relationships[i].ID() != rebuilt.Relationships[i].ID() {
			t.Errorf("relationship %d diverges: %s vs %s", i, entry.Relationships[i].ID(), rebuilt.Relationships[i].ID())
		}
	}
}

// tamper fetches the stored payload, applies a mutation, writes it back, and
// returns the mutated record for decode assertions.
func tamper(t *testing.T, fs cache.Cache, key cache.Key, mutate func(map[string]any)) cache.Record {
	t.Helper()
	out := fs.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("no cached record to tamper with (%s)", out.State)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Record.Data, &payload); err != nil {
		t.Fatal(err)
	}
	mutate(payload)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec := *out.Record
	rec.Data = data
	if err := fs.Put(context.Background(), key, rec); err != nil {
		t.Fatal(err)
	}
	out = fs.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("tampered record unreadable: %s", out.State)
	}
	return *out.Record
}

func TestRecordTamperRejections(t *testing.T) {
	doc := Document{Kind: KindJS, Content: []byte("k=" + awsKeyID + " s=" + awsSecret), Filename: "app.js"}
	// The S3-capped document: a pure-endpoint bucket URL, capped at Low
	// (urlTypeCap) by contract with the weight-0 url_type_cap marker.
	s3Doc := Document{Kind: KindJS, Content: []byte(`const u = "https://my-bucket.s3.us-east-1.amazonaws.com/file.txt";`)}

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
		altDoc *Document // when set, scanned instead of doc
	}{
		{
			"inflated score",
			func(p map[string]any) {
				p["secrets"].([]any)[0].(map[string]any)["score"] = 1.01
			},
			"out of [0,1]",
			nil,
		},
		{
			"level stronger than score",
			func(p map[string]any) {
				s0 := p["secrets"].([]any)[0].(map[string]any)
				s0["score"] = 0.3
				s0["level"] = "high"
			},
			"stronger than score",
			nil,
		},
		{
			"level gated below stored",
			// Internally consistent with the score (high ≤ levelForScore(0.9)
			// = high, weights valid, score within the derived cap), but the
			// engine's level gates would demote a 0.9 with one non-pattern
			// factor to Medium: caught by the gate re-validation, not the
			// level≤score bound (the 0.3/high case above is that one).
			func(p map[string]any) {
				s0 := p["secrets"].([]any)[0].(map[string]any)
				s0["score"] = 0.9
				s0["level"] = "high"
				s0["factors"] = []any{
					map[string]any{"name": "pattern", "weight": 0.9},
					map[string]any{"name": "entropy", "weight": 0.35},
				}
			},
			"outranks the gated level",
			nil,
		},
		{
			"invented pair factor",
			// The original score rides on the original factor list; a
			// fabricated "pair" factor with a valid weight recomposes to a
			// different score — caught by the composition check, not by the
			// weight or cap checks (adding factors only loosens the cap).
			func(p map[string]any) {
				s0 := p["secrets"].([]any)[0].(map[string]any)
				s0["factors"] = append(s0["factors"].([]any),
					map[string]any{"name": "pair", "weight": 0.45})
			},
			"does not match the recomposed score",
			nil,
		},
		{
			"truncated as completed",
			func(p map[string]any) {
				p["truncated"] = true
			},
			"claims truncation",
			nil,
		},
		{
			"unknown family",
			func(p map[string]any) {
				p["secrets"].([]any)[0].(map[string]any)["family"] = "royal"
			},
			"unknown family",
			nil,
		},
		{
			"bad factor weight",
			func(p map[string]any) {
				s := p["secrets"].([]any)[0].(map[string]any)
				s["factors"].([]any)[0].(map[string]any)["weight"] = 2.0
			},
			"invalid factor",
			nil,
		},
		{
			"empty pattern IDs",
			func(p map[string]any) {
				p["secrets"].([]any)[0].(map[string]any)["pattern_ids"] = []any{}
			},
			"no pattern IDs",
			nil,
		},
		{
			"missing evidence link",
			func(p map[string]any) {
				p["secrets"].([]any)[0].(map[string]any)["evidence_ids"] = []string{"secret:bogus/value/x"}
			},
			"missing evidence",
			nil,
		},
		{
			"wrong candidate source",
			func(p map[string]any) {
				p["candidate_source"] = map[string]any{"kind": "host", "value": "evil.example.com"}
			},
			"candidate source",
			nil,
		},
		{
			"analysis version mismatch",
			func(p map[string]any) {
				p["version"] = analysisVersion + 1
			},
			"analysis version",
			nil,
		},
		{
			"duplicated candidate",
			func(p map[string]any) {
				p["secrets"] = append(p["secrets"].([]any), p["secrets"].([]any)[0])
			},
			"duplicates",
			nil,
		},
		{
			"capped S3 score escapes the URL type cap",
			func(p map[string]any) {
				// Internally consistent (score in [0,1], level matches the
				// score, weights valid) but the pure-endpoint URL cap
				// contract says the current engine could never produce
				// this: caught by the cap re-derivation, not the bounds.
				s0 := s3secret(t, p)
				s0["score"] = 0.99
				s0["level"] = "high"
				dropURLCapFactor(s0)
			},
			"exceeds the derived cap",
			&s3Doc,
		},
		{
			"cap-eligible S3 type missing its url_type_cap marker",
			func(p map[string]any) {
				// Score intact and within the cap; only the weight-0 marker
				// factor is dropped: the marker must be present exactly
				// when the type is capped.
				dropURLCapFactor(s3secret(t, p))
			},
			"url_type_cap factor missing",
			&s3Doc,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fs := openTestCache(t)
			use := doc
			if tt.altDoc != nil {
				use = *tt.altDoc
			}
			sd, _, key := scanOnce(t, fs, use)
			rec := tamper(t, fs, key, tt.mutate)
			_, err := decodeStoredScan(rec, sd, defaultScanLimits())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("tamper %q must be rejected with %q, got %v", tt.name, tt.want, err)
			}
		})
	}
}

// s3secret returns the stored S3 candidate inside a tampered payload,
// looked up by type so the mutation never depends on candidate ordering.
func s3secret(t *testing.T, p map[string]any) map[string]any {
	t.Helper()
	for _, s := range p["secrets"].([]any) {
		m := s.(map[string]any)
		if m["candidate"].(map[string]any)["type"] == string(asset.SecretTypeS3) {
			return m
		}
	}
	t.Fatal("tamper payload carries no S3 candidate")
	return nil
}

// dropURLCapFactor removes the weight-0 url_type_cap marker factor from one
// stored secret (the "silently dropped cap" tamper class).
func dropURLCapFactor(s0 map[string]any) {
	fac := s0["factors"].([]any)
	kept := make([]any, 0, len(fac))
	for _, f := range fac {
		if f.(map[string]any)["name"] != "url_type_cap" {
			kept = append(kept, f)
		}
	}
	s0["factors"] = kept
}

func TestRecordEnvelopeValidation(t *testing.T) {
	fs := openTestCache(t)
	doc := Document{Kind: KindJS, Content: []byte("k=" + awsKeyID)}
	sd, _, key := scanOnce(t, fs, doc)
	out := fs.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatal("expected hit")
	}

	bad := *out.Record
	bad.Status = cache.StatusIncomplete
	if _, err := decodeStoredScan(bad, sd, defaultScanLimits()); err == nil {
		t.Error("incomplete status must be rejected")
	}

	bad = *out.Record
	bad.Operation = "other.op"
	if _, err := decodeStoredScan(bad, sd, defaultScanLimits()); err == nil {
		t.Error("wrong operation must be rejected")
	}

	bad = *out.Record
	bad.Target = "document:deadbeef"
	if _, err := decodeStoredScan(bad, sd, defaultScanLimits()); err == nil {
		t.Error("mismatched target must be rejected")
	}

	bad = *out.Record
	bad.Data = nil
	if _, err := decodeStoredScan(bad, sd, defaultScanLimits()); err == nil {
		t.Error("empty payload must be rejected")
	}

	// A record written for a DIFFERENT document is rejected against this
	// one (identity containment).
	other, _, _ := scanOnce(t, fs, Document{Kind: KindEnv, Content: []byte("A=1\nk=" + awsKeyID)})
	if _, err := decodeStoredScan(*out.Record, other, defaultScanLimits()); err == nil {
		t.Error("a record must only decode for its own document")
	}
}

func TestRecordTruncatedStoredIncomplete(t *testing.T) {
	fs := openTestCache(t)
	big := Document{Kind: KindJS, Content: make([]byte, MaxDocumentBytes+16)}
	for i := range big.Content {
		big.Content[i] = byte('a' + i%26)
	}
	sd, entry, key := scanOnce(t, fs, big)

	if entry.Status != StatusIncomplete {
		t.Fatalf("truncated entry status = %s, want incomplete", entry.Status)
	}
	out := fs.Get(context.Background(), key)
	if out.State != cache.StateIncomplete {
		t.Fatalf("truncated record state = %s, want incomplete (never a hit)", out.State)
	}

	// Even if the status is hand-forced to completed, decode rejects the
	// truncated-as-completed tamper class.
	rec := *out.Record
	rec.Status = cache.StatusCompleted
	if _, err := decodeStoredScan(rec, sd, defaultScanLimits()); err == nil {
		t.Error("truncated-as-completed must be rejected on decode")
	}
}

func TestRecordKeyCoversResultRelevantInputs(t *testing.T) {
	fs := openTestCache(t)
	base := Document{Kind: KindJS, Content: []byte("k=" + awsKeyID)}

	k1, err1 := func() (cache.Key, error) {
		sd, _, _ := scanOnce(t, fs, base)
		return secretKey(sd, loadDB(t).Version())
	}()
	if err1 != nil {
		t.Fatal(err1)
	}

	variants := []Document{
		{Kind: KindJSON, Content: []byte("k=" + awsKeyID)}, // kind
		{Kind: KindJS, Content: []byte("k2=" + awsKeyID)},  // content
		{Kind: KindJS, Content: []byte("k=" + awsKeyID), Filename: "other.js"},
		{Kind: KindJS, Content: []byte("k=" + awsKeyID), Technology: []string{"aws"}},
		{Kind: KindJS, Content: []byte("k=" + awsKeyID), Hostname: "h.example.com"},
		{Kind: KindJS, Content: []byte("k=" + awsKeyID), Source: "wayback"}, // provenance source
	}
	for i, v := range variants {
		sd, _, key := scanOnce(t, fs, v)
		_ = sd
		if key == k1 {
			t.Errorf("variant %d must derive a different cache key", i)
		}
	}
	_ = time.Now
}

// TestIngestCrossSourceNeverSharesCache pins the provenance-source contract:
// the Source field enters the scan identity and cache key, so two ingests of
// the SAME content under different provenance sources never share a cache
// record — the second is a fresh scan attributed to its own source, and the
// first record decodes only under the identity that wrote it.
func TestIngestCrossSourceNeverSharesCache(t *testing.T) {
	fs := openTestCache(t)
	clock := newFakeClock()
	doc := func(src string) Document {
		return Document{Kind: KindJS, Content: []byte("k=" + awsKeyID), Filename: "app.js", Source: src}
	}

	cfg := baseCfg()
	cfg.Clock = clock
	cfg.Cache = fs
	var mu sync.Mutex
	var entries []ReportEntry
	cfg.Emit = func(ctx context.Context, d DocumentRef, e ReportEntry) error {
		mu.Lock()
		entries = append(entries, e)
		mu.Unlock()
		return nil
	}

	var m1, m2 Metrics
	cfg.Metrics = &m1
	rep1, err := Ingest(context.Background(), cfg, sliceSource([]Document{doc("wayback")}))
	if err != nil {
		t.Fatal(err)
	}
	if s := m1.Snapshot(); s.Scanned != 1 || s.Stored != 1 {
		t.Fatalf("first run must scan and store exactly once: %+v", s)
	}
	if len(rep1.Secrets) != 1 || len(rep1.Secrets[0].Sources) != 1 || rep1.Secrets[0].Sources[0] != "wayback" {
		t.Fatalf("first-run secrets/sources = %+v", rep1.Secrets)
	}

	// Same content + filename, different provenance source: a cache MISS by
	// construction, scanned fresh, attributed to the new source.
	cfg.Metrics = &m2
	rep2, err := Ingest(context.Background(), cfg, sliceSource([]Document{doc("gau")}))
	if err != nil {
		t.Fatal(err)
	}
	if s := m2.Snapshot(); s.Scanned != 1 || s.Stored != 1 {
		t.Fatalf("second run must NOT hit the first run's record: %+v", s)
	}
	if len(rep2.Secrets) != 1 || len(rep2.Secrets[0].Sources) != 1 || rep2.Secrets[0].Sources[0] != "gau" {
		t.Fatalf("second-run secrets/sources = %+v", rep2.Secrets)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(entries) != 2 {
		t.Fatalf("emit entries = %d, want 2", len(entries))
	}
	if entries[0].Cached || len(entries[0].Sources) != 1 || entries[0].Sources[0] != "wayback" {
		t.Errorf("entry 0 sources/cached = %v/%v, want [wayback]/false", entries[0].Sources, entries[0].Cached)
	}
	if entries[1].Cached || len(entries[1].Sources) != 1 || entries[1].Sources[0] != "gau" {
		t.Errorf("entry 1 sources/cached = %v/%v, want [gau]/false", entries[1].Sources, entries[1].Cached)
	}

	// The first record still exists under its own identity and decodes
	// there; it is rejected under the other source's identity (target
	// mismatch) — the identity containment holds per source.
	sdWB, _, keyWB := scanOnce(t, fs, doc("wayback"))
	out := fs.Get(context.Background(), keyWB)
	if !out.IsHit() {
		t.Fatalf("first run's record must remain readable under its own source: %s", out.State)
	}
	if _, err := decodeStoredScan(*out.Record, sdWB, defaultScanLimits()); err != nil {
		t.Errorf("decode under the owning source: %v", err)
	}
	sdGAU, _, _ := scanOnce(t, fs, doc("gau"))
	if _, err := decodeStoredScan(*out.Record, sdGAU, defaultScanLimits()); err == nil {
		t.Error("the other source's identity must not decode the record")
	}
}
