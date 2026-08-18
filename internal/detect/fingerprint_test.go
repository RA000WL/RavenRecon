package detect

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// fingerprintBaseSnapshot returns a canonical snapshot carrying every
// fingerprintable domain — one JavaScript asset with EVERY observation
// field set, plus evidence, technology, secret candidate, and endpoint
// records with distinct provenance values — so that a mutation of any
// single covered field is observable in the fingerprint. All provenance
// timestamps are pinned to the same constant: they must never enter the
// fingerprint.
func fingerprintBaseSnapshot(t testing.TB) Snapshot {
	t.Helper()
	u, err := asset.ParseURL(testSubjectURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	host, err := asset.NewHost("example.com", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	at := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	js, err := asset.NewJavaScript("https://example.com/app.js", asset.Provenance{
		Source: "js-src", Reference: "js-ref", Confidence: 0.8, DiscoveredAt: at,
	})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	js.Hash = "legacy-hash-a"
	must := func(j asset.JavaScript, err error) asset.JavaScript {
		t.Helper()
		if err != nil {
			t.Fatalf("build javascript observation: %v", err)
		}
		return j
	}
	js = must(asset.WithHost(js, "cdn.example.com"))
	js = must(asset.WithContentHash(js, strings.Repeat("a", 64)))
	js = must(asset.WithSize(js, 4096))
	js = must(asset.WithContentType(js, "application/javascript"))
	js = must(asset.WithETag(js, `"abc"`))
	js = must(asset.WithLastModified(js, at.Add(-time.Hour)))
	js = must(asset.WithDiscoverySource(js, "html-scan"))
	js = must(asset.WithStatusCode(js, 200))
	js = must(asset.WithFinalURL(js, "https://cdn.example.com/app.js"))

	ev, err := asset.NewEvidence(asset.MethodHeader, "server", "nginx", u.Identity(), asset.Provenance{
		Source: "ev-src", Reference: "ev-ref", Confidence: 0.7, DiscoveredAt: at,
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	tech, err := asset.NewTechnology("nginx", "server", asset.Provenance{
		Source: "tech-src", Reference: "tech-ref", Confidence: 0.6, DiscoveredAt: at,
	})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeAPIKey, "sk-test-0123456789abcdef0123456789abcdef", u.Identity(), asset.Provenance{
		Source: "sec-src", Reference: "sec-ref", Confidence: 0.9, DiscoveredAt: at,
	})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	endp, err := asset.NewEndpoint("GET", testSubjectURL, asset.Provenance{
		Source: "endp-src", Reference: "endp-ref", Confidence: 0.5, DiscoveredAt: at,
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}

	return Snapshot{
		Assets:       []asset.Identity{u.Identity(), host.Identity()},
		Evidence:     []asset.Evidence{ev},
		Technologies: []asset.Technology{tech},
		Secrets:      []asset.SecretCandidate{sec},
		JavaScript:   []asset.JavaScript{js},
		Endpoints:    []asset.Endpoint{endp},
	}
}

// copyFingerprintSnapshot deep-copies every slice of s so a mutation in one
// test case can never leak into the next.
func copyFingerprintSnapshot(s Snapshot) Snapshot {
	c := s
	c.Assets = append([]asset.Identity(nil), s.Assets...)
	c.Relationships = append([]asset.Relationship(nil), s.Relationships...)
	c.Evidence = append([]asset.Evidence(nil), s.Evidence...)
	c.Technologies = append([]asset.Technology(nil), s.Technologies...)
	c.Secrets = append([]asset.SecretCandidate(nil), s.Secrets...)
	c.JavaScript = append([]asset.JavaScript(nil), s.JavaScript...)
	c.Endpoints = append([]asset.Endpoint(nil), s.Endpoints...)
	return c
}

func fingerprintOf(t testing.TB, s Snapshot) string {
	t.Helper()
	corpus, err := normalizeSnapshot(s)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fp, err := fingerprintSnapshot(corpus)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	return fp
}

func ruleKeyOf(t testing.TB, r Rule, fp string) cache.Key {
	t.Helper()
	key, err := ruleKey(r, fp, nil)
	if err != nil {
		t.Fatalf("ruleKey: %v", err)
	}
	return key
}

// TestFingerprintCoversObservableFields pins M-7: the snapshot fingerprint
// must cover EVERY observable field a rule can read through the Context, so
// two corpora differing in exactly one such field can never share a cached
// rule result. Before the fix, fingerprintScript covered only identity,
// content hash, size, reference, and confidence — a snapshot whose observed
// status code, final redirect URL, content type, ETag, last-modified,
// discovery source, or host differed from a cached observation was served
// the older rule findings.
func TestFingerprintCoversObservableFields(t *testing.T) {
	rule := makeRule(t, "a.b", nil)
	base := fingerprintBaseSnapshot(t)
	baseFP := fingerprintOf(t, base)
	baseKey := ruleKeyOf(t, rule, baseFP)

	altFinalURL, err := asset.ParseURL("https://cdn2.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	altHost, err := asset.NewHost("cdn2.example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"javascript host", func(s *Snapshot) { s.JavaScript[0].Host = altHost }},
		{"javascript legacy hash", func(s *Snapshot) { s.JavaScript[0].Hash = "legacy-hash-b" }},
		{"javascript content hash", func(s *Snapshot) { s.JavaScript[0].ContentHash = strings.Repeat("b", 64) }},
		{"javascript size", func(s *Snapshot) { s.JavaScript[0].Size = 4097 }},
		{"javascript content type", func(s *Snapshot) { s.JavaScript[0].ContentType = "text/javascript" }},
		{"javascript etag", func(s *Snapshot) { s.JavaScript[0].ETag = `"def"` }},
		{"javascript last modified", func(s *Snapshot) {
			s.JavaScript[0].LastModified = s.JavaScript[0].LastModified.Add(time.Hour)
		}},
		{"javascript discovery source", func(s *Snapshot) { s.JavaScript[0].DiscoverySource = "tool-adapter" }},
		{"javascript status code", func(s *Snapshot) { s.JavaScript[0].StatusCode = 404 }},
		{"javascript final url", func(s *Snapshot) { s.JavaScript[0].FinalURL = altFinalURL }},
		{"javascript provenance source", func(s *Snapshot) { s.JavaScript[0].Prov.Source = "js-src-2" }},
		{"javascript provenance reference", func(s *Snapshot) { s.JavaScript[0].Prov.Reference = "js-ref-2" }},
		{"javascript provenance confidence", func(s *Snapshot) { s.JavaScript[0].Prov.Confidence = 0.3 }},
		{"evidence provenance source", func(s *Snapshot) { s.Evidence[0].Prov.Source = "ev-src-2" }},
		{"endpoint provenance source", func(s *Snapshot) { s.Endpoints[0].Prov.Source = "endp-src-2" }},
		{"secret provenance reference", func(s *Snapshot) { s.Secrets[0].Prov.Reference = "sec-ref-2" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := copyFingerprintSnapshot(base)
			tc.mutate(&v)
			fp := fingerprintOf(t, v)
			if fp == baseFP {
				t.Fatalf("fingerprint must change when only %s differs", tc.name)
			}
			key := ruleKeyOf(t, rule, fp)
			if key == baseKey {
				t.Fatalf("rule key must change when only %s differs", tc.name)
			}
		})
	}
}

// TestFingerprintExcludesProvenanceTimestamps pins the documented exclusion
// (record.go rationale): DiscoveredAt changes every run while producing
// identical findings, so it must never enter the fingerprint — for the
// JavaScript asset just like every other provenance-bearing domain.
func TestFingerprintExcludesProvenanceTimestamps(t *testing.T) {
	rule := makeRule(t, "a.b", nil)
	base := fingerprintBaseSnapshot(t)
	baseFP := fingerprintOf(t, base)
	baseKey := ruleKeyOf(t, rule, baseFP)

	v := copyFingerprintSnapshot(base)
	v.Evidence[0].Prov.DiscoveredAt = v.Evidence[0].Prov.DiscoveredAt.Add(2 * time.Hour)
	v.Technologies[0].Prov.DiscoveredAt = v.Technologies[0].Prov.DiscoveredAt.Add(3 * time.Hour)
	v.Secrets[0].Prov.DiscoveredAt = v.Secrets[0].Prov.DiscoveredAt.Add(4 * time.Hour)
	v.JavaScript[0].Prov.DiscoveredAt = v.JavaScript[0].Prov.DiscoveredAt.Add(5 * time.Hour)
	v.Endpoints[0].Prov.DiscoveredAt = v.Endpoints[0].Prov.DiscoveredAt.Add(6 * time.Hour)
	fp := fingerprintOf(t, v)
	if fp != baseFP {
		t.Fatalf("provenance timestamps must not change the fingerprint")
	}
	key := ruleKeyOf(t, rule, fp)
	if key != baseKey {
		t.Fatalf("provenance timestamps must not change the key")
	}
}

// TestRunJavaScriptObservationInvalidatesCache pins the M-7 scenario
// end-to-end: two runs whose snapshots differ ONLY in an observed script
// status code must not share a cached rule result — the second must execute
// fresh, never be served the first observation's findings.
func TestRunJavaScriptObservationInvalidatesCache(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	var executions int32
	det := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		atomic.AddInt32(&executions, 1)
		f, err := testFinding(dctx, "a.x", "Rule a.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}
	reg := newTestRegistry(t, makeRule(t, "a.x", &ruleOptions{detector: det}))
	base := fingerprintBaseSnapshot(t)
	run := func(v Snapshot) {
		cfg := DefaultEngineConfig(reg)
		cfg.Cache = fs
		if _, err := Run(context.Background(), cfg, v); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}

	run(base)
	run(base)
	if atomic.LoadInt32(&executions) != 1 {
		t.Fatalf("identical snapshots must hit the cache: %d executions", executions)
	}

	changed := copyFingerprintSnapshot(base)
	changed.JavaScript[0].StatusCode = 404
	run(changed)
	if atomic.LoadInt32(&executions) != 2 {
		t.Fatalf("a changed observed status code must invalidate the cached result: %d executions", executions)
	}
}
