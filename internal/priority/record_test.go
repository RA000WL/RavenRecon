package priority

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

func keySignal() Signal {
	return Signal{
		Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/api/v2/admin"},
		Kind:     asset.KindURL,
		Path:     "/api/v2/admin",
		Hostname: "www.example.com",
		Technologies: []TechSignal{
			{Name: "auth0", Category: "authentication", Confidence: 0.9, Identity: "authentication/auth0"},
		},
		Secrets: []SecretSignal{
			{Type: asset.SecretTypeAWS, Confidence: 0.8, Identity: "secret_candidate:aws/x/y"},
		},
		ParameterNames: []string{"query"},
		Headers:        []string{"x-powered-by: express"},
		Port:           8080,
		Service:        "grafana",
		Observations:   2,
		FirstSeen:      fixedTime(10),
		ScoredAt:       fixedTime(20),
	}
}

// TestPriorityKeyComponents pins the cache-key contract: the key contains
// the operation, the priority schema version, the catalog digest, and the
// FULL asset fingerprint — every score-material field change produces a
// different key, while the result-metadata timestamps deliberately do
// not.
func TestPriorityKeyComponents(t *testing.T) {
	ic, rc := mustCatalogs(t)
	digest := CatalogsDigest(ic, rc)
	base := keySignal()
	baseKey, err := priorityKey(base, digest)
	if err != nil {
		t.Fatal(err)
	}
	again, err := priorityKey(base, digest)
	if err != nil {
		t.Fatal(err)
	}
	if baseKey != again {
		t.Error("key must be stable across computations")
	}
	if string(baseKey) != string(mustKey(t, cache.KeyParts{
		Operation: "priority.score",
		Target:    base.Identity.String(),
		Config: map[string]string{
			"schema":   "1",
			"catalogs": digest,
			"asset":    mustFingerprint(t, base),
		},
	})) {
		t.Error("key must be exactly the documented component composition")
	}

	mutations := map[string]func(*Signal){
		"identity": func(s *Signal) { s.Identity.Value = "https://www.example.com/api/v2/other" },
		"kind": func(s *Signal) {
			s.Kind = asset.KindEndpoint
			s.Identity.Kind = asset.KindEndpoint
			s.Identity.Value = "GET https://www.example.com/api/v2/admin"
		},
		"path":              func(s *Signal) { s.Path = "/api/v2/user" },
		"hostname":          func(s *Signal) { s.Hostname = "api.example.com" },
		"endpoint method":   func(s *Signal) { s.EndpointMethod = "WS" },
		"parameter added":   func(s *Signal) { s.ParameterNames = []string{"query", "file"} },
		"parameter order":   func(s *Signal) { s.ParameterNames = []string{"file", "query"} },
		"js bundle bytes":   func(s *Signal) { s.JSBundleBytes = 1 << 20 },
		"tech name":         func(s *Signal) { s.Technologies[0].Name = "okta" },
		"tech category":     func(s *Signal) { s.Technologies[0].Category = "cloud_provider" },
		"tech confidence":   func(s *Signal) { s.Technologies[0].Confidence = 0.4 },
		"tech identity":     func(s *Signal) { s.Technologies[0].Identity = "authentication/okta" },
		"secret type":       func(s *Signal) { s.Secrets[0].Type = asset.SecretTypeJWT },
		"secret confidence": func(s *Signal) { s.Secrets[0].Confidence = 0.3 },
		"port":              func(s *Signal) { s.Port = 9090 },
		"service":           func(s *Signal) { s.Service = "kibana" },
		"headers":           func(s *Signal) { s.Headers = []string{"x-runtime: 0.1"} },
		"observations":      func(s *Signal) { s.Observations = 5 },
	}
	for name, mutate := range mutations {
		s := keySignal()
		mutate(&s)
		k, err := priorityKey(s, digest)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k == baseKey {
			t.Errorf("key must change on a %s change", name)
		}
	}

	// Timestamps are result metadata, not score inputs: they must NOT
	// change the key (they are stored verbatim, TTL uses CreatedAt).
	for name, mutate := range map[string]func(*Signal){
		"first_seen": func(s *Signal) { s.FirstSeen = fixedTime(99) },
		"scored_at":  func(s *Signal) { s.ScoredAt = fixedTime(99) },
	} {
		s := keySignal()
		mutate(&s)
		if k, err := priorityKey(s, digest); err != nil || k != baseKey {
			t.Errorf("%s must not change the key (got %v, err %v)", name, k, err)
		}
	}

	// ANY catalog edit changes the digest and therefore every key.
	mutated := Indicator{
		ID: "m", Category: "extra", Weight: 0.1, Field: FieldPath,
		Terms: []string{"/zz"}, Reason: "extra %s", Recommendation: "review the path %s",
	}
	mIC, err := CompileForTest("interestingness", append(interestingnessTable(), mutated))
	if err != nil {
		t.Fatal(err)
	}
	mutDigest := CatalogsDigest(mIC, rc)
	if mutDigest == digest {
		t.Fatal("mutated catalog must change the digest")
	}
	if k, err := priorityKey(base, mutDigest); err != nil || k == baseKey {
		t.Errorf("a catalog edit must invalidate every cached key (err %v)", err)
	}
}

func mustKey(t *testing.T, parts cache.KeyParts) cache.Key {
	t.Helper()
	k, err := cache.NewKey(parts)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustFingerprint(t *testing.T, s Signal) string {
	t.Helper()
	fp, err := fingerprintSignal(s)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// TestStoredSurfaceRoundTrip pins the encode/decode contract: a scored
// surface survives the record round trip bit-for-bit when it satisfies the
// engine's own invariants.
func TestStoredSurfaceRoundTrip(t *testing.T) {
	ic, rc := mustCatalogs(t)
	sig := keySignal()
	sig.ScoredAt = fixedTime(20)
	surface, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000500, 0).UTC()
	rec, err := encodeStoredSurface(surface, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != cache.StatusCompleted || rec.Operation != Operation || rec.Target != sig.Identity.String() {
		t.Errorf("record envelope = %+v", rec)
	}
	if !rec.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want the store-time stamp", rec.CreatedAt)
	}
	got, err := decodeStoredSurface(rec, sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(*got, surface) {
		t.Errorf("round trip diverged:\n%+v\n%+v", *got, surface)
	}
}

// TestValidateSurfaceInvariants pins every strict decode rejection shape
// (each also gates the encode side, keeping the cache coherent).
func TestValidateSurfaceInvariants(t *testing.T) {
	ic, rc := mustCatalogs(t)
	sig := keySignal()
	base, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSurfaceInvariants(base, sig); err != nil {
		t.Fatalf("fresh surface must pass its own invariants: %v", err)
	}
	if len(base.Factors) < 3 {
		t.Fatal("fixture needs multiple factors")
	}

	mut := func(f func(*SurfaceAsset)) SurfaceAsset {
		s := base
		f(&s)
		return s
	}
	shapes := []struct {
		name   string
		mutate func(*SurfaceAsset)
	}{
		{"zero identity", func(s *SurfaceAsset) { s.Identity = asset.Identity{} }},
		{"identity mismatch", func(s *SurfaceAsset) { s.Identity.Value = "https://other.example.com/x" }},
		{"kind mirror mismatch", func(s *SurfaceAsset) { s.Kind = asset.KindEndpoint }},
		{"unknown level", func(s *SurfaceAsset) { s.Level = PriorityLevel("ultra") }},
		{"nan score", func(s *SurfaceAsset) { s.Score = math.NaN() }},
		{"score over one", func(s *SurfaceAsset) { s.Score = 1.5 }},
		{"nan confidence", func(s *SurfaceAsset) { s.Confidence = math.NaN() }},
		{"score contradicts factors", func(s *SurfaceAsset) { s.Score = 0.0111 }},
		{"factor weight nan", func(s *SurfaceAsset) { s.Factors[0].Weight = math.NaN() }},
		{"factor list over bound", func(s *SurfaceAsset) {
			s.Factors = append(append([]Factor{}, s.Factors...), make([]Factor, maxFactors)...)
		}},
		{"truncated factor list", func(s *SurfaceAsset) { s.Factors = s.Factors[:1] }},
		{"indicator factor without recommendation", func(s *SurfaceAsset) {
			for i := range s.Factors {
				if s.Factors[i].Recommendation != "" {
					s.Factors[i].Recommendation = ""
					break
				}
			}
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			s := mut(shape.mutate)
			if err := validateSurfaceInvariants(s, sig); err == nil {
				t.Fatalf("%s must be rejected", shape.name)
			}
		})
	}

	// A level the stored factors could never produce: a single-category
	// surface (max medium) stored as high is tampering or a bug.
	single := Signal{
		Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/admin"},
		Kind:     asset.KindURL, Path: "/admin", ScoredAt: fixedTime(1),
	}
	singleSurface, err := ScoreSurface(single, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if singleSurface.Level != LevelMedium {
		t.Fatalf("fixture level = %s, want medium", singleSurface.Level)
	}
	tamperedLevel := singleSurface
	tamperedLevel.Level = LevelHigh
	if err := validateSurfaceInvariants(tamperedLevel, single); err == nil {
		t.Error("a high level on a single-category medium surface must be rejected")
	}

	// A confidence factor must not carry a recommendation.
	withConf := base
	for i := range withConf.Factors {
		if withConf.Factors[i].Name == "confidence:technology" {
			withConf.Factors[i].Recommendation = "review this technology observation"
			break
		}
	}
	if err := validateSurfaceInvariants(withConf, sig); err == nil {
		t.Error("confidence factor with a recommendation must be rejected")
	}
}

// TestValidateCanonicalIdentity pins the identity parseability checks per
// kind — the decode seam demands canonically parseable identities, and the
// builders must round-trip to the same identity.
func TestValidateCanonicalIdentity(t *testing.T) {
	valid := []asset.Identity{
		{Kind: asset.KindURL, Value: "https://www.example.com/a?x=1"},
		{Kind: asset.KindEndpoint, Value: "GET https://www.example.com/a"},
		{Kind: asset.KindHost, Value: "api.example.com"},
		{Kind: asset.KindDomain, Value: "example.com"},
		{Kind: asset.KindIP, Value: "192.0.2.10"},
		{Kind: asset.KindIP, Value: "2001:db8::1"},
		{Kind: asset.KindJavaScript, Value: "https://www.example.com/bundle.js"},
		{Kind: asset.KindSourceMap, Value: "https://www.example.com/bundle.js.map"},
		{Kind: asset.KindPort, Value: "tcp/8080"},
	}
	for _, id := range valid {
		if err := validateCanonicalIdentity(id); err != nil {
			t.Errorf("identity %s must validate: %v", id, err)
		}
	}
	invalid := []asset.Identity{
		{Kind: asset.KindURL, Value: "not a url"},
		{Kind: asset.KindURL, Value: "https://www.EXAMPLE.com./a"},     // non-canonical casing/dot
		{Kind: asset.KindEndpoint, Value: "https://www.example.com/a"}, // no method
		{Kind: asset.KindEndpoint, Value: "GET not a url"},
		{Kind: asset.KindHost, Value: "192.0.2.10"},       // IP literal is not a host
		{Kind: asset.KindHost, Value: "api..example.com"}, // empty label
		{Kind: asset.KindDomain, Value: "not a domain"},
		{Kind: asset.KindIP, Value: "not-an-ip"},
		{Kind: asset.KindJavaScript, Value: "not a url"},
		{Kind: asset.KindSourceMap, Value: "not a url"},
		{Kind: asset.KindPort, Value: ""},
	}
	for _, id := range invalid {
		if err := validateCanonicalIdentity(id); err == nil {
			t.Errorf("identity %s must be rejected", id)
		}
	}
}
