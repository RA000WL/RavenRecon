package secrentel

import (
	"encoding/base64"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// mintJWT builds a structurally valid JWT ({"alg":"HS256"} header, the
// given payload JSON, fixed signature) for expiry tests. Payloads use
// epoch-edge "exp" values (1 / 9999999999) so the expired/valid reading
// stays deterministic for decades without clock injection.
func mintJWT(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".c2lnbmF0dXJl"
}

func TestJWTExpiryState(t *testing.T) {
	expired := mintJWT(t, `{"sub":"1234567890","exp":1}`)
	valid := mintJWT(t, `{"sub":"1234567890","exp":9999999999}`)
	noExp := mintJWT(t, `{"sub":"1234567890"}`)
	strExp := mintJWT(t, `{"sub":"1234567890","exp":"tomorrow"}`)

	if st, ok := jwtExpiryState(expired); !ok || st != jwtExpiryExpired {
		t.Errorf("exp=1: state = %v, ok = %v; want expired, true", st, ok)
	}
	if st, ok := jwtExpiryState(valid); !ok || st != jwtExpiryValid {
		t.Errorf("exp=9999999999: state = %v, ok = %v; want valid, true", st, ok)
	}
	for name, tok := range map[string]string{
		"no exp claim":    noExp,
		"string exp":      strExp,
		"two segments":    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		"bad payload b64": "eyJhbGciOiJIUzI1NiJ9.%%%.c2lnbmF0dXJl",
		"empty":           "",
	} {
		if st, ok := jwtExpiryState(tok); ok || st != jwtExpiryNone {
			t.Errorf("%s: state = %v, ok = %v; want none, false", name, st, ok)
		}
	}
	if isJWTExpired(valid) || isJWTExpired(noExp) {
		t.Error("valid and exp-less tokens must not read as expired")
	}
	if !isJWTExpired(expired) {
		t.Error("exp=1 token must read as expired")
	}
}

func TestJWTExpiryConfidenceCap(t *testing.T) {
	expired := mintJWT(t, `{"sub":"1234567890","exp":1}`)
	valid := mintJWT(t, `{"sub":"1234567890","exp":9999999999}`)

	strong := func(value string) confidenceInput {
		return confidenceInput{
			Strength: 0.9, Family: "structured", Type: asset.SecretTypeJWT, Value: value,
			EntropyOK: true, EntropyHit: true,
			Context:  Context{NameHint: "jwt"},
			TechHit:  "x",
			Endpoint: "https://api.example.com/token",
		}
	}

	// An expired JWT with strong multi-evidence support is labeled and
	// capped at Low: expired tokens prove history, not live access.
	c := deriveConfidence(strong(expired))
	if !hasFactor(c, "jwt_expired") {
		t.Errorf("expired JWT must carry the jwt_expired factor: %+v", c.Factors)
	}
	for _, f := range c.Factors {
		if f.Name == "jwt_expired" && f.Weight != 0 {
			t.Errorf("jwt_expired must weigh 0, got %v", f.Weight)
		}
	}
	if c.Score > expiredJWTCap {
		t.Errorf("expired JWT score = %v, want <= %v", c.Score, expiredJWTCap)
	}
	if c.Level.rank() > LevelLow.rank() {
		t.Errorf("expired JWT level = %s, want <= low", c.Level)
	}
	if got := countNonPattern(c.Factors); got != 4 {
		t.Errorf("countNonPattern = %d, want 4 (entropy/context/technology/endpoint; pattern and jwt_expired excluded)", got)
	}

	// The cap survives pair/repeat recomputation: the marker rides the
	// stored factor list, so boosted scores still clamp.
	paired := applyPairFactor(c, asset.SecretTypeJWT, "structured", nil)
	if paired.Score > expiredJWTCap {
		t.Errorf("pair-boosted expired JWT score = %v, want <= %v", paired.Score, expiredJWTCap)
	}
	if !hasFactor(paired, "jwt_expired") {
		t.Error("pair recompute must retain the jwt_expired marker")
	}
	repeated := applyRepeatFactor(paired, asset.SecretTypeJWT, "structured", nil)
	if repeated.Score > expiredJWTCap {
		t.Errorf("repeat-boosted expired JWT score = %v, want <= %v", repeated.Score, expiredJWTCap)
	}

	// A valid JWT with identical evidence is untouched: no marker, High.
	v := deriveConfidence(strong(valid))
	if hasFactor(v, "jwt_expired") {
		t.Errorf("valid JWT must not carry jwt_expired: %+v", v.Factors)
	}
	if v.Level != LevelHigh {
		t.Errorf("valid multi-evidence JWT should be High, got %s (%v): %+v", v.Level, v.Score, v.Factors)
	}
	if v.Score <= expiredJWTCap {
		t.Errorf("valid JWT score = %v, want above the expired cap %v", v.Score, expiredJWTCap)
	}

	// An exp-less JWT behaves exactly as before (no marker either).
	bare := deriveConfidence(strong(mintJWT(t, `{"sub":"1234567890"}`)))
	if hasFactor(bare, "jwt_expired") {
		t.Errorf("exp-less JWT must not carry jwt_expired: %+v", bare.Factors)
	}
	if bare.Score != v.Score || bare.Level != v.Level {
		t.Errorf("exp-less JWT (%v/%s) must score exactly like a valid one (%v/%s)",
			bare.Score, bare.Level, v.Score, v.Level)
	}

	// The expiry read is type-gated: a non-JWT candidate carrying a
	// JWT-shaped value earns no marker.
	other := strong(expired)
	other.Type = asset.SecretTypeGitHub
	if o := deriveConfidence(other); hasFactor(o, "jwt_expired") {
		t.Errorf("non-JWT type must not carry jwt_expired: %+v", o.Factors)
	}
}

func TestJWTExpiryScanLabelsExpired(t *testing.T) {
	expired := mintJWT(t, `{"sub":"1234567890","exp":1}`)
	valid := mintJWT(t, `{"sub":"1234567890","exp":9999999999}`)

	// Expired JWT: kept (shape is valid), labeled, and capped at Low.
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte(`var token="` + expired + `";`)})
	c := findByValue(out, "eyJ")
	if c == nil {
		t.Fatalf("expired JWT must be kept: %+v", out.counts)
	}
	if !hasFactor(c.confidence, "jwt_expired") {
		t.Errorf("scanned expired JWT must carry jwt_expired: %+v", c.confidence.Factors)
	}
	if c.confidence.Score > expiredJWTCap {
		t.Errorf("scanned expired JWT score = %v, want <= %v", c.confidence.Score, expiredJWTCap)
	}
	if c.confidence.Level.rank() > LevelLow.rank() {
		t.Errorf("scanned expired JWT level = %s, want <= low", c.confidence.Level)
	}

	// Valid JWT: kept with unchanged behavior (no marker).
	_, out = scanOf(t, Document{Kind: KindJS, Content: []byte(`var token="` + valid + `";`)})
	c = findByValue(out, "eyJ")
	if c == nil {
		t.Fatalf("valid JWT must be kept: %+v", out.counts)
	}
	if hasFactor(c.confidence, "jwt_expired") {
		t.Errorf("scanned valid JWT must not carry jwt_expired: %+v", c.confidence.Factors)
	}

	// Malformed JWT: still dropped by the structural validator, unchanged.
	bad := "eyJmb28iOiJiYXIifQ" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + detRand(20, alnumMixed, 7, 1)
	_, out = scanOf(t, Document{Kind: KindJS, Content: []byte("t('" + bad + "')")})
	if len(out.candidates) != 0 {
		t.Errorf("malformed JWT must be dropped, got %+v", out.candidates)
	}
	if out.counts.DroppedValidator != 1 {
		t.Errorf("DroppedValidator = %d, want 1", out.counts.DroppedValidator)
	}
}
