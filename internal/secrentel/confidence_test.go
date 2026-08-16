package secrentel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

func TestDeriveConfidenceCapsAndGates(t *testing.T) {
	// A structured match with ZERO supporting factors: capped at
	// structuredCap (0.59) and gated to Medium.
	c := deriveConfidence(confidenceInput{Strength: 0.9, Family: "structured"})
	if c.Score > structuredCap {
		t.Errorf("lone structured score = %v, want <= %v", c.Score, structuredCap)
	}
	if c.Level == LevelHigh {
		t.Errorf("one signal can never be High: %+v", c)
	}
	if !hasFactor(c, "pattern") {
		t.Error("pattern factor must always be present")
	}

	// AWS key + secret + endpoint + context: evidence accumulates to High
	// (>= 2 non-pattern factors).
	c = deriveConfidence(confidenceInput{
		Strength: 0.75, Family: "structured", EntropyOK: true, EntropyHit: true,
		Context:  Context{NameHint: "provider", Variable: "awsSecret"},
		Endpoint: "s3.amazonaws.com",
	})
	if c.Level != LevelHigh {
		t.Errorf("multi-evidence AWS secret should be High, got %s (%v): %+v", c.Level, c.Score, c.Factors)
	}

	// Documentation context caps at Low regardless of everything else.
	c = deriveConfidence(confidenceInput{
		Strength: 0.9, Family: "structured", EntropyOK: true, EntropyHit: true,
		Context:  Context{NameHint: "provider"},
		Endpoint: "x", TechHit: "aws", Pair: true,
		FPFlags: []string{"context-marker:test"},
	})
	if c.Score > fpContextCap {
		t.Errorf("FP-context score = %v, want <= %v", c.Score, fpContextCap)
	}
	if c.Level.rank() > LevelLow.rank() {
		t.Errorf("FP-context level = %s, want <= low", c.Level)
	}

	// Generic family ("random base64") never exceeds Low.
	c = deriveConfidence(confidenceInput{
		Strength: 0.35, Family: "generic", EntropyOK: true, EntropyHit: true,
		Context: Context{Variable: "secret"}, TechHit: "x", Endpoint: "y",
	})
	if c.Score > genericCap || c.Level.rank() > LevelLow.rank() {
		t.Errorf("generic family must cap at Low: score %v level %s", c.Score, c.Level)
	}

	// Public keys cap below Low threshold territory.
	c = deriveConfidence(confidenceInput{Strength: 0.3, Family: "public", EntropyOK: false})
	if c.Score > publicKeyCap {
		t.Errorf("public family score = %v, want <= %v", c.Score, publicKeyCap)
	}

	// Entropy alone (a lone generic pattern with entropy and nothing else)
	// stays at Low.
	c = deriveConfidence(confidenceInput{Strength: 0.35, Family: "generic", EntropyOK: true})
	if c.Level.rank() > LevelLow.rank() {
		t.Errorf("entropy alone must not exceed Low: %s", c.Level)
	}
}

func hasFactor(c ConfidenceResult, name string) bool {
	for _, f := range c.Factors {
		if f.Name == name {
			return true
		}
	}
	return false
}

func TestApplyPairAndRepeatFactors(t *testing.T) {
	base := deriveConfidence(confidenceInput{Strength: 0.9, Family: "structured", EntropyOK: true, EntropyHit: true})
	paired := applyPairFactor(base, asset.SecretTypeGitHub, "structured", nil)
	if paired.Score <= base.Score {
		t.Errorf("pair factor must raise the score: %v -> %v", base.Score, paired.Score)
	}
	if !hasFactor(paired, "pair") {
		t.Error("pair factor must be recorded")
	}
	// The pair factor is capped by the FP context flags when present.
	pairedFP := applyPairFactor(base, asset.SecretTypeGitHub, "structured", []string{"context-marker:test"})
	if pairedFP.Score > fpContextCap {
		t.Errorf("pair boost must respect the FP cap: %v", pairedFP.Score)
	}

	// Repeat: same recomputation discipline, monotone.
	rep := applyRepeatFactor(paired, asset.SecretTypeGitHub, "structured", nil)
	if rep.Score < paired.Score {
		t.Errorf("repeat factor must not lower the score: %v -> %v", paired.Score, rep.Score)
	}
	if !hasFactor(rep, "repeat") {
		t.Error("repeat factor must be recorded")
	}
	// The generic cap still applies on recompute.
	g := deriveConfidence(confidenceInput{Strength: 0.35, Family: "generic", EntropyOK: true})
	rg := applyRepeatFactor(g, asset.SecretTypeGitHub, "generic", nil)
	if rg.Score > genericCap {
		t.Errorf("repeat recompute must respect the generic cap: %v", rg.Score)
	}
}

func TestEndpointFactorSuppressedWhenInValue(t *testing.T) {
	// The endpoint indicator inside the candidate's OWN value is the
	// pattern's match material: counting it again as a correlation signal
	// would double-count. The factor fires only for outside evidence.
	inValue := deriveConfidence(confidenceInput{
		Strength: 0.35, Family: "structured",
		Type: asset.SecretTypeS3, Value: "https://my-bucket.s3.us-east-1.amazonaws.com/x",
		Endpoint: "amazonaws.com",
	})
	if hasFactor(inValue, "endpoint") {
		t.Errorf("endpoint factor must be suppressed when the value IS the endpoint: %+v", inValue.Factors)
	}
	outside := deriveConfidence(confidenceInput{
		Strength: 0.75, Family: "structured",
		Value: "AKIA" + strings.Repeat("A", 16), Endpoint: "amazonaws.com",
	})
	if !hasFactor(outside, "endpoint") {
		t.Errorf("endpoint factor must fire for outside evidence: %+v", outside.Factors)
	}
}

func TestURLCredentialsFactor(t *testing.T) {
	// A structured URL-shaped value with user:pass@ authority carries real
	// credential material: a dedicated factor, independent of the endpoint.
	c := deriveConfidence(confidenceInput{
		Strength: 0.85, Family: "structured",
		Type:  asset.SecretTypePostgreSQLURL,
		Value: "postgres://admin:hunter2@db.example.com:5432/prod",
	})
	if !hasFactor(c, "url_credentials") {
		t.Errorf("userinfo URL must earn url_credentials: %+v", c.Factors)
	}
	for _, f := range c.Factors {
		if f.Name == "url_credentials" && f.Weight != urlCredentialsWeight {
			t.Errorf("url_credentials weight = %v, want %v", f.Weight, urlCredentialsWeight)
		}
	}

	// Credential-less URL: no userinfo, no factor.
	none := deriveConfidence(confidenceInput{
		Strength: 0.7, Family: "contextual", Type: asset.SecretTypeDatabaseURL,
		Value: "postgres://db.example.com/prod",
	})
	if hasFactor(none, "url_credentials") {
		t.Errorf("credential-less URL must not earn url_credentials: %+v", none.Factors)
	}

	// Contextual family: the factor is reserved for structured shapes (the
	// database_url assignment family needs the clamp, not a boost).
	ctx := deriveConfidence(confidenceInput{
		Strength: 0.7, Family: "contextual", Type: asset.SecretTypeDatabaseURL,
		Value: "mysql://u:p@db.example.com/prod",
	})
	if hasFactor(ctx, "url_credentials") {
		t.Errorf("contextual family must not earn url_credentials: %+v", ctx.Factors)
	}
}

func TestURLTypeCapClampSurvivesRecompute(t *testing.T) {
	// A pure-endpoint URL shape with STRONG evidence is still capped at
	// Low by contract, and the url_type_cap factor records the clamp
	// honestly (weight 0: never evidence toward the gates).
	c := deriveConfidence(confidenceInput{
		Strength: 0.9, Family: "structured", Type: asset.SecretTypeS3,
		Value:   "https://my-bucket.s3.us-east-1.amazonaws.com/x",
		Context: Context{NameHint: "provider"}, Endpoint: "amazonaws.com", Pair: true,
	})
	if c.Score > urlTypeCap || c.Level.rank() > LevelLow.rank() {
		t.Errorf("endpoint URL shape must cap at Low: %s %.2f", c.Level, c.Score)
	}
	if !hasFactor(c, "url_type_cap") {
		t.Error("url_type_cap factor must be recorded")
	}
	for _, f := range c.Factors {
		if f.Name == "url_type_cap" && f.Weight != 0 {
			t.Errorf("url_type_cap must weigh 0, got %v", f.Weight)
		}
	}

	// The clamp survives the pair and repeat recomputes (the exact
	// overreach class being fixed: a pair-boosted bucket must not escape).
	paired := applyPairFactor(c, asset.SecretTypeS3, string(patterns.FamilyStructured), nil)
	if paired.Score > urlTypeCap || paired.Level.rank() > LevelLow.rank() {
		t.Errorf("pair recompute must keep the clamp: %s %.2f", paired.Level, paired.Score)
	}
	repeated := applyRepeatFactor(c, asset.SecretTypeS3, string(patterns.FamilyStructured), nil)
	if repeated.Score > urlTypeCap || repeated.Level.rank() > LevelLow.rank() {
		t.Errorf("repeat recompute must keep the clamp: %s %.2f", repeated.Level, repeated.Score)
	}

	// Webhook URLs are deliberately NOT capped: a Discord webhook is
	// genuinely sensitive despite being URL-shaped.
	w := deriveConfidence(confidenceInput{
		Strength: 0.85, Family: "structured", Type: asset.SecretTypeWebhookURL,
		Value:   "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("a", 60),
		Context: Context{NameHint: "provider"},
	})
	if hasFactor(w, "url_type_cap") || w.Level.rank() < LevelMedium.rank() {
		t.Errorf("webhook URLs must not be capped: %+v", w.Factors)
	}
}

func TestCountNonPatternCanonicalRule(t *testing.T) {
	// The canonical counting rule shared by every confidence path: every
	// factor except "pattern" and the weight-0 "url_type_cap" marker.
	factors := []Factor{
		{Name: "pattern", Weight: 0.9},
		{Name: "entropy", Weight: entropyStrongWeight},
		{Name: "context", Weight: contextStrongWeight},
		{Name: "endpoint", Weight: endpointWeight},
		{Name: "technology", Weight: techWeight},
		{Name: "pair", Weight: pairWeight},
		{Name: "repeat", Weight: repeatWeight},
		{Name: "url_type_cap", Weight: 0},
		{Name: "pattern", Weight: 0.6}, // any "pattern" factor is excluded by name
	}
	if got := countNonPattern(factors); got != 6 {
		t.Errorf("countNonPattern = %d, want 6 (entropy/context/endpoint/technology/pair/repeat counted; pattern and url_type_cap excluded)", got)
	}
	if got := countNonPattern(nil); got != 0 {
		t.Errorf("countNonPattern(nil) = %d, want 0", got)
	}
	markerOnly := []Factor{{Name: "url_type_cap", Weight: 0}, {Name: "pattern", Weight: 0.5}}
	if got := countNonPattern(markerOnly); got != 0 {
		t.Errorf("pattern + url_type_cap alone must count 0, got %d", got)
	}
}

func TestApplyGatesURLCapMarkerNeverCounts(t *testing.T) {
	// The weight-0 url_type_cap marker records a clamp and must never count
	// toward the level gates: [pattern, url_type_cap, one evidence factor]
	// gates exactly like [pattern, one evidence factor].
	oneEvidence := []Factor{
		{Name: "pattern", Weight: 0.9},
		{Name: "entropy", Weight: entropyStrongWeight},
	}
	markerPlusOne := []Factor{
		{Name: "pattern", Weight: 0.9},
		{Name: "url_type_cap", Weight: 0},
		{Name: "entropy", Weight: entropyStrongWeight},
	}
	// One supporting factor: High gates to Medium, Medium stays Medium —
	// identical with or without the marker.
	if got, want := applyGates(LevelHigh, markerPlusOne), applyGates(LevelHigh, oneEvidence); got != want || got != LevelMedium {
		t.Errorf("High with marker+one factor = %s, want %s (both gated to Medium)", got, want)
	}
	if got, want := applyGates(LevelMedium, markerPlusOne), applyGates(LevelMedium, oneEvidence); got != want || got != LevelMedium {
		t.Errorf("Medium with marker+one factor = %s, want %s (both stay Medium)", got, want)
	}
	// Zero supporting factors: the marker alone does not rescue Medium.
	markerOnly := []Factor{{Name: "pattern", Weight: 0.9}, {Name: "url_type_cap", Weight: 0}}
	patternOnly := []Factor{{Name: "pattern", Weight: 0.9}}
	if got, want := applyGates(LevelMedium, markerOnly), applyGates(LevelMedium, patternOnly); got != want || got != LevelLow {
		t.Errorf("Medium with marker only = %s, want %s (both gated to Low)", got, want)
	}
	if got, want := applyGates(LevelHigh, markerOnly), applyGates(LevelHigh, patternOnly); got != want || got != LevelMedium {
		t.Errorf("High with marker only = %s, want %s (both gated to Medium)", got, want)
	}
}

func TestConfidenceLevelsParse(t *testing.T) {
	for _, l := range []Level{LevelHigh, LevelMedium, LevelLow, LevelUnknown} {
		if !l.Valid() {
			t.Errorf("%q must be valid", l)
		}
		got, err := ParseLevel(l.String())
		if err != nil || got != l {
			t.Errorf("ParseLevel(%q) = %v, %v", l, got, err)
		}
	}
	if _, err := ParseLevel("very-high"); err == nil {
		t.Error("unknown level must fail")
	}
	if LevelHigh.rank() <= LevelMedium.rank() {
		t.Error("rank order is broken")
	}
}
