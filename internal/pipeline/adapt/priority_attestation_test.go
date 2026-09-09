package adapt

import (
	"context"
	"math"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/secrentel"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
	"github.com/RA000WL/RavenRecon/internal/techintel"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// structuredSecretTypes is the exact allowlist secretSignal attests above
// the bar: every secret type carrying at least one structured pattern in
// the emitting phase's database. nonStructuredSecretTypes is its
// complement. Together they must cover asset.KnownSecretTypes exactly — a
// new secret type fails this test until it is classified in
// structuredSecretType (fail-closed: unclassified types never attest).
var structuredSecretTypes = []asset.SecretType{
	asset.SecretTypeJWT,
	asset.SecretTypeAWS,
	asset.SecretTypeGoogle,
	asset.SecretTypeFirebase,
	asset.SecretTypeStripe,
	asset.SecretTypeGitHub,
	asset.SecretTypePrivateKey,
	asset.SecretTypeRSAPrivateKey,
	asset.SecretTypeSSHPrivateKey,
	asset.SecretTypeAzure,
	asset.SecretTypeGitLab,
	asset.SecretTypeTwilio,
	asset.SecretTypeSlack,
	asset.SecretTypeDiscord,
	asset.SecretTypeOpenAI,
	asset.SecretTypeAnthropic,
	asset.SecretTypeOAuth,
	asset.SecretTypePostgreSQLURL,
	asset.SecretTypeMySQLURL,
	asset.SecretTypeMongoDBURL,
	asset.SecretTypeRedisURL,
	asset.SecretTypeSMTP,
	asset.SecretTypeWebhookURL,
	asset.SecretTypeS3,
	asset.SecretTypeDigitalOcean,
}

var nonStructuredSecretTypes = []asset.SecretType{
	asset.SecretTypeGeneric,
	asset.SecretTypeBearer,
	asset.SecretTypeDatabaseURL,
	asset.SecretTypeCloudflare,
	asset.SecretTypeVercel,
	asset.SecretTypeNetlify,
	asset.SecretTypeRailway,
	asset.SecretTypeAPIKey,
	asset.SecretTypePublicKey,
	asset.SecretTypeCustomToken,
}

func mkAttestSecret(t testing.TB, typ asset.SecretType, conf float64) asset.SecretCandidate {
	t.Helper()
	src := mustURL(t, "https://www.example.com/app.js").Identity()
	s, err := asset.NewSecretCandidate(typ, "AKIAIOSFODNN7EXAMPLE", src, asset.Provenance{Source: "test", Confidence: conf})
	if err != nil {
		t.Fatalf("NewSecretCandidate(%q): %v", typ, err)
	}
	return s
}

// TestSecretSignalStructuredFamiliesOnly pins the NEW-141 F1 predicate:
// only structured-family types attest above the bar. Bearer at 0.95 and a
// lone-contextual candidate at 0.75 stay unattested (unattributed shapes
// and uncapped contextual strengths); a structured-supported candidate
// attests. The full type vocabulary is swept against the hardcoded
// classification so a new type fails loudly until classified.
func TestSecretSignalStructuredFamiliesOnly(t *testing.T) {
	// The classification covers the whole vocabulary exactly once.
	seen := map[asset.SecretType]int{}
	for _, typ := range structuredSecretTypes {
		seen[typ]++
	}
	for _, typ := range nonStructuredSecretTypes {
		seen[typ]++
	}
	for _, typ := range asset.KnownSecretTypes() {
		if seen[typ] != 1 {
			t.Errorf("type %q classified %d times, want exactly once (update structuredSecretType + the test sets)", typ, seen[typ])
		}
	}
	if len(seen) != len(asset.KnownSecretTypes()) {
		t.Errorf("classification covers %d types, vocabulary has %d", len(seen), len(asset.KnownSecretTypes()))
	}

	// Bearer at 0.95 attests nothing: a bearer token is a contextual
	// assignment shape, unattributed however confident.
	if ss, ok := secretSignal(mkAttestSecret(t, asset.SecretTypeBearer, 0.95)); !ok {
		t.Fatal("bearer at 0.95: secretSignal refused a canonical candidate")
	} else if ss.Structural {
		t.Error("bearer at 0.95: Structural = true, want false (unattributed shapes never attest)")
	}

	// Lone-contextual at 0.75 attests nothing: database_url is purely
	// contextual (no zero-support cap), so 0.75 may carry zero supporting
	// factors.
	if ss, ok := secretSignal(mkAttestSecret(t, asset.SecretTypeDatabaseURL, 0.75)); !ok {
		t.Fatal("database_url at 0.75: secretSignal refused a canonical candidate")
	} else if ss.Structural {
		t.Error("database_url at 0.75: Structural = true, want false (lone-contextual matches never attest)")
	}

	// Structured-supported attests: an attributed AWS shape above the bar
	// fired with support.
	if ss, ok := secretSignal(mkAttestSecret(t, asset.SecretTypeAWS, 0.95)); !ok {
		t.Fatal("aws at 0.95: secretSignal refused a canonical candidate")
	} else if !ss.Structural {
		t.Error("aws at 0.95: Structural = false, want true (structured-supported shapes attest)")
	}

	// Full sweep: every structured type attests at 0.95; every
	// non-structured type attests at nothing (0.95 and 0.75 alike); the bar
	// itself attests nothing for any type.
	for _, typ := range structuredSecretTypes {
		ss, ok := secretSignal(mkAttestSecret(t, typ, 0.95))
		if !ok {
			t.Fatalf("%s at 0.95: secretSignal refused a canonical candidate", typ)
		}
		if !ss.Structural {
			t.Errorf("%s at 0.95: Structural = false, want true (structured family)", typ)
		}
	}
	for _, typ := range nonStructuredSecretTypes {
		for _, conf := range []float64{0.75, 0.95} {
			ss, ok := secretSignal(mkAttestSecret(t, typ, conf))
			if !ok {
				t.Fatalf("%s at %v: secretSignal refused a canonical candidate", typ, conf)
			}
			if ss.Structural {
				t.Errorf("%s at %v: Structural = true, want false (non-structured family never attests)", typ, conf)
			}
		}
	}
	for _, typ := range asset.KnownSecretTypes() {
		ss, ok := secretSignal(mkAttestSecret(t, typ, 0.59))
		if !ok {
			t.Fatalf("%s at the bar: secretSignal refused a canonical candidate", typ)
		}
		if ss.Structural {
			t.Errorf("%s at the bar: Structural = true, want false (the bar itself never attests)", typ)
		}
	}
}

// TestStructuralBarEqualsEngineCaps pins the NEW-141 F2 equality —
// structuralConfidenceBar == techintel spoofableScoreCap == secrentel
// structuredCap — through observable engine behavior, never by importing
// the unexported constants. A spoofable-only technology run through the
// real techintel Ingest and a zero-support structured secret run through
// the real secrentel Ingest must score identically (both engines' caps
// agree), and the adapter must refuse attestation exactly there while
// attesting one float step above. A drift on either side — an engine cap
// move or an adapter bar move — fails loudly here.
func TestStructuralBarEqualsEngineCaps(t *testing.T) {
	ctx := context.Background()

	// Spoofable-only technology: one high-weight header indicator, so the
	// raw score (0.9) trips the spoofable-only cap and nothing else.
	techDB, err := fingerprints.CompileForTest([]fingerprints.Fingerprint{{
		Name:     "synthetic-spoofable",
		Category: asset.CategoryFramework,
		Indicators: []fingerprints.Indicator{{
			Kind:   fingerprints.IndicatorHeader,
			Match:  "x-synthetic-spoofable",
			Weight: 0.9,
		}},
	}})
	if err != nil {
		t.Fatalf("CompileForTest(fingerprints): %v", err)
	}
	techCfg := techintel.DefaultConfig()
	techCfg.DB = techDB
	techSrc := techintel.SliceObservationSource{{
		URL:     mustURL(t, "https://www.example.com/"),
		Headers: []techintel.HeaderEntry{{Name: "X-Synthetic-Spoofable", Value: "present"}},
	}}
	techRep, err := techintel.Ingest(ctx, techCfg, &techSrc)
	if err != nil {
		t.Fatalf("techintel.Ingest: %v", err)
	}
	var spoofScore float64 = -1
	for _, tech := range techRep.Technologies {
		if tech.Name == "synthetic-spoofable" {
			spoofScore = tech.Prov.Confidence
		}
	}
	if spoofScore < 0 {
		t.Fatalf("spoofable-only technology missing from report: %+v", techRep.Technologies)
	}

	// Zero-support structured secret: one high-strength structured
	// pattern, matched bare in a config document with no assignment
	// context, no entropy rule, and no correlation — so the structured
	// zero-support cap is the only thing that binds.
	secretDB, err := patterns.CompileForTest([]patterns.Pattern{{
		ID:       "test-structured-token",
		Type:     asset.SecretTypeGitHub,
		Family:   patterns.FamilyStructured,
		Regex:    `gh_test_[0-9A-Za-z]{16}`,
		Anchors:  []string{"gh_test_"},
		Strength: 0.9,
		MinLen:   24,
		MaxLen:   24,
	}})
	if err != nil {
		t.Fatalf("CompileForTest(patterns): %v", err)
	}
	secretCfg := secrentel.DefaultConfig()
	secretCfg.DB = secretDB
	secretSrc := secrentel.SliceDocumentSource{{
		Kind:    secrentel.KindConfig,
		Content: []byte("gh_test_ABCDEF1234567890"),
	}}
	secretRep, err := secrentel.Ingest(ctx, secretCfg, &secretSrc)
	if err != nil {
		t.Fatalf("secrentel.Ingest: %v", err)
	}
	if len(secretRep.Secrets) != 1 {
		t.Fatalf("structured scan secrets = %d, want exactly 1 (the lone match): %+v", len(secretRep.Secrets), secretRep.Secrets)
	}
	got := secretRep.Secrets[0]
	if got.Family != patterns.FamilyStructured {
		t.Fatalf("candidate family = %q, want structured (the zero-support cap path)", got.Family)
	}
	structScore := got.Confidence.Score

	// The two engine caps agree — observed, never imported.
	if spoofScore != structScore {
		t.Fatalf("engine caps disagree: spoofable-only tech scores %v, zero-support structured secret scores %v (want equality)", spoofScore, structScore)
	}
	if !(spoofScore > 0 && spoofScore < 1) {
		t.Fatalf("capped score = %v, want a sane (0,1) cap value", spoofScore)
	}

	// The adapter bar sits exactly there: the capped score itself never
	// attests (it may BE the capped detection), one float step above does.
	mkTech := func(conf float64) asset.Technology {
		tech, err := asset.NewTechnology("synthetic-tech", asset.CategoryFramework, asset.Provenance{Source: "test", Confidence: conf})
		if err != nil {
			t.Fatalf("NewTechnology: %v", err)
		}
		return tech
	}
	above := math.Nextafter(spoofScore, math.Inf(1))
	ts, ok := techSignal(mkTech(spoofScore))
	if !ok {
		t.Fatal("techSignal refused the engine-observed score")
	}
	if ts.Structural {
		t.Errorf("tech at engine cap %v: Structural = true, want false", spoofScore)
	}
	ts, ok = techSignal(mkTech(above))
	if !ok {
		t.Fatal("techSignal refused one step above the engine cap")
	}
	if !ts.Structural {
		t.Errorf("tech one step above engine cap %v: Structural = false, want true", above)
	}
	ss, ok := secretSignal(mkAttestSecret(t, asset.SecretTypeGitHub, structScore))
	if !ok {
		t.Fatal("secretSignal refused the engine-observed score")
	}
	if ss.Structural {
		t.Errorf("structured secret at engine cap %v: Structural = true, want false", structScore)
	}
	ss, ok = secretSignal(mkAttestSecret(t, asset.SecretTypeGitHub, math.Nextafter(structScore, math.Inf(1))))
	if !ok {
		t.Fatal("secretSignal refused one step above the engine cap")
	}
	if !ss.Structural {
		t.Errorf("structured secret one step above engine cap: Structural = false, want true")
	}
}
