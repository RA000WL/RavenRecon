package secrentel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// syntheticExampleSecret is AWS's own documented example access key ID: a
// fixed SYNTHETIC value, never a real credential, used to pin that
// decode-rejection diagnostics never embed candidate values.
const syntheticExampleSecret = "AKIAIOSFODNN7EXAMPLE"

// storedSecretRecord hand-builds a completed cache record carrying exactly
// one stored secret built from the given fields. Every field is under the
// test's control so a rejection test can target ONE re-validation check
// deterministically, without depending on pattern/context internals. All
// non-target checks pass for the cases in this file.
func storedSecretRecord(t *testing.T, sd scannedDocument, typ asset.SecretType, value string, family patterns.Family, score float64, level string, factors []Factor) cache.Record {
	t.Helper()
	cand, err := asset.NewSecretCandidate(typ, value, sd.candidateSource(),
		asset.Provenance{Source: "test", DiscoveredAt: fixedTime(0)})
	if err != nil {
		t.Fatal(err)
	}
	st := storedScan{
		Version:      analysisVersion,
		Kind:         string(sd.kind),
		CandidateSrc: sd.candidateSource(),
		Secrets: []storedSecret{{
			Candidate:  cand,
			Family:     family,
			Score:      score,
			Level:      level,
			Factors:    factors,
			PatternIDs: []string{"test.pattern"},
			Source:     "test",
			ObservedAt: fixedTime(0),
		}},
		FirstSeen: fixedTime(0),
		LastSeen:  fixedTime(0).Add(time.Minute),
		Sources:   []string{"test"},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        sd.identity.String(),
		Status:        cache.StatusCompleted,
		CreatedAt:     fixedTime(0),
		Data:          data,
	}
}

// TestDecodeRejectionErrorsRedactCandidateValues is the M-4 regression:
// every decode-rejection error that names a candidate must carry the
// redacted form (type + short hash prefix of the value), never the value
// itself and never the full candidate ID — a tampered or
// analysis-version-stale record must not print secret material into
// diagnostics.
func TestDecodeRejectionErrorsRedactCandidateValues(t *testing.T) {
	sd, err := prepareDocument(Document{
		Kind:     KindJS,
		Content:  []byte("k=" + syntheticExampleSecret),
		Filename: "app.js",
	}, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultScanLimits()

	// Each case is internally consistent with everything except the ONE
	// check it must fail, and that check is one of the four whose error
	// interpolates the candidate identity.
	cases := []struct {
		name    string
		typ     asset.SecretType
		value   string
		family  patterns.Family
		score   float64
		level   string
		factors []Factor
		want    string
	}{
		{
			name: "score exceeds the derived cap",
			// A structured AWS match with ZERO supporting factors: the
			// contract caps the score at structuredCap (0.59); 0.9 exceeds
			// it (level high is consistent with the score, and the factor
			// weights are valid).
			typ: asset.SecretTypeAWS, value: syntheticExampleSecret,
			family: patterns.FamilyStructured, score: 0.9, level: string(LevelHigh),
			factors: []Factor{{Name: "pattern", Weight: 0.9}},
			want:    "exceeds the derived cap",
		},
		{
			name: "url_type_cap marker missing on a capped type",
			// S3 is a pure-endpoint URL type: the weight-0 url_type_cap
			// marker must be present, and the score rides under urlTypeCap
			// (0.2), so only the marker check fails.
			typ: asset.SecretTypeS3, value: "https://share.s3.example.com/obj.txt",
			family: patterns.FamilyStructured, score: 0.1, level: string(LevelUnknown),
			factors: []Factor{{Name: "pattern", Weight: 0.1}},
			want:    "url_type_cap factor missing",
		},
		{
			name: "url_type_cap marker present on an uncapped type",
			// The marker factor (weight 0) rides on an AWS candidate: the
			// marker must be absent exactly when the type is uncapped.
			typ: asset.SecretTypeAWS, value: syntheticExampleSecret,
			family: patterns.FamilyStructured, score: 0.1, level: string(LevelUnknown),
			factors: []Factor{{Name: "pattern", Weight: 0.1}, {Name: "url_type_cap", Weight: 0}},
			want:    "url_type_cap factor present",
		},
		{
			name: "score contradicts its own factor list",
			// The factors recompose to min(combine([0.9]), 0.59) = 0.59, not
			// the stored 0.3; everything else (level, weights, cap) passes.
			typ: asset.SecretTypeAWS, value: syntheticExampleSecret,
			family: patterns.FamilyStructured, score: 0.3, level: string(LevelLow),
			factors: []Factor{{Name: "pattern", Weight: 0.9}},
			want:    "does not match the recomposed score",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := storedSecretRecord(t, sd, tt.typ, tt.value, tt.family, tt.score, tt.level, tt.factors)
			_, err := decodeStoredScan(rec, sd, limits)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("decode must reject with %q, got: %v", tt.want, err)
			}
			msg := err.Error()

			// The redacted form is computed here with the raw primitives
			// (sha256 + hex of the first four bytes), independently of the
			// production helper.
			sum := sha256.Sum256([]byte(tt.value))
			wantRedacted := string(tt.typ) + "/" + hex.EncodeToString(sum[:4])
			if !strings.Contains(msg, wantRedacted) {
				t.Errorf("rejection error must carry the redacted form %q, got: %q", wantRedacted, msg)
			}
			if strings.Contains(msg, tt.value) {
				t.Errorf("rejection error leaks the candidate value %q: %q", tt.value, msg)
			}
			full, err := asset.NewSecretCandidate(tt.typ, tt.value, sd.candidateSource(), asset.Provenance{})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(msg, full.ID()) {
				t.Errorf("rejection error leaks the full candidate ID %q: %q", full.ID(), msg)
			}
		})
	}
}

// TestFindingsOutputCarryCandidateValueUnredacted pins the M-4 scope
// boundary: redaction applies ONLY to diagnostics. The engine's legitimate
// findings output — SecretResult.Value, the canonical Candidate.Value, and
// the MethodSecret evidence records — must carry the candidate value
// verbatim.
func TestFindingsOutputCarryCandidateValueUnredacted(t *testing.T) {
	cfg := baseCfg()
	cfg.Clock = newFakeClock()
	rep, err := Ingest(context.Background(), cfg, sliceSource([]Document{
		{Kind: KindJS, Content: []byte("k=" + awsKeyID), Filename: "app.js"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Secrets) != 1 {
		t.Fatalf("secrets = %d, want 1", len(rep.Secrets))
	}
	s := rep.Secrets[0]
	if s.Value != awsKeyID {
		t.Errorf("SecretResult.Value must carry the candidate value unredacted, got %q", s.Value)
	}
	if s.Candidate.Value != awsKeyID {
		t.Errorf("Candidate.Value must carry the candidate value unredacted, got %q", s.Candidate.Value)
	}
	if s.Value == redactedCandidateID(s.Candidate) {
		t.Errorf("findings must never pass through the redaction helper: %q", s.Value)
	}
	found := false
	for _, ev := range rep.Evidence {
		if ev.Value == awsKeyID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the MethodSecret evidence must carry the candidate value unredacted; evidence: %+v", rep.Evidence)
	}
}
