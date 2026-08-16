package priority

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func baseSignal() Signal {
	return Signal{
		Identity:  asset.Identity{Kind: asset.KindEndpoint, Value: "GET https://www.example.com/api/v2/admin"},
		Kind:      asset.KindEndpoint,
		Path:      "/api/v2/admin",
		Hostname:  "www.example.com",
		FirstSeen: fixedTime(10),
		ScoredAt:  fixedTime(20),
	}
}

func fixedTime(sec int) time.Time {
	return time.Unix(1700000000+int64(sec), 0).UTC()
}

func TestScoreDeterministic(t *testing.T) {
	ic, rc := mustCatalogs(t)
	a, err := ScoreSurface(baseSignal(), ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ScoreSurface(baseSignal(), ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("identical inputs produced different outputs:\n%+v\n%+v", a, b)
	}
	if !a.ScoredAt.Equal(fixedTime(20)) || !a.FirstSeen.Equal(fixedTime(10)) {
		t.Error("explicit timestamps must be echoed, never clock-read")
	}
}

func TestScoreExplainability(t *testing.T) {
	ic, rc := mustCatalogs(t)
	sig := baseSignal()
	sig.Technologies = []TechSignal{{Name: "django", Category: "framework", Confidence: 0.85, Identity: "framework/django"}}
	sig.Secrets = []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: 0.9, Identity: "secret_candidate:aws/x/y"}}
	sig.Observations = 3
	sig.Port = 8080
	sig.Headers = []string{"x-powered-by: express"}

	out, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Factors) == 0 {
		t.Fatal("expected factors")
	}
	for _, f := range out.Factors {
		if err := f.validate(); err != nil {
			t.Errorf("factor contract violated: %v", err)
		}
		if f.Weight > 0 && (len(f.Evidence) == 0 || f.Reason == "") {
			t.Errorf("nonzero factor without evidence/reason: %+v", f)
		}
	}
	// Evidence cites the referenced identities, not just the self identity.
	var citedSelf, citedTech, citedSecret bool
	for _, f := range out.Factors {
		for _, e := range f.Evidence {
			if e == sig.Identity.String() {
				citedSelf = true
			}
			if e == "framework/django" {
				citedTech = true
			}
			if e == "secret_candidate:aws/x/y" {
				citedSecret = true
			}
		}
	}
	if !citedSelf || !citedTech || !citedSecret {
		t.Errorf("evidence audit trail incomplete: self=%v tech=%v secret=%v", citedSelf, citedTech, citedSecret)
	}
}

// recompose rebuilds the score from the emitted factor list through the
// documented composition (group, cap, combine) — the pin for the combine
// math.
func recompose(factors []Factor) float64 {
	byGroup := groupFactors(factors)
	product := 1.0
	for _, name := range sortedKeys(byGroup) {
		fs := byGroup[name]
		w := combineFactors(fs)
		if name == "confidence" {
			w = math.Min(w, confidenceGroupCap)
		} else {
			w = math.Min(w, perCategoryCap)
		}
		product *= 1 - w
	}
	return round4(1 - product)
}

func TestCombineMathPinned(t *testing.T) {
	ic, rc := mustCatalogs(t)

	// Single category, single factor: score == the entry weight exactly.
	out, err := ScoreSurface(Signal{
		Identity: testIdentity(), Kind: asset.KindURL, Path: "/actuator/health",
		FirstSeen: fixedTime(1), ScoredAt: fixedTime(2),
	}, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	act, _ := ic.ByID("actuator-path")
	if out.Score != round4(act.Weight) {
		t.Errorf("single-factor score = %v, want entry weight %v", out.Score, act.Weight)
	}

	// The emitted factor list recomposes to the score exactly.
	sig := baseSignal()
	sig.Technologies = []TechSignal{{Name: "auth0", Category: "authentication", Confidence: 0.9}}
	sig.Secrets = []SecretSignal{{Type: asset.SecretTypeJWT, Confidence: 0.8}}
	out, err = ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if got := recompose(out.Factors); got != out.Score {
		t.Errorf("recomposed score %v != emitted score %v (factors %v)", got, out.Score, out.Factors)
	}

	// Removing one group changes the score by exactly its recomputed
	// effect (never more, never less).
	var groups []string
	seen := map[string]bool{}
	for _, f := range out.Factors {
		if !seen[groupKey(f)] {
			seen[groupKey(f)] = true
			groups = append(groups, groupKey(f))
		}
	}
	if len(groups) < 2 {
		t.Fatalf("need >=2 groups for the removal pin, got %v", groups)
	}
	var kept []Factor
	for _, f := range out.Factors {
		if groupKey(f) != groups[0] {
			kept = append(kept, f)
		}
	}
	if want := recompose(kept); want == out.Score {
		t.Errorf("removing group %q must change the score", groups[0])
	} else if got := recompose(kept); got != want {
		t.Errorf("recompose not idempotent")
	}
}

func TestCapsAndGates(t *testing.T) {
	// Custom catalogs pin cap/gate behavior exactly.
	huge := func(id, cat string) Indicator {
		return Indicator{ID: id, Category: cat, Weight: 1.0, Field: FieldPath, Terms: []string{"/x"}, Reason: "test %s", Recommendation: "test guidance %s"}
	}
	one, err := CompileForTest("interestingness", []Indicator{huge("a", "alpha")})
	if err != nil {
		t.Fatal(err)
	}
	two, err := CompileForTest("interestingness", []Indicator{huge("a", "alpha"), huge("b", "beta")})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileForTest("risk", []Indicator{})
	if err != nil {
		t.Fatal(err)
	}
	sig := Signal{Identity: testIdentity(), Kind: asset.KindURL, Path: "/x", ScoredAt: fixedTime(1)}

	// Single category, weight 1.0: capped at perCategoryCap, gated to
	// medium (one indicator category can never be high).
	out, err := ScoreSurface(sig, one, empty)
	if err != nil {
		t.Fatal(err)
	}
	if out.Score != perCategoryCap {
		t.Errorf("single-category score = %v, want cap %v", out.Score, perCategoryCap)
	}
	if out.Level != LevelMedium {
		t.Errorf("single-category level = %s, want medium", out.Level)
	}

	// Two categories: both at cap → score 1−0.4² = 0.84 → high.
	out, err = ScoreSurface(sig, two, empty)
	if err != nil {
		t.Fatal(err)
	}
	if want := round4(1 - (1-perCategoryCap)*(1-perCategoryCap)); out.Score != want {
		t.Errorf("two-category score = %v, want %v", out.Score, want)
	}
	if out.Level != LevelHigh {
		t.Errorf("two-category level = %s, want high", out.Level)
	}

	// Zero signals: unknown, zero scores, no factors, no panic.
	out, err = ScoreSurface(Signal{Identity: testIdentity(), Kind: asset.KindURL}, one, empty)
	if err != nil {
		t.Fatal(err)
	}
	if out.Level != LevelUnknown || out.Score != 0 || len(out.Factors) != 0 || out.Interestingness != 0 || out.Confidence != 0 {
		t.Errorf("zero-signal surface = %+v", out)
	}

	// Confidence group is capped in the score but reported uncapped.
	confSig := Signal{
		Identity: testIdentity(), Kind: asset.KindURL,
		Technologies: []TechSignal{
			{Name: "a", Category: "framework", Confidence: 0.95},
			{Name: "b", Category: "server", Confidence: 0.95},
			{Name: "c", Category: "cdn", Confidence: 0.95},
		},
		ScoredAt: fixedTime(1),
	}
	out, err = ScoreSurface(confSig, one, empty)
	if err != nil {
		t.Fatal(err)
	}
	if want := round4(1 - 0.05*0.05*0.05); out.Confidence != want {
		t.Errorf("confidence = %v, want uncapped combine %v", out.Confidence, want)
	}
	// Score uses the capped group alone (no path signal was given).
	if out.Score != confidenceGroupCap {
		t.Errorf("confidence-capped score = %v, want %v (group cap alone)", out.Score, confidenceGroupCap)
	}
	if out.Level != LevelLow {
		t.Errorf("confidence-only level = %s, want low (confidence is not an indicator category; without one, medium is unreachable)", out.Level)
	}
}

func TestOverlapPolicy(t *testing.T) {
	ic, rc := mustCatalogs(t)

	// /api/v2 fires BOTH the api and versioned_api categories (independent
	// families) but exactly ONE factor per category.
	out, err := ScoreSurface(Signal{Identity: testIdentity(), Kind: asset.KindURL, Path: "/api/v2/users"}, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range out.Factors {
		counts[f.Name]++
	}
	for name, n := range counts {
		if n > 1 && name != "confidence:technology" && name != "confidence:secret" {
			t.Errorf("category %s emitted %d factors from one field; the overlap policy allows one per (category, field)", name, n)
		}
	}
	if counts["interestingness:api"] != 1 || counts["interestingness:versioned_api"] != 1 {
		t.Errorf("api/versioned factors = %v", counts)
	}

	// Longest-literal-wins inside one category: a custom catalog with two
	// same-category entries where the longer term's entry must win.
	cat, err := CompileForTest("interestingness", []Indicator{
		{ID: "a-short", Category: "alpha", Weight: 0.9, Field: FieldPath, Terms: []string{"/a"}, Reason: "short %s", Recommendation: "test guidance %s"},
		{ID: "b-long", Category: "alpha", Weight: 0.2, Field: FieldPath, Terms: []string{"/abc"}, Reason: "long %s", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := CompileForTest("risk", nil)
	out, err = ScoreSurface(Signal{Identity: testIdentity(), Kind: asset.KindURL, Path: "/abc"}, cat, empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Factors) != 1 || out.Factors[0].Weight != 0.2 {
		t.Errorf("longest-literal entry must win, got %+v", out.Factors)
	}
	if out.Factors[0].Reason != "long /abc" {
		t.Errorf("reason must cite the matched term: %q", out.Factors[0].Reason)
	}
}

// TestOverlapPolicyScansAllTermsPerItem pins the longest-match policy for
// list-field (matchItems) matches: when a short term precedes a longer one
// in the same entry's Terms, the item's best term is still the longest, and
// an entry whose longest term beats another entry's term wins the group.
func TestOverlapPolicyScansAllTermsPerItem(t *testing.T) {
	cat, err := CompileForTest("interestingness", []Indicator{
		{ID: "a-multi", Category: "alpha", Weight: 0.2, Field: FieldPath, Terms: []string{"/foo", "/foobarbaz"}, Reason: "multi \"%s\"", Recommendation: "test guidance %s"},
		{ID: "b-mid", Category: "alpha", Weight: 0.9, Field: FieldPath, Terms: []string{"/foobar"}, Reason: "mid \"%s\"", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileForTest("risk", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ScoreSurface(Signal{Identity: testIdentity(), Kind: asset.KindURL, Path: "/foobarbaz"}, cat, empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Factors) != 1 {
		t.Fatalf("factors = %v; want exactly one alpha factor", out.Factors)
	}
	f := out.Factors[0]
	if f.Weight != 0.2 {
		t.Errorf("winning weight = %v; want entry a-multi's 0.2 via its longest term /foobarbaz (length 9), got %+v", f.Weight, f)
	}
	if f.Reason != "multi \"/foobarbaz\"" {
		t.Errorf("reason = %q; want the entry's longest term /foobarbaz substituted", f.Reason)
	}
}

// TestOverlapPolicyScansAllTermsPerListItem pins the longest-match policy
// inside matchItems — the LIST-field dispatch (secret_type, tech_name,
// tech_category, parameter_name, header), which the FieldPath test above
// never reaches (FieldPath dispatches to matchSingle). One item whose value
// contains both a short term and a longer term of the same entry must yield
// the LONGEST term, even though the short term is listed (and matched)
// first — break-at-first-match would substitute the short term.
//
// The secret-type vocabulary is fixed by the asset model (35 canonical
// types; validateSignal rejects unknown values), so the trap item is the
// canonical ssh_private_key — exactly the shape the production
// high_value_secret entry matches via its "private_key" term: it contains
// both "ssh" (3 bytes) and "private_key" (11 bytes), and the entry lists
// the short term first.
func TestOverlapPolicyScansAllTermsPerListItem(t *testing.T) {
	cat, err := CompileForTest("risk", []Indicator{
		{ID: "a-short-first", Category: "secret_family", Weight: 0.2, Field: FieldSecretType, Terms: []string{"ssh", "private_key"}, Reason: "secret type %s observed", Recommendation: "review the secret type %s"},
		{ID: "b-oauth", Category: "secret_family", Weight: 0.1, Field: FieldSecretType, Terms: []string{"oauth"}, Reason: "secret type %s observed", Recommendation: "review the secret type %s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileForTest("interestingness", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Zero confidence keeps the confidence group out of the factor list so
	// the exactly-one-factor assertion is exact.
	sig := Signal{
		Identity: testIdentity(), Kind: asset.KindURL,
		Secrets:  []SecretSignal{{Type: asset.SecretTypeSSHPrivateKey, Confidence: 0}},
		ScoredAt: fixedTime(1),
	}
	out, err := ScoreSurface(sig, cat, empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Factors) != 1 {
		t.Fatalf("factors = %v; want exactly one factor (from entry a-short-first)", out.Factors)
	}
	f := out.Factors[0]
	if f.Name != "risk:secret_family" {
		t.Errorf("factor name = %q; want the single (category, field) group risk:secret_family", f.Name)
	}
	if f.Weight != 0.2 {
		t.Errorf("winning weight = %v; want entry a-short-first's 0.2", f.Weight)
	}
	if !strings.Contains(f.Reason, "private_key") {
		t.Errorf("reason = %q; want the entry's longest term private_key substituted", f.Reason)
	}
	if f.Reason != "secret type private_key observed" {
		t.Errorf("reason = %q; want exactly %q", f.Reason, "secret type private_key observed")
	}
}

// TestOverlapPolicyLiteralBeatsRegex pins the specificity tie-break: a
// literal term match (specificity = term length) beats a regex match
// (specificity 0) on the same category and field, regardless of weight.
func TestOverlapPolicyLiteralBeatsRegex(t *testing.T) {
	cat, err := CompileForTest("interestingness", []Indicator{
		{ID: "a-regex", Category: "alpha", Weight: 0.9, Field: FieldHost, Regex: `^internal\.`, Reason: "internal-suggesting regex", Recommendation: "review the internal-suggesting host"},
		{ID: "b-lit", Category: "alpha", Weight: 0.2, Field: FieldHost, Terms: []string{"internal"}, Reason: "internal-suggesting host label \"%s\" observed", Recommendation: "review the host label %s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileForTest("risk", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ScoreSurface(Signal{Identity: testIdentity(), Kind: asset.KindURL, Hostname: "internal.example.com"}, cat, empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Factors) != 1 {
		t.Fatalf("factors = %v; want exactly one alpha factor", out.Factors)
	}
	f := out.Factors[0]
	if f.Weight != 0.2 {
		t.Errorf("winning weight = %v; want the literal entry's 0.2 (literal beats regex), got %+v", f.Weight, f)
	}
	if f.Reason != "internal-suggesting host label \"internal\" observed" {
		t.Errorf("reason = %q; want the literal entry's term cited", f.Reason)
	}
}

// TestConfidenceFactorsPerTypeBound pins the per-type confidence factor
// bound: technology and secret confidence factors are each capped at
// maxConfidenceSignalFactors independently, so secrets are never crowded
// out by (or crowded out by) technology factors.
func TestConfidenceFactorsPerTypeBound(t *testing.T) {
	ic, rc := mustCatalogs(t)
	var secrets []SecretSignal
	for i := 0; i < 12; i++ {
		secrets = append(secrets, SecretSignal{Type: asset.SecretTypeAWS, Confidence: 0.9})
	}
	sig := Signal{
		Identity: testIdentity(), Kind: asset.KindURL,
		Secrets:  secrets,
		ScoredAt: fixedTime(1),
	}
	out, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	tech, secret := 0, 0
	for _, f := range out.Factors {
		switch f.Name {
		case "confidence:technology":
			tech++
		case "confidence:secret":
			secret++
		}
	}
	if secret != maxConfidenceSignalFactors {
		t.Errorf("secret confidence factors = %d; want exactly %d (0 technologies must not change the secret bound)", secret, maxConfidenceSignalFactors)
	}
	if tech != 0 {
		t.Errorf("technology confidence factors = %d; want 0", tech)
	}

	// The discriminating mixed case: 12 technologies AND 12 secrets, all
	// with valid confidence > 0. A per-type bound yields 8 + 8; a single
	// shared counter of maxConfidenceSignalFactors would yield 8 TOTAL —
	// this case tells them apart.
	var techs []TechSignal
	for i := 0; i < 12; i++ {
		techs = append(techs, TechSignal{
			Name:       fmt.Sprintf("zz-tech-%02d", i),
			Category:   "misc",
			Confidence: 0.5,
		})
	}
	mixedSecrets := make([]SecretSignal, 0, 12)
	for i := 0; i < 12; i++ {
		mixedSecrets = append(mixedSecrets, SecretSignal{Type: asset.SecretTypeJWT, Confidence: 0.5})
	}
	mixed := Signal{
		Identity: testIdentity(), Kind: asset.KindURL,
		Technologies: techs,
		Secrets:      mixedSecrets,
		ScoredAt:     fixedTime(1),
	}
	out, err = ScoreSurface(mixed, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	tech, secret = 0, 0
	for _, f := range out.Factors {
		switch f.Name {
		case "confidence:technology":
			tech++
		case "confidence:secret":
			secret++
		}
	}
	if tech != maxConfidenceSignalFactors {
		t.Errorf("mixed case technology confidence factors = %d; want exactly %d (per-type bound)", tech, maxConfidenceSignalFactors)
	}
	if secret != maxConfidenceSignalFactors {
		t.Errorf("mixed case secret confidence factors = %d; want exactly %d (per-type bound)", secret, maxConfidenceSignalFactors)
	}
	if total := tech + secret; total != 2*maxConfidenceSignalFactors {
		t.Errorf("mixed case confidence factors total = %d; want %d — a shared counter would cap the total at %d", total, 2*maxConfidenceSignalFactors, maxConfidenceSignalFactors)
	}
}

// TestScoreRejectsNaNConfidence pins the NaN guards in validateSignal: NaN
// compares false against both comparison bounds, so without the explicit
// math.IsNaN check a NaN confidence flows into clamp01 (also NaN-blind) and
// yields a NaN SurfaceAsset.Score. Scoring must return the validation error
// and no result instead.
func TestScoreRejectsNaNConfidence(t *testing.T) {
	ic, rc := mustCatalogs(t)
	cases := []struct {
		name string
		sig  Signal
	}{
		{
			"nan technology confidence",
			Signal{
				Identity: testIdentity(), Kind: asset.KindURL,
				Technologies: []TechSignal{{Name: "django", Category: "framework", Confidence: math.NaN()}},
				ScoredAt:     fixedTime(1),
			},
		},
		{
			"nan secret confidence",
			Signal{
				Identity: testIdentity(), Kind: asset.KindURL,
				Secrets:  []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: math.NaN()}},
				ScoredAt: fixedTime(1),
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ScoreSurface(tt.sig, ic, rc)
			if err == nil {
				t.Fatalf("NaN confidence must fail validation, got result %+v", out)
			}
			if !strings.Contains(err.Error(), "confidence") {
				t.Errorf("error %q must identify the confidence field", err)
			}
			if !reflect.DeepEqual(out, SurfaceAsset{}) {
				t.Errorf("error path must return no result, got %+v", out)
			}
		})
	}
}

// TestCombineMathNeverNaNForFiniteInput is defense in depth behind the
// validation guards: for ANY finite weights (including extremes outside
// [0,1], which the clamps absorb), combineFactors never returns NaN — the
// combination stays a finite value in [0,1] — and round4 never returns NaN
// for any finite input.
//
// Round 2 extended the invariant to NaN weights themselves: a NaN compares
// false against every clamp bound, so the NaN-safe clamps (clampWeight in
// combineFactors, clamp01, minf) map it to a real value — NaN can never
// produce a score contribution, even if a NaN weight somehow reached the
// combination math past Factor.validate's rejection.
func TestCombineMathNeverNaNForFiniteInput(t *testing.T) {
	smallest := math.SmallestNonzeroFloat64
	nearOne := math.Nextafter(1, 0) // largest float strictly below 1
	manyNearOne := make([]Factor, 2048)
	for i := range manyNearOne {
		manyNearOne[i] = Factor{Weight: nearOne}
	}
	nan := math.NaN()
	slices := [][]Factor{
		nil,
		{{Weight: 0}},
		{{Weight: 1}},
		{{Weight: smallest}},
		{{Weight: nearOne}},
		{{Weight: -math.MaxFloat64}, {Weight: math.MaxFloat64}}, // clamped to 0 and 1
		{{Weight: -0.0}, {Weight: 0.0}},
		{{Weight: 0.5}, {Weight: 0.25}, {Weight: 0.125}},
		manyNearOne,                    // product underflows to 0, never NaN
		{{Weight: nan}},                // NaN clamps to 0: no contribution
		{{Weight: nan}, {Weight: 0.5}}, // NaN cannot drag a real weight to NaN
		{{Weight: nan}, {Weight: 1}, {Weight: nan}}, // mixed NaN noise around a full weight
	}
	for i, fs := range slices {
		got := combineFactors(fs)
		if math.IsNaN(got) {
			t.Errorf("case %d: combineFactors = NaN", i)
		}
		if got < 0 || got > 1 {
			t.Errorf("case %d: combineFactors = %v, outside [0,1]", i, got)
		}
	}
	if got := combineFactors([]Factor{{Weight: nan}, {Weight: 0.5}}); got != 0.5 {
		t.Errorf("NaN + 0.5 combine = %v, want 0.5 (NaN contributes nothing)", got)
	}
	// The confidence clamp is NaN-safe in both directions.
	if got := clamp01(nan); got != 0 {
		t.Errorf("clamp01(NaN) = %v, want 0", got)
	}
	if got := clamp01(2.0); got != 1 {
		t.Errorf("clamp01(2) = %v, want 1", got)
	}
	if got := minf(nan, 0.7); got != 0.7 {
		t.Errorf("minf(NaN, 0.7) = %v, want 0.7", got)
	}
	if got := minf(0.7, nan); got != 0.7 {
		t.Errorf("minf(0.7, NaN) = %v, want 0.7", got)
	}
	for _, v := range []float64{
		0, 1, -1, smallest, nearOne, 0.00005, 1234.56789,
		math.MaxFloat64, -math.MaxFloat64,
	} {
		if r := round4(v); math.IsNaN(r) {
			t.Errorf("round4(%v) = NaN", v)
		}
	}
}

// TestFactorValidateRejectsNaNWeight pins the type-level NaN guard: NaN
// compares false against both comparison bounds of the old check
// (`w < 0 || w > 1`), so without the explicit math.IsNaN rejection a
// NaN-weight Factor would validate and propagate a NaN score through every
// combine it touches.
func TestFactorValidateRejectsNaNWeight(t *testing.T) {
	f := Factor{
		Name:     "interestingness:admin",
		Weight:   math.NaN(),
		Evidence: []string{"url:https://www.example.com/admin"},
		Reason:   "administrative path segment \"/admin\" observed",
	}
	if err := f.validate(); err == nil || !strings.Contains(err.Error(), "NaN") {
		t.Errorf("NaN-weight factor must be rejected with a NaN-identifying error, got %v", err)
	}
	f.Weight = 0.5
	if err := f.validate(); err != nil {
		t.Errorf("finite-weight factor must validate: %v", err)
	}
}

func TestKindSpecificScoring(t *testing.T) {
	ic, rc := mustCatalogs(t)
	cases := []struct {
		name string
		sig  Signal
		want float64 // minimum expected score
	}{
		{
			"endpoint path",
			Signal{Identity: testIdentity(), Kind: asset.KindEndpoint, Path: "/actuator/env"},
			0.59, // actuator 0.6; a single category stays at/below the 0.6 cap
		},
		{
			"javascript size",
			Signal{Identity: asset.Identity{Kind: asset.KindJavaScript, Value: "https://x.example.com/bundle.js"}, Kind: asset.KindJavaScript, JSBundleBytes: 2 << 20, Path: "/bundle.js"},
			0.29,
		},
		{
			"secret type",
			Signal{Identity: testIdentity(), Kind: asset.KindURL, Secrets: []SecretSignal{{Type: asset.SecretTypeAWS, Confidence: 0.95}}},
			0.7,
		},
		{
			"port",
			Signal{Identity: testIdentity(), Kind: asset.KindPort, Port: 8080},
			0.34,
		},
		{
			"private host",
			Signal{Identity: testIdentity(), Kind: asset.KindURL, Hostname: "192.168.1.10"},
			0.49,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tt.sig.ScoredAt = fixedTime(1)
			out, err := ScoreSurface(tt.sig, ic, rc)
			if err != nil {
				t.Fatal(err)
			}
			if out.Score < tt.want {
				t.Errorf("score %v < expected minimum %v (factors %v)", out.Score, tt.want, out.Factors)
			}
			if out.Score > 1 || out.Score < 0 {
				t.Errorf("score out of [0,1]")
			}
		})
	}
}

func TestScoreInputValidation(t *testing.T) {
	ic, rc := mustCatalogs(t)
	if _, err := ScoreSurface(Signal{}, ic, rc); err == nil {
		t.Error("zero identity must fail")
	}
	// A kind without a value is not a canonical identity (the F-2 gate).
	emptyValue := testIdentity()
	emptyValue.Value = ""
	if _, err := ScoreSurface(Signal{Identity: emptyValue, Kind: "url"}, ic, rc); err == nil ||
		!strings.Contains(err.Error(), "identity value must not be empty") {
		t.Errorf("empty identity value must fail with a named error, got %v", err)
	}
	if _, err := ScoreSurface(Signal{Identity: testIdentity()}, ic, rc); err == nil {
		t.Error("empty kind must fail")
	}
	if _, err := ScoreSurface(Signal{Identity: testIdentity(), Kind: "url"}, nil, rc); err == nil {
		t.Error("nil catalog must fail")
	}
	bad := []Signal{
		{Identity: testIdentity(), Kind: "url", Path: string(make([]byte, maxSignalPathBytes+1))},
		{Identity: testIdentity(), Kind: "url", ParameterNames: make([]string, maxSignalParams+1)},
		{Identity: testIdentity(), Kind: "url", Technologies: []TechSignal{{Name: "x", Confidence: 1.5}}},
		{Identity: testIdentity(), Kind: "url", Secrets: []SecretSignal{{Type: asset.SecretType("bogus")}}},
		{Identity: testIdentity(), Kind: "url", Headers: []string{""}},
		{Identity: testIdentity(), Kind: "url", JSBundleBytes: -1},
		{Identity: testIdentity(), Kind: "url", Port: 70000},
		{Identity: testIdentity(), Kind: "url", Observations: -1},
	}
	for i, sig := range bad {
		if _, err := ScoreSurface(sig, ic, rc); err == nil {
			t.Errorf("invalid signal %d must fail", i)
		}
	}
}

func TestFactorBoundAndCapDeterministic(t *testing.T) {
	// A pathological signal with more factor groups than maxFactors keeps
	// the highest-weight set deterministically.
	var techs []TechSignal
	for i := 0; i < maxSignalTechs; i++ {
		techs = append(techs, TechSignal{Name: fmt.Sprintf("tech%02d", i), Category: "framework", Confidence: 0.5})
	}
	ic, rc := mustCatalogs(t)
	sig := Signal{
		Identity: testIdentity(), Kind: asset.KindURL,
		Path:         "/api/v2/admin/actuator/swagger/debug/graphql",
		Technologies: techs,
		ScoredAt:     fixedTime(1),
	}
	a, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Factors) > maxFactors {
		t.Errorf("factor list = %d over bound %d", len(a.Factors), maxFactors)
	}
	b, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("capping must stay deterministic")
	}
	if got := recompose(a.Factors); got != a.Score {
		t.Errorf("capped factors must still recompose to the score: %v != %v", got, a.Score)
	}
}
