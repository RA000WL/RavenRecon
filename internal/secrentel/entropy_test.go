package secrentel

import (
	"strings"
	"testing"
)

// detRand synthesizes deterministic high-entropy strings: character i comes
// from charset[(i*step+offset) % len(charset)], so every position differs
// from its neighbors and the run is reproducible without math/rand.
func detRand(n int, charset string, step, offset int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(charset[(i*step+offset)%len(charset)])
	}
	return b.String()
}

const alnumMixed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestAssessEntropyKnownValues(t *testing.T) {
	cases := []struct {
		name       string
		value      string
		class      string
		shannon    float64
		normalized float64
	}{
		{"uniform hex", "aaaaaaaa", "hex", 0, 0},
		{"mixed hex", "0123456789abcdef", "hex", 4, 1},
		{"alnum mixed", "aB3xK9", "base64url", 2.585, 0.4308},
		{"word lowercase", "password", "base64url", 2.75, 0.4583},
		{"base64 symbols", "ab+/12==", "base64", 2.75, 0.4583},
		{"base64url symbols", "ab-_12", "base64url", 2.585, 0.4308},
		{"other class", "a b c d", "other", 2.1281, 0.9165},
		{"empty", "", "", 0, 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a := AssessEntropy(tt.value)
			if a.Class != tt.class {
				t.Errorf("class = %q, want %q", a.Class, tt.class)
			}
			if a.Shannon != tt.shannon {
				t.Errorf("shannon = %v, want %v", a.Shannon, tt.shannon)
			}
			if a.Normalized != tt.normalized {
				t.Errorf("normalized = %v, want %v", a.Normalized, tt.normalized)
			}
		})
	}
}

func TestAssessEntropyShapes(t *testing.T) {
	// UUID recognition.
	a := AssessEntropy("550e8400-e29b-41d4-a716-446655440000")
	if !a.IsUUID {
		t.Error("canonical UUID must be recognized")
	}
	if a.Class != "base64url" {
		// dashes are valid base64url alphabet bytes; only hex letters also
		// fit the hex class, so the combined class is base64url.
		t.Errorf("UUID class = %q, want base64url", a.Class)
	}
	if AssessEntropy("550e8400-e29b-41d4-a716-44665544000").IsUUID {
		t.Error("non-canonical UUID must not be recognized")
	}

	// JWT shape recognition.
	a = AssessEntropy("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if !a.IsJWT {
		t.Error("JWT shape must be recognized")
	}
	if AssessEntropy("eyJhbGciOiJIUzI1NiJ9.not!jwt.two").IsJWT {
		t.Error("a non-base64url middle segment is not a JWT shape")
	}

	// Length weighting: a 16-char value weighs 0.5, a 40-char value 1.0.
	a = AssessEntropy(detRand(16, alnumMixed, 7, 0))
	if a.LengthWeight != 0.5 {
		t.Errorf("length weight = %v, want 0.5", a.LengthWeight)
	}
	a = AssessEntropy(detRand(40, alnumMixed, 7, 0))
	if a.LengthWeight != 1 {
		t.Errorf("length weight = %v, want 1", a.LengthWeight)
	}
	if a.Randomness != a.Normalized {
		t.Errorf("randomness = %v, want normalized %v (weight 1)", a.Randomness, a.Normalized)
	}

	// Word-like detection.
	if !AssessEntropy("passwordpassword").looksWordLike() {
		t.Error("repeated word must look word-like")
	}
	if AssessEntropy(detRand(40, alnumMixed, 7, 1)).looksWordLike() {
		t.Error("high-entropy value must not look word-like")
	}
}

func TestEntropySatisfiesRule(t *testing.T) {
	high := AssessEntropy(detRand(40, alnumMixed, 7, 2)) // ~5.36 bits, ~0.9 normalized
	low := AssessEntropy("aaaaaaaaaaaaaaaa")             // 0 entropy

	rule := entropyRuleView{MinShannon: 3.0, MinNormalized: 0.55}
	if !high.satisfies(rule) {
		t.Error("high-entropy value must satisfy the rule")
	}
	if low.satisfies(rule) {
		t.Error("uniform value must fail the rule")
	}
	if !low.satisfies(entropyRuleView{}) {
		t.Error("an empty rule is always satisfied")
	}
}

func TestEntropyCacheMemoizesAndBounds(t *testing.T) {
	c := newEntropyCache()
	v := detRand(48, alnumMixed, 11, 5)
	a1 := c.assess(v)
	a2 := c.assess(v)
	if a1 != a2 {
		t.Error("repeated assessment must be memoized (equal results)")
	}
	if len(c.m) != 1 {
		t.Errorf("cache holds %d entries, want 1", len(c.m))
	}

	// The memoization map is bounded: distinct values beyond the cap are
	// still assessed but not retained.
	c2 := newEntropyCache()
	for i := 0; i < maxEntropyCacheEntries+50; i++ {
		c2.assess(detRand(32, alnumMixed, 7, i))
	}
	if len(c2.m) > maxEntropyCacheEntries {
		t.Errorf("cache grew to %d entries, want <= %d", len(c2.m), maxEntropyCacheEntries)
	}
}
