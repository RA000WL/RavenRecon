package secrentel

import (
	"math"
	"regexp"
)

// EntropyAssessment is the entropy engine's full classification of one
// candidate value. It is a pure observation — it never classifies a secret
// by itself (see the package doc: entropy alone NEVER classifies).
type EntropyAssessment struct {
	// Shannon is the Shannon entropy of the value in bits per character.
	Shannon float64 `json:"shannon"`
	// Class is the observed character class: "hex", "base64url", "base64",
	// "alnum", or "other".
	Class string `json:"class"`
	// ClassMax is the maximum possible entropy of the class (log2 of the
	// alphabet size); for "other" it is the log2 of the value's own distinct
	// character count.
	ClassMax float64 `json:"class_max"`
	// Normalized is Shannon / ClassMax, capped at 1: how close the value is
	// to maximal randomness for its class.
	Normalized float64 `json:"normalized"`
	// Length is the value length in bytes.
	Length int `json:"length"`
	// IsUUID reports the canonical 8-4-4-4-12 hex UUID shape.
	IsUUID bool `json:"is_uuid,omitempty"`
	// IsJWT reports the three-segment eyJ… . eyJ… . sig shape.
	IsJWT bool `json:"is_jwt,omitempty"`
	// LengthWeight scales randomness by length (values under 32 bytes are
	// progressively weaker random evidence): min(1, len/32).
	LengthWeight float64 `json:"length_weight"`
	// Randomness is Normalized * LengthWeight — the single comparable
	// randomness score in [0,1].
	Randomness float64 `json:"randomness"`
}

// class alphabets, in detection order (hex ⊂ alnum, base64url ⊂ alnum…).
const (
	classHexMax        = 4.0              // log2(16)
	classBase64Max     = 6.0              // log2(64)
	classAlnumMax      = 5.95419631038687 // log2(62)
	classOtherMaxFloor = 1.0
)

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	jwtRe  = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// entropyCache is the engine's bounded memoization of per-value assessments
// (minified bundles repeat the same values constantly; the spec's "avoid
// repeated entropy calculations"). Bounded to maxEntropyCacheEntries; the
// map is drop-new beyond the bound (first N distinct values win, which is
// deterministic for a fixed document because scanning order is fixed).
type entropyCache struct {
	m map[string]EntropyAssessment
}

const maxEntropyCacheEntries = 4096

func newEntropyCache() *entropyCache {
	return &entropyCache{m: make(map[string]EntropyAssessment)}
}

// assess computes (or replays) the entropy assessment of value.
func (c *entropyCache) assess(value string) EntropyAssessment {
	if a, ok := c.m[value]; ok {
		return a
	}
	a := AssessEntropy(value)
	if len(c.m) < maxEntropyCacheEntries {
		c.m[value] = a
	}
	return a
}

// AssessEntropy is the pure entropy classification of one value.
//
// It computes byte-level Shannon entropy, detects the character class (hex,
// base64url, base64, alnum, other — in that order, most restrictive first),
// normalizes against the class maximum, recognizes UUID and JWT shapes,
// and applies the length weighting (a 12-character value is weaker random
// evidence than a 40-character one). Results are rounded to 4 decimal places
// for deterministic storage and comparison.
func AssessEntropy(value string) EntropyAssessment {
	a := EntropyAssessment{Length: len(value)}
	if a.Length == 0 {
		return a
	}

	// Shannon over byte frequencies; class detection in the same pass
	// (most restrictive class wins: hex ⊂ base64url/b64 ⊂ alnum).
	freq := make(map[byte]float64, 64)
	isHex, isB64URL, isB64, isAlnum := true, true, true, true
	for i := 0; i < len(value); i++ {
		b := value[i]
		freq[b]++
		digit := b >= '0' && b <= '9'
		lower := b >= 'a' && b <= 'z'
		upper := b >= 'A' && b <= 'Z'
		alnum := digit || lower || upper
		if !(digit || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			isHex = false
		}
		if !(alnum || b == '-' || b == '_') {
			isB64URL = false
		}
		if !(alnum || b == '+' || b == '/' || b == '=') {
			isB64 = false
		}
		if !alnum {
			isAlnum = false
		}
	}

	n := float64(len(value))
	for _, f := range freq {
		p := f / n
		a.Shannon -= p * math.Log2(p)
	}

	switch {
	case isHex:
		a.Class, a.ClassMax = "hex", classHexMax
	case isB64URL:
		a.Class, a.ClassMax = "base64url", classBase64Max
	case isB64:
		a.Class, a.ClassMax = "base64", classBase64Max
	case isAlnum:
		a.Class, a.ClassMax = "alnum", classAlnumMax
	default:
		a.Class = "other"
		a.ClassMax = math.Log2(float64(len(freq)))
		if a.ClassMax < classOtherMaxFloor {
			a.ClassMax = classOtherMaxFloor
		}
	}
	if a.ClassMax > 0 {
		a.Normalized = a.Shannon / a.ClassMax
		if a.Normalized > 1 {
			a.Normalized = 1
		}
	}

	a.IsUUID = uuidRe.MatchString(value)
	a.IsJWT = jwtRe.MatchString(value)
	a.LengthWeight = math.Min(1, float64(len(value))/32)
	a.Randomness = a.Normalized * a.LengthWeight

	a.Shannon = round4(a.Shannon)
	a.ClassMax = round4(a.ClassMax)
	a.Normalized = round4(a.Normalized)
	a.LengthWeight = round4(a.LengthWeight)
	a.Randomness = round4(a.Randomness)
	return a
}

// satisfies reports whether the assessment meets a pattern's entropy rule.
func (a EntropyAssessment) satisfies(rule entropyRuleView) bool {
	if rule.MinShannon > 0 && a.Shannon < rule.MinShannon {
		return false
	}
	if rule.MinNormalized > 0 {
		// The normalized check is only meaningful against the pattern's
		// expected class; when the observed class differs the observed
		// class's own normalization is used (a hex value assessed against a
		// base64 expectation is normalized against hex's maximum, which the
		// assessment already carries).
		if a.Normalized < rule.MinNormalized {
			return false
		}
	}
	return true
}

// entropyRuleView is the local view of patterns.EntropyRule (kept as a tiny
// interface-free struct so the engine can be tested without the DB).
type entropyRuleView struct {
	MinShannon    float64
	MinNormalized float64
	Class         string
}

// round4 rounds to 4 decimal places for deterministic storage.
func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

// looksRandomWord reports whether a value is word-like rather than random:
// low normalized entropy for its class. Used by the false-positive engine.
func (a EntropyAssessment) looksWordLike() bool {
	return a.Normalized < 0.5
}
