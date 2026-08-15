package techintel

import (
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// Confidence thresholds and caps. All are fixed constants, deliberately NOT
// configuration: the confidence model is a documented contract, not a tuning
// knob.
const (
	// highScoreThreshold: scores at or above 0.8 are High.
	highScoreThreshold = 0.8
	// mediumScoreThreshold: scores at or above 0.5 (and below 0.8) are Medium.
	mediumScoreThreshold = 0.5
	// lowScoreThreshold: scores at or above 0.2 (and below 0.5) are Low.
	lowScoreThreshold = 0.2

	// spoofableScoreCap caps the score of a technology whose every matched
	// indicator is spoofable (tier Spoofable). No spoofable-only technology
	// can reach High; the cap pins such technologies at Medium even when the
	// raw combination would clear the High threshold.
	spoofableScoreCap = 0.59

	// weakIndicatorWeight is the lone-weak-indicator boundary: a technology
	// that fired on exactly ONE independent indicator with a weight below
	// this value never exceeds Low.
	weakIndicatorWeight = 0.35
)

// ConfidenceLevel is the typed confidence classification of one technology
// detection. String values are the canonical lowercase forms; unknown values
// are rejected by ParseConfidenceLevel.
type ConfidenceLevel string

const (
	// LevelHigh: score >= 0.8 with at least one structural indicator.
	LevelHigh ConfidenceLevel = "high"
	// LevelMedium: score >= 0.5, or a spoofable-only technology capped.
	LevelMedium ConfidenceLevel = "medium"
	// LevelLow: score >= 0.2, or a lone weak indicator.
	LevelLow ConfidenceLevel = "low"
	// LevelUnknown: score below 0.2. Still reported, but as a weak signal.
	LevelUnknown ConfidenceLevel = "unknown"
)

// String returns the canonical lowercase level label.
func (l ConfidenceLevel) String() string { return string(l) }

// Valid reports whether l is a known confidence level.
func (l ConfidenceLevel) Valid() bool {
	switch l {
	case LevelHigh, LevelMedium, LevelLow, LevelUnknown:
		return true
	}
	return false
}

// ParseConfidenceLevel parses a canonical level label.
func ParseConfidenceLevel(s string) (ConfidenceLevel, error) {
	l := ConfidenceLevel(s)
	if !l.Valid() {
		return "", fmt.Errorf("invalid confidence level %q", s)
	}
	return l, nil
}

// rank orders levels from weakest to strongest; it is used for deterministic
// level comparisons (min/max).
func (l ConfidenceLevel) rank() int {
	switch l {
	case LevelUnknown:
		return 0
	case LevelLow:
		return 1
	case LevelMedium:
		return 2
	case LevelHigh:
		return 3
	}
	return -1
}

// weaker reports whether l is a strictly weaker level than o.
func (l ConfidenceLevel) weaker(o ConfidenceLevel) bool { return l.rank() < o.rank() }

// stronger reports whether l is a strictly stronger level than o.
func (l ConfidenceLevel) stronger(o ConfidenceLevel) bool { return l.rank() > o.rank() }

// levelForScore maps a raw score to its threshold level. The spoofable-only
// cap and the lone-weak-indicator rule are applied by deriveConfidence, not
// here.
func levelForScore(score float64) ConfidenceLevel {
	switch {
	case score >= highScoreThreshold:
		return LevelHigh
	case score >= mediumScoreThreshold:
		return LevelMedium
	case score >= lowScoreThreshold:
		return LevelLow
	default:
		return LevelUnknown
	}
}

// indicatorGroup is ONE independent match the analyzer recorded for a
// fingerprint: the indicator kind and slot it matched in, and the indicator's
// weight.
//
// Independence is defined exactly: two matches are INDEPENDENT when their
// indicator KINDS differ or their SLOTS differ. Two matches of the same kind
// in the same slot are the same observation evidence (for example two
// indicators both substrings of one header line) and combine by max weight.
type indicatorGroup struct {
	kind   fingerprints.IndicatorKind
	slot   int
	weight float64
}

// deriveConfidence computes the score and confidence level for one fired
// technology from its independent indicator groups.
//
// Score = 1 − ∏(1 − wᵢ) over independent groups (groups of the same
// kind+slot collapse to their max weight). Then the documented caps apply:
//
//  1. spoofable-only: when NO matched indicator is structural (tier
//     Structural), the score is capped at spoofableScoreCap (0.59), so the
//     level can never exceed Medium;
//  2. lone weak indicator: when exactly ONE independent group fired and its
//     weight is below weakIndicatorWeight (0.35), the level never exceeds
//     Low (the raw score is kept; the threshold mapping already produces
//     Low for such scores — the rule is a documented guarantee, applied
//     explicitly);
//  3. thresholds: score >= 0.8 High, >= 0.5 Medium, >= 0.2 Low, else
//     Unknown. Unknown technologies are still reported.
//
// The returned score is the capped score (after rule 1), so stored levels
// and scores are mutually consistent for the decode re-check.
func deriveConfidence(groups []indicatorGroup) (float64, ConfidenceLevel) {
	if len(groups) == 0 {
		return 0, LevelUnknown
	}

	// Collapse dependent (same kind+slot) groups to their max weight.
	merged := make([]indicatorGroup, 0, len(groups))
	for _, g := range groups {
		placed := false
		for i := range merged {
			if merged[i].kind == g.kind && merged[i].slot == g.slot {
				if g.weight > merged[i].weight {
					merged[i].weight = g.weight
				}
				placed = true
				break
			}
		}
		if !placed {
			merged = append(merged, g)
		}
	}

	hasStructural := false
	score := 1.0
	for _, g := range merged {
		w := g.weight
		if w < 0 {
			w = 0
		}
		if w > 1 {
			w = 1
		}
		score *= 1 - w
		if g.kind.Tier() == fingerprints.TierStructural {
			hasStructural = true
		}
	}
	score = 1 - score

	// Rule 1: spoofable-only cap.
	if !hasStructural && score > spoofableScoreCap {
		score = spoofableScoreCap
	}

	level := levelForScore(score)

	// Rule 2: lone weak indicator never exceeds Low.
	if len(merged) == 1 && merged[0].weight < weakIndicatorWeight && level.stronger(LevelLow) {
		level = LevelLow
	}
	return score, level
}
