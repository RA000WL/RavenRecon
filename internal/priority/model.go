package priority

import (
	"fmt"
	"math"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// PriorityLevel is the typed priority classification of one scored surface.
// String values are canonical lowercase forms; unknown values are rejected
// by ParsePriorityLevel (mirroring secrentel.Level).
type PriorityLevel string

const (
	// LevelHigh: score >= 0.8 with at least TWO independent indicator
	// categories matched.
	LevelHigh PriorityLevel = "high"
	// LevelMedium: score >= 0.5 with at least one indicator category.
	LevelMedium PriorityLevel = "medium"
	// LevelLow: score >= 0.2.
	LevelLow PriorityLevel = "low"
	// LevelUnknown: score below 0.2, or a zero-signal surface. Still
	// reported.
	LevelUnknown PriorityLevel = "unknown"
)

// String returns the canonical lowercase level label.
func (l PriorityLevel) String() string { return string(l) }

// Valid reports whether l is a known level.
func (l PriorityLevel) Valid() bool {
	switch l {
	case LevelHigh, LevelMedium, LevelLow, LevelUnknown:
		return true
	}
	return false
}

// ParsePriorityLevel parses a canonical level label.
func ParsePriorityLevel(s string) (PriorityLevel, error) {
	l := PriorityLevel(s)
	if !l.Valid() {
		return "", fmt.Errorf("invalid priority level %q", s)
	}
	return l, nil
}

// rank orders levels weakest→strongest.
func (l PriorityLevel) rank() int {
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

// Bounds applied to model structures (fixed constants).
const (
	// maxFactorNameBytes bounds a factor name.
	maxFactorNameBytes = 128
	// maxReasonBytes bounds a factor reason.
	maxReasonBytes = 256
	// maxRecommendationBytes bounds a rendered factor recommendation (the
	// catalog-side template bound in catalog.go guarantees the worst-case
	// rendered recommendation stays within this bound by construction).
	maxRecommendationBytes = 256
	// maxEvidencePerFactor bounds the evidence reference list of one factor.
	maxEvidencePerFactor = 8
)

// Factor is one named, fully explained contribution to a surface's score.
//
// Every factor with a nonzero Weight MUST carry at least one Evidence
// reference (a canonical asset identity string, e.g. "url:https://…" or a
// relationship ID) and a non-empty Reason; ScoreSurface enforces this as an
// internal invariant and the tests pin it — a score can never rest on an
// unexplained signal.
type Factor struct {
	// Name identifies the factor's group and category, e.g.
	// "interestingness:admin" or "risk:high-value-secret".
	Name string `json:"name"`

	// Weight is the factor's contribution strength in [0,1].
	Weight float64 `json:"weight"`

	// Evidence holds the canonical asset identity strings (or relationship
	// IDs) the factor references — the audit trail from score to
	// observation.
	Evidence []string `json:"evidence,omitempty"`

	// Reason is the human-readable explanation of why this factor fired.
	Reason string `json:"reason"`

	// Recommendation is the rendered reconnaissance guidance for the
	// indicator that fired this factor (empty for confidence factors, which
	// are not indicator-driven). It is rendered at score time from the
	// catalog entry's template — its single %s substituted with the matched
	// term — so it is derivable from the emitted factor list alone and
	// survives cache round-trips verbatim. Guidance language only: never an
	// exploitation instruction, never a vulnerability claim.
	Recommendation string `json:"recommendation,omitempty"`
}

// validate checks the factor contract: bounded name and reason, weight in
// [0,1] (NaN rejected explicitly — NaN compares false against every bound and
// would otherwise propagate a NaN score), and — for nonzero weights — at
// least one evidence reference.
func (f Factor) validate() error {
	if f.Name == "" || len(f.Name) > maxFactorNameBytes {
		return fmt.Errorf("factor name %q is empty or over %d bytes", f.Name, maxFactorNameBytes)
	}
	if math.IsNaN(f.Weight) || f.Weight < 0 || f.Weight > 1 {
		return fmt.Errorf("factor %q weight %v is NaN or out of [0,1]", f.Name, f.Weight)
	}
	if len(f.Reason) == 0 || len(f.Reason) > maxReasonBytes {
		return fmt.Errorf("factor %q reason is empty or over %d bytes", f.Name, maxReasonBytes)
	}
	if len(f.Recommendation) > maxRecommendationBytes {
		return fmt.Errorf("factor %q recommendation is over %d bytes", f.Name, maxRecommendationBytes)
	}
	if f.Weight > 0 && len(f.Evidence) == 0 {
		return fmt.Errorf("factor %q with weight %v carries no evidence", f.Name, f.Weight)
	}
	if len(f.Evidence) > maxEvidencePerFactor {
		return fmt.Errorf("factor %q carries %d evidence refs over bound %d", f.Name, len(f.Evidence), maxEvidencePerFactor)
	}
	return nil
}

// SurfaceAsset is the canonical scored-surface model: one Phase 2 asset
// with its composed priority, its complete reasoning, and its timing. It is
// the unit Round 2's engine will emit, cache, and report.
type SurfaceAsset struct {
	// Identity is the canonical identity of the scored Phase 2 asset.
	Identity asset.Identity `json:"identity"`

	// Kind is the asset kind of Identity (mirrored for convenience).
	Kind asset.Kind `json:"kind"`

	// Score is the composed priority score in [0,1], rounded to 4 decimals.
	Score float64 `json:"score"`

	// Level is the gated classification of Score.
	Level PriorityLevel `json:"level"`

	// Interestingness is the catalog-driven sub-score: the combined weight
	// of every matched interestingness category (after per-category caps),
	// rounded to 4 decimals.
	Interestingness float64 `json:"interestingness"`

	// Confidence is the observed-evidence sub-score, composed ONLY from
	// confidences the earlier phases actually recorded (technology and
	// secret candidate Prov.Confidence, cross-source observation counts).
	// It is never invented.
	Confidence float64 `json:"confidence"`

	// Factors is the complete reasoning behind Score — interestingness,
	// risk, and confidence factors in deterministic order.
	Factors []Factor `json:"factors"`

	// FirstSeen is the earliest observation time of the underlying asset
	// (an explicit input; the engine reads no clock).
	FirstSeen time.Time `json:"first_seen"`

	// ScoredAt is the scoring timestamp (an explicit input; the engine
	// reads no clock).
	ScoredAt time.Time `json:"scored_at"`
}
