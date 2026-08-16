package secrentel

import (
	"fmt"
	"math"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Level is the typed confidence classification of one secret candidate.
// String values are canonical lowercase forms.
type Level string

const (
	// LevelHigh: score >= 0.8 with at least TWO independent non-pattern
	// factors (never one signal).
	LevelHigh Level = "high"
	// LevelMedium: score >= 0.5 with at least one non-pattern factor (or a
	// >=0.85-strength pattern with entropy support).
	LevelMedium Level = "medium"
	// LevelLow: score >= 0.2, and the mandatory cap for documentation/test
	// contexts, generic families, and public keys.
	LevelLow Level = "low"
	// LevelUnknown: score below 0.2. Still reported.
	LevelUnknown Level = "unknown"
)

// String returns the canonical lowercase level label.
func (l Level) String() string { return string(l) }

// Valid reports whether l is a known level.
func (l Level) Valid() bool {
	switch l {
	case LevelHigh, LevelMedium, LevelLow, LevelUnknown:
		return true
	}
	return false
}

// ParseLevel parses a canonical level label.
func ParseLevel(s string) (Level, error) {
	l := Level(s)
	if !l.Valid() {
		return "", fmt.Errorf("invalid confidence level %q", s)
	}
	return l, nil
}

// rank orders levels weakest→strongest.
func (l Level) rank() int {
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

// Factor is one named confidence contribution.
type Factor struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

// ConfidenceResult is the confidence engine's verdict for one candidate: the
// combined score, the level, and every contributing factor (the model is
// fully inspectable — no anonymous scores).
type ConfidenceResult struct {
	Score   float64  `json:"score"`
	Level   Level    `json:"level"`
	Factors []Factor `json:"factors"`
}

// Confidence contract constants. All fixed, deliberately NOT configuration:
// the model is a documented contract (mirroring techintel).
const (
	// Factor weights.
	entropyStrongWeight  = 0.35 // entropy rule satisfied with headroom
	entropyWeakWeight    = 0.15 // entropy rule satisfied marginally
	contextStrongWeight  = 0.4  // provider/hint matched in the variable or JSON key
	contextWeakWeight    = 0.15 // an assignment name exists, no hint match
	techWeight           = 0.25 // provider-matching technology observed
	endpointWeight       = 0.3  // provider endpoint observed in the document
	urlCredentialsWeight = 0.3  // URL-shaped value carries user:pass@ authority
	pairWeight           = 0.45 // sibling candidate of the same provider present
	repeatWeight         = 0.2  // same (type, value) observed in >= 2 documents

	// Caps.
	fpContextCap  = 0.45 // documentation/test context: never above Low
	genericCap    = 0.45 // generic family ("random base64"): never above Low
	publicKeyCap  = 0.35 // public keys are not secrets: never above Low
	structuredCap = 0.59 // a structured match with ZERO supporting factors
	// stays Medium-or-below: a prefix alone is
	// not high confidence
	urlTypeCap = lowThreshold // pure-endpoint URL shapes (S3 bucket,
	// credential-less database_url, Firebase database URL): never above Low

	// Thresholds.
	highThreshold   = 0.8
	mediumThreshold = 0.5
	lowThreshold    = 0.2

	// Level gates: High needs >= 2 non-pattern factors; Medium needs >= 1
	// (or strength >= strongSoloPattern with entropy support).
	strongSoloPattern = 0.85
)

// confidenceInput is everything the confidence engine considers for one
// candidate. The pattern factor is always present (a candidate exists only
// because a pattern matched); every other factor is optional evidence.
type confidenceInput struct {
	Strength   float64 // winning pattern's strength
	Family     string  // structured / contextual / generic / public
	Type       asset.SecretType
	Value      string   // the candidate's matched value
	EntropyOK  bool     // entropy rule satisfied
	EntropyHit bool     // strong randomness beyond the rule
	Context    Context  // extracted context (NameHint = strong)
	TechHit    string   // matched provider technology ("" = none)
	Endpoint   string   // matched provider endpoint ("" = none)
	Pair       bool     // same-provider sibling candidate exists
	FPFlags    []string // context-level false-positive flags
}

// deriveConfidence computes score and level from the input's factors.
//
// Score = 1 − ∏(1 − wᵢ) over the recorded factors (independent signals
// accumulate, mirroring techintel's model). Then the documented caps apply
// through expectedCapFor — documentation/test context → fpContextCap;
// generic family → genericCap; public family → publicKeyCap; a structured
// match with zero supporting factors → structuredCap; a pure-endpoint URL
// type (S3 bucket, credential-less database_url, Firebase database URL) →
// urlTypeCap (lowThreshold, recorded as the weight-0 url_type_cap factor).
// Finally the level gates: High requires at least two non-pattern factors,
// Medium at least one (or a strongSoloPattern-strength pattern with entropy
// support).
//
// Two URL overreach rules are encoded here: the endpoint factor fires only
// when the endpoint indicator is NOT part of the candidate's own value (a
// URL whose value literally contains the provider endpoint was already
// counted by its pattern — double counting), and a structured URL-shaped
// value with a user:pass@ authority earns the url_credentials factor
// (genuine credential material, independent of the hostname shape).
func deriveConfidence(in confidenceInput) ConfidenceResult {
	var factors []Factor
	factors = append(factors, Factor{Name: "pattern", Weight: in.Strength})

	add := func(f Factor) {
		factors = append(factors, f)
	}

	if in.EntropyOK {
		w := entropyWeakWeight
		if in.EntropyHit {
			w = entropyStrongWeight
		}
		add(Factor{Name: "entropy", Weight: w})
	}
	if in.Context.NameHint != "" {
		add(Factor{Name: "context", Weight: contextStrongWeight, Detail: in.Context.NameHint})
	} else if in.Context.Variable != "" || in.Context.JSONKey != "" {
		add(Factor{Name: "context", Weight: contextWeakWeight})
	}
	if in.TechHit != "" {
		add(Factor{Name: "technology", Weight: techWeight, Detail: in.TechHit})
	}
	// Endpoint evidence is suppressed when the endpoint indicator is inside
	// the candidate's own value: the value already IS the provider endpoint
	// (an S3 bucket URL, a Firebase database URL, a webhook URL), so the
	// pattern counted it once; counting it again as correlation is
	// double-counting.
	if in.Endpoint != "" && !containsFold(in.Value, in.Endpoint) {
		add(Factor{Name: "endpoint", Weight: endpointWeight, Detail: in.Endpoint})
	}
	if in.Family == "structured" && hasURLUserinfo(in.Value) {
		add(Factor{Name: "url_credentials", Weight: urlCredentialsWeight})
	}
	if in.Pair {
		add(Factor{Name: "pair", Weight: pairWeight})
	}

	urlCapped := urlTypeCapped(in.Type)
	if urlCapped {
		// Weight-0 cap marker: records the clamp honestly without ever
		// counting as evidence toward the level gates.
		factors = append(factors, Factor{Name: "url_type_cap", Weight: 0, Detail: "endpoint URL shape: capped at Low by contract"})
	}

	// Supporting-factor count by the canonical rule (countNonPattern): every
	// factor except "pattern" and the weight-0 "url_type_cap" marker.
	nonPattern := countNonPattern(factors)

	score := combineFactors(factors)
	level := levelForScore(score)

	// Caps, through the single cap-rule source (expectedCapFor): the
	// tightest bound this candidate's type, family, flags, and factor count
	// allow.
	score = math.Min(score, expectedCapFor(in.Type, in.Family, in.FPFlags, nonPattern))
	score = round4(score)
	level = levelForScore(score)

	// Level gates.
	if level == LevelHigh && nonPattern < 2 {
		level = LevelMedium
	}
	if level == LevelMedium && nonPattern == 0 && !(in.Strength >= strongSoloPattern && in.EntropyOK) {
		level = LevelLow
	}
	return ConfidenceResult{Score: score, Level: level, Factors: factors}
}

// expectedCapFor returns the tightest cap the confidence contract applies
// to a candidate: documentation/test context (fpContextCap), the generic
// and public family caps, the structured zero-supporting-factor cap
// (structuredCap), and the pure-endpoint URL type clamp (urlTypeCap) —
// whichever binds first. nonPattern counts the candidate's supporting
// factors exactly as deriveConfidence counts them (every factor except
// "pattern" and the weight-0 "url_type_cap" marker; the pair factor
// appended by applyPairFactor counts, matching the stored record).
//
// This is the SINGLE source of the cap rules: deriveConfidence applies it
// to every fresh score, recomputeCapped re-applies it on the pair/repeat
// recompute paths, and decodeStoredScan re-derives the same cap from a
// stored record's own type/family/flags/factors so a tampered score above
// it is rejected, never served.
func expectedCapFor(typ asset.SecretType, family string, fpFlags []string, nonPattern int) float64 {
	c := 1.0
	if len(fpFlags) > 0 {
		c = math.Min(c, fpContextCap)
	}
	switch family {
	case "generic":
		c = math.Min(c, genericCap)
	case "public":
		c = math.Min(c, publicKeyCap)
	case "structured":
		if nonPattern == 0 {
			c = math.Min(c, structuredCap)
		}
	}
	if urlTypeCapped(typ) {
		c = math.Min(c, urlTypeCap)
	}
	return c
}

// urlTypeCapped reports whether typ is a pure-endpoint URL shape whose
// confidence is capped at Low by contract: the URL itself is observation
// material (attack-surface context), not a secret. Webhook URLs are
// deliberately NOT capped — a Discord or Slack webhook endpoint IS
// genuinely sensitive.
func urlTypeCapped(typ asset.SecretType) bool {
	switch typ {
	case asset.SecretTypeS3, asset.SecretTypeDatabaseURL, asset.SecretTypeFirebase:
		return true
	}
	return false
}

// hasURLUserinfo reports whether value is a scheme://user:pass@host-shaped
// URL: a "://" separator followed by an authority containing "@" before the
// first path/query/fragment separator. Connection strings carry real
// credentials only when the authority has userinfo.
func hasURLUserinfo(value string) bool {
	i := strings.Index(value, "://")
	if i < 0 {
		return false
	}
	rest := value[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	return strings.Contains(rest[:end], "@")
}

// applyPairFactor recomputes a derived confidence with the same-provider
// sibling-pair factor appended (applied after the base derivation, once
// candidate IDs are final). Caps and gates re-apply through the same pure
// functions, with the pair counted as a non-pattern factor; the
// pure-endpoint URL type clamp re-applies through expectedCapFor so a
// pair-boosted bucket URL can never escape its Low ceiling.
func applyPairFactor(c ConfidenceResult, typ asset.SecretType, family string, fpFlags []string) ConfidenceResult {
	cp := ConfidenceResult{
		Score:   c.Score,
		Level:   c.Level,
		Factors: append(append([]Factor{}, c.Factors...), Factor{Name: "pair", Weight: pairWeight}),
	}
	cp.Score = round4(recomputeCapped(cp.Factors, typ, family, fpFlags))
	cp.Level = levelForScore(cp.Score)
	cp.Level = applyGates(cp.Level, cp.Factors)
	return cp
}

// applyRepeatFactor recomputes a stored confidence with the cross-document
// repeat factor appended (report build time). The stored factors are reused
// verbatim; only the repeat factor is new, so a cache-served candidate and a
// fresh one repeat-boost identically. The pure-endpoint URL type clamp
// re-applies through expectedCapFor (the stored url_type_cap factor marks
// it; the recompute enforces it).
func applyRepeatFactor(c ConfidenceResult, typ asset.SecretType, family string, fpFlags []string) ConfidenceResult {
	cp := ConfidenceResult{
		Score:   c.Score,
		Level:   c.Level,
		Factors: append(append([]Factor{}, c.Factors...), Factor{Name: "repeat", Weight: repeatWeight}),
	}
	cp.Score = round4(recomputeCapped(cp.Factors, typ, family, fpFlags))
	cp.Level = levelForScore(cp.Score)
	cp.Level = applyGates(cp.Level, cp.Factors)
	return cp
}

// recomputeCapped combines the factors and applies the tightest cap the
// confidence contract allows — through expectedCapFor, the single cap-rule
// source (fpContextCap for FP-flagged candidates, genericCap / publicKeyCap
// for those families, urlTypeCap for pure-endpoint URL types; never inline
// re-implementations).
//
// INVARIANT: every recompute path (applyPairFactor, applyRepeatFactor)
// appends a non-pattern factor (pair or repeat) before recomputing, so the
// factor list always carries >= 1 non-pattern factor and structuredCap (a
// structured match with ZERO supporting factors) never binds here. The
// count comes from the factor list itself (countNonPattern), so any future
// factor-model change stays consistent automatically.
func recomputeCapped(factors []Factor, typ asset.SecretType, family string, fpFlags []string) float64 {
	return math.Min(combineFactors(factors), expectedCapFor(typ, family, fpFlags, countNonPattern(factors)))
}

// countNonPattern returns the number of supporting (non-pattern) factors in
// a factor list, by the canonical counting rule shared by every confidence
// path: every factor EXCEPT "pattern" and the weight-0 "url_type_cap"
// marker. The marker records a clamp (never evidence); the pattern factor is
// the candidate's existence condition (always present, never evidence).
// deriveConfidence, applyGates, recomputeCapped, and decodeStoredScan all
// count through this one helper, so the cap/gate factor accounting can never
// drift between paths.
func countNonPattern(factors []Factor) int {
	n := 0
	for _, f := range factors {
		if f.Name != "pattern" && f.Name != "url_type_cap" {
			n++
		}
	}
	return n
}

// applyGates enforces the level gates over a factor list: High needs at
// least two non-pattern factors, Medium at least one. Non-pattern factors
// are counted by the canonical rule (countNonPattern): every factor except
// "pattern" and the weight-0 "url_type_cap" marker — the marker records a
// clamp and never counts as evidence toward the gates.
func applyGates(level Level, factors []Factor) Level {
	nonPattern := countNonPattern(factors)
	if level == LevelHigh && nonPattern < 2 {
		return LevelMedium
	}
	if level == LevelMedium && nonPattern == 0 {
		return LevelLow
	}
	return level
}

// combineFactors is 1 − ∏(1 − wᵢ) over the factors' weights.
func combineFactors(factors []Factor) float64 {
	score := 1.0
	for _, f := range factors {
		w := f.Weight
		if w < 0 {
			w = 0
		}
		if w > 1 {
			w = 1
		}
		score *= 1 - w
	}
	return 1 - score
}

// levelForScore maps a (capped) score to its threshold level.
func levelForScore(score float64) Level {
	switch {
	case score >= highThreshold:
		return LevelHigh
	case score >= mediumThreshold:
		return LevelMedium
	case score >= lowThreshold:
		return LevelLow
	default:
		return LevelUnknown
	}
}

// factorWeightsAreValid checks a decoded factor list (record re-validation).
func factorWeightsAreValid(factors []Factor) bool {
	for _, f := range factors {
		if f.Name == "" {
			return false
		}
		if f.Weight < 0 || f.Weight > 1 {
			return false
		}
	}
	return true
}
