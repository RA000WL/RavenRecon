package priority

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TechSignal is one technology detection attached to a scored asset:
// techintel/jsintel observations mapped by the Round-2 engine. Confidence
// is the technology asset's Prov.Confidence — never invented here.
type TechSignal struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	// Identity is the technology's canonical identity string
	// ("category/name"); empty falls back to the scored asset's identity
	// in factor evidence.
	Identity string `json:"identity,omitempty"`
}

// SecretSignal is one secret candidate attached to a scored asset:
// secrentel/jsintel candidates mapped by the Round-2 engine. Confidence is
// the candidate's Prov.Confidence — never invented here.
type SecretSignal struct {
	Type       asset.SecretType `json:"type"`
	Confidence float64          `json:"confidence"`
	// Identity is the candidate's canonical identity string; empty falls
	// back to the scored asset's identity in factor evidence.
	Identity string `json:"identity,omitempty"`
}

// Signal is the scoring input: one canonical Phase 2 asset reduced to the
// observed signals the catalogs and confidence engine consume. The Round-2
// engine maps canonical assets into it; tests construct it directly.
// Everything is caller-supplied — the engine reads no clock and performs
// no I/O.
type Signal struct {
	// Identity is the canonical identity of the asset being scored
	// (required, non-zero).
	Identity asset.Identity `json:"identity"`

	// Kind is the asset's kind (required, non-empty).
	Kind asset.Kind `json:"kind"`

	// Path is the canonical path (endpoint/URL/JavaScript/source-map
	// resource URL path).
	Path string `json:"path,omitempty"`

	// Hostname is the host the asset was observed on (labels; also the
	// private-address regex target).
	Hostname string `json:"hostname,omitempty"`

	// EndpointMethod is the endpoint's method field, which jsintel uses to
	// carry the endpoint class ("WS", "SSE", "GQL", "GET").
	EndpointMethod string `json:"endpoint_method,omitempty"`

	// ParameterNames are the observed parameter names (urlintel).
	ParameterNames []string `json:"parameter_names,omitempty"`

	// JSBundleBytes is the observed JavaScript body size in bytes.
	JSBundleBytes int64 `json:"js_bundle_bytes,omitempty"`

	// Technologies are the technologies detected on the asset.
	Technologies []TechSignal `json:"technologies,omitempty"`

	// Secrets are the secret candidates observed on the asset.
	Secrets []SecretSignal `json:"secrets,omitempty"`

	// Port is the observed port number (0 = not observed).
	Port int `json:"port,omitempty"`

	// Service is the observed service name.
	Service string `json:"service,omitempty"`

	// Headers are the observed final-response headers as lowercased
	// "key: value" lines (httpprobe's bounded, sorted HeaderEntry list
	// rendered by the Round-2 mapper).
	Headers []string `json:"headers,omitempty"`

	// Observations is the cross-source observation count of the asset (0 or
	// 1 = no repeat evidence).
	Observations int `json:"observations,omitempty"`

	// FirstSeen is the earliest observation time of the asset.
	FirstSeen time.Time `json:"first_seen,omitempty"`

	// ScoredAt is the scoring timestamp.
	ScoredAt time.Time `json:"scored_at,omitempty"`
}

// Scoring contract constants. All fixed, deliberately NOT configuration:
// the model is a documented contract (mirroring secrentel's confidence
// constants).
const (
	// perCategoryCap caps any single indicator category's combined
	// contribution: no single category can dominate a score.
	perCategoryCap = 0.6
	// confidenceGroupCap caps the combined confidence contribution.
	confidenceGroupCap = 0.5
	// observationFactorWeight is the repeat-observation confidence factor.
	observationFactorWeight = 0.2
	// observationFactorMin is the observation count that fires it.
	observationFactorMin = 2
	// maxConfidenceSignalFactors bounds technology/secret confidence
	// factors (highest confidence kept, ties by name).
	maxConfidenceSignalFactors = 8

	// Thresholds.
	highThreshold   = 0.8
	mediumThreshold = 0.5
	lowThreshold    = 0.2

	// Level gates: high needs >= 2 independent indicator categories,
	// medium >= 1.
	highCategoryGate   = 2
	mediumCategoryGate = 1

	// maxFactors bounds the emitted factor list; a pathological signal
	// matching more groups keeps the highest-weight factors (ties by name).
	maxFactors = 32
)

// Signal bounds (fixed constants; violations are input errors).
const (
	maxSignalPathBytes    = 16384
	maxSignalHostBytes    = 253
	maxSignalParams       = 64
	maxSignalParamBytes   = 128
	maxSignalTechs        = 32
	maxSignalSecrets      = 32
	maxSignalHeaders      = 128
	maxSignalHeaderBytes  = 512
	maxSignalMethodBytes  = 16
	maxSignalServiceBytes = 128
)

// match is one winning catalog match: the (category, field) group key, the
// winning indicator, the matched term, and the evidence identities.
type match struct {
	group    string // "interestingness:admin" / "risk:high_value_secret"
	category string
	field    SignalField
	ind      Indicator
	term     string // matched literal term ("" for regex/size/kind)
	evidence []string
	// specificity ranks the overlap policy: literal term length (regex,
	// size, and kind matches carry 0 and lose to any literal).
	specificity int
}

// ScoreSurface scores one signal against the two catalogs and returns the
// fully explained SurfaceAsset. The output is deterministic: identical
// inputs (including the explicit timestamps) produce bit-for-bit identical
// results; factor order is interestingness categories (sorted), risk
// categories (sorted), confidence factors last.
//
// Composition (mirroring secrentel's deriveConfidence math, cite:
// internal/secrentel/confidence.go combineFactors):
//
//	score = 1 − ∏(1 − w_g)   over groups g
//	group = min(cap, 1 − ∏(1 − w_f))   over a category's factors f
//
// with perCategoryCap on indicator categories, confidenceGroupCap on the
// confidence group, and level gates: high requires score >= 0.8 AND at
// least two distinct indicator categories; medium requires score >= 0.5
// AND at least one; low >= 0.2; else unknown.
func ScoreSurface(sig Signal, interesting, risk *Catalog) (SurfaceAsset, error) {
	if interesting == nil || risk == nil {
		return SurfaceAsset{}, fmt.Errorf("priority: both catalogs are required")
	}
	if err := validateSignal(sig); err != nil {
		return SurfaceAsset{}, fmt.Errorf("priority: invalid signal: %w", err)
	}

	var factors []Factor
	factors = append(factors, matchCatalog(sig, interesting)...)
	factors = append(factors, matchCatalog(sig, risk)...)
	factors = append(factors, confidenceFactors(sig)...)

	// Bound the factor list deterministically: highest weight first, ties
	// by name, then by first evidence (a total order — the kept set never
	// depends on construction order).
	if len(factors) > maxFactors {
		factors = capFactors(factors)
	}
	for _, f := range factors {
		if err := f.validate(); err != nil {
			return SurfaceAsset{}, fmt.Errorf("priority: internal invariant violated: %w", err)
		}
	}

	score, interestingness, confidence, indicatorCategories := compose(factors)

	// Confidence is the UNCAPPED combination (1 − ∏(1 − wᵢ)) of the
	// individual confidence factors. It is descriptive only and must NOT be
	// presented as the confidence group's contribution to Score — the score
	// consumes the group after the confidenceGroupCap (0.5).
	out := SurfaceAsset{
		Identity:        sig.Identity,
		Kind:            sig.Kind,
		Score:           score,
		Interestingness: interestingness,
		Confidence:      confidence,
		Factors:         factors,
		FirstSeen:       sig.FirstSeen,
		ScoredAt:        sig.ScoredAt,
	}
	out.Level = levelFor(out.Score, indicatorCategories)
	return out, nil
}

// compose runs the documented composition over a factor list and returns
// the rounded score, interestingness sub-score, uncapped confidence, and
// the count of distinct indicator categories. It is the single composition
// point shared by ScoreSurface, the Round-2 correlation aggregate, and
// cache decode re-validation, so every consumer provably uses the same
// math:
//
//	score           = round4(1 − ∏_g (1 − w_g))   over groups g
//	w_g             = min(cap_g, 1 − ∏_f (1 − w_f))   over group g's factors
//	cap_g           = confidenceGroupCap for the confidence group,
//	                  perCategoryCap for every indicator category
//	interestingness = round4(1 − ∏_g∈interestingness (1 − w_g))
//	confidence      = round4(1 − ∏_f∈confidence (1 − w_f))   (uncapped)
//
// Grouping follows groupKey: all confidence:* factors share ONE group;
// indicator factors group by their full name (group:category).
func compose(factors []Factor) (score, interestingness, confidence float64, indicatorCategories int) {
	totalProduct := 1.0
	interestingProduct := 1.0
	confidenceProduct := 1.0

	byGroup := groupFactors(factors)
	for _, name := range sortedKeys(byGroup) {
		fs := byGroup[name]
		w := combineFactors(fs)
		if name == "confidence" {
			w = minf(w, confidenceGroupCap)
			for _, f := range fs {
				confidenceProduct *= 1 - f.Weight
			}
		} else {
			w = minf(w, perCategoryCap)
			indicatorCategories++
			if strings.HasPrefix(name, "interestingness:") {
				interestingProduct *= 1 - w
			}
		}
		totalProduct *= 1 - w
	}
	return round4(1 - totalProduct), round4(1 - interestingProduct), round4(1 - confidenceProduct), indicatorCategories
}

// levelFor applies the threshold and gate rules.
func levelFor(score float64, indicatorCategories int) PriorityLevel {
	switch {
	case score >= highThreshold && indicatorCategories >= highCategoryGate:
		return LevelHigh
	case score >= mediumThreshold && indicatorCategories >= mediumCategoryGate:
		return LevelMedium
	case score >= lowThreshold:
		return LevelLow
	default:
		return LevelUnknown
	}
}

// combineFactors is 1 − ∏(1 − wᵢ) over the factors' weights — the same
// combination math as secrentel's combineFactors
// (internal/secrentel/confidence.go). NaN weights are defense in depth
// behind Factor.validate's NaN rejection: a NaN compares false against
// every clamp bound, so it is clamped to 0 here and can never contribute a
// NaN product (a NaN score contribution).
func combineFactors(fs []Factor) float64 {
	score := 1.0
	for _, f := range fs {
		score *= 1 - clampWeight(f.Weight)
	}
	return 1 - score
}

// clampWeight clamps a factor weight into [0,1], NaN-safe: NaN maps to 0
// (no contribution) instead of propagating.
func clampWeight(w float64) float64 {
	if math.IsNaN(w) {
		return 0
	}
	if w < 0 {
		return 0
	}
	if w > 1 {
		return 1
	}
	return w
}

// matchCatalog runs one catalog over the signal and emits one factor per
// winning (category, field) group, in catalog order. The OVERLAP POLICY:
// when several entries of one category match the same field, the entry
// with the LONGEST matching literal term wins; regex, size, and kind
// matches (specificity 0) lose to any literal and tie-break by indicator
// ID; one factor per category per field, never more.
func matchCatalog(sig Signal, c *Catalog) []Factor {
	groups := make(map[string]*match)
	lowerPath := lowercaseASCII(sig.Path)
	lowerHost := lowercaseASCII(sig.Hostname)
	lowerService := lowercaseASCII(sig.Service)
	lowerMethod := lowercaseASCII(sig.EndpointMethod)
	portStr := ""
	if sig.Port > 0 {
		portStr = strconv.Itoa(sig.Port)
	}
	selfID := sig.Identity.String()

	for _, e := range c.Entries() {
		var m *match
		switch e.Field {
		case FieldPath:
			m = matchSingle(e, lowerPath, selfID)
		case FieldHost:
			m = matchSingle(e, lowerHost, selfID)
		case FieldServiceName:
			m = matchSingle(e, lowerService, selfID)
		case FieldEndpointMethod:
			m = matchSingle(e, lowerMethod, selfID)
		case FieldPort:
			m = matchSingle(e, portStr, selfID)
		case FieldKind:
			if string(sig.Kind) == e.Kind {
				m = &match{ind: e, evidence: []string{selfID}}
			}
		case FieldJSBundleSize:
			if sig.JSBundleBytes >= e.MinJSBytes {
				m = &match{ind: e, evidence: []string{selfID}}
			}
		case FieldTechName:
			m = matchItems(e, selfID, len(sig.Technologies), func(i int) (string, string) {
				t := sig.Technologies[i]
				return lowercaseASCII(t.Name), t.Identity
			})
		case FieldTechCategory:
			m = matchItems(e, selfID, len(sig.Technologies), func(i int) (string, string) {
				t := sig.Technologies[i]
				return lowercaseASCII(t.Category), t.Identity
			})
		case FieldParameterName:
			m = matchItems(e, selfID, len(sig.ParameterNames), func(i int) (string, string) {
				return lowercaseASCII(sig.ParameterNames[i]), ""
			})
		case FieldSecretType:
			m = matchItems(e, selfID, len(sig.Secrets), func(i int) (string, string) {
				return lowercaseASCII(string(sig.Secrets[i].Type)), sig.Secrets[i].Identity
			})
		case FieldHeader:
			m = matchItems(e, selfID, len(sig.Headers), func(i int) (string, string) {
				return lowercaseASCII(sig.Headers[i]), ""
			})
		}
		if m == nil {
			continue
		}
		m.field = e.Field
		m.group = groupOf(c, m.ind.Category)
		m.category = m.ind.Category
		key := m.group + ":" + string(m.field)
		prev, ok := groups[key]
		if !ok || matchBetter(m, prev) {
			groups[key] = m
		}
	}

	// Deterministic emission: group keys sorted.
	var out []Factor
	for _, key := range sortedMatchKeys(groups) {
		m := groups[key]
		reason := m.ind.Reason
		rec := m.ind.Recommendation
		if m.term != "" {
			reason = strings.Replace(reason, "%s", m.term, 1)
			rec = strings.Replace(rec, "%s", m.term, 1)
		}
		ev := m.evidence
		if len(ev) > maxEvidencePerFactor {
			ev = ev[:maxEvidencePerFactor]
		}
		out = append(out, Factor{
			Name:           m.group,
			Weight:         m.ind.Weight,
			Evidence:       ev,
			Reason:         reason,
			Recommendation: rec,
		})
	}
	return out
}

// matchSingle matches an entry against one scalar field value.
func matchSingle(e Indicator, value, selfID string) *match {
	if value == "" {
		return nil
	}
	if len(e.Terms) > 0 {
		bestTerm := ""
		for _, t := range e.Terms {
			if strings.Contains(value, t) && len(t) > len(bestTerm) {
				bestTerm = t
			}
		}
		if bestTerm == "" {
			return nil
		}
		return &match{ind: e, term: bestTerm, evidence: []string{selfID}, specificity: len(bestTerm)}
	}
	if e.re != nil && e.re.MatchString(value) {
		return &match{ind: e, evidence: []string{selfID}}
	}
	return nil
}

// matchItems matches an entry against a list field: every item whose value
// matches contributes evidence; the longest matched term wins per the
// overlap policy.
func matchItems(e Indicator, selfID string, n int, item func(int) (value, identity string)) *match {
	var evidence []string
	bestTerm := ""
	for i := 0; i < n; i++ {
		value, id := item(i)
		if value == "" {
			continue
		}
		matched := false
		if len(e.Terms) > 0 {
			for _, t := range e.Terms {
				if strings.Contains(value, t) {
					matched = true
					if len(t) > len(bestTerm) {
						bestTerm = t
					}
				}
			}
		} else if e.re != nil && e.re.MatchString(value) {
			matched = true
		}
		if matched {
			if id == "" {
				id = selfID
			}
			evidence = appendUnique(evidence, id)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &match{ind: e, term: bestTerm, evidence: evidence, specificity: len(bestTerm)}
}

// matchBetter is the deterministic overlap tie-break: longer literal term
// first, then lower indicator ID.
func matchBetter(a, b *match) bool {
	if a.specificity != b.specificity {
		return a.specificity > b.specificity
	}
	return a.ind.ID < b.ind.ID
}

// confidenceFactors builds the confidence group from signals the earlier
// phases actually recorded — technology and secret Prov.Confidence and the
// cross-source observation count. Never invented.
func confidenceFactors(sig Signal) []Factor {
	var out []Factor

	// Each signal type contributes at most maxConfidenceSignalFactors
	// factors, independently: technology confidence factors and secret
	// confidence factors are bounded separately, so a technology-heavy
	// signal never crowds out secret evidence (and vice versa).
	techs := append([]TechSignal{}, sig.Technologies...)
	sort.SliceStable(techs, func(i, j int) bool {
		if techs[i].Confidence != techs[j].Confidence {
			return techs[i].Confidence > techs[j].Confidence
		}
		return techs[i].Name < techs[j].Name
	})
	techFactors := 0
	for _, t := range techs {
		if techFactors >= maxConfidenceSignalFactors {
			break
		}
		if t.Confidence <= 0 {
			continue
		}
		ev := t.Identity
		if ev == "" {
			ev = sig.Identity.String()
		}
		out = append(out, Factor{
			Name:     "confidence:technology",
			Weight:   clamp01(t.Confidence),
			Evidence: []string{ev},
			Reason:   fmt.Sprintf("technology observation confidence %.2f recorded by the detection phase", t.Confidence),
		})
		techFactors++
	}

	secrets := append([]SecretSignal{}, sig.Secrets...)
	sort.SliceStable(secrets, func(i, j int) bool {
		if secrets[i].Confidence != secrets[j].Confidence {
			return secrets[i].Confidence > secrets[j].Confidence
		}
		return secrets[i].Type < secrets[j].Type
	})
	secretFactors := 0
	for _, s := range secrets {
		if secretFactors >= maxConfidenceSignalFactors {
			break
		}
		if s.Confidence <= 0 {
			continue
		}
		ev := s.Identity
		if ev == "" {
			ev = sig.Identity.String()
		}
		out = append(out, Factor{
			Name:     "confidence:secret",
			Weight:   clamp01(s.Confidence),
			Evidence: []string{ev},
			Reason:   fmt.Sprintf("secret candidate observation confidence %.2f recorded by the detection phase", s.Confidence),
		})
		secretFactors++
	}

	if sig.Observations >= observationFactorMin {
		out = append(out, Factor{
			Name:     "confidence:observations",
			Weight:   observationFactorWeight,
			Evidence: []string{sig.Identity.String()},
			Reason:   fmt.Sprintf("asset observed by %d distinct sources", sig.Observations),
		})
	}
	return out
}

// groupOf builds a factor name prefix from the catalog's name.
func groupOf(c *Catalog, category string) string {
	return c.Name() + ":" + category
}

// groupFactors buckets factors by group key: every confidence factor
// shares ONE group (capped once); indicator factors group by their full
// name (group:category).
func groupFactors(fs []Factor) map[string][]Factor {
	out := make(map[string][]Factor, len(fs))
	for _, f := range fs {
		out[groupKey(f)] = append(out[groupKey(f)], f)
	}
	return out
}

// groupKey is the canonical grouping key of a factor.
func groupKey(f Factor) string {
	if strings.HasPrefix(f.Name, "confidence") {
		return "confidence"
	}
	return f.Name
}

// sortedKeys returns map keys sorted (deterministic iteration).
func sortedKeys(m map[string][]Factor) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedMatchKeys(m map[string]*match) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// capFactors keeps the top maxFactors factors: weight desc, then name asc,
// then first evidence asc — a total order independent of construction.
func capFactors(fs []Factor) []Factor {
	sorted := append([]Factor{}, fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Weight != sorted[j].Weight {
			return sorted[i].Weight > sorted[j].Weight
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		if len(sorted[i].Evidence) == 0 || len(sorted[j].Evidence) == 0 {
			return len(sorted[i].Evidence) < len(sorted[j].Evidence)
		}
		return sorted[i].Evidence[0] < sorted[j].Evidence[0]
	})
	kept := sorted[:maxFactors]
	// Restore the deterministic output order: group name asc (stable, so
	// same-group factors keep their construction order).
	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].Name < kept[j].Name
	})
	return kept
}

// validateSignal enforces the input bounds.
func validateSignal(sig Signal) error {
	if sig.Identity.IsZero() {
		return fmt.Errorf("identity must not be zero")
	}
	// A kind without a value is not a canonical identity (Phase 2 builders
	// never produce one; validateCanonicalIdentity's per-kind rules all
	// demand a non-empty value) — reject it at the gate rather than scoring
	// an unaddressable asset.
	if sig.Identity.Value == "" {
		return fmt.Errorf("identity value must not be empty")
	}
	if sig.Kind == "" {
		return fmt.Errorf("kind must not be empty")
	}
	if len(sig.Path) > maxSignalPathBytes {
		return fmt.Errorf("path is %d bytes over bound %d", len(sig.Path), maxSignalPathBytes)
	}
	if len(sig.Hostname) > maxSignalHostBytes {
		return fmt.Errorf("hostname is %d bytes over bound %d", len(sig.Hostname), maxSignalHostBytes)
	}
	if len(sig.EndpointMethod) > maxSignalMethodBytes {
		return fmt.Errorf("endpoint method is %d bytes over bound %d", len(sig.EndpointMethod), maxSignalMethodBytes)
	}
	if len(sig.Service) > maxSignalServiceBytes {
		return fmt.Errorf("service name is %d bytes over bound %d", len(sig.Service), maxSignalServiceBytes)
	}
	if len(sig.ParameterNames) > maxSignalParams {
		return fmt.Errorf("%d parameter names over bound %d", len(sig.ParameterNames), maxSignalParams)
	}
	for _, p := range sig.ParameterNames {
		if p == "" || len(p) > maxSignalParamBytes {
			return fmt.Errorf("parameter name is empty or over %d bytes", maxSignalParamBytes)
		}
	}
	if len(sig.Technologies) > maxSignalTechs {
		return fmt.Errorf("%d technologies over bound %d", len(sig.Technologies), maxSignalTechs)
	}
	for _, t := range sig.Technologies {
		if t.Name == "" || len(t.Name) > maxSignalParamBytes {
			return fmt.Errorf("technology name is empty or over %d bytes", maxSignalParamBytes)
		}
		// NaN compares false against every bound, so it is rejected
		// explicitly: a NaN confidence would propagate into a NaN score.
		if math.IsNaN(t.Confidence) || t.Confidence < 0 || t.Confidence > 1 {
			return fmt.Errorf("technology %q confidence %v out of [0,1]", t.Name, t.Confidence)
		}
	}
	if len(sig.Secrets) > maxSignalSecrets {
		return fmt.Errorf("%d secrets over bound %d", len(sig.Secrets), maxSignalSecrets)
	}
	for _, s := range sig.Secrets {
		if !s.Type.Valid() {
			return fmt.Errorf("unknown secret type %q", s.Type)
		}
		if math.IsNaN(s.Confidence) || s.Confidence < 0 || s.Confidence > 1 {
			return fmt.Errorf("secret %q confidence %v out of [0,1]", s.Type, s.Confidence)
		}
	}
	if len(sig.Headers) > maxSignalHeaders {
		return fmt.Errorf("%d headers over bound %d", len(sig.Headers), maxSignalHeaders)
	}
	for _, h := range sig.Headers {
		if h == "" || len(h) > maxSignalHeaderBytes {
			return fmt.Errorf("header line is empty or over %d bytes", maxSignalHeaderBytes)
		}
	}
	if sig.JSBundleBytes < 0 {
		return fmt.Errorf("js bundle bytes %d must not be negative", sig.JSBundleBytes)
	}
	if sig.Port < 0 || sig.Port > 65535 {
		return fmt.Errorf("port %d out of 0..65535", sig.Port)
	}
	if sig.Observations < 0 {
		return fmt.Errorf("observations %d must not be negative", sig.Observations)
	}
	return nil
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func minf(a, b float64) float64 {
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// round4 rounds to 4 decimal places for deterministic storage and
// comparison (secrentel's convention).
func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}
