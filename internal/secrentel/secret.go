package secrentel

import (
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// Related is one correlated reference from a candidate to another candidate
// (pair siblings).
type Related struct {
	CandidateID string `json:"candidate_id"`
	Relation    string `json:"relation"` // "pair"
}

// scannedCandidate is the engine-internal, fully classified candidate: the
// canonical Phase 2 asset plus every intelligence dimension Phase 8 adds.
// This is the unit the scan stage produces and the cache record stores
// (serialized as storedSecret).
type scannedCandidate struct {
	id          string                // candidate asset ID (dedup key)
	cand        asset.SecretCandidate // canonical asset, materialized at scan time
	typ         asset.SecretType
	provider    string
	patternIDs  []string
	family      patterns.Family
	strength    float64 // winning pattern's strength
	value       string  // stored value (asset-layer bounded, ≤512 bytes)
	entropy     EntropyAssessment
	entropyOK   bool
	context     Context
	location    Location
	confidence  ConfidenceResult
	related     []Related
	fpFlags     []string
	evidenceIDs []string
	provSource  string
	observedAt  time.Time
}

// SecretResult is the report-level secret: the full evidence tree of one
// candidate — never an anonymous string. Reports carry these sorted by
// confidence score desc, then candidate ID asc.
type SecretResult struct {
	// Candidate is the canonical Phase 2 asset (type, stored value, source
	// identity, provenance; Prov.Confidence carries the score).
	Candidate asset.SecretCandidate `json:"candidate"`

	// Type classifies the candidate (mirrors Candidate.Type, explicit for
	// convenience).
	Type asset.SecretType `json:"type"`

	// Provider is the owning provider ("aws", "github", ...; "" = generic).
	Provider string `json:"provider,omitempty"`

	// PatternIDs are the fingerprints that matched.
	PatternIDs []string `json:"pattern_ids"`

	// Family is the winning pattern's family.
	Family patterns.Family `json:"family"`

	// Value mirrors Candidate.Value (the stored, bounded value).
	Value string `json:"value"`

	// Entropy is the entropy assessment of the value.
	Entropy EntropyAssessment `json:"entropy"`

	// Context is the extracted surrounding evidence.
	Context Context `json:"context"`

	// Location is where in the document the match sits.
	Location Location `json:"location"`

	// Confidence is the composed verdict with every factor.
	Confidence ConfidenceResult `json:"confidence"`

	// Related carries same-provider pair siblings.
	Related []Related `json:"related,omitempty"`

	// FPFlags are context-level false-positive flags (cap confidence at Low).
	FPFlags []string `json:"fp_flags,omitempty"`

	// Document references the document of the winning observation.
	Document DocumentRef `json:"document"`

	// Observations counts the distinct scan identities that saw this
	// candidate in the run.
	Observations int `json:"observations"`

	// Sources are the provenance sources that reported it (deduplicated,
	// first-observation order).
	Sources []string `json:"sources"`

	// FirstSeen / LastSeen are the observation timestamps.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Cached reports that the winning observation was served from cache.
	Cached bool `json:"cached,omitempty"`
}

// resultOf converts an engine candidate into its report form.
func (c scannedCandidate) resultOf(doc DocumentRef, observations int, sources []string, cached bool) SecretResult {
	return SecretResult{
		Candidate:    c.cand,
		Type:         c.typ,
		Provider:     c.provider,
		PatternIDs:   c.patternIDs,
		Family:       c.family,
		Value:        c.value,
		Entropy:      c.entropy,
		Context:      c.context,
		Location:     c.location,
		Confidence:   c.confidence,
		Related:      c.related,
		FPFlags:      c.fpFlags,
		Document:     doc,
		Observations: observations,
		Sources:      sources,
		FirstSeen:    c.observedAt,
		LastSeen:     c.observedAt,
		Cached:       cached,
	}
}

// candidateAsset builds the canonical Phase 2 asset at scan time: identity =
// type / stored value / document candidate source (the single construction
// point; when the document came from a JavaScript asset this is the SAME
// identity jsintel would produce for the same value, so the two phases
// deduplicate on one Phase 2 candidate).
func (c *scannedCandidate) candidateAsset(sd *scannedDocument) asset.SecretCandidate {
	prov := asset.Provenance{
		Source:       c.provSource,
		DiscoveredAt: c.observedAt,
		Confidence:   c.confidence.Score,
	}
	cand, err := asset.NewSecretCandidate(c.typ, c.value, sd.candidateSource(), prov)
	if err != nil {
		// The scan stage only produces validated candidates; an error here
		// means an internal invariant broke. The zero asset keeps the
		// report structurally valid; engine tests pin that produced
		// candidates always construct.
		return asset.SecretCandidate{}
	}
	return cand
}
