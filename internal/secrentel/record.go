package secrentel

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// Operation is the stable cache operation name for secret scans.
const Operation = "secret.scan"

// capTolerance is the float slack allowed when re-deriving confidence caps
// at decode: an engine-produced capped score is exactly the cap constant
// after round4 plus the JSON round trip, so this tolerance only guards
// against unrelated float noise — anything beyond it is a tampered score.
const capTolerance = 1e-9

// secretKey builds the cache key for one document's scan. The key covers
// the scan identity (kind + content digest + filename + URL + hostname +
// technology hints + provenance source — every result-relevant input), the
// pattern database schema version, and the engine analysis version: bumping
// either invalidates every cached scan by construction. Timings,
// concurrency, and the fixed caps never enter keys.
func secretKey(sd scannedDocument, schema int) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    sd.identity.String(),
		Config:    sd.cacheConfig(schema),
	})
}

// storedSecret is the serialized form of one scanned candidate. The
// canonical asset is stored directly (it round-trips through the asset
// layer); the intelligence dimensions follow. Factor weights are validated
// on decode so a tampered record can never serve an inflated score.
type storedSecret struct {
	Candidate   asset.SecretCandidate `json:"candidate"`
	Provider    string                `json:"provider,omitempty"`
	PatternIDs  []string              `json:"pattern_ids"`
	Family      patterns.Family       `json:"family"`
	Entropy     EntropyAssessment     `json:"entropy"`
	EntropyOK   bool                  `json:"entropy_ok,omitempty"`
	Context     Context               `json:"context"`
	Location    Location              `json:"location"`
	Score       float64               `json:"score"`
	Level       string                `json:"level"`
	Factors     []Factor              `json:"factors"`
	Related     []Related             `json:"related,omitempty"`
	FPFlags     []string              `json:"fp_flags,omitempty"`
	EvidenceIDs []string              `json:"evidence_ids,omitempty"`
	Source      string                `json:"source"`
	ObservedAt  time.Time             `json:"observed_at"`
}

// storedScan is the structured payload of one completed scan record.
type storedScan struct {
	Version      int              `json:"version"`
	Kind         string           `json:"kind"`
	Truncated    bool             `json:"truncated,omitempty"`
	Overflow     bool             `json:"overflow,omitempty"`
	Counts       scanCounts       `json:"counts"`
	CandidateSrc asset.Identity   `json:"candidate_source"`
	EdgeFrom     asset.Identity   `json:"edge_from,omitempty"`
	EdgeKind     string           `json:"edge_kind,omitempty"`
	Secrets      []storedSecret   `json:"secrets"`
	Evidence     []asset.Evidence `json:"evidence,omitempty"`
	FirstSeen    time.Time        `json:"first_seen"`
	LastSeen     time.Time        `json:"last_seen"`
	Sources      []string         `json:"sources"`
}

// encodeStoredScan serializes one scan's entry into a cache record. Only
// completed (untruncated) and honestly-truncated (incomplete) scans reach
// this function; failed and cancelled documents are never stored.
//
// The envelope's CreatedAt is stamped from the STORE time (the run clock),
// never the observation time: TTL is measured from CreatedAt (the Phase 3
// convention).
func encodeStoredScan(sd scannedDocument, entry ReportEntry, now time.Time) (cache.Record, error) {
	st := storedScan{
		Version:      analysisVersion,
		Kind:         string(sd.kind),
		Truncated:    entry.Truncated,
		Overflow:     entry.Overflow,
		Counts:       entry.Counts,
		CandidateSrc: entry.CandidateSrc,
		FirstSeen:    entry.FirstSeen,
		LastSeen:     entry.LastSeen,
		Sources:      entry.Sources,
	}
	if entry.EdgeSrc.Present {
		st.EdgeFrom = entry.EdgeSrc.From
		st.EdgeKind = string(entry.EdgeSrc.Kind)
	}
	for i := range entry.Secrets {
		c := &entry.Secrets[i]
		ss := storedSecret{
			Candidate:   c.cand,
			Provider:    c.provider,
			PatternIDs:  c.patternIDs,
			Family:      c.family,
			Entropy:     c.entropy,
			EntropyOK:   c.entropyOK,
			Context:     c.context,
			Location:    c.location,
			Score:       c.confidence.Score,
			Level:       string(c.confidence.Level),
			Factors:     c.confidence.Factors,
			Related:     c.related,
			FPFlags:     c.fpFlags,
			EvidenceIDs: c.evidenceIDs,
			Source:      c.provSource,
			ObservedAt:  c.observedAt,
		}
		st.Secrets = append(st.Secrets, ss)
	}
	st.Evidence = entry.Evidence

	data, err := json.Marshal(st)
	if err != nil {
		return cache.Record{}, fmt.Errorf("encode stored scan: %w", err)
	}
	status := cache.StatusCompleted
	if entry.Truncated {
		status = cache.StatusIncomplete
	}
	return cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        sd.identity.String(),
		Status:        status,
		CreatedAt:     now.UTC(),
		Data:          data,
	}, nil
}

// redactedCandidateID returns the diagnostic-safe form of one candidate's
// identity: the candidate type plus a short SHA-256 prefix of its value
// (the first four digest bytes, eight hex characters). The full canonical
// identity embeds the percent-encoded candidate VALUE, so it must never
// appear in errors or logs: a tampered cache record — or a valid record
// rejected by a newer analysisVersion — would otherwise print real secret
// material into diagnostics. Findings output (reports, evidence records)
// carries the value by design and is never routed through this helper.
func redactedCandidateID(c asset.SecretCandidate) string {
	return string(c.Type) + "/" + digestHex([]byte(c.Value))[:8]
}

// decodeStoredScan strictly re-validates a completed cache record before it
// is served. Every violated invariant rejects the record (never served);
// the caller deletes it and recomputes. Validation covers: envelope fields,
// payload version, timestamps, counts within caps, canonical candidate
// assets (round-trip through the asset constructor with the same identity),
// valid families/levels/providers, factor weights in [0,1], levels never
// stronger than the score allows, stored levels re-gated from the stored
// factor list (a High/Medium the factor count could never produce is
// tampering or a bug), confidence caps re-derived from the stored
// candidate's own type/family/FP flags (a score above the cap the current
// engine could have produced — or a url_type_cap marker absent where the
// type is capped, or present where it is not — is tampering or a bug), the
// stored score matching the score recomposed from the stored factors
// through the same pure functions (a factor list that contradicts its own
// score is tampering or a bug), canonical evidence records, and evidence
// links only to retained evidence identities.
func decodeStoredScan(rec cache.Record, sd scannedDocument, limits scanLimits) (*storedScan, error) {
	if rec.Status != cache.StatusCompleted {
		return nil, fmt.Errorf("record status %q is not completed", rec.Status)
	}
	if rec.SchemaVersion != cache.SchemaVersion {
		return nil, fmt.Errorf("record schema version %d != %d", rec.SchemaVersion, cache.SchemaVersion)
	}
	if rec.Operation != Operation {
		return nil, fmt.Errorf("record operation %q != %q", rec.Operation, Operation)
	}
	if len(rec.Data) == 0 {
		return nil, fmt.Errorf("record payload is empty")
	}
	if rec.Target != sd.identity.String() {
		return nil, fmt.Errorf("record target does not match the scan identity")
	}

	var s storedScan
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		return nil, fmt.Errorf("decode record payload: %w", err)
	}
	if s.Version != analysisVersion {
		return nil, fmt.Errorf("record analysis version %d != %d", s.Version, analysisVersion)
	}
	if s.Kind != string(sd.kind) {
		return nil, fmt.Errorf("record kind %q != %q", s.Kind, sd.kind)
	}
	if s.Truncated {
		// A truncated scan is never stored completed; a record claiming both
		// is contradictory (the truncated-as-completed tamper class).
		return nil, fmt.Errorf("completed record claims truncation")
	}
	if len(s.Secrets) > limits.maxCandidates {
		return nil, fmt.Errorf("record has %d secrets over cap %d", len(s.Secrets), limits.maxCandidates)
	}
	if s.FirstSeen.IsZero() || s.LastSeen.IsZero() || s.LastSeen.Before(s.FirstSeen) {
		return nil, fmt.Errorf("record timestamps are not ordered")
	}
	if s.CandidateSrc != sd.candidateSource() {
		return nil, fmt.Errorf("record candidate source does not match the document")
	}

	_, docEdgeKind, hasEdge := sd.edgeSource()
	if s.EdgeKind != "" {
		if !hasEdge {
			return nil, fmt.Errorf("record carries an edge source the document cannot have")
		}
		if s.EdgeKind != string(docEdgeKind) {
			return nil, fmt.Errorf("record edge kind %q does not match the document", s.EdgeKind)
		}
	}

	evIDs := make(map[string]bool, len(s.Evidence))
	for _, ev := range s.Evidence {
		rebuilt, err := asset.NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return nil, fmt.Errorf("evidence is not canonical: %w", err)
		}
		if rebuilt.ID() != ev.ID() {
			return nil, fmt.Errorf("evidence identity diverges from canonical form")
		}
		evIDs[ev.Identity().Value] = true
	}

	seenCand := make(map[string]bool, len(s.Secrets))
	for i, ss := range s.Secrets {
		if !ss.Candidate.Type.Valid() {
			return nil, fmt.Errorf("secret %d: unknown type %q", i, ss.Candidate.Type)
		}
		canon, err := asset.NewSecretCandidate(ss.Candidate.Type, ss.Candidate.Value, ss.Candidate.Source, ss.Candidate.Prov)
		if err != nil {
			return nil, fmt.Errorf("secret %d candidate is not canonical: %w", i, err)
		}
		if canon.ID() != ss.Candidate.ID() {
			return nil, fmt.Errorf("secret %d identity diverges from canonical form", i)
		}
		if seenCand[canon.ID()] {
			return nil, fmt.Errorf("secret %d duplicates an earlier candidate", i)
		}
		seenCand[canon.ID()] = true
		if !ss.Family.Valid() {
			return nil, fmt.Errorf("secret %d: unknown family %q", i, ss.Family)
		}
		if ss.Score < 0 || ss.Score > 1 {
			return nil, fmt.Errorf("secret %d score %.3f out of [0,1]", i, ss.Score)
		}
		lv, err := ParseLevel(ss.Level)
		if err != nil {
			return nil, fmt.Errorf("secret %d level: %w", i, err)
		}
		if lv.rank() > levelForScore(ss.Score).rank() {
			return nil, fmt.Errorf("secret %d level %s stronger than score %.3f allows", i, lv, ss.Score)
		}
		if !factorWeightsAreValid(ss.Factors) {
			return nil, fmt.Errorf("secret %d has invalid factor weights", i)
		}
		// Confidence cap re-derivation: any record in the current
		// analysisVersion was produced by this engine, so the stored score
		// can never exceed the cap the contract derives from the stored
		// candidate's own type, family, FP flags, and factor count (the
		// pair factor counts as a supporting factor — it is in the stored
		// list). A higher score means a tampered record or an engine bug;
		// reject it, never silently re-clamp. The tolerance only absorbs
		// float round-trip noise: an engine-capped score lands exactly on
		// the cap constant after round4 + JSON round-trip.
		nonPattern := countNonPattern(ss.Factors)
		expCap := expectedCapFor(ss.Candidate.Type, string(ss.Family), ss.FPFlags, nonPattern)
		if ss.Score > expCap+capTolerance {
			return nil, fmt.Errorf("secret %d (%s) score %.3f exceeds the derived cap %.3f for its type/family/flags",
				i, redactedCandidateID(ss.Candidate), ss.Score, expCap)
		}
		// The weight-0 url_type_cap marker is appended by the engine exactly
		// when the type is cap-eligible (deriveConfidence): a record that
		// contradicts that — missing the marker on a capped type, or
		// carrying it on an uncapped one — is tampered or buggy and must
		// never be served.
		hasURLCap := false
		for _, f := range ss.Factors {
			if f.Name == "url_type_cap" {
				hasURLCap = true
				break
			}
		}
		if urlTypeCapped(ss.Candidate.Type) && !hasURLCap {
			return nil, fmt.Errorf("secret %d (%s): url_type_cap factor missing for cap-eligible type %s",
				i, redactedCandidateID(ss.Candidate), ss.Candidate.Type)
		}
		if !urlTypeCapped(ss.Candidate.Type) && hasURLCap {
			return nil, fmt.Errorf("secret %d (%s): url_type_cap factor present for uncapped type %s",
				i, redactedCandidateID(ss.Candidate), ss.Candidate.Type)
		}
		// Level-gate re-validation: the engine's own invariant is that the
		// stored level equals applyGates(levelForScore(score), storedFactors)
		// — deriveConfidence and applyPairFactor both end there (the
		// strongSoloPattern escape in deriveConfidence can never fire with
		// zero non-pattern factors, because the entropy factor it requires
		// would itself be in the list). A stored level that OUTRANKS the
		// gated level (e.g. high with a single non-pattern factor) could
		// only come from a tampered record; reject it.
		gated := applyGates(levelForScore(ss.Score), ss.Factors)
		if lv.rank() > gated.rank() {
			return nil, fmt.Errorf("secret %d level %s outranks the gated level %s its factors allow",
				i, lv, gated)
		}
		// Score-composition re-validation: every engine-produced score is
		// round4(recomputeCapped(storedFactors, …)) — deriveConfidence
		// stores exactly round4(min(combine, expectedCapFor)) and
		// applyPairFactor stores round4(recomputeCapped(...)) with the
		// identical factor list, and recomputeCapped is pure (the same
		// expectedCapFor/countNonPattern/combineFactors every confidence
		// path shares). A factor list whose recomposed score diverges from
		// the stored score (e.g. an invented "pair" factor with a valid
		// weight) contradicts the record it rides on; reject it. The
		// weight-0 url_type_cap marker multiplies as ×1 and is excluded
		// from the factor count, so the marker-presence checks above remain
		// necessary for the marker's honesty.
		recomposed := round4(recomputeCapped(ss.Factors, ss.Candidate.Type, string(ss.Family), ss.FPFlags))
		if math.Abs(ss.Score-recomposed) > capTolerance {
			return nil, fmt.Errorf("secret %d (%s) score %.3f does not match the recomposed score %.3f from its factors",
				i, redactedCandidateID(ss.Candidate), ss.Score, recomposed)
		}
		if len(ss.PatternIDs) == 0 {
			return nil, fmt.Errorf("secret %d carries no pattern IDs", i)
		}
		for _, pid := range ss.PatternIDs {
			if pid == "" || len(pid) > 64 {
				return nil, fmt.Errorf("secret %d has an invalid pattern ID", i)
			}
		}
		for _, id := range ss.EvidenceIDs {
			if !evIDs[id] {
				return nil, fmt.Errorf("secret %d links missing evidence", i)
			}
		}
	}
	return &s, nil
}

// entryFromStored rebuilds a completed ReportEntry from a decoded cache
// record: ZERO scanning, ZERO pattern matching, ZERO entropy calculations.
// Relationships are rebuilt deterministically from the stored edge source,
// the candidates, and their evidence links.
func entryFromStored(sd scannedDocument, s *storedScan) ReportEntry {
	entry := ReportEntry{
		ID:           sd.identity,
		Status:       StatusCompleted,
		Doc:          sd.ref(),
		CandidateSrc: s.CandidateSrc,
		Truncated:    s.Truncated,
		Overflow:     s.Overflow,
		Counts:       s.Counts,
		Evidence:     s.Evidence,
		FirstSeen:    s.FirstSeen,
		LastSeen:     s.LastSeen,
		Sources:      s.Sources,
		Cached:       true,
	}
	entry.Secrets = make([]scannedCandidate, 0, len(s.Secrets))
	for _, ss := range s.Secrets {
		entry.Secrets = append(entry.Secrets, scannedCandidate{
			id:          ss.Candidate.ID(),
			cand:        ss.Candidate,
			typ:         ss.Candidate.Type,
			provider:    ss.Provider,
			patternIDs:  ss.PatternIDs,
			family:      ss.Family,
			value:       ss.Candidate.Value,
			entropy:     ss.Entropy,
			entropyOK:   ss.EntropyOK,
			context:     ss.Context,
			location:    ss.Location,
			confidence:  ConfidenceResult{Score: ss.Score, Level: Level(ss.Level), Factors: ss.Factors},
			related:     ss.Related,
			fpFlags:     ss.FPFlags,
			evidenceIDs: ss.EvidenceIDs,
			provSource:  ss.Source,
			observedAt:  ss.ObservedAt,
		})
	}
	entry.EdgeSrc = edgeSourceOf(&sd)
	entry.Relationships = rebuildEdges(entry.Secrets, entry.EdgeSrc)
	return entry
}

// rebuildEdges reconstructs the graph edges of a cache-served entry: the
// source→candidate edge (per candidate) and candidate→evidence edges (per
// recorded evidence identity), deduplicated and sorted.
func rebuildEdges(cands []scannedCandidate, edge edgeSourceSnapshot) []asset.Relationship {
	var out []asset.Relationship
	byID := make(map[string]asset.Relationship)
	add := func(r asset.Relationship) {
		byID[r.ID()] = r
	}
	for _, c := range cands {
		candID := asset.Identity{Kind: asset.KindSecretCandidate, Value: c.id}
		if edge.Present {
			if r, err := asset.NewRelationship(edge.From, edge.Kind, candID); err == nil {
				add(r)
			}
		}
		for _, evID := range c.evidenceIDs {
			evIdentity := asset.Identity{Kind: asset.KindEvidence, Value: evID}
			if r, err := asset.NewRelationship(candID, asset.RelationshipSecretCandidateToEvidence, evIdentity); err == nil {
				add(r)
			}
		}
	}
	out = make([]asset.Relationship, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
