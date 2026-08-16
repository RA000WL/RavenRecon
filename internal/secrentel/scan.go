package secrentel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// scanLimits are the per-document caps (config defaults are fixed constants
// of the stage; they never enter cache keys because they never change the
// meaning of a stored record — a lowered cap simply re-truncates on the next
// scan, exactly like the other phases' fixed caps).
type scanLimits struct {
	maxCandidates        int
	maxMatchesPerPattern int
	maxEvidencePerCand   int
	maxPatternEvidence   int
}

func defaultScanLimits() scanLimits {
	return scanLimits{
		maxCandidates:        64,
		maxMatchesPerPattern: 64,
		maxEvidencePerCand:   8,
		maxPatternEvidence:   3,
	}
}

// scanCounts are the honest per-document accounting of every dropped or
// suppressed match (surfaced through Metrics; nothing is silently lost).
type scanCounts struct {
	SuppressedFP          int // known example/placeholder values
	DroppedNegative       int // pattern negative indicators
	DroppedValidator      int // structural validation failures
	DroppedEntropy        int // entropy-rule failures
	DroppedLength         int // outside pattern length bounds
	DroppedDuplicateValue int // contextual duplicate of a structured value
	OverflowDropped       int // beyond the per-document candidate cap
}

// scanOutcome is the full result of scanning one document.
type scanOutcome struct {
	candidates         []scannedCandidate
	evidence           []asset.Evidence
	edges              []asset.Relationship
	counts             scanCounts
	overflowCandidates bool
	signalsScanned     int
}

// scanDocument runs the full scan pipeline over one prepared document:
// pattern matching → per-match validation (length, negatives, validators,
// false-positive values, entropy rules) → dedup by (type, value) →
// cross-family duplicate removal → context extraction → correlation →
// confidence → canonical assets, evidence records, and graph edges.
// Everything is bounded: per-pattern matches, per-document candidates,
// evidence per candidate, and the entropy memo.
func scanDocument(sd scannedDocument, db *patterns.DB, limits scanLimits) scanOutcome {
	out := scanOutcome{}
	content := sd.content
	if len(content) == 0 {
		return out
	}
	pats := db.Patterns()
	byID := make(map[string]patterns.Pattern, len(pats))
	for _, p := range pats {
		byID[p.ID] = p
	}
	lines := buildLineIndex(content)
	entropy := newEntropyCache()

	// The anchor gate: one lowercased copy of the document, computed lazily
	// on the first anchored pattern, gates every case-insensitive contextual
	// family behind a substring check (see Pattern.Anchors). Without it the
	// case-insensitive regexes scan every byte of every document — the
	// measured difference is ~1000x per pattern.
	var lowerOnce string
	var lowerDone bool
	lower := func() string {
		if !lowerDone {
			lowerOnce = toLowerASCII(string(content))
			lowerDone = true
		}
		return lowerOnce
	}

	type key struct {
		typ   asset.SecretType
		value string
	}
	candIndex := make(map[key]int)
	structuredValues := make(map[string]struct{})
	contextualValues := make(map[string]struct{})

	// Phase 1: match, validate, dedup.
	strContent := string(content)
	for _, p := range pats {
		if len(p.Anchors) > 0 {
			hit := false
			lc := lower()
			for _, a := range p.Anchors {
				if strings.Contains(lc, a) {
					hit = true
					break
				}
			}
			if !hit {
				continue // anchor absent: no possible match, skip the regex
			}
		}
		matches := p.Match().FindAllStringSubmatchIndex(strContent, limits.maxMatchesPerPattern+1)
		for i, m := range matches {
			if i >= limits.maxMatchesPerPattern {
				out.counts.OverflowDropped += len(matches) - i
				break
			}
			if m[0] < 0 || m[1] < m[0] {
				continue
			}
			start, end := m[0], m[1]
			if p.Group > 0 {
				gs, ge := m[2*p.Group], m[2*p.Group+1]
				if gs < 0 || ge < gs {
					continue
				}
				start, end = gs, ge
			}
			if p.Trail > 0 && p.Group == 0 {
				if end+p.Trail <= len(content) {
					end = end + p.Trail
				} else {
					end = len(content)
				}
			}
			value := string(content[start:end])

			if p.MinLen > 0 && len(value) < p.MinLen || p.MaxLen > 0 && len(value) > p.MaxLen {
				out.counts.DroppedLength++
				continue
			}
			dropped := false
			for _, n := range p.Negatives {
				if containsFold(value, n) {
					out.counts.DroppedNegative++
					dropped = true
					break
				}
			}
			if dropped {
				continue
			}
			if !runValidator(p.Validator, value) {
				out.counts.DroppedValidator++
				continue
			}
			if reason := classifyValue(value, p.Type); reason != "" {
				out.counts.SuppressedFP++
				continue
			}
			assessment := entropy.assess(value)
			if p.Entropy.MinShannon > 0 || p.Entropy.MinNormalized > 0 {
				if !assessment.satisfies(entropyRuleView{
					MinShannon:    p.Entropy.MinShannon,
					MinNormalized: p.Entropy.MinNormalized,
					Class:         string(p.Entropy.Class),
				}) {
					out.counts.DroppedEntropy++
					continue
				}
			}

			k := key{typ: p.Type, value: value}
			if idx, ok := candIndex[k]; ok {
				c := &out.candidates[idx]
				c.patternIDs = appendUniqueString(c.patternIDs, p.ID)
				if p.Strength > c.strength {
					c.strength = p.Strength
					c.family = p.Family
				}
				continue
			}
			if len(out.candidates) >= limits.maxCandidates {
				out.counts.OverflowDropped++
				continue
			}
			candIndex[k] = len(out.candidates)
			out.candidates = append(out.candidates, scannedCandidate{
				typ:        p.Type,
				provider:   p.Provider,
				patternIDs: []string{p.ID},
				family:     p.Family,
				strength:   p.Strength,
				value:      value,
				entropy:    assessment,
				entropyOK:  p.Entropy.MinShannon > 0 || p.Entropy.MinNormalized > 0,
				location:   lines.locate(start),
				provSource: sd.source,
				observedAt: sd.observedAt,
			})
			switch p.Family {
			case patterns.FamilyStructured:
				structuredValues[value] = struct{}{}
			case patterns.FamilyContextual:
				contextualValues[value] = struct{}{}
			}
		}
	}

	// Phase 2: drop lower-specificity candidates whose value a
	// higher-specificity family already identified — contextual duplicates
	// of structured matches, and generic duplicates of either (the
	// double-report false positive: the specific classification wins).
	kept := out.candidates[:0]
	for _, c := range out.candidates {
		switch c.family {
		case patterns.FamilyContextual:
			if _, dup := structuredValues[c.value]; dup {
				out.counts.DroppedDuplicateValue++
				continue
			}
		case patterns.FamilyGeneric:
			if _, dup := structuredValues[c.value]; dup {
				out.counts.DroppedDuplicateValue++
				continue
			}
			if _, dup := contextualValues[c.value]; dup {
				out.counts.DroppedDuplicateValue++
				continue
			}
		}
		kept = append(kept, c)
	}
	out.candidates = kept

	if len(out.candidates) == 0 {
		return out
	}

	// Phase 3: context and confidence. The canonical asset materialization
	// assigns each candidate its final ID (candidate IDs are needed before
	// pair correlation). The string-state index is built ONCE here (one
	// forward pass); every candidate's comment detection is string-aware
	// through it.
	signals := scanSignals(content, db.Correlations(), sd.technology)
	out.signalsScanned = signals.scanned
	state := buildStateIndex(content)
	urlPath := ""
	if sd.url != nil {
		urlPath = sd.url.Path
	}
	fpCtx := classifyContext(sd.filename, urlPath)

	for i := range out.candidates {
		c := &out.candidates[i]

		// Winning pattern (max strength, ID tie-break) drives hints.
		win := byID[c.patternIDs[0]]
		for _, pid := range c.patternIDs {
			if p, ok := byID[pid]; ok && (p.Strength > win.Strength || (p.Strength == win.Strength && p.ID < win.ID)) {
				win = p
			}
		}
		c.context = extractContext(content, c.location.Offset,
			c.location.Offset+len(c.value), c.provider, win.Hints, win.Positives, state)
		c.fpFlags = fpCtx

		sig := signals.byProvider[c.provider]

		in := confidenceInput{
			Strength:   c.strength,
			Family:     string(c.family),
			Type:       c.typ,
			Value:      c.value,
			EntropyOK:  c.entropyOK && c.entropy.Shannon > 0,
			EntropyHit: c.entropyOK && c.entropy.Normalized >= 0.75,
			Context:    c.context,
			TechHit:    sig.tech,
			Endpoint:   sig.endpoint,
			Pair:       false, // pairs are correlated below, once IDs are final
			FPFlags:    c.fpFlags,
		}
		c.confidence = deriveConfidence(in)

		// Canonical asset: identity materialization (also assigns c.id and
		// syncs the stored value with the asset layer's bounded form).
		assetCand := c.candidateAsset(&sd)
		c.cand = assetCand
		c.id = assetCand.ID()
		c.value = assetCand.Value
	}

	// Phase 4: pair correlation (IDs are final), evidence records, and
	// graph edges. A pair factor is appended through the confidence model's
	// factor list so the stored record and the recomputation agree.
	pairs := buildPairs(out.candidates)
	for i := range out.candidates {
		c := &out.candidates[i]
		if siblings := pairs[c.id]; siblings != nil {
			for _, sib := range siblings {
				c.related = append(c.related, Related{CandidateID: sib, Relation: "pair"})
			}
			c.confidence = applyPairFactor(c.confidence, c.typ, string(c.family), c.fpFlags)
		}
		out.evidence = append(out.evidence, c.evidenceRecords(&sd, signals.byProvider[c.provider], limits)...)
		out.edges = append(out.edges, c.edgesOf(&sd)...)
	}

	// Deterministic ordering: candidates by ID, evidence and edges by
	// identity.
	sort.SliceStable(out.candidates, func(i, j int) bool {
		return out.candidates[i].id < out.candidates[j].id
	})
	sort.SliceStable(out.evidence, func(i, j int) bool {
		return out.evidence[i].ID() < out.evidence[j].ID()
	})
	sort.SliceStable(out.edges, func(i, j int) bool {
		return out.edges[i].ID() < out.edges[j].ID()
	})
	return out
}

// evidenceRecords builds the candidate's evidence chain (MethodSecret),
// bounded by the evidence cap. Every record's source is the document's
// candidate source identity; the created evidence identity values are
// recorded on the candidate (evidenceIDs) so edgesOf links them without a
// second construction.
func (c *scannedCandidate) evidenceRecords(sd *scannedDocument, sig providerSignals, limits scanLimits) []asset.Evidence {
	src := sd.candidateSource()
	prov := asset.Provenance{Source: c.provSource, DiscoveredAt: c.observedAt}
	var out []asset.Evidence
	add := func(indicator, value string) bool {
		if len(out) >= limits.maxEvidencePerCand {
			return false
		}
		ev, err := asset.NewEvidence(asset.MethodSecret, indicator, value, src, prov)
		if err != nil {
			return true // skip malformed, keep room
		}
		out = append(out, ev)
		c.evidenceIDs = append(c.evidenceIDs, ev.Identity().Value)
		return true
	}
	pids := c.patternIDs
	if len(pids) > limits.maxPatternEvidence {
		pids = pids[:limits.maxPatternEvidence]
	}
	for _, pid := range pids {
		if !add("secret:"+pid, c.value) {
			break
		}
	}
	add("entropy", fmt.Sprintf("shannon:%.2f/class:%s/normalized:%.2f", c.entropy.Shannon, c.entropy.Class, c.entropy.Normalized))
	if c.context.Variable != "" {
		add("context:variable", c.context.Variable)
	}
	if c.context.JSONKey != "" {
		add("context:json_key", c.context.JSONKey)
	}
	if sig.endpoint != "" {
		add("correlation:endpoint", sig.endpoint)
	}
	if sig.tech != "" {
		add("correlation:technology", sig.tech)
	}
	if len(c.related) > 0 {
		add("correlation:pair", c.related[0].CandidateID)
	}
	for _, f := range c.fpFlags {
		add("fp:context", f)
	}
	return out
}

// edgesOf builds the candidate's graph edges: source→candidate (when the
// document came from a JavaScript or URL asset) and candidate→evidence for
// every evidence record of this candidate (by recorded identity value).
func (c *scannedCandidate) edgesOf(sd *scannedDocument) []asset.Relationship {
	var out []asset.Relationship
	candID := asset.Identity{Kind: asset.KindSecretCandidate, Value: c.id}
	if from, kind, ok := sd.edgeSource(); ok {
		if r, err := asset.NewRelationship(from, kind, candID); err == nil {
			out = append(out, r)
		}
	}
	for _, evID := range c.evidenceIDs {
		evIdentity := asset.Identity{Kind: asset.KindEvidence, Value: evID}
		if r, err := asset.NewRelationship(candID, asset.RelationshipSecretCandidateToEvidence, evIdentity); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// appendUniqueString appends s when not already present (bounded lists).
func appendUniqueString(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
