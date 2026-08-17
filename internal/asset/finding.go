package asset

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Bounds applied by NewFinding (fixed constants; they never enter cache keys).
const (
	// maxFindingRuleIDBytes bounds the rule ID embedded in the identity.
	maxFindingRuleIDBytes = 128
	// maxFindingRuleNameBytes bounds the denormalized rule name.
	maxFindingRuleNameBytes = 256
	// maxFindingCategoryBytes bounds the category label (the vocabulary is
	// owned by the detection framework; the asset layer bounds the field).
	maxFindingCategoryBytes = 64
	// maxFindingLabelBytes bounds the priority and status labels (the
	// vocabularies are owned by the detection framework).
	maxFindingLabelBytes = 32
	// maxFindingEvidence bounds the evidence records one finding cites.
	maxFindingEvidence = 16
	// maxFindingRelated bounds the related-asset references.
	maxFindingRelated = 32
	// maxFindingRelationships bounds the related-asset edges.
	maxFindingRelationships = 32
	// maxFindingMetadataEntries / maxFindingMetadataKeyBytes /
	// maxFindingMetadataValueBytes bound the typed metadata map.
	maxFindingMetadataEntries  = 16
	maxFindingMetadataKeyBytes = 64
	// maxFindingMetadataValueBytes bounds one metadata value.
	maxFindingMetadataValueBytes = 256
)

// Finding is the canonical detection finding (phase 10): one structured,
// evidence-cited judgment a detection rule produced about one subject asset.
//
// The identity is "ruleID@subject" (each component percent-encoded, the
// subject as its canonical identity string), namespaced by KindFinding — the
// same rule firing twice on the same subject is one finding that merges, and
// findings can never collide with any other asset kind.
//
// A finding is a recorded judgment, never a verified fact: the framework that
// produces it executes rules only, and no field claims exploitation,
// reachability, or a tested behavior. The priority and status vocabularies
// are owned by the detection framework; the asset layer bounds the fields.
type Finding struct {
	// RuleID is the ID of the rule that produced the finding. Part of the
	// identity.
	RuleID string `json:"rule_id"`

	// RuleName is the human-readable name of the rule, denormalized from
	// the immutable rule metadata for self-describing reports. Not part of
	// the identity.
	RuleName string `json:"rule_name"`

	// Category is the rule's category label (the detection framework's
	// vocabulary). Not part of the identity.
	Category string `json:"category"`

	// Subject is the canonical identity of the asset the finding is about.
	// Part of the identity.
	Subject Identity `json:"subject"`

	// Confidence is the rule's confidence in this finding, in [0,1]. Not
	// part of the identity.
	Confidence float64 `json:"confidence"`

	// Evidence cites the Phase 2 evidence records backing the finding. A
	// finding must carry at least one evidence record — a judgment that
	// rests on nothing is not representable (NewFinding enforces this).
	Evidence []Evidence `json:"evidence"`

	// RelatedAssets references other canonical asset identities involved in
	// the finding beyond its subject.
	RelatedAssets []Identity `json:"related_assets,omitempty"`

	// Relationships carries typed edges between the related assets the
	// finding cites (never involving the finding itself: a finding is a
	// judgment about assets, not a graph node with its own edges).
	Relationships []Relationship `json:"relationships,omitempty"`

	// Priority is the attention-ordering label (the detection framework's
	// vocabulary). It is an ordering hint for a researcher, never a
	// severity or exploitability claim.
	Priority string `json:"priority"`

	// Status is the lifecycle label (the detection framework's vocabulary).
	Status string `json:"status"`

	// Created is the time the finding was first produced.
	Created time.Time `json:"created"`

	// Updated is the time the finding was last re-observed or revised; a
	// zero value normalizes to Created.
	Updated time.Time `json:"updated"`

	// Metadata carries bounded typed string annotations. It is a
	// map[string]string — never an anonymous map — with bounded entry
	// count, keys, and values.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewFinding builds a validated, normalized Finding.
//
// Validation covers every bound (see the constants above), the confidence
// range (NaN is rejected explicitly — NaN compares false against every bound
// and would otherwise propagate), the presence of at least one evidence
// record, non-zero subject and related identities, and timestamp ordering.
// Normalization deduplicates evidence (by identity, through MergeEvidence),
// related assets (by identity), and relationships (by edge ID), sorts each
// list deterministically, and defaults Updated to Created.
func NewFinding(f Finding) (Finding, error) {
	if err := validateFindingLabel(f.RuleID, "rule id", maxFindingRuleIDBytes); err != nil {
		return Finding{}, err
	}
	if err := validateFindingLabel(f.RuleName, "rule name", maxFindingRuleNameBytes); err != nil {
		return Finding{}, err
	}
	if err := validateFindingLabel(f.Category, "category", maxFindingCategoryBytes); err != nil {
		return Finding{}, err
	}
	if err := validateFindingLabel(f.Priority, "priority", maxFindingLabelBytes); err != nil {
		return Finding{}, err
	}
	if err := validateFindingLabel(f.Status, "status", maxFindingLabelBytes); err != nil {
		return Finding{}, err
	}
	if f.Subject.IsZero() {
		return Finding{}, fmt.Errorf("finding subject identity must not be zero")
	}
	if math.IsNaN(f.Confidence) || f.Confidence < 0 || f.Confidence > 1 {
		return Finding{}, fmt.Errorf("finding confidence %v is NaN or out of [0,1]", f.Confidence)
	}
	if len(f.Evidence) == 0 {
		return Finding{}, fmt.Errorf("finding for rule %q carries no evidence", f.RuleID)
	}
	if len(f.Evidence) > maxFindingEvidence {
		return Finding{}, fmt.Errorf("finding for rule %q cites %d evidence records over bound %d",
			f.RuleID, len(f.Evidence), maxFindingEvidence)
	}
	for i, ev := range f.Evidence {
		canonical, err := NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return Finding{}, fmt.Errorf("evidence record %d: %w", i, err)
		}
		if canonical != ev {
			return Finding{}, fmt.Errorf("evidence record %d is not canonical", i)
		}
	}
	if len(f.RelatedAssets) > maxFindingRelated {
		return Finding{}, fmt.Errorf("finding for rule %q references %d related assets over bound %d",
			f.RuleID, len(f.RelatedAssets), maxFindingRelated)
	}
	for i, id := range f.RelatedAssets {
		if id.IsZero() {
			return Finding{}, fmt.Errorf("related asset %d is a zero identity", i)
		}
	}
	if len(f.Relationships) > maxFindingRelationships {
		return Finding{}, fmt.Errorf("finding for rule %q carries %d relationships over bound %d",
			f.RuleID, len(f.Relationships), maxFindingRelationships)
	}
	for i, rel := range f.Relationships {
		canonical, err := NewRelationship(rel.From, rel.Kind, rel.To)
		if err != nil {
			return Finding{}, fmt.Errorf("relationship %d: %w", i, err)
		}
		if canonical != rel {
			return Finding{}, fmt.Errorf("relationship %d is not canonical", i)
		}
	}
	if len(f.Metadata) > maxFindingMetadataEntries {
		return Finding{}, fmt.Errorf("finding for rule %q carries %d metadata entries over bound %d",
			f.RuleID, len(f.Metadata), maxFindingMetadataEntries)
	}
	for k, v := range f.Metadata {
		if err := validateFindingLabel(k, "metadata key", maxFindingMetadataKeyBytes); err != nil {
			return Finding{}, err
		}
		if len(v) > maxFindingMetadataValueBytes {
			return Finding{}, fmt.Errorf("metadata value for %q is over %d bytes", k, maxFindingMetadataValueBytes)
		}
	}
	if f.Created.IsZero() {
		return Finding{}, fmt.Errorf("finding for rule %q has no creation time", f.RuleID)
	}
	if f.Updated.IsZero() {
		f.Updated = f.Created
	}
	if f.Updated.Before(f.Created) {
		return Finding{}, fmt.Errorf("finding updated time %s precedes created time %s", f.Updated, f.Created)
	}

	f.Evidence = dedupeEvidence(f.Evidence)
	f.RelatedAssets = dedupeFindingIdentities(f.RelatedAssets)
	f.Relationships = dedupeFindingRelationships(f.Relationships)
	return f, nil
}

// validateFindingLabel enforces the shared string-field contract: non-empty,
// within bound, printable ASCII (no control characters inside a canonical
// label).
func validateFindingLabel(s, what string, max int) error {
	if s == "" {
		return fmt.Errorf("finding %s must not be empty", what)
	}
	if len(s) > max {
		return fmt.Errorf("finding %s is over %d bytes", what, max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("finding %s contains a non-printable character", what)
		}
	}
	return nil
}

// dedupeEvidence merges same-identity evidence records deterministically and
// sorts by identity value.
func dedupeEvidence(list []Evidence) []Evidence {
	sorted := make([]Evidence, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Identity().Value < sorted[j].Identity().Value
	})
	out := make([]Evidence, 0, len(sorted))
	for _, ev := range sorted {
		if n := len(out); n > 0 {
			if merged, err := MergeEvidence(out[n-1], ev); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

// dedupeFindingIdentities removes duplicates and sorts by identity string.
func dedupeFindingIdentities(list []Identity) []Identity {
	sorted := make([]Identity, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	out := make([]Identity, 0, len(sorted))
	for _, id := range sorted {
		if n := len(out); n > 0 && out[n-1] == id {
			continue
		}
		out = append(out, id)
	}
	return out
}

// dedupeFindingRelationships removes duplicate edges and sorts by edge ID.
func dedupeFindingRelationships(list []Relationship) []Relationship {
	sorted := make([]Relationship, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })
	out := make([]Relationship, 0, len(sorted))
	for _, rel := range sorted {
		if n := len(out); n > 0 && out[n-1].ID() == rel.ID() {
			continue
		}
		out = append(out, rel)
	}
	return out
}

// Identity returns the deterministic identity used for deduplication:
// KindFinding namespaced, value "ruleID@subject" with each component
// percent-encoded (the subject as its canonical identity string), so a
// separator inside a rule ID or an identity value can never blur the
// boundary.
func (f Finding) Identity() Identity {
	return Identity{
		Kind:  KindFinding,
		Value: percentEncode(f.RuleID) + "@" + percentEncode(f.Subject.String()),
	}
}

// ID returns the canonical identity string.
func (f Finding) ID() string { return f.Identity().String() }

// String returns the canonical identity value, e.g.
// "rule-xss.reflected%40url%3Ahttps%3A%2F%2Fexample.com".
func (f Finding) String() string { return f.Identity().Value }

// MergeFindings combines two observations of the same finding.
//
// The identity fields (rule ID, subject) must match. The denormalized rule
// metadata (name, category) and the priority/status labels are taken from the
// higher-confidence side — equal confidences resolve through the
// lexicographically smaller (name, category, priority, status) tuple, so the
// result never depends on merge order. Timestamps compose honestly (earliest
// Created, latest Updated) and confidence keeps the maximum.
//
// The evidence, related-asset, relationship, and metadata lists union
// deterministically up to their per-list bounds. When a union exceeds its
// bound the cut is DETERMINISTIC but not signaled: the merged lists are
// already sorted, so the retained records are the sorted prefix — evidence
// keeps the maxFindingEvidence smallest identities, related assets the
// maxFindingRelated smallest identity strings, relationships the
// maxFindingRelationships smallest edge IDs, and metadata drops the
// lexicographically largest keys beyond maxFindingMetadataEntries. A merge
// therefore never returns the full union of two maximal lists (two
// 16-record evidence lists merge to 16 records, not 32); callers that need
// to detect the cut must compare lengths before and after.
func MergeFindings(a, b Finding) (Finding, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Finding{}, mergeMismatch(KindFinding, a.Identity(), b.Identity())
	}
	m := a
	if b.Confidence > a.Confidence {
		m.RuleName, m.Category, m.Priority, m.Status = b.RuleName, b.Category, b.Priority, b.Status
		m.Confidence = b.Confidence
	} else if b.Confidence == a.Confidence &&
		(b.RuleName < a.RuleName || (b.RuleName == a.RuleName &&
			(b.Category < a.Category || (b.Category == a.Category &&
				(b.Priority < a.Priority || (b.Priority == a.Priority && b.Status < a.Status)))))) {
		m.RuleName, m.Category, m.Priority, m.Status = b.RuleName, b.Category, b.Priority, b.Status
	}
	if b.Created.Before(a.Created) {
		m.Created = b.Created
	}
	if b.Updated.After(a.Updated) {
		m.Updated = b.Updated
	}
	m.Evidence = dedupeEvidence(append(append([]Evidence{}, a.Evidence...), b.Evidence...))
	m.RelatedAssets = dedupeFindingIdentities(append(append([]Identity{}, a.RelatedAssets...), b.RelatedAssets...))
	m.Relationships = dedupeFindingRelationships(append(append([]Relationship{}, a.Relationships...), b.Relationships...))
	m.Metadata = mergeFindingMetadata(a.Metadata, b.Metadata)
	if len(m.Evidence) > maxFindingEvidence {
		m.Evidence = m.Evidence[:maxFindingEvidence]
	}
	if len(m.RelatedAssets) > maxFindingRelated {
		m.RelatedAssets = m.RelatedAssets[:maxFindingRelated]
	}
	if len(m.Relationships) > maxFindingRelationships {
		m.Relationships = m.Relationships[:maxFindingRelationships]
	}
	return m, nil
}

// mergeFindingMetadata unions two metadata maps; an existing non-empty value
// wins over an empty one, and otherwise the receiver's value is kept — the
// result never depends on map iteration order.
func mergeFindingMetadata(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range b {
		out[k] = v
	}
	for k, v := range a {
		if existing, ok := out[k]; !ok || existing == "" {
			out[k] = v
		}
	}
	if len(out) > maxFindingMetadataEntries {
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:len(keys)-maxFindingMetadataEntries] {
			delete(out, k)
		}
	}
	return out
}
