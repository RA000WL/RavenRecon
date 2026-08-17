package detect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// FindingPriority is the typed attention-ordering label of a finding. It is
// an ordering hint for a researcher — never a severity, exploitability, or
// impact claim, and never a tested behavior.
type FindingPriority string

// Finding priorities, weakest → strongest.
const (
	PriorityInfo     FindingPriority = "info"
	PriorityLow      FindingPriority = "low"
	PriorityMedium   FindingPriority = "medium"
	PriorityHigh     FindingPriority = "high"
	PriorityCritical FindingPriority = "critical"
)

// String returns the canonical lowercase priority label.
func (p FindingPriority) String() string { return string(p) }

// Valid reports whether p is one of the known priorities.
func (p FindingPriority) Valid() bool {
	switch p {
	case PriorityInfo, PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical:
		return true
	}
	return false
}

// ParseFindingPriority parses a canonical priority label.
func ParseFindingPriority(s string) (FindingPriority, error) {
	p := FindingPriority(s)
	if !p.Valid() {
		return "", fmt.Errorf("unknown finding priority %q", s)
	}
	return p, nil
}

// rank orders priorities weakest→strongest (used by deterministic merges).
func (p FindingPriority) rank() int {
	switch p {
	case PriorityInfo:
		return 0
	case PriorityLow:
		return 1
	case PriorityMedium:
		return 2
	case PriorityHigh:
		return 3
	case PriorityCritical:
		return 4
	}
	return -1
}

// FindingStatus is the typed lifecycle label of a finding. The framework
// always emits open; dismissed is reserved for downstream consumer
// bookkeeping (a researcher dismissed the finding) and is accepted on parse
// only.
type FindingStatus string

// Finding statuses.
const (
	StatusOpen      FindingStatus = "open"
	StatusDismissed FindingStatus = "dismissed"
)

// String returns the canonical lowercase status label.
func (s FindingStatus) String() string { return string(s) }

// Valid reports whether s is one of the known statuses.
func (s FindingStatus) Valid() bool {
	switch s {
	case StatusOpen, StatusDismissed:
		return true
	}
	return false
}

// ParseFindingStatus parses a canonical status label.
func ParseFindingStatus(s string) (FindingStatus, error) {
	v := FindingStatus(s)
	if !v.Valid() {
		return "", fmt.Errorf("unknown finding status %q", s)
	}
	return v, nil
}

// validateFinding checks one detector-returned (or cache-decoded) finding
// against the framework's full output contract. It is the single validation
// point shared by the fresh-execution path and the cache decode path, so a
// cached finding and a fresh finding obey identical rules:
//
//   - the finding re-validates canonically through asset.NewFinding and
//     round-trips byte-identically (bounds, deduplication, normalization);
//   - the denormalized rule metadata matches the EXECUTING rule exactly —
//     RuleID, RuleName, and Category — so a rule can never forge another
//     rule's findings (finding corruption guard);
//   - the priority and status labels are known vocabulary values;
//   - the subject, every related asset, and every evidence record's source
//     asset were OBSERVED in the run's corpus (a finding can never cite an
//     asset the earlier phases never produced — the subject it is about, the
//     assets it relates, and the assets its evidence was observed on);
//   - an optional "rule_version" metadata entry equals the executing rule's
//     version.
func validateFinding(f asset.Finding, r Rule, observed map[asset.Identity]struct{}) error {
	canonical, err := asset.NewFinding(f)
	if err != nil {
		return fmt.Errorf("finding is not canonical: %w", err)
	}
	fb, cb := marshalFindingJSON(f), marshalFindingJSON(canonical)
	if fb != cb {
		return fmt.Errorf("finding does not round-trip canonically")
	}
	if f.RuleID != r.ID {
		return fmt.Errorf("finding rule id %q does not match the executing rule %q", f.RuleID, r.ID)
	}
	if f.RuleName != r.Name {
		return fmt.Errorf("finding rule name %q does not match the executing rule", f.RuleName)
	}
	if f.Category != r.Category.String() {
		return fmt.Errorf("finding category %q does not match the rule category %q", f.Category, r.Category)
	}
	if _, err := ParseFindingPriority(f.Priority); err != nil {
		return fmt.Errorf("finding priority: %w", err)
	}
	if _, err := ParseFindingStatus(f.Status); err != nil {
		return fmt.Errorf("finding status: %w", err)
	}
	if _, ok := observed[f.Subject]; !ok {
		return fmt.Errorf("finding subject %s was not observed in the corpus", f.Subject)
	}
	for i, id := range f.RelatedAssets {
		if _, ok := observed[id]; !ok {
			return fmt.Errorf("related asset %d (%s) was not observed in the corpus", i, id)
		}
	}
	// A canonical finding's evidence records always carry a non-zero source
	// (asset.NewEvidence rejects zero sources); the zero guard keeps this
	// check total even for hand-rolled inputs.
	for i, ev := range f.Evidence {
		if ev.Source.IsZero() {
			continue
		}
		if _, ok := observed[ev.Source]; !ok {
			return fmt.Errorf("evidence record %d cites unobserved source %s", i, ev.Source)
		}
	}
	if v, ok := f.Metadata["rule_version"]; ok && v != r.Version {
		return fmt.Errorf("finding claims rule version %q but the executing rule is %q", v, r.Version)
	}
	return nil
}

// marshalFindingJSON is the canonical serialized form used for round-trip
// equality (encoding/json sorts map keys, so the form is deterministic).
func marshalFindingJSON(f asset.Finding) string {
	buf, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(buf)
}

// mergeFindings reduces a rule's findings to one per identity through the
// asset merge primitive, preserving the input's first-occurrence order.
func mergeFindings(list []asset.Finding) ([]asset.Finding, error) {
	index := make(map[string]int, len(list))
	out := make([]asset.Finding, 0, len(list))
	for _, f := range list {
		id := f.Identity().String()
		if i, ok := index[id]; ok {
			merged, err := asset.MergeFindings(out[i], f)
			if err != nil {
				return nil, fmt.Errorf("merge finding %s: %w", id, err)
			}
			out[i] = merged
			continue
		}
		index[id] = len(out)
		out = append(out, f)
	}
	return out, nil
}

// sortFindings orders findings by identity string — the report's canonical
// deterministic order.
func sortFindings(list []asset.Finding) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().String() < list[j].Identity().String()
	})
}
