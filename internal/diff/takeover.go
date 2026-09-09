package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Takeover bloom (NEW-143): a derived projection of the findings presence
// axis that surfaces takeover-finding deltas per (rule, provider) in the
// human summary. It is observational only — a regrouping of identities
// already diffed under "findings" — and never claims exploitability.
//
// Construction: SnapshotOf indexes every finding whose rule ID carries
// the "takeover." prefix by (rule, provider) (provider from the
// finding's metadata, "unknown" when absent so hand-rolled inputs stay
// deterministic); Diff subtracts the baseline histogram from the current
// one. The bloom is nil if and only if NEITHER side tracks takeover
// findings — empty-takeover reports carry no section (absent, pinned by
// TestTakeoverBloomAbsentWhenEmpty). A non-nil bloom with empty
// Added/Removed means takeover is tracked on at least one side with no
// count change.
//
// The bloom never affects Delta.Empty, AddedCount, or RemovedCount: it
// projects the findings axis, it is not a new axis (an unchanged
// takeover set alongside other changes still reports through those).

// TakeoverCount is one (rule, provider) cell of the takeover bloom.
type TakeoverCount struct {
	Rule     string `json:"rule"`
	Provider string `json:"provider"`
	Count    int    `json:"count"`
}

// TakeoverBloom is the takeover projection of a Delta: per-(rule,
// provider) added/removed finding counts, each list sorted by (rule,
// provider) and non-nil whenever the bloom itself is non-nil (never
// nil-vs-empty ambiguity within a tracked bloom).
type TakeoverBloom struct {
	Added   []TakeoverCount `json:"added"`
	Removed []TakeoverCount `json:"removed"`
}

// Empty reports whether the bloom carries no count change on either
// side (a nil bloom — untracked on both sides — is also empty).
func (b *TakeoverBloom) Empty() bool {
	return b == nil || (len(b.Added) == 0 && len(b.Removed) == 0)
}

// AddedTotal and RemovedTotal sum the bloom cells per side.
func (b *TakeoverBloom) AddedTotal() int {
	if b == nil {
		return 0
	}
	n := 0
	for _, c := range b.Added {
		n += c.Count
	}
	return n
}

// RemovedTotal sums the removed bloom cells.
func (b *TakeoverBloom) RemovedTotal() int {
	if b == nil {
		return 0
	}
	n := 0
	for _, c := range b.Removed {
		n += c.Count
	}
	return n
}

// takeoverRulePrefix is the rule-ID namespace the bloom tracks. The
// framework ships no registry of pack prefixes; the literal prefix keeps
// the projection decoupled from pack registration (core never branches
// on tool or pack names — the bloom reads finding rule IDs, not pack
// membership).
const takeoverRulePrefix = "takeover."

// takeoverUnknownProvider is the deterministic provider cell for
// takeover findings carrying no provider metadata (hand-rolled or
// foreign inputs): they still count, never vanish silently.
const takeoverUnknownProvider = "unknown"

// takeoverKey joins one histogram cell. NUL cannot appear in a rule ID
// (bounded printable labels) or a provider value (bounded metadata
// values exclude it by construction of the canonical forms), so the
// boundary never blurs.
func takeoverKey(rule, provider string) string { return rule + "\x00" + provider }

// splitTakeoverKey recovers the cell coordinates.
func splitTakeoverKey(key string) (rule, provider string) {
	rule, provider, _ = strings.Cut(key, "\x00")
	return rule, provider
}

// buildTakeoverCounts indexes one snapshot's takeover findings by
// (rule, provider). It returns nil when the snapshot tracks no takeover
// findings (so Diff can distinguish "absent on both sides" from
// "tracked but unchanged").
func buildTakeoverCounts(findings []asset.Finding) map[string]int {
	var out map[string]int
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, takeoverRulePrefix) {
			continue
		}
		provider := f.Metadata["provider"]
		if provider == "" {
			provider = takeoverUnknownProvider
		}
		if out == nil {
			out = make(map[string]int)
		}
		out[takeoverKey(f.RuleID, provider)]++
	}
	return out
}

// diffTakeover subtracts the baseline histogram from the current one,
// yielding the bloom (nil iff neither side tracks takeover findings).
// Cells are sorted by (rule, provider) for deterministic rendering.
func diffTakeover(baseline, current map[string]int) *TakeoverBloom {
	if len(baseline) == 0 && len(current) == 0 {
		return nil
	}
	bloom := &TakeoverBloom{Added: []TakeoverCount{}, Removed: []TakeoverCount{}}
	keys := make([]string, 0, len(baseline)+len(current))
	seen := make(map[string]struct{}, len(baseline)+len(current))
	for k := range baseline {
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	for k := range current {
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		delta := current[k] - baseline[k]
		if delta == 0 {
			continue
		}
		rule, provider := splitTakeoverKey(k)
		if delta > 0 {
			bloom.Added = append(bloom.Added, TakeoverCount{Rule: rule, Provider: provider, Count: delta})
		} else {
			bloom.Removed = append(bloom.Removed, TakeoverCount{Rule: rule, Provider: provider, Count: -delta})
		}
	}
	sortTakeoverCells(bloom.Added)
	sortTakeoverCells(bloom.Removed)
	return bloom
}

func sortTakeoverCells(cells []TakeoverCount) {
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Rule != cells[j].Rule {
			return cells[i].Rule < cells[j].Rule
		}
		return cells[i].Provider < cells[j].Provider
	})
}

// formatTakeoverCell renders one bloom cell for the human outputs:
// "takeover.cname.unclaimed provider=herokuapp.com x2".
func formatTakeoverCell(c TakeoverCount) string {
	return fmt.Sprintf("%s provider=%s x%d", c.Rule, c.Provider, c.Count)
}
