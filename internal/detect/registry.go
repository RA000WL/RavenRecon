package detect

import (
	"fmt"
	"sort"
	"sync"
)

// maxRegistryRules bounds the registry (fixed constant): it protects the
// scheduler's memory from runaway registration while staying far above the
// documented performance targets (100/500/1000 rules).
const maxRegistryRules = 4096

// Registry is the rule registration point: rules are validated on
// registration, stored as immutable deep copies, and never mutated
// afterwards. It is safe for concurrent use; the expected pattern is
// single-writer at startup, many readers at run time.
//
// Per-rule validation (duplicate IDs and names, metadata completeness,
// category/version/cost/input/output/asset-kind vocabularies, dependency
// syntax, timeout bounds, detector presence) happens in Register — an
// invalid rule is rejected at registration, never at execution. The
// dependency GRAPH (missing dependency references, cycles) spans multiple
// rules and is validated by Validate, which the engine calls before every
// run (and which callers should call once at startup).
type Registry struct {
	mu    sync.RWMutex
	rules map[string]Rule
	names map[string]string // lowercase name -> rule ID
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		rules: make(map[string]Rule),
		names: make(map[string]string),
	}
}

// Register validates rule and adds it to the registry as an immutable deep
// copy. Duplicate rule IDs and duplicate names (case-insensitive) are
// rejected.
func (r *Registry) Register(rule Rule) error {
	if err := validateRule(rule); err != nil {
		return fmt.Errorf("detect: register rule: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rules) >= maxRegistryRules {
		return fmt.Errorf("detect: registry is full (%d rules)", maxRegistryRules)
	}
	if _, ok := r.rules[rule.ID]; ok {
		return fmt.Errorf("detect: duplicate rule id %q", rule.ID)
	}
	nameKey := lowerASCII(rule.Name)
	if owner, ok := r.names[nameKey]; ok {
		return fmt.Errorf("detect: rule name %q duplicates rule %q", rule.Name, owner)
	}
	r.rules[rule.ID] = rule.clone()
	r.names[nameKey] = rule.ID
	return nil
}

// Get returns a copy of the registered rule with the given ID.
func (r *Registry) Get(id string) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	if !ok {
		return Rule{}, false
	}
	return rule.clone(), true
}

// Rules returns every registered rule as copies sorted by ID — the
// deterministic registry order.
func (r *Registry) Rules() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len returns the number of registered rules.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

// Validate checks the dependency graph over every registered rule: every
// dependency must reference a registered rule, and the graph must be
// acyclic. The error names the smallest offending rule ID deterministically.
func (r *Registry) Validate() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rule := range r.rules {
		for _, dep := range rule.Dependencies {
			if _, ok := r.rules[dep]; !ok {
				return fmt.Errorf("detect: rule %q depends on unregistered rule %q", rule.ID, dep)
			}
		}
	}
	if _, err := scheduleLevels(r.rules); err != nil {
		return err
	}
	return nil
}

// scheduleLevels computes the dependency levels of the rule graph through
// layered Kahn elimination: level 0 holds every rule with no dependencies,
// level n+1 holds every rule whose dependencies all live in earlier levels.
// Within a level, rule IDs are sorted, so the schedule is a deterministic
// function of the graph. Total work is O(V log V + E) — no quadratic
// scheduling. A cycle surfaces as an error naming the smallest rule ID that
// remains unreachable.
func scheduleLevels(rules map[string]Rule) ([][]string, error) {
	indegree := make(map[string]int, len(rules))
	dependents := make(map[string][]string, len(rules))
	for id, rule := range rules {
		indegree[id] = len(rule.Dependencies)
		for _, dep := range rule.Dependencies {
			dependents[dep] = append(dependents[dep], id)
		}
	}
	ready := make([]string, 0, len(rules))
	for id, deg := range indegree {
		if deg == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)

	var levels [][]string
	scheduled := 0
	for len(ready) > 0 {
		levels = append(levels, ready)
		scheduled += len(ready)
		next := make([]string, 0, len(ready))
		for _, id := range ready {
			for _, dependent := range dependents[id] {
				indegree[dependent]--
				if indegree[dependent] == 0 {
					next = append(next, dependent)
				}
			}
		}
		sort.Strings(next)
		ready = next
	}
	if scheduled != len(rules) {
		smallest := ""
		for id, deg := range indegree {
			if deg > 0 && (smallest == "" || id < smallest) {
				smallest = id
			}
		}
		return nil, fmt.Errorf("detect: dependency cycle detected (rule %q is on a cycle)", smallest)
	}
	return levels, nil
}

// lowerASCII lowercases ASCII letters only — the duplicate-name fold. It
// avoids unicode folding surprises in rule names.
func lowerASCII(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}
