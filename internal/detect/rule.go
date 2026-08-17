package detect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Rule model bounds (fixed constants).
const (
	// maxRuleIDBytes bounds a rule ID.
	maxRuleIDBytes = 128
	// maxRuleNameBytes bounds a rule name.
	maxRuleNameBytes = 256
	// maxRuleDescriptionBytes bounds a rule description.
	maxRuleDescriptionBytes = 1024
	// maxRuleAuthorBytes bounds the author attribution.
	maxRuleAuthorBytes = 128
	// maxRuleVersionBytes bounds a rule version.
	maxRuleVersionBytes = 32
	// maxRuleDependencies bounds the dependency list of one rule.
	maxRuleDependencies = 16
	// maxRuleTimeout bounds a rule's declared timeout.
	maxRuleTimeout = 10 * time.Minute
)

// RuleInput names one structured input domain a rule consumes from the
// detection Context. The declared inputs are descriptive metadata (surfaced
// for scheduling and audit); the Context always carries every domain and a
// rule reads what it declared.
type RuleInput string

// Rule input domains (exactly the fixed Context domains).
const (
	InputAssets        RuleInput = "assets"
	InputRelationships RuleInput = "relationships"
	InputEvidence      RuleInput = "evidence"
	InputTechnology    RuleInput = "technology"
	InputSecrets       RuleInput = "secrets"
	InputJavaScript    RuleInput = "javascript"
	InputEndpoints     RuleInput = "endpoints"
)

// Valid reports whether i is one of the known input domains.
func (i RuleInput) Valid() bool {
	switch i {
	case InputAssets, InputRelationships, InputEvidence, InputTechnology,
		InputSecrets, InputJavaScript, InputEndpoints:
		return true
	}
	return false
}

// KnownRuleInputs returns every input domain in canonical sorted order. The
// returned slice is a fresh copy.
func KnownRuleInputs() []RuleInput {
	return []RuleInput{
		InputAssets, InputEndpoints, InputEvidence, InputJavaScript,
		InputRelationships, InputSecrets, InputTechnology,
	}
}

// RuleOutput names one structured output a rule emits. Phase 10's only
// output is findings: evidence records and related-asset edges ride ON the
// findings that cite them, and the framework stores nothing else.
type RuleOutput string

// Rule outputs.
const (
	OutputFindings RuleOutput = "findings"
)

// Valid reports whether o is one of the known outputs.
func (o RuleOutput) Valid() bool {
	switch o {
	case OutputFindings:
		return true
	}
	return false
}

// KnownRuleOutputs returns every output in canonical sorted order. The
// returned slice is a fresh copy.
func KnownRuleOutputs() []RuleOutput {
	return []RuleOutput{OutputFindings}
}

// Cost is the declared estimated cost class of a rule — a scheduling hint
// for future phase consumers, never an enforced budget.
type Cost string

// Cost classes.
const (
	CostLow    Cost = "low"
	CostMedium Cost = "medium"
	CostHigh   Cost = "high"
)

// String returns the canonical lowercase cost label.
func (c Cost) String() string { return string(c) }

// Valid reports whether c is one of the known cost classes.
func (c Cost) Valid() bool {
	switch c {
	case CostLow, CostMedium, CostHigh:
		return true
	}
	return false
}

// ParseCost parses a canonical cost label.
func ParseCost(s string) (Cost, error) {
	c := Cost(s)
	if !c.Valid() {
		return "", fmt.Errorf("unknown rule cost %q", s)
	}
	return c, nil
}

// Detector is one rule's detection function. It receives the cancellation
// context (already carrying the rule's own deadline) and the immutable
// detection Context, and returns the findings it produced.
//
// Contract: a detector operates only on the structured Context domains, must
// honor ctx cancellation, must not panic (panics are contained and fail the
// rule, never the run), and must return findings that pass validateFinding —
// built through asset.NewFinding with the rule's own ID, name, and category,
// subjects drawn from the observed corpus, and at least one evidence record
// each. A detector performs no I/O of its own in phase 10; the framework
// gives it everything it may look at.
type Detector func(ctx context.Context, dctx *Context) ([]asset.Finding, error)

// Rule is one registered detection rule: an immutable metadata descriptor
// plus the Detector that implements it. Rules are immutable once registered:
// the Registry deep-copies every slice at registration time and hands back
// copies, so no caller-held alias can mutate a registered rule.
type Rule struct {
	// ID is the canonical rule identifier: lowercase letters, digits,
	// dots, hyphens, and underscores, e.g. "exposure.admin-panel".
	ID string `json:"id"`

	// Name is the human-readable rule name.
	Name string `json:"name"`

	// Description explains what the rule detects and on what signals.
	Description string `json:"description"`

	// Category is the rule's classification (see Category).
	Category Category `json:"category"`

	// Version is the rule's semantic version, "major.minor.patch". The
	// contract: bump the version whenever the detector's logic or metadata
	// changes — the version enters the rule result cache key, so an edit
	// without a bump can serve stale cached findings.
	Version string `json:"version"`

	// Inputs lists the Context domains the rule consumes (descriptive).
	Inputs []RuleInput `json:"inputs"`

	// Outputs lists the structured outputs the rule emits.
	Outputs []RuleOutput `json:"outputs"`

	// Dependencies lists the IDs of rules that must complete before this
	// rule executes. Dependencies order execution; they do not (yet) flow
	// data: the Context's domains are the fixed pre-run corpus. Cycles are
	// rejected at validation.
	Dependencies []string `json:"dependencies,omitempty"`

	// RequiredAssetTypes lists the asset kinds the rule needs in the
	// corpus; a rule whose required kind is absent from the snapshot is
	// skipped with an honest reason instead of executed against nothing.
	RequiredAssetTypes []asset.Kind `json:"required_asset_types,omitempty"`

	// EstimatedCost declares the rule's cost class (hint, not a budget).
	EstimatedCost Cost `json:"estimated_cost"`

	// Timeout is the rule's execution deadline. Must be > 0 and bounded.
	Timeout time.Duration `json:"timeout"`

	// Author attributes the rule's authorship.
	Author string `json:"author"`

	// Enabled selects whether the rule executes. Disabled rules remain
	// registered (and must still validate) but are skipped at run time.
	Enabled bool `json:"enabled"`

	// Detector is the rule's implementation. Never nil for a valid rule.
	Detector Detector `json:"-"`
}

// validateRule checks the complete rule contract (everything except the
// dependency graph, which the Registry validates as a whole): metadata
// completeness, category/version/cost vocabularies, input and output
// domains, dependency syntax, required asset kinds, timeout bounds, and the
// detector's presence.
func validateRule(r Rule) error {
	if err := validateRuleID(r.ID); err != nil {
		return err
	}
	if r.Name == "" || len(r.Name) > maxRuleNameBytes {
		return fmt.Errorf("rule %q name is empty or over %d bytes", r.ID, maxRuleNameBytes)
	}
	if r.Description == "" || len(r.Description) > maxRuleDescriptionBytes {
		return fmt.Errorf("rule %q description is empty or over %d bytes", r.ID, maxRuleDescriptionBytes)
	}
	if !r.Category.Valid() {
		return fmt.Errorf("rule %q category %q is unknown (known: %s)",
			r.ID, r.Category, strings.Join(sortedCategories(), ", "))
	}
	if err := validateRuleVersion(r.Version); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if len(r.Inputs) == 0 {
		return fmt.Errorf("rule %q declares no inputs", r.ID)
	}
	seenInputs := make(map[RuleInput]bool, len(r.Inputs))
	for _, in := range r.Inputs {
		if !in.Valid() {
			return fmt.Errorf("rule %q input %q is unknown", r.ID, in)
		}
		if seenInputs[in] {
			return fmt.Errorf("rule %q declares input %q twice", r.ID, in)
		}
		seenInputs[in] = true
	}
	if len(r.Outputs) == 0 {
		return fmt.Errorf("rule %q declares no outputs", r.ID)
	}
	seenOutputs := make(map[RuleOutput]bool, len(r.Outputs))
	for _, out := range r.Outputs {
		if !out.Valid() {
			return fmt.Errorf("rule %q output %q is unknown", r.ID, out)
		}
		if seenOutputs[out] {
			return fmt.Errorf("rule %q declares output %q twice", r.ID, out)
		}
		seenOutputs[out] = true
	}
	if len(r.Dependencies) > maxRuleDependencies {
		return fmt.Errorf("rule %q declares %d dependencies over bound %d",
			r.ID, len(r.Dependencies), maxRuleDependencies)
	}
	seenDeps := make(map[string]bool, len(r.Dependencies))
	for _, dep := range r.Dependencies {
		if err := validateRuleID(dep); err != nil {
			return fmt.Errorf("rule %q dependency: %w", r.ID, err)
		}
		if dep == r.ID {
			return fmt.Errorf("rule %q depends on itself", r.ID)
		}
		if seenDeps[dep] {
			return fmt.Errorf("rule %q declares dependency %q twice", r.ID, dep)
		}
		seenDeps[dep] = true
	}
	for _, k := range r.RequiredAssetTypes {
		if !k.Valid() {
			return fmt.Errorf("rule %q requires unknown asset kind %q", r.ID, k)
		}
	}
	if !r.EstimatedCost.Valid() {
		return fmt.Errorf("rule %q estimated cost %q is unknown", r.ID, r.EstimatedCost)
	}
	if r.Timeout <= 0 || r.Timeout > maxRuleTimeout {
		return fmt.Errorf("rule %q timeout %s must be > 0 and <= %s", r.ID, r.Timeout, maxRuleTimeout)
	}
	if r.Author == "" || len(r.Author) > maxRuleAuthorBytes {
		return fmt.Errorf("rule %q author is empty or over %d bytes", r.ID, maxRuleAuthorBytes)
	}
	if r.Detector == nil {
		return fmt.Errorf("rule %q has no detector", r.ID)
	}
	return nil
}

// validateRuleID enforces the canonical rule ID shape: lowercase slug
// characters only, 1..maxRuleIDBytes bytes. Canonical IDs make dependency
// references and cache targets unambiguous.
func validateRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("rule id must not be empty")
	}
	if len(id) > maxRuleIDBytes {
		return fmt.Errorf("rule id %q is over %d bytes", id, maxRuleIDBytes)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return fmt.Errorf("rule id %q contains %q (allowed: lowercase letters, digits, '.', '-', '_')",
				id, string(rune(c)))
		}
	}
	return nil
}

// validateRuleVersion enforces the "major.minor.patch" numeric shape.
func validateRuleVersion(v string) error {
	if v == "" {
		return fmt.Errorf("version must not be empty")
	}
	if len(v) > maxRuleVersionBytes {
		return fmt.Errorf("version %q is over %d bytes", v, maxRuleVersionBytes)
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return fmt.Errorf("version %q is not major.minor.patch", v)
	}
	for _, p := range parts {
		if p == "" || len(p) > 9 {
			return fmt.Errorf("version %q has a malformed component", v)
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return fmt.Errorf("version %q has a non-numeric component", v)
			}
		}
	}
	return nil
}

// clone returns a deep copy of the rule's slice and map fields so a
// registered rule can never be mutated through a caller-held alias.
func (r Rule) clone() Rule {
	cp := r
	cp.Inputs = copySlice(r.Inputs)
	cp.Outputs = copySlice(r.Outputs)
	cp.Dependencies = copySlice(r.Dependencies)
	cp.RequiredAssetTypes = copySlice(r.RequiredAssetTypes)
	return cp
}

func copySlice[T any](src []T) []T {
	if len(src) == 0 {
		return nil
	}
	out := make([]T, len(src))
	copy(out, src)
	return out
}
