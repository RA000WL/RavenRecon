package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Rule, context, and logger bounds (fixed constants). These constants are
// part of the frozen SDK surface (Level 1, the "SDK v1 (Core)" freeze of
// milestone v1.2.5; see api.go for the stability policy): the framework
// enforces exactly these limits at validation and at run time, and rule
// authors compile against them. A bound change is an SDK change — it must
// not happen silently.
const (
	// MaxRuleIDBytes bounds a rule ID.
	MaxRuleIDBytes = 128
	// MaxRuleNameBytes bounds a rule name.
	MaxRuleNameBytes = 256
	// MaxRuleDescriptionBytes bounds a rule description.
	MaxRuleDescriptionBytes = 1024
	// MaxRuleAuthorBytes bounds the author attribution.
	MaxRuleAuthorBytes = 128
	// MaxRuleVersionBytes bounds a rule version.
	MaxRuleVersionBytes = 32
	// MaxRuleDependencies bounds the dependency list of one rule.
	MaxRuleDependencies = 16
	// MaxRuleTimeout bounds a rule's declared timeout.
	MaxRuleTimeout = 10 * time.Minute
	// MaxContextConfigEntries bounds the configuration map delivered to
	// rules.
	MaxContextConfigEntries = 64
	// MaxContextConfigKeyBytes bounds one configuration key.
	MaxContextConfigKeyBytes = 64
	// MaxContextConfigValueBytes bounds one configuration value.
	MaxContextConfigValueBytes = 256
	// MaxLogEntries bounds the default logger's retained entries; entries
	// beyond the bound are counted, never stored.
	MaxLogEntries = 256
	// MaxLogMessageBytes bounds one log message.
	MaxLogMessageBytes = 512
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

// ValidateRule checks the complete rule contract (everything except the
// dependency graph, which the Registry validates as a whole): metadata
// completeness, category/version/cost vocabularies, input and output
// domains, dependency syntax, required asset kinds, timeout bounds, and the
// detector's presence. It is the exported SDK validation entry point and
// the SINGLE validation point: Registry.Register and BenchmarkDetector
// delegate to it, so a rule rejected here is rejected identically at
// registration.
func ValidateRule(r Rule) error {
	return validateRule(r)
}

// validateRule checks the complete rule contract (everything except the
// dependency graph, which the Registry validates as a whole): metadata
// completeness, category/version/cost vocabularies, input and output
// domains, dependency syntax, required asset kinds, timeout bounds, and the
// detector's presence. Exported callers use ValidateRule.
func validateRule(r Rule) error {
	if err := validateRuleID(r.ID); err != nil {
		return err
	}
	if r.Name == "" || len(r.Name) > MaxRuleNameBytes {
		return fmt.Errorf("rule %q name is empty or over %d bytes", r.ID, MaxRuleNameBytes)
	}
	if r.Description == "" || len(r.Description) > MaxRuleDescriptionBytes {
		return fmt.Errorf("rule %q description is empty or over %d bytes", r.ID, MaxRuleDescriptionBytes)
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
	if len(r.Dependencies) > MaxRuleDependencies {
		return fmt.Errorf("rule %q declares %d dependencies over bound %d",
			r.ID, len(r.Dependencies), MaxRuleDependencies)
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
	if r.Timeout <= 0 || r.Timeout > MaxRuleTimeout {
		return fmt.Errorf("rule %q timeout %s must be > 0 and <= %s", r.ID, r.Timeout, MaxRuleTimeout)
	}
	if r.Author == "" || len(r.Author) > MaxRuleAuthorBytes {
		return fmt.Errorf("rule %q author is empty or over %d bytes", r.ID, MaxRuleAuthorBytes)
	}
	if r.Detector == nil {
		return fmt.Errorf("rule %q has no detector", r.ID)
	}
	return nil
}

// validateRuleID enforces the canonical rule ID shape: lowercase slug
// characters only, 1..MaxRuleIDBytes bytes. Canonical IDs make dependency
// references and cache targets unambiguous.
func validateRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("rule id must not be empty")
	}
	if len(id) > MaxRuleIDBytes {
		return fmt.Errorf("rule id %q is over %d bytes", id, MaxRuleIDBytes)
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

// ParseRuleVersion parses a rule version, "major.minor.patch" with numeric
// components (each 1..9 digits, whole string at most MaxRuleVersionBytes
// bytes), and returns the three components. It is the exported SDK entry
// point of the single version parser; validateRuleVersion shares the same
// parser, so a version that parses validates, and vice versa.
func ParseRuleVersion(s string) (major, minor, patch int, err error) {
	return parseRuleVersion(s)
}

// parseRuleVersion is the single rule-version parser: it enforces the
// "major.minor.patch" numeric shape and returns the three components.
// validateRuleVersion and the exported ParseRuleVersion both use it.
func parseRuleVersion(v string) (major, minor, patch int, err error) {
	if v == "" {
		return 0, 0, 0, fmt.Errorf("version must not be empty")
	}
	if len(v) > MaxRuleVersionBytes {
		return 0, 0, 0, fmt.Errorf("version %q is over %d bytes", v, MaxRuleVersionBytes)
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("version %q is not major.minor.patch", v)
	}
	nums := [3]int{}
	for i, p := range parts {
		if p == "" || len(p) > 9 {
			return 0, 0, 0, fmt.Errorf("version %q has a malformed component", v)
		}
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return 0, 0, 0, fmt.Errorf("version %q has a non-numeric component", v)
			}
		}
		n, convErr := strconv.Atoi(p)
		if convErr != nil {
			// Unreachable after the digit and 9-byte checks above (a
			// 9-digit component always fits an int); defensive only, so a
			// future bound change can never silently truncate.
			return 0, 0, 0, fmt.Errorf("version %q has a malformed component", v)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// validateRuleVersion enforces the "major.minor.patch" numeric shape
// through the shared parser.
func validateRuleVersion(v string) error {
	_, _, _, err := parseRuleVersion(v)
	return err
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
