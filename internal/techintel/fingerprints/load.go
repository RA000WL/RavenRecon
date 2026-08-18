package fingerprints

import (
	"fmt"
	"math"
	"regexp"
	"sort"
)

// Load merges, validates, and compiles every category table into an
// immutable DB. It returns an error if any entry violates the model
// (duplicate names across tables, empty Match, invalid regex, weight out of
// range, bad category, bad indicator kind), so a malformed table can never
// reach the engine.
func Load() (*DB, error) {
	return compile(allTables())
}

// newRawDB is the TEST-ONLY constructor: it runs exactly the Load pipeline
// over caller-supplied raw entries, so validation paths are testable without
// touching the production tables. Production code must use Load.
func newRawDB(entries []Fingerprint) (*DB, error) {
	return compile(entries)
}

// CompileForTest builds a DB through exactly the Load pipeline (validation,
// compile-once regexes, deterministic sort) over caller-supplied entries.
// It exists so ENGINE tests can exercise COMPILED indicators — version
// extraction, the regex kinds — with synthetic fixtures (hand-built
// Indicators have nil MatchRe/VersionRe and silently never match).
// Production code must use Load; engine code must NEVER compile its own
// regular expressions.
func CompileForTest(entries []Fingerprint) (*DB, error) {
	return compile(entries)
}

// allTables merges the category tables in fixed, documented order.
func allTables() []Fingerprint {
	var out []Fingerprint
	out = append(out, frameworkTable()...)
	out = append(out, buildToolTable()...)
	out = append(out, serverTable()...)
	out = append(out, cdnTable()...)
	out = append(out, cloudTable()...)
	out = append(out, authTable()...)
	out = append(out, apiTable()...)
	out = append(out, cmsTable()...)
	out = append(out, infraTable()...)
	out = append(out, languageTable()...)
	return out
}

// compile validates every raw entry, compiles every regex exactly once, and
// returns the sorted, immutable DB.
func compile(entries []Fingerprint) (*DB, error) {
	d := &DB{schemaVersion: SchemaVersion}
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		if err := validateFingerprint(raw); err != nil {
			return nil, fmt.Errorf("fingerprint %q: %w", raw.Name, err)
		}
		if _, dup := seen[raw.Name]; dup {
			return nil, fmt.Errorf("duplicate fingerprint name %q across tables", raw.Name)
		}
		seen[raw.Name] = struct{}{}

		fp := raw
		fp.Indicators = make([]Indicator, len(raw.Indicators))
		for i, ind := range raw.Indicators {
			fp.Indicators[i] = ind
			if ind.Kind == IndicatorHTMLRegex || ind.Kind == IndicatorGenerator {
				fp.Indicators[i].matchRe = regexp.MustCompile(ind.Match)
			}
			if ind.Version != nil {
				fp.Indicators[i].versionRe = regexp.MustCompile(ind.Version.Pattern)
			}
		}
		d.fingerprints = append(d.fingerprints, fp)
	}
	sort.Slice(d.fingerprints, func(i, j int) bool {
		if d.fingerprints[i].Name != d.fingerprints[j].Name {
			return d.fingerprints[i].Name < d.fingerprints[j].Name
		}
		return d.fingerprints[i].Category < d.fingerprints[j].Category
	})
	return d, nil
}

// validateFingerprint enforces the data model on one raw entry. Validation
// is deliberately strict: a malformed table must fail Load, never reach the
// engine.
func validateFingerprint(fp Fingerprint) error {
	if fp.Name == "" {
		return fmt.Errorf("fingerprint name must not be empty")
	}
	if !fp.Category.Valid() {
		return fmt.Errorf("unknown technology category %q", fp.Category)
	}
	if len(fp.Indicators) == 0 {
		return fmt.Errorf("must have at least one indicator")
	}
	for i, ind := range fp.Indicators {
		if !ind.Kind.Valid() {
			return fmt.Errorf("indicator %d: invalid indicator kind %q", i, ind.Kind)
		}
		if ind.Match == "" {
			return fmt.Errorf("indicator %d: match must not be empty", i)
		}
		if math.IsNaN(ind.Weight) || ind.Weight <= 0 || ind.Weight > 1 {
			return fmt.Errorf("indicator %d: weight %v must satisfy 0 < weight <= 1 and must not be NaN", i, ind.Weight)
		}
		if ind.Kind == IndicatorHTMLRegex || ind.Kind == IndicatorGenerator {
			if _, err := regexp.Compile(ind.Match); err != nil {
				return fmt.Errorf("indicator %d: match %q is not a valid regex: %v", i, ind.Match, err)
			}
		}
		if ind.Version != nil {
			if ind.Version.Pattern == "" {
				return fmt.Errorf("indicator %d: version pattern must not be empty", i)
			}
			if _, err := regexp.Compile(ind.Version.Pattern); err != nil {
				return fmt.Errorf("indicator %d: version pattern %q is not a valid regex: %v", i, ind.Version.Pattern, err)
			}
			if ind.Version.Group < 0 {
				return fmt.Errorf("indicator %d: version group %d must not be negative", i, ind.Version.Group)
			}
		}
	}
	return nil
}
