package patterns

import (
	"fmt"
	"regexp"
	"sort"
)

// FingerprintCount is the canonical number of production pattern
// fingerprints (aws 4 + cloud 11 + saas 10 + tokens 5 + keys 5 + data/web
// 8). TestLoadProductionDatabase asserts db.Len() == FingerprintCount so
// the documented count can never drift from the database.
const FingerprintCount = 43

// Load merges, validates, and compiles every pattern table into an immutable
// DB. It returns an error if any entry violates the model (duplicate IDs,
// malformed regex, out-of-range group/strength/bounds, unknown type, family,
// validator, or entropy class), so a malformed table can never reach the
// engine. Patterns are compiled exactly once, here.
func Load() (*DB, error) {
	return compile(allTables())
}

// CompileForTest builds a DB through exactly the Load pipeline (validation,
// compile-once regexes, deterministic sort) over caller-supplied entries and
// correlation table. It exists so ENGINE tests can exercise COMPILED patterns
// (hand-built Patterns have nil compiled regexes and silently never match).
// Production code must use Load; engine code must NEVER compile its own
// regular expressions.
func CompileForTest(entries []Pattern, correlations ...[]ProviderCorrelation) (*DB, error) {
	var corr []ProviderCorrelation
	if len(correlations) > 0 {
		corr = correlations[0]
	}
	return compile(entries, corr)
}

// allTables merges the pattern tables in fixed, documented order. The
// correlation table is engine-consumed data and is validated with the rest.
func allTables() ([]Pattern, []ProviderCorrelation) {
	var out []Pattern
	out = append(out, awsTable()...)
	out = append(out, cloudTable()...)
	out = append(out, saasTable()...)
	out = append(out, tokenTable()...)
	out = append(out, keyTable()...)
	out = append(out, dataWebTable()...)
	return out, correlationTable()
}

// compile validates every raw entry, compiles every regex exactly once, and
// returns the sorted, immutable DB.
func compile(entries []Pattern, correlations []ProviderCorrelation) (*DB, error) {
	d := &DB{schemaVersion: SchemaVersion}
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		if err := validatePattern(raw); err != nil {
			return nil, err
		}
		if _, dup := seen[raw.ID]; dup {
			return nil, fmt.Errorf("duplicate pattern ID %q across tables", raw.ID)
		}
		seen[raw.ID] = struct{}{}

		p := raw
		p.re = regexp.MustCompile(p.Regex)
		d.patterns = append(d.patterns, p)
	}
	sort.Slice(d.patterns, func(i, j int) bool {
		return d.patterns[i].ID < d.patterns[j].ID
	})

	seenProvider := make(map[string]struct{}, len(correlations))
	for _, c := range correlations {
		if err := validateProvider(c.Provider); err != nil {
			return nil, fmt.Errorf("correlation entry: %w", err)
		}
		if _, dup := seenProvider[c.Provider]; dup {
			return nil, fmt.Errorf("duplicate correlation provider %q", c.Provider)
		}
		seenProvider[c.Provider] = struct{}{}
		for _, s := range append(append([]string{}, c.Endpoints...), c.Tech...) {
			if s == "" || len(s) > maxIndicatorBytes {
				return nil, fmt.Errorf("correlation %q: invalid indicator %q", c.Provider, s)
			}
		}
		d.correlations = append(d.correlations, c)
	}
	sort.Slice(d.correlations, func(i, j int) bool {
		return d.correlations[i].Provider < d.correlations[j].Provider
	})
	return d, nil
}
