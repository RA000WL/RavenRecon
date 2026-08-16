package patterns

import (
	"fmt"
	"regexp"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Validator names a structural validation applied to a matched value after
// the regex match. Validators are offline, pure checks — they never contact a
// service (Phase 8 verifies nothing online, by design).
type Validator string

const (
	// ValidatorNone: no structural check beyond the regex.
	ValidatorNone Validator = ""
	// ValidatorJWTStructure: the value must be three dot-separated
	// base64url segments whose first segment decodes to JSON carrying an
	// "alg" member.
	ValidatorJWTStructure Validator = "jwt_structure"
	// ValidatorHex: every byte of the value is a hex digit.
	ValidatorHex Validator = "hex"
	// ValidatorBase64Decodable: the value decodes as padded standard base64.
	ValidatorBase64Decodable Validator = "base64_decodable"
	// ValidatorUUID: the value is a canonical 8-4-4-4-12 hex UUID.
	ValidatorUUID Validator = "uuid"
	// ValidatorMixedAlnum: an alnum value must contain at least one digit and
	// at least one letter (an all-letter or all-digit tail is a word, not a
	// key).
	ValidatorMixedAlnum Validator = "mixed_alnum"
)

// Valid reports whether v is a known validator.
func (v Validator) Valid() bool {
	switch v {
	case ValidatorNone, ValidatorJWTStructure, ValidatorHex,
		ValidatorBase64Decodable, ValidatorUUID, ValidatorMixedAlnum:
		return true
	}
	return false
}

// EntropyClass names the character class an entropy assessment is measured
// against. The normalized score divides the observed Shannon entropy by the
// class's maximum (log2 of the class size), so scores are comparable across
// classes.
type EntropyClass string

const (
	// ClassAny: no class expectation.
	ClassAny EntropyClass = ""
	// ClassHex: 0-9a-f (16 symbols, max 4 bits/char).
	ClassHex EntropyClass = "hex"
	// ClassBase64: A-Za-z0-9+/= (64 symbols, max 6 bits/char).
	ClassBase64 EntropyClass = "base64"
	// ClassBase64URL: A-Za-z0-9-_ (URL-safe base64 alphabet).
	ClassBase64URL EntropyClass = "base64url"
	// ClassAlnum: A-Za-z0-9 (62 symbols).
	ClassAlnum EntropyClass = "alnum"
)

// Valid reports whether c is a known class.
func (c EntropyClass) Valid() bool {
	switch c {
	case ClassAny, ClassHex, ClassBase64, ClassBase64URL, ClassAlnum:
		return true
	}
	return false
}

// EntropyRule is a pattern's expectation about the randomness of its matched
// values. A value that fails the rule is DROPPED (counted, never emitted):
// for context-shaped patterns the entropy minimum is the primary defense
// against matching prose, placeholders, and repeated characters.
type EntropyRule struct {
	// MinShannon is the minimum Shannon entropy in bits per character.
	MinShannon float64 `json:"min_shannon,omitempty"`
	// MinNormalized is the minimum Shannon entropy divided by the expected
	// class maximum (see EntropyClass). The class is the pattern's expected
	// class; 0 disables the normalized check.
	MinNormalized float64 `json:"min_normalized,omitempty"`
	// Class is the expected character class ("" = no class expectation; the
	// normalized check then divides by log2(distinct chars observed), which
	// is always 1.0 and disabled in practice).
	Class EntropyClass `json:"class,omitempty"`
}

// Family classifies how a pattern's match evidence may be used in confidence
// scoring. The family is data (stored per pattern) and the engine's caps are
// contract:
//
//	structured  — strong prefix/marker shapes; eligible for High.
//	contextual  — assignment-shaped matches (the variable name is part of the
//	              match); eligible for Medium and High only with entropy
//	              support.
//	generic     — generic high-entropy families (a random base64 blob under a
//	              generic name); the score is capped at Low: "random base64"
//	              alone is never more than a weak signal.
//	public      — public key material; definitionally not a secret, capped at
//	              Low.
type Family string

const (
	FamilyStructured Family = "structured"
	FamilyContextual Family = "contextual"
	FamilyGeneric    Family = "generic"
	FamilyPublic     Family = "public"
)

// Valid reports whether f is a known family.
func (f Family) Valid() bool {
	switch f {
	case FamilyStructured, FamilyContextual, FamilyGeneric, FamilyPublic:
		return true
	}
	return false
}

// Pattern is one secret fingerprint. Regex is matched against document
// content; when Group is nonzero the capture group's text is the candidate
// value, otherwise the whole match is. Trail extends the value by up to Trail
// bytes past the match end (private key material following the BEGIN marker).
//
// Anchors are REQUIRED lowercase substrings of any match (checked against a
// single lowercased copy of the document before the regex runs): they gate
// the case-insensitive contextual/generic families, whose regexes cannot use
// RE2's literal-prefix fast path, behind a cheap substring check. Every
// anchor must be a necessary substring of every possible match — a wrong
// anchor would skip real matches (Load enforces presence and form; the
// table reviews enforce necessity).
type Pattern struct {
	ID        string           `json:"id"`
	Type      asset.SecretType `json:"type"`
	Provider  string           `json:"provider,omitempty"`
	Family    Family           `json:"family"`
	Regex     string           `json:"regex"`
	Anchors   []string         `json:"anchors,omitempty"`
	Group     int              `json:"group,omitempty"`
	Trail     int              `json:"trail,omitempty"`
	Strength  float64          `json:"strength"`
	MinLen    int              `json:"min_len,omitempty"`
	MaxLen    int              `json:"max_len,omitempty"`
	Validator Validator        `json:"validator,omitempty"`
	Entropy   EntropyRule      `json:"entropy,omitempty"`
	Negatives []string         `json:"negatives,omitempty"`
	Positives []string         `json:"positives,omitempty"`
	Hints     []string         `json:"hints,omitempty"`

	// re is Regex compiled exactly once by the compiler. Match is the
	// exported accessor; the engine must never compile its own regexes.
	re *regexp.Regexp
}

// Match returns the compiled regular expression. The returned instance is
// shared and immutable; it is nil only for Pattern values that never went
// through the compiler (hand-built test fixtures). Production patterns always
// come from a compiled DB.
func (p Pattern) Match() *regexp.Regexp { return p.re }

// numGroups reports how many capture groups the compiled regex has.
func (p Pattern) numGroups() int {
	if p.re == nil {
		return 0
	}
	return p.re.NumSubexp()
}

// ProviderCorrelation is one provider's cross-evidence correlation data: the
// endpoint substrings and technology-name substrings whose observation in the
// same document as a candidate of the provider raises the candidate's
// confidence (see the engine's correlation stage).
type ProviderCorrelation struct {
	Provider  string   `json:"provider"`
	Endpoints []string `json:"endpoints,omitempty"`
	Tech      []string `json:"tech,omitempty"`
}

// SchemaVersion versions the pattern database schema and data semantics.
// Cache keys for secret scans must include it: bumping SchemaVersion
// invalidates every cached scan by construction, mirroring
// internal/cache's schema versioning. Never reuse a bumped version number.
const SchemaVersion = 1

// Bounds enforced by Load. Fixed constants, deliberately not configuration:
// they bound the database's own data model, not any runtime behavior.
const (
	// maxIDBytes bounds a pattern ID (IDs enter evidence indicator keys).
	maxIDBytes = 64
	// maxProviderBytes bounds a provider name.
	maxProviderBytes = 24
	// maxIndicatorsPerField bounds the negatives/positives/hints lists.
	maxIndicatorsPerField = 16
	// maxAnchorsPerPattern bounds the anchor list.
	maxAnchorsPerPattern = 8
	// maxIndicatorBytes bounds each indicator substring.
	maxIndicatorBytes = 64
)

// DB is an immutable, validated, compile-once pattern database. A DB is
// produced only by Load (production tables) or the exported-for-test
// compiler; it never mutates after construction.
type DB struct {
	schemaVersion int
	patterns      []Pattern // sorted by ID
	correlations  []ProviderCorrelation
}

// Version returns the schema version of this database.
func (d *DB) Version() int { return d.schemaVersion }

// Len returns the number of patterns in the database.
func (d *DB) Len() int { return len(d.patterns) }

// Patterns returns every pattern sorted deterministically by ID. The returned
// slice is a fresh copy (the compiled regex pointers are shared and never
// rewritten).
func (d *DB) Patterns() []Pattern {
	out := make([]Pattern, len(d.patterns))
	copy(out, d.patterns)
	return out
}

// Correlations returns the provider correlation table sorted by provider.
// The returned slice is a fresh copy.
func (d *DB) Correlations() []ProviderCorrelation {
	out := make([]ProviderCorrelation, len(d.correlations))
	copy(out, d.correlations)
	return out
}

// ByID returns the pattern with the given ID and whether it exists.
func (d *DB) ByID(id string) (Pattern, bool) {
	for _, p := range d.patterns {
		if p.ID == id {
			return p, true
		}
	}
	return Pattern{}, false
}

// validate checks one raw pattern against the data model. Validation is
// deliberately strict: a malformed table must fail Load, never reach the
// engine.
func validatePattern(p Pattern) error {
	if p.ID == "" {
		return fmt.Errorf("pattern ID must not be empty")
	}
	if len(p.ID) > maxIDBytes {
		return fmt.Errorf("pattern ID is longer than %d bytes", maxIDBytes)
	}
	if !p.Type.Valid() {
		return fmt.Errorf("pattern %q: unknown secret type %q", p.ID, p.Type)
	}
	if err := validateProvider(p.Provider); err != nil {
		return fmt.Errorf("pattern %q: %w", p.ID, err)
	}
	if !p.Family.Valid() {
		return fmt.Errorf("pattern %q: unknown family %q", p.ID, p.Family)
	}
	if p.Regex == "" {
		return fmt.Errorf("pattern %q: regex must not be empty", p.ID)
	}
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return fmt.Errorf("pattern %q: regex %q does not compile: %w", p.ID, p.Regex, err)
	}
	if p.Group < 0 || p.Group > re.NumSubexp() {
		return fmt.Errorf("pattern %q: group %d out of range (regex has %d groups)", p.ID, p.Group, re.NumSubexp())
	}
	if p.Trail < 0 || p.Trail > maxTrailBytes {
		return fmt.Errorf("pattern %q: trail %d out of range [0,%d]", p.ID, p.Trail, maxTrailBytes)
	}
	if p.Strength <= 0 || p.Strength > 1 {
		return fmt.Errorf("pattern %q: strength %v must satisfy 0 < strength <= 1", p.ID, p.Strength)
	}
	if p.MinLen < 0 || p.MaxLen < 0 || (p.MaxLen > 0 && p.MinLen > p.MaxLen) {
		return fmt.Errorf("pattern %q: invalid length bounds [%d,%d]", p.ID, p.MinLen, p.MaxLen)
	}
	if !p.Validator.Valid() {
		return fmt.Errorf("pattern %q: unknown validator %q", p.ID, p.Validator)
	}
	if !p.Entropy.Class.Valid() {
		return fmt.Errorf("pattern %q: unknown entropy class %q", p.ID, p.Entropy.Class)
	}
	if p.Entropy.MinShannon < 0 || p.Entropy.MinShannon > 8 {
		return fmt.Errorf("pattern %q: min shannon %v out of [0,8]", p.ID, p.Entropy.MinShannon)
	}
	if p.Entropy.MinNormalized < 0 || p.Entropy.MinNormalized > 1 {
		return fmt.Errorf("pattern %q: min normalized entropy %v out of [0,1]", p.ID, p.Entropy.MinNormalized)
	}
	for name, list := range map[string][]string{
		"negatives": p.Negatives, "positives": p.Positives, "hints": p.Hints,
	} {
		if len(list) > maxIndicatorsPerField {
			return fmt.Errorf("pattern %q: more than %d %s", p.ID, maxIndicatorsPerField, name)
		}
		for _, s := range list {
			if s == "" {
				return fmt.Errorf("pattern %q: empty %s entry", p.ID, name)
			}
			if len(s) > maxIndicatorBytes {
				return fmt.Errorf("pattern %q: %s entry %q longer than %d bytes", p.ID, name, s, maxIndicatorBytes)
			}
		}
	}
	return validateAnchors(p)
}

// validateAnchors enforces the anchor contract: contextual and generic
// families REQUIRE anchors (their case-insensitive regexes must never scan
// anchor-free documents); every anchor is non-empty lowercase [a-z0-9_-] of
// at least 2 bytes (matched against a lowercased document — hyphens occur in
// real naming forms like api-key); the list is bounded.
func validateAnchors(p Pattern) error {
	if len(p.Anchors) > maxAnchorsPerPattern {
		return fmt.Errorf("pattern %q: more than %d anchors", p.ID, maxAnchorsPerPattern)
	}
	for _, a := range p.Anchors {
		if len(a) < 2 {
			return fmt.Errorf("pattern %q: anchor %q must be at least 2 bytes", p.ID, a)
		}
		if len(a) > maxIndicatorBytes {
			return fmt.Errorf("pattern %q: anchor %q longer than %d bytes", p.ID, a, maxIndicatorBytes)
		}
		for i := 0; i < len(a); i++ {
			b := a[i]
			allowed := b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '-'
			if !allowed {
				return fmt.Errorf("pattern %q: anchor %q must be lowercase [a-z0-9_-]", p.ID, a)
			}
		}
	}
	switch p.Family {
	case FamilyContextual, FamilyGeneric:
		if len(p.Anchors) == 0 {
			return fmt.Errorf("pattern %q: family %s requires at least one anchor", p.ID, p.Family)
		}
	}
	return nil
}

// maxTrailBytes bounds the Trail extension (key material after a marker).
const maxTrailBytes = 256

// validateProvider enforces the provider form: empty or lowercase
// [a-z0-9_-] within maxProviderBytes.
func validateProvider(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxProviderBytes {
		return fmt.Errorf("provider %q is longer than %d bytes", p, maxProviderBytes)
	}
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' {
			continue
		}
		return fmt.Errorf("provider %q must be lowercase [a-z0-9_-]", p)
	}
	return nil
}
