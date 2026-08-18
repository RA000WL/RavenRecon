package detect

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// T1 — exported SDK surface: ValidateRule.
// ---------------------------------------------------------------------------

func TestValidateRuleExportedAcceptsFixture(t *testing.T) {
	r := makeRule(t, "exposure.admin-panel", nil)
	if err := ValidateRule(r); err != nil {
		t.Fatalf("ValidateRule: %v", err)
	}
}

func TestValidateRuleExportedRejections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(r *Rule)
	}{
		{"invalid id shape", func(r *Rule) { r.ID = "Bad-ID" }},
		{"oversized id", func(r *Rule) { r.ID = strings.Repeat("a", MaxRuleIDBytes+1) }},
		{"empty name", func(r *Rule) { r.Name = "" }},
		{"oversized name", func(r *Rule) { r.Name = strings.Repeat("n", MaxRuleNameBytes+1) }},
		{"empty description", func(r *Rule) { r.Description = "" }},
		{"unknown category", func(r *Rule) { r.Category = Category("bogus") }},
		{"bad version", func(r *Rule) { r.Version = "1.0" }},
		{"self dependency", func(r *Rule) { r.Dependencies = []string{"a.b"}; r.ID = "a.b" }},
		{"no inputs", func(r *Rule) { r.Inputs = nil }},
		{"no outputs", func(r *Rule) { r.Outputs = nil }},
		{"unknown cost", func(r *Rule) { r.EstimatedCost = Cost("extreme") }},
		{"zero timeout", func(r *Rule) { r.Timeout = 0 }},
		{"empty author", func(r *Rule) { r.Author = "" }},
		{"nil detector", func(r *Rule) { r.Detector = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRule(t, "a.b", nil)
			tc.mut(&r)
			if err := ValidateRule(r); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

// TestRegisterDelegatesToValidateRule pins the single validation point:
// Register must produce exactly the validation error ValidateRule produces
// (wrapped under the stable "detect: register rule:" prefix), so a rule
// rejected by one is rejected identically by the other.
func TestRegisterDelegatesToValidateRule(t *testing.T) {
	invalid := []struct {
		name string
		mut  func(r *Rule)
	}{
		{"empty id", func(r *Rule) { r.ID = "" }},
		{"invalid id shape", func(r *Rule) { r.ID = "Bad-ID" }},
		{"oversized id", func(r *Rule) { r.ID = strings.Repeat("a", MaxRuleIDBytes+1) }},
		{"empty name", func(r *Rule) { r.Name = "" }},
		{"unknown category", func(r *Rule) { r.Category = Category("bogus") }},
		{"bad version", func(r *Rule) { r.Version = "1.0" }},
		{"non-numeric version", func(r *Rule) { r.Version = "1.x.0" }},
		{"self dependency", func(r *Rule) { r.Dependencies = []string{"a.b"}; r.ID = "a.b" }},
		{"nil detector", func(r *Rule) { r.Detector = nil }},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRule(t, "a.b", nil)
			tc.mut(&r)

			vErr := ValidateRule(r)
			if vErr == nil {
				t.Fatalf("ValidateRule accepted the invalid rule")
			}
			reg := NewRegistry()
			regErr := reg.Register(r)
			if regErr == nil {
				t.Fatalf("Register accepted the invalid rule")
			}
			inner := errors.Unwrap(regErr)
			if inner == nil {
				t.Fatalf("Register error %q is not a wrapped validation error", regErr)
			}
			if inner.Error() != vErr.Error() {
				t.Fatalf("Register validation diverged from ValidateRule:\nregister inner: %q\nValidateRule:   %q",
					inner.Error(), vErr.Error())
			}
		})
	}

	// The wrap prefix is part of the stable contract.
	reg := NewRegistry()
	err := reg.Register(makeRule(t, "a.b", &ruleOptions{version: "bogus"}))
	if err == nil || !strings.HasPrefix(err.Error(), "detect: register rule: ") {
		t.Fatalf("register error contract broken: %v", err)
	}
}

// ---------------------------------------------------------------------------
// T1 — exported SDK surface: ParseRuleVersion.
// ---------------------------------------------------------------------------

func TestParseRuleVersion(t *testing.T) {
	major, minor, patch, err := ParseRuleVersion("1.2.3")
	if err != nil {
		t.Fatalf("ParseRuleVersion: %v", err)
	}
	if major != 1 || minor != 2 || patch != 3 {
		t.Fatalf("got (%d,%d,%d), want (1,2,3)", major, minor, patch)
	}

	// Round-trip: a rule whose Version was produced from the parsed ints
	// validates, and the version re-parses to the same components.
	r := makeRule(t, "a.b", nil)
	r.Version = fmt.Sprintf("%d.%d.%d", major, minor, patch)
	if err := ValidateRule(r); err != nil {
		t.Fatalf("rule with a parsed version must validate: %v", err)
	}
	m2, n2, p2, err := ParseRuleVersion(r.Version)
	if err != nil || m2 != major || n2 != minor || p2 != patch {
		t.Fatalf("round trip failed: got (%d,%d,%d,%v)", m2, n2, p2, err)
	}

	// Wide components parse (9 digits always fit an int).
	m3, n3, p3, err := ParseRuleVersion("999999999.123456789.0")
	if err != nil || m3 != 999999999 || n3 != 123456789 || p3 != 0 {
		t.Fatalf("wide components failed: (%d,%d,%d,%v)", m3, n3, p3, err)
	}
}

func TestParseRuleVersionRejections(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"non numeric", "a.b.c"},
		{"two components", "1.2"},
		{"four components", "1.2.3.4"},
		{"negative major", "-1.0.0"},
		{"negative patch", "1.0.-1"},
		{"empty component", "1..3"},
		{"10-digit component", "1234567890.0.0"},
		{"leading space", " 1.2.3"},
		{"trailing space", "1.2.3 "},
		{"over length bound", strings.Repeat("1", MaxRuleVersionBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := ParseRuleVersion(tc.in); err == nil {
				t.Fatalf("ParseRuleVersion(%q) must fail", tc.in)
			}
		})
	}

	// The internal validator shares the same parser: identical accept and
	// reject behavior.
	if err := validateRuleVersion("1.2.3"); err != nil {
		t.Fatalf("validateRuleVersion: %v", err)
	}
	for _, tc := range cases {
		if err := validateRuleVersion(tc.in); err == nil {
			t.Fatalf("validateRuleVersion(%q) must fail", tc.in)
		}
	}

	// Length-bound pin: a 33-byte version trips the byte check before the
	// shape check; a 32-byte single-component string passes the byte check
	// and fails the shape check.
	err := validateRuleVersion(strings.Repeat("1", MaxRuleVersionBytes+1))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("over %d bytes", MaxRuleVersionBytes)) {
		t.Fatalf("over-bound version must name the byte bound: %v", err)
	}
	if err := validateRuleVersion(strings.Repeat("1", MaxRuleVersionBytes)); err == nil {
		t.Fatalf("32-byte non-shaped version must fail the shape check")
	}
}

// ---------------------------------------------------------------------------
// T1 — exported bounds constants.
// ---------------------------------------------------------------------------

// TestSDKBoundsConstants pins the frozen Level 1 bound values: these exact
// numbers are the contract rule authors compile against.
func TestSDKBoundsConstants(t *testing.T) {
	if MaxRuleIDBytes != 128 {
		t.Fatalf("MaxRuleIDBytes = %d, want 128", MaxRuleIDBytes)
	}
	if MaxRuleNameBytes != 256 {
		t.Fatalf("MaxRuleNameBytes = %d, want 256", MaxRuleNameBytes)
	}
	if MaxRuleDescriptionBytes != 1024 {
		t.Fatalf("MaxRuleDescriptionBytes = %d, want 1024", MaxRuleDescriptionBytes)
	}
	if MaxRuleAuthorBytes != 128 {
		t.Fatalf("MaxRuleAuthorBytes = %d, want 128", MaxRuleAuthorBytes)
	}
	if MaxRuleVersionBytes != 32 {
		t.Fatalf("MaxRuleVersionBytes = %d, want 32", MaxRuleVersionBytes)
	}
	if MaxRuleDependencies != 16 {
		t.Fatalf("MaxRuleDependencies = %d, want 16", MaxRuleDependencies)
	}
	if MaxRuleTimeout != 10*time.Minute {
		t.Fatalf("MaxRuleTimeout = %s, want 10m0s", MaxRuleTimeout)
	}
	if MaxContextConfigEntries != 64 {
		t.Fatalf("MaxContextConfigEntries = %d, want 64", MaxContextConfigEntries)
	}
	if MaxContextConfigKeyBytes != 64 {
		t.Fatalf("MaxContextConfigKeyBytes = %d, want 64", MaxContextConfigKeyBytes)
	}
	if MaxContextConfigValueBytes != 256 {
		t.Fatalf("MaxContextConfigValueBytes = %d, want 256", MaxContextConfigValueBytes)
	}
	if MaxLogEntries != 256 {
		t.Fatalf("MaxLogEntries = %d, want 256", MaxLogEntries)
	}
	if MaxLogMessageBytes != 512 {
		t.Fatalf("MaxLogMessageBytes = %d, want 512", MaxLogMessageBytes)
	}
}

// TestRuleBoundsEnforced hits each rule bound at and past the boundary
// through ValidateRule — the same validation Register applies.
func TestRuleBoundsEnforced(t *testing.T) {
	ok := makeRule(t, "a.b", nil)

	// ID.
	at := ok
	at.ID = strings.Repeat("a", MaxRuleIDBytes)
	if err := ValidateRule(at); err != nil {
		t.Fatalf("ID at MaxRuleIDBytes must validate: %v", err)
	}
	over := ok
	over.ID = strings.Repeat("a", MaxRuleIDBytes+1)
	if err := ValidateRule(over); err == nil {
		t.Fatalf("ID over MaxRuleIDBytes must be rejected")
	}

	// Name.
	at = ok
	at.Name = strings.Repeat("n", MaxRuleNameBytes)
	if err := ValidateRule(at); err != nil {
		t.Fatalf("name at MaxRuleNameBytes must validate: %v", err)
	}
	over = ok
	over.Name = strings.Repeat("n", MaxRuleNameBytes+1)
	if err := ValidateRule(over); err == nil {
		t.Fatalf("name over MaxRuleNameBytes must be rejected")
	}

	// Description.
	at = ok
	at.Description = strings.Repeat("d", MaxRuleDescriptionBytes)
	if err := ValidateRule(at); err != nil {
		t.Fatalf("description at MaxRuleDescriptionBytes must validate: %v", err)
	}
	over = ok
	over.Description = strings.Repeat("d", MaxRuleDescriptionBytes+1)
	if err := ValidateRule(over); err == nil {
		t.Fatalf("description over MaxRuleDescriptionBytes must be rejected")
	}

	// Author.
	at = ok
	at.Author = strings.Repeat("u", MaxRuleAuthorBytes)
	if err := ValidateRule(at); err != nil {
		t.Fatalf("author at MaxRuleAuthorBytes must validate: %v", err)
	}
	over = ok
	over.Author = strings.Repeat("u", MaxRuleAuthorBytes+1)
	if err := ValidateRule(over); err == nil {
		t.Fatalf("author over MaxRuleAuthorBytes must be rejected")
	}

	// Version: the longest valid shape (3 × 9 digits) validates; the byte
	// bound trips before the shape check.
	at = ok
	at.Version = "999999999.999999999.999999999"
	if err := ValidateRule(at); err != nil {
		t.Fatalf("max-shape version must validate: %v", err)
	}
	over = ok
	over.Version = strings.Repeat("1", MaxRuleVersionBytes+1)
	if err := ValidateRule(over); err == nil {
		t.Fatalf("version over MaxRuleVersionBytes must be rejected")
	}

	// Dependencies.
	deps := make([]string, MaxRuleDependencies)
	for i := range deps {
		deps[i] = fmtDep(i)
	}
	at = ok
	at.Dependencies = deps
	if err := ValidateRule(at); err != nil {
		t.Fatalf("dependencies at MaxRuleDependencies must validate: %v", err)
	}
	over = ok
	overDeps := make([]string, MaxRuleDependencies+1)
	for i := range overDeps {
		overDeps[i] = fmtDep(i)
	}
	over.Dependencies = overDeps
	if err := ValidateRule(over); err == nil {
		t.Fatalf("dependencies over MaxRuleDependencies must be rejected")
	}

	// Timeout.
	at = ok
	at.Timeout = MaxRuleTimeout
	if err := ValidateRule(at); err != nil {
		t.Fatalf("timeout at MaxRuleTimeout must validate: %v", err)
	}
	over = ok
	over.Timeout = MaxRuleTimeout + time.Second
	if err := ValidateRule(over); err == nil {
		t.Fatalf("timeout over MaxRuleTimeout must be rejected")
	}

	// Register enforces the same bounds (single validation point).
	reg := NewRegistry()
	big := makeRule(t, "c.d", nil)
	big.Name = strings.Repeat("n", MaxRuleNameBytes+1)
	if err := reg.Register(big); err == nil {
		t.Fatalf("Register must reject an over-bound rule")
	}
}

// TestContextBoundsEnforced hits each context bound at and past the
// boundary.
func TestContextBoundsEnforced(t *testing.T) {
	// Config entries.
	at := make(map[string]string)
	for i := 0; i < MaxContextConfigEntries; i++ {
		at[fmt.Sprintf("k%02d", i)] = "v"
	}
	if err := validateConfig(at); err != nil {
		t.Fatalf("config at MaxContextConfigEntries must validate: %v", err)
	}
	over := make(map[string]string)
	for i := 0; i < MaxContextConfigEntries+1; i++ {
		over[fmt.Sprintf("k%02d", i)] = "v"
	}
	if err := validateConfig(over); err == nil {
		t.Fatalf("config over MaxContextConfigEntries must be rejected")
	}

	// Config key.
	if err := validateConfig(map[string]string{strings.Repeat("k", MaxContextConfigKeyBytes): "v"}); err != nil {
		t.Fatalf("key at MaxContextConfigKeyBytes must validate: %v", err)
	}
	if err := validateConfig(map[string]string{strings.Repeat("k", MaxContextConfigKeyBytes+1): "v"}); err == nil {
		t.Fatalf("key over MaxContextConfigKeyBytes must be rejected")
	}

	// Config value.
	if err := validateConfig(map[string]string{"k": strings.Repeat("v", MaxContextConfigValueBytes)}); err != nil {
		t.Fatalf("value at MaxContextConfigValueBytes must validate: %v", err)
	}
	if err := validateConfig(map[string]string{"k": strings.Repeat("v", MaxContextConfigValueBytes+1)}); err == nil {
		t.Fatalf("value over MaxContextConfigValueBytes must be rejected")
	}

	// Logger entries: MaxLogEntries retained, the next dropped.
	l := newBoundedLogger()
	for i := 0; i < MaxLogEntries+1; i++ {
		l.Log(LevelInfo, "a.b", "m")
	}
	entries, dropped := l.snapshot()
	if len(entries) != MaxLogEntries || dropped != 1 {
		t.Fatalf("logger entry bounds wrong: %d entries, %d dropped", len(entries), dropped)
	}

	// Logger messages: truncated at MaxLogMessageBytes at and past the
	// bound.
	l2 := newBoundedLogger()
	l2.Log(LevelInfo, "a.b", strings.Repeat("x", MaxLogMessageBytes))
	l2.Log(LevelInfo, "a.b", strings.Repeat("y", MaxLogMessageBytes+1))
	e, _ := l2.snapshot()
	if len(e) != 2 || len(e[0].Message) != MaxLogMessageBytes || len(e[1].Message) != MaxLogMessageBytes {
		t.Fatalf("message truncation wrong: %+v", e)
	}
}

// ---------------------------------------------------------------------------
// T2 — Registry.Seal.
// ---------------------------------------------------------------------------

func TestRegistrySeal(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "a.b", nil)); err != nil {
		t.Fatalf("register before seal: %v", err)
	}

	reg.Seal()

	// Register fails after Seal with the documented error.
	err := reg.Register(makeRule(t, "c.d", nil))
	if err == nil {
		t.Fatalf("register after seal must fail")
	}
	if err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed error wrong: %v", err)
	}

	// The sealed check precedes validation (report parity).
	if err := reg.Register(Rule{}); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("invalid rule after seal must report sealed: %v", err)
	}

	// Reads keep working after Seal.
	if got, ok := reg.Get("a.b"); !ok || got.ID != "a.b" {
		t.Fatalf("Get after seal failed")
	}
	if reg.Len() != 1 {
		t.Fatalf("Len after seal = %d, want 1", reg.Len())
	}
	if rules := reg.Rules(); len(rules) != 1 || rules[0].ID != "a.b" {
		t.Fatalf("Rules after seal failed")
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after seal: %v", err)
	}
}

func TestNewRegistryUnsealed(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "a.b", nil)); err != nil {
		t.Fatalf("new registry must start unsealed: %v", err)
	}
	reg.Seal()
	if err := reg.Register(makeRule(t, "c.d", nil)); err == nil {
		t.Fatalf("sealed registry must reject registration")
	}
}

// ---------------------------------------------------------------------------
// T3 — API versioning.
// ---------------------------------------------------------------------------

func TestCheckAPIVersion(t *testing.T) {
	if APIMajor != 1 || APIMinor != 0 {
		t.Fatalf("frozen SDK API level is %d.%d, want 1.0", APIMajor, APIMinor)
	}

	// Same major, minor at or below this build's minor: compatible.
	if err := CheckAPIVersion(1, 0); err != nil {
		t.Fatalf("CheckAPIVersion(1,0): %v", err)
	}
	if err := CheckAPIVersion(1, -1); err != nil {
		t.Fatalf("CheckAPIVersion(1,-1) must pass per the exact semantics: %v", err)
	}

	// Incompatible pairs: major mismatch or a too-new required minor.
	rejected := []struct {
		name string
		maj  int
		min  int
	}{
		{"future minor", 1, 1},
		{"future major", 2, 0},
		{"zero major", 0, 0},
		{"zero major future minor", 0, 99},
		{"future major and minor", 2, 5},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAPIVersion(tc.maj, tc.min)
			if err == nil {
				t.Fatalf("CheckAPIVersion(%d,%d) must fail", tc.maj, tc.min)
			}
			msg := err.Error()
			if !strings.Contains(msg, "detect SDK") {
				t.Fatalf("error must name the SDK: %q", msg)
			}
			if !strings.Contains(msg, fmt.Sprintf("%d.%d", tc.maj, tc.min)) {
				t.Fatalf("error must name the required version: %q", msg)
			}
			if !strings.Contains(msg, fmt.Sprintf("%d.%d", APIMajor, APIMinor)) {
				t.Fatalf("error must name this build's version: %q", msg)
			}
		})
	}
}
