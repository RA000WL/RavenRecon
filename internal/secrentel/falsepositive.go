package secrentel

import (
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// The false-positive engine has two explicit layers:
//
//  1. VALUE suppression — the candidate is NOT emitted (counted only): the
//     value is a documented provider example, a placeholder, dummy material,
//     lorem-ipsum text, or an obvious repeated-character filler. These values
//     are known-bogus; emitting them at any confidence is noise.
//
//  2. CONTEXT capping — the candidate IS emitted but its confidence is
//     capped at Low (fpContextCap): the document's filename or URL path says
//     test/spec/example/docs/mock. A test file can still contain a real
//     secret, so the observation is honest — but it can never be
//     high-confidence queue material.
//
// The split is deliberate: suppression is reserved for values the providers
// themselves publish as examples; everything else is graded, never hidden.

// fpValueMarkers are case-insensitive substrings that mark a value as
// placeholder/dummy material. Bounded, curated, and deliberately
// conservative: a marker must never appear in a plausible real value (note
// "example" is NOT here — hostnames like db.example.com appear in real
// connection strings; the providers' EXAMPLE convention is matched
// case-sensitively below).
var fpValueMarkers = []string{
	"changeme", "change_me", "change-me", "replace_me", "replaceme",
	"placeholder", "dummy", "lorem ipsum", "loremipsum", "insert_", "enteryour",
	"your_api", "your-api", "yourtoken", "your_token", "your-secret",
	"notreal", "not-real", "not_a_real", "fakekey", "fake-key", "faketoken",
	"redacted", "masked", "xxxxx", "*****", "abc123xyz", "samplekey",
	"sample-key", "sampletoken", "sample-token", "testtest", "secretvalue",
	"please_change", "to_be_replaced", "xxxxxxxx",
}

// fpExampleMarkers are CASE-SENSITIVE uppercase markers: the EXAMPLE
// convention of provider documentation (AKIAIOSFODNN7EXAMPLE,
// …EXAMPLEKEY). Case sensitivity keeps example.com hostnames in real
// connection strings from being suppressed.
var fpExampleMarkers = []string{"EXAMPLE"}

// fpContextMarkers are case-insensitive substrings of a filename or URL path
// that mark documentation/test/sample context.
var fpContextMarkers = []string{
	"test", "spec", "example", "sample", "demo", "docs", "mock", "fixture",
	"tutorial", "changelog", "readme", "sandbox", "staging",
}

// containsFold reports whether s contains sub, case-insensitively.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// classifyValue decides whether a matched VALUE is known-bogus. It returns
// the suppression reason ("" when the value is not suppressed). Providers'
// documented example values are suppressed regardless of any other signal;
// so are placeholders, dummy values, lorem-ipsum material, and uniform
// filler runs.
func classifyValue(value string, typ asset.SecretType) string {
	for _, m := range fpValueMarkers {
		if containsFold(value, m) {
			return "value-marker:" + m
		}
	}
	for _, m := range fpExampleMarkers {
		if strings.Contains(value, m) {
			return "value-marker:" + m
		}
	}
	if isUniformRun(value) {
		return "uniform-run"
	}
	if len(value) <= 12 && looksHumanWord(value) {
		return "short-word"
	}
	return ""
}

// isUniformRun reports whether the whole value is one repeated byte (aaaa…,
// 1111…).
func isUniformRun(value string) bool {
	if len(value) < 8 {
		return false
	}
	first := value[0]
	for i := 1; i < len(value); i++ {
		if value[i] != first {
			return false
		}
	}
	return true
}

// looksHumanWord reports whether a short value is a plain lowercase word
// ("hunter2x" no, "password" yes): all [a-z] with at least 5 letters. Real
// secrets in scope of the pattern database are never plain words.
func looksHumanWord(value string) bool {
	letters := 0
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' {
			letters++
			continue
		}
		if b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			return false // mixed-case/digit short strings stay candidates
		}
		return false
	}
	return letters >= 5
}

// classifyContext returns the false-positive context flags of a document:
// matched markers in the filename or URL path. Flags cap confidence at Low
// (fpContextCap) but never suppress the candidate.
func classifyContext(filename, urlPath string) []string {
	var flags []string
	subject := filename + "/" + urlPath
	for _, m := range fpContextMarkers {
		if containsFold(subject, m) {
			flags = append(flags, "context-marker:"+m)
		}
	}
	// Bounded: at most 3 flags retained (the subject is bounded anyway, but
	// the report stays compact).
	if len(flags) > 3 {
		flags = flags[:3]
	}
	return flags
}
