package discovery

import "regexp"

// VersionPattern matches the first semver-like token in tool output, with an
// optional leading "v". It is intentionally tolerant: -version output formats
// differ across tools and versions ("Current Version: v2.6.3", "v3.23.0", ...).
//
// This is the single version-pattern definition for the framework:
// urlintel/adapt and jsintel/adapt already import this package and will
// migrate their private copies to it.
var VersionPattern = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:[-+._][0-9A-Za-z]+)*`)

// ExtractVersion returns the first version-like token in out, or "".
func ExtractVersion(out []byte) string {
	if m := VersionPattern.Find(out); m != nil {
		return string(m)
	}
	return ""
}

// extractVersion is the package-internal spelling used by tool detection
// (and pinned by detect_test.go).
func extractVersion(out []byte) string { return ExtractVersion(out) }
