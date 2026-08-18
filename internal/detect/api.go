// The detection SDK is versioned in three independent layers:
//
//   - SchemaVersion (record.go) versions the CACHE RECORD LAYOUT: a schema
//     bump invalidates stored rule results; it never changes the SDK
//     contract.
//   - APIMajor/APIMinor (below) version the frozen SDK SURFACE (Level 1,
//     the "SDK v1 (Core)" freeze of milestone v1.2.5): the rule-author
//     contract — Rule, Detector, Context, Snapshot, Registry (including
//     Seal), Run, the vocabularies and parsers, and the exported bounds
//     constants. A major bump means packs must be recompiled against a new
//     contract; a minor bump is backward compatible (this build
//     understands every pack compiled against its own minor or lower).
//   - Rule.Version versions rule CONTENT: the detector's logic and
//     metadata. A content bump changes the rule's cache key (the documented
//     bump contract); it never affects SDK compatibility.
//
// Level 1 stability policy: the surface above is frozen for the lifetime of
// API (APIMajor, APIMinor). Any change that would break a pack compiled
// against it must be a deliberate, documented reopening decision that bumps
// APIMajor — never a silent alteration of the contract.
package detect

import "fmt"

// APIMajor and APIMinor identify the frozen SDK surface version (Level 1).
// They are independent of SchemaVersion (cache record layout) and
// Rule.Version (rule content): a pack compiled against this build's SDK
// surface carries the API level it was built against and verifies it
// through CheckAPIVersion before loading.
const (
	APIMajor = 1
	APIMinor = 0
)

// CheckAPIVersion reports whether a pack compiled against version
// (requiredMajor, requiredMinor) of the SDK is compatible with this build:
// same major, and this build's minor >= the required minor. A
// major mismatch means the pack must be recompiled; a too-new required
// minor means this build predates the pack. The error names the SDK and
// both versions. Pack loaders call this before loading any rule.
func CheckAPIVersion(requiredMajor, requiredMinor int) error {
	if requiredMajor != APIMajor {
		return fmt.Errorf("detect SDK: pack requires API %d.%d, this build provides %d.%d (major version mismatch: the pack must be recompiled against the current SDK)",
			requiredMajor, requiredMinor, APIMajor, APIMinor)
	}
	if requiredMinor > APIMinor {
		return fmt.Errorf("detect SDK: pack requires API %d.%d, this build provides %d.%d (this build predates the pack's required minor)",
			requiredMajor, requiredMinor, APIMajor, APIMinor)
	}
	return nil
}
