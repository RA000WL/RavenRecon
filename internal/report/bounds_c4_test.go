package report

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented per-kind cap to its C-4 value; over-bound rejection behavior
// is covered by the model/validate unit tests.

// TestC4BoundConstants pins report's documented per-kind cap.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "report 100k/modelPerKind" for every remaining per-kind list.
	if maxModelPerKind != 100_000 {
		t.Fatalf("maxModelPerKind = %d, want 100k (100000) per OPTIMIZATION.md C-4", maxModelPerKind)
	}
}
