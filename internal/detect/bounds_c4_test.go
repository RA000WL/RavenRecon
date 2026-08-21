package detect

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented run findings cap to its C-4 value; truncation behavior is
// covered by the run unit tests.

// TestC4BoundConstants pins detect's documented findings cap.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "detect 4096 findings" retained per run.
	if maxFindingsPerRun != 4096 {
		t.Fatalf("maxFindingsPerRun = %d, want 4096 per OPTIMIZATION.md C-4", maxFindingsPerRun)
	}
}
