package pipeline

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// pipeline's document-size cap to its C-4 value; truncation behavior is
// covered by the stage unit tests.

// TestC4BoundConstants pins the pipeline document cap.
func TestC4BoundConstants(t *testing.T) {
	// MaxDocumentBytes bounds any single document handed to a stage; it is
	// the pipeline-side mirror of jsintel's 2 MiB JS cap (C-4).
	if MaxDocumentBytes != 2<<20 {
		t.Fatalf("MaxDocumentBytes = %d, want 2 MiB (2<<20) per OPTIMIZATION.md C-4", MaxDocumentBytes)
	}
}
