package secrentel

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented candidate/evidence caps to their C-4 values; overflow and
// accounting behavior is covered by the scan/engine unit tests.

// TestC4BoundConstants pins secrentel's documented caps via DefaultConfig.
func TestC4BoundConstants(t *testing.T) {
	cfg := DefaultConfig()
	// C-4: "secrentel 64 candidates/8 evidence".
	if cfg.MaxCandidatesPerDocument != 64 {
		t.Fatalf("DefaultConfig().MaxCandidatesPerDocument = %d, want 64 per OPTIMIZATION.md C-4", cfg.MaxCandidatesPerDocument)
	}
	if cfg.MaxEvidencePerCandidate != 8 {
		t.Fatalf("DefaultConfig().MaxEvidencePerCandidate = %d, want 8 per OPTIMIZATION.md C-4", cfg.MaxEvidencePerCandidate)
	}
	// The internal scan limits must mirror the config defaults exactly;
	// a drift between the two would make the stored-record re-validation
	// cap (record.go) disagree with what the scanner actually produced.
	lim := defaultScanLimits()
	if lim.maxCandidates != cfg.MaxCandidatesPerDocument {
		t.Fatalf("defaultScanLimits.maxCandidates = %d, want %d (config default)", lim.maxCandidates, cfg.MaxCandidatesPerDocument)
	}
	if lim.maxEvidencePerCand != cfg.MaxEvidencePerCandidate {
		t.Fatalf("defaultScanLimits.maxEvidencePerCand = %d, want %d (config default)", lim.maxEvidencePerCand, cfg.MaxEvidencePerCandidate)
	}
}
