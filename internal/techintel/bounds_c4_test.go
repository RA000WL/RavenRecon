package techintel

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented observation caps to their C-4 values; truncation behavior is
// covered by the analyze/ingest unit tests.

// TestC4BoundConstants pins techintel's documented caps.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "techintel 128/512 HTML caps" — technologies and indicators per
	// observation, as surfaced through DefaultConfig.
	cfg := DefaultConfig()
	if cfg.MaxTechnologiesPerObservation != 128 {
		t.Fatalf("DefaultConfig().MaxTechnologiesPerObservation = %d, want 128 per OPTIMIZATION.md C-4", cfg.MaxTechnologiesPerObservation)
	}
	if cfg.MaxIndicatorsPerObservation != 512 {
		t.Fatalf("DefaultConfig().MaxIndicatorsPerObservation = %d, want 512 per OPTIMIZATION.md C-4", cfg.MaxIndicatorsPerObservation)
	}
	// The HTML extraction caps (analyze.go) bound the candidate lists the
	// 128/512 observation caps draw from; they are part of the same
	// documented bounding contract (doc.go: "scripts/css/metas 128").
	if maxHTMLScripts != 128 || maxHTMLCSS != 128 || maxHTMLMetas != 128 {
		t.Fatalf("HTML caps scripts=%d css=%d metas=%d, want 128/128/128 per doc.go's documented list caps",
			maxHTMLScripts, maxHTMLCSS, maxHTMLMetas)
	}
}
