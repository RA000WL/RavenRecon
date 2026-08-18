package techintel

import (
	"math"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

func TestConfidenceLevelValidAndParse(t *testing.T) {
	all := []ConfidenceLevel{LevelUnknown, LevelLow, LevelMedium, LevelHigh}
	for _, l := range all {
		if !l.Valid() {
			t.Errorf("%q must be Valid", l)
		}
		got, err := ParseConfidenceLevel(string(l))
		if err != nil {
			t.Errorf("ParseConfidenceLevel(%q): %v", l, err)
			continue
		}
		if got != l || got.String() != string(l) {
			t.Errorf("round trip %q -> %q", l, got)
		}
	}
	for _, bad := range []string{"", "HIGH", "High", "very high", "bogus"} {
		if _, err := ParseConfidenceLevel(bad); err == nil {
			t.Errorf("ParseConfidenceLevel(%q) must fail", bad)
		}
		if ConfidenceLevel(bad).Valid() {
			t.Errorf("%q must not be Valid", bad)
		}
	}
}

func TestConfidenceLevelOrdering(t *testing.T) {
	// rank orders weakest to strongest; weaker/stronger are strict.
	if LevelUnknown.rank() >= LevelLow.rank() || LevelLow.rank() >= LevelMedium.rank() ||
		LevelMedium.rank() >= LevelHigh.rank() {
		t.Fatal("level ranks must be strictly increasing")
	}
	if !LevelLow.weaker(LevelHigh) || !LevelMedium.weaker(LevelHigh) || !LevelUnknown.weaker(LevelLow) {
		t.Error("weaker comparison wrong")
	}
	if !LevelHigh.stronger(LevelLow) || !LevelMedium.stronger(LevelUnknown) {
		t.Error("stronger comparison wrong")
	}
	if LevelHigh.weaker(LevelHigh) || LevelHigh.stronger(LevelHigh) {
		t.Error("comparisons must be strict")
	}
	if ConfidenceLevel("bogus").rank() != -1 {
		t.Error("unknown level must rank -1")
	}
}

func TestLevelForScore(t *testing.T) {
	cases := []struct {
		score float64
		want  ConfidenceLevel
	}{
		{0.0, LevelUnknown},
		{0.19, LevelUnknown},
		{0.2, LevelLow},
		{0.49, LevelLow},
		{0.5, LevelMedium},
		{0.79, LevelMedium},
		{0.8, LevelHigh},
		{1.0, LevelHigh},
	}
	for _, tt := range cases {
		if got := levelForScore(tt.score); got != tt.want {
			t.Errorf("levelForScore(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestDeriveConfidence(t *testing.T) {
	g := func(kind fingerprints.IndicatorKind, slot int, w float64) indicatorGroup {
		return indicatorGroup{kind: kind, slot: slot, weight: w}
	}

	t.Run("no groups unknown", func(t *testing.T) {
		score, lvl := deriveConfidence(nil)
		if score != 0 || lvl != LevelUnknown {
			t.Errorf("deriveConfidence(nil) = %v/%q, want 0/unknown", score, lvl)
		}
	})

	t.Run("single spoofable capped", func(t *testing.T) {
		// A lone header indicator can never reach High: the spoofable-only
		// cap pins the score at 0.59 -> Medium.
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHeader, 0, 0.9)})
		if math.Abs(score-spoofableScoreCap) > 1e-9 {
			t.Errorf("score = %v, want cap %v", score, spoofableScoreCap)
		}
		if lvl != LevelMedium {
			t.Errorf("level = %q, want medium", lvl)
		}
	})

	t.Run("single structural high", func(t *testing.T) {
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, 0.9)})
		if math.Abs(score-0.9) > 1e-9 {
			t.Errorf("score = %v, want 0.9", score)
		}
		if lvl != LevelHigh {
			t.Errorf("level = %q, want high", lvl)
		}
	})

	t.Run("independent groups combine", func(t *testing.T) {
		// 1 - (0.4 * 0.4) = 0.84 -> High.
		score, lvl := deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHTMLSubstring, 0, 0.6),
			g(fingerprints.IndicatorHTMLSubstring, 1, 0.6),
		})
		if math.Abs(score-0.84) > 1e-9 {
			t.Errorf("score = %v, want 0.84", score)
		}
		if lvl != LevelHigh {
			t.Errorf("level = %q, want high", lvl)
		}
	})

	t.Run("same kind and slot collapse to max weight", func(t *testing.T) {
		// Two indicators both substrings of one header line are the same
		// observation evidence: combined by max weight (0.9), then capped.
		score, lvl := deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHeader, 0, 0.5),
			g(fingerprints.IndicatorHeader, 0, 0.9),
		})
		if math.Abs(score-spoofableScoreCap) > 1e-9 {
			t.Errorf("score = %v, want cap %v", score, spoofableScoreCap)
		}
		if lvl != LevelMedium {
			t.Errorf("level = %q, want medium", lvl)
		}
	})

	t.Run("same kind different slots are independent and capped", func(t *testing.T) {
		// 1 - 0.3*0.3 = 0.91 but spoofable-only -> capped to 0.59.
		score, lvl := deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHeader, 0, 0.7),
			g(fingerprints.IndicatorHeader, 1, 0.7),
		})
		if math.Abs(score-spoofableScoreCap) > 1e-9 {
			t.Errorf("score = %v, want cap %v", score, spoofableScoreCap)
		}
		if lvl != LevelMedium {
			t.Errorf("level = %q, want medium", lvl)
		}
	})

	t.Run("one structural lifts the cap", func(t *testing.T) {
		score, lvl := deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHeader, 0, 0.7),
			g(fingerprints.IndicatorHTMLSubstring, 0, 0.7),
		})
		if math.Abs(score-0.91) > 1e-9 {
			t.Errorf("score = %v, want 0.91", score)
		}
		if lvl != LevelHigh {
			t.Errorf("level = %q, want high", lvl)
		}
	})

	t.Run("lone weak indicator never exceeds low", func(t *testing.T) {
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, 0.3)})
		if math.Abs(score-0.3) > 1e-9 {
			t.Errorf("score = %v, want 0.3", score)
		}
		if lvl != LevelLow {
			t.Errorf("level = %q, want low", lvl)
		}
	})

	t.Run("very weak indicator is unknown", func(t *testing.T) {
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, 0.1)})
		if math.Abs(score-0.1) > 1e-9 {
			t.Errorf("score = %v, want 0.1", score)
		}
		if lvl != LevelUnknown {
			t.Errorf("level = %q, want unknown", lvl)
		}
	})

	t.Run("NaN weights carry no evidence", func(t *testing.T) {
		// Defense in depth: the loader rejects NaN weights, so a NaN group
		// is unreachable from a validated database. If one ever appears it
		// must not poison the product: it is skipped entirely.
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, math.NaN())})
		if math.IsNaN(score) || score != 0 || lvl != LevelUnknown {
			t.Errorf("lone NaN group: score = %v level = %q, want 0/unknown (never NaN)", score, lvl)
		}
		score, lvl = deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHTMLSubstring, 0, math.NaN()),
			g(fingerprints.IndicatorHTMLSubstring, 1, 0.9),
		})
		if math.IsNaN(score) || math.Abs(score-0.9) > 1e-9 || lvl != LevelHigh {
			t.Errorf("NaN among valid groups: score = %v level = %q, want 0.9/high (never NaN)", score, lvl)
		}
		// A NaN group sharing kind+slot with a valid one must not win (or
		// stick in) the max-weight collapse.
		score, lvl = deriveConfidence([]indicatorGroup{
			g(fingerprints.IndicatorHeader, 0, math.NaN()),
			g(fingerprints.IndicatorHeader, 0, 0.9),
		})
		if math.IsNaN(score) || math.Abs(score-spoofableScoreCap) > 1e-9 || lvl != LevelMedium {
			t.Errorf("NaN collapsing with a valid group: score = %v level = %q, want cap/medium", score, lvl)
		}
	})

	t.Run("weights clamp to [0,1]", func(t *testing.T) {
		score, lvl := deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, 1.5)})
		if math.Abs(score-1.0) > 1e-9 || lvl != LevelHigh {
			t.Errorf("oversized weight: score = %v level = %q, want 1/high", score, lvl)
		}
		score, lvl = deriveConfidence([]indicatorGroup{g(fingerprints.IndicatorHTMLSubstring, 0, -5)})
		if score != 0 || lvl != LevelUnknown {
			t.Errorf("negative weight: score = %v level = %q, want 0/unknown", score, lvl)
		}
	})

	t.Run("score and level agree with levelForScore", func(t *testing.T) {
		// Every deriveConfidence result must be self-consistent with the
		// threshold mapping (the decode re-check contract).
		for _, groups := range [][]indicatorGroup{
			{g(fingerprints.IndicatorHeader, 0, 0.9)},
			{g(fingerprints.IndicatorHeader, 0, 0.7), g(fingerprints.IndicatorHTMLSubstring, 0, 0.7)},
			{g(fingerprints.IndicatorHTMLSubstring, 0, 0.3)},
			{g(fingerprints.IndicatorDNSCNAME, 3, 0.5)},
			{g(fingerprints.IndicatorHeader, 0, math.NaN())},
		} {
			score, lvl := deriveConfidence(groups)
			if lvl.stronger(levelForScore(score)) {
				t.Errorf("level %q stronger than score %v allows", lvl, score)
			}
		}
	})
}
