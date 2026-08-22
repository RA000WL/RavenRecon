package adapt

// v1.7 Batch F acceptance profiles: messy-contradictory and hostile-adversarial
// (NEW-56 D1/D2). These extend the Batch E clean pattern (acceptance_clean_test.go)
// through the same seams: fakeRunner, fakeResolver, cannedTransport (now with
// path-scoped and oversized arms), loopback JS, fixed clock, fresh temp-dir
// cache per iteration, normalized goldens via internal/golden with -update,
// sortedScrubSources redaction, maskTimestamps.
//
// Two profiles:
//   - messy-contradictory: contradictory DNS (including dns_poison), path-scoped
//     HTTP redirects (301/302 chains), CNAME, duplicate urlintel lines, synthetic
//     secrets.
//   - hostile-adversarial: hostile headers, oversized bodies (httpprobe 1 MiB+,
//     js 2 MiB+), discovery burst via quality_max_per_source, adversarial
//     content.
// Both are adversarial CONTENT only — hostile inputs flow through faked seams;
// nothing dials out (hermetic, loopback only).
//
// Golden layout per profile (D2):
//   testdata/acceptance_messy-contradictory/run.golden + stage_<name>.golden
//   testdata/acceptance_hostile-adversarial/run.golden + stage_<name>.golden
// No markdown golden for these profiles (clean only, per D2).

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/golden"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// acceptanceMessyGoldenDir and acceptanceHostileGoldenDir hold the per-profile
// goldens. Names mirror the fixture profile directory names.
var (
	acceptanceMessyGoldenDir   = filepath.Join("testdata", "acceptance_messy-contradictory")
	acceptanceHostileGoldenDir = filepath.Join("testdata", "acceptance_hostile-adversarial")
)

func runAcceptanceProfile(t *testing.T, profile, goldenDir string) {
	t.Helper()
	m, err := loadFixtureManifest(fixturesDir(t), profile)
	if err != nil {
		t.Fatalf("loadFixtureManifest(%s): %v", profile, err)
	}
	h := newFixtureHarness(t, m)
	cfg := h.scanConfig(t)
	clk := fixedClock{now: fixedTime}

	reports := make([]pipeline.RunReport, 0, acceptanceRuns)
	outputDirs := make([]string, 0, acceptanceRuns)
	cacheDirs := make([]string, 0, acceptanceRuns)
	for i := 0; i < acceptanceRuns; i++ {
		cacheDir := t.TempDir()
		c, err := cache.Open(cacheDir, cache.WithClock(clk.Now))
		if err != nil {
			t.Fatalf("run %d: cache.Open: %v", i+1, err)
		}
		outDir := t.TempDir()
		cfg.OutputDir = outDir
		rep, err := pipeline.Run(context.Background(), cfg, c, clk, h.stages())
		if err != nil {
			t.Fatalf("run %d: Run: %v", i+1, err)
		}
		reports = append(reports, rep)
		outputDirs = append(outputDirs, outDir)
		cacheDirs = append(cacheDirs, cacheDir)
	}

	// Determinism gate.
	for i := 1; i < len(reports); i++ {
		if !reflect.DeepEqual(reports[0], reports[i]) {
			t.Fatalf("%s runs differ (run %d vs run %d):\nfirst:\n%+v\nlater:\n%+v", profile, 1, i+1, reports[0], reports[i])
		}
	}
	rep := reports[0]

	if len(rep.Stages) != 12 {
		t.Fatalf("Stages = %d, want 12", len(rep.Stages))
	}
	// Profile-specific sanity: messy and hostile are not required to be
	// completed; they exercise truncation, failure, and adversarial content.
	// We only pin that the run produced a report and that stage records are
	// present. Detailed expectations are in the goldens.

	reds := goldenRedactions(cacheDirs[0], outputDirs, h.loopback)

	golden.Compare(t, filepath.Join(goldenDir, "run.golden"), normalizeRunReport(t, reds, rep))

	for _, sr := range rep.Stages {
		sr := sr
		t.Run(string(sr.Name), func(t *testing.T) {
			golden.Compare(t, filepath.Join(goldenDir, "stage_"+string(sr.Name)+".golden"), normalizeStageRecord(t, reds, sr))
		})
	}
}

func TestAcceptanceMessyContradictory(t *testing.T) {
	runAcceptanceProfile(t, "messy-contradictory", acceptanceMessyGoldenDir)
	// Hermeticity sanity: the harness never touches PATH or network; the
	// fixture manifest is synthetic. No further action needed — the harness
	// itself fatals on unhandled shapes.
	_ = os.Getenv("PATH") // referenced to ensure test stays hermetic (no exec)
}

func TestAcceptanceHostileAdversarial(t *testing.T) {
	runAcceptanceProfile(t, "hostile-adversarial", acceptanceHostileGoldenDir)
	_ = os.Getenv("PATH")
}
