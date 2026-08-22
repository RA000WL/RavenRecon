package adapt

// TestAcceptanceCleanProfile is the v1.7 batch E clean-profile acceptance
// run (NEW-56 batch E; TODO.md NEW-56 decisions D1 and D2): the committed
// fixtures/clean-baseline/manifest.json is materialized through the
// EXISTING T4 harness seams (acceptance_support_test.go — fake discovery
// runner, fake resolver, canned HTTP transport, scripted gau, loopback JS
// server behind the rewrite transport, synthetic catalogs, production
// report registry) and drives the REAL twelve-stage adapters end to end.
//
// Hermeticity: nothing leaves the process — every external tool invocation
// lands on the scripted fakeRunner (fakeLookup resolves tool names to
// themselves; no executable is ever exec'd), DNS answers come from the
// fakeResolver, HTTP probes from the cannedTransport, live-URL probes
// from the hermetic liveTransport, and only the jsintel fetches touch the
// loopback httptest server. No public internet, no tools on PATH (§13).
//
// Determinism: THREE consecutive runs — each with a FRESH temp-dir cache
// (decision D1) and its own output directory — must be DeepEqual pairwise
// before any golden is consulted. The run uses the package fixed clock;
// the normalizer additionally masks every timestamp/duration field so the
// goldens are independent of the concrete instant (decision D2), and the
// machine-local literals (temp/cache/output directories, the loopback
// URL) are redacted before marshal.
//
// Golden layout (testdata/acceptance_clean/, one file per artifact):
//
//   - run.golden             the WHOLE normalized RunReport JSON;
//   - stage_<name>.golden    ONE golden PER StageRecord — the failing
//                            subtest IS the stage name, so a regression
//                            names the regressed stage directly;
//   - report.md.golden       the markdown report the production registry
//                            committed into the first run's OutputDir.
//
// Regenerate ONLY through the shared flag:
//
//	go test ./internal/pipeline/adapt/ -run TestAcceptanceCleanProfile -update
//
// A normal run never writes (internal/golden).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/golden"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// acceptanceGoldenDir holds the clean-profile goldens, relative to the
// package directory (the test binary's working directory).
var acceptanceGoldenDir = filepath.Join("testdata", "acceptance_clean")

// acceptanceRuns is the consecutive-run count of the determinism gate:
// three identical cold runs over fresh caches must agree pairwise before
// anything is compared against a golden.
const acceptanceRuns = 3

func TestAcceptanceCleanProfile(t *testing.T) {
	m, err := loadFixtureManifest(fixturesDir(t), "clean-baseline")
	if err != nil {
		t.Fatalf("loadFixtureManifest(clean-baseline): %v", err)
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

	// --- Determinism gate: pairwise DeepEqual across the three runs ---
	for i := 1; i < len(reports); i++ {
		if !reflect.DeepEqual(reports[0], reports[i]) {
			t.Fatalf("clean-profile runs differ (run %d vs run %d):\nfirst:\n%+v\nlater:\n%+v",
				1, i+1, reports[0], reports[i])
		}
	}
	rep := reports[0]

	// --- Sanity pins ahead of the goldens: the T4-pinned success shape,
	// asserted directly so a broken run fails here with a readable message
	// instead of an opaque golden diff. ---
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", rep.Outcome)
	}
	if len(rep.Stages) != 12 {
		t.Fatalf("Stages = %d, want 12", len(rep.Stages))
	}
	for i, sr := range rep.Stages {
		if sr.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("stage %d (%s) outcome = %q, want completed", i, sr.Name, sr.Outcome)
		}
		if sr.Truncated || len(sr.StickyFlags) != 0 {
			t.Errorf("stage %s truncated/stickyFlags = %v/%v, want false/empty", sr.Name, sr.Truncated, sr.StickyFlags)
		}
	}
	if rep.Truncated || len(rep.StickyFlags) != 0 || rep.ItemsFailed != 0 {
		t.Fatalf("run Truncated/StickyFlags/ItemsFailed = %v/%v/%d, want false/empty/0",
			rep.Truncated, rep.StickyFlags, rep.ItemsFailed)
	}

	// --- Golden machinery (D2). Redactions cover every machine-local
	// literal the harness touched: the OS temp root, each run's cache and
	// output directories, and the loopback base URL. ---
	reds := goldenRedactions(cacheDirs[0], outputDirs, h.loopback)

	golden.Compare(t, filepath.Join(acceptanceGoldenDir, "run.golden"),
		normalizeRunReport(t, reds, rep))

	// ONE GOLDEN PER STAGE RECORD, the subtest named BY the stage: a drift
	// in one stage fails that stage's subtest and nothing else.
	for _, sr := range rep.Stages {
		sr := sr
		t.Run(string(sr.Name), func(t *testing.T) {
			golden.Compare(t, filepath.Join(acceptanceGoldenDir, "stage_"+string(sr.Name)+".golden"),
				normalizeStageRecord(t, reds, sr))
		})
	}

	// The markdown report the PRODUCTION registry committed during run 1:
	// byte-compared as rendered (its timestamps carry the fixed clock, its
	// digest is content-derived, and the model's wall-clock statistics are
	// zero through the pipeline adapter — nothing to normalize). The file
	// name is the report engine's deterministic default base
	// ("ravenrecon-report-<target>") plus the markdown extension.
	t.Run("report-markdown", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join(outputDirs[0], "ravenrecon-report-example.com.md"))
		if err != nil {
			t.Fatalf("read committed markdown report: %v", err)
		}
		golden.Compare(t, filepath.Join(acceptanceGoldenDir, "report.md.golden"), b)
	})
}

// TestGoldenRedactionScrubOrderDeterministic pins the redaction walker's
// fixed longest-first application order (sortedScrubSources): a string
// carrying NESTED sources — a cache directory inside the OS temp root —
// must collapse to the most specific placeholder on every call, never to
// "<temp>/<...>" just because Go's map iteration landed there first. The
// loop re-scrubs fresh copies many times so the randomized per-iteration
// map order cannot consistently mask an ordering regression.
func TestGoldenRedactionScrubOrderDeterministic(t *testing.T) {
	tmpRoot := t.TempDir()
	cacheDir := filepath.Join(tmpRoot, "c0", "cache")
	loopback := "http://127.0.0.1:1"
	reds := goldenRedactions(cacheDir, []string{filepath.Join(tmpRoot, "out")}, loopback)

	doc := func() map[string]any {
		return map[string]any{
			"a": cacheDir + "/runs/x",
			"b": []any{"see " + loopback + " and " + tmpRoot + "/elsewhere"},
			"c": map[string]any{"d": "plain"},
		}
	}

	var want []byte
	var last map[string]any
	for i := 0; i < 64; i++ {
		v := doc()
		scrubRedactions(v, reds)
		last = v
		got, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal scrubbed doc: %v", err)
		}
		if want == nil {
			want = got
			continue
		}
		if string(got) != string(want) {
			t.Fatalf("scrub order flapped on iteration %d:\nwant %s\ngot  %s", i, want, got)
		}
	}
	// The specific-wins property itself: the nested cache directory became
	// its own placeholder (longest-first), not a rewritten temp prefix.
	if got := last["a"]; got != "<cache-dir>/runs/x" {
		t.Fatalf("nested cache dir = %v, want <cache-dir>/runs/x (longest-first)", got)
	}
	b0 := last["b"].([]any)[0].(string)
	if !strings.Contains(b0, "<loopback>") || !strings.Contains(b0, "<temp>/") {
		t.Fatalf("loopback/temp redaction = %q", b0)
	}
	if strings.Contains(b0, loopback) || strings.Contains(b0, tmpRoot) {
		t.Fatalf("machine-local literal survived scrubbing: %q", b0)
	}
}
