package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/pipeline/adapt"
	"github.com/RA000WL/RavenRecon/internal/tui"
)

// The scan command tests below are hermetic: no external tools, no
// network, no installed binaries. Run-level behavior is exercised through
// the stages seam (runScan's constructor parameter) with fake stages; the
// T6 smoke E2E test (TestRunScanSmokeE2E) drives the PRODUCTION factory
// shape — newScanStages' exact construction — with only the exec- and
// network-capable seams substituted hermetically. The compiled-in
// fingerprint/pattern databases, the production priority catalogs, the
// empty detect registry, and the four builtin report reporters ARE loaded
// (that is the smoke test's point); no executable is ever spawned and no
// socket is ever dialed.

// fakeScanStage is one hermetic pipeline.Stage that returns a canned
// result. calls optionally counts invocations (the runner skips provided
// stages whose name is not in the selection).
type fakeScanStage struct {
	name   pipeline.StageName
	result pipeline.StageResult
	calls  *int
}

func (s *fakeScanStage) Name() pipeline.StageName { return s.name }

func (s *fakeScanStage) Run(_ context.Context, _ pipeline.StageInput) (pipeline.StageResult, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.result, nil
}

// fakeScanStages returns a stages seam providing all twelve stage names in
// pipeline order. results[i] shapes stage i; missing results default to a
// vacuous completed result. The optional cfgSink captures the ScanConfig
// the runner-wiring passed to the seam.
func fakeScanStages(results []pipeline.StageResult, cfgSink *pipeline.ScanConfig) func(pipeline.ScanConfig) []pipeline.Stage {
	return func(cfg pipeline.ScanConfig) []pipeline.Stage {
		if cfgSink != nil {
			*cfgSink = cfg
		}
		names := pipeline.AllStages()
		out := make([]pipeline.Stage, len(names))
		for i, n := range names {
			r := pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}
			if i < len(results) {
				r = results[i]
			}
			out[i] = &fakeScanStage{name: n, result: r}
		}
		return out
	}
}

func TestParseScanArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantOpts scanOptions
		wantErr  bool
		wantHelp bool
		wantErrf string // substring of the error, when wantErr
	}{
		{
			name:     "domain only",
			args:     []string{"example.com"},
			wantOpts: scanOptions{target: "example.com", outputDir: defaultOutputDir},
		},
		{
			name: "options after target",
			args: []string{"example.com",
				"--stages", " discover , dns ",
				"--sources", " subfinder , amass ",
				"--request-timeout", "10s",
				"--concurrency", "8",
				"--timeout", "5m",
				"--cache", "/tmp/rcache",
				"--no-cache",
				"--output", "out/",
				"--verbose"},
			wantOpts: scanOptions{
				target:            "example.com",
				stages:            []pipeline.StageName{pipeline.StageDiscover, pipeline.StageDNS},
				stagesSet:         true,
				sources:           []string{"subfinder", "amass"},
				sourcesSet:        true,
				requestTimeout:    "10s",
				requestTimeoutSet: true,
				concurrency:       8,
				concurrencySet:    true,
				timeout:           5 * time.Minute,
				timeoutSet:        true,
				cacheDir:          "/tmp/rcache",
				noCache:           true,
				outputDir:         "out/",
				verbose:           true,
			},
		},
		{
			name:     "default output dir",
			args:     []string{"example.com", "--no-cache"},
			wantOpts: scanOptions{target: "example.com", noCache: true, outputDir: defaultOutputDir},
		},
		{
			name:     "tui flag",
			args:     []string{"example.com", "--tui"},
			wantOpts: scanOptions{target: "example.com", tui: true, outputDir: defaultOutputDir},
		},
		{
			name:     "tui compact flag requires tui",
			args:     []string{"example.com", "--tui", "--tui-compact"},
			wantOpts: scanOptions{target: "example.com", tui: true, tuiCompact: true, outputDir: defaultOutputDir},
		},
		{
			name:     "tui and verbose mutually exclusive",
			args:     []string{"example.com", "--tui", "--verbose"},
			wantErr:  true,
			wantErrf: "--tui and --verbose are mutually exclusive",
		},
		{
			name:     "verbose and tui mutually exclusive in either order",
			args:     []string{"example.com", "--verbose", "--tui"},
			wantErr:  true,
			wantErrf: "--tui and --verbose are mutually exclusive",
		},
		{
			name:     "tui compact without tui",
			args:     []string{"example.com", "--tui-compact"},
			wantErr:  true,
			wantErrf: "--tui-compact requires --tui",
		},
		{
			name:     "raw target preserved for normalization",
			args:     []string{" EXAMPLE.COM. "},
			wantOpts: scanOptions{target: " EXAMPLE.COM. ", outputDir: defaultOutputDir},
		},
		{
			name:     "missing target",
			args:     []string{},
			wantErr:  true,
			wantErrf: "missing target",
		},
		{
			name:     "help short",
			args:     []string{"-h"},
			wantHelp: true,
		},
		{
			name:     "help long",
			args:     []string{"--help"},
			wantHelp: true,
		},
		{
			name:     "help word",
			args:     []string{"help"},
			wantHelp: true,
		},
		{
			name:     "help after target",
			args:     []string{"example.com", "-h"},
			wantHelp: true,
		},
		{
			name:     "unknown flag",
			args:     []string{"example.com", "--bogus"},
			wantErr:  true,
			wantErrf: "flag",
		},
		{
			name:     "empty stages list",
			args:     []string{"example.com", "--stages", ","},
			wantErr:  true,
			wantErrf: "empty stage list",
		},
		{
			name:     "explicitly empty stages flag",
			args:     []string{"example.com", "--stages", ""},
			wantErr:  true,
			wantErrf: "empty stage list",
		},
		{
			name:     "unknown stage",
			args:     []string{"example.com", "--stages", "bogus"},
			wantErr:  true,
			wantErrf: `unknown stage "bogus"`,
		},
		{
			name:     "unknown stage names the vocabulary",
			args:     []string{"example.com", "--stages", "nmap"},
			wantErr:  true,
			wantErrf: "known stages:",
		},
		{
			name:     "empty sources list",
			args:     []string{"example.com", "--sources", ","},
			wantErr:  true,
			wantErrf: "empty source list",
		},
		{
			name:     "invalid request-timeout",
			args:     []string{"example.com", "--request-timeout", "abc"},
			wantErr:  true,
			wantErrf: "invalid duration",
		},
		{
			name:     "empty request-timeout",
			args:     []string{"example.com", "--request-timeout", ""},
			wantErr:  true,
			wantErrf: "empty duration",
		},
		{
			name:     "negative request-timeout",
			args:     []string{"example.com", "--request-timeout", "-5s"},
			wantErr:  true,
			wantErrf: "must be >= 0",
		},
		{
			name:     "zero request-timeout means engine default",
			args:     []string{"example.com", "--request-timeout", "0"},
			wantOpts: scanOptions{target: "example.com", requestTimeout: "0", requestTimeoutSet: true, outputDir: defaultOutputDir},
		},
		{
			name:     "invalid timeout",
			args:     []string{"example.com", "--timeout", "abc"},
			wantErr:  true,
			wantErrf: "invalid duration",
		},
		{
			name:     "negative timeout",
			args:     []string{"example.com", "--timeout", "-2s"},
			wantErr:  true,
			wantErrf: "must be >= 0",
		},
		{
			name:     "zero concurrency",
			args:     []string{"example.com", "--concurrency", "0"},
			wantErr:  true,
			wantErrf: "must be >= 1",
		},
		{
			name:     "negative concurrency",
			args:     []string{"example.com", "--concurrency", "-1"},
			wantErr:  true,
			wantErrf: "must be >= 1",
		},
		{
			name:     "stray argument after flags",
			args:     []string{"example.com", "--no-cache", "extra"},
			wantErr:  true,
			wantErrf: "unexpected argument",
		},
		{
			name:     "extra positional target",
			args:     []string{"example.com", "other.org"},
			wantErr:  true,
			wantErrf: "unexpected argument",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseScanArgs(tc.args)
			if tc.wantHelp {
				if !errors.Is(err, errScanHelp) {
					t.Fatalf("want errScanHelp, got %v", err)
				}
				return
			}
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrf) {
					t.Fatalf("want error containing %q, got %v", tc.wantErrf, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScanArgs(%v): %v", tc.args, err)
			}
			if !reflect.DeepEqual(opts, tc.wantOpts) {
				t.Fatalf("opts = %+v, want %+v", opts, tc.wantOpts)
			}
		})
	}
}

func TestBuildScanConfigDefaults(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	cfg, err := buildScanConfig(scanOptions{target: "example.com", outputDir: defaultOutputDir}, target)
	if err != nil {
		t.Fatalf("buildScanConfig: %v", err)
	}
	if cfg.Target.Name != "example.com" {
		t.Fatalf("Target = %q, want canonical example.com", cfg.Target.Name)
	}
	if !reflect.DeepEqual(cfg.Stages, pipeline.AllStages()) {
		t.Fatalf("Stages = %v, want all ten in pipeline order", cfg.Stages)
	}
	if cfg.StageParams != nil {
		t.Fatalf("StageParams = %v, want nil without flag selections", cfg.StageParams)
	}
	if cfg.StageBounds != nil {
		t.Fatalf("StageBounds = %v, want nil without concurrency/timeout flags", cfg.StageBounds)
	}
	if cfg.OutputDir != defaultOutputDir {
		t.Fatalf("OutputDir = %q, want %q", cfg.OutputDir, defaultOutputDir)
	}
}

func TestBuildScanConfigSelections(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	opts := scanOptions{
		target:            "example.com",
		stages:            []pipeline.StageName{pipeline.StageDiscover, pipeline.StageDNS, pipeline.StageReport},
		stagesSet:         true,
		sources:           []string{"subfinder"},
		sourcesSet:        true,
		requestTimeout:    "3s",
		requestTimeoutSet: true,
		concurrency:       8,
		concurrencySet:    true,
		timeout:           5 * time.Minute,
		timeoutSet:        true,
		outputDir:         "out/",
	}
	cfg, err := buildScanConfig(opts, target)
	if err != nil {
		t.Fatalf("buildScanConfig: %v", err)
	}
	// The selection is kept in caller order, not reordered.
	wantStages := []pipeline.StageName{pipeline.StageDiscover, pipeline.StageDNS, pipeline.StageReport}
	if !reflect.DeepEqual(cfg.Stages, wantStages) {
		t.Fatalf("Stages = %v, want %v", cfg.Stages, wantStages)
	}
	if got := cfg.StageParams[pipeline.StageDiscover]["sources"]; got != "subfinder" {
		t.Fatalf("discover sources param = %q, want %q", got, "subfinder")
	}
	if got := cfg.StageParams[pipeline.StageHTTPProbe]["request_timeout"]; got != "3s" {
		t.Fatalf("httpprobe request_timeout param = %q, want %q", got, "3s")
	}
	if len(cfg.StageParams) != 2 {
		t.Fatalf("StageParams = %v, want exactly discover and httpprobe entries", cfg.StageParams)
	}
	// --concurrency and --timeout apply to every SELECTED stage, and only
	// to selected stages.
	if len(cfg.StageBounds) != len(wantStages) {
		t.Fatalf("StageBounds = %v, want one entry per selected stage", cfg.StageBounds)
	}
	for _, name := range wantStages {
		b, ok := cfg.StageBounds[name]
		if !ok {
			t.Fatalf("StageBounds missing selected stage %q", name)
		}
		if b.MaxConcurrency != 8 || b.Timeout != 5*time.Minute {
			t.Fatalf("bounds[%s] = %+v, want MaxConcurrency 8, Timeout 5m", name, b)
		}
	}
	if _, ok := cfg.StageBounds[pipeline.StageURLIntel]; ok {
		t.Fatal("StageBounds must not contain unselected stages")
	}
	if cfg.OutputDir != "out/" {
		t.Fatalf("OutputDir = %q, want %q", cfg.OutputDir, "out/")
	}
}

func TestScanCache(t *testing.T) {
	// Caching is disabled by default: no --cache, no config → nil.
	def := config.Default()
	if c, err := scanCache(def, scanOptions{}); err != nil || c != nil {
		t.Fatalf("default scanCache = (%v, %v), want (nil, nil)", c, err)
	}

	// An enabled cache in configuration opens at its configured directory.
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Cache.Enabled = true
	cfg.Cache.Dir = dir
	cfg.Cache.TTL = time.Hour
	if c, err := scanCache(cfg, scanOptions{}); err != nil {
		t.Fatalf("config-enabled scanCache: %v", err)
	} else if c == nil {
		t.Fatal("config-enabled scanCache must open a cache")
	}

	// An explicit --cache dir opens regardless of configuration.
	if c, err := scanCache(def, scanOptions{cacheDir: t.TempDir()}); err != nil {
		t.Fatalf("--cache scanCache: %v", err)
	} else if c == nil {
		t.Fatal("--cache must open a cache even when configuration disables it")
	}

	// --no-cache forces the cache off on every path.
	if c, err := scanCache(cfg, scanOptions{noCache: true}); err != nil || c != nil {
		t.Fatalf("--no-cache with config enabled = (%v, %v), want (nil, nil)", c, err)
	}
	if c, err := scanCache(def, scanOptions{cacheDir: t.TempDir(), noCache: true}); err != nil || c != nil {
		t.Fatalf("--no-cache with --cache = (%v, %v), want (nil, nil)", c, err)
	}
}

// TestStageObserver pins the --verbose rendering: one compact line per
// stage_started/stage_finished, truncation and error suffixes, and the
// containment contract (unknown kinds and hostile payloads never panic).
func TestStageObserver(t *testing.T) {
	var buf bytes.Buffer
	o := &stageObserver{w: &buf}

	o.Observe(event.Event{Kind: event.KindStageStarted, Payload: event.StageStarted{Name: "discover"}})
	o.Observe(event.Event{Kind: event.KindStageFinished, Payload: event.StageFinished{
		Name: "dns", Outcome: "completed", ItemsProcessed: 3, ItemsFailed: 1,
	}})
	o.Observe(event.Event{Kind: event.KindStageFinished, Payload: event.StageFinished{
		Name: "httpprobe", Outcome: "partial", Truncated: true, ItemsProcessed: 2, ItemsFailed: 1,
	}})
	o.Observe(event.Event{Kind: event.KindStageFinished, Payload: event.StageFinished{
		Name: "report", Outcome: "failed", Err: `boom "quoted"`,
	}})
	// Unknown kinds are ignored; hostile events are contained by the
	// type assertions (observed, never panicking): a payload mismatched
	// to its kind and a nil payload under a stage kind.
	o.Observe(event.Event{Kind: event.KindScanStopped, Payload: event.ScanStopped{State: "partial"}})
	o.Observe(event.Event{Kind: event.KindStageStarted, Payload: event.StageFinished{Name: "discover"}})
	o.Observe(event.Event{Kind: event.KindStageFinished, Payload: nil})

	out := buf.String()
	for _, want := range []string{
		"stage_started discover\n",
		"stage_finished dns outcome=completed processed=3 failed=1\n",
		"stage_finished httpprobe outcome=partial processed=2 failed=1 truncated\n",
		`stage_finished report outcome=failed processed=0 failed=0 err="boom \"quoted\""` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("observer output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "scan_stopped") {
		t.Fatalf("observer must ignore non-stage kinds:\n%s", out)
	}
}

// TestScanStageVocabularyMatchesPipeline pins the CLI's duplicated stage
// vocabulary to pipeline.AllStages (the stageVocabularyCLI comment cites
// this test): any pipeline stage added or renamed without the CLI copy
// catching up is a test failure, not a silent CLI gap.
func TestScanStageVocabularyMatchesPipeline(t *testing.T) {
	names := splitList(stageVocabularyCLI)
	all := pipeline.AllStages()
	if len(names) != len(all) {
		t.Fatalf("stageVocabularyCLI has %d entries, pipeline.AllStages has %d", len(names), len(all))
	}
	for i, n := range names {
		if n != string(all[i]) {
			t.Fatalf("stageVocabularyCLI[%d] = %q, pipeline order has %q", i, n, all[i])
		}
	}
}

func TestPrintScanSummary(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	dir := t.TempDir()
	for _, f := range []string{"report.md", "report.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep := pipeline.RunReport{
		Target:         target,
		Outcome:        pipeline.OutcomePartial,
		ItemsProcessed: 7,
		ItemsFailed:    2,
		StickyFlags:    map[string]bool{"probe_truncated": true, "corpus_capped": true},
		Stages: []pipeline.StageRecord{
			{Name: pipeline.StageDiscover, Outcome: pipeline.OutcomeCompleted, ItemsProcessed: 5},
			{
				Name: pipeline.StageHTTPProbe, Outcome: pipeline.OutcomePartial,
				ItemsProcessed: 2, ItemsFailed: 1, Truncated: true,
				StickyFlags: map[string]bool{"probe_truncated": true},
				Err:         errors.New("boom"),
			},
		},
	}
	var buf bytes.Buffer
	if err := printScanSummary(&buf, rep, dir, true); err != nil {
		t.Fatalf("printScanSummary: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"RavenRecon scan: example.com (cache: on)\n",
		"Outcome: partial\n",
		"Flags: corpus_capped probe_truncated\n", // sorted
		"Processed: 7  Failed: 2\n",
		"discover",
		"completed",
		"processed=5 failed=0",
		"httpprobe",
		"partial",
		"processed=2 failed=1 truncated",
		"flags=probe_truncated",
		`error="boom"`,
		"Output: " + dir + "\n",
		"  report.json\n",
		"  report.md\n", // sorted listing
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintScanSummaryCacheOff(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	rep := pipeline.RunReport{Target: target, Outcome: pipeline.OutcomeCompleted}
	var buf bytes.Buffer
	if err := printScanSummary(&buf, rep, t.TempDir(), false); err != nil {
		t.Fatalf("printScanSummary: %v", err)
	}
	if !strings.Contains(buf.String(), "RavenRecon scan: example.com (cache: off)") {
		t.Fatalf("want cache off in the header:\n%s", buf.String())
	}
}

// TestPrintScanSummaryNoReportFiles pins the honest empty-directory note:
// a run whose report stage committed nothing must say so, never list
// nothing silently.
func TestPrintScanSummaryNoReportFiles(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	rep := pipeline.RunReport{Target: target, Outcome: pipeline.OutcomeCompleted}
	var buf bytes.Buffer
	if err := printScanSummary(&buf, rep, t.TempDir(), false); err != nil {
		t.Fatalf("printScanSummary: %v", err)
	}
	if !strings.Contains(buf.String(), "(no report files — the report stage committed nothing)") {
		t.Fatalf("want the no-files note:\n%s", buf.String())
	}
}

// TestPrintScanSummaryUnreadableOutput pins the honest note for a missing
// or unreadable output directory: the summary still succeeds (the run
// data is already printed) and the failure is named, never hidden.
func TestPrintScanSummaryUnreadableOutput(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	rep := pipeline.RunReport{Target: target, Outcome: pipeline.OutcomeCompleted}
	var buf bytes.Buffer
	if err := printScanSummary(&buf, rep, filepath.Join(t.TempDir(), "missing"), false); err != nil {
		t.Fatalf("printScanSummary must not fail on a missing output dir: %v", err)
	}
	if !strings.Contains(buf.String(), "(unable to list:") {
		t.Fatalf("want the honest unable-to-list note:\n%s", buf.String())
	}
}

func TestReportFiles(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"b.txt", "a.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files, err := reportFiles(dir)
	if err != nil {
		t.Fatalf("reportFiles: %v", err)
	}
	if !reflect.DeepEqual(files, []string{"a.json", "b.txt"}) {
		t.Fatalf("reportFiles = %v, want sorted non-directory entries", files)
	}
	if _, err := reportFiles(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("reportFiles on a missing directory must error")
	}
}

// TestRunScanOutcomeMapping pins the documented exit-code contract: runs
// that completed, or completed with partial results, exit cleanly (nil);
// failed, cancelled, and incomplete runs return an error (main exits 1) —
// and EVERY run prints its summary first with the honest outcome.
func TestRunScanOutcomeMapping(t *testing.T) {
	dnsFailed := pipeline.StageResult{Outcome: pipeline.OutcomeFailed, ItemsFailed: 1, Err: errors.New("boom")}
	cases := []struct {
		name    string
		args    []string
		results []pipeline.StageResult
		wantErr string // substring of the run error; "" = clean exit
	}{
		{
			name:    "completed",
			args:    []string{"example.com", "--stages", "discover"},
			wantErr: "",
		},
		{
			name:    "partial",
			args:    []string{"example.com", "--stages", "discover,dns"},
			results: []pipeline.StageResult{{Outcome: pipeline.OutcomeCompleted}, {Outcome: pipeline.OutcomePartial}},
			wantErr: "",
		},
		{
			name:    "failed",
			args:    []string{"example.com", "--stages", "dns"},
			results: []pipeline.StageResult{{}, dnsFailed},
			wantErr: "run outcome failed",
		},
		{
			name:    "cancelled",
			args:    []string{"example.com", "--stages", "dns"},
			results: []pipeline.StageResult{{}, {Outcome: pipeline.OutcomeCancelled}},
			wantErr: "run outcome cancelled",
		},
		{
			name:    "incomplete",
			args:    []string{"example.com", "--stages", "dns"},
			results: []pipeline.StageResult{{}, {Outcome: pipeline.OutcomeIncomplete}},
			wantErr: "run outcome incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := runScan(context.Background(), &buf, tc.args, fakeScanStages(tc.results, nil), nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("runScan: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if !strings.Contains(buf.String(), "Outcome: "+tc.name+"\n") {
				t.Fatalf("summary must state the honest outcome %q:\n%s", tc.name, buf.String())
			}
		})
	}
}

// TestRunScanFailedStillSummarized pins that a failed run returns the
// error AFTER the summary is printed (exit 1 still summarizes), and the
// stage line carries the honest failure detail.
func TestRunScanFailedStillSummarized(t *testing.T) {
	var buf bytes.Buffer
	results := []pipeline.StageResult{{}, {Outcome: pipeline.OutcomeFailed, ItemsFailed: 1, Err: errors.New("boom")}}
	err := runScan(context.Background(), &buf, []string{"example.com", "--stages", "dns"}, fakeScanStages(results, nil), nil)
	if err == nil || !strings.Contains(err.Error(), "run outcome failed") {
		t.Fatalf("want run-outcome-failed error, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RavenRecon scan: example.com") {
		t.Fatalf("the summary must still be printed:\n%s", out)
	}
	if !strings.Contains(out, `error="boom"`) {
		t.Fatalf("the stage failure detail must render:\n%s", out)
	}
}

// TestRunScanValidationErrorsNeverInvokeStages pins that every
// validation-error path returns before the stages seam is consulted:
// nothing runs, nothing is constructed.
func TestRunScanValidationErrorsNeverInvokeStages(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantErrf string
	}{
		{name: "missing target", args: []string{}, wantErrf: "missing target"},
		{name: "IP target rejected", args: []string{"192.0.2.1"}, wantErrf: "is an IP address, not a hostname"},
		{name: "blank target rejected", args: []string{"   "}, wantErrf: "invalid target"},
		{name: "unknown stage", args: []string{"example.com", "--stages", "bogus"}, wantErrf: "unknown stage"},
		{name: "unknown flag", args: []string{"example.com", "--bogus"}, wantErrf: "flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			seam := func(pipeline.ScanConfig) []pipeline.Stage {
				calls++
				return nil
			}
			var buf bytes.Buffer
			err := runScan(context.Background(), &buf, tc.args, seam, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrf) {
				t.Fatalf("want error containing %q, got %v", tc.wantErrf, err)
			}
			if calls != 0 {
				t.Fatalf("stages seam consulted %d times on a validation error; want 0", calls)
			}
		})
	}
}

// TestRunScanTargetNormalized pins the single-normalization-point rule at
// the CLI boundary: uppercase, surrounding whitespace, and a trailing dot
// are normalized away through asset.NewDomain before the pipeline runs,
// and the seam receives the canonical target (with the raw form only in
// Original).
func TestRunScanTargetNormalized(t *testing.T) {
	var cfgSink pipeline.ScanConfig
	var buf bytes.Buffer
	err := runScan(context.Background(), &buf, []string{" EXAMPLE.COM. "}, fakeScanStages(nil, &cfgSink), nil)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if cfgSink.Target.Name != "example.com" {
		t.Fatalf("seam target.Name = %q, want canonical example.com", cfgSink.Target.Name)
	}
	if cfgSink.Target.Original != " EXAMPLE.COM. " {
		t.Fatalf("seam target.Original = %q, want the raw input preserved", cfgSink.Target.Original)
	}
	if cfgSink.OutputDir != defaultOutputDir {
		t.Fatalf("seam OutputDir = %q, want the documented default %q", cfgSink.OutputDir, defaultOutputDir)
	}
	out := buf.String()
	if !strings.Contains(out, "RavenRecon scan: example.com") {
		t.Fatalf("summary must show the canonical target:\n%s", out)
	}
	if strings.Contains(out, " EXAMPLE.COM. ") {
		t.Fatalf("summary must not echo the raw target form:\n%s", out)
	}
}

// TestRunScanCacheState pins the cache on/off rendering through the real
// runScan cache path: --cache opens a cache (summary says on), --no-cache
// forces it off even when --cache was given.
func TestRunScanCacheState(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "cache on", args: []string{"example.com", "--cache", ""}, want: "(cache: on)"},
		{name: "no-cache forces off", args: []string{"example.com", "--cache", "", "--no-cache"}, want: "(cache: off)"},
		{name: "default off", args: []string{"example.com"}, want: "(cache: off)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]string, len(tc.args))
			copy(args, tc.args)
			if tc.want == "(cache: on)" {
				// Each subtest needs its own temp cache dir.
				args[2] = t.TempDir()
			}
			var buf bytes.Buffer
			if err := runScan(context.Background(), &buf, args, fakeScanStages(nil, nil), nil); err != nil {
				t.Fatalf("runScan: %v", err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("summary missing %q:\n%s", tc.want, buf.String())
			}
		})
	}
}

// TestRunScanInterrupted pins the Ctrl-C/SIGTERM contract: a run context
// cancelled before the run starts returns promptly with a
// context.Canceled-wrapped error AFTER the summary is printed (partial
// results are never lost), and never invokes any stage.
func TestRunScanInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	seam := func(cfg pipeline.ScanConfig) []pipeline.Stage {
		calls++
		stages := fakeScanStages(nil, nil)(cfg)
		return stages
	}
	var buf bytes.Buffer
	start := time.Now()
	err := runScan(ctx, &buf, []string{"example.com"}, seam, nil)
	if err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a context.Canceled-wrapped error", err)
	}
	if !strings.Contains(err.Error(), "run interrupted") {
		t.Fatalf("error = %v, want the interrupted-run framing", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled run took %s to return; want prompt cancellation", elapsed)
	}
	out := buf.String()
	if !strings.Contains(out, "Outcome: cancelled") {
		t.Fatalf("the cancelled summary must still be printed:\n%s", out)
	}
	if calls != 1 {
		t.Fatalf("stages seam consulted %d times; want exactly 1 (stages constructed, none invoked)", calls)
	}
}

// ---------------------------------------------------------------------------
// TUI wiring (--tui) harness and tests. Hermetic: the fake TUI mirrors the
// real Controller.Run contract — consume the subscriber's events until it
// closes or the context is cancelled, then return — so the join assertions
// below are real ordering guarantees, not sleeps or polls.

// fakeTUI is a hermetic tuiRunner mirroring tui.Controller.Run's contract:
// it consumes the subscriber's events until the subscriber closes or the
// context is cancelled, then records its return. cfg/sub/w capture what the
// seam handed it; events records the consumed stream. err is the injected
// Run result returned when the subscriber closes (the write-failure path);
// a cancelled context returns ctx.Err(), exactly like the real controller.
type fakeTUI struct {
	mu     sync.Mutex
	sub    *event.Subscriber
	cfg    config.TUIConfig
	w      io.Writer
	events []event.Event
	err    error // injected Run result on subscriber close

	// returned records that Run returned; every --tui test asserts it is
	// true once runScan has returned (the structural bounded-join
	// guarantee — a missing join leaves the goroutine blocked forever).
	returned  bool
	returnErr error
}

// tuiSeamSnapshot is the immutable capture of what the seam handed the fake
// and what the fake observed while it ran.
type tuiSeamSnapshot struct {
	cfg      config.TUIConfig
	sub      *event.Subscriber
	w        io.Writer
	events   []event.Event
	returned bool
}

// newFakeTUIFactory returns the scanTUIFactory seam that hands the fake to
// runScan and captures the constructed subscription on it.
func newFakeTUIFactory(f *fakeTUI) scanTUIFactory {
	return func(cfg config.TUIConfig, sub *event.Subscriber, w io.Writer) (tuiRunner, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.cfg = cfg
		f.sub = sub
		f.w = w
		return f, nil
	}
}

// Run implements tuiRunner.
func (f *fakeTUI) Run(ctx context.Context) error {
	// An already-cancelled context wins before the loop starts, mirroring
	// the real controller's documented precedence.
	if err := ctx.Err(); err != nil {
		f.recordReturn(err)
		return err
	}
	for {
		select {
		case ev := <-f.sub.Events():
			f.recordEvent(ev)
		case <-f.sub.Done():
			f.drainEvents()
			f.recordReturn(f.err)
			return f.err
		case <-ctx.Done():
			f.drainEvents()
			f.recordReturn(ctx.Err())
			return ctx.Err()
		}
	}
}

// drainEvents consumes whatever remains buffered on the subscriber
// (non-blocking), mirroring the real controller's finish() drain.
func (f *fakeTUI) drainEvents() {
	for {
		select {
		case ev := <-f.sub.Events():
			f.recordEvent(ev)
		default:
			return
		}
	}
}

func (f *fakeTUI) recordEvent(ev event.Event) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
}

func (f *fakeTUI) recordReturn(err error) {
	f.mu.Lock()
	f.returned = true
	f.returnErr = err
	f.mu.Unlock()
}

func (f *fakeTUI) snapshot() tuiSeamSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return tuiSeamSnapshot{
		cfg:      f.cfg,
		sub:      f.sub,
		w:        f.w,
		events:   append([]event.Event(nil), f.events...),
		returned: f.returned,
	}
}

// assertTUIReturned fails the test unless the fake's Run had already
// returned: after runScan returns, the bounded join (subscriber Close →
// <-tuiDone) must have completed. A missing join leaves the goroutine
// blocked on the subscriber forever — the leak this assertion catches.
func assertTUIReturned(t *testing.T, f *fakeTUI) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.returned {
		t.Fatal("TUI Run did not return before runScan returned — the join is missing or the fake is still blocked")
	}
}

// TestResolveTUIColor pins the color resolution: a pipe writer is not a
// character device, so --tui renders without color when stderr is piped or
// redirected (hermetic — no TTY simulation attempted).
func TestResolveTUIColor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if got := resolveTUIColor(w); got != "off" {
		t.Fatalf("resolveTUIColor(os.Pipe writer) = %q, want %q", got, "off")
	}
	var buf bytes.Buffer
	if got := resolveTUIColor(&buf); got != "off" {
		t.Fatalf("resolveTUIColor(non-file writer) = %q, want %q", got, "off")
	}
}

// TestRunScanTUIWiring pins the full --tui wiring end to end: the bus is
// the run's single event sink (ScanConfig.Observer non-nil on the seam
// capture), all 24 stage events (12 stages × started+finished) reach the
// controller's subscriber in order with bus-assigned sequences, the seam
// receives Enabled/Compact from the flags and os.Stderr as the writer,
// Controller.Run returns before runScan returns, and the summary is
// byte-identical to the no-flag run.
func TestRunScanTUIWiring(t *testing.T) {
	dir := t.TempDir() // pre-created so both summaries list no report files identically
	var plain bytes.Buffer
	if err := runScan(context.Background(), &plain, []string{"example.com", "--output", dir}, fakeScanStages(nil, nil), nil); err != nil {
		t.Fatalf("no-flag run: %v", err)
	}

	for _, tc := range []struct {
		name        string
		args        []string
		wantCompact bool
	}{
		{name: "full frame", args: []string{"--tui"}, wantCompact: false},
		{name: "compact frame", args: []string{"--tui", "--tui-compact"}, wantCompact: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfgSink pipeline.ScanConfig
			fake := &fakeTUI{}
			args := append([]string{"example.com", "--output", dir}, tc.args...)
			var buf bytes.Buffer
			if err := runScan(context.Background(), &buf, args, fakeScanStages(nil, &cfgSink), newFakeTUIFactory(fake)); err != nil {
				t.Fatalf("runScan %v: %v", tc.args, err)
			}

			if cfgSink.Observer == nil {
				t.Fatal("--tui must wire ScanConfig.Observer to the bus (seam capture saw nil)")
			}
			snap := fake.snapshot()
			if snap.sub == nil {
				t.Fatal("the TUI seam must receive the subscriber")
			}
			if snap.w != os.Stderr {
				t.Fatalf("the TUI seam writer = %v, want os.Stderr (frames are stderr diagnostics)", snap.w)
			}
			if !snap.cfg.Enabled {
				t.Fatal("seam config Enabled = false, want true")
			}
			if snap.cfg.Compact != tc.wantCompact {
				t.Fatalf("seam config Compact = %v, want %v", snap.cfg.Compact, tc.wantCompact)
			}
			if len(snap.events) != 24 {
				t.Fatalf("controller consumed %d events, want 24 (12 stages × started+finished)", len(snap.events))
			}
			for i, ev := range snap.events {
				wantKind := event.KindStageStarted
				if i%2 == 1 {
					wantKind = event.KindStageFinished
				}
				if ev.Kind != wantKind {
					t.Fatalf("event %d kind = %s, want %s (started/finished alternating)", i, ev.Kind, wantKind)
				}
				if want := uint64(i + 1); ev.Sequence != want {
					t.Fatalf("event %d sequence = %d, want %d (bus-assigned, no drops)", i, ev.Sequence, want)
				}
			}
			assertTUIReturned(t, fake)
			if buf.String() != plain.String() {
				t.Fatalf("--tui summary differs from the no-flag summary\n--tui:\n%s\nplain:\n%s", buf.String(), plain.String())
			}
		})
	}
}

// TestNewScanTUIProductionAdapter pins that the production TUI seam
// returns a real *tui.Controller, not a stub: every render-content
// contract exercised in internal/tui applies verbatim to the --tui CLI
// path. (The wiring test above exercises transport through the fake seam;
// this pins the production adapter itself.)
func TestNewScanTUIProductionAdapter(t *testing.T) {
	bus := event.NewBus(nil)
	sub, err := bus.Subscribe(8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sub.Close(); bus.Close() }()

	ctl, err := newScanTUI(config.TUIConfig{Enabled: true}, sub, io.Discard)
	if err != nil {
		t.Fatalf("newScanTUI: %v", err)
	}
	if _, ok := ctl.(*tui.Controller); !ok {
		t.Fatalf("newScanTUI must return a real *tui.Controller, got %T", ctl)
	}
}

// TestRunScanNoFlagObserverNil pins the zero-change contract: without
// --verbose or --tui the ScanConfig.Observer stays nil, so the no-flag
// path emits nothing and behaves byte-identically to pre-TUI versions.
func TestRunScanNoFlagObserverNil(t *testing.T) {
	var cfgSink pipeline.ScanConfig
	var buf bytes.Buffer
	if err := runScan(context.Background(), &buf, []string{"example.com"}, fakeScanStages(nil, &cfgSink), nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if cfgSink.Observer != nil {
		t.Fatalf("no-flag run wired Observer = %v, want nil (zero behavior change)", cfgSink.Observer)
	}
}

// TestRunScanTUIOutcomeUnchanged pins that --tui never changes the exit
// semantics or the summary content: a failed run still returns the
// run-outcome-failed error with the honest failed summary, and the TUI is
// joined before runScan returns.
func TestRunScanTUIOutcomeUnchanged(t *testing.T) {
	dnsFailed := pipeline.StageResult{Outcome: pipeline.OutcomeFailed, ItemsFailed: 1, Err: errors.New("boom")}
	fake := &fakeTUI{}
	var buf bytes.Buffer
	err := runScan(context.Background(), &buf,
		[]string{"example.com", "--stages", "dns", "--tui"},
		fakeScanStages([]pipeline.StageResult{{}, dnsFailed}, nil),
		newFakeTUIFactory(fake))
	if err == nil || !strings.Contains(err.Error(), "run outcome failed") {
		t.Fatalf("want run-outcome-failed error, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Outcome: failed") {
		t.Fatalf("the summary must state the honest failed outcome:\n%s", out)
	}
	if !strings.Contains(out, `error="boom"`) {
		t.Fatalf("the stage failure detail must render:\n%s", out)
	}
	assertTUIReturned(t, fake)
}

// TestRunScanTUIWriteFailureIsWarning pins the TUI failure contract: a
// non-nil Run result (e.g. a broken frame writer) is a "tui: ..." warning
// on stderr only; scan's exit semantics and summary are unchanged.
func TestRunScanTUIWriteFailureIsWarning(t *testing.T) {
	fake := &fakeTUI{err: errors.New("frame write failed")}
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	var buf bytes.Buffer
	runErr := runScan(context.Background(), &buf, []string{"example.com", "--tui"}, fakeScanStages(nil, nil), newFakeTUIFactory(fake))
	w.Close()
	stderr, _ := io.ReadAll(r)
	r.Close()
	if runErr != nil {
		t.Fatalf("a TUI write failure must not fail the run: %v", runErr)
	}
	if !strings.Contains(string(stderr), "tui: frame write failed") {
		t.Fatalf("stderr missing the tui warning, got: %q", string(stderr))
	}
	if !strings.Contains(buf.String(), "Outcome: completed") {
		t.Fatalf("the summary must still be printed:\n%s", buf.String())
	}
	assertTUIReturned(t, fake)
}

// TestRunScanTUICancelled pins the --tui cancellation path: a pre-cancelled
// run context returns promptly (the bounded join never hangs), the
// cancelled summary still prints, the TUI's Run returned (mirroring the
// real controller's already-cancelled precedence), and the controller's
// ctx.Err() result surfaces as the documented stderr note — exit semantics
// unchanged.
func TestRunScanTUICancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeTUI{}
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	calls := 0
	seam := func(cfg pipeline.ScanConfig) []pipeline.Stage {
		calls++
		return fakeScanStages(nil, nil)(cfg)
	}
	var buf bytes.Buffer
	start := time.Now()
	err = runScan(ctx, &buf, []string{"example.com", "--tui"}, seam, newFakeTUIFactory(fake))
	w.Close()
	stderr, _ := io.ReadAll(r)
	r.Close()
	if err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a context.Canceled-wrapped error", err)
	}
	if !strings.Contains(err.Error(), "run interrupted") {
		t.Fatalf("error = %v, want the interrupted-run framing", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled --tui run took %s to return; want prompt cancellation (bounded join)", elapsed)
	}
	out := buf.String()
	if !strings.Contains(out, "Outcome: cancelled") {
		t.Fatalf("the cancelled summary must still be printed:\n%s", out)
	}
	if calls != 1 {
		t.Fatalf("stages seam consulted %d times; want exactly 1 (stages constructed, none invoked)", calls)
	}
	assertTUIReturned(t, fake)
	// The controller reports the cancelled context; the CLI surfaces it as
	// an honest stderr note, never a changed exit code.
	if !strings.Contains(string(stderr), "tui:") {
		t.Fatalf("stderr missing the tui note for the cancelled context, got: %q", string(stderr))
	}
}

// TestRunScanTUIRunnerRequired pins the defensive seam guard: --tui without
// a TUI factory is a usage error that returns before the stages run
// (construction order: parse → config → cache → TUI → run).
func TestRunScanTUIRunnerRequired(t *testing.T) {
	calls := 0
	seam := func(pipeline.ScanConfig) []pipeline.Stage {
		calls++
		return nil
	}
	var buf bytes.Buffer
	err := runScan(context.Background(), &buf, []string{"example.com", "--tui"}, seam, nil)
	if err == nil || !strings.Contains(err.Error(), "no TUI runner available") {
		t.Fatalf("want the no-TUI-runner error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("stages seam consulted %d times on a --tui construction error; want 0", calls)
	}
}

// TestRunScanHelp pins the help paths: runScan prints the usage and
// returns cleanly for -h, and the CLI dispatcher routes scan help the
// same way as discover help. The dispatcher-level scan cases below
// exercise only argument validation (they error before any stage
// construction): no external tools or networks are involved.
func TestRunScanHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := runScan(context.Background(), &buf, []string{"-h"}, nil, nil); err != nil {
		t.Fatalf("scan -h must print usage and succeed, got %v", err)
	}
	if !strings.Contains(buf.String(), "RavenRecon scan - end-to-end reconnaissance pipeline") {
		t.Fatalf("usage output missing the scan title:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "Usage:") {
		t.Fatalf("usage output missing the usage section:\n%s", buf.String())
	}
}

func TestRunScanDispatchValidation(t *testing.T) {
	// scan dispatch: help exits cleanly (usage to stdout), missing target
	// errors before anything runs.
	if err := Run(context.Background(), []string{"scan", "-h"}); err != nil {
		t.Fatalf("scan -h via Run must succeed, got %v", err)
	}
	if err := Run(context.Background(), []string{"scan"}); err == nil || !strings.Contains(err.Error(), "missing target") {
		t.Fatalf("scan without a target must error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// T6 smoke E2E fixtures (hermetic). Local to this file — adapt's harness
// fixtures are unexported and must not be exported. No executable is
// spawned and no socket is ever dialed.

// smokeLookup resolves every tool name to itself, as if found on PATH.
func smokeLookup(name string) (string, error) { return name, nil }

// smokeScriptEntry is one canned discovery or urlintel execution.
type smokeScriptEntry struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

// smokeScript keys are "path " + strings.Join(args, " "), following the
// scripted shape from internal/pipeline/adapt/t4_determinism_test.go:
// every detection probe is answered, the in-scope host is emitted, and
// gau completes cleanly with nothing to add. Chaos is answered as well
// (PDCP_API_KEY is set by the test harness; chaos returns the same host).
var smokeScript = map[string]smokeScriptEntry{
	"subfinder -version":                 {stdout: "Current Version: v2.6.3\n"},
	"assetfinder -h":                     {stderr: "Usage: assetfinder [domain]\n", exitCode: 2},
	"amass -version":                     {stdout: "v3.23.0\n"},
	"chaos -version":                     {stdout: "chaos v0.5.3\n"},
	"subfinder -d example.com -silent":   {stdout: "www.example.com\n"},
	"assetfinder example.com":            {stdout: "www.example.com\n"},
	"amass enum -passive -d example.com": {stdout: "www.example.com\n"},
	"chaos -d example.com -silent -json": {stdout: "{\"domain\":\"www.example.com\"}\n"},
	"gau -version":                       {stdout: "v1.11.0\n"},
	"gau example.com":                    {},
}

// smokeRunner is a scripted discovery.Runner (thread-safe: the discovery
// stage runs its sources concurrently, and the urlintel stage shares the
// same runner instance).
type smokeRunner struct {
	mu     sync.Mutex
	script map[string]smokeScriptEntry
	calls  []string
}

func newSmokeRunner() *smokeRunner { return &smokeRunner{script: smokeScript} }

func (r *smokeRunner) Run(_ context.Context, cmd discovery.Cmd, _ discovery.Limits) (discovery.RunResult, error) {
	key := cmd.Path + " " + strings.Join(cmd.Args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, key)
	entry, ok := r.script[key]
	r.mu.Unlock()
	if !ok {
		return discovery.RunResult{}, fmt.Errorf("smoke runner: unscripted invocation %q", key)
	}
	if entry.err != nil {
		return discovery.RunResult{}, entry.err
	}
	return discovery.RunResult{Stdout: []byte(entry.stdout), Stderr: []byte(entry.stderr), ExitCode: entry.exitCode}, nil
}

var _ discovery.Runner = (*smokeRunner)(nil)

// smokeResolver answers www.example.com with a single A record (one IPv4)
// and NODATA (empty answers, nil error — the legitimate empty-answer
// convention) for every other host and record type.
type smokeResolver struct {
	mu   sync.Mutex
	seen map[string]int
}

func (r *smokeResolver) Lookup(_ context.Context, host string, rt dns.RecordType) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[string]int)
	}
	r.seen[host]++
	if strings.TrimSuffix(host, ".") == "www.example.com" && rt == dns.TypeA {
		return []string{"93.184.216.34"}, nil
	}
	return nil, nil // NODATA
}

var _ dns.Resolver = (*smokeResolver)(nil)

// smokeTransport is a canned http.RoundTripper: 200 for www.example.com on
// http and https, and a DNS-style error for every other host. It never
// dials a socket.
type smokeTransport struct {
	mu   sync.Mutex
	seen int
}

func (t *smokeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.seen++
	t.mu.Unlock()
	if req.URL.Host != "www.example.com" || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return nil, &net.DNSError{Err: "smoke: no such host", Name: req.URL.Host}
	}
	return &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader("hello\n")),
		ContentLength: 6,
		Request:       req,
	}, nil
}

var _ http.RoundTripper = (*smokeTransport)(nil)

// smokeScanStages builds the production-shaped twelve-stage seam for the
// hermetic smoke tests: the same twelve adapters newScanStages constructs,
// with ONLY the exec- and network-capable seams substituted (a scripted
// discovery.Runner and fake LookupFunc for discover + urlintel, a fake
// dns.Resolver, and a canned http.RoundTripper for httpprobe AND jsintel —
// see TODO NEW-16) and every non-exec stage at its production nil seam.
// cfgSink, when non-nil, captures the ScanConfig the runner-wiring passed
// to the seam.
func smokeScanStages(runner *smokeRunner, tr *smokeTransport, cfgSink *pipeline.ScanConfig) func(pipeline.ScanConfig) []pipeline.Stage {
	return func(cfg pipeline.ScanConfig) []pipeline.Stage {
		if cfgSink != nil {
			*cfgSink = cfg
		}
		return []pipeline.Stage{
			adapt.NewDiscoveryStage(runner, smokeLookup),
			adapt.NewDNSStage(&smokeResolver{}),
			adapt.NewHTTPProbeStage(tr),
			adapt.NewURLIntelStage(runner, smokeLookup),
			adapt.NewCrawlStage(nil),
			adapt.NewTechIntelStage(nil),
			adapt.NewJSIntelStage(tr),
			adapt.NewSecretIntelStage(nil),
			adapt.NewUrlliveStage(tr),
			adapt.NewPriorityStage(nil, nil),
			adapt.NewDetectStage(nil),
			adapt.NewReportStage(nil),
		}
	}
}

// TestRunScanSmokeE2E drives runScan with the PRODUCTION stage shape — the
// same ten adapters newScanStages constructs — substituting ONLY the exec-
// and network-capable seams hermetically: a scripted discovery.Runner and
// fake LookupFunc (discover, urlintel), a fake dns.Resolver (dns), and a
// canned http.RoundTripper (httpprobe AND jsintel — see TODO NEW-16:
// httpprobe always records its probe-target URLs, so a nil jsintel
// transport would reach the real network the moment a host was probed).
// Every non-exec stage keeps its production nil seam: techintel's
// compiled-in fingerprint DB, secrentel's production patterns.Load,
// priority's production catalogs, the EMPTY detect registry, and
// report.NewDefaultRegistry's four builtin reporters — all genuinely
// loaded. Cache is off (the single-shot default).
func TestRunScanSmokeE2E(t *testing.T) {
	t.Setenv("PDCP_API_KEY", "testkey")
	tr := &smokeTransport{}
	runner := newSmokeRunner()
	stages := smokeScanStages(runner, tr, nil)

	run := func(dir string) string {
		t.Helper()
		var buf bytes.Buffer
		args := []string{"example.com", "--output", dir}
		if err := runScan(context.Background(), &buf, args, stages, nil); err != nil {
			t.Fatalf("runScan: %v", err)
		}
		return buf.String()
	}

	outDir := t.TempDir()
	summary := run(outDir)

	// The summary must carry the outcome line (completed) and one stage
	// line per pipeline stage, all completed (printScanSummary's format).
	if !strings.Contains(summary, "Outcome: completed") {
		t.Errorf("summary missing the completed outcome line:\n%s", summary)
	}
	for _, name := range pipeline.AllStages() {
		want := fmt.Sprintf("  %-10s %-10s", name, pipeline.OutcomeCompleted)
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing completed stage line for %s:\n%s", name, summary)
		}
	}

	// Hermeticity proof: every network-capable round trip went through the
	// canned transport. httpprobe performs 2 round trips (http + https for
	// www.example.com) and jsintel fetches the 2 canonical probe targets
	// through the SAME canned transport — the production default transport
	// is never reached, so no socket is ever dialed.
	if tr.seen < 4 {
		t.Errorf("canned transport served %d round trips, want >= 4 (2 httpprobe + 2 jsintel), proving no socket was dialed", tr.seen)
	}

	// Report files follow the engine's deterministic base-name rules:
	// report.Run derives "ravenrecon-report-" + the target name when no
	// BaseName is configured (engine.go:251-258), then sanitizes it through
	// sanitizeBaseName (writer.go:26-68) — example.com →
	// ravenrecon-report-example.com — and each single-part reporter writes
	// dir/BaseName + "." + id + "." + ext; json and markdown are single-part
	// formats, so the files are ravenrecon-report-example.com.json and
	// ravenrecon-report-example.com.md (csv names its parts). The summary
	// lists them.
	for _, file := range []string{"ravenrecon-report-example.com.json", "ravenrecon-report-example.com.md"} {
		if _, err := os.Stat(filepath.Join(outDir, file)); err != nil {
			t.Errorf("report file %s: %v", file, err)
		}
		if !strings.Contains(summary, "  "+file) {
			t.Errorf("summary must list the report file %s:\n%s", file, summary)
		}
	}

	// Light determinism: a second run into a FRESH temp dir (cache still
	// off, same fixtures) produces the same summary content; the only
	// allowed difference is the output-dir path itself, normalized away.
	secondDir := t.TempDir()
	second := run(secondDir)
	norm := func(s, dir string) string { return strings.ReplaceAll(s, dir, "<out>") }
	if norm(second, secondDir) != norm(summary, outDir) {
		t.Errorf("second run summary differs\nfirst:\n%s\nsecond:\n%s", summary, second)
	}
}

// TestRunScanUnknownSourcePassThrough pins the unknown-source
// pass-through as a REAL passthrough through the production discovery
// adapter + engine (the smoke fixtures substitute only the exec seams):
// `--sources nmap` reaches the seam's config as the discover stage's
// "sources" StageParam, the built-in discovery engine rejects the unknown
// source by name BEFORE any tool executes (pipeline.go resolveSourceNames),
// the discover stage records failed, and the failure is surfaced honestly —
// never silently absorbed, never a panic. Two variants pin the documented
// run-level semantics:
//
//   - the full ten-stage run: the runner fail-CONTINUES past the failed
//     discover stage (run.go), the remaining stages complete, and the fold
//     lands on partial (foldOutcome rule 5: failed together with completed
//     stages is partial — never failed, never silently completed) — runScan
//     exits cleanly with the summary naming the failure;
//   - --stages discover only: no stage completed, so the fold lands on
//     failed and runScan returns the named "run outcome failed" error (the
//     exit-1 path), with the summary still printed.
func TestRunScanUnknownSourcePassThrough(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantErr     string // substring of the run error; "" = clean exit
		wantOutcome string // summary Outcome line
	}{
		{
			name:        "full run fail-continues to partial with the error named",
			args:        []string{"example.com", "--sources", "nmap"},
			wantErr:     "",
			wantOutcome: "partial",
		},
		{
			name:        "discover-only run ends failed with the error named",
			args:        []string{"example.com", "--stages", "discover", "--sources", "nmap"},
			wantErr:     "run outcome failed",
			wantOutcome: "failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfgSink pipeline.ScanConfig
			tr := &smokeTransport{}
			runner := newSmokeRunner()
			var buf bytes.Buffer
			args := append(append([]string{}, tc.args...), "--output", t.TempDir())
			err := runScan(context.Background(), &buf, args, smokeScanStages(runner, tr, &cfgSink), nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("runScan: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if got := cfgSink.StageParams[pipeline.StageDiscover]["sources"]; got != "nmap" {
				t.Fatalf("discover sources param = %q, want the unknown source passed through unchanged", got)
			}
			out := buf.String()
			if !strings.Contains(out, "Outcome: "+tc.wantOutcome+"\n") {
				t.Fatalf("summary must state the honest outcome %q:\n%s", tc.wantOutcome, out)
			}
			// The summary renders the stage error Go-quoted, hence the
			// escaped quotes around nmap.
			if !strings.Contains(out, `unknown source \"nmap\"`) {
				t.Fatalf("summary must name the unknown-source failure:\n%s", out)
			}
		})
	}
}
