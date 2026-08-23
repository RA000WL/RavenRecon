package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/pipeline/adapt"
)

// The ingest command tests are hermetic: no external tools, no network.
// Flag/config/run-level behavior is exercised through the stages seam with
// fake stages (mirroring scan_test.go); the smoke E2E test drives the
// PRODUCTION factories for exactly the two selected stages — the real
// ingest adapter over a tempdir fixture file and the real report adapter
// writing into a tempdir output directory. The plain-urls importer reads a
// local file; the report engine writes local files; no executable is ever
// spawned and no socket is ever dialed.

// fakeIngestStages returns a stages seam providing one fake stage per name
// in the selection (the runner resolves provided stages against cfg.Stages
// by name). results shapes individual stages; unlisted stages complete
// vacuously. cfgSink optionally captures the ScanConfig the runner passed.
func fakeIngestStages(results map[pipeline.StageName]pipeline.StageResult, cfgSink *pipeline.ScanConfig) func(pipeline.ScanConfig) []pipeline.Stage {
	return func(cfg pipeline.ScanConfig) []pipeline.Stage {
		if cfgSink != nil {
			*cfgSink = cfg
		}
		out := make([]pipeline.Stage, 0, len(cfg.Stages))
		for _, n := range cfg.Stages {
			r := pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}
			if res, ok := results[n]; ok {
				r = res
			}
			out = append(out, &fakeScanStage{name: n, result: r})
		}
		return out
	}
}

func TestParseIngestArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantOpts ingestOptions
		wantErr  bool
		wantHelp bool
		wantErrf string
	}{
		{
			name:     "target and single path",
			args:     []string{"example.com", "/tmp/urls.txt"},
			wantOpts: ingestOptions{target: "example.com", paths: []string{"/tmp/urls.txt"}, outputDir: defaultOutputDir},
		},
		{
			name: "options before target, multiple paths",
			args: []string{
				"--stages", " dns , report ",
				"--cache", "/tmp/rcache",
				"--no-cache",
				"--output", "out/",
				"--tui",
				"example.com",
				"/tmp/urls.txt", "/tmp/httpx.json",
			},
			wantOpts: ingestOptions{
				target:    "example.com",
				paths:     []string{"/tmp/urls.txt", "/tmp/httpx.json"},
				stages:    []pipeline.StageName{pipeline.StageDNS, pipeline.StageReport},
				stagesSet: true,
				cacheDir:  "/tmp/rcache",
				noCache:   true,
				outputDir: "out/",
				tui:       true,
			},
		},
		{
			name:     "raw target preserved for normalization",
			args:     []string{" EXAMPLE.COM. ", "/tmp/urls.txt"},
			wantOpts: ingestOptions{target: " EXAMPLE.COM. ", paths: []string{"/tmp/urls.txt"}, outputDir: defaultOutputDir},
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
			name:     "no arguments at all",
			args:     []string{},
			wantErr:  true,
			wantErrf: "missing target and input path",
		},
		{
			name:     "target without any path",
			args:     []string{"example.com"},
			wantErr:  true,
			wantErrf: "missing input path argument",
		},
		{
			name:     "unknown flag",
			args:     []string{"--bogus", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "flag",
		},
		{
			// Roadmap honesty: auto-detection only, there is no --type
			// flag — it must fail as an unknown flag, never be absorbed.
			name:     "--type is not a flag, ever",
			args:     []string{"--type", "httpx", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "flag",
		},
		{
			name:     "discover rejected with the corpus-replaces-discovery rationale",
			args:     []string{"--stages", "discover,dns", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: `"discover" is not available in ingest`,
		},
		{
			name:     "ingest itself cannot be reselected",
			args:     []string{"--stages", "ingest", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "always runs first",
		},
		{
			name:     "unknown stage names the downstream vocabulary",
			args:     []string{"--stages", "nmap", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "known stages:",
		},
		{
			name:     "empty stages list",
			args:     []string{"--stages", ",", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "empty stage list",
		},
		{
			name:     "explicitly empty stages flag",
			args:     []string{"--stages", "", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "empty stage list",
		},
		{
			name:     "tui and verbose mutually exclusive",
			args:     []string{"--tui", "--verbose", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "--tui and --verbose are mutually exclusive",
		},
		{
			name:     "tui compact requires tui",
			args:     []string{"--tui-compact", "example.com", "/tmp/urls.txt"},
			wantErr:  true,
			wantErrf: "--tui-compact requires --tui",
		},
		{
			name:     "option after the target is a targeted usage error, never a path",
			args:     []string{"example.com", "/tmp/u.txt", "--stages", "report"},
			wantErr:  true,
			wantErrf: `looks like an option but follows the target`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseIngestArgs(tc.args)
			if tc.wantHelp {
				if !errors.Is(err, errIngestHelp) {
					t.Fatalf("want errIngestHelp, got %v", err)
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
				t.Fatalf("parseIngestArgs(%v): %v", tc.args, err)
			}
			if !reflect.DeepEqual(opts, tc.wantOpts) {
				t.Fatalf("opts = %+v, want %+v", opts, tc.wantOpts)
			}
		})
	}
}

func TestIngestDownstreamStagesMatchPipeline(t *testing.T) {
	// The derived vocabulary must be exactly pipeline.AllStages() minus
	// discover, in order — the derivation is the drift guard for both the
	// default selection and the --stages validation message.
	all := pipeline.AllStages()
	var want []pipeline.StageName
	for _, s := range all {
		if s != pipeline.StageDiscover {
			want = append(want, s)
		}
	}
	got := ingestDownstreamStages()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ingestDownstreamStages = %v, want AllStages minus discover = %v", got, want)
	}
}

func TestBuildIngestConfigDefaults(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	opts, err := parseIngestArgs([]string{"EXAMPLE.COM", "/tmp/a.txt", "/tmp/b"})
	if err != nil {
		t.Fatalf("parseIngestArgs: %v", err)
	}
	cfg, err := buildIngestConfig(opts, target)
	if err != nil {
		t.Fatalf("buildIngestConfig: %v", err)
	}

	// Default selection: ingest first, then all eleven downstream stages in
	// pipeline order (imported corpus replaces discovery as corpus source).
	wantStages := append([]pipeline.StageName{pipeline.StageIngest}, ingestDownstreamStages()...)
	if !reflect.DeepEqual(cfg.Stages, wantStages) {
		t.Fatalf("Stages = %v, want %v", cfg.Stages, wantStages)
	}
	if cfg.Stages[0] != pipeline.StageIngest {
		t.Fatalf("first stage = %q, want ingest always first", cfg.Stages[0])
	}

	// Paths flow to the ingest stage's documented param, newline-joined
	// verbatim (validation happens once, in the stage).
	wantPaths := strings.Join([]string{"/tmp/a.txt", "/tmp/b"}, "\n")
	if got := cfg.StageParams[pipeline.StageIngest]["paths"]; got != wantPaths {
		t.Fatalf("ingest paths param = %q, want %q", got, wantPaths)
	}
	if len(cfg.StageParams) != 1 {
		t.Fatalf("StageParams = %v, want exactly the ingest entry", cfg.StageParams)
	}
	if cfg.OutputDir != defaultOutputDir {
		t.Fatalf("OutputDir = %q, want %q", cfg.OutputDir, defaultOutputDir)
	}
	if cfg.Target.Name != "example.com" {
		t.Fatalf("Target.Name = %q, want canonical example.com", cfg.Target.Name)
	}
}

func TestBuildIngestConfigSelection(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	opts, err := parseIngestArgs([]string{"--stages", "report,dns", "example.com", "/tmp/a.txt"})
	if err != nil {
		t.Fatalf("parseIngestArgs: %v", err)
	}
	cfg, err := buildIngestConfig(opts, target)
	if err != nil {
		t.Fatalf("buildIngestConfig: %v", err)
	}
	// Ingest is ALWAYS first; the caller's downstream order is preserved
	// after it (mirroring scan's caller-order selection semantics).
	wantStages := []pipeline.StageName{pipeline.StageIngest, pipeline.StageReport, pipeline.StageDNS}
	if !reflect.DeepEqual(cfg.Stages, wantStages) {
		t.Fatalf("Stages = %v, want %v", cfg.Stages, wantStages)
	}
}

// TestRunIngestOutcomeMapping pins the exit-code contract — identical to
// scan: completed/partial exit cleanly, failed/cancelled/incomplete return
// an error (main exits 1), and every run prints its honest summary first.
func TestRunIngestOutcomeMapping(t *testing.T) {
	cases := []struct {
		name    string
		results map[pipeline.StageName]pipeline.StageResult
		wantErr string
	}{
		{
			name:    "completed",
			wantErr: "",
		},
		{
			name: "partial",
			results: map[pipeline.StageName]pipeline.StageResult{
				pipeline.StageDNS: {Outcome: pipeline.OutcomePartial},
			},
			wantErr: "",
		},
		{
			// Every SELECTED stage must fail for the run outcome to be
			// failed (the always-first ingest stage participates: with it
			// completing, failed+completed folds to partial).
			name: "failed",
			results: map[pipeline.StageName]pipeline.StageResult{
				pipeline.StageIngest: {Outcome: pipeline.OutcomeFailed, ItemsFailed: 1, Err: errors.New("boom")},
				pipeline.StageDNS:    {Outcome: pipeline.OutcomeFailed, ItemsFailed: 1, Err: errors.New("boom")},
			},
			wantErr: "run outcome failed",
		},
		{
			name: "cancelled",
			results: map[pipeline.StageName]pipeline.StageResult{
				pipeline.StageDNS: {Outcome: pipeline.OutcomeCancelled},
			},
			wantErr: "run outcome cancelled",
		},
		{
			name: "incomplete",
			results: map[pipeline.StageName]pipeline.StageResult{
				pipeline.StageDNS: {Outcome: pipeline.OutcomeIncomplete},
			},
			wantErr: "run outcome incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := runIngest(context.Background(), &buf,
				[]string{"--stages", "dns", "example.com", "/tmp/urls.txt"},
				fakeIngestStages(tc.results, nil), nil)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("runIngest: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if !strings.Contains(buf.String(), "RavenRecon ingest: example.com") {
				t.Fatalf("summary missing the ingest header:\n%s", buf.String())
			}
			if !strings.Contains(buf.String(), "Outcome: "+tc.name+"\n") {
				t.Fatalf("summary must state the honest outcome %q:\n%s", tc.name, buf.String())
			}
		})
	}
}

// TestRunIngestValidationErrorsNeverInvokeStages pins that every
// validation-error path returns before the stages seam is consulted.
func TestRunIngestValidationErrorsNeverInvokeStages(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantErrf string
	}{
		{name: "no args", args: []string{}, wantErrf: "missing target and input path"},
		{name: "target only", args: []string{"example.com"}, wantErrf: "missing input path"},
		{name: "IP target rejected", args: []string{"192.0.2.1", "/tmp/u.txt"}, wantErrf: "is an IP address, not a hostname"},
		{name: "discover rejected", args: []string{"--stages", "discover", "example.com", "/tmp/u.txt"}, wantErrf: "not available in ingest"},
		{name: "unknown flag", args: []string{"--bogus", "example.com", "/tmp/u.txt"}, wantErrf: "flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			seam := func(pipeline.ScanConfig) []pipeline.Stage {
				calls++
				return nil
			}
			var buf bytes.Buffer
			err := runIngest(context.Background(), &buf, tc.args, seam, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrf) {
				t.Fatalf("want error containing %q, got %v", tc.wantErrf, err)
			}
			if calls != 0 {
				t.Fatalf("stages seam consulted %d times on a validation error; want 0", calls)
			}
		})
	}
}

// TestRunIngestTargetNormalized pins the single-normalization-point rule:
// the seam receives the canonical target built by asset.NewDomain.
func TestRunIngestTargetNormalized(t *testing.T) {
	var cfgSink pipeline.ScanConfig
	var buf bytes.Buffer
	err := runIngest(context.Background(), &buf,
		[]string{" EXAMPLE.COM. ", "/tmp/urls.txt"},
		fakeIngestStages(nil, &cfgSink), nil)
	if err != nil {
		t.Fatalf("runIngest: %v", err)
	}
	if cfgSink.Target.Name != "example.com" {
		t.Fatalf("seam target.Name = %q, want canonical example.com", cfgSink.Target.Name)
	}
	if cfgSink.Target.Original != " EXAMPLE.COM. " {
		t.Fatalf("seam target.Original = %q, want the raw input preserved", cfgSink.Target.Original)
	}
	// The seam's ingest params carry the paths verbatim.
	if got := cfgSink.StageParams[pipeline.StageIngest]["paths"]; got != "/tmp/urls.txt" {
		t.Fatalf("seam paths param = %q, want /tmp/urls.txt", got)
	}
	out := buf.String()
	if strings.Contains(out, " EXAMPLE.COM. ") {
		t.Fatalf("summary must not echo the raw target form:\n%s", out)
	}
}

// TestRunIngestCacheState pins the cache on/off rendering through the real
// runIngest cache path (mirroring scan's contract: --cache wins over
// configuration, --no-cache forces off, default off).
func TestRunIngestCacheState(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "cache on", args: []string{"--cache", "", "example.com", "/tmp/u.txt"}, want: "(cache: on)"},
		{name: "no-cache forces off", args: []string{"--cache", "", "--no-cache", "example.com", "/tmp/u.txt"}, want: "(cache: off)"},
		{name: "default off", args: []string{"example.com", "/tmp/u.txt"}, want: "(cache: off)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]string, len(tc.args))
			copy(args, tc.args)
			if tc.want == "(cache: on)" {
				args[1] = t.TempDir() // each subtest gets its own cache dir
			}
			var buf bytes.Buffer
			if err := runIngest(context.Background(), &buf, args, fakeIngestStages(nil, nil), nil); err != nil {
				t.Fatalf("runIngest: %v", err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("summary missing %q:\n%s", tc.want, buf.String())
			}
		})
	}
}

// TestRunIngestInterrupted pins the Ctrl-C/SIGTERM contract: a pre-cancelled
// run context returns promptly with a context-wrapped error AFTER the
// summary is printed, and the stages were constructed but none invoked.
func TestRunIngestInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	seam := func(cfg pipeline.ScanConfig) []pipeline.Stage {
		calls++
		return fakeIngestStages(nil, nil)(cfg)
	}
	var buf bytes.Buffer
	err := runIngest(ctx, &buf, []string{"example.com", "/tmp/u.txt"}, seam, nil)
	if err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a context.Canceled-wrapped error", err)
	}
	if !strings.Contains(err.Error(), "run interrupted") {
		t.Fatalf("error = %v, want the interrupted-run framing", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Outcome: cancelled") {
		t.Fatalf("the cancelled summary must still be printed:\n%s", out)
	}
	if calls != 1 {
		t.Fatalf("stages seam consulted %d times; want exactly 1 (stages constructed, none invoked)", calls)
	}
}

// TestRunIngestTUIWiring pins that --tui wires the bus as the run's single
// observer, the controller is joined before runIngest returns, and the
// summary is byte-identical to the no-flag run (the frame never changes the
// machine-facing output). Reuses scan_test.go's fakeTUI harness.
func TestRunIngestTUIWiring(t *testing.T) {
	dir := t.TempDir()
	var plain bytes.Buffer
	if err := runIngest(context.Background(), &plain,
		[]string{"--output", dir, "example.com", "/tmp/u.txt"},
		fakeIngestStages(nil, nil), nil); err != nil {
		t.Fatalf("no-flag run: %v", err)
	}

	var cfgSink pipeline.ScanConfig
	fake := &fakeTUI{}
	var buf bytes.Buffer
	if err := runIngest(context.Background(), &buf,
		[]string{"--output", dir, "--tui", "example.com", "/tmp/u.txt"},
		fakeIngestStages(nil, &cfgSink), newFakeTUIFactory(fake)); err != nil {
		t.Fatalf("--tui run: %v", err)
	}
	if cfgSink.Observer == nil {
		t.Fatal("--tui must wire ScanConfig.Observer to the bus")
	}
	snap := fake.snapshot()
	if snap.sub == nil {
		t.Fatal("the TUI seam must receive the subscriber")
	}
	assertTUIReturned(t, fake)
	// NEW-82: a RunMetadata event (declared target + output directory)
	// precedes the runner's events, then 12 selected stages ×
	// started+finished = 24 stage events, sequences intact.
	if len(snap.events) != 25 {
		t.Fatalf("controller consumed %d events, want 25 (RunMetadata + 24 stage events)", len(snap.events))
	}
	first := snap.events[0]
	if first.Kind != event.KindRunMetadata {
		t.Fatalf("first event kind = %s, want %s (RunMetadata must be published before the controller starts)", first.Kind, event.KindRunMetadata)
	}
	meta, ok := first.Payload.(event.RunMetadata)
	if !ok {
		t.Fatalf("first payload = %T, want event.RunMetadata", first.Payload)
	}
	if meta.Target != "example.com" {
		t.Fatalf("RunMetadata.Target = %q, want the declared target", meta.Target)
	}
	if meta.OutputDir != dir {
		t.Fatalf("RunMetadata.OutputDir = %q, want the effective --output directory %q", meta.OutputDir, dir)
	}
	for i, ev := range snap.events[1:] {
		wantKind := eventKindAt(i)
		if ev.Kind != wantKind {
			t.Fatalf("stage event %d kind = %s, want %s", i, ev.Kind, wantKind)
		}
		if want := uint64(i + 2); ev.Sequence != want {
			t.Fatalf("stage event %d sequence = %d, want %d", i, ev.Sequence, want)
		}
	}
	if buf.String() != plain.String() {
		t.Fatalf("--tui summary differs from the no-flag summary\n--tui:\n%s\nplain:\n%s", buf.String(), plain.String())
	}
}

// eventKindAt maps position → expected kind for alternating started/finished.
func eventKindAt(i int) event.Kind {
	if i%2 == 0 {
		return event.KindStageStarted
	}
	return event.KindStageFinished
}

// TestRunIngestTUIRunnerRequired pins the defensive seam guard mirrors
// scan's: --tui without a factory errors before any stage runs.
func TestRunIngestTUIRunnerRequired(t *testing.T) {
	calls := 0
	seam := func(pipeline.ScanConfig) []pipeline.Stage {
		calls++
		return nil
	}
	var buf bytes.Buffer
	err := runIngest(context.Background(), &buf, []string{"--tui", "example.com", "/tmp/u.txt"}, seam, nil)
	if err == nil || !strings.Contains(err.Error(), "no TUI runner available") {
		t.Fatalf("want the no-TUI-runner error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("stages seam consulted %d times; want 0", calls)
	}
}

// TestRunIngestHelp pins the usage document: real flags, real defaults, the
// default pipeline order, the no---type statement, and the discover rule.
func TestRunIngestHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := runIngest(context.Background(), &buf, []string{"-h"}, nil, nil); err != nil {
		t.Fatalf("ingest -h must print usage and succeed, got %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"RavenRecon ingest - import existing reconnaissance data",
		"ravenrecon ingest [options] <target> <path> [<path>...]",
		"--stages",
		"--output",
		"--cache",
		"--no-cache",
		"--verbose",
		"--tui",
		"--tui-compact",
		"NO --type flag",
		"discover",
		"is scan's job",
		defaultOutputDir,
		"Exit codes",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage output missing %q:\n%s", want, out)
		}
	}
	// Every downstream vocabulary name appears in the usage text.
	for _, n := range ingestDownstreamStages() {
		if !strings.Contains(out, string(n)) {
			t.Fatalf("usage output missing stage name %q:\n%s", n, out)
		}
	}
}

// TestRunIngestDispatchValidation routes through the CLI dispatcher:
// help exits cleanly, bad invocations error before anything runs.
func TestRunIngestDispatchValidation(t *testing.T) {
	if err := Run(context.Background(), []string{"ingest", "-h"}); err != nil {
		t.Fatalf("ingest -h via Run must succeed, got %v", err)
	}
	if err := Run(context.Background(), []string{"ingest"}); err == nil || !strings.Contains(err.Error(), "missing target") {
		t.Fatalf("bare ingest via Run must error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Smoke E2E: production ingest + report adapters over temp fixtures.

// smokeIngestE2EStages is the production-shaped seam for the SELECTED
// stages (--stages report): the real composed ingest stage plus the real
// report stage at its production default registry. Unselected adapters are
// omitted entirely — the runner would skip them anyway, and constructing
// them would drag exec/network-capable seams into a hermetic test.
func smokeIngestE2EStages() func(pipeline.ScanConfig) []pipeline.Stage {
	return func(cfg pipeline.ScanConfig) []pipeline.Stage {
		return []pipeline.Stage{
			adapt.NewIngestStage(),
			adapt.NewReportStage(nil),
		}
	}
}

// TestRunIngestSmokeE2E drives the full command shape hermetically: a
// tempdir urls.txt fixture → real ingest stage (content detection picks
// plain-urls) → real report stage writing json+markdown into a tempdir —
// and pins that report.json exists containing the IMPORTED assets, the
// origins census, and per-asset attribution naming the importer and file.
func TestRunIngestSmokeE2E(t *testing.T) {
	base := t.TempDir()
	urlsPath := filepath.Join(base, "urls.txt")
	content := strings.Join([]string{
		"http://api.example.com/login",
		"https://api.example.com/admin",
		"http://www.example.com/",
	}, "\n") + "\n"
	if err := os.WriteFile(urlsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	outDir := filepath.Join(base, "out")

	var buf bytes.Buffer
	args := []string{"--output", outDir, "--stages", "report", "example.com", urlsPath}
	if err := runIngest(context.Background(), &buf, args, smokeIngestE2EStages(), nil); err != nil {
		t.Fatalf("runIngest: %v\nsummary:\n%s", err, buf.String())
	}

	summary := buf.String()
	if !strings.Contains(summary, "Outcome: completed") {
		t.Fatalf("summary missing the completed outcome:\n%s", summary)
	}
	if !strings.Contains(summary, "  ingest     completed") {
		t.Fatalf("summary missing the completed ingest stage line:\n%s", summary)
	}

	reportJSON := filepath.Join(outDir, "ravenrecon-report-example.com.json")
	raw, err := os.ReadFile(reportJSON)
	if err != nil {
		t.Fatalf("read %s: %v\nsummary:\n%s", reportJSON, err, summary)
	}

	var doc struct {
		URLs []struct {
			Scheme   string `json:"scheme"`
			HostPort string `json:"hostport"`
		} `json:"urls"`
		Origins     map[string]int `json:"origins"`
		Attribution map[string]struct {
			Importer     string `json:"importer"`
			Filename     string `json:"filename"`
			OriginalTool string `json:"original_tool"`
		} `json:"attribution"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse report.json: %v", err)
	}

	// Imported assets present: all three in-scope URLs reached the report.
	if len(doc.URLs) != 3 {
		t.Fatalf("report.json carries %d urls, want 3:\n%s", len(doc.URLs), raw)
	}
	hostPorts := map[string]bool{}
	for _, u := range doc.URLs {
		hostPorts[u.HostPort] = true
	}
	if !hostPorts["api.example.com"] || !hostPorts["www.example.com"] {
		t.Fatalf("report.json urls missing imported hosts: %v", hostPorts)
	}

	// Origins census: every retained asset arrived through ingestion.
	if doc.Origins == nil || doc.Origins["imported"] != 3 {
		t.Fatalf("origins census wrong: %v (attribution keys=%d)", doc.Origins, len(doc.Attribution))
	}
	if doc.Origins["discovered"] != 0 {
		t.Fatalf("discovered origin count = %d, want 0 (an import-only run discovers nothing)", doc.Origins["discovered"])
	}

	// Attribution: every URL attributed to the plain-urls importer and its
	// source file.
	if len(doc.Attribution) != 3 {
		t.Fatalf("attribution entries = %d, want 3", len(doc.Attribution))
	}
	attributedAPI := false
	for id, entry := range doc.Attribution {
		if entry.Importer != "plain-urls" {
			t.Fatalf("attribution[%s].importer = %q, want plain-urls", id, entry.Importer)
		}
		if entry.Filename != "urls.txt" {
			t.Fatalf("attribution[%s].filename = %q, want urls.txt", id, entry.Filename)
		}
		if strings.HasPrefix(id, "url:") && strings.Contains(id, "api.example.com") {
			attributedAPI = true
		}
	}
	if !attributedAPI {
		t.Fatalf("no attribution key covers api.example.com: %v", doc.Attribution)
	}
}

// TestParseIngestArgsHelpAfterOption is the NEW-83 regression test: a bare
// "help" following an option becomes the target positional (Go's flag
// package stops at the first non-flag argument), which previously produced
// a confusing invalid-target error. Per the contract comment it is a help
// request.
func TestParseIngestArgsHelpAfterOption(t *testing.T) {
	opts, err := parseIngestArgs([]string{"--tui", "help"})
	if err != errIngestHelp {
		t.Fatalf("bare help after an option must return errIngestHelp, got %v", err)
	}
	if opts.target != "" {
		t.Fatalf("help request must not produce options, got %+v", opts)
	}
}
