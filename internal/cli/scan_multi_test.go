package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// Multi-target scan tests (hermetic): parse coverage for the multi-target
// grammar (positional fan-out, --targets files, --target-parallel bounds),
// execution coverage through the stages seam (sequential and bounded-
// parallel fan-out, combined summary, exit-code contract, interruption,
// up-front validation, dry-run, and the single-target backward-compat
// pin). No external tools, no network, no installed binaries.

// configCapture records every ScanConfig handed to the stages seam. It is
// mutex-guarded because --target-parallel fans pipelines out across
// goroutines; the production newScanStages equivalent is pure construction
// and needs no such guard.
type configCapture struct {
	mu   sync.Mutex
	cfgs []pipeline.ScanConfig
}

// seam is the stages seam: it records the config and returns vacuous
// completed stages for every pipeline stage name (the runner skips stages
// outside the selection).
func (c *configCapture) seam(cfg pipeline.ScanConfig) []pipeline.Stage {
	c.mu.Lock()
	c.cfgs = append(c.cfgs, cfg)
	c.mu.Unlock()
	names := pipeline.AllStages()
	out := make([]pipeline.Stage, len(names))
	for i, n := range names {
		out[i] = &fakeScanStage{name: n, result: pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}}
	}
	return out
}

func (c *configCapture) snapshot() []pipeline.ScanConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pipeline.ScanConfig(nil), c.cfgs...)
}

// fakeOutcomeStage is a one-stage hermetic pipeline stage returning a canned
// outcome (with the failure detail a failed outcome conventionally carries).
type fakeOutcomeStage struct {
	name    pipeline.StageName
	outcome pipeline.Outcome
	err     error
}

func (s *fakeOutcomeStage) Name() pipeline.StageName { return s.name }

func (s *fakeOutcomeStage) Run(_ context.Context, _ pipeline.StageInput) (pipeline.StageResult, error) {
	return pipeline.StageResult{Outcome: s.outcome, ItemsFailed: boolToInt(s.outcome == pipeline.OutcomeFailed), Err: s.err}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// perTargetStages returns a stages seam giving each target's single selected
// stage (--stages discover) the mapped outcome, keyed by canonical target.
func perTargetStages(outcomes map[string]pipeline.Outcome) func(pipeline.ScanConfig) []pipeline.Stage {
	return func(cfg pipeline.ScanConfig) []pipeline.Stage {
		outcome := outcomes[cfg.Target.Name]
		st := &fakeOutcomeStage{name: cfg.Stages[0], outcome: outcome}
		if outcome == pipeline.OutcomeFailed {
			st.err = errors.New("boom")
		}
		return []pipeline.Stage{st}
	}
}

// gateStage blocks inside Run until its release channel closes, with enter/
// exit hooks around the block — the deterministic concurrency probe for the
// --target-parallel semaphore bound.
type gateStage struct {
	name    pipeline.StageName
	onEnter func()
	onExit  func()
	release chan struct{}
}

func (s *gateStage) Name() pipeline.StageName { return s.name }

func (s *gateStage) Run(_ context.Context, _ pipeline.StageInput) (pipeline.StageResult, error) {
	if s.onEnter != nil {
		s.onEnter()
	}
	if s.release != nil {
		<-s.release
	}
	if s.onExit != nil {
		s.onExit()
	}
	return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
}

// TestParseScanArgsMultiTarget pins the multi-target grammar: multiple
// positional targets before options, --targets FILE entries (blanks and
// # comments skipped, whitespace/CRLF trimmed), positional+file combination
// with exact-duplicate collapsing, --target-parallel bounds (unset=0,
// 1..maxTargetParallel valid), the help token anywhere among leading
// tokens, and the usage errors (unreadable/empty file, out-of-range
// parallelism, --tui with several targets).
func TestParseScanArgsMultiTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	mixed := writeFile("mixed.txt", "# leading comment\n\n  a.example.com  \nb.example.com\r\n#trailer\nc.example.com\n")
	dupes := writeFile("dupes.txt", "a.example.com\nc.example.com\n")
	commentsOnly := writeFile("comments.txt", "# only comments\n\n   \n")

	cases := []struct {
		name        string
		args        []string
		wantTargets []string
		wantPar     int
		wantHelp    bool
		wantErrf    string
	}{
		{
			name:        "two positionals",
			args:        []string{"a.example.com", "b.example.com"},
			wantTargets: []string{"a.example.com", "b.example.com"},
		},
		{
			name:        "positionals then options",
			args:        []string{"a.example.com", "b.example.com", "--no-cache", "--output", "out/"},
			wantTargets: []string{"a.example.com", "b.example.com"},
		},
		{
			name:        "targets file with blanks, comments, CRLF, padding",
			args:        []string{"--targets", mixed},
			wantTargets: []string{"a.example.com", "b.example.com", "c.example.com"},
		},
		{
			name:        "positionals combine with file, exact dupes collapse, order kept",
			args:        []string{"b.example.com", "a.example.com", "--targets", dupes},
			wantTargets: []string{"b.example.com", "a.example.com", "c.example.com"},
		},
		{
			name:        "target-parallel max accepted",
			args:        []string{"a.example.com", "--target-parallel", "8"},
			wantTargets: []string{"a.example.com"},
			wantPar:     maxTargetParallel,
		},
		{
			name:     "help among leading tokens",
			args:     []string{"a.example.com", "help"},
			wantHelp: true,
		},
		{
			name:     "missing targets file",
			args:     []string{"--targets", filepath.Join(dir, "nope.txt")},
			wantErrf: "--targets",
		},
		{
			name:     "explicitly empty --targets path",
			args:     []string{"a.example.com", "--targets", ""},
			wantErrf: "empty file path",
		},
		{
			name:     "comments-only file yields no targets",
			args:     []string{"--targets", commentsOnly},
			wantErrf: "missing target argument",
		},
		{
			name:     "target-parallel zero rejected",
			args:     []string{"a.example.com", "--target-parallel", "0"},
			wantErrf: "--target-parallel",
		},
		{
			name:     "target-parallel negative rejected",
			args:     []string{"a.example.com", "--target-parallel", "-1"},
			wantErrf: "--target-parallel",
		},
		{
			name:     "target-parallel above max rejected",
			args:     []string{"a.example.com", "--target-parallel", "9"},
			wantErrf: "between 1 and 8",
		},
		{
			name:     "tui with multiple targets rejected",
			args:     []string{"a.example.com", "b.example.com", "--tui"},
			wantErrf: "--tui requires exactly one target",
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
			if tc.wantErrf != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrf) {
					t.Fatalf("want error containing %q, got %v", tc.wantErrf, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScanArgs(%v): %v", tc.args, err)
			}
			if !reflect.DeepEqual(opts.targets, tc.wantTargets) {
				t.Fatalf("targets = %v, want %v", opts.targets, tc.wantTargets)
			}
			if opts.targetParallel != tc.wantPar {
				t.Fatalf("targetParallel = %d, want %d", opts.targetParallel, tc.wantPar)
			}
		})
	}
}

// TestRunScanMultiTargetSequential pins the core fan-out contract: two
// positional targets run the existing pipeline once each, every seam
// invocation receives ITS OWN ScanConfig with the correct canonical Target
// and the per-target output subdirectory (<output>/<target>/), detailed
// summaries print in input order, and the combined summary lists both
// targets with the produced-data count.
func TestRunScanMultiTargetSequential(t *testing.T) {
	out := t.TempDir()
	capture := &configCapture{}
	var buf bytes.Buffer
	args := []string{
		"a.example.com", "B.EXAMPLE.COM.", // second form must normalize canonically
		"--stages", "discover", "--output", out,
	}
	if err := runScan(context.Background(), &buf, args, capture.seam, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	cfgs := capture.snapshot()
	if len(cfgs) != 2 {
		t.Fatalf("seam consulted %d times, want 2 (one pipeline per target)", len(cfgs))
	}
	if cfgs[0].Target.Name != "a.example.com" || cfgs[1].Target.Name != "b.example.com" {
		t.Fatalf("seam targets = %q, %q; want canonical a.example.com then b.example.com",
			cfgs[0].Target.Name, cfgs[1].Target.Name)
	}
	wantOutA := filepath.Join(out, "a.example.com")
	wantOutB := filepath.Join(out, "b.example.com")
	if cfgs[0].OutputDir != wantOutA || cfgs[1].OutputDir != wantOutB {
		t.Fatalf("seam output dirs = %q, %q; want per-target subdirectories %q, %q",
			cfgs[0].OutputDir, cfgs[1].OutputDir, wantOutA, wantOutB)
	}
	got := buf.String()
	headerA := "RavenRecon scan: a.example.com"
	headerB := "RavenRecon scan: b.example.com"
	ia, ib := strings.Index(got, headerA), strings.Index(got, headerB)
	if ia == -1 || ib == -1 {
		t.Fatalf("per-target summaries missing:\n%s", got)
	}
	if ia > ib {
		t.Fatalf("summaries must print in input order:\n%s", got)
	}
	for _, want := range []string{
		"\nRavenRecon scan summary: 2 targets\n",
		"Targets with data: 2/2 (completed/partial)\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("combined summary missing %q:\n%s", want, got)
		}
	}
}

// TestRunScanMultiTargetParallelBounded pins BOTH halves of the §10
// semaphore contract deterministically: --target-parallel 2 genuinely
// overlaps two pipelines (the gated stage observes two in flight before the
// gate opens), and the bound holds (the peak can never exceed two — an
// unbounded implementation would show four). No sleeps: the main test
// waits on arrivals and releases the gate, so the test is timing-free.
func TestRunScanMultiTargetParallelBounded(t *testing.T) {
	out := t.TempDir()
	gate := make(chan struct{})
	arrived := make(chan int, 8)
	var mu sync.Mutex
	inflight, peak := 0, 0
	enter := func() {
		mu.Lock()
		inflight++
		if inflight > peak {
			peak = inflight
		}
		cur := inflight
		mu.Unlock()
		select {
		case arrived <- cur:
		default:
		}
	}
	exit := func() {
		mu.Lock()
		inflight--
		mu.Unlock()
	}
	capture := &configCapture{}
	seam := func(cfg pipeline.ScanConfig) []pipeline.Stage {
		capture.mu.Lock()
		capture.cfgs = append(capture.cfgs, cfg)
		capture.mu.Unlock()
		return []pipeline.Stage{&gateStage{name: pipeline.StageDiscover, onEnter: enter, onExit: exit, release: gate}}
	}

	args := []string{
		"t1.example.com", "t2.example.com", "t3.example.com", "t4.example.com",
		"--stages", "discover", "--target-parallel", "2", "--output", out,
	}
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runScan(context.Background(), &buf, args, seam, nil) }()

	reached := false
	deadline := time.After(5 * time.Second)
wait:
	for !reached {
		select {
		case cur := <-arrived:
			if cur >= 2 {
				reached = true
			}
		case <-deadline:
			break wait
		}
	}
	close(gate) // unwind every worker even on the failure path — no leaks
	if err := <-done; err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if !reached {
		mu.Lock()
		p := peak
		mu.Unlock()
		t.Fatalf("two pipelines never overlapped (peak=%d); --target-parallel 2 must run two concurrently", p)
	}
	mu.Lock()
	p := peak
	mu.Unlock()
	if p != 2 {
		t.Fatalf("peak concurrent pipelines = %d, want exactly 2 (semaphore bound)", p)
	}
	if n := len(capture.snapshot()); n != 4 {
		t.Fatalf("seam consulted %d times, want 4 (one pipeline per target)", n)
	}
	got := buf.String()
	for _, name := range []string{"t1.example.com", "t2.example.com", "t3.example.com", "t4.example.com"} {
		if !strings.Contains(got, name+"\n") && !strings.Contains(got, "  "+name) {
			t.Fatalf("combined summary missing target %s:\n%s", name, got)
		}
	}
	if !strings.Contains(got, "Targets with data: 4/4") {
		t.Fatalf("combined summary missing the produced-data count:\n%s", got)
	}
}

// TestRunScanMultiTargetInterrupted pins the Ctrl-C/SIGTERM semantics of a
// multi-target run: with the context cancelled before anything starts, NO
// target's pipeline ever begins, both targets are recorded cancelled in the
// combined summary ("not started"), the summary still prints, and the
// returned error wraps context.Canceled with the interrupted framing.
func TestRunScanMultiTargetInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	capture := &configCapture{}
	var buf bytes.Buffer
	args := []string{"a.example.com", "b.example.com", "--stages", "discover"}
	err := runScan(ctx, &buf, args, capture.seam, nil)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want a context.Canceled-wrapped error, got %v", err)
	}
	if !strings.Contains(err.Error(), "run interrupted") {
		t.Fatalf("error = %v, want the interrupted-run framing", err)
	}
	if n := len(capture.snapshot()); n != 0 {
		t.Fatalf("seam consulted %d times; a cancelled queued target must never start", n)
	}
	got := buf.String()
	if !strings.Contains(got, "RavenRecon scan summary: 2 targets") {
		t.Fatalf("the combined summary must still print:\n%s", got)
	}
	if !strings.Contains(got, "cancelled") || !strings.Contains(got, "not started") {
		t.Fatalf("skipped targets must be recorded honestly as not-started cancellations:\n%s", got)
	}
	if strings.Contains(got, "RavenRecon scan: a.example.com") {
		t.Fatalf("no per-target summary may print for a target that never started:\n%s", got)
	}
}

// TestRunScanMultiTargetExitCodes pins the documented multi-target exit
// rule: exit 1 ONLY when every target ended failed or cancelled; ANY single
// successful target (completed or partial) yields exit 0, with the combined
// summary listing each honest per-target outcome.
func TestRunScanMultiTargetExitCodes(t *testing.T) {
	t.Run("all failed exits 1", func(t *testing.T) {
		var buf bytes.Buffer
		err := runScan(context.Background(), &buf,
			[]string{"a.example.com", "b.example.com", "--stages", "discover"},
			perTargetStages(map[string]pipeline.Outcome{
				"a.example.com": pipeline.OutcomeFailed,
				"b.example.com": pipeline.OutcomeFailed,
			}), nil)
		if err == nil || !strings.Contains(err.Error(), "all 2 targets") {
			t.Fatalf("want the all-targets-failed error, got %v", err)
		}
		if !strings.Contains(buf.String(), "Targets with data: 0/2") {
			t.Fatalf("combined summary must report 0/2:\n%s", buf.String())
		}
	})
	t.Run("any success exits 0", func(t *testing.T) {
		var buf bytes.Buffer
		err := runScan(context.Background(), &buf,
			[]string{"a.example.com", "b.example.com", "--stages", "discover"},
			perTargetStages(map[string]pipeline.Outcome{
				"a.example.com": pipeline.OutcomeFailed,
				"b.example.com": pipeline.OutcomePartial,
			}), nil)
		if err != nil {
			t.Fatalf("a single producing target must give exit 0, got %v", err)
		}
		got := buf.String()
		if !strings.Contains(got, "Targets with data: 1/2") {
			t.Fatalf("combined summary must report 1/2:\n%s", got)
		}
		if !strings.Contains(got, "\n  b.example.com") || !strings.Contains(got, "partial") || !strings.Contains(got, "failed") {
			t.Fatalf("combined summary must list each target's honest outcome:\n%s", got)
		}
	})
}

// TestRunScanMultiTargetInvalidTargetAbortsFirst pins the up-front
// validation contract: one invalid target among valid ones aborts the WHOLE
// invocation naming the offender, before any stage construction and before
// any other target runs.
func TestRunScanMultiTargetInvalidTargetAbortsFirst(t *testing.T) {
	capture := &configCapture{}
	var buf bytes.Buffer
	err := runScan(context.Background(), &buf,
		[]string{"a.example.com", "bad_target!", "--stages", "discover"},
		capture.seam, nil)
	if err == nil || !strings.Contains(err.Error(), `invalid target "bad_target!"`) {
		t.Fatalf("want an invalid-target error naming the offender, got %v", err)
	}
	if n := len(capture.snapshot()); n != 0 {
		t.Fatalf("seam consulted %d times; validation must abort before any stage", n)
	}
}

// TestRunScanMultiTargetsFileEndToEnd drives a full run through --targets:
// comment lines, blank lines, CRLF endings, and surrounding whitespace are
// all normalized away, both remaining targets run their own pipeline, and
// the combined summary reports both.
func TestRunScanMultiTargetsFileEndToEnd(t *testing.T) {
	out := t.TempDir()
	file := filepath.Join(out, "targets.txt")
	content := "# program scope\n\n  a.example.com  \r\nb.example.com\n# end\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	capture := &configCapture{}
	var buf bytes.Buffer
	args := []string{"--targets", file, "--stages", "discover", "--output", out}
	if err := runScan(context.Background(), &buf, args, capture.seam, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	cfgs := capture.snapshot()
	if len(cfgs) != 2 || cfgs[0].Target.Name != "a.example.com" || cfgs[1].Target.Name != "b.example.com" {
		t.Fatalf("file targets resolved wrong: %+v", cfgs)
	}
	if !strings.Contains(buf.String(), "Targets with data: 2/2") {
		t.Fatalf("combined summary missing:\n%s", buf.String())
	}
}

// TestRunScanDryRunMultiTarget pins the multi-target --dry-run form: one
// effective-configuration block PER target (showing that target's output
// subdirectory), blank-line separated, exiting 0 with the stages seam never
// consulted.
func TestRunScanDryRunMultiTarget(t *testing.T) {
	out := t.TempDir()
	calls := 0
	seam := func(pipeline.ScanConfig) []pipeline.Stage {
		calls++
		return nil
	}
	var buf bytes.Buffer
	args := []string{"a.example.com", "b.example.com", "--dry-run", "--output", out}
	if err := runScan(context.Background(), &buf, args, seam, nil); err != nil {
		t.Fatalf("dry run must exit cleanly, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("stages seam invoked %d time(s) during dry run, want 0", calls)
	}
	got := buf.String()
	for _, want := range []string{
		"RavenRecon scan (dry run): a.example.com",
		"RavenRecon scan (dry run): b.example.com",
		"Output: " + filepath.Join(out, "a.example.com"),
		"Output: " + filepath.Join(out, "b.example.com"),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("multi dry-run output missing %q:\n%s", want, got)
		}
	}
}

// TestRunScanSingleTargetStaysLegacy is the backward-compatibility pin: a
// SINGLE target behaves byte-identically to the historical command even
// with --target-parallel given — exactly one detailed summary, NO combined
// summary block, and the --output value used VERBATIM (never turned into a
// per-target subdirectory).
func TestRunScanSingleTargetStaysLegacy(t *testing.T) {
	out := t.TempDir()
	capture := &configCapture{}
	var buf bytes.Buffer
	args := []string{"example.com", "--target-parallel", "4", "--stages", "discover", "--output", out}
	if err := runScan(context.Background(), &buf, args, capture.seam, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if n := len(capture.snapshot()); n != 1 {
		t.Fatalf("seam consulted %d times, want exactly 1", n)
	}
	got := buf.String()
	if c := strings.Count(got, "RavenRecon scan: example.com"); c != 1 {
		t.Fatalf("single-target run printed %d summaries, want exactly 1:\n%s", c, got)
	}
	if strings.Contains(got, "RavenRecon scan summary:") {
		t.Fatalf("single-target runs must not grow a combined summary block:\n%s", got)
	}
	if !strings.Contains(got, "Output: "+out+"\n") {
		t.Fatalf("single-target output dir must stay the flag value verbatim (no subdirectory):\n%s", got)
	}
}
