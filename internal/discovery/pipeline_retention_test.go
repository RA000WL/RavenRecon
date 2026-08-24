package discovery

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestRunRetainsPartialHostsOnCancellation pins NEW-94's root-cause fix: a
// tool killed mid-stream keeps its already-captured output. The Runner
// contract guarantees a final quiescent capture on every path, including a
// cancellation kill (ExecRunner returns the bytes streamed before the kill
// alongside the joined context error); the adapter must parse that capture
// post-mortem instead of discarding it, so the report carries the enumerated
// hosts under the honest cancelled status.
//
// The fake mirrors ExecRunner.Run's cancellation path exactly: block until
// the context fires, return the partial capture AND the context error.
// Before the fix this test failed with an empty host list (the capture was
// discarded on the error path); it is the regression guard for that loss.
func TestRunRetainsPartialHostsOnCancellation(t *testing.T) {
	script := fullScript()
	// Build the blocking entry with access to nothing but the ctx: the
	// script map value signature has no ctx, so poll ctx.Err via closure.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobStarted := make(chan struct{})
	var once sync.Once
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		once.Do(func() { close(jobStarted) })
		<-ctx.Done()
		return RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, ctx.Err()
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1 // deterministic: only the subfinder job is running
	cfg.Timeout = 0     // the pipeline adapter's default bounds (no per-job deadline)

	var rep Report
	var runErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, runErr = Run(ctx, mustDomain(t, "example.com"), cfg)
	}()
	<-jobStarted
	cancel()
	<-done

	if runErr != nil {
		t.Fatalf("Run error: %v", runErr)
	}
	got := rep.Results[0]
	if got.Status != OutCancelled {
		t.Fatalf("subfinder status = %s, want cancelled (outcome stays honest)", got.Status)
	}
	if !errors.Is(got.Err, context.Canceled) {
		t.Fatalf("subfinder Err = %v, want context.Canceled", got.Err)
	}
	want := []string{"api.example.com", "www.example.com"}
	if names(got.Hosts) == nil || !reflect.DeepEqual(names(got.Hosts), want) {
		t.Fatalf("retained subfinder hosts = %v, want %v (partial capture must survive the kill)", names(got.Hosts), want)
	}
	// The merged report carries the retained set too — this is what the
	// pipeline adapter turns into Additions downstream.
	all := names(rep.All())
	for _, w := range want {
		found := false
		for _, n := range all {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Report.All() = %v, missing retained host %s", all, w)
		}
	}
}

// TestShutdownDrainBudget pins the NEW-94 drain-budget derivation: the
// budget must cover every submitted job's worst-case clean completion (all
// concurrency waves plus rate-limited start stagger) before forcing, and the
// no-deadline configuration gets a documented bounded completion window
// instead of a flat constant smaller than realistic enumerations.
func TestShutdownDrainBudget(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		submitted int
		want      time.Duration
	}{
		{
			name:      "no deadline: bounded completion window",
			cfg:       Config{Timeout: 0},
			submitted: 4,
			want:      shutdownNoDeadlineBudget,
		},
		{
			name:      "negative timeout treated as disabled",
			cfg:       Config{Timeout: -time.Second},
			submitted: 2,
			want:      shutdownNoDeadlineBudget,
		},
		{
			name:      "single wave",
			cfg:       Config{Timeout: 10 * time.Second, Concurrency: 4},
			submitted: 4,
			want:      10*time.Second + shutdownGrace,
		},
		{
			name:      "two waves cover queued jobs",
			cfg:       Config{Timeout: 30 * time.Second, Concurrency: 2},
			submitted: 4,
			want:      60*time.Second + shutdownGrace,
		},
		{
			name:      "rate-limited start stagger added",
			cfg:       Config{Timeout: 30 * time.Second, Concurrency: 4, Rate: 0.5, Burst: 1},
			submitted: 3,
			want:      30*time.Second + 4*time.Second + shutdownGrace,
		},
		{
			name:      "burst absorbs starts within capacity",
			cfg:       Config{Timeout: 30 * time.Second, Concurrency: 4, Rate: 2, Burst: 4},
			submitted: 4,
			want:      30*time.Second + shutdownGrace,
		},
		{
			name:      "zero submitted still leaves the grace period",
			cfg:       Config{Timeout: 10 * time.Second, Concurrency: 2},
			submitted: 0,
			want:      shutdownGrace,
		},
		{
			name:      "defensive: concurrency below one clamped",
			cfg:       Config{Timeout: 10 * time.Second, Concurrency: 0},
			submitted: 2,
			want:      20*time.Second + shutdownGrace,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shutdownDrainBudget(tc.cfg, tc.submitted); got != tc.want {
				t.Fatalf("shutdownDrainBudget(%+v, %d) = %s, want %s", tc.cfg, tc.submitted, got, tc.want)
			}
		})
	}
}

// TestRunQualityGateAppliesToRetainedHosts verifies the data-quality gate
// still protects an interrupted run: a source killed mid-stream whose partial
// capture was parsed post-mortem is capped by MaxPerSource exactly like a
// completed source (burst/over_cap protection), and the issue is recorded on
// the cancelled slot (NEW-94 honesty rule: retained ≠ ungated).
func TestRunQualityGateAppliesToRetainedHosts(t *testing.T) {
	setChaosKey(t)
	script := fullScript()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobStarted := make(chan struct{})
	var once sync.Once
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		once.Do(func() { close(jobStarted) })
		<-ctx.Done()
		// A burst of eight hosts captured before the kill.
		stdout := "a1.example.com\na2.example.com\na3.example.com\na4.example.com\n" +
			"a5.example.com\na6.example.com\na7.example.com\na8.example.com\n"
		return RunResult{Stdout: []byte(stdout)}, ctx.Err()
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1
	cfg.Timeout = 0
	cfg.Quality = QualityConfig{MaxPerSource: 5} // burst fixture: cap above the retained count

	var rep Report
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, err = Run(ctx, mustDomain(t, "example.com"), cfg)
	}()
	<-jobStarted
	cancel()
	<-done
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	got := rep.Results[0]
	if got.Status != OutCancelled {
		t.Fatalf("subfinder status = %s, want cancelled", got.Status)
	}
	if len(got.Hosts) != 5 {
		t.Fatalf("retained host count = %d, want 5 (the gate must cap the retained set)", len(got.Hosts))
	}
	if len(got.QualityIssues) != 1 || got.QualityIssues[0].Signal != SignalOverCap || got.QualityIssues[0].Count != 8 {
		t.Fatalf("quality issues = %+v, want one over_cap issue with count 8", got.QualityIssues)
	}
	if len(rep.QualityIssues) != 1 || rep.QualityIssues[0].Source != "subfinder" {
		t.Fatalf("report issues = %+v, want the aggregated subfinder over_cap issue", rep.QualityIssues)
	}
}
