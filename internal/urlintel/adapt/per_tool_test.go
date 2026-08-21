package adapt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// delayRunner simulates a tool that takes delay to produce out. It respects
// ctx deadline: if ctx fires before delay, it returns a per-tool timeout error
// with the partial capture (the same out truncated to whatever was available
// before timeout — for hermetic tests we return the full out on timeout to
// verify ingest still processes it). Detection probes (version flags) return
// immediately with a version string and never delay.
type delayRunner struct {
	delay time.Duration
	out   []byte
	code  int
}

func (r *delayRunner) Run(ctx context.Context, cmd discovery.Cmd, _ discovery.Limits) (discovery.RunResult, error) {
	// Detection probe: args contain version flag
	for _, a := range cmd.Args {
		if a == "-version" || a == "--version" {
			return discovery.RunResult{Stdout: []byte("gau 2.1.1\n")}, nil
		}
	}
	select {
	case <-time.After(r.delay):
		return discovery.RunResult{Stdout: r.out, ExitCode: r.code}, nil
	case <-ctx.Done():
		// Real ExecRunner would return whatever was captured before kill plus
		// the context error. For hermetic testing we return the full out as
		// the captured prefix to verify ingest still processes lines.
		return discovery.RunResult{Stdout: r.out}, ctx.Err()
	}
}

func TestPerToolTimeoutHelper(t *testing.T) {
	cfg := DefaultConfig()
	if got := cfg.ToolTimeout("gau"); got != DefaultToolTimeout {
		t.Fatalf("default ToolTimeout = %s, want %s", got, DefaultToolTimeout)
	}
	cfg.ToolTimeoutDefault = 90 * time.Second
	if got := cfg.ToolTimeout("gau"); got != 90*time.Second {
		t.Fatalf("ToolTimeout with default = %s, want 90s", got)
	}
	cfg.PerToolTimeout = map[string]time.Duration{"gau": 100 * time.Millisecond}
	if got := cfg.ToolTimeout("gau"); got != 100*time.Millisecond {
		t.Fatalf("per-tool ToolTimeout = %s, want 100ms", got)
	}
	if got := cfg.ToolTimeout("waybackurls"); got != 90*time.Second {
		t.Fatalf("fallback ToolTimeout = %s, want 90s", got)
	}
	// Zero per-tool entry falls back
	cfg.PerToolTimeout["gau"] = 0
	if got := cfg.ToolTimeout("gau"); got != 90*time.Second {
		t.Fatalf("zero per-tool should fallback, got %s", got)
	}
}

func TestPerToolTimeoutValidation(t *testing.T) {
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.ToolTimeoutDefault = -1 * time.Second
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected validation error for negative ToolTimeoutDefault")
	}
	cfg = testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.PerToolTimeout = map[string]time.Duration{"gau": -5 * time.Second}
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected validation error for negative PerToolTimeout")
	}
}

func TestPerToolTimeoutPartial(t *testing.T) {
	// Gau with 80ms per-tool timeout, runner delay 300ms => per-tool timeout
	// triggers, result partial, ingest still processes lines.
	urls := []byte("https://example.com/a\nhttps://example.com/b\n")
	runner := &delayRunner{delay: 300 * time.Millisecond, out: urls}
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.PerToolTimeout = map[string]time.Duration{"gau": 80 * time.Millisecond}
	cfg.Timeout = 5 * time.Second // outer pool timeout generous

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Status != ResultPartial {
		t.Fatalf("result status = %s, want partial (per-tool timeout)", r.Status)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "per-tool timeout") {
		t.Fatalf("result err = %v, want per-tool timeout diagnostic", r.Err)
	}
	// Ingest still processed the captured lines despite timeout.
	if r.Lines != 2 {
		t.Fatalf("lines = %d, want 2 (ingest processed collected lines)", r.Lines)
	}
	if len(rep.Report.Entries) != 2 {
		t.Fatalf("report entries = %d, want 2", len(rep.Report.Entries))
	}
}

func TestPerToolTimeoutOnlyRunner(t *testing.T) {
	// Verify per-tool timeout bounds runner only, not ingest. Runner times out
	// but ingest of the partial capture still completes within outer deadline.
	urls := []byte("https://example.com/a\n")
	runner := &delayRunner{delay: 200 * time.Millisecond, out: urls}
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.PerToolTimeout = map[string]time.Duration{"gau": 50 * time.Millisecond}
	cfg.Timeout = 0 // no outer deadline, ingest must still complete
	cfg.IngestWorkers = 2

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Results[0].Status != ResultPartial {
		t.Fatalf("status = %s, want partial", rep.Results[0].Status)
	}
	if rep.Results[0].Lines != 1 {
		t.Fatalf("lines = %d, want 1", rep.Results[0].Lines)
	}
}

func TestPerToolTimeoutDoesNotOverrideOuterCancellation(t *testing.T) {
	// Outer context cancellation still reports cancelled, not partial.
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{block: true})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.PerToolTimeout = map[string]time.Duration{"gau": 5 * time.Second}
	cfg.Timeout = 0

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var rep RunReport
	go func() {
		rep, _ = Run(ctx, cfg)
		close(done)
	}()
	waitUntil(t, "tool execution starts", testTimeout, func() bool { return runner.callCount() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after cancellation")
	}
	if rep.Results[0].Status != ResultCancelled {
		t.Fatalf("status = %s, want cancelled (outer cancellation dominates)", rep.Results[0].Status)
	}
}

func TestPerToolTimeoutDefaultFallback(t *testing.T) {
	// When PerToolTimeout not set for tool, ToolTimeoutDefault is used.
	urls := []byte("https://example.com/a\n")
	runner := &delayRunner{delay: 200 * time.Millisecond, out: urls}
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.ToolTimeoutDefault = 60 * time.Millisecond
	cfg.Timeout = 5 * time.Second

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Results[0].Status != ResultPartial {
		t.Fatalf("status = %s, want partial via default", rep.Results[0].Status)
	}
}
