package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// fixedTime is the deterministic timestamp used in CLI rendering tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func TestParseDiscoverArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantOpts discoverOptions
		wantErr  bool
		wantHelp bool
		wantErrf string // substring of the error, when wantErr
	}{
		{
			name:     "domain only",
			args:     []string{"example.com"},
			wantOpts: discoverOptions{domain: "example.com"},
		},
		{
			name: "options after domain",
			args: []string{"example.com", "--sources", " subfinder , amass ", "--no-cache"},
			wantOpts: discoverOptions{
				domain:  "example.com",
				sources: []string{"subfinder", "amass"},
				noCache: true,
			},
		},
		{
			name:     "no-cache only",
			args:     []string{"example.com", "--no-cache"},
			wantOpts: discoverOptions{domain: "example.com", noCache: true},
		},
		{
			name:     "missing domain",
			args:     []string{},
			wantErr:  true,
			wantErrf: "domain",
		},
		{
			name:     "help first",
			args:     []string{"-h"},
			wantHelp: true,
		},
		{
			name:     "help word first",
			args:     []string{"help"},
			wantHelp: true,
		},
		{
			name:     "help after domain",
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
			name:     "empty source list",
			args:     []string{"example.com", "--sources", ","},
			wantErr:  true,
			wantErrf: "empty source list",
		},
		{
			name:     "explicitly empty sources flag",
			args:     []string{"example.com", "--sources", ""},
			wantErr:  true,
			wantErrf: "empty source list",
		},
		{
			name:     "stray argument after flags",
			args:     []string{"example.com", "--no-cache", "extra"},
			wantErr:  true,
			wantErrf: "unexpected argument",
		},
		{
			name:     "extra positional domain",
			args:     []string{"example.com", "other.org"},
			wantErr:  true,
			wantErrf: "unexpected argument",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseDiscoverArgs(tc.args)
			if tc.wantHelp {
				if !errors.Is(err, errDiscoverHelp) {
					t.Fatalf("want errDiscoverHelp, got %v", err)
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
				t.Fatalf("parseDiscoverArgs(%v): %v", tc.args, err)
			}
			if opts.domain != tc.wantOpts.domain || opts.noCache != tc.wantOpts.noCache {
				t.Fatalf("opts = %+v, want %+v", opts, tc.wantOpts)
			}
			if len(opts.sources) != len(tc.wantOpts.sources) {
				t.Fatalf("sources = %v, want %v", opts.sources, tc.wantOpts.sources)
			}
			for i := range opts.sources {
				if opts.sources[i] != tc.wantOpts.sources[i] {
					t.Fatalf("sources = %v, want %v", opts.sources, tc.wantOpts.sources)
				}
			}
		})
	}
}

func TestDiscoverConfigDefaults(t *testing.T) {
	cfg := config.Default()
	dc, err := discoverConfig(cfg, discoverOptions{domain: "example.com"})
	if err != nil {
		t.Fatalf("discoverConfig: %v", err)
	}
	if dc.Concurrency != cfg.Concurrency {
		t.Fatalf("concurrency = %d, want global %d", dc.Concurrency, cfg.Concurrency)
	}
	if dc.Timeout != cfg.Timeout {
		t.Fatalf("timeout = %s, want global %s", dc.Timeout, cfg.Timeout)
	}
	if dc.Rate != cfg.Rate {
		t.Fatalf("rate = %v, want global %v", dc.Rate, cfg.Rate)
	}
	if dc.Sources != nil {
		t.Fatalf("sources = %v, want nil (all built-in)", dc.Sources)
	}
	if dc.Bin != nil {
		t.Fatalf("bin = %v, want nil (PATH lookup)", dc.Bin)
	}
	if dc.Cache != nil {
		t.Fatal("cache must stay disabled by default")
	}
}

func TestDiscoverConfigDiscoveryOverrides(t *testing.T) {
	cfg := config.Default()
	cfg.Discovery.Timeout = 2 * time.Minute
	cfg.Discovery.DetectTimeout = 3 * time.Second
	cfg.Discovery.MaxOutputSize = 4096
	cfg.Discovery.Bin = map[string]string{"subfinder": "/opt/subfinder"}
	dc, err := discoverConfig(cfg, discoverOptions{domain: "example.com", sources: []string{"subfinder"}})
	if err != nil {
		t.Fatalf("discoverConfig: %v", err)
	}
	if dc.Timeout != 2*time.Minute {
		t.Fatalf("timeout = %s, want override 2m", dc.Timeout)
	}
	if dc.DetectTimeout != 3*time.Second {
		t.Fatalf("detect timeout = %s, want override 3s", dc.DetectTimeout)
	}
	if dc.MaxOutputSize != 4096 {
		t.Fatalf("max output = %d, want 4096", dc.MaxOutputSize)
	}
	if dc.Bin["subfinder"] != "/opt/subfinder" {
		t.Fatalf("bin = %v, want subfinder override", dc.Bin)
	}
	if len(dc.Sources) != 1 || dc.Sources[0] != "subfinder" {
		t.Fatalf("sources = %v, want [subfinder]", dc.Sources)
	}
}

func TestDiscoverConfigCacheWiring(t *testing.T) {
	cfg := config.Default()
	dir := t.TempDir()
	cfg.Cache.Enabled = true
	cfg.Cache.Dir = dir
	cfg.Cache.TTL = time.Hour

	dc, err := discoverConfig(cfg, discoverOptions{domain: "example.com"})
	if err != nil {
		t.Fatalf("discoverConfig: %v", err)
	}
	if dc.Cache == nil {
		t.Fatal("an enabled cache must be wired into the run")
	}
	// --no-cache forces the cache off even when configuration enables it.
	dc2, err := discoverConfig(cfg, discoverOptions{domain: "example.com", noCache: true})
	if err != nil {
		t.Fatalf("discoverConfig: %v", err)
	}
	if dc2.Cache != nil {
		t.Fatal("--no-cache must disable the cache")
	}
}

func TestPrintDiscoverReport(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	h1, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	h2, err := asset.NewHost("www.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	rep := discovery.Report{
		Target: target,
		Results: []discovery.SourceResult{
			{
				Source: "subfinder",
				Detection: discovery.Detection{
					Source: "subfinder", Status: discovery.StatusOK,
					Reason: "executable /usr/bin/subfinder; version v2.6.3",
				},
				Status:  discovery.OutCompleted,
				Version: "v2.6.3",
				Hosts:   []asset.Host{h1, h2},
			},
			{
				Source: "amass",
				Detection: discovery.Detection{
					Source: "amass", Status: discovery.StatusMissing,
					Reason: `executable "amass" not found`,
				},
				Status: discovery.OutSkipped,
			},
		},
	}
	var buf bytes.Buffer
	if err := printDiscoverReport(&buf, rep, false); err != nil {
		t.Fatalf("printDiscoverReport: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"RavenRecon discover: example.com",
		"cache: off",
		"subfinder [OK]",
		"detection: executable /usr/bin/subfinder; version v2.6.3",
		"outcome: completed — 2 hosts",
		"api.example.com",
		"(subfinder @ 2026-08-13T12:00:00Z)",
		"amass [MISSING]",
		"outcome: skipped",
		"Merged across sources: 2 unique hosts",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report output missing %q:\n%s", want, out)
		}
	}
}

// TestPrintDiscoverReportCachePutWarning verifies a completed source whose
// cache write failed still surfaces the error as a warning line: the user
// must never believe results were cached when the cache rejected them.
func TestPrintDiscoverReportCachePutWarning(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	rep := discovery.Report{
		Target: target,
		Results: []discovery.SourceResult{
			{
				Source: "subfinder",
				Detection: discovery.Detection{
					Source: "subfinder", Status: discovery.StatusOK,
					Reason: "executable /usr/bin/subfinder; version v2.6.3",
				},
				Status:  discovery.OutCompleted,
				Version: "v2.6.3",
				Err:     errors.New("discovery: subfinder: cache put: disk full"),
			},
		},
	}
	var buf bytes.Buffer
	if err := printDiscoverReport(&buf, rep, true); err != nil {
		t.Fatalf("printDiscoverReport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "outcome: completed") {
		t.Fatalf("missing completed outcome line:\n%s", out)
	}
	if !strings.Contains(out, "warning:") || !strings.Contains(out, "cache put: disk full") {
		t.Fatalf("cache put failure must render as a warning:\n%s", out)
	}
}

// TestPrintDiscoverReportCancelledShowsPartialHosts verifies cancelled
// outcomes still render whatever partial hosts were observed before
// cancellation.
func TestPrintDiscoverReportCancelledShowsPartialHosts(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	h1, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	rep := discovery.Report{
		Target: target,
		Results: []discovery.SourceResult{
			{
				Source: "subfinder",
				Detection: discovery.Detection{
					Source: "subfinder", Status: discovery.StatusOK,
					Reason: "executable /usr/bin/subfinder; version v2.6.3",
				},
				Status: discovery.OutCancelled,
				Err:    context.Canceled,
				Hosts:  []asset.Host{h1},
			},
		},
	}
	var buf bytes.Buffer
	if err := printDiscoverReport(&buf, rep, false); err != nil {
		t.Fatalf("printDiscoverReport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "outcome: cancelled") {
		t.Fatalf("missing cancelled outcome line:\n%s", out)
	}
	if !strings.Contains(out, "warning: context canceled") {
		t.Fatalf("cancelled cause must render as a warning:\n%s", out)
	}
	if !strings.Contains(out, "api.example.com") {
		t.Fatalf("partial hosts of a cancelled outcome must render:\n%s", out)
	}
}

func TestPrintDoctorDiscovery(t *testing.T) {
	dets := []discovery.Detection{
		{Source: "subfinder", Status: discovery.StatusOK, Reason: "executable /usr/bin/subfinder; version v2.6.3"},
		{Source: "assetfinder", Status: discovery.StatusWarn, Reason: "executable /usr/bin/assetfinder exists; -h produced no output, capability not verified"},
		{Source: "amass", Status: discovery.StatusMissing, Reason: `executable "amass" not found`},
	}
	var buf bytes.Buffer
	if err := printDoctorDiscovery(&buf, dets); err != nil {
		t.Fatalf("printDoctorDiscovery: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"subfinder:   [OK]",
		"assetfinder: [WARN]",
		"amass:       [MISSING]",
		"executable /usr/bin/subfinder; version v2.6.3",
		`executable "amass" not found`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}

// The Run-level tests below exercise only argument validation: they return
// errors before any tool detection or execution happens, so they never
// require installed binaries or network access.

func TestRunUnknownCommand(t *testing.T) {
	err := Run(context.Background(), []string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("want unknown-command error, got %v", err)
	}
}

func TestRunDiscoverMissingDomain(t *testing.T) {
	err := Run(context.Background(), []string{"discover"})
	if err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("want missing-domain error, got %v", err)
	}
}

func TestRunDiscoverInvalidTarget(t *testing.T) {
	err := Run(context.Background(), []string{"discover", "bad..name"})
	if err == nil || !strings.Contains(err.Error(), "invalid target") {
		t.Fatalf("want invalid-target error, got %v", err)
	}
}

func TestRunDiscoverUnknownSource(t *testing.T) {
	err := Run(context.Background(), []string{"discover", "example.com", "--sources", "nmap"})
	if err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("want unknown-source error, got %v", err)
	}
}

func TestRunDiscoverUnknownFlag(t *testing.T) {
	err := Run(context.Background(), []string{"discover", "example.com", "--bogus"})
	if err == nil || !strings.Contains(err.Error(), "flag") {
		t.Fatalf("want flag error, got %v", err)
	}
}

func TestRunDiscoverHelp(t *testing.T) {
	if err := Run(context.Background(), []string{"discover", "-h"}); err != nil {
		t.Fatalf("discover -h must print usage and succeed, got %v", err)
	}
}

// TestRunDiscoverCancelledContext simulates a signal (Ctrl-C/SIGTERM)
// delivering cancellation into the context that main wires via
// signal.NotifyContext: Run must return promptly with a non-nil error that
// wraps context.Canceled — main's print-and-exit-1 path — and never hang.
// Hermetic: with a cancelled context, discovery.Run fails before any tool
// detection or execution, so no real binaries are involved.
func TestRunDiscoverCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := Run(ctx, []string{"discover", "example.com"})
	if err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a context.Canceled-wrapped error", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled run took %s to return; want prompt cancellation", elapsed)
	}
}

// TestRunDiscoverCancelledMidRun verifies the F3 behavior decision: a run
// context cancelled MID-RUN (Ctrl-C/SIGTERM after detection and execution
// have started) must not exit cleanly. The partial report is still printed
// (partial results are never lost) and the returned context.Canceled-wrapped
// error makes main print it and exit 1. Hermetic: the subfinder tool is a
// PATH shim script created in t.TempDir (real subprocesses, no installed
// tools, no network), and the per-job deadline is not involved — the run
// context itself is cancelled. Skipped on Windows (POSIX shell shims).
func TestRunDiscoverCancelledMidRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell shims are not available on windows")
	}
	dir := t.TempDir()
	shim := filepath.Join(dir, "subfinder")
	body := "#!/bin/sh\n" +
		`if [ "$1" = "-version" ]; then echo "Current Version: v2.6.3"; exit 0; fi` + "\n" +
		"sleep 300\n"
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	var buf bytes.Buffer
	start := time.Now()
	err := runDiscover(ctx, &buf, []string{"example.com", "--sources", "subfinder"})
	if err == nil {
		t.Fatal("a run interrupted mid-way must return an error, not exit cleanly")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want a context.Canceled-wrapped error", err)
	}
	if elapsed := time.Since(start); elapsed >= 15*time.Second {
		t.Fatalf("interrupted run took %s to return; want prompt bounded completion", elapsed)
	}
	out := buf.String()
	if !strings.Contains(out, "RavenRecon discover: example.com") {
		t.Fatalf("the partial report must still be printed:\n%s", out)
	}
	if !strings.Contains(out, "outcome: cancelled") {
		t.Fatalf("the cancelled outcome must be reported:\n%s", out)
	}
}
