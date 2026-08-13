package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func fullScript() map[string]func(Cmd) (RunResult, error) {
	s := standardScript()
	s["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
	}
	s["assetfinder example.com"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("www.example.com\nblog.example.com\n")}, nil
	}
	s["amass enum -passive -d example.com"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("mail.example.com\napi.example.com\n")}, nil
	}
	return s
}

func mustRun(t *testing.T, target asset.Domain, cfg Config) Report {
	t.Helper()
	rep, err := Run(context.Background(), target, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// TestRunAllSources exercises the full pipeline: detection, pool jobs per
// source, cross-source deduplication by identity, and merge semantics.
func TestRunAllSources(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	if len(rep.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(rep.Results))
	}
	order := []string{"subfinder", "assetfinder", "amass"}
	for i, want := range order {
		if rep.Results[i].Source != want {
			t.Fatalf("results[%d].Source = %q, want %q", i, rep.Results[i].Source, want)
		}
		if rep.Results[i].Detection.Status != StatusOK {
			t.Fatalf("%s detection = %s (%s), want ok", want, rep.Results[i].Detection.Status, rep.Results[i].Detection.Reason)
		}
		if rep.Results[i].Status != OutCompleted {
			t.Fatalf("%s status = %s, want completed", want, rep.Results[i].Status)
		}
	}
	// Per-source host counts: subfinder 2, assetfinder 2, amass 2.
	if got := len(rep.Results[0].Hosts); got != 2 {
		t.Fatalf("subfinder hosts = %d, want 2", got)
	}
	if got := len(rep.Results[1].Hosts); got != 2 {
		t.Fatalf("assetfinder hosts = %d, want 2", got)
	}
	if got := len(rep.Results[2].Hosts); got != 2 {
		t.Fatalf("amass hosts = %d, want 2", got)
	}
	if r.discoverCallCount() != 3 {
		t.Fatalf("discover calls = %d, want 3", r.discoverCallCount())
	}
}

// TestRunMergesByPhase2Identity verifies cross-source dedup: the same host
// found by several tools resolves to one identity with merged provenance.
func TestRunMergesByPhase2Identity(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	all := rep.All()
	want := []string{"api.example.com", "blog.example.com", "mail.example.com", "www.example.com"}
	if len(all) != len(want) {
		t.Fatalf("merged hosts = %v, want %v", names(all), want)
	}
	for i := range all {
		if all[i].Name != want[i] {
			t.Fatalf("merged[%d] = %q, want %q", i, all[i].Name, want[i])
		}
	}
	// www.example.com was discovered by subfinder and assetfinder with the
	// same clock; MergeHosts keeps the earliest (tie resolves to the first
	// encountered source), preserving provenance.
	for _, h := range all {
		if h.Name == "www.example.com" {
			if h.Prov.Source != "subfinder" {
				t.Fatalf("merged www provenance source = %q, want subfinder", h.Prov.Source)
			}
			if h.Prov.DiscoveredAt != fixedTime {
				t.Fatalf("merged www provenance time = %v, want %v", h.Prov.DiscoveredAt, fixedTime)
			}
		}
	}
}

// TestRunProvenanceMergeEarliestWins advances the clock between sources so
// the earliest observation's provenance survives the merge. Concurrency 1
// makes the source order deterministic: subfinder observes first (at
// fixedTime), then assetfinder advances the clock and observes the same host
// one minute later.
func TestRunProvenanceMergeEarliestWins(t *testing.T) {
	clk := newFakeClock(fixedTime)
	script := fullScript()
	script["assetfinder example.com"] = func(Cmd) (RunResult, error) {
		clk.advance(time.Minute) // assetfinder observes one minute later
		return RunResult{Stdout: []byte("www.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Now = clk.now
	cfg.Concurrency = 1 // deterministic source order
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	// The fixture's full merged set: subfinder (api, www) at fixedTime, amass
	// (mail, api) one minute later, assetfinder (www) one minute later.
	all := rep.All()
	want := []string{"api.example.com", "mail.example.com", "www.example.com"}
	if len(all) != len(want) {
		t.Fatalf("merged = %v, want %v", names(all), want)
	}
	for i := range all {
		if all[i].Name != want[i] {
			t.Fatalf("merged[%d] = %q, want %q", i, all[i].Name, want[i])
		}
	}
	// assetfinder's own observation keeps its later timestamp.
	for _, res := range rep.Results {
		if res.Source == "assetfinder" && len(res.Hosts) == 1 {
			if res.Hosts[0].Prov.DiscoveredAt != fixedTime.Add(time.Minute) {
				t.Fatalf("assetfinder provenance = %v, want %v", res.Hosts[0].Prov.DiscoveredAt, fixedTime.Add(time.Minute))
			}
		}
	}
	// The merged identity keeps the earliest timestamp (subfinder's).
	for _, h := range all {
		if h.Name != "www.example.com" {
			continue
		}
		if h.Prov.DiscoveredAt != fixedTime {
			t.Fatalf("merged provenance = %v, want %v", h.Prov.DiscoveredAt, fixedTime)
		}
		if h.Prov.Source != "subfinder" {
			t.Fatalf("merged provenance source = %q, want subfinder", h.Prov.Source)
		}
	}
}

// TestRunMissingSourceSkipped verifies the documented handling of MISSING
// tools: skip with a clear warning, never a crash, never a failed run.
func TestRunMissingSourceSkipped(t *testing.T) {
	l := newFakeLookup()
	l.errs["amass"] = errors.New("not found in PATH")
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, l)
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	if len(rep.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(rep.Results))
	}
	if rep.Results[2].Source != "amass" || rep.Results[2].Status != OutSkipped {
		t.Fatalf("amass result = %+v, want skipped", rep.Results[2])
	}
	if rep.Results[2].Detection.Status != StatusMissing {
		t.Fatalf("amass detection = %s, want missing", rep.Results[2].Detection.Status)
	}
	if rep.Results[2].Detection.Reason == "" {
		t.Fatal("expected a skip reason")
	}
	if r.discoverCallCount() != 2 {
		t.Fatalf("discover calls = %d, want 2 (amass must not run)", r.discoverCallCount())
	}
	for i := 0; i < 2; i++ {
		if rep.Results[i].Status != OutCompleted {
			t.Fatalf("results[%d] status = %s, want completed", i, rep.Results[i].Status)
		}
	}
}

func TestRunAllSourcesMissing(t *testing.T) {
	l := newFakeLookup()
	for _, n := range builtInNames() {
		l.errs[n] = errors.New("not found in PATH")
	}
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, l)
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	if len(rep.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(rep.Results))
	}
	for _, res := range rep.Results {
		if res.Status != OutSkipped {
			t.Fatalf("%s status = %s, want skipped", res.Source, res.Status)
		}
	}
	if got := r.discoverCallCount(); got != 0 {
		t.Fatalf("discover calls = %d, want 0", got)
	}
	if len(rep.All()) != 0 {
		t.Fatalf("merged hosts = %v, want none", names(rep.All()))
	}
}

func TestRunSourceSelection(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Sources = []string{"subfinder", "amass"}
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	if rep.Results[0].Source != "subfinder" || rep.Results[1].Source != "amass" {
		t.Fatalf("unexpected selection order: %s, %s", rep.Results[0].Source, rep.Results[1].Source)
	}
	if r.discoverCallCount() != 2 {
		t.Fatalf("discover calls = %d, want 2", r.discoverCallCount())
	}
}

func TestRunUnknownSource(t *testing.T) {
	cfg := testConfig(newFakeRunner(t, fullScript()), newFakeLookup())
	cfg.Sources = []string{"nmap"}
	_, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("want unknown-source error, got %v", err)
	}
}

func TestRunBadPoolConfig(t *testing.T) {
	cfg := testConfig(newFakeRunner(t, fullScript()), newFakeLookup())
	cfg.Concurrency = 0
	_, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("want pool validation error, got %v", err)
	}
}

func TestRunNilContext(t *testing.T) {
	_, err := Run(nil, mustDomain(t, "example.com"), testConfig(nil, fakeLookup{}))
	if err == nil {
		t.Fatal("expected an error for a nil context")
	}
}

// TestRunPanickingAdapterIsolation verifies a panicking tool cannot take down
// the scan: the source is reported failed and the other sources still run.
func TestRunPanickingAdapterIsolation(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		panic("boom")
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	if rep.Results[0].Source != "subfinder" || rep.Results[0].Status != OutFailed {
		t.Fatalf("subfinder result = %+v, want failed", rep.Results[0])
	}
	if rep.Results[0].Err == nil || !strings.Contains(rep.Results[0].Err.Error(), "panic") {
		t.Fatalf("subfinder error = %v, want panic message", rep.Results[0].Err)
	}
	if rep.Results[1].Status != OutCompleted || rep.Results[2].Status != OutCompleted {
		t.Fatalf("other sources must complete, got %s / %s", rep.Results[1].Status, rep.Results[2].Status)
	}
}

// TestDetectSafePanicBecomesWarn verifies the detection panic containment
// helper itself: a panicking Detect becomes a WARN with a reason and an empty
// version, never a MISSING and never a crash.
func TestDetectSafePanicBecomesWarn(t *testing.T) {
	det := detectSafe(context.Background(), panicSource{name: "subfinder"})
	if det.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", det.Status)
	}
	if det.Reason == "" || !strings.Contains(det.Reason, "panicked") {
		t.Fatalf("reason = %q, want a panic mention", det.Reason)
	}
	if det.Version != "" {
		t.Fatalf("version = %q, want empty", det.Version)
	}
	if det.Status == StatusMissing {
		t.Fatal("a panicking detection must never be reported MISSING")
	}
}

// TestRunPanickingDetectionIsWarnContained verifies a panicking Detect (the
// -version probe) cannot crash the run or the CLI: the source gets a WARN
// detection with a reason, is still executed (WARN is not MISSING), the other
// sources still run, and Run returns normally.
func TestRunPanickingDetectionIsWarnContained(t *testing.T) {
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		panic("detection boom")
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	det := rep.Results[0].Detection
	if det.Status != StatusWarn {
		t.Fatalf("subfinder detection = %s, want warn (reason: %s)", det.Status, det.Reason)
	}
	if !strings.Contains(det.Reason, "panicked") {
		t.Fatalf("detection reason = %q, want panic mention", det.Reason)
	}
	if rep.Results[0].Status != OutCompleted {
		t.Fatalf("a WARN-detected source must still execute; status = %s", rep.Results[0].Status)
	}
	if got := r.discoverCallCount(); got != 3 {
		t.Fatalf("discover calls = %d, want 3 (all sources including the panicking one)", got)
	}
	if rep.Results[1].Status != OutCompleted || rep.Results[2].Status != OutCompleted {
		t.Fatalf("other sources must complete, got %s / %s", rep.Results[1].Status, rep.Results[2].Status)
	}
}

// TestRunWarnDetectedSourceStillExecutes verifies the documented WARN
// semantics at pipeline level: a broken version flag (unrecognizable output)
// is a WARN, never a skip — the source is still executed and its discovery
// output is used.
func TestRunWarnDetectedSourceStillExecutes(t *testing.T) {
	script := fullScript()
	script["subfinder -version"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("???\n")}, nil // garbled: no version
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	if rep.Results[0].Detection.Status != StatusWarn {
		t.Fatalf("subfinder detection = %s, want warn", rep.Results[0].Detection.Status)
	}
	if rep.Results[0].Status != OutCompleted {
		t.Fatalf("WARN-detected source must be executed; status = %s", rep.Results[0].Status)
	}
	if len(rep.Results[0].Hosts) != 2 {
		t.Fatalf("subfinder hosts = %v, want the executed payload", names(rep.Results[0].Hosts))
	}
	if got := r.discoverCallCount(); got != 3 {
		t.Fatalf("discover calls = %d, want 3", got)
	}
}

// TestRunRejectsUnnormalizedTargetLiteral verifies the pipeline-boundary
// defense-in-depth: a hand-built asset.Domain literal that bypasses
// asset.NewDomain's normalization rules is rejected before any tool
// invocation (not even detection).
func TestRunRejectsUnnormalizedTargetLiteral(t *testing.T) {
	cases := map[string]struct {
		domain   asset.Domain
		wantErrf string
	}{
		"invalid label": {
			domain:   asset.Domain{Name: "-evil", Original: "-evil"},
			wantErrf: "invalid target",
		},
		"uppercase, uncanonical": {
			domain:   asset.Domain{Name: "Example.COM", Original: "Example.COM"},
			wantErrf: "not in canonical form",
		},
		"trailing dot": {
			domain:   asset.Domain{Name: "example.com.", Original: "example.com."},
			wantErrf: "not in canonical form",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newFakeRunner(t, fullScript())
			cfg := testConfig(r, newFakeLookup())
			_, err := Run(context.Background(), tc.domain, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrf) {
				t.Fatalf("want error containing %q, got %v", tc.wantErrf, err)
			}
			if n := r.callCount(); n != 0 {
				t.Fatalf("no tool invocation may happen for a rejected target, got %d calls", n)
			}
		})
	}
}

// TestRunConcurrencyBounded verifies the pool's concurrency is respected:
// with Concurrency 1 the three jobs run strictly sequentially.
func TestRunConcurrencyBounded(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1
	cfg.QueueSize = 3
	mustRun(t, mustDomain(t, "example.com"), cfg)
	if r.maxConcurrent != 1 {
		t.Fatalf("max concurrent executions = %d, want 1", r.maxConcurrent)
	}
}

// TestRunCancellation verifies that cancelling the run context cancels jobs,
// stores StatusCancelled records, and reports without crashing.
func TestRunCancellation(t *testing.T) {
	r := newFakeRunner(t, fullScript())
	r.blockKeys = map[string]bool{"subfinder -d example.com -silent": true}
	r.blockStarted = make(chan struct{})
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1 // deterministic: only the subfinder job is running
	ctx, cancel := context.WithCancel(context.Background())
	var rep Report
	var runErr error
	done := make(chan struct{})
	go func() {
		rep, runErr = Run(ctx, mustDomain(t, "example.com"), cfg)
		close(done)
	}()
	<-r.blockStarted
	cancel()
	<-done
	if runErr != nil {
		t.Fatalf("Run error: %v", runErr)
	}
	if rep.Results[0].Status != OutCancelled {
		t.Fatalf("subfinder status = %s, want cancelled (got %+v)", rep.Results[0].Status, rep.Results[0].Err)
	}
	if rep.Results[0].Err == nil {
		t.Fatal("cancelled result must carry the cause")
	}
}

// TestRunPartialResultReports verifies a non-zero exit with usable output is
// reported as partial, not as a hard failure.
func TestRunPartialResultReports(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("api.example.com\n"), ExitCode: 1}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	if rep.Results[0].Status != OutPartial {
		t.Fatalf("subfinder status = %s, want partial", rep.Results[0].Status)
	}
	if len(rep.Results[0].Hosts) != 1 {
		t.Fatalf("partial hosts = %v, want 1 retained", names(rep.Results[0].Hosts))
	}
	// The other sources are unaffected.
	if rep.Results[1].Status != OutCompleted || rep.Results[2].Status != OutCompleted {
		t.Fatalf("other sources: %s / %s, want completed", rep.Results[1].Status, rep.Results[2].Status)
	}
}

// TestRunFailedResultReports verifies a clean failure with no usable output
// is reported as failed, not a crash and not a success.
func TestRunFailedResultReports(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{}, errors.New("permission denied")
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	if rep.Results[0].Status != OutFailed {
		t.Fatalf("subfinder status = %s, want failed", rep.Results[0].Status)
	}
	if rep.Results[0].Err == nil {
		t.Fatal("failed result must carry the cause")
	}
}

// TestRunMalformedCountFlowsThrough verifies skipped lines are reported as
// diagnostics on the result without poisoning the valid hosts.
func TestRunMalformedCountFlowsThrough(t *testing.T) {
	script := fullScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		return RunResult{Stdout: []byte("api.example.com\n..\n.example.com\n")}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)
	if rep.Results[0].Malformed != 2 {
		t.Fatalf("malformed = %d, want 2", rep.Results[0].Malformed)
	}
	if len(rep.Results[0].Hosts) != 1 {
		t.Fatalf("hosts = %v, want [api.example.com]", names(rep.Results[0].Hosts))
	}
}
