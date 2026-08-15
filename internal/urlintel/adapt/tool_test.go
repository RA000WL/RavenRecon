package adapt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// TestBuiltinsStableOrder pins the built-in tool order: cache keys,
// selections, and reports all order on this list.
func TestBuiltinsStableOrder(t *testing.T) {
	bs := Builtins()
	want := []string{"gau", "waybackurls", "waymore"}
	if len(bs) != len(want) {
		t.Fatalf("Builtins() = %d tools, want %d", len(bs), len(want))
	}
	for i, w := range want {
		if bs[i].Name != w {
			t.Fatalf("Builtins()[%d].Name = %q, want %q", i, bs[i].Name, w)
		}
	}
}

// TestLookupTool pins the name -> descriptor registry.
func TestLookupTool(t *testing.T) {
	for _, name := range []string{"gau", "waybackurls", "waymore"} {
		tool, ok := LookupTool(name)
		if !ok {
			t.Fatalf("LookupTool(%q) not found", name)
		}
		if tool.Name != name {
			t.Fatalf("LookupTool(%q).Name = %q", name, tool.Name)
		}
	}
	if _, ok := LookupTool("katana"); ok {
		t.Fatal("LookupTool(katana) found; katana is deferred")
	}
}

// TestToolArgs pins the exact invocation argv of every built-in tool: the
// target appears exactly once, as its own single argv element, and the argv
// is never shell-joined nor embedded in a flag value.
func TestToolArgs(t *testing.T) {
	h := mustHost(t, "example.com")
	cases := []struct {
		name string
		tool Tool
		want []string
	}{
		{"gau", Gau(), []string{"example.com"}},
		{"waybackurls", Waybackurls(), []string{"example.com"}},
		{"waymore", Waymore(), []string{"-i", "example.com", "-mode", "U"}},
	}
	for _, c := range cases {
		got := c.tool.Args(h)
		if len(got) != len(c.want) {
			t.Fatalf("%s Args = %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s Args = %v, want %v", c.name, got, c.want)
			}
		}
		// The target must appear exactly once, always as its own element.
		count := 0
		for _, a := range got {
			if a == "example.com" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s Args = %v: target appears %d times, want exactly 1", c.name, got, count)
		}
	}
}

// TestProbeArgs pins the detection probe argv of the version-probed tools.
func TestProbeArgs(t *testing.T) {
	if got := Gau().ProbeArgs; len(got) != 1 || got[0] != "-version" {
		t.Fatalf("gau probe = %v, want [-version]", got)
	}
	if got := Waymore().ProbeArgs; len(got) != 1 || got[0] != "--version" {
		t.Fatalf("waymore probe = %v, want [--version]", got)
	}
	if got := Waybackurls().ProbeArgs; len(got) != 0 {
		t.Fatalf("waybackurls probe = %v, want none (existence-only detection)", got)
	}
}

// detectConfig builds a detection-only configuration over the fake seams.
func detectConfig(tool Tool, runner discovery.Runner, lookup discovery.LookupFunc) Config {
	cfg := DefaultConfig()
	cfg.Tools = []Tool{tool}
	cfg.Runner = runner
	cfg.LookPath = lookup
	cfg.DetectTimeout = 5 * time.Second
	return cfg
}

// detectOne runs DetectTools for one tool and returns its detection.
func detectOne(t *testing.T, tool Tool, runner discovery.Runner, lookup discovery.LookupFunc) discovery.Detection {
	t.Helper()
	dets := DetectTools(context.Background(), detectConfig(tool, runner, lookup))
	if len(dets) != 1 {
		t.Fatalf("DetectTools returned %d detections, want 1", len(dets))
	}
	return dets[0]
}

// TestDetectVersionStdout: a version-probed tool whose probe prints a
// semver-like token to stdout is detected OK with the version.
func TestDetectVersionStdout(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("Current Version: v2.6.3\n")})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusOK || d.Version != "v2.6.3" || !d.Capable || !d.Exists {
		t.Fatalf("detection = %+v, want OK/version v2.6.3/capable/exists", d)
	}
	// The probe must have gone through the runner with the exact argv.
	if got := runner.argsOf(0); len(got) != 1 || got[0] != "-version" {
		t.Fatalf("probe argv = %v, want [-version]", got)
	}
}

// TestDetectVersionStderr: some tools print their banner on stderr; the
// detection must read it too.
func TestDetectVersionStderr(t *testing.T) {
	runner := newFakeRunner(runStep{errOut: []byte("gau v1.2.3\n")})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusOK || d.Version != "v1.2.3" {
		t.Fatalf("detection = %+v, want OK with stderr version", d)
	}
}

// TestDetectWaymoreProbe: waymore is probed with the real argparse
// double-dash version action.
func TestDetectWaymoreProbe(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("waymore v1.0.0\n")})
	d := detectOne(t, Waymore(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusOK || d.Version != "v1.0.0" {
		t.Fatalf("detection = %+v, want OK/version v1.0.0", d)
	}
	if got := runner.argsOf(0); len(got) != 1 || got[0] != "--version" {
		t.Fatalf("waymore probe argv = %v, want [--version]", got)
	}
}

// TestDetectNoRecognizableVersion: a probe that runs but prints no version
// is WARN — never MISSING: existence and capability are separate concerns.
func TestDetectNoRecognizableVersion(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("usage: gau [flags]\n")})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
	if !d.Exists {
		t.Fatal("existing tool must report Exists even when the probe garbles")
	}
}

// TestDetectProbeNonZeroExit: a version that prints despite a non-zero exit
// is still detected OK (the runner reports the process executed and exited;
// the capture is valid).
func TestDetectProbeNonZeroExit(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n"), code: 2})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusOK || d.Version != "2.1.1" {
		t.Fatalf("detection = %+v, want OK/version 2.1.1", d)
	}
}

// TestDetectProbeExecutionError: a probe that cannot be executed is WARN at
// worst, never MISSING.
func TestDetectProbeExecutionError(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: errors.New("boom")})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
}

// TestDetectProbeTimeout: a probe that times out is WARN at worst, never
// MISSING.
func TestDetectProbeTimeout(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: context.DeadlineExceeded})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
}

// TestDetectMissing: an unresolvable executable is MISSING.
func TestDetectMissing(t *testing.T) {
	lookup := newFakeLookup()
	lookup.AddErr("gau", errors.New("not found"))
	d := detectOne(t, Gau(), newFakeRunner(), lookup.asFunc())
	if d.Status != discovery.StatusMissing || d.Exists {
		t.Fatalf("detection = %+v, want MISSING/nonexistent", d)
	}
}

// TestDetectExecutableVanished: the executable disappears between lookup and
// execution — MISSING, per the runner's ErrExecutableNotFound contract.
func TestDetectExecutableVanished(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: discovery.ErrExecutableNotFound})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusMissing {
		t.Fatalf("detection = %+v, want MISSING", d)
	}
}

// TestDetectExistenceOnlyRunsNoProbe: waybackurls' detection is executable
// existence, and the runner must never be invoked by it — no probe can
// misreport an installed tool that has no version flag.
func TestDetectExistenceOnlyRunsNoProbe(t *testing.T) {
	runner := newFakeRunner()
	d := detectOne(t, Waybackurls(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusOK || !d.Capable {
		t.Fatalf("detection = %+v, want OK/capable", d)
	}
	if runner.callCount() != 0 {
		t.Fatalf("existence-only detection executed %d probes; want 0", runner.callCount())
	}
}

// TestDetectBoundedByTimeout: every probe runs under a context deadline (the
// detection budget) even when the caller's context has none.
func TestDetectBoundedByTimeout(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")})
	detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if !runner.sawDeadline() {
		t.Fatal("detection probe did not run under a bounded context deadline")
	}
}

// TestDetectBinOverride: the per-run Bin override wins over the descriptor's
// default name for lookup.
func TestDetectBinOverride(t *testing.T) {
	lookup := newFakeLookup()
	cfg := detectConfig(Gau(), newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}), lookup.asFunc())
	cfg.Bin = map[string]string{"gau": "custom-gau"}
	dets := DetectTools(context.Background(), cfg)
	if len(dets) != 1 || dets[0].Status != discovery.StatusOK {
		t.Fatalf("detections = %+v, want one OK", dets)
	}
	req := lookup.requested()
	if len(req) != 1 || req[0] != "custom-gau" {
		t.Fatalf("lookup requested %v, want [custom-gau]", req)
	}
}

// TestDetectDescriptorBinOverride: the descriptor's Bin is used when the
// per-run override is absent.
func TestDetectDescriptorBinOverride(t *testing.T) {
	tool := Gau()
	tool.Bin = "descriptor-gau"
	lookup := newFakeLookup()
	detectOne(t, tool, newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}), lookup.asFunc())
	req := lookup.requested()
	if len(req) != 1 || req[0] != "descriptor-gau" {
		t.Fatalf("lookup requested %v, want [descriptor-gau]", req)
	}
}

// TestDetectPanicContained: a panicking probe becomes a WARN with a reason,
// never a MISSING and never a crash.
func TestDetectPanicContained(t *testing.T) {
	runner := newFakeRunner(runStep{panics: true})
	d := detectOne(t, Gau(), runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN (panicked probe)", d)
	}
	if d.Reason == "" {
		t.Fatal("WARN detection must carry a reason")
	}
}

// TestDetectNoProbeConfigured: a hand-built version-probed descriptor without
// a probe is WARN, never executed blindly and never MISSING.
func TestDetectNoProbeConfigured(t *testing.T) {
	tool := Tool{Name: "custom", ProbeKind: ProbeVersion}
	runner := newFakeRunner()
	d := detectOne(t, tool, runner, newFakeLookup().asFunc())
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN (no probe configured)", d)
	}
	if runner.callCount() != 0 {
		t.Fatalf("no-probe detection executed %d probes; want 0", runner.callCount())
	}
}

// TestDetectToolsOrderAndDedupe: detection runs in selection order, once per
// unique tool.
func TestDetectToolsOrderAndDedupe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tools = []Tool{Waybackurls(), Gau(), Waybackurls()}
	cfg.Runner = newFakeRunner(runStep{out: []byte("gau 2.1.1\n")})
	cfg.LookPath = newFakeLookup().asFunc()
	dets := DetectTools(context.Background(), cfg)
	if len(dets) != 2 {
		t.Fatalf("DetectTools = %d detections, want 2 (deduplicated)", len(dets))
	}
	if dets[0].Source != "waybackurls" || dets[1].Source != "gau" {
		t.Fatalf("detection order = [%s %s], want [waybackurls gau]", dets[0].Source, dets[1].Source)
	}
}

// TestExtractVersion pins the tolerant version extraction across the known
// tool output shapes.
func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Current Version: v2.6.3\n", "v2.6.3"},
		{"waymore v1.0.0\n", "v1.0.0"},
		{"gau 2.1.1\n", "2.1.1"},
		{"Version: 1.2.3-beta.1\n", "1.2.3-beta.1"},
		{"v0.0.1\n", "v0.0.1"},
		{"no version here\n", ""},
		{"", ""},
		{"v1\n", ""}, // not semver-like
	}
	for _, c := range cases {
		if got := extractVersion([]byte(c.in)); got != c.want {
			t.Fatalf("extractVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
