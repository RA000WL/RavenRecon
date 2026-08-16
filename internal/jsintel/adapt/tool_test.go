package adapt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// TestToolsRegistry pins the built-in registry: exactly the three tools of
// this phase, each with its executable shape (the script names ARE the
// executables for the python pair), probe kind, and probe argv.
func TestToolsRegistry(t *testing.T) {
	if len(Tools) != 3 {
		t.Fatalf("Tools = %d entries, want 3", len(Tools))
	}
	cases := []struct {
		name      string
		bin       string
		probeKind ProbeKind
		probeArgs []string
	}{
		{"subjs", "subjs", ProbeVersion, []string{"-version"}},
		{"linkfinder", "linkfinder.py", ProbeExistence, nil},
		{"secretfinder", "SecretFinder.py", ProbeExistence, nil},
	}
	for _, c := range cases {
		tool, ok := Tools[c.name]
		if !ok {
			t.Fatalf("Tools[%q] missing", c.name)
		}
		if tool.Name != c.name || tool.Bin != c.bin ||
			tool.ProbeKind != c.probeKind || len(tool.ProbeArgs) != len(c.probeArgs) {
			t.Fatalf("Tools[%q] = %+v, want bin=%q probe=%v args=%v",
				c.name, tool, c.bin, c.probeKind, c.probeArgs)
		}
		for i := range c.probeArgs {
			if tool.ProbeArgs[i] != c.probeArgs[i] {
				t.Fatalf("Tools[%q].ProbeArgs = %v, want %v", c.name, tool.ProbeArgs, c.probeArgs)
			}
		}
		if !tool.Valid() {
			t.Fatalf("Tools[%q].Valid() = false", c.name)
		}
	}
}

// TestValidRejectsUnknownTools: only the three built-in names are valid;
// unknown names and the zero Tool are refused.
func TestValidRejectsUnknownTools(t *testing.T) {
	for _, name := range []string{"katana", "paramspider", ""} {
		tool := Tool{Name: name}
		if tool.Valid() {
			t.Fatalf("Tool{Name: %q}.Valid() = true, want false", name)
		}
	}
	if (Tool{}).Valid() {
		t.Fatal("zero Tool is valid, want false")
	}
}

// TestBuildArgv pins the exact invocation argv of every built-in tool: the
// binary form carries the pinned subjs flags with the temp file as its own
// single element; the script forms carry -i <target> -o cli — the script
// itself is the command's Path, never an argv element — each argument as a
// separate element, never shell-joined.
func TestBuildArgv(t *testing.T) {
	cases := []struct {
		name     string
		tool     Tool
		target   string
		tmpfile  string
		wantArgs int
		wantLast string
	}{
		{"subjs", Tools["subjs"], "https://example.com/", "/tmp/x.txt", 6, "/tmp/x.txt"},
		{"linkfinder", Tools["linkfinder"], "https://example.com/", "", 4, "cli"},
		{"secretfinder", Tools["secretfinder"], "https://example.com/", "", 4, "cli"},
	}
	for _, c := range cases {
		got := c.tool.buildArgv(c.target, c.tmpfile)
		if len(got) != c.wantArgs {
			t.Fatalf("%s argv = %v, want %d elements", c.name, got, c.wantArgs)
		}
		if got[len(got)-1] != c.wantLast {
			t.Fatalf("%s argv = %v, want last element %q", c.name, got, c.wantLast)
		}
	}
	subjs := Tools["subjs"].buildArgv("https://example.com/", "/tmp/x.txt")
	want := []string{"-c", "1", "-t", "15", "-i", "/tmp/x.txt"}
	for i := range want {
		if subjs[i] != want[i] {
			t.Fatalf("subjs argv = %v, want %v", subjs, want)
		}
	}
	lf := Tools["linkfinder"].buildArgv("https://example.com/", "")
	want = []string{"-i", "https://example.com/", "-o", "cli"}
	for i := range want {
		if lf[i] != want[i] {
			t.Fatalf("linkfinder argv = %v, want %v", lf, want)
		}
	}
}

// detectOne runs Detect for one tool over the fake seams and returns its
// detection.
func detectOne(t *testing.T, tool Tool, runner discovery.Runner, lookup discovery.LookupFunc, overrides map[string]string) discovery.Detection {
	t.Helper()
	r := discovery.Runner(runner)
	return Detect(context.Background(), &r, lookup, tool, overrides)
}

// TestDetectSubjsVersionStdout: the version probe prints a semver-like token
// to stdout; subjs is detected OK with the version, and the probe ran with
// the exact argv.
func TestDetectSubjsVersionStdout(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("subjs version: 1.0.1\n")})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusOK || d.Version != "1.0.1" || !d.Capable || !d.Exists {
		t.Fatalf("detection = %+v, want OK/version 1.0.1/capable/exists", d)
	}
	if got := runner.argsOf(0); len(got) != 1 || got[0] != "-version" {
		t.Fatalf("probe argv = %v, want [-version]", got)
	}
}

// TestDetectSubjsVersionStderr: some tools print their banner on stderr; the
// detection must read it too.
func TestDetectSubjsVersionStderr(t *testing.T) {
	runner := newFakeRunner(runStep{errOut: []byte("subjs version: 0.9.0\n")})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusOK || d.Version != "0.9.0" {
		t.Fatalf("detection = %+v, want OK with stderr version", d)
	}
}

// TestDetectSubjsNoRecognizableVersion: a probe that runs but prints no
// version is WARN — never MISSING: existence and capability are separate
// concerns.
func TestDetectSubjsNoRecognizableVersion(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("usage: subjs [flags]\n")})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
	if !d.Exists {
		t.Fatal("existing tool must report Exists even when the probe garbles")
	}
}

// TestDetectSubjsProbeNonZeroExit: a version that prints despite a non-zero
// exit is still detected OK (the runner reports the process executed and
// exited; the capture is valid).
func TestDetectSubjsProbeNonZeroExit(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("subjs version: 1.0.1\n"), code: 2})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusOK || d.Version != "1.0.1" {
		t.Fatalf("detection = %+v, want OK/version 1.0.1", d)
	}
}

// TestDetectSubjsProbeExecutionError: a probe that cannot be executed is
// WARN at worst, never MISSING.
func TestDetectSubjsProbeExecutionError(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: errors.New("boom")})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
}

// TestDetectSubjsProbeTimeout: a probe that times out is WARN at worst,
// never MISSING.
func TestDetectSubjsProbeTimeout(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: context.DeadlineExceeded})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN", d)
	}
}

// TestDetectSubjsMissing: an unresolvable executable is MISSING.
func TestDetectSubjsMissing(t *testing.T) {
	lookup := newFakeLookup()
	lookup.AddErr("subjs", errors.New("not found"))
	d := detectOne(t, Tools["subjs"], newFakeRunner(), lookup.asFunc(), nil)
	if d.Status != discovery.StatusMissing || d.Exists {
		t.Fatalf("detection = %+v, want MISSING/nonexistent", d)
	}
}

// TestDetectSubjsExecutableVanished: the executable disappears between
// lookup and execution — MISSING, per the runner's ErrExecutableNotFound
// contract.
func TestDetectSubjsExecutableVanished(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: discovery.ErrExecutableNotFound})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusMissing {
		t.Fatalf("detection = %+v, want MISSING", d)
	}
}

// TestDetectExistenceOnlyRunsNoProbe: linkfinder and secretfinder are
// detected by the tool's executable existence (the script IS the executable
// under the wrapper model), and the runner must never be invoked by
// detection — no probe can misreport an installed tool that has no version
// flag.
func TestDetectExistenceOnlyRunsNoProbe(t *testing.T) {
	for _, name := range []string{"linkfinder", "secretfinder"} {
		runner := newFakeRunner()
		lookup := newFakeLookup()
		d := detectOne(t, Tools[name], runner, lookup.asFunc(), nil)
		if d.Status != discovery.StatusOK || !d.Capable {
			t.Fatalf("%s detection = %+v, want OK/capable", name, d)
		}
		if runner.callCount() != 0 {
			t.Fatalf("%s existence-only detection executed %d probes; want 0", name, runner.callCount())
		}
		// Exactly one resolution: the tool's executable (the script name).
		want := []string{Tools[name].Bin}
		got := lookup.requested()
		if len(got) != len(want) {
			t.Fatalf("%s lookups = %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s lookups = %v, want %v", name, got, want)
			}
		}
	}
}

// TestDetectExecutableMissing: the tool's executable (the script) does not
// resolve — MISSING (there is no interpreter half to fall back on).
func TestDetectExecutableMissing(t *testing.T) {
	lookup := newFakeLookup()
	lookup.AddErr("linkfinder.py", errors.New("not found"))
	d := detectOne(t, Tools["linkfinder"], newFakeRunner(), lookup.asFunc(), nil)
	if d.Status != discovery.StatusMissing {
		t.Fatalf("detection = %+v, want MISSING (executable absent)", d)
	}
}

// TestDetectExecutableOverride: the executable override replaces the lookup
// for the python pair (keyed by the script name — no interpreter key).
func TestDetectExecutableOverride(t *testing.T) {
	lookup := newFakeLookup()
	overrides := map[string]string{"linkfinder.py": "/opt/tools/linkfinder.py"}
	d := detectOne(t, Tools["linkfinder"], newFakeRunner(), lookup.asFunc(), overrides)
	if d.Status != discovery.StatusOK || !d.Capable {
		t.Fatalf("detection = %+v, want OK/capable", d)
	}
	if got := lookup.requested(); len(got) != 0 {
		t.Fatalf("lookups = %v, want none (executable overridden)", got)
	}
}

// TestDetectBinOverride: the per-run executable override wins over the
// descriptor's default name for lookup.
func TestDetectBinOverride(t *testing.T) {
	lookup := newFakeLookup()
	overrides := map[string]string{"subjs": "/opt/bin/subjs"}
	runner := newFakeRunner(runStep{out: []byte("subjs version: 1.0.1\n")})
	d := detectOne(t, Tools["subjs"], runner, lookup.asFunc(), overrides)
	if d.Status != discovery.StatusOK {
		t.Fatalf("detection = %+v, want OK", d)
	}
	if got := lookup.requested(); len(got) != 0 {
		t.Fatalf("lookups = %v, want none (executable overridden)", got)
	}
	if got := runner.pathOf(0); got != "/opt/bin/subjs" {
		t.Fatalf("probe path = %q, want /opt/bin/subjs", got)
	}
}

// TestDetectBoundedByTimeout: every probe runs under a context deadline (the
// detection budget) even when the caller's context has none.
func TestDetectBoundedByTimeout(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("subjs version: 1.0.1\n")})
	detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if !runner.sawDeadline() {
		t.Fatal("detection probe did not run under a bounded context deadline")
	}
}

// TestDetectNoProbeConfigured: a hand-built version-probed descriptor
// without a probe is WARN, never executed blindly and never MISSING.
func TestDetectNoProbeConfigured(t *testing.T) {
	tool := Tool{Name: "subjs", Bin: "subjs", ProbeKind: ProbeVersion}
	runner := newFakeRunner()
	d := detectOne(t, tool, runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN (no probe configured)", d)
	}
	if runner.callCount() != 0 {
		t.Fatalf("no-probe detection executed %d probes; want 0", runner.callCount())
	}
}

// TestDetectPanicContained: a panicking probe becomes a WARN with a reason,
// never a MISSING and never a crash.
func TestDetectPanicContained(t *testing.T) {
	runner := newFakeRunner(runStep{panics: true})
	d := detectOne(t, Tools["subjs"], runner, newFakeLookup().asFunc(), nil)
	if d.Status != discovery.StatusWarn {
		t.Fatalf("detection = %+v, want WARN (panicked probe)", d)
	}
	if d.Reason == "" {
		t.Fatal("WARN detection must carry a reason")
	}
}

// TestExtractVersion pins the tolerant version extraction across the known
// tool output shapes.
func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"subjs version: 1.0.1\n", "1.0.1"},
		{"Current Version: v2.6.3\n", "v2.6.3"},
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

// TestDetectTimeoutConstant sanity-pins the detection budget.
func TestDetectTimeoutConstant(t *testing.T) {
	if DefaultDetectTimeout != 5*time.Second {
		t.Fatalf("DefaultDetectTimeout = %s, want 5s", DefaultDetectTimeout)
	}
}
