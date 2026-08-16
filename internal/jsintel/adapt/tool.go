// Package adapt implements the JavaScript-discovery tool adapters (roadmap
// v0.8, Phase 7, Pass E) for the jsintel engine: subjs, LinkFinder, and
// SecretFinder presented as jsintel.Source streams of raw stdout lines.
// It is a library-level stage with no CLI command yet. The engine's
// Source/Item seam (internal/jsintel) is the output boundary; the hardened
// execution layer (Runner, Limits, Detection) comes from internal/discovery;
// nothing else is imported. All tests are hermetic: fake runners and
// executables on a temporary PATH, never real tools and never the public
// Internet.
//
// # Tools
//
// Three built-in tools, described as data (Tool descriptors; the pipeline
// never branches on tool names — each descriptor carries its pinned argv
// form and input shape):
//
//	subjs:       subjs -c 1 -t 15 -i <tmpfile>   (Go binary; MIT; version
//	            probe "subjs -version")
//	linkfinder:  linkfinder.py -i <target> -o cli   (python3 script; MIT;
//	            existence-only detection)
//	secretfinder: SecretFinder.py -i <target> -o cli (python3 script;
//	            GPL-3.0; existence-only detection)
//
// All three are ACTIVE adapters: they fetch the target themselves, so every
// run performs the tool's own network activity, bounded only by the runner's
// limits (the caller's context deadline and the per-stream output cap); the
// tools' traffic is the tools' own responsibility, never re-limited by
// RavenRecon.
//
// Katana's JS output is deliberately DEFERRED (documented future work),
// consistent with urlintel's katana deferral.
//
// # Executable + wrapper contract
//
// For the python pair the SCRIPT IS the executable: the tool's Path is
// "linkfinder.py" / "SecretFinder.py". The documented install contract is a
// PATH wrapper with a shebang (or a symlink to the real script), or a
// per-run path override — there is no python3-interpreter split, and the
// adapter never resolves executables itself. Command resolution (bare name
// through PATH, or the override value verbatim) and missing-executable
// classification (discovery.ErrExecutableNotFound, wrapped with context)
// are the discovery Runner's job.
//
// # Overrides
//
// The per-run override map is keyed by the executable NAME — "subjs",
// "linkfinder.py", "SecretFinder.py": a value replaces that name as the
// command's Path (the runner executes it verbatim, no PATH lookup for that
// invocation). This mirrors the urlintel/adapt override shape (per-name
// executable replacement) with the script names as first-class keys.
//
// # Detection semantics
//
// subjs is version-probed ("subjs -version", which prints "subjs version:
// 1.0.1" to stdout and exits 0 — no network). A broken, unsupported,
// garbled, or timing-out probe is at worst a WARN — existence and capability
// are separate concerns, and a correctly installed tool is never reported
// MISSING because its version flag misbehaved. The python pair is
// existence-probed: the tool's executable (the script, possibly a wrapper)
// must resolve; there is no probe, so no probe can misreport an installed
// tool.
package adapt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// ProbeKind selects a tool's detection strategy.
//
// Detection must be tool-specific, and a broken version flag must never mark
// an installed tool as missing: existence and capability are separate
// concerns (the discovery package's Status trinity: OK / WARN / MISSING).
type ProbeKind int

const (
	// ProbeVersion: the tool supports a version flag (subjs -version);
	// detection runs the probe through the runner and requires a
	// recognizable semver-like token in the bounded capture. A broken,
	// unsupported, garbled, or timing-out probe is a WARN at worst.
	ProbeVersion ProbeKind = iota
	// ProbeExistence: the tool has no reliable version flag (linkfinder,
	// secretfinder); executable existence IS the entire detection. There
	// is no probe, so no probe can misreport an installed tool.
	ProbeExistence
)

// Tool describes one JavaScript-discovery tool: its identity, detection
// strategy, and pinned argv form. Tools are data — every tool-specific
// behavior lives in the built-in descriptors (Tools), and the pipeline
// never branches on tool names. Use the built-in descriptors from Tools; a
// hand-built descriptor must keep Name and the probe fields consistent (a
// version-probed tool with no ProbeArgs is detected as WARN, never executed
// blindly as a probe).
type Tool struct {
	// Name is the stable adapter identity ("subjs", "linkfinder",
	// "secretfinder"). It is the engine's adapter key (enters provenance);
	// the same tool must use the same name across runs.
	Name string

	// Bin is the executable name (the command's Path when no override is
	// given): "subjs" for the binary, "linkfinder.py" / "SecretFinder.py"
	// for the python pair — the SCRIPT IS the executable (install
	// contract: a PATH wrapper with a shebang, or a per-run override).
	// Empty means Name.
	Bin string

	// ProbeKind selects the detection strategy (see ProbeKind).
	ProbeKind ProbeKind

	// ProbeArgs is the detection probe argv; non-empty exactly when
	// ProbeKind is ProbeVersion.
	ProbeArgs []string

	// inputFile marks the input shape: subjs reads its single target URL
	// from a 0600 temp file passed via -i; the python pair takes the
	// target as its own -i argv element.
	inputFile bool

	// argv builds the pinned argument vector for one target: the target
	// always appears as its own single argv element, never embedded in a
	// flag value and never shell-joined.
	argv func(target, tmpfile string) []string
}

// Tools is the built-in registry, keyed by the stable adapter identity. It
// is read-only after package initialization — never mutate it.
var Tools = map[string]Tool{
	"subjs": {
		Name:      "subjs",
		Bin:       "subjs",
		ProbeKind: ProbeVersion,
		ProbeArgs: []string{"-version"},
		inputFile: true,
		argv: func(_ string, tmpfile string) []string {
			// -c 1 pins the tool-internal worker count for determinism
			// (moot for a single input URL); -t 15 is the upstream default
			// per-URL timeout.
			return []string{"-c", "1", "-t", "15", "-i", tmpfile}
		},
	},
	"linkfinder": {
		Name:      "linkfinder",
		Bin:       "linkfinder.py",
		ProbeKind: ProbeExistence,
		argv: func(target, _ string) []string {
			// "cli" prints to stdout; never -d (stdout pollution) and
			// never -o without "cli" (writes output.html and spawns
			// xdg-open).
			return []string{"-i", target, "-o", "cli"}
		},
	},
	"secretfinder": {
		Name:      "secretfinder",
		Bin:       "SecretFinder.py",
		ProbeKind: ProbeExistence,
		argv: func(target, _ string) []string {
			// Same pinned form as linkfinder. -H is never passed (broken
			// in the tool: crashes with an AttributeError).
			return []string{"-i", target, "-o", "cli"}
		},
	},
}

// Valid reports whether t is one of the built-in descriptors (by Name). A
// hand-built descriptor that keeps the built-in name also keeps the
// descriptor's behavior (the pinned argv shapes and input forms live in the
// registry and are keyed by Name).
func (t Tool) Valid() bool {
	_, ok := Tools[t.Name]
	return ok
}

// binName returns the executable name for t: the descriptor's Bin, else the
// tool's default name. This name is the override-map key and the command's
// Path when no override is given.
func (t Tool) binName() string {
	if t.Bin != "" {
		return t.Bin
	}
	return t.Name
}

// buildArgv assembles the pinned argv for one target: the target always
// appears as its own single element, never embedded in a flag value and
// never shell-joined. tmpfile is the subjs target file ("" for the python
// pair, whose target is the -i value). The forms are data, keyed by the
// tool's name in the registry; the pipeline never branches on names.
func (t Tool) buildArgv(target, tmpfile string) []string {
	b, ok := Tools[t.Name]
	if !ok || b.argv == nil {
		return nil
	}
	return b.argv(target, tmpfile)
}

// targetFile reports whether the tool reads its target from a temp file
// (subjs) rather than from an argv element (the python pair). The shape is
// data, keyed by the tool's name in the registry.
func (t Tool) targetFile() bool {
	b, ok := Tools[t.Name]
	return ok && b.inputFile
}

// DefaultDetectTimeout bounds one detection probe invocation.
const DefaultDetectTimeout = 5 * time.Second

// env is the execution environment for one run or detection: the hardened
// runner, the capture limits, the detection budget, and the per-name
// overrides. Zero values mean production defaults. There is deliberately no
// lookup seam here: command resolution is the runner's job, never the
// adapter's (detection's existence check takes its own optional lookup
// seam, mirroring urlintel/adapt).
type env struct {
	runner        discovery.Runner
	limits        discovery.Limits
	detectTimeout time.Duration
	overrides     map[string]string
}

// sanitized returns e with production defaults applied.
func (e env) sanitized() env {
	if e.runner == nil {
		e.runner = discovery.ExecRunner{}
	}
	if e.detectTimeout <= 0 {
		e.detectTimeout = DefaultDetectTimeout
	}
	if e.limits.MaxOutput <= 0 {
		e.limits.MaxOutput = discovery.DefaultMaxOutput
	}
	return e
}

// runnerOf dereferences the optional runner pointer (the pinned Run/Detect
// seam): nil means the production ExecRunner.
func runnerOf(r *discovery.Runner) discovery.Runner {
	if r != nil && *r != nil {
		return *r
	}
	return discovery.ExecRunner{}
}

// pathFor resolves the command's Path for one invocation: the per-run
// override (keyed by the executable NAME — "subjs", "linkfinder.py",
// "SecretFinder.py") wins, else the bare name. The adapter NEVER resolves
// executables itself (no exec.LookPath here): a bare name is resolved by the
// discovery Runner, which classifies a missing executable as
// discovery.ErrExecutableNotFound (wrapped with context).
func (e env) pathFor(name string) string {
	if e.overrides != nil {
		if p, ok := e.overrides[name]; ok && p != "" {
			return p
		}
	}
	return name
}

// Detect checks t's availability per its descriptor, mirroring the discovery
// package's detection contract:
//
//   - Version-probed tools (subjs): the executable is resolved (the per-run
//     override wins, else the lookup seam), then the probe through the
//     runner (bounded by the detection timeout), then tolerant version
//     extraction from the bounded capture (stdout first, then stderr). A
//     probe that fails to execute, garbles, times out, or prints no
//     recognizable version is at worst StatusWarn — never StatusMissing,
//     because the executable exists and may still run.
//   - Existence-only tools (linkfinder, secretfinder): executable
//     resolution IS the detection (these tools have no version flag, and
//     existence is the only probe-less way to establish availability; the
//     same resolution shape as urlintel's existence-only detection).
//     StatusOK with no probe executed; capabilities are exercised at run
//     time and its failures are surfaced by the execution result, never by
//     detection.
//
// r, lookup, and overrides are seams: nil runner means ExecRunner, nil
// lookup means exec.LookPath, nil overrides means none.
func Detect(ctx context.Context, r *discovery.Runner, lookup discovery.LookupFunc, t Tool, overrides map[string]string) discovery.Detection {
	if lookup == nil {
		lookup = exec.LookPath
	}
	return detectSafe(ctx, env{
		runner:    runnerOf(r),
		overrides: overrides,
	}, lookup, t)
}

// detectSafe runs a tool's detection with panic containment, matching the
// containment style used elsewhere in the house: a panicking detection
// becomes a WARN with a reason (never a MISSING and never a crash), so one
// broken runner cannot take down a detection pass.
func detectSafe(ctx context.Context, e env, lookup discovery.LookupFunc, t Tool) (d discovery.Detection) {
	defer func() {
		if r := recover(); r != nil {
			d = discovery.Detection{
				Source: t.Name,
				Status: discovery.StatusWarn,
				Reason: fmt.Sprintf("detection panicked: %v", r),
			}
		}
	}()
	return t.detect(ctx, e, lookup)
}

// detect implements the per-tool detection (see Detect).
func (t Tool) detect(ctx context.Context, e env, lookup discovery.LookupFunc) discovery.Detection {
	e = e.sanitized()
	d := discovery.Detection{Source: t.Name}

	name := t.binName()
	path := e.pathFor(name)
	if path == name {
		// No override (or a pathological override value equal to the
		// name): resolve through the lookup seam to establish existence.
		var err error
		path, err = lookup(name)
		if err != nil {
			d.Status = discovery.StatusMissing
			d.Reason = fmt.Sprintf("executable %q not found", name)
			return d
		}
	}
	d.Exists = true

	if t.ProbeKind == ProbeExistence {
		d.Status = discovery.StatusOK
		d.Capable = true
		d.Reason = fmt.Sprintf("executable %s found; existence-only detection (no version flag; capabilities are exercised at run time)", path)
		return d
	}

	if len(t.ProbeArgs) == 0 {
		// A hand-built version-probed descriptor without a probe cannot be
		// probed honestly: report WARN, never MISSING and never a blind
		// no-arg execution.
		d.Status = discovery.StatusWarn
		d.Reason = fmt.Sprintf("executable %s exists; no detection probe configured", path)
		return d
	}

	ctx, cancel := context.WithTimeout(ctx, e.detectTimeout)
	defer cancel()

	res, err := e.runner.Run(ctx, discovery.Cmd{Path: path, Args: t.ProbeArgs}, e.limits)
	if err != nil {
		if errors.Is(err, discovery.ErrExecutableNotFound) {
			// The executable disappeared between resolution and execution.
			d.Status = discovery.StatusMissing
			d.Reason = fmt.Sprintf("executable %q not found", name)
			return d
		}
		d.Status = discovery.StatusWarn
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			d.Reason = fmt.Sprintf("executable %s exists but %s did not answer within the detection budget: %v", path, strings.Join(t.ProbeArgs, " "), err)
		} else {
			d.Reason = fmt.Sprintf("executable %s exists but %s could not be executed: %v", path, strings.Join(t.ProbeArgs, " "), err)
		}
		return d
	}

	if v := extractVersion(res.Stdout); v != "" {
		d.Status = discovery.StatusOK
		d.Capable = true
		d.Version = v
		d.Reason = fmt.Sprintf("executable %s; version %s", path, v)
		return d
	}
	if v := extractVersion(res.Stderr); v != "" {
		d.Status = discovery.StatusOK
		d.Capable = true
		d.Version = v
		d.Reason = fmt.Sprintf("executable %s; version %s (stderr)", path, v)
		return d
	}

	d.Status = discovery.StatusWarn
	d.Reason = fmt.Sprintf("executable %s exists; %s produced no recognizable version", path, strings.Join(t.ProbeArgs, " "))
	return d
}

// versionPattern matches the first semver-like token in tool output, with an
// optional leading "v". It mirrors internal/discovery's tolerant pattern
// (unexported there): version outputs differ across tools and versions
// ("subjs version: 1.0.1", "Current Version: v2.6.3", ...).
var versionPattern = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:[-+._][0-9A-Za-z]+)*`)

// extractVersion returns the first semver-like token in out, or "".
func extractVersion(out []byte) string {
	if m := versionPattern.Find(out); m != nil {
		return string(m)
	}
	return ""
}
