package adapt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// ProbeKind selects a tool's detection strategy.
//
// Detection must be tool-specific, and a broken version flag must never mark
// an installed tool as missing: existence and capability are separate
// concerns (the discovery package's Status trinity: OK / WARN / MISSING).
type ProbeKind int

const (
	// ProbeVersion: the tool supports a version flag (gau -version, waymore
	// --version); detection runs the probe through the runner and requires
	// a recognizable semver-like token in the bounded capture. A broken,
	// unsupported, garbled, or timing-out probe is a WARN at worst.
	ProbeVersion ProbeKind = iota
	// ProbeExistence: the tool has no reliable version flag (waybackurls);
	// executable existence IS the entire detection. There is no probe, so
	// no probe can misreport an installed tool.
	ProbeExistence
)

// Tool describes one historical-URL tool: its identity, detection strategy,
// and typed argv construction. Tools are data — every tool-specific behavior
// lives in its descriptor, and the pipeline never branches on tool names.
// Build tools with the built-in constructors (Gau, Waybackurls, Waymore) or
// Builtins; hand-built descriptors must set Name and the probe fields
// consistently (a version-probed tool with no ProbeArgs is detected as WARN,
// never executed blindly as a probe).
type Tool struct {
	// Name is the stable adapter identity. It is the engine's adapter key
	// (enters per-(URL, adapter) cache keys and provenance) — the same tool
	// must use the same name across runs.
	Name string

	// Bin is the executable name to resolve through PATH (or the per-run
	// Bin override). Empty means Name.
	Bin string

	// ProbeKind selects the detection strategy (see ProbeKind).
	ProbeKind ProbeKind

	// ProbeArgs is the detection probe argv; non-empty exactly when
	// ProbeKind is ProbeVersion.
	ProbeArgs []string

	// args builds the typed argv for one canonical target host: the target
	// always appears as its own single argv element, never embedded in a
	// flag value and never shell-joined.
	args func(host asset.Host) []string
}

// Gau returns the gau (lc/gau) descriptor.
//
// Invocation: gau <host> — positional target; gau accepts one or more
// domain arguments directly. Detection: -version (gau's Go-flag parser
// accepts single-dash flags).
func Gau() Tool {
	return Tool{
		Name:      "gau",
		ProbeKind: ProbeVersion,
		ProbeArgs: []string{"-version"},
		args:      func(h asset.Host) []string { return []string{h.Name} },
	}
}

// Waybackurls returns the waybackurls (tomnomnom) descriptor.
//
// Invocation: waybackurls <host> — positional target; upstream reads
// flag.Arg(0) when present, falling back to stdin, so the target is passed
// as one argv element rather than piped. Detection: existence-only — the
// tool has no version flag (its flags are -dates, -no-subs, -get-versions;
// none prints a version), so any probe could only misreport an installed
// tool.
func Waybackurls() Tool {
	return Tool{
		Name:      "waybackurls",
		ProbeKind: ProbeExistence,
		args:      func(h asset.Host) []string { return []string{h.Name} },
	}
}

// Waymore returns the waymore (xnl-h4ck3r) descriptor.
//
// Invocation: waymore -i <host> -mode U — URL-only mode: stdout carries the
// archived URLs and response downloading is never reachable (the -mode value
// R and the default mode B download archived response BODIES, which is
// outside RavenRecon's reconnaissance scope). Detection: --version (real
// argparse version action: prints the version and exits 0).
func Waymore() Tool {
	return Tool{
		Name:      "waymore",
		ProbeKind: ProbeVersion,
		ProbeArgs: []string{"--version"},
		args:      func(h asset.Host) []string { return []string{"-i", h.Name, "-mode", "U"} },
	}
}

// Builtins returns the built-in tools in stable order: gau, waybackurls,
// waymore. Cache keys, selections, and reports all order on this list.
func Builtins() []Tool {
	return []Tool{Gau(), Waybackurls(), Waymore()}
}

// LookupTool returns the built-in tool with the given name.
func LookupTool(name string) (Tool, bool) {
	for _, t := range Builtins() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Args builds the typed argv for one canonical target host. Arguments are
// separate values passed to the runner: the target is never concatenated
// into shell syntax, flags, or a command line.
func (t Tool) Args(target asset.Host) []string {
	if t.args == nil {
		return nil
	}
	return t.args(target)
}

// bin returns the executable to resolve: the descriptor's Bin, else the
// tool's default name.
func (t Tool) bin() string {
	if t.Bin != "" {
		return t.Bin
	}
	return t.Name
}

// DefaultDetectTimeout bounds one detection probe invocation.
const DefaultDetectTimeout = 5 * time.Second

// env is the execution environment for one run: the hardened runner, the
// lookup seam, the capture limits, the detection budget, and per-tool
// executable overrides. Zero values mean production defaults.
type env struct {
	runner        discovery.Runner
	lookup        discovery.LookupFunc
	limits        discovery.Limits
	detectTimeout time.Duration
	bins          map[string]string
}

// sanitized returns e with production defaults applied.
func (e env) sanitized() env {
	if e.runner == nil {
		e.runner = discovery.ExecRunner{}
	}
	if e.lookup == nil {
		e.lookup = exec.LookPath
	}
	if e.detectTimeout <= 0 {
		e.detectTimeout = DefaultDetectTimeout
	}
	if e.limits.MaxOutput <= 0 {
		e.limits.MaxOutput = discovery.DefaultMaxOutput
	}
	return e
}

// binOf resolves the executable for t: the per-run Bin override wins, then
// the descriptor's Bin, then the tool's default name.
func (e env) binOf(t Tool) string {
	if e.bins != nil {
		if b, ok := e.bins[t.Name]; ok && b != "" {
			return b
		}
	}
	return t.bin()
}

// detect checks t's availability per its descriptor. The semantics mirror
// the discovery package's detection contract:
//
//   - Version-probed tools: executable lookup, then the probe through the
//     runner (bounded by the detection timeout), then tolerant version
//     extraction from the bounded capture (stdout first, then stderr). A
//     probe that fails to execute, garbles, times out, or prints no
//     recognizable version is at worst StatusWarn — never StatusMissing,
//     because the executable exists and may still run.
//   - Existence-only tools: executable lookup IS the detection. StatusOK
//     with no probe executed; capabilities are exercised at run time and
//     its failures are surfaced by the ToolResult, never by detection.
func (t Tool) detect(ctx context.Context, e env) discovery.Detection {
	e = e.sanitized()
	d := discovery.Detection{Source: t.Name}

	bin := e.binOf(t)
	path, err := e.lookup(bin)
	if err != nil {
		d.Status = discovery.StatusMissing
		d.Reason = fmt.Sprintf("executable %q not found", bin)
		return d
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
			// The executable disappeared between lookup and execution.
			d.Status = discovery.StatusMissing
			d.Reason = fmt.Sprintf("executable %q not found", bin)
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
// ("Current Version: v2.6.3", "waymore v1.0.0", "gau 2.1.1", ...).
var versionPattern = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:[-+._][0-9A-Za-z]+)*`)

// extractVersion returns the first semver-like token in out, or "".
func extractVersion(out []byte) string {
	if m := versionPattern.Find(out); m != nil {
		return string(m)
	}
	return ""
}
