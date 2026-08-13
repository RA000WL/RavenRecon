package discovery

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Status classifies the detection of one source's tool.
type Status string

const (
	// StatusOK: the executable exists, runs, and its capability check
	// succeeded (version determined, or — for tools without a version flag —
	// a harmless invocation produced expected output).
	StatusOK Status = "ok"

	// StatusWarn: the executable exists but part of the check failed — for
	// example the version flag is unsupported, produced no recognizable
	// version, or could not be executed. A broken version command must never
	// cause a correctly installed tool to be reported missing.
	StatusWarn Status = "warn"

	// StatusMissing: the executable could not be found at all.
	StatusMissing Status = "missing"
)

// String implements fmt.Stringer.
func (s Status) String() string { return string(s) }

// Label returns the bracketed CLI label: [OK], [WARN], or [MISSING].
func (s Status) Label() string {
	switch s {
	case StatusOK:
		return "[OK]"
	case StatusWarn:
		return "[WARN]"
	case StatusMissing:
		return "[MISSING]"
	default:
		return "[" + string(s) + "]"
	}
}

// Detection is the result of checking one source's tool availability. It is
// shared by the discover command and the doctor command; there is no second
// detection implementation.
type Detection struct {
	// Source is the source name ("subfinder", ...).
	Source string

	// Status is the overall classification ([OK]/[WARN]/[MISSING]).
	Status Status

	// Reason explains how the classification was determined, for human
	// output.
	Reason string

	// Exists reports whether the executable was found.
	Exists bool

	// Version is the detected tool version, or "" when it cannot be
	// determined (assetfinder has no version flag).
	Version string

	// Capable reports whether the capability check succeeded.
	Capable bool
}

// LookupFunc resolves an executable name or path to its filesystem location,
// mirroring exec.LookPath. It is a seam for tests: nil means exec.LookPath.
type LookupFunc func(name string) (string, error)

// toolEnv is the per-tool plumbing shared by every adapter. A source is
// constructed with exactly one env; tests inject fakes through its seams.
type toolEnv struct {
	name          string
	bin           string // override; empty means PATH lookup of name
	runner        Runner
	lookup        LookupFunc
	limits        Limits
	detectTimeout time.Duration
	now           func() time.Time
}

// sanitized returns e with nil seams replaced by production defaults and
// non-positive tunables normalized.
func (e toolEnv) sanitized() toolEnv {
	if e.runner == nil {
		e.runner = ExecRunner{}
	}
	if e.lookup == nil {
		e.lookup = exec.LookPath
	}
	if e.detectTimeout <= 0 {
		e.detectTimeout = defaultDetectTimeout
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e
}

// binOrName returns the executable to resolve: the configured override, or
// the tool's default name (PATH lookup).
func (e toolEnv) binOrName() string {
	if e.bin != "" {
		return e.bin
	}
	return e.name
}

// provenance mirrors asset.NewProvenance with an injectable clock so tests
// are deterministic. The source is the tool name, so the same identity
// discovered by two tools carries two distinct provenance sources.
func (e toolEnv) provenance() asset.Provenance {
	return asset.Provenance{Source: e.name, DiscoveredAt: e.now().UTC()}
}

// detectMode selects how a detection invocation is classified.
type detectMode int

const (
	// modeVersion: the invocation is a version flag; success requires a
	// recognizable version in stdout.
	modeVersion detectMode = iota
	// modeCapability: the invocation is a harmless capability probe; success
	// requires the process to run and produce some output.
	modeCapability
)

// detectVersioned detects a tool that supports a version flag (subfinder,
// amass). An exit failure, timeout, or unrecognizable output is a WARN, never
// a MISSING.
func detectVersioned(ctx context.Context, e toolEnv, flag string) Detection {
	return detectExec(ctx, e, []string{flag}, modeVersion)
}

// detectCapability detects a tool without a reliable version flag
// (assetfinder): existence plus a harmless invocation whose output proves the
// binary runs. assetfinder has no version flag, so this is the documented
// detection mechanism for it.
func detectCapability(ctx context.Context, e toolEnv, flag string) Detection {
	return detectExec(ctx, e, []string{flag}, modeCapability)
}

func detectExec(ctx context.Context, e toolEnv, args []string, mode detectMode) Detection {
	e = e.sanitized()
	d := Detection{Source: e.name}
	ctx, cancel := context.WithTimeout(ctx, e.detectTimeout)
	defer cancel()
	path, err := e.lookup(e.binOrName())
	if err != nil {
		d.Status = StatusMissing
		d.Reason = fmt.Sprintf("executable %q not found", e.binOrName())
		return d
	}
	d.Exists = true
	res, err := e.runner.Run(ctx, Cmd{Path: path, Args: args}, e.limits)
	if err != nil {
		if errors.Is(err, ErrExecutableNotFound) {
			// The executable disappeared between lookup and execution.
			d.Status = StatusMissing
			d.Reason = fmt.Sprintf("executable %q not found", e.binOrName())
			return d
		}
		d.Status = StatusWarn
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			d.Reason = fmt.Sprintf("executable %s exists but the check was cancelled: %v", path, err)
		} else {
			d.Reason = fmt.Sprintf("executable %s exists but could not be executed: %v", path, err)
		}
		return d
	}
	switch mode {
	case modeVersion:
		// Version strings can be printed to either stream (subfinder's banner
		// goes to stderr, amass's to stdout); both are bounded captures.
		v := extractVersion(res.Stdout)
		if v == "" {
			v = extractVersion(res.Stderr)
		}
		if v != "" {
			d.Status = StatusOK
			d.Version = v
			d.Capable = true
			d.Reason = fmt.Sprintf("executable %s; version %s", path, v)
			return d
		}
		d.Status = StatusWarn
		d.Reason = fmt.Sprintf("executable %s exists; %s produced no recognizable version", path, strings.Join(args, " "))
		return d
	default: // modeCapability
		if len(strings.TrimSpace(string(res.Stdout)))+len(strings.TrimSpace(string(res.Stderr))) > 0 {
			d.Status = StatusOK
			d.Capable = true
			d.Reason = fmt.Sprintf("executable %s; capability verified via %s (version flag unsupported)", path, strings.Join(args, " "))
			return d
		}
		d.Status = StatusWarn
		d.Reason = fmt.Sprintf("executable %s exists; %s produced no output, capability not verified", path, strings.Join(args, " "))
		return d
	}
}

// versionPattern matches the first semver-like token in tool output, with an
// optional leading "v". It is intentionally tolerant: -version output formats
// differ across tools and versions ("Current Version: v2.6.3", "v3.23.0", ...).
var versionPattern = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:[-+._][0-9A-Za-z]+)*`)

// extractVersion returns the first version-like token in out, or "".
func extractVersion(out []byte) string {
	if m := versionPattern.Find(out); m != nil {
		return string(m)
	}
	return ""
}
