package discovery

import (
	"context"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Source adapts one passive subdomain discovery tool. The core pipeline acts
// only on this interface; every tool-specific behavior — flag assembly,
// detection strategy, output parsing — lives inside the adapters, so the
// pipeline contains no tool-name branching.
type Source interface {
	// Name is the stable source name ("subfinder", "assetfinder", "amass").
	Name() string

	// Detect checks the tool's availability and capability. Detection is
	// bounded by the environment's detect timeout; a broken or missing
	// version flag never reports the tool missing.
	Detect(ctx context.Context) Detection

	// Discover executes passive enumeration for target and returns the
	// discovered subdomains normalized through the Phase 2 asset model,
	// deduplicated by identity and sorted. It performs no caching and no
	// scheduling — the pipeline owns both. Cancellation, missing
	// executables, and non-zero exits are reported as errors (never a
	// panic), and captured output is always bounded.
	Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error)
}

// DiscoverResult is the structured outcome of one adapter execution.
type DiscoverResult struct {
	// Hosts are the normalized, per-source deduplicated, sorted hosts.
	Hosts []asset.Host

	// Malformed counts lines that did not normalize to a valid host. It is
	// diagnostics only and never poisons the results.
	Malformed int

	// Truncated reports that stdout hit the capture cap: the captured set is
	// incomplete by definition.
	Truncated bool
}

// builtInNames returns the built-in sources in stable order. Cache keys, the
// CLI, and the doctor all order on this.
func builtInNames() []string { return []string{"subfinder", "assetfinder", "amass", "chaos"} }

// registry maps source names to their adapters, constructed with the tool
// environment for one run.
var registry = map[string]func(e toolEnv) Source{
	"subfinder":   func(e toolEnv) Source { return subfinder{env: e} },
	"assetfinder": func(e toolEnv) Source { return assetfinder{env: e} },
	"amass":       func(e toolEnv) Source { return amass{env: e} },
	"chaos":       func(e toolEnv) Source { return chaos{env: e} },
	"asnmap":      func(e toolEnv) Source { return asnmap{env: e} },
}

// runAndParse executes one tool invocation and normalizes its stdout. It is
// shared by all three adapters; tool differences are the argv passed in.
//
// No error path discards captured output. The Runner contract guarantees a
// final, quiescent capture on every path — including a cancellation kill,
// where Run returns the bytes streamed before the process died alongside the
// joined context error (runner.go waitCommand/ExecRunner.Run). The capture is
// therefore parsed even when Run fails, so a source killed mid-stream by a
// deadline or a forced shutdown retains whatever it enumerated before the
// kill: the caller receives the parsed result AND the error, and classify
// maps the outcome honestly (cancelled for context errors, partial for other
// failures with usable output) while the retained hosts propagate into the
// report (NEW-94: a fully-enumerated host corpus must never vanish because
// the process was killed after the data had already been captured).
//
// A non-zero exit likewise does not discard captured output: the caller
// receives both the parsed partial result and an error carrying the exit
// code, and the pipeline classifies partial results as incomplete rather
// than failing them.
func runAndParse(ctx context.Context, e toolEnv, name string, args []string) (DiscoverResult, error) {
	e = e.sanitized()
	path, err := e.lookup(e.binOrName())
	if err != nil {
		if !lookupMissing(err) {
			return DiscoverResult{}, fmt.Errorf("%s: resolve executable %s: %w", name, e.binOrName(), err)
		}
		return DiscoverResult{}, fmt.Errorf("%s: %w (%s)", name, ErrExecutableNotFound, e.binOrName())
	}
	res, rerr := e.runner.Run(ctx, Cmd{Path: path, Args: args}, e.limits)
	// Parse whatever was captured, error or not: res is valid on every path
	// (a start failure yields the zero RunResult, whose empty capture parses
	// to an empty result — harmless), and the buffers are quiescent before
	// Run returned.
	hosts, malformed := parseHostLines(res.Stdout, e.provenance())
	dres := DiscoverResult{Hosts: hosts, Malformed: malformed, Truncated: res.StdoutTruncated}
	if rerr != nil {
		return dres, fmt.Errorf("%s: %w", name, rerr)
	}
	if res.ExitCode != 0 {
		return dres, fmt.Errorf("%s: exited with code %d", name, res.ExitCode)
	}
	return dres, nil
}
