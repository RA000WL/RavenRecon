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
func builtInNames() []string { return []string{"subfinder", "assetfinder", "amass"} }

// registry maps source names to their adapters, constructed with the tool
// environment for one run.
var registry = map[string]func(e toolEnv) Source{
	"subfinder":   func(e toolEnv) Source { return subfinder{env: e} },
	"assetfinder": func(e toolEnv) Source { return assetfinder{env: e} },
	"amass":       func(e toolEnv) Source { return amass{env: e} },
}

// runAndParse executes one tool invocation and normalizes its stdout. It is
// shared by all three adapters; tool differences are the argv passed in.
//
// A non-zero exit does not discard captured output: the caller receives both
// the parsed partial result and an error carrying the exit code, and the
// pipeline classifies partial results as incomplete rather than failing them.
func runAndParse(ctx context.Context, e toolEnv, name string, args []string) (DiscoverResult, error) {
	e = e.sanitized()
	path, err := e.lookup(e.binOrName())
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: %w (%s)", name, ErrExecutableNotFound, e.binOrName())
	}
	res, err := e.runner.Run(ctx, Cmd{Path: path, Args: args}, e.limits)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: %w", name, err)
	}
	hosts, malformed := parseHostLines(res.Stdout, e.provenance())
	dres := DiscoverResult{Hosts: hosts, Malformed: malformed, Truncated: res.StdoutTruncated}
	if res.ExitCode != 0 {
		return dres, fmt.Errorf("%s: exited with code %d", name, res.ExitCode)
	}
	return dres, nil
}
