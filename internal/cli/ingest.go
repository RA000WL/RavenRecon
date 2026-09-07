package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/pipeline/adapt"
)

// The ingest command (v1.8 T12): import existing reconnaissance data
// (plain lists, httpx/dnsx/naabu/katana/nuclei JSON, Burp/ZAP XML, wayback
// CDX/WARC archives) through the SAME pipeline stages a scan uses — there
// is no parallel execution path (locked decision D6). The imported corpus
// REPLACES discovery as the corpus source: the run composes
// [ingest + selected downstream stages], and discover is deliberately not
// available here (discovery of a domain is scan's job).
//
// Structure mirrors scan.go exactly: parse → normalize target → build
// config → resolve cache → wire observer/TUI → pipeline.Run → summary →
// documented exit mapping.

const ingestUsage = `RavenRecon ingest - import existing reconnaissance data

Usage:
  ravenrecon ingest [options] <target> <path> [<path>...]

Imports local data files for one in-scope target and enriches them through
the same pipeline stages a scan uses. Each path is a file or a directory;
directories are walked recursively in deterministic (lexical) order, files
reachable both explicitly and under a listed directory are imported exactly
once, and symlinks inside directories are not followed (a directory holding
only symlinks is an error, never a silent no-op). Path segments containing
"..", FIFOs/devices, and missing entries are rejected.

Format detection is automatic from file content: plain lists (domains,
subdomains, URLs, alive hosts, JS files, IPs, CIDRs), httpx/dnsx/naabu/
katana/nuclei JSON exports, Burp/ZAP XML, and wayback CDX/WARC archives.
There is deliberately NO --type flag: detection is content-based only.

Default pipeline (in this order):

  ingest → dns → httpprobe → urlintel → crawl → techintel → jsintel
  → secrentel → urllive → priority → detect → report

The imported corpus REPLACES discovery as the corpus source; every other
stage is unchanged. Options must come BEFORE the target; everything after
the target is an input path.

Options:
  --stages <a,b>          Restrict the DOWNSTREAM enrichment stages after
                          ingest (comma separated). Known stages: dns,
                          httpprobe, urlintel, crawl, techintel, jsintel,
                          secrentel, urllive, priority, detect, report.
                          Default: all eleven, in pipeline order. "discover"
                          is not available in ingest (discovery of a domain
                          is scan's job); "ingest" always runs first and
                          cannot be reselected.
  --output <dir>          Report output directory. The report stage creates
                          it as needed and commits each report file
                          atomically. Default: ravenrecon-report (under the
                          current working directory).
  --cache <dir>           Open the persistent cache at dir for this run
                          (per-file content-hash keys: an unchanged file is
                          served from cache without re-parsing).
  --no-cache              Disable the cache for this run even if --cache was
                          given (or caching is enabled in configuration).
  --config <file>         JSON config file (flags > env > file > defaults).
  --verbose               Print one line per stage event (stage_started /
                          stage_finished) to stderr as the run progresses.
                          Mutually exclusive with --tui.
  --tui                   Render a live observability frame on stderr while
                          the run progresses (the same frame as scan:
                          phase, stage lifecycle, progress counters,
                          warnings/errors, target and output directory,
                          final summary). Mutually exclusive with --verbose.
  --tui-compact           Condense the --tui frame. Requires --tui.

Scope: imports are filtered against the declared target — hosts and URLs
outside the target's scope never enter the corpus, whatever an input file
contains. Reports attribute every retained asset to its origin
(discovered/imported) with per-asset provenance (importer, original tool,
source file).

Exit codes (identical to scan):
  0   the run completed, or completed with partial results (usable report —
      the summary states the outcome explicitly).
  1   usage/validation errors, cache open failures, and runs that ended
      failed, cancelled, or incomplete (see the summary); also any run
      interrupted by Ctrl-C/SIGTERM, which is still summarized first.

Signals: Ctrl-C or SIGTERM cancels the run gracefully — the partial summary
is still printed and the exit code is 1. A second signal forces an
immediate exit.

Target validation: the domain is normalized through the Phase 2 asset model;
uppercase, surrounding whitespace, and a trailing dot are normalized away.

RavenRecon is intended for authorized security testing and
bug bounty programs where the target is explicitly in scope.
`

// errIngestHelp is returned by parseIngestArgs when the user asked for
// ingest help; runIngest prints the ingest usage and exits cleanly. It
// mirrors errScanHelp.
var errIngestHelp = errors.New("ingest: help requested")

// ingestDownstreamStages returns the eleven downstream stage names in
// pipeline order — pipeline.AllStages() minus discover — derived from the
// pipeline package itself so the CLI copy can never drift from the real
// order (the scan command pins its literal vocabulary with a test; the
// ingest command derives instead, because its selection excludes one name).
func ingestDownstreamStages() []pipeline.StageName {
	var out []pipeline.StageName
	for _, s := range pipeline.AllStages() {
		if s != pipeline.StageDiscover {
			out = append(out, s)
		}
	}
	return out
}

// ingestOptions is the parsed (target, paths, flags) tuple of the ingest
// command.
type ingestOptions struct {
	target string

	// paths are the input files/directories, verbatim; validation and
	// expansion happen in ONE place — the ingest stage's
	// expandIngestPaths — never twice.
	paths []string

	// stages is the ordered downstream selection; nil means all eleven
	// downstream stages (everything except discover).
	stages    []pipeline.StageName
	stagesSet bool

	cacheDir   string
	noCache    bool
	outputDir  string
	verbose    bool
	tui        bool
	tuiCompact bool

	// configPath is --config: JSON config file (flags > env > file >
	// defaults). Empty means defaults + environment only.
	configPath string
}

// parseIngestArgs parses "ingest" arguments. The contract differs from
// scan/discover by necessity — this command takes MULTIPLE positional
// inputs, and Go's flag package stops parsing at the first positional — so
// options must come BEFORE the target: everything after the target is an
// input path (documented in ingestUsage). -h/--help/help anywhere before
// the positionals, and a bare "help" as the first post-option word, print
// ingest usage via errIngestHelp. Validation of flag
// VALUES happens here; the target is validated and normalized through
// asset.NewDomain (the single normalization point) by runIngest, and the
// paths are validated by the ingest stage itself (the single validation
// point for existence/type/traversal).
func parseIngestArgs(args []string) (ingestOptions, error) {
	if len(args) == 0 {
		return ingestOptions{}, fmt.Errorf("ingest: missing target and input path arguments (usage: ravenrecon ingest [options] <target> <path> [<path>...])")
	}
	switch args[0] {
	case "-h", "--help", "help":
		return ingestOptions{}, errIngestHelp
	}

	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed
	stages := fs.String("stages", "", "comma-separated downstream stage names")
	cacheDir := fs.String("cache", "", "cache directory")
	noCache := fs.Bool("no-cache", false, "disable the cache for this run")
	outputDir := fs.String("output", "", "report output directory")
	configPath := fs.String("config", "", "JSON config file (flags > env > file > defaults)")
	verbose := fs.Bool("verbose", false, "print stage events to stderr")
	tuiFlag := fs.Bool("tui", false, "render a live observability frame on stderr")
	tuiCompact := fs.Bool("tui-compact", false, "condense the --tui frame (requires --tui)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ingestOptions{}, errIngestHelp
		}
		return ingestOptions{}, fmt.Errorf("ingest: %w", err)
	}

	positional := fs.Args()
	if len(positional) == 0 {
		return ingestOptions{}, fmt.Errorf("ingest: missing target argument (usage: ravenrecon ingest [options] <target> <path> [<path>...])")
	}
	// A bare "help" following the options is a help request per the
	// contract above — never a target domain that would fail
	// normalization with a confusing invalid-target error.
	if positional[0] == "help" {
		return ingestOptions{}, errIngestHelp
	}
	if len(positional) == 1 {
		return ingestOptions{}, fmt.Errorf("ingest: missing input path argument after %q (usage: ravenrecon ingest [options] <target> <path> [<path>...])", positional[0])
	}
	for _, p := range positional[1:] {
		if strings.HasPrefix(p, "-") && len(p) > 1 {
			return ingestOptions{}, fmt.Errorf("ingest: %q looks like an option but follows the target — options must come BEFORE the target; everything after it is an input path", p)
		}
	}

	opts := ingestOptions{
		target:     positional[0],
		paths:      positional[1:],
		noCache:    *noCache,
		verbose:    *verbose,
		tui:        *tuiFlag,
		tuiCompact: *tuiCompact,
		cacheDir:   *cacheDir,
		outputDir:  *outputDir,
		configPath: *configPath,
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "stages" {
			opts.stagesSet = true
		}
	})

	if opts.stagesSet {
		names := splitList(*stages)
		if len(names) == 0 {
			return ingestOptions{}, fmt.Errorf("ingest: --stages: empty stage list")
		}
		for _, n := range names {
			switch n {
			case string(pipeline.StageDiscover):
				return ingestOptions{}, fmt.Errorf("ingest: --stages: %q is not available in ingest — the imported corpus replaces discovery as the corpus source (discovery of a domain is scan's job)", n)
			case string(pipeline.StageIngest):
				return ingestOptions{}, fmt.Errorf("ingest: --stages: the ingest stage always runs first; --stages selects downstream stages only")
			}
			name := pipeline.StageName(n)
			if !pipeline.ValidStage(name) {
				return ingestOptions{}, fmt.Errorf("ingest: --stages: unknown stage %q (known stages: %s)", n, strings.Join(stageNames(ingestDownstreamStages()), ", "))
			}
			opts.stages = append(opts.stages, name)
		}
	}
	// Identical observability-surface rules as scan: exactly one event sink
	// (--tui XOR --verbose), and --tui-compact modifies --tui so it
	// requires it (never a silent no-op).
	if opts.tui && opts.verbose {
		return ingestOptions{}, fmt.Errorf("ingest: --tui and --verbose are mutually exclusive")
	}
	if opts.tuiCompact && !opts.tui {
		return ingestOptions{}, fmt.Errorf("ingest: --tui-compact requires --tui")
	}
	// An explicitly empty --output "" selects the documented default output
	// directory (mirroring scan). An explicitly empty --cache "" is treated
	// as "no cache directory flag".
	if opts.outputDir == "" {
		opts.outputDir = defaultOutputDir
	}
	return opts, nil
}

// stageNames renders a StageName slice as strings.
func stageNames(names []pipeline.StageName) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = string(n)
	}
	return out
}

// buildIngestConfig maps the parsed ingest options onto the pipeline run
// configuration: the stage list is ALWAYS [ingest + selected downstream]
// (ingest first, by construction — the operator cannot reorder or remove
// it), and the ingest stage's params carry the input paths newline-joined
// (newline is the ONLY separator — commas are reserved inside paths and
// rejected at expansion time; see expandIngestPaths). Mirroring
// buildScanConfig, no new config.Config fields and no bounds overrides: the
// runner resolves defaults.
func buildIngestConfig(opts ingestOptions, target asset.Domain) (pipeline.ScanConfig, error) {
	downstream := opts.stages
	if !opts.stagesSet {
		downstream = ingestDownstreamStages()
	}
	stages := make([]pipeline.StageName, 0, 1+len(downstream))
	stages = append(stages, pipeline.StageIngest)
	stages = append(stages, downstream...)

	cfg := pipeline.ScanConfig{
		Target:    target,
		Stages:    stages,
		OutputDir: opts.outputDir,
		StageParams: map[pipeline.StageName]map[string]string{
			pipeline.StageIngest: {"paths": strings.Join(opts.paths, "\n")},
		},
	}
	return cfg, nil
}

// ingestCache opens the persistent cache for an ingest run. It mirrors
// scanCache/resolveScanCacheDir semantics exactly (explicit --cache dir wins
// over configuration; configuration-enabled otherwise; --no-cache forces
// off on every path) with ingest-prefixed error wrapping — the resolution
// logic is duplicated rather than shared so the error messages name the
// command the user actually ran.
func ingestCache(cfg config.Config, opts ingestOptions, obs event.Observer) (cache.Cache, error) {
	if opts.noCache {
		return nil, nil
	}
	dir := opts.cacheDir
	if dir == "" {
		if !cfg.Cache.Enabled {
			return nil, nil
		}
		dir = cfg.Cache.Dir
		if dir == "" {
			d, err := cache.DefaultDir()
			if err != nil {
				return nil, fmt.Errorf("ingest: resolve default cache directory: %w", err)
			}
			dir = d
		}
	}
	openOpts := []cache.Option{cache.WithTTL(cfg.Cache.TTL)}
	if obs != nil {
		openOpts = append(openOpts, cache.WithObserver(obs))
	}
	c, err := cache.Open(dir, openOpts...)
	if err != nil {
		return nil, fmt.Errorf("ingest: open cache at %s: %w", dir, err)
	}
	return c, nil
}

// newIngestStages returns the production ingest pipeline: the ingest stage
// composed with ALL eleven downstream adapters (constructed with their
// production nil seams, identical to newScanStages minus the discovery
// adapter). The runner resolves provided stages against cfg.Stages by name,
// so a trimmed --stages selection simply skips the unselected adapters —
// construction is total, invocation follows the selection. The cfg
// parameter exists for seam-shape parity with newScanStages; production
// adapters derive everything from their StageInput.
func newIngestStages(cfg pipeline.ScanConfig) []pipeline.Stage {
	return []pipeline.Stage{
		adapt.NewIngestStage(),
		adapt.NewDNSStage(nil),
		adapt.NewHTTPProbeStage(nil),
		adapt.NewURLIntelStage(nil, nil),
		adapt.NewCrawlStage(nil),
		adapt.NewTechIntelStage(nil),
		adapt.NewJSIntelStage(nil),
		adapt.NewSecretIntelStage(nil),
		adapt.NewUrlliveStage(nil),
		adapt.NewPriorityStage(nil, nil),
		adapt.NewDetectStage(nil),
		adapt.NewReportStage(nil),
	}
}

// runIngest parses the ingest arguments, normalizes the target through
// asset.NewDomain (the single normalization point), builds the pipeline
// configuration from the flags, runs [ingest + selected downstream] through
// pipeline.Run with the real wall clock, prints the run summary to w, and
// maps the outcome to the DOCUMENTED EXIT SEMANTICS — identical to scan:
//
//	completed → nil (exit 0)
//	partial   → nil (exit 0; the summary states the run was partial)
//	failed / cancelled / incomplete → error (main prints it and exits 1)
//
// Usage/validation errors and cache open failures return errors too. A run
// context cancelled mid-run (Ctrl-C/SIGTERM) returns a context-wrapped
// error AFTER the summary is printed — partial results are never lost.
//
// The stages parameter is the hermetic test seam (production call sites
// pass newIngestStages); tuiNew is the same seam for --tui (production:
// newScanTUI — the TUI layer is command-independent). Verbose lines and
// the TUI frame go to os.Stderr (diagnostics); the summary goes to w (the
// machine-facing result), mirroring runScan.
func runIngest(ctx context.Context, w io.Writer, args []string, stages func(pipeline.ScanConfig) []pipeline.Stage, tuiNew scanTUIFactory) error {
	opts, err := parseIngestArgs(args)
	if err != nil {
		if errors.Is(err, errIngestHelp) {
			return printIngestUsage(w)
		}
		return err
	}
	target, err := asset.NewDomain(opts.target, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("ingest: invalid target %q: %w", opts.target, err)
	}
	cfg, err := buildIngestConfig(opts, target)
	if err != nil {
		return err
	}
	base, err := resolveBaseConfig(opts.configPath)
	if err != nil {
		return err
	}
	fwd := &forwardingObserver{}
	c, err := ingestCache(base, opts, fwd)
	if err != nil {
		return err
	}
	if opts.verbose {
		// Same sink as scan --verbose: one compact line per stage event,
		// synchronously, in stage order. The shared cache handle joins
		// it via the forwarder.
		so := &stageObserver{w: os.Stderr}
		cfg.Observer = so
		fwd.set(so)
	}
	if opts.tui {
		// Identical wiring to runScan's --tui block: one bus, one bounded
		// subscriber, one controller goroutine, joined on every return
		// path; a Run result is a stderr warning that never changes exit
		// semantics. (The full lifecycle rationale lives on runScan.)
		if tuiNew == nil {
			return fmt.Errorf("ingest: --tui: no TUI runner available")
		}
		bus := event.NewBus(nil)
		sub, err := bus.Subscribe(tuiSubscriberBuffer)
		if err != nil {
			bus.Close()
			return fmt.Errorf("ingest: --tui: subscribe: %w", err)
		}
		// Run-level metadata FIRST, before the controller starts
		// consuming (NEW-82) — identical to runScan.
		bus.Publish(event.Event{
			Kind:    event.KindRunMetadata,
			Payload: event.RunMetadata{Target: target.String(), OutputDir: cfg.OutputDir},
		})
		ctl, err := tuiNew(config.TUIConfig{
			Enabled: true,
			Compact: opts.tuiCompact,
			Color:   resolveTUIColor(os.Stderr),
		}, sub, os.Stderr)
		if err != nil {
			bus.Close()
			return fmt.Errorf("ingest: --tui: %w", err)
		}
		cfg.Observer = bus
		fwd.set(bus)
		tuiDone := make(chan error, 1)
		go func() { tuiDone <- ctl.Run(ctx) }()
		defer func() {
			sub.Close()
			if terr := <-tuiDone; terr != nil {
				fmt.Fprintf(os.Stderr, "tui: %v\n", terr)
			}
			bus.Close()
		}()
	}
	rep, err := pipeline.Run(ctx, cfg, c, wallClock{}, stages(cfg))
	if err != nil {
		return fmt.Errorf("ingest: %w", err)
	}
	if err := printIngestSummary(w, rep, cfg.OutputDir, c != nil); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("ingest: run interrupted: %w", ctx.Err())
	}
	switch rep.Outcome {
	case pipeline.OutcomeCompleted, pipeline.OutcomePartial:
		return nil
	case pipeline.OutcomeFailed:
		return fmt.Errorf("ingest: run outcome failed: one or more stages failed (see the summary)")
	case pipeline.OutcomeCancelled:
		return fmt.Errorf("ingest: run outcome cancelled (see the summary)")
	default: // OutcomeIncomplete
		return fmt.Errorf("ingest: run outcome incomplete: the retained set is incomplete (see the summary)")
	}
}

func printIngestUsage(w io.Writer) error {
	_, err := io.WriteString(w, ingestUsage)
	return err
}

// printIngestSummary renders one ingest run's summary in printScanSummary's
// shape with an ingest header: the target, the cache state, the outcome,
// one honest line per stage, and the committed report files. Durations and
// timestamps are absent (determinism, mirroring printScanSummary); temp
// render files are excluded via the shared reportFiles helper.
func printIngestSummary(w io.Writer, rep pipeline.RunReport, outputDir string, cached bool) error {
	if _, err := fmt.Fprintf(w, "RavenRecon ingest: %s (cache: %s)\n\n", rep.Target.Name, onOff(cached)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Outcome: %s\n", rep.Outcome); err != nil {
		return err
	}
	if len(rep.StickyFlags) > 0 {
		flags := make([]string, 0, len(rep.StickyFlags))
		for f := range rep.StickyFlags {
			flags = append(flags, f)
		}
		sort.Strings(flags)
		if _, err := fmt.Fprintf(w, "Flags: %s\n", strings.Join(flags, " ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "Processed: %d  Failed: %d\n\n", rep.ItemsProcessed, rep.ItemsFailed); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "Stages:\n"); err != nil {
		return err
	}
	for _, sr := range rep.Stages {
		var b strings.Builder
		fmt.Fprintf(&b, "  %-10s %-10s processed=%d failed=%d", sr.Name, sr.Outcome, sr.ItemsProcessed, sr.ItemsFailed)
		if sr.Truncated {
			b.WriteString(" truncated")
		}
		if len(sr.StickyFlags) > 0 {
			flags := make([]string, 0, len(sr.StickyFlags))
			for f := range sr.StickyFlags {
				flags = append(flags, f)
			}
			sort.Strings(flags)
			fmt.Fprintf(&b, " flags=%s", strings.Join(flags, ","))
		}
		if sr.Err != nil {
			fmt.Fprintf(&b, " error=%q", sr.Err.Error())
		}
		if _, err := fmt.Fprintln(w, b.String()); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nOutput: %s\n", outputDir); err != nil {
		return err
	}
	files, err := reportFiles(outputDir)
	if err != nil {
		// Honest note, never a failed summary (mirrors printScanSummary).
		if _, werr := fmt.Fprintf(w, "  (unable to list: %v)\n", err); werr != nil {
			return werr
		}
		return nil
	}
	for _, f := range files {
		if _, err := fmt.Fprintf(w, "  %s\n", f); err != nil {
			return err
		}
	}
	if len(files) == 0 {
		if _, err := fmt.Fprint(w, "  (no report files — the report stage committed nothing)\n"); err != nil {
			return err
		}
	}
	return nil
}
