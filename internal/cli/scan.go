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
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/pipeline/adapt"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/tui"
)

const scanUsage = `RavenRecon scan - end-to-end reconnaissance pipeline

Usage:
  ravenrecon scan <target> [options]

Runs the full deterministic pipeline for one domain target:

  discover → dns → httpprobe → urlintel → crawl → techintel → jsintel
  → secrentel → priority → detect → report

Options (after the target):
  --stages <a,b>          Restrict the run to the given stages (comma
                          separated). Known stages: discover, dns, httpprobe,
                          urlintel, crawl, techintel, jsintel, secrentel, priority,
                          detect, report. Default: all eleven, in pipeline order.
  --sources <a,b>         Restrict the discovery stage's passive sources
                          (subfinder, assetfinder, amass).
  --request-timeout <d>   Per-request timeout for the httpprobe stage (Go
                          duration, e.g. 10s). 0 = engine default.
  --concurrency <n>       Worker concurrency override for every selected
                          stage (>= 1).
  --timeout <d>           Per-stage deadline override for every selected
                          stage (Go duration; 0 = no per-job deadline).
  --cache <dir>           Open the persistent cache at dir for this run.
  --no-cache              Disable the cache for this run even if --cache was
                          given (or caching is enabled in configuration).
  --output <dir>          Report output directory. The report stage creates
                          it as needed and commits each report file
                          atomically; re-running into the same directory
                          replaces previously completed report files.
                          Default: ravenrecon-report (under the current
                          working directory).
  --verbose               Print one line per stage event (stage_started /
                          stage_finished) to stderr as the run progresses.
                          Mutually exclusive with --tui.
  --tui                   Render a live observability frame on stderr while
                          the run progresses: stage lifecycle, progress,
                          worker dashboard, throughput, interesting assets,
                          errors, and one deterministic final summary
                          frame. Mutually exclusive with --verbose.
  --tui-compact           Condense the --tui frame (no per-worker or
                          resource sections). Requires --tui.

Discovery is passive-only. It invokes external tools in their passive modes:
  subfinder -d <domain> -silent, assetfinder <domain>,
  amass enum -passive -d <domain>.
Run 'ravenrecon doctor' to check which discovery tools are installed. No
active enumeration, brute force, or intel modes are ever run.

The default run carries NO detection rules (the framework ships no rules, by
design), so the detect stage completes with zero findings unless a caller
supplies a rule registry programmatically.

Exit codes:
  0   the run completed, or completed with partial results (usable report —
      the summary states the outcome explicitly).
  1   usage/validation errors, cache open failures, and runs that ended
      failed, cancelled, or incomplete (see the summary); also any run
      interrupted by Ctrl-C/SIGTERM, which is still summarized first.

--tui renders on stderr as the run progresses and never changes the summary
(stdout) or the exit codes: the frame is live diagnostics, the summary is
the machine-facing result, and a TUI write failure (for example a broken
pipe) or shutdown reason (for example the run context's cancellation) is
a 'tui:' warning on stderr only.

Signals: Ctrl-C or SIGTERM cancels the run gracefully — the partial summary
is still printed and the exit code is 1. A second signal forces an immediate
exit.

Target validation: the domain is normalized through the Phase 2 asset model;
uppercase, surrounding whitespace, and a trailing dot are normalized away.

RavenRecon is intended for authorized security testing and
bug bounty programs where the target is explicitly in scope.
`

// stageVocabularyCLI lists the eleven pipeline stage names in pipeline order
// for usage and validation errors. It mirrors pipeline.stageVocabulary,
// which is deliberately unexported; the CLI keeps its own copy in sync
// with pipeline.AllStages (pinned by TestScanStageVocabularyMatchesPipeline).
const stageVocabularyCLI = "discover, dns, httpprobe, urlintel, crawl, techintel, jsintel, secrentel, priority, detect, report"

// defaultOutputDir is the --output default: a directory under the current
// working directory, created as needed by the report engine.
const defaultOutputDir = "ravenrecon-report"

// scanOptions is the parsed (target, flags) pair of the scan command.
type scanOptions struct {
	target string

	// stages is the ordered stage selection; nil means all ten stages.
	stages    []pipeline.StageName
	stagesSet bool

	// sources is the discovery stage's source selection; nil means every
	// built-in source.
	sources    []string
	sourcesSet bool

	// requestTimeout is the validated non-negative Go duration string passed
	// to the httpprobe stage's "request_timeout" param ("" or "0" = engine
	// default; negative values are rejected in parseScanArgs).
	requestTimeout    string
	requestTimeoutSet bool

	// concurrency is the per-stage worker override (0 = unset).
	concurrency    int
	concurrencySet bool

	// timeout is the per-stage deadline override (0 = no per-job deadline,
	// the engine default).
	timeout    time.Duration
	timeoutSet bool

	cacheDir  string
	noCache   bool
	outputDir string
	verbose   bool

	// tui enables the live observability frame on stderr (--tui); it is
	// mutually exclusive with verbose. tuiCompact condenses the frame
	// (--tui-compact) and requires tui.
	tui        bool
	tuiCompact bool
}

// parseScanArgs parses "scan" arguments: exactly one target domain,
// followed by options. Options must come after the target (the target is
// positional); -h/--help anywhere prints scan usage via errScanHelp.
// Validation happens here for flag values (stage names against the fixed
// vocabulary, durations, concurrency); the target itself is validated and
// normalized through asset.NewDomain — the single normalization point —
// by runScan, mirroring how runDiscover handles the discover target.
func parseScanArgs(args []string) (scanOptions, error) {
	if len(args) == 0 {
		return scanOptions{}, fmt.Errorf("scan: missing target argument (usage: ravenrecon scan <target> [options])")
	}
	switch args[0] {
	case "-h", "--help", "help":
		return scanOptions{}, errScanHelp
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed
	stages := fs.String("stages", "", "comma-separated stage names")
	sources := fs.String("sources", "", "comma-separated discovery source names")
	requestTimeout := fs.String("request-timeout", "", "httpprobe per-request timeout (Go duration)")
	concurrency := fs.Int("concurrency", 0, "worker concurrency override (>= 1)")
	timeout := fs.String("timeout", "", "per-stage deadline (Go duration; 0 = none)")
	cacheDir := fs.String("cache", "", "cache directory")
	noCache := fs.Bool("no-cache", false, "disable the cache for this run")
	outputDir := fs.String("output", "", "report output directory")
	verbose := fs.Bool("verbose", false, "print stage events to stderr")
	tuiFlag := fs.Bool("tui", false, "render a live observability frame on stderr")
	tuiCompact := fs.Bool("tui-compact", false, "condense the --tui frame (requires --tui)")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return scanOptions{}, errScanHelp
		}
		return scanOptions{}, fmt.Errorf("scan: %w", err)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return scanOptions{}, fmt.Errorf("scan: unexpected argument(s) %q (usage: ravenrecon scan <target> [options])", rest[0])
	}

	opts := scanOptions{
		target:     args[0],
		noCache:    *noCache,
		verbose:    *verbose,
		tui:        *tuiFlag,
		tuiCompact: *tuiCompact,
		cacheDir:   *cacheDir,
		outputDir:  *outputDir,
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "stages":
			opts.stagesSet = true
		case "sources":
			opts.sourcesSet = true
		case "request-timeout":
			opts.requestTimeoutSet = true
		case "concurrency":
			opts.concurrencySet = true
		case "timeout":
			opts.timeoutSet = true
		}
	})

	if opts.stagesSet {
		// Empty or all-empty selections are user errors, mirroring the
		// discover --sources handling: only a MISSING flag may mean
		// "everything".
		names := splitList(*stages)
		if len(names) == 0 {
			return scanOptions{}, fmt.Errorf("scan: --stages: empty stage list")
		}
		for _, n := range names {
			name := pipeline.StageName(n)
			if !pipeline.ValidStage(name) {
				return scanOptions{}, fmt.Errorf("scan: --stages: unknown stage %q (known stages: %s)", n, stageVocabularyCLI)
			}
			opts.stages = append(opts.stages, name)
		}
	}
	if opts.sourcesSet {
		for _, s := range splitList(*sources) {
			opts.sources = append(opts.sources, s)
		}
		if len(opts.sources) == 0 {
			return scanOptions{}, fmt.Errorf("scan: --sources: empty source list")
		}
	}
	if opts.requestTimeoutSet {
		if *requestTimeout == "" {
			return scanOptions{}, fmt.Errorf("scan: --request-timeout: empty duration")
		}
		d, err := time.ParseDuration(*requestTimeout)
		if err != nil {
			return scanOptions{}, fmt.Errorf("scan: --request-timeout: invalid duration %q: %v", *requestTimeout, err)
		}
		// Negative values are rejected outright: the engine treats d <= 0
		// as its 0 = default (10 s), so a negative value would be silently
		// absorbed otherwise (mirroring --timeout's must-be->= 0 check;
		// 0 itself stays valid = the engine default).
		if d < 0 {
			return scanOptions{}, fmt.Errorf("scan: --request-timeout: must be >= 0 (got %s)", d)
		}
		opts.requestTimeout = *requestTimeout
	}
	if opts.concurrencySet && *concurrency < 1 {
		return scanOptions{}, fmt.Errorf("scan: --concurrency: must be >= 1 (got %d)", *concurrency)
	} else if opts.concurrencySet {
		opts.concurrency = *concurrency
	}
	if opts.timeoutSet {
		if *timeout == "" {
			return scanOptions{}, fmt.Errorf("scan: --timeout: empty duration")
		}
		d, err := time.ParseDuration(*timeout)
		if err != nil {
			return scanOptions{}, fmt.Errorf("scan: --timeout: invalid duration %q: %v", *timeout, err)
		}
		if d < 0 {
			return scanOptions{}, fmt.Errorf("scan: --timeout: must be >= 0 (got %s)", d)
		}
		opts.timeout = d
	}
	// --tui and --verbose are mutually exclusive: the frame is the live
	// observability surface, the one-line-per-event sink is the other; a
	// run has exactly one event sink (ScanConfig.Observer) and the flags
	// must never silently pick one. --tui-compact only modifies the frame,
	// so it requires --tui (a compact frame without a frame is a usage
	// error, never a silent no-op).
	if opts.tui && opts.verbose {
		return scanOptions{}, fmt.Errorf("scan: --tui and --verbose are mutually exclusive")
	}
	if opts.tuiCompact && !opts.tui {
		return scanOptions{}, fmt.Errorf("scan: --tui-compact requires --tui")
	}
	// An explicitly empty --cache "" is treated as "no cache directory
	// flag": scanCache then falls back to the configured/default cache
	// directory (mirroring an absent flag). An explicitly empty --output
	// "" selects the documented default output directory.
	if opts.outputDir == "" {
		opts.outputDir = defaultOutputDir
	}
	return opts, nil
}

// splitList splits a comma-separated flag value into trimmed, non-empty
// elements.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// buildScanConfig maps the parsed scan options onto the pipeline run
// configuration. It wires flags directly to pipeline.ScanConfig — no new
// config.Config fields (the scan command has no configuration-file
// surface yet; see the CLI-wiring section of ARCHITECTURE.md).
func buildScanConfig(opts scanOptions, target asset.Domain) (pipeline.ScanConfig, error) {
	cfg := pipeline.ScanConfig{
		Target:    target,
		Stages:    opts.stages,
		OutputDir: opts.outputDir,
	}
	if len(cfg.Stages) == 0 {
		cfg.Stages = pipeline.AllStages()
	}

	// Per-stage parameters.
	if opts.sourcesSet {
		cfg.StageParams = map[pipeline.StageName]map[string]string{
			pipeline.StageDiscover: {"sources": strings.Join(opts.sources, ",")},
		}
	}
	if opts.requestTimeoutSet {
		if cfg.StageParams == nil {
			cfg.StageParams = make(map[pipeline.StageName]map[string]string)
		}
		cfg.StageParams[pipeline.StageHTTPProbe] = map[string]string{"request_timeout": opts.requestTimeout}
	}

	// Per-stage bounds: --concurrency and --timeout apply to EVERY
	// selected stage.
	if opts.concurrencySet || opts.timeoutSet {
		bounds := make(map[pipeline.StageName]pipeline.StageConfig, len(cfg.Stages))
		for _, name := range cfg.Stages {
			b := pipeline.StageConfig{}
			if opts.concurrencySet {
				b.MaxConcurrency = opts.concurrency
			}
			if opts.timeoutSet {
				b.Timeout = opts.timeout
			}
			bounds[name] = b
		}
		cfg.StageBounds = bounds
	}

	// Observer is wired by runScan (with --verbose or --tui), not here.
	return cfg, nil
}

// scanCache opens the persistent cache for a scan run. Mirroring
// discoverConfig: with an explicit --cache dir the cache is opened there
// regardless of configuration; without it, the cache is opened only when
// enabled in configuration (at the configured dir or the platform default),
// and --no-cache forces it off on every path.
func scanCache(cfg config.Config, opts scanOptions) (cache.Cache, error) {
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
				return nil, fmt.Errorf("scan: resolve default cache directory: %w", err)
			}
			dir = d
		}
	}
	c, err := cache.Open(dir, cache.WithTTL(cfg.Cache.TTL))
	if err != nil {
		return nil, fmt.Errorf("scan: open cache at %s: %w", dir, err)
	}
	return c, nil
}

// newScanStages returns the production eleven-stage pipeline: every adapter
// constructed with its production (nil) seams. The cfg parameter is
// accepted for the runScan stages-func contract; the production adapters
// derive everything from the StageInput the runner provides, so cfg is not
// consulted here.
//
// Production seams (each adapter's documented nil behavior):
//
//	discover   discovery.ExecRunner + exec.LookPath (external tools)
//	dns        the engine's default resolver (stdlib pure-Go net.Resolver)
//	httpprobe  the engine's bounded default transport
//	urlintel   discovery.ExecRunner + exec.LookPath (external tools)
//	crawl      discovery.ExecRunner + exec.LookPath (katana binary)
//	techintel  fingerprints.Load — the compiled-in 145-fingerprint DB
//	jsintel    the engine's bounded default transport
//	secrentel  patterns.Load — the compiled-in pattern database
//	priority   the engine's production catalogs (nil/nil = production
//	           tables)
//	detect     the EMPTY registry (D2 — no rules ship with the framework)
//	report     report.NewDefaultRegistry — the four builtin reporters
//	           (json, csv, markdown, html)
func newScanStages(cfg pipeline.ScanConfig) []pipeline.Stage {
	return []pipeline.Stage{
		adapt.NewDiscoveryStage(nil, nil),
		adapt.NewDNSStage(nil),
		adapt.NewHTTPProbeStage(nil),
		adapt.NewURLIntelStage(nil, nil),
		adapt.NewCrawlStage(nil),
		adapt.NewTechIntelStage(nil),
		adapt.NewJSIntelStage(nil),
		adapt.NewSecretIntelStage(nil),
		adapt.NewPriorityStage(nil, nil),
		adapt.NewDetectStage(nil),
		adapt.NewReportStage(nil),
	}
}

// tuiSubscriberBuffer is the --tui subscriber buffer size. A full scan run
// emits exactly ~22 stage events (one started + one finished per stage,
// synchronously, on every path), so 64 gives comfortable headroom for the
// controller's drain-at-close and for future instrumented stages (pool and
// cache events) while staying a small fixed bound — the bus drops (and
// counts) rather than blocks on a full buffer.
const tuiSubscriberBuffer = 64

// tuiRunner is the runnable live-observability seam: the production
// implementation is *tui.Controller (constructed by newScanTUI); tests
// inject fakes that mirror Controller.Run's contract — consume the
// subscriber's events until it closes or the context is cancelled, then
// return promptly.
type tuiRunner interface {
	Run(ctx context.Context) error
}

// scanTUIFactory constructs the TUI runner for a --tui run. It is the
// constructor seam for the live observability layer, mirroring the stages
// seam: production call sites pass newScanTUI (cli.go); tests inject
// fakes. The factory is consulted only when --tui is set.
type scanTUIFactory func(cfg config.TUIConfig, sub *event.Subscriber, w io.Writer) (tuiRunner, error)

// newScanTUI is the production TUI seam: it adapts tui.NewController to
// the scanTUIFactory shape. *tui.Controller satisfies tuiRunner.
func newScanTUI(cfg config.TUIConfig, sub *event.Subscriber, w io.Writer) (tuiRunner, error) {
	return tui.NewController(cfg, sub, w)
}

// resolveTUIColor resolves the --tui color mode from the writer the frame
// renders to: a character device (a real terminal) means "on"; pipes,
// files, and redirects mean "off". The TUI library renders color only when
// the resolved mode is exactly "on" — this is the caller-side "auto"
// resolution, and the library never probes the terminal itself.
func resolveTUIColor(w io.Writer) string {
	f, ok := w.(*os.File)
	if !ok {
		return "off"
	}
	st, err := f.Stat()
	if err != nil {
		return "off"
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		return "on"
	}
	return "off"
}

// runScan parses the scan arguments, normalizes the target through
// asset.NewDomain (the single normalization point), builds the pipeline
// configuration from the flags, runs the provided stages through
// pipeline.Run with the real wall clock, prints the run summary to w, and
// maps the outcome to the documented exit semantics:
//
//	completed → nil (exit 0)
//	partial   → nil (exit 0; the summary states the run was partial)
//	failed / cancelled / incomplete → error (main prints it and exits 1)
//
// Usage and validation errors, cache open failures, and run-level errors
// (pipeline.Run's configuration/resolution errors) return errors too. A
// run context cancelled mid-run (Ctrl-C/SIGTERM) returns a
// context-wrapped error AFTER the summary is printed — partial results are
// never lost, mirroring runDiscover.
//
// The stages parameter is the hermetic test seam: production call sites
// pass newScanStages; tests inject fake stage sets. Seams are constructor
// parameters, never environment or globals. tuiNew is the same seam for
// the live observability layer (--tui): production call sites pass
// newScanTUI; tests inject fakes.
//
// Verbose events go to os.Stderr directly, independent of w (the summary
// writer): stage events are diagnostics, the summary is the machine-facing
// output (mirroring how discover separates per-source reports from
// warnings). The TUI frame also renders to os.Stderr for the same reason
// (with color resolved from os.Stderr's character-device state).
func runScan(ctx context.Context, w io.Writer, args []string, stages func(pipeline.ScanConfig) []pipeline.Stage, tuiNew scanTUIFactory) error {
	opts, err := parseScanArgs(args)
	if err != nil {
		if errors.Is(err, errScanHelp) {
			return printScanUsage(w)
		}
		return err
	}
	target, err := asset.NewDomain(opts.target, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("scan: invalid target %q: %w", opts.target, err)
	}
	cfg, err := buildScanConfig(opts, target)
	if err != nil {
		return err
	}
	c, err := scanCache(config.Default(), opts)
	if err != nil {
		return err
	}
	if opts.verbose {
		// Stage events are emitted synchronously in stage order as the
		// runner proceeds; the observer prints each one as it arrives.
		cfg.Observer = &stageObserver{w: os.Stderr}
	}
	if opts.tui {
		// Live observability: one bus, one bounded subscriber, one
		// controller goroutine. Construction errors return before the
		// stages run, mirroring every other usage error.
		if tuiNew == nil {
			return fmt.Errorf("scan: --tui: no TUI runner available")
		}
		bus := event.NewBus(nil) // nil clock = the wall clock
		sub, err := bus.Subscribe(tuiSubscriberBuffer)
		if err != nil {
			bus.Close() // the bus is owned here; no goroutine was started
			return fmt.Errorf("scan: --tui: subscribe: %w", err)
		}
		// Enabled + Compact come from the flags; Color is resolved from
		// os.Stderr (a character device renders color, pipes/redirects do
		// not). Every other field stays zero and the library normalizes it
		// to its documented defaults (250 ms refresh, 1024-event history,
		// 10/s interesting rate).
		ctl, err := tuiNew(config.TUIConfig{
			Enabled: true,
			Compact: opts.tuiCompact,
			Color:   resolveTUIColor(os.Stderr),
		}, sub, os.Stderr)
		if err != nil {
			bus.Close() // releases the subscriber; no goroutine was started
			return fmt.Errorf("scan: --tui: %w", err)
		}
		// The bus is the run's single event sink (ScanConfig.Observer is
		// the only observer the pipeline runner consults) and the
		// controller consumes the run's stage events through it.
		cfg.Observer = bus
		tuiDone := make(chan error, 1) // buffered: Run's result never blocks
		go func() { tuiDone <- ctl.Run(ctx) }()
		// Lifecycle (bounded, leak-free): the goroutine above is joined on
		// EVERY return path via this defer, registered right after
		// construction. sub.Close() is the deterministic termination — the
		// controller's Run loop selects on the subscriber's Done channel,
		// so closing the subscriber ends the stream and Run returns
		// promptly; the bounded join then guarantees the goroutine is gone
		// before runScan returns. bus.Close() runs last: with no
		// subscribers left it drops (and counts) any straggler publishes.
		// A non-nil Run result (a write failure, or the controller
		// reporting the run context's cancellation) is a warning on stderr
		// only — it never changes scan's exit semantics or the summary.
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
		return fmt.Errorf("scan: %w", err)
	}
	if err := printScanSummary(w, rep, cfg.OutputDir, c != nil); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("scan: run interrupted: %w", ctx.Err())
	}
	switch rep.Outcome {
	case pipeline.OutcomeCompleted, pipeline.OutcomePartial:
		return nil
	case pipeline.OutcomeFailed:
		return fmt.Errorf("scan: run outcome failed: one or more stages failed (see the summary)")
	case pipeline.OutcomeCancelled:
		return fmt.Errorf("scan: run outcome cancelled (see the summary)")
	default: // OutcomeIncomplete
		return fmt.Errorf("scan: run outcome incomplete: the retained set is incomplete (see the summary)")
	}
}

func printScanUsage(w io.Writer) error {
	_, err := io.WriteString(w, scanUsage)
	return err
}

// printScanSummary renders one scan run's summary: the target, the cache
// state, the pipeline outcome, one line per stage (name, outcome, honest
// counters, truncation/flags, error detail), and the report output — the
// output directory plus the report files that exist there (the report
// stage's engine result is not surfaced on the pipeline StageRecord, so
// the CLI lists the committed files honestly from the directory itself).
// Durations and timestamps are deliberately absent: the summary must be
// stable across runs for the same input (the pipeline's determinism
// property, T4), and the CLI runs on the real wall clock.
func printScanSummary(w io.Writer, rep pipeline.RunReport, outputDir string, cached bool) error {
	if _, err := fmt.Fprintf(w, "RavenRecon scan: %s (cache: %s)\n\n", rep.Target.Name, onOff(cached)); err != nil {
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
		// The report stage may have failed or been cancelled before
		// committing anything, or the directory may be unreadable: an
		// honest note, never a failed summary — the run data is already
		// printed above.
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

// reportFiles lists the direct, non-directory entries of dir, sorted by
// name. An unreadable or missing directory is an error the caller renders
// as an honest note.
func reportFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// wallClock is the CLI's runtime.Clock: the real wall clock. Determinism
// is a pipeline property (T4 — the pipeline packages inject their own
// clocks in tests); pipeline.Run requires a non-nil clock, so the CLI
// supplies a real one and the summary deliberately never prints
// timestamps.
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var _ runtime.Clock = wallClock{}
