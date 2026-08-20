package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/event"
	"github.com/RA000WL/RavenRecon/internal/version"
)

const usage = `RavenRecon - intelligent reconnaissance framework

Usage:
  ravenrecon <command> [options]

Commands:
  version       Show version information
  doctor        Check the local RavenRecon environment
  discover      Run passive subdomain discovery for a domain
  scan          Run the full end-to-end reconnaissance pipeline for a domain

Options:
  -h, --help    Show this help message

Examples:
  ravenrecon version
  ravenrecon doctor
  ravenrecon discover example.com
  ravenrecon discover example.com --sources subfinder,amass
  ravenrecon scan example.com
  ravenrecon scan example.com --stages discover,dns,httpprobe --output out/

Discovery is passive-only. It invokes external tools in their passive modes:
  subfinder -d <domain> -silent, assetfinder <domain>,
  amass enum -passive -d <domain>.
The scan command runs discover → dns → httpprobe → urlintel → techintel →
jsintel → secrentel → priority → detect → report and writes the report
into an output directory (default ravenrecon-report).
No active enumeration, brute force, or intel modes are ever run.

RavenRecon is intended for authorized security testing and
bug bounty programs where the target is explicitly in scope.
`

const discoverUsage = `RavenRecon discover - passive subdomain discovery

Usage:
  ravenrecon discover <domain> [options]

Options (after the domain):
  --sources <a,b>   Restrict to the given sources (subfinder, assetfinder,
                    amass). Default: all built-in sources.
  --no-cache        Disable the cache for this run (default: cache is off
                    unless enabled in configuration).

Signals: Ctrl-C or SIGTERM cancels the run gracefully — the partial report
is still printed and the exit code is 1. A second signal forces an
immediate exit.

Target validation: the domain is normalized through the Phase 2 asset model;
uppercase, surrounding whitespace, and a trailing dot are normalized away.

Discovery invokes only passive enumeration:
  subfinder -d <domain> -silent
  assetfinder <domain>
  amass enum -passive -d <domain>
No active enumeration, brute force, or intel modes are ever run.

RavenRecon is intended for authorized security testing and
bug bounty programs where the target is explicitly in scope.
`

// errDiscoverHelp is returned by parseDiscoverArgs when the user asked for
// discover help; runDiscover prints the discover usage and exits cleanly.
var errDiscoverHelp = errors.New("discover: help requested")

// errScanHelp is returned by parseScanArgs when the user asked for scan
// help; runScan prints the scan usage and exits cleanly. It mirrors
// errDiscoverHelp.
var errScanHelp = errors.New("scan: help requested")

// stageObserver is the scan command's --verbose sink: it prints one
// compact line per stage event to its writer as the pipeline runner emits
// them (synchronously, in stage order). It observes only the stage
// lifecycle kinds the pipeline emits — anything else is ignored, and a
// hostile or invalid event can never panic the writer path (the payload
// assertions are checked).
type stageObserver struct {
	w io.Writer
}

// Observe implements event.Observer.
func (o *stageObserver) Observe(ev event.Event) {
	switch ev.Kind {
	case event.KindStageStarted:
		p, _ := ev.Payload.(event.StageStarted)
		fmt.Fprintf(o.w, "stage_started %s\n", p.Name)
	case event.KindStageFinished:
		p, _ := ev.Payload.(event.StageFinished)
		var b strings.Builder
		fmt.Fprintf(&b, "stage_finished %s outcome=%s processed=%d failed=%d",
			p.Name, p.Outcome, p.ItemsProcessed, p.ItemsFailed)
		if p.Truncated {
			b.WriteString(" truncated")
		}
		if p.Err != "" {
			fmt.Fprintf(&b, " err=%q", p.Err)
		}
		fmt.Fprintln(o.w, b.String())
	}
}

// Run executes the RavenRecon CLI.
func Run(ctx context.Context, args []string) error {
	if ctx == nil {
		return fmt.Errorf("context must not be nil")
	}

	if len(args) == 0 {
		return printUsage(os.Stdout)
	}

	switch args[0] {
	case "help", "-h", "--help":
		return printUsage(os.Stdout)

	case "version":
		return printVersion(os.Stdout)

	case "doctor":
		return runDoctor(ctx, os.Stdout)

	case "discover":
		return runDiscover(ctx, os.Stdout, args[1:])

	case "scan":
		return runScan(ctx, os.Stdout, args[1:], newScanStages)

	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func printUsage(w io.Writer) error {
	_, err := io.WriteString(w, usage)
	return err
}

func printVersion(w io.Writer) error {
	_, err := fmt.Fprintf(
		w,
		"RavenRecon %s\ncommit: %s\ndate: %s\n",
		version.Version,
		version.Commit,
		version.Date,
	)

	return err
}

// discoverOptions is the parsed (domain, flags) pair of the discover command.
type discoverOptions struct {
	domain  string
	sources []string // nil or empty means every built-in source
	noCache bool
}

// parseDiscoverArgs parses "discover" arguments: exactly one target domain,
// followed by options. Options must come after the domain (the domain is
// positional); -h/--help anywhere prints discover usage via errDiscoverHelp.
func parseDiscoverArgs(args []string) (discoverOptions, error) {
	if len(args) == 0 {
		return discoverOptions{}, fmt.Errorf("discover: missing domain argument (usage: ravenrecon discover <domain> [options])")
	}
	switch args[0] {
	case "-h", "--help", "help":
		return discoverOptions{}, errDiscoverHelp
	}

	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed
	noCache := fs.Bool("no-cache", false, "disable the cache for this run")
	sources := fs.String("sources", "", "comma-separated source names")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return discoverOptions{}, errDiscoverHelp
		}
		return discoverOptions{}, fmt.Errorf("discover: %w", err)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return discoverOptions{}, fmt.Errorf("discover: unexpected argument(s) %q (usage: ravenrecon discover <domain> [options])", rest[0])
	}

	// "not given" and "explicitly empty" are different: only a missing flag
	// may mean "all built-in sources". An explicit --sources "" (or one that
	// splits to nothing, like ",") is a user error, so a typo can never
	// silently run every source.
	sourcesSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sources" {
			sourcesSet = true
		}
	})

	opts := discoverOptions{domain: args[0], noCache: *noCache}
	if sourcesSet {
		for _, s := range strings.Split(*sources, ",") {
			if s = strings.TrimSpace(s); s != "" {
				opts.sources = append(opts.sources, s)
			}
		}
		if len(opts.sources) == 0 {
			return discoverOptions{}, fmt.Errorf("discover: --sources: empty source list")
		}
	}
	return opts, nil
}

// discoverConfig maps the global configuration plus the parsed discover
// options onto a discovery run configuration. It wires the cache only when it
// is enabled in configuration and not disabled for this run.
func discoverConfig(cfg config.Config, opts discoverOptions) (discovery.Config, error) {
	dc := discovery.DefaultConfig()
	dc.Concurrency = cfg.Concurrency
	dc.Timeout = cfg.Timeout
	dc.Rate = cfg.Rate
	dc.Sources = opts.sources
	dc.Bin = cfg.Discovery.Bin
	if cfg.Discovery.Timeout > 0 {
		dc.Timeout = cfg.Discovery.Timeout
	}
	if cfg.Discovery.DetectTimeout > 0 {
		dc.DetectTimeout = cfg.Discovery.DetectTimeout
	}
	if cfg.Discovery.MaxOutputSize > 0 {
		dc.MaxOutputSize = cfg.Discovery.MaxOutputSize
	}
	if cfg.Cache.Enabled && !opts.noCache {
		dir := cfg.Cache.Dir
		if dir == "" {
			d, err := cache.DefaultDir()
			if err != nil {
				return discovery.Config{}, fmt.Errorf("discover: resolve default cache directory: %w", err)
			}
			dir = d
		}
		c, err := cache.Open(dir, cache.WithTTL(cfg.Cache.TTL))
		if err != nil {
			return discovery.Config{}, fmt.Errorf("discover: open cache at %s: %w", dir, err)
		}
		dc.Cache = c
	}
	return dc, nil
}

// runDiscover runs passive discovery for the given domain and prints the
// per-source report. Errors in individual sources are reported per source and
// do not fail the command; run-level errors (bad arguments, invalid target,
// pool failure, cancellation) return an error. A run context cancelled
// mid-run (Ctrl-C/SIGTERM) is a failed command, not a clean exit: the
// partial report is still printed above (partial results are never lost),
// and the returned context-wrapped error makes main exit 1. A per-source
// cancelled outcome caused by a job deadline does not fail the command: the
// run context itself was not interrupted.
func runDiscover(ctx context.Context, w io.Writer, args []string) error {
	opts, err := parseDiscoverArgs(args)
	if err != nil {
		if errors.Is(err, errDiscoverHelp) {
			return printDiscoverUsage(w)
		}
		return err
	}
	target, err := asset.NewDomain(opts.domain, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("discover: invalid target %q: %w", opts.domain, err)
	}
	cfg, err := discoverConfig(config.Default(), opts)
	if err != nil {
		return err
	}
	rep, err := discovery.Run(ctx, target, cfg)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if err := printDiscoverReport(w, rep, cfg.Cache != nil); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("discover: run interrupted: %w", ctx.Err())
	}
	return nil
}

func printDiscoverUsage(w io.Writer) error {
	_, err := io.WriteString(w, discoverUsage)
	return err
}

// printDiscoverReport formats one discovery run's report for humans. Errors
// in individual sources appear as warning lines; the merged host list is
// printed last.
func printDiscoverReport(w io.Writer, rep discovery.Report, cached bool) error {
	if _, err := fmt.Fprintf(w, "RavenRecon discover: %s (cache: %s)\n\n",
		rep.Target.Name, onOff(cached)); err != nil {
		return err
	}
	for _, res := range rep.Results {
		det := res.Detection
		if _, err := fmt.Fprintf(w, "%s %s\n", res.Source, det.Status.Label()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  detection: %s\n", det.Reason); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  outcome: %s", res.Status); err != nil {
			return err
		}
		switch res.Status {
		case discovery.OutCompleted:
			if _, err := fmt.Fprintf(w, " — %d hosts (cached: %t, malformed: %d, truncated: %t)",
				len(res.Hosts), res.Cached, res.Malformed, res.Truncated); err != nil {
				return err
			}
		case discovery.OutPartial:
			if _, err := fmt.Fprintf(w, " — %d hosts retained (malformed: %d, truncated: %t)",
				len(res.Hosts), res.Malformed, res.Truncated); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "\n"); err != nil {
			return err
		}
		// A non-nil error on ANY outcome — including a completed run whose
		// cache write failed — must be visible, so the user never believes
		// results were cached when they were not.
		if res.Err != nil {
			if _, err := fmt.Fprintf(w, "  warning: %v\n", res.Err); err != nil {
				return err
			}
		}
		for _, h := range res.Hosts {
			if _, err := fmt.Fprintf(w, "    %-40s %s\n", h.Name, provLabel(h.Prov)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "\n"); err != nil {
			return err
		}
	}

	merged := rep.All()
	if _, err := fmt.Fprintf(w, "Merged across sources: %d unique hosts\n", len(merged)); err != nil {
		return err
	}
	for _, h := range merged {
		if _, err := fmt.Fprintf(w, "  %-40s %s\n", h.Name, provLabel(h.Prov)); err != nil {
			return err
		}
	}
	return nil
}

// provLabel renders a host's provenance as "(source @ RFC3339)", or just
// "(source)" when the timestamp is missing. Hosts with no provenance at all
// render as "(provenance unknown)".
func provLabel(p asset.Provenance) string {
	if p.Source == "" && p.DiscoveredAt.IsZero() {
		return "(provenance unknown)"
	}
	if p.DiscoveredAt.IsZero() {
		return "(" + p.Source + ")"
	}
	return fmt.Sprintf("(%s @ %s)", p.Source, p.DiscoveredAt.Format(time.RFC3339))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func runDoctor(ctx context.Context, w io.Writer) error {
	cfg := config.Default()

	cacheDir := cfg.Cache.Dir
	if cacheDir == "" {
		if d, err := cache.DefaultDir(); err == nil {
			cacheDir = d
		} else {
			cacheDir = "(unavailable: " + err.Error() + ")"
		}
	}

	sources := "all built-in (subfinder, assetfinder, amass)"
	if len(cfg.Discovery.Sources) > 0 {
		sources = strings.Join(cfg.Discovery.Sources, ", ")
	}

	if _, err := fmt.Fprintf(
		w,
		`RavenRecon doctor

Foundation: OK
Configuration:
  Concurrency: %d
  Timeout:     %s
  Rate:        %.2f req/s
  User-Agent:  %s
Cache:
  Enabled:     %t
  Directory:   %s
  TTL:         %s (0 = no expiration)
Discovery:
  Sources:     %s
`,
		cfg.Concurrency,
		cfg.Timeout,
		cfg.Rate,
		cfg.UserAgent,
		cfg.Cache.Enabled,
		cacheDir,
		cfg.Cache.TTL,
		sources,
	); err != nil {
		return err
	}

	// Per-source detection uses the same implementation as the discover
	// command's pipeline (discovery.DetectAll); there is no second detection
	// path to drift out of sync.
	return printDoctorDiscovery(w, discovery.DetectAll(ctx, cfg.Discovery.Bin, cfg.Discovery.DetectTimeout))
}

// printDoctorDiscovery formats per-source tool detection states. It is split
// from runDoctor so the rendering is testable without real tool binaries.
func printDoctorDiscovery(w io.Writer, dets []discovery.Detection) error {
	for _, d := range dets {
		if _, err := fmt.Fprintf(w, "  %-12s %s %s\n", d.Source+":", d.Status.Label(), d.Reason); err != nil {
			return err
		}
	}
	return nil
}
