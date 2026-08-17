package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/config"
)

// Frame bounds (fixed constants; the frame is built as one bounded buffer).
const (
	// maxLineBytes truncates every rendered line (rune-safe, marked).
	maxLineBytes = 200
	// maxWorkerRows bounds the per-worker dashboard rows rendered per frame.
	maxWorkerRows = 32
	// maxFrameBytes bounds the whole frame. The structure guarantees it:
	// fixed header/section lines plus bounded feeds (64 interesting items,
	// 32 error groups, 32 worker rows) at maxLineBytes each, plus the
	// summary block. The bound is asserted in tests.
	maxFrameBytes = 64 << 10
)

// Options is the resolved render configuration (see OptionsFromConfig).
// Color is the caller-resolved boolean ("auto" is resolved by the caller
// from its own terminal detection; the library never probes the terminal).
type Options struct {
	// Compact condenses the frame (no per-worker rows, no resource
	// section).
	Compact bool
	// Quiet renders only the error feed and the final run summary.
	Quiet bool
	// Color enables the library's fixed ANSI styling of section headers.
	Color bool
}

// color codes: fixed constants added by the renderer AFTER sanitization, so
// a frame's only ESC bytes are these. Section headers are bold; error
// severities are bold red.
const (
	ansiBold    = "\x1b[1m"
	ansiBoldRed = "\x1b[1;31m"
	ansiReset   = "\x1b[0m"
)

// OptionsFromConfig normalizes a TUIConfig into the resolved render
// options. Zero fields defer to the documented defaults (plain, full
// frame). The caller must resolve the Color mode ("auto") from its own
// terminal detection before calling — the library never probes the
// terminal — and any unresolved mode ("auto", "", or anything but "on")
// renders plain, the natural mode for non-TTY writers.
func OptionsFromConfig(cfg config.TUIConfig) Options {
	return Options{
		Compact: cfg.Compact,
		Quiet:   cfg.Quiet,
		Color:   cfg.Color == "on",
	}
}

// Render builds the deterministic live frame for the state at time now.
// The frame is a pure function of (state, now, opts): the same events and
// the same clock always produce the same bytes. Unknown values render as
// "unknown"/"—"; a percentage is never faked.
func Render(s *State, now time.Time, opts Options) string {
	var b strings.Builder
	b.Grow(4096)

	if !opts.Quiet {
		header(s, opts, &b)
		progressSection(s, now, opts, &b)
		workerSection(s, now, opts, &b)
		throughputSection(s, now, opts, &b)
		if !opts.Compact {
			resourceSection(s, now, opts, &b)
		}
		interestingSection(s, opts, &b)
	}
	errorSection(s, opts, &b)
	return b.String()
}

// RenderFinal builds the final frame: the live frame plus the final run
// summary block. It is what the controller renders once the stream has been
// drained at shutdown.
func RenderFinal(s *State, now time.Time, opts Options) string {
	live := Render(s, now, opts)
	if live == "" || strings.HasSuffix(live, "\n") {
		return live + summarySection(s, opts)
	}
	return live + "\n" + summarySection(s, opts)
}

func header(s *State, opts Options, b *strings.Builder) {
	target := s.progress.target
	if target == "" {
		target = "untitled run"
	}
	line(b, opts, "ravenrecon — "+target)
}

func progressSection(s *State, now time.Time, opts Options, b *strings.Builder) {
	p := s.progress
	phase := p.phase
	if phase == "" {
		phase = "—"
	}
	line(b, opts, "phase "+phase)

	var tasks string
	if p.totalKnown {
		tasks = fmt.Sprintf("tasks %d/%d", p.completed, p.total)
		remaining, _ := p.remaining()
		tasks += fmt.Sprintf(" · remaining %d", remaining)
	} else {
		tasks = fmt.Sprintf("tasks %d/unknown", p.completed)
	}
	if inFlight, known := p.inFlightCount(); known {
		tasks += fmt.Sprintf(" · in-flight %d", inFlight)
	} else {
		tasks += " · in-flight unknown"
	}

	elapsed, ok := p.elapsed(now)
	if ok {
		tasks += " · elapsed " + formatDuration(elapsed)
	} else {
		tasks += " · elapsed —"
	}
	if eta, ok := p.eta(now, s.rates); ok {
		tasks += " · eta ~" + formatDuration(eta)
	} else {
		tasks += " · eta unknown"
	}
	line(b, opts, tasks)
}

func workerSection(s *State, now time.Time, opts Options, b *strings.Builder) {
	running, waiting, idle, cancelled, failed, completed := s.workers.counts()
	line(b, opts, fmt.Sprintf(
		"workers running %d · waiting %d · idle %d · cancelled %d · failed %d · completed %d · active %d",
		running, waiting, idle, cancelled, failed, completed, s.workers.active))
	line(b, opts, fmt.Sprintf("queue depth %d", s.queueDepth()))
	if opts.Compact {
		return
	}
	rows := s.workers.snapshot()
	shown := 0
	for _, w := range rows {
		if shown == maxWorkerRows {
			line(b, opts, fmt.Sprintf("… %d more workers", len(rows)-shown))
			break
		}
		row := formatWorkerRow(w, now)
		if w.lastError != "" {
			row += " · last: " + w.lastError
		}
		line(b, opts, "  "+row)
		shown++
	}
}

func throughputSection(s *State, now time.Time, opts Options, b *strings.Builder) {
	var sb strings.Builder
	sb.WriteString("throughput ")
	for i, m := range displayedMetrics {
		if i > 0 {
			sb.WriteString(" · ")
		}
		fmt.Fprintf(&sb, "%s %s/s", metricNames[m], strconv.FormatFloat(s.rates.rate(m, now), 'f', 1, 64))
	}
	line(b, opts, sb.String())
}

func resourceSection(s *State, now time.Time, opts Options, b *strings.Builder) {
	res := s.SampleResources(now)
	fds := "—"
	if res.OpenFDs >= 0 {
		fds = strconv.Itoa(res.OpenFDs)
	}
	line(b, opts, fmt.Sprintf("resources heap %s · goroutines %d · open-fds %s",
		formatBytes(res.HeapBytes), res.Goroutines, fds))
}

func interestingSection(s *State, opts Options, b *strings.Builder) {
	items := s.feed.snapshot()
	if len(items) == 0 {
		return
	}
	line(b, opts, "interesting:")
	for _, it := range items {
		line(b, opts, "  · "+it.label+" — "+it.detail)
	}
}

func errorSection(s *State, opts Options, b *strings.Builder) {
	groups := s.errors.snapshot()
	if len(groups) == 0 {
		return
	}
	line(b, opts, "errors:")
	for _, g := range groups {
		sev := g.severity.String()
		row := fmt.Sprintf("  [%s ×%d] %s: %s", g.category, g.count, sev, g.latestMsg)
		if g.count > 1 {
			row += fmt.Sprintf(" (latest %s)", g.latestAt.Format("15:04:05"))
		}
		line(b, opts, row)
	}
}

// summarySection renders the FINAL RUN SUMMARY block. Every value comes
// from the consumed event stream (State.Summary); anything the stream never
// established renders as "—".
func summarySection(s *State, opts Options) string {
	sum := s.Summary()
	var b strings.Builder
	line(&b, opts, "── summary ──")
	dur := "—"
	if !sum.StartedAt.IsZero() && !sum.EndedAt.IsZero() {
		dur = formatDuration(sum.Duration)
	}
	outcome := sum.Outcome
	if outcome == "" {
		outcome = "—"
	}
	line(&b, opts, "duration "+dur+" · outcome "+outcome)
	line(&b, opts, fmt.Sprintf("assets %d · hosts %d · urls %d · endpoints %d · technologies %d · secrets %d",
		sum.Assets, sum.Hosts, sum.URLs, sum.Endpoints, sum.Technologies, sum.Secrets))
	line(&b, opts, fmt.Sprintf("findings %d · rules %d · relationships %d",
		sum.Findings, sum.Rules, sum.Relationships))
	line(&b, opts, fmt.Sprintf("cache hits %d · cache misses %d · warnings %d · errors %d",
		sum.CacheHits, sum.CacheMisses, sum.Warnings, sum.Errors))
	dir := sum.OutputDir
	if dir == "" {
		dir = "—"
	}
	line(&b, opts, "output dir "+dir)
	return b.String()
}

// line writes one bounded, sanitized line plus newline. The content has
// already been sanitized at ingestion; this truncates display length only.
func line(b *strings.Builder, opts Options, s string) {
	if len(s) > maxLineBytes {
		s = truncateLabel(s)
	}
	if opts.Color {
		// Styling is applied here, at the very end: the content is clean,
		// and the only ESC bytes in the frame are these fixed codes.
		s = ansiBold + s + ansiReset
	}
	b.WriteString(s)
	b.WriteByte('\n')
}
