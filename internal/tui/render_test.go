package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// fixedResources is the injected sampler used by every render test so
// frames are fully deterministic.
func fixedResources(s *State) {
	s.sample = func() Resources {
		return Resources{HeapBytes: 12 << 20, Goroutines: 42, OpenFDs: 17}
	}
}

// TestRenderInFlightUnknown pins the honest unknown rendering: once the
// started-ID set overflows, the frame says "in-flight unknown" instead of
// fabricating a number.
func TestRenderInFlightUnknown(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	for i := 0; i < startedIDCap+1; i++ {
		s.progress.taskStarted(uint64(i))
	}
	if _, known := s.progress.inFlightCount(); known {
		t.Fatal("in-flight must be unknown after overflow")
	}
	got := Render(s, testBase.Add(10*time.Second), Options{})
	if !strings.Contains(got, "in-flight unknown") {
		t.Fatalf("frame must render in-flight unknown, got:\n%s", got)
	}
	if strings.Contains(got, "in-flight 0") {
		t.Fatal("frame must not fabricate a number after overflow")
	}
}

// TestRenderGolden pins the exact live frame of the scripted run at
// t0+10s. Every value is hand-verifiable: elapsed 10s, tasks 3/3,
// remaining 0, ETA 0, two completed workers (worker 0 ran two tasks,
// worker 1 one), throughput assets (3 samples from t0+9ms to t0+11ms →
// (3-1)/(10s-9ms) ≈ 0.2/s, all other metrics single-sample → 0.0), the
// three interesting items newest-first, and the two error groups sorted.
func TestRenderGolden(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	now := testBase.Add(10 * time.Second)

	want := "" +
		"ravenrecon — example.com\n" +
		"phase discovery\n" +
		"tasks 3/3 · remaining 0 · in-flight 0 · elapsed 10.0s · eta ~0.0s\n" +
		"workers running 0 · waiting 0 · idle 0 · cancelled 0 · failed 0 · completed 2 · active 0\n" +
		"queue depth 0\n" +
		"  worker 0 completed (2 tasks)\n" +
		"  worker 1 completed (1 tasks)\n" +
		"throughput assets 0.2/s · urls 0.0/s · requests 0.0/s · js 0.0/s · rules 0.0/s · relationships 0.0/s · cache-hits 0.0/s · cache-misses 0.0/s\n" +
		"resources heap 12 MiB · goroutines 42 · open-fds 17\n" +
		"interesting:\n" +
		"  · host:example.com — high-value recommendation\n" +
		"  · finding:r1@url:https://example.com — finding high (r1)\n" +
		"  · endpoint:https://example.com/graphql — graphql endpoint\n" +
		"errors:\n" +
		"  [dns ×1] error: nxdomain\n" +
		"  [timeout ×1] warning: slow\n"

	if got := Render(s, now, Options{}); got != want {
		t.Fatalf("golden frame mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderFinalGolden pins the final frame: the live frame plus the
// run summary derived only from the stream.
func TestRenderFinalGolden(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	now := testBase.Add(10 * time.Second)

	want := "" +
		"ravenrecon — example.com\n" +
		"phase discovery\n" +
		"tasks 3/3 · remaining 0 · in-flight 0 · elapsed 10.0s · eta ~0.0s\n" +
		"workers running 0 · waiting 0 · idle 0 · cancelled 0 · failed 0 · completed 2 · active 0\n" +
		"queue depth 0\n" +
		"  worker 0 completed (2 tasks)\n" +
		"  worker 1 completed (1 tasks)\n" +
		"throughput assets 0.2/s · urls 0.0/s · requests 0.0/s · js 0.0/s · rules 0.0/s · relationships 0.0/s · cache-hits 0.0/s · cache-misses 0.0/s\n" +
		"resources heap 12 MiB · goroutines 42 · open-fds 17\n" +
		"interesting:\n" +
		"  · host:example.com — high-value recommendation\n" +
		"  · finding:r1@url:https://example.com — finding high (r1)\n" +
		"  · endpoint:https://example.com/graphql — graphql endpoint\n" +
		"errors:\n" +
		"  [dns ×1] error: nxdomain\n" +
		"  [timeout ×1] warning: slow\n" +
		"── summary ──\n" +
		"duration 10.0s · outcome completed\n" +
		"assets 3 · hosts 1 · urls 1 · endpoints 1 · technologies 0 · secrets 0\n" +
		"findings 1 · rules 2 · relationships 1\n" +
		"cache hits 1 · cache misses 1 · warnings 1 · errors 1\n" +
		"output dir /tmp/out\n"

	if got := RenderFinal(s, now, Options{}); got != want {
		t.Fatalf("final golden frame mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderUnknowns pins the honest unknown rendering of an empty
// state: "—", "unknown", and no fabricated percentages.
func TestRenderUnknowns(t *testing.T) {
	s := NewState(highRate)
	fixedResources(s)
	frame := Render(s, testBase, Options{})
	for _, want := range []string{"ravenrecon — untitled run", "phase —", "tasks 0/unknown", "elapsed —", "eta unknown"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame must contain %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "%") {
		t.Fatalf("no percentage may ever be faked:\n%s", frame)
	}
}

// TestRenderCompact pins the condensed frame: no per-worker rows, no
// resources section.
func TestRenderCompact(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	frame := Render(s, testBase.Add(10*time.Second), Options{Compact: true})
	if strings.Contains(frame, "worker 0 completed") {
		t.Fatalf("compact frame must not render worker rows:\n%s", frame)
	}
	if strings.Contains(frame, "resources heap") {
		t.Fatalf("compact frame must not render the resources section:\n%s", frame)
	}
	if !strings.Contains(frame, "queue depth 0") {
		t.Fatalf("compact frame must keep the queue summary:\n%s", frame)
	}
}

// TestRenderQuiet pins the quiet frame: only the error feed, and the
// final summary on RenderFinal.
func TestRenderQuiet(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	frame := Render(s, testBase.Add(10*time.Second), Options{Quiet: true})
	if strings.Contains(frame, "ravenrecon —") || strings.Contains(frame, "phase discovery") {
		t.Fatalf("quiet frame must suppress routine output:\n%s", frame)
	}
	if !strings.Contains(frame, "[dns ×1] error: nxdomain") {
		t.Fatalf("quiet frame must keep the error feed:\n%s", frame)
	}

	final := RenderFinal(s, testBase.Add(10*time.Second), Options{Quiet: true})
	if !strings.Contains(final, "── summary ──") {
		t.Fatalf("quiet final frame must include the summary:\n%s", final)
	}
}

// TestRenderQuietEmpty pins that a quiet run with no errors renders
// nothing live and only the summary at the end.
func TestRenderQuietEmpty(t *testing.T) {
	s := NewState(highRate)
	if got := Render(s, testBase, Options{Quiet: true}); got != "" {
		t.Fatalf("quiet empty live frame must be empty, got %q", got)
	}
	final := RenderFinal(s, testBase, Options{Quiet: true})
	if !strings.Contains(final, "── summary ──") {
		t.Fatalf("quiet empty final frame must still carry the summary:\n%s", final)
	}
}

// TestRenderColor pins the color contract: the ONLY ESC bytes in a frame
// are the renderer's fixed codes, and stripping them reproduces the plain
// frame exactly.
func TestRenderColor(t *testing.T) {
	s := applyScript(t, scriptedRun())
	fixedResources(s)
	now := testBase.Add(10 * time.Second)

	plain := Render(s, now, Options{})
	colored := Render(s, now, Options{Color: true})

	stripped := strings.ReplaceAll(colored, ansiBold, "")
	stripped = strings.ReplaceAll(stripped, ansiReset, "")
	if stripped != plain {
		t.Fatalf("color codes must be additive:\n--- stripped ---\n%s\n--- plain ---\n%s", stripped, plain)
	}
	esc := strings.Count(colored, "\x1b")
	fixed := strings.Count(colored, ansiBold) + strings.Count(colored, ansiReset)
	if esc != fixed {
		t.Fatalf("frame contains %d ESC bytes, want only the %d fixed codes", esc, fixed)
	}
	if !strings.Contains(colored, ansiBold+"ravenrecon — example.com"+ansiReset) {
		t.Fatalf("header must be styled:\n%s", colored)
	}
}

// TestRenderFrameBounds pins the structural bound: a hostile stream with
// maximum-length labels, messages, feeds, and worker rows cannot exceed
// maxFrameBytes, and no line exceeds maxLineBytes.
func TestRenderFrameBounds(t *testing.T) {
	s := NewState(highRate)
	fixedResources(s)

	long := strings.Repeat("a", 512)

	// 32 error groups with 512-byte messages.
	for i := 0; i < 32; i++ {
		s.Apply(ev(event.KindError, i, event.NewError("cat-"+twoDigit(i), long)).WithSeverity(event.SeverityError))
	}
	// 64 interesting assets with 211-byte identities (truncated to 200 at
	// ingestion, so the frame lines stay bounded).
	for i := 0; i < maxFeedItems; i++ {
		s.Apply(ev(event.KindAssetDiscovered, 100+i, event.AssetDiscovered{
			Identity: "technology:" + strings.Repeat(twoDigit(i), 100), Kind: "technology",
		}))
	}
	// 32 workers, each with a long last error.
	for i := 0; i < 32; i++ {
		s.Apply(ev(event.KindWorkerStarted, 200+i, event.WorkerStarted{Worker: i}))
		s.Apply(ev(event.KindTaskStarted, 300+i, event.TaskStarted{JobID: uint64(i), Worker: i}))
		s.Apply(ev(event.KindTaskRunning, 400+i, event.TaskRunning{JobID: uint64(i), Worker: i}))
		s.Apply(ev(event.KindTaskFailed, 500+i, event.TaskFailed{
			TaskTerminal: event.NewTaskTerminal(uint64(i), i, testBase, "boom", long),
		}))
	}

	frame := Render(s, testBase.Add(10*time.Second), Options{})
	if len(frame) > maxFrameBytes {
		t.Fatalf("frame is %d bytes, bound is %d", len(frame), maxFrameBytes)
	}
	for _, l := range strings.Split(frame, "\n") {
		if len(l) > maxLineBytes {
			t.Fatalf("line exceeds %d bytes: %q", maxLineBytes, l)
		}
	}
}

// TestRenderDeterminism pins the pure-function contract: the same events
// and the same clock always produce the same bytes.
func TestRenderDeterminism(t *testing.T) {
	a := applyScript(t, scriptedRun())
	b := applyScript(t, scriptedRun())
	fixedResources(a)
	fixedResources(b)
	now := testBase.Add(10 * time.Second)
	if Render(a, now, Options{}) != Render(b, now, Options{}) {
		t.Fatal("Render must be a pure function of (state, now, opts)")
	}
}

func TestOptionsFromConfigDefaults(t *testing.T) {
	o := OptionsFromConfig(config.TUIConfig{})
	if o.Compact || o.Quiet || o.Color {
		t.Fatalf("zero config must normalize to the default options: %+v", o)
	}
}

func TestOptionsFromConfigPassthrough(t *testing.T) {
	o := OptionsFromConfig(config.TUIConfig{Compact: true, Quiet: true, Color: "on"})
	if !o.Compact || !o.Quiet || !o.Color {
		t.Fatalf("explicit fields must pass through: %+v", o)
	}
}

// TestOptionsFromConfigColorResolution pins that only the resolved "on"
// mode enables color; anything else (including unresolved "auto" and
// zero) renders plain.
func TestOptionsFromConfigColorResolution(t *testing.T) {
	for _, c := range []string{"", "auto", "off", "ON", "sometimes"} {
		if o := OptionsFromConfig(config.TUIConfig{Color: c}); o.Color {
			t.Fatalf("color mode %q must render plain", c)
		}
	}
	if o := OptionsFromConfig(config.TUIConfig{Color: "on"}); !o.Color {
		t.Fatal("color mode \"on\" must enable styling")
	}
}

// TestFormatBytes pins the deterministic byte rendering.
func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{900, "900 B"},
		{1024, "1 KiB"},
		{12 << 20, "12 MiB"},
		{uint64(1.5 * (1 << 30)), "1.5 GiB"},
	}
	for _, tc := range cases {
		if got := formatBytes(tc.n); got != tc.want {
			t.Fatalf("formatBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestFormatFloat1 pins the one-decimal rendering with the ".0" trim.
func TestFormatFloat1(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0.200180, "0.2"},
		{12.0, "12"},
		{0.5, "0.5"},
		{95.23, "95.2"},
	}
	for _, tc := range cases {
		if got := formatFloat1(tc.v); got != tc.want {
			t.Fatalf("formatFloat1(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}
