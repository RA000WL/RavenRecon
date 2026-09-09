package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// TestParseDiscoverArgsOutput pins the NEW-138 --output flag: absent means
// stream to stdout; a value routes the stream to that file.
func TestParseDiscoverArgsOutput(t *testing.T) {
	opts, err := parseDiscoverArgs([]string{"example.com"})
	if err != nil {
		t.Fatalf("parseDiscoverArgs: %v", err)
	}
	if opts.output != "" {
		t.Fatalf("output = %q, want empty (stream to stdout)", opts.output)
	}
	opts, err = parseDiscoverArgs([]string{"example.com", "--output", "out.jsonl"})
	if err != nil {
		t.Fatalf("parseDiscoverArgs: %v", err)
	}
	if opts.output != "out.jsonl" {
		t.Fatalf("output = %q, want out.jsonl", opts.output)
	}
	opts, err = parseDiscoverArgs([]string{"example.com", "--sources", "subfinder", "--output", "o.jsonl", "--no-cache"})
	if err != nil {
		t.Fatalf("parseDiscoverArgs: %v", err)
	}
	if opts.output != "o.jsonl" || len(opts.sources) != 1 || !opts.noCache {
		t.Fatalf("opts = %+v, want output+source+no-cache", opts)
	}
}

// TestDiscoverStreamSinkLines pins the sink rendering: one JSON line per
// event, serialized under concurrency, with the first write error sticky.
func TestDiscoverStreamSinkLines(t *testing.T) {
	h, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	var buf bytes.Buffer
	s := &discoverStream{w: &buf}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.write(discovery.HostEvent{Source: "subfinder", Host: h, Status: discovery.OutCompleted})
		}()
	}
	wg.Wait()
	if err := s.cause(); err != nil {
		t.Fatalf("cause: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 8 {
		t.Fatalf("lines = %d, want 8", len(lines))
	}
	want := `{"host":"api.example.com","source":"subfinder","discovered_at":"2026-08-13T12:00:00Z","status":"completed","cached":false}`
	for _, l := range lines {
		if l != want {
			t.Fatalf("line = %q, want %q", l, want)
		}
	}
}

// errWriter fails every write; it pins the sink's sticky-error behavior.
type errWriter struct{ err error }

func (w *errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDiscoverStreamSinkStickyError(t *testing.T) {
	h, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	s := &discoverStream{w: &errWriter{err: os.ErrClosed}}
	ev := discovery.HostEvent{Source: "subfinder", Host: h, Status: discovery.OutCompleted}
	s.write(ev)
	s.write(ev) // second write is a no-op once the first failed
	if s.cause() != os.ErrClosed {
		t.Fatalf("cause = %v, want the first write error", s.cause())
	}
}

// writeDiscoverShim installs a POSIX PATH shim for one discovery tool: it
// answers the detection probe and prints canned hosts for enumeration.
// Hermetic: real subprocesses, no installed tools, no network.
func writeDiscoverShim(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
}

// discoverShimPATH installs subfinder + assetfinder shims enumerating
// example.com (www.example.com via both — the stream-repeat fixture) and
// returns a cleanup-scoped PATH prepend. Skips on Windows (POSIX shims).
func discoverShimPATH(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell shims are not available on windows")
	}
	dir := t.TempDir()
	writeDiscoverShim(t, dir, "subfinder",
		`if [ "$1" = "-version" ]; then echo "Current Version: v2.6.3"; exit 0; fi`+"\n"+
			"echo \"api.example.com\"\n"+
			"echo \"www.example.com\"\n")
	writeDiscoverShim(t, dir, "assetfinder",
		`if [ "$1" = "-h" ]; then echo "Usage: assetfinder [domain]"; exit 2; fi`+"\n"+
			"echo \"www.example.com\"\n"+
			"echo \"blog.example.com\"\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func discoverStreamArgs(extra ...string) []string {
	args := []string{"example.com", "--sources", "subfinder,assetfinder", "--no-cache"}
	return append(args, extra...)
}

// TestRunDiscoverStreamsToStdout is the NEW-138 default-routing pin: without
// --output, host lines stream to stdout ahead of the byte-identical summary.
func TestRunDiscoverStreamsToStdout(t *testing.T) {
	discoverShimPATH(t)
	var buf bytes.Buffer
	if err := runDiscover(context.Background(), &buf, discoverStreamArgs()); err != nil {
		t.Fatalf("runDiscover: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`{"host":"api.example.com","source":"subfinder"`,
		`{"host":"www.example.com","source":"assetfinder"`,
		"RavenRecon discover: example.com",
		"Merged across sources: 3 unique hosts",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
	// Stream precedes summary: the last stream line sits before the report
	// header, and the summary body itself is unchanged (starts with the
	// same header the non-streaming renderer pins).
	streamIdx := strings.LastIndex(out, `{"host":`)
	headerIdx := strings.Index(out, "RavenRecon discover: example.com")
	if streamIdx < 0 || headerIdx < 0 || streamIdx > headerIdx {
		t.Fatalf("stream lines must precede the summary:\n%s", out)
	}
	// Dedup policy at the CLI surface: www.example.com streams twice (once
	// per source) while the merged summary carries it once.
	if got := strings.Count(out, `"www.example.com"`); got != 2 {
		t.Fatalf("www.example.com stream lines = %d, want 2 (repeat, not dedup)", got)
	}
	merged := out[strings.Index(out, "Merged across sources:"):]
	if got := strings.Count(merged, "www.example.com"); got != 1 {
		t.Fatalf("merged www.example.com lines = %d, want 1:\n%s", got, merged)
	}
}

// TestRunDiscoverOutputFile is the NEW-138 --output pin: the file gets ONLY
// the stream (never the summary); stdout keeps the summary only.
func TestRunDiscoverOutputFile(t *testing.T) {
	discoverShimPATH(t)
	file := filepath.Join(t.TempDir(), "stream.jsonl")
	var buf bytes.Buffer
	if err := runDiscover(context.Background(), &buf, discoverStreamArgs("--output", file)); err != nil {
		t.Fatalf("runDiscover: %v", err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read --output file: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("file lines = %d, want 4 (2 subfinder + 2 assetfinder):\n%s", len(lines), raw)
	}
	seen := map[string]int{}
	for _, l := range lines {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(l), &decoded); err != nil {
			t.Fatalf("file line is not valid JSON: %v (%q)", err, l)
		}
		for _, k := range []string{"host", "source", "discovered_at", "status", "cached"} {
			if _, ok := decoded[k]; !ok {
				t.Fatalf("file line missing key %q: %q", k, l)
			}
		}
		host, _ := decoded["host"].(string)
		src, _ := decoded["source"].(string)
		seen[host+"/"+src]++
	}
	for _, want := range []string{
		"api.example.com/subfinder", "www.example.com/subfinder",
		"www.example.com/assetfinder", "blog.example.com/assetfinder",
	} {
		if seen[want] != 1 {
			t.Fatalf("file missing %q (seen %v):\n%s", want, seen, raw)
		}
	}
	// The summary must never leak into the file silently.
	for _, banned := range []string{"RavenRecon discover:", "Merged across sources:", "outcome:"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("file must carry ONLY the stream, found %q:\n%s", banned, raw)
		}
	}
	// Stdout keeps the summary only — no stream lines.
	stdout := buf.String()
	if strings.Contains(stdout, `{"host":`) {
		t.Fatalf("with --output, stdout must be summary-only:\n%s", stdout)
	}
	for _, want := range []string{"RavenRecon discover: example.com", "Merged across sources: 3 unique hosts"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing summary %q:\n%s", want, stdout)
		}
	}
}

// TestRunDiscoverOutputFileBadPath fails before any tool runs: a bad --output
// path is a usage-time error, never a silent stream loss.
func TestRunDiscoverOutputFileBadPath(t *testing.T) {
	discoverShimPATH(t)
	var buf bytes.Buffer
	bad := filepath.Join(t.TempDir(), "no-such-dir", "stream.jsonl")
	err := runDiscover(context.Background(), &buf, discoverStreamArgs("--output", bad))
	if err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("want --output open error, got %v", err)
	}
}

// TestJoinDiscoverPostRunErrKeepsEveryCause pins the NEW-138 MEDIUM-2
// follow-up: post-run errors are joined, never laddered — a failing writer
// plus a failing run must surface both causes, not just the first.
func TestJoinDiscoverPostRunErrKeepsEveryCause(t *testing.T) {
	streamCause := errors.New("no space left on device")
	closeCause := errors.New("close: I/O error")
	runCause := errors.New("pool shutdown: context deadline exceeded")
	err := joinDiscoverPostRunErr("stream.jsonl", streamCause, closeCause, runCause)
	if err == nil {
		t.Fatal("want a joined error, got nil")
	}
	for _, cause := range []error{streamCause, closeCause, runCause} {
		if !errors.Is(err, cause) {
			t.Errorf("joined error missing cause %v:\n%v", cause, err)
		}
	}
	for _, want := range []string{"stream output", `close --output "stream.jsonl"`, "pool shutdown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q:\n%v", want, err)
		}
	}
	// Partial joins and the all-clean case.
	if err := joinDiscoverPostRunErr("", nil, nil, nil); err != nil {
		t.Fatalf("all-nil join = %v, want nil", err)
	}
	solo := joinDiscoverPostRunErr("", streamCause, nil, nil)
	if !errors.Is(solo, streamCause) || !strings.Contains(solo.Error(), "stream output") {
		t.Fatalf("single-cause join = %v, want the wrapped stream cause", solo)
	}
}

// TestRunDiscoverFailingStdoutSurfacesStreamCause proves the join is wired
// into runDiscover: a stdout that fails every write poisons the stream sink
// and the command reports the stream cause.
func TestRunDiscoverFailingStdoutSurfacesStreamCause(t *testing.T) {
	discoverShimPATH(t)
	w := &errWriter{err: errors.New("stdout exploded")}
	err := runDiscover(context.Background(), w, discoverStreamArgs())
	if err == nil || !strings.Contains(err.Error(), "stream output") {
		t.Fatalf("want stream-output error, got %v", err)
	}
	if !errors.Is(err, w.err) {
		t.Fatalf("returned error does not wrap the writer cause: %v", err)
	}
}

// TestDiscoverSummaryByteIdenticalWithAndWithoutStream pins LOW-2: enabling
// the host stream must not change one byte of the summary. A fixed Report
// renders through the untouched printDiscoverReport renderer twice — once
// with the stream sink fed (stream and summary on separate writers, as
// runDiscover wires them), once without — and the two summaries must be
// byte-identical. No renderer change; the stream leaves the summary alone.
func TestDiscoverSummaryByteIdenticalWithAndWithoutStream(t *testing.T) {
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	hosts := make([]asset.Host, 0, 3)
	for _, name := range []string{"api.example.com", "www.example.com", "blog.example.com"} {
		h, err := asset.NewHost(name, asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
		if err != nil {
			t.Fatalf("NewHost: %v", err)
		}
		hosts = append(hosts, h)
	}
	rep := discovery.Report{
		Target: target,
		Results: []discovery.SourceResult{
			{
				Source:    "subfinder",
				Detection: discovery.Detection{Source: "subfinder", Status: discovery.StatusOK, Reason: "executable /usr/bin/subfinder; version v2.6.3"},
				Status:    discovery.OutCompleted,
				Version:   "v2.6.3",
				Hosts:     hosts,
			},
			{
				Source:    "amass",
				Detection: discovery.Detection{Source: "amass", Status: discovery.StatusMissing, Reason: `executable "amass" not found`},
				Status:    discovery.OutSkipped,
			},
		},
	}
	var withoutStream bytes.Buffer
	if err := printDiscoverReport(&withoutStream, rep, false); err != nil {
		t.Fatalf("printDiscoverReport: %v", err)
	}
	// With streaming: feed every host through the real sink on its own
	// writer, then render the same summary.
	var stream bytes.Buffer
	sink := &discoverStream{w: &stream}
	for _, res := range rep.Results {
		for _, h := range res.Hosts {
			sink.write(discovery.HostEvent{Source: res.Source, Host: h, Status: res.Status})
		}
	}
	if err := sink.cause(); err != nil {
		t.Fatalf("stream sink: %v", err)
	}
	if got := strings.Count(strings.TrimSuffix(stream.String(), "\n"), "\n") + 1; got != 3 {
		t.Fatalf("stream lines = %d, want 3 (one per host)", got)
	}
	var withStream bytes.Buffer
	if err := printDiscoverReport(&withStream, rep, false); err != nil {
		t.Fatalf("printDiscoverReport: %v", err)
	}
	if !bytes.Equal(withStream.Bytes(), withoutStream.Bytes()) {
		t.Fatalf("summary differs with the stream enabled:\n--- without ---\n%s\n--- with ---\n%s", withoutStream.String(), withStream.String())
	}
}

// TestRunDiscoverOutputFileSlowContext is a hermetic backpressure note: the
// stream sink performs bounded O(line) writes on the finalizing worker, so a
// healthy run completes promptly even with --output on real subprocesses.
func TestRunDiscoverOutputFilePromptCompletion(t *testing.T) {
	discoverShimPATH(t)
	file := filepath.Join(t.TempDir(), "stream.jsonl")
	var buf bytes.Buffer
	start := time.Now()
	if err := runDiscover(context.Background(), &buf, discoverStreamArgs("--output", file)); err != nil {
		t.Fatalf("runDiscover: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 60*time.Second {
		t.Fatalf("streaming run took %s; want prompt bounded completion", elapsed)
	}
}
