//go:build !windows

package adapt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestRunWithRealExecutable exercises the production path end to end with a
// real executable on a temporary PATH: exec.LookPath resolution, the
// hardened discovery ExecRunner, unbounded-by-construction argv passing
// (probe argv vs positional target argv), and the full ingest pipeline.
// Hermetic: the executable is a tiny shell script we wrote — no real tools,
// no network.
func TestRunWithRealExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "gau")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-version\" ]; then\n" +
		"  echo \"gau 2.1.1\"\n" +
		"else\n" +
		"  printf 'https://example.com/a?q=1\\nhttps://example.com/b\\n'\n" +
		"fi\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := DefaultConfig()
	cfg.Tools = []Tool{Gau()}
	cfg.Targets = []asset.Host{mustHost(t, "example.com")}
	cfg.Concurrency = 1
	cfg.QueueSize = 4
	cfg.Timeout = 30 * time.Second
	cfg.Rate = 0
	cfg.Burst = 0
	cfg.IngestWorkers = 2
	cfg.Clock = newFakeClock(fixedTime)

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Status != ResultCompleted || r.Lines != 2 {
		t.Fatalf("result = %+v, want completed with 2 lines", r)
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report),
		[]string{"https://example.com/a?q=1", "https://example.com/b"})
	if rep.Report.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0 (clean URL lines only)", rep.Report.Malformed)
	}
}

// TestRunWithRealExecutableBadLines: garbage lines from a real process are
// counted as malformed by the engine, never fatal and never entries.
func TestRunWithRealExecutableBadLines(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "waymore")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then\n" +
		"  echo \"waymore v1.0.0\"\n" +
		"else\n" +
		"  printf 'https://example.com/ok\\nnot a url at all\\n'\n" +
		"fi\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := DefaultConfig()
	cfg.Tools = []Tool{Waymore()}
	cfg.Targets = []asset.Host{mustHost(t, "example.com")}
	cfg.Concurrency = 1
	cfg.QueueSize = 4
	cfg.Timeout = 30 * time.Second
	cfg.Rate = 0
	cfg.IngestWorkers = 2
	cfg.Clock = newFakeClock(fixedTime)

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Results[0].Status != ResultCompleted {
		t.Fatalf("result = %+v, want completed", rep.Results[0])
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{"https://example.com/ok"})
	if rep.Report.Malformed != 1 {
		t.Fatalf("malformed = %d, want 1 (the non-URL line)", rep.Report.Malformed)
	}
}
