//go:build !windows

package adapt

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// TestRunSubjsWithRealExecutable exercises the production path end to end
// with a real executable on a temporary PATH: exec.LookPath resolution (nil
// lookup seam), the hardened discovery ExecRunner (nil runner seam), the
// subjs temp-file flow with real file creation/removal, and the ItemLine
// stream. The detection probe runs through the same real path. Hermetic:
// the executable is a tiny shell script we wrote — no real tools, no
// network.
func TestRunSubjsWithRealExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "subjs")
	// The read is EOF-tolerant: the adapter writes exactly the target URL
	// with no trailing newline, and shell read returns non-zero at EOF even
	// when it read characters — `|| [ -n "$url" ]` keeps the final line,
	// matching how a real Go tool (bufio.Scanner) reads it.
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-version\" ]; then\n" +
		"  echo \"subjs version: 1.0.1\"\n" +
		"  exit 0\n" +
		"fi\n" +
		"while read -r url || [ -n \"$url\" ]; do\n" +
		"  printf '%sapp.js\\n' \"$url\"\n" +
		"done < \"$6\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Detection through the real seams: nil runner (ExecRunner), nil lookup
	// (exec.LookPath). The version probe prints "subjs version: 1.0.1".
	r := discovery.Runner(nil)
	d := Detect(context.Background(), &r, nil, Tools["subjs"], nil)
	if d.Status != discovery.StatusOK || d.Version != "1.0.1" || !d.Capable || !d.Exists {
		t.Fatalf("detection = %+v, want OK/version 1.0.1/capable/exists", d)
	}

	// Execution through the real seams with a nil runner pointer (the
	// production ExecRunner) and nil overrides: the adapter passes the bare
	// name "subjs" as Path and the RUNNER resolves it through PATH.
	src, err := Run(context.Background(), nil, Tools["subjs"], "https://example.com/", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	items := drainItems(t, src)
	requireLines(t, items, "https://example.com/app.js")

	// The temp file was created and removed by the adapter; no leftover may
	// remain in os.TempDir. The adapter's pattern prefix pins the naming so
	// the leftover check is exact.
	leftovers, lerr := filepath.Glob(filepath.Join(os.TempDir(), "ravenrecon-subjs-*.txt"))
	if lerr != nil {
		t.Fatalf("glob temp dir: %v", lerr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("leftover subjs temp files: %v", leftovers)
	}
}

// TestRunScriptToolWithRealWrapper runs the python pair end to end through
// the real seams with a PATH wrapper that has a shebang — the documented
// install contract of the wrapper model (the script IS the executable; the
// adapter passes the bare name and the runner resolves it). Detection
// (existence-only) and execution share the real path.
func TestRunScriptToolWithRealWrapper(t *testing.T) {
	dir := t.TempDir()
	// A sh wrapper standing in for the linkfinder executable: shebang,
	// ignores the pinned argv, prints one endpoint on stdout.
	lf := filepath.Join(dir, "linkfinder.py")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-i\" ]; then\n" +
		"  printf '/api/v1/users\\n'\n" +
		"fi\n"
	if err := os.WriteFile(lf, []byte(script), 0o755); err != nil {
		t.Fatalf("write linkfinder.py wrapper: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	r := discovery.Runner(nil)
	d := Detect(context.Background(), &r, nil, Tools["linkfinder"], nil)
	if d.Status != discovery.StatusOK || !d.Capable || !d.Exists {
		t.Fatalf("detection = %+v, want OK/capable/exists", d)
	}
	if d.Version != "" {
		t.Fatalf("existence-only detection reported version %q, want none", d.Version)
	}

	src, err := Run(context.Background(), nil, Tools["linkfinder"], "https://example.com/", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	requireLines(t, drainItems(t, src), "/api/v1/users")
}
