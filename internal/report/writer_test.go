package report

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSanitizeBaseName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"EXample.COM", "example.com"},
		{"a b/c\\d", "a-b-c-d"},
		{"..", ""},
		{"../../etc/passwd", "etc-passwd"},
		{"host_underscore", "host-underscore"},
		{"trailing.dots...", "trailing.dots"},
		{"-leading-dash-", "leading-dash"},
	}
	for _, tc := range cases {
		got, err := sanitizeBaseName(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Fatalf("sanitizeBaseName(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("sanitizeBaseName(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("sanitizeBaseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if len(got) > maxBaseNameBytes {
			t.Fatalf("sanitized name over bound: %d", len(got))
		}
		if strings.ContainsAny(got, "/\\\x00") {
			t.Fatalf("sanitized name %q still carries path characters", got)
		}
	}
	long, err := sanitizeBaseName(strings.Repeat("a", 500))
	if err != nil {
		t.Fatalf("long name: %v", err)
	}
	if len(long) > maxBaseNameBytes {
		t.Fatalf("long name not bounded: %d", len(long))
	}
}

func TestFileSinkCommitCreatesDirectoryAndFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "reports")
	paths := map[string]string{
		"":      filepath.Join(dir, "report.json"),
		"hosts": filepath.Join(dir, "report.hosts.csv"),
	}
	sink, err := newFileSink(dir, false, func(part string) string { return paths[part] })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	w, err := sink.Writer("")
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	hw, err := sink.Writer("hosts")
	if err != nil {
		t.Fatalf("writer hosts: %v", err)
	}
	if _, err := hw.Write([]byte("host\n")); err != nil {
		t.Fatalf("write hosts: %v", err)
	}
	if err := hw.Close(); err != nil {
		t.Fatalf("close hosts: %v", err)
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("committed file missing: %v", err)
		}
	}
	// No temporary files survive a commit.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Fatalf("temp file survived commit: %s", e.Name())
		}
	}
}

func TestFileSinkAbortLeavesNoFiles(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json")
	os.WriteFile(final, []byte("previous"), 0o600) // a previous good report
	sink, err := newFileSink(dir, false, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	w, _ := sink.Writer("")
	w.Write([]byte("partial"))
	w.Close()
	sink.Abort()
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("previous file lost: %v", err)
	}
	data, _ := os.ReadFile(final)
	if string(data) != "previous" {
		t.Fatalf("previous file overwritten: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Fatalf("temp file survived abort: %s", e.Name())
		}
	}
}

func TestFileSinkRejectsReopenedAndOpenParts(t *testing.T) {
	sink, err := newFileSink(t.TempDir(), false, func(string) string { return "x" })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	w, _ := sink.Writer("")
	if _, err := sink.Writer(""); err == nil {
		t.Fatalf("reopened part accepted")
	}
	if _, err := sink.Parts(); err == nil {
		t.Fatalf("Parts accepted an open part")
	}
	io.WriteString(w, "x")
	w.Close()
	if _, err := sink.Parts(); err != nil {
		t.Fatalf("Parts rejected closed part: %v", err)
	}
	sink.Abort()
}

func TestFileSinkCompression(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json.gz")
	sink, err := newFileSink(dir, true, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	w, _ := sink.Writer("")
	payload := strings.Repeat("ravenrecon compression test ", 100)
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	parts, err := sink.Parts()
	if err != nil {
		t.Fatalf("parts: %v", err)
	}
	if !parts[0].Compressed {
		t.Fatalf("part not marked compressed")
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	f, err := os.Open(final)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != payload {
		t.Fatalf("decompressed payload mismatch")
	}
}

func TestFileSinkRawWriterSkipsCompression(t *testing.T) {
	// The raw-writer seam exists for the cache-hit commit: stored part
	// bytes are already-final file bytes (gzip-compressed for compressed
	// reporters) and must reach the temp file exactly as given, while
	// keeping every other sink semantic (temp file, close, fsync,
	// validation as compressed, atomic rename).
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json.gz")
	sink, err := newFileSink(dir, true, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	compressed := buf.Bytes()

	w, err := sink.RawWriter("")
	if err != nil {
		t.Fatalf("raw writer: %v", err)
	}
	if _, err := w.Write(compressed); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("raw close: %v", err)
	}
	parts, err := sink.Parts()
	if err != nil {
		t.Fatalf("parts: %v", err)
	}
	if !parts[0].Compressed {
		t.Fatalf("raw part not marked compressed (the file on disk is)")
	}
	if parts[0].Bytes != int64(len(compressed)) {
		t.Fatalf("raw part bytes = %d, want %d", parts[0].Bytes, len(compressed))
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(data, compressed) {
		t.Fatalf("raw writer did not preserve the exact file bytes (re-compressed?)")
	}
	// The compressed validator semantics hold: one decompression yields
	// the exact payload.
	r, err := openValidated(final, true)
	if err != nil {
		t.Fatalf("openValidated: %v", err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != `{"ok":true}` {
		t.Fatalf("decompressed payload mismatch: %q", got)
	}
}

func TestFileSinkOverwritesSafely(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json")
	os.WriteFile(final, []byte("old"), 0o600)
	sink, _ := newFileSink(dir, false, func(string) string { return final })
	w, _ := sink.Writer("")
	io.WriteString(w, `{"new":true}`)
	w.Close()
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	data, _ := os.ReadFile(final)
	if !bytes.Equal(data, []byte(`{"new":true}`)) {
		t.Fatalf("overwrite failed: %q", data)
	}
}

func TestMemSink(t *testing.T) {
	sink := newMemSink()
	w, err := sink.Writer("")
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	io.WriteString(w, "hello")
	w.Close()
	if _, err := sink.Writer(""); err == nil {
		t.Fatalf("reopened mem part accepted")
	}
	buf, err := sink.buffer("")
	if err != nil || string(buf) != "hello" {
		t.Fatalf("buffer = %q, %v", buf, err)
	}
	if _, err := sink.buffer("missing"); err == nil {
		t.Fatalf("missing buffer returned")
	}
}

func TestFileSinkRejectsInvalidPartNames(t *testing.T) {
	// Part names enter filenames; anything outside the framework's
	// [a-z0-9-] vocabulary (path separators, traversal, case, whitespace,
	// over-length) is rejected at the sink — the single choke point every
	// file-creating path (fresh render and cache-served commit) uses.
	sink, err := newFileSink(t.TempDir(), false, func(part string) string { return part })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	for _, part := range []string{
		"../evil", "../../etc/passwd", "a/b", `a\b`, "UPPER", "with space",
		"dot.name", strings.Repeat("x", 33), "\x00",
	} {
		if _, err := sink.Writer(part); err == nil {
			t.Fatalf("invalid part name %q accepted", part)
		}
	}
	if _, err := sink.Writer(""); err != nil {
		t.Fatalf("default part name rejected: %v", err)
	}
	if _, err := sink.Writer("hosts"); err != nil {
		t.Fatalf("legal part name rejected: %v", err)
	}
	sink.Abort()
}

// TestFileSinkCommitSyncsDirectory pins the crash-safe-write hardening:
// after the renames, Commit applies its directory-durability step to the
// output directory exactly once (NEW-33). The dirSync seam makes the call
// observable without depending on filesystem sync semantics.
func TestFileSinkCommitSyncsDirectory(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json")
	sink, err := newFileSink(dir, false, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	var called []string
	sink.dirSync = func(d string) error {
		called = append(called, d)
		return nil
	}
	w, err := sink.Writer("")
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	io.WriteString(w, `{"ok":true}`)
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(called) != 1 {
		t.Fatalf("dirSync called %d times, want exactly 1", len(called))
	}
	if called[0] != dir {
		t.Fatalf("dirSync called with %q, want output directory %q", called[0], dir)
	}
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("committed file missing: %v", err)
	}
}

// TestFileSinkCommitSkipsDirSyncWhenCommitFails verifies the durability
// step only follows successful renames: a commit that never renames (an
// open part) must not report the directory as synced.
func TestFileSinkCommitSkipsDirSyncWhenCommitFails(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileSink(dir, false, func(string) string { return filepath.Join(dir, "report.json") })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	var calls int
	sink.dirSync = func(string) error { calls++; return nil }
	if _, err := sink.Writer(""); err != nil {
		t.Fatalf("writer: %v", err)
	}
	// The part is still open: Parts fails and Commit returns before any
	// rename.
	if err := sink.Commit(); err == nil {
		t.Fatal("expected Commit to fail with an open part")
	}
	if calls != 0 {
		t.Fatalf("dirSync called %d times on failed commit, want 0", calls)
	}
	sink.Abort()
}

// TestFileSinkCommitToleratesDirSyncFailure pins the best-effort contract:
// the files are already renamed into place when the directory sync runs,
// so a dir-sync failure must never fail the Commit nor lose the report.
func TestFileSinkCommitToleratesDirSyncFailure(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "report.json")
	sink, err := newFileSink(dir, false, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	sink.dirSync = func(string) error { return errors.New("injected dir-sync failure") }
	w, err := sink.Writer("")
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	io.WriteString(w, `{"ok":true}`)
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("Commit must succeed despite dir-sync failure: %v", err)
	}
	data, err := os.ReadFile(final)
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("committed content lost after dir-sync failure: %q, %v", data, err)
	}
}

// TestSyncDirBestEffort exercises the real helper on a live directory; on
// filesystems without directory-fsync support the helper's ENOSYS/EINVAL
// filter keeps it silent (see internal/cache for the errno table test).
func TestSyncDirBestEffort(t *testing.T) {
	dir := t.TempDir()
	if err := syncDirBestEffort(dir); err != nil {
		t.Logf("directory fsync unsupported or failed on this filesystem (treated as best-effort): %v", err)
	}
	if err := syncDirBestEffort(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("syncDirBestEffort on a missing directory must report the open error")
	}
	if !isUnsupportedDirSync(fmt.Errorf("wrap: %w", syscall.ENOSYS)) {
		t.Fatal("ENOSYS must classify as unsupported directory fsync")
	}
	if isUnsupportedDirSync(io.EOF) {
		t.Fatal("ordinary errors must not classify as unsupported directory fsync")
	}
}
