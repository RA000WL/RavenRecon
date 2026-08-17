package report

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
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
