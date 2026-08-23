package importer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// --- fixtures ---------------------------------------------------------------

const classicCDX = "com,example)/ 20200809173112 https://example.com/ text/html 200 P7VYB5Q2N4CEP2HJDJFO4M2XU3FJLY7A 10421\n" +
	"com,example)/page-a 20200809173113 https://example.com/page-a text/html 200 ABCDEFGHIJKLMNOPQRST 523\n"

// writeArchiveTemp writes content to a fresh temp dir under a custom name.
func writeArchiveTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// writeGzipArchiveTemp gzips content into name (e.g. "sample.cdx.gz").
func writeGzipArchiveTemp(t *testing.T, name, content string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzipWriterFor(&buf)
	gz.write([]byte(content))
	gz.close()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

type warcRec struct {
	target    string
	warcType  string
	body      []byte
	noLength  bool  // omit Content-Length entirely (malformed)
	lengthLie int64 // declare this Content-Length instead of len(body)
	extraHdr  string
}

// buildWARC emits spec-framed records: headers CRLF-terminated, blank line,
// payload, then the CRLFCRLF record separator.
func buildWARC(recs []warcRec) string {
	var b strings.Builder
	for i, r := range recs {
		b.WriteString("WARC/1.0\r\n")
		fmt.Fprintf(&b, "WARC-Record-ID: <urn:test:rec-%d>\r\n", i)
		if r.warcType != "" {
			b.WriteString("WARC-Type: " + r.warcType + "\r\n")
		}
		if r.target != "" {
			b.WriteString("WARC-Target-URI: " + r.target + "\r\n")
		}
		if r.extraHdr != "" {
			b.WriteString(r.extraHdr)
		}
		if !r.noLength {
			cl := int64(len(r.body))
			if r.lengthLie > 0 {
				cl = r.lengthLie
			}
			fmt.Fprintf(&b, "Content-Length: %d\r\n", cl)
		}
		b.WriteString("\r\n")
		b.Write(r.body)
		b.WriteString("\r\n\r\n")
	}
	return b.String()
}

func mustTopName(t *testing.T, path, peek string) string {
	t.Helper()
	r := newFullRegistry(t)
	matches := r.Detect(path, []byte(peek))
	if len(matches) == 0 {
		t.Fatalf("Detect(%s): no matches", path)
	}
	return matches[0].Importer.Name()
}

// --- detection ---------------------------------------------------------------

func TestArchiveDetection(t *testing.T) {
	r := newFullRegistry(t)

	cases := []struct {
		name    string
		content string
		file    string
		wantTop string
	}{
		{
			name:    "classic cdx",
			content: strings.Repeat(classicCDX, 3),
			file:    "export.cdx",
			wantTop: "archive-cdx",
		},
		{
			name:    "cdx renamed dat",
			content: strings.Repeat(classicCDX, 3),
			file:    "export.dat",
			wantTop: "archive-cdx",
		},
		{
			name: "surtless variant detected by content",
			content: strings.Repeat(
				"https://example.com/plain 20200809173114 text/plain 200 DIGESTXYZDIGESTXYZ 900\n", 4),
			file:    "plain.txt",
			wantTop: "archive-cdx",
		},
		{
			name: "iso-ish timestamp variant",
			content: strings.Repeat(
				"com,example)/iso 2020-08-09T17:31:15Z https://example.com/iso text/html - DIGESTQQ 700\n", 4),
			file:    "iso.cdx",
			wantTop: "archive-cdx",
		},
		{
			name:    "warc magic",
			content: buildWARC([]warcRec{{target: "https://example.com/", warcType: "response", body: []byte("<html></html>")}}),
			file:    "capture.warc",
			wantTop: "archive-warc",
		},
		{
			name:    "warc renamed txt",
			content: buildWARC([]warcRec{{target: "https://example.com/", warcType: "response", body: []byte("x")}}),
			file:    "capture.txt",
			wantTop: "archive-warc",
		},
		{
			name:    "plain urls not stolen",
			content: "https://example.com/a\nhttps://example.com/b\nhttps://example.com/c\n",
			file:    "urls.txt",
			wantTop: "plain-urls",
		},
		{
			name: "one stray cdx line among url list stays plain",
			content: func() string {
				var b strings.Builder
				for i := 0; i < 20; i++ {
					fmt.Fprintf(&b, "https://example.com/u%d\n", i)
				}
				b.WriteString(strings.TrimRight(classicCDX, "\n"))
				return b.String()
			}(),
			file:    "mixed.txt",
			wantTop: "plain-urls",
		},
		{
			name:    "httpx ndjson still json family",
			content: "{\"url\":\"https://example.com\",\"status_code\":200}\n{\"url\":\"https://example.com/b\",\"status_code\":200}\n",
			file:    "out.jsonl",
			wantTop: "json-httpx",
		},
		{
			name:    "burp xml still xml family",
			content: "<?xml version=\"1.0\"?><items><item><url>https://example.com/a</url></item></items>",
			file:    "burp.xml",
			wantTop: "xml-burp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeArchiveTemp(t, tc.file, tc.content)
			peek, err := peekFile(p)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			matches := r.Detect(p, peek)
			if len(matches) == 0 {
				t.Fatalf("no matches for %s", tc.file)
			}
			if got := matches[0].Importer.Name(); got != tc.wantTop {
				t.Fatalf("top match %q (%.2f), want %q", got, matches[0].Confidence, tc.wantTop)
			}
		})
	}

	t.Run("gzip cdx detected via inflated content", func(t *testing.T) {
		p := writeGzipArchiveTemp(t, "export.cdx.gz", strings.Repeat(classicCDX, 3))
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if got := mustTopName(t, p, string(peek)); got != "archive-cdx" {
			t.Fatalf("top %q want archive-cdx", got)
		}
	})

	t.Run("gzip warc detected via inflated content", func(t *testing.T) {
		p := writeGzipArchiveTemp(t, "capture.warc.gz",
			buildWARC([]warcRec{{target: "https://example.com/", warcType: "response", body: []byte("hi")}}))
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if got := mustTopName(t, p, string(peek)); got != "archive-warc" {
			t.Fatalf("top %q want archive-warc", got)
		}
	})

	t.Run("corrupt gzip declines honestly", func(t *testing.T) {
		p := writeArchiveTemp(t, "bad.cdx.gz", "\x1f\x8bdefinitely-not-gzip-payload")
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		for _, m := range r.Detect(p, peek) {
			if n := m.Importer.Name(); n == "archive-cdx" || n == "archive-warc" {
				t.Fatalf("archive importer claimed corrupt gzip: %s", n)
			}
		}
	})

	t.Run("whitespace-only file claimed by nobody", func(t *testing.T) {
		p := writeArchiveTemp(t, "blank.txt", "   \n\t\n")
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if matches := r.Detect(p, peek); len(matches) != 0 {
			t.Fatalf("expected no claims, got %d", len(matches))
		}
	})

	t.Run("half cdx half urls resolves to archive-cdx", func(t *testing.T) {
		// Documented ambiguity: at exactly ratio 0.5 both families claim;
		// the structured format outranks the loose URL shape.
		var b strings.Builder
		for i := 0; i < 10; i++ {
			fmt.Fprintf(&b, "https://example.com/u%d\n", i)
		}
		b.WriteString(strings.Repeat(classicCDX, 10))
		p := writeArchiveTemp(t, "half.txt", b.String())
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if got := mustTopName(t, p, string(peek)); got != "archive-cdx" {
			t.Fatalf("top %q want archive-cdx", got)
		}
	})
}

// --- CDX import ---------------------------------------------------------------

func TestCDXImportTable(t *testing.T) {
	cases := []struct {
		name       string
		content    string
		bounds     Bounds
		wantProc   int
		wantFailed int
		wantTrunc  bool
		wantURLs   int
	}{
		{
			name:     "valid classic with duplicate",
			content:  classicCDX + "com,example)/ 20200901000000 https://example.com/ text/html 200 SAME 42\n",
			wantProc: 2, wantURLs: 2,
		},
		{
			name:       "malformed row counted failed",
			content:    "these are just some random words here\n",
			wantFailed: 1,
		},
		{
			name:     "surtless variant imports original from field zero",
			content:  "https://example.com/plain 20200809173114 text/plain 200 DIGESTXX 900\n",
			wantProc: 1,
			wantURLs: 1,
		},
		{
			name:     "empty file",
			content:  "",
			wantProc: 0, wantURLs: 0,
		},
		{
			name:      "decompressed cap trips honest truncation",
			content:   strings.Repeat(classicCDX, 4),
			bounds:    Bounds{MaxDecompressedBytes: 64},
			wantProc:  0,
			wantTrunc: true,
		},
		{
			name:       "oversized line failed and truncated",
			content:    strings.Repeat(classicCDX, 1) + "com,example)/huge 20200809173115 https://example.com/" + strings.Repeat("a", 40000) + " text/html 200 D 1\n" + "com,example)/tail 20200809173116 https://example.com/tail text/html 200 TAILD 12\n",
			wantProc:   3,
			wantFailed: 1,
			wantTrunc:  true,
			wantURLs:   3,
		},
		{
			name:      "max output tail drop",
			content:   classicCDX + "com,example)/c 20200809173117 https://example.com/c text/html 200 CCC 7\n",
			bounds:    Bounds{MaxOutput: 2},
			wantProc:  2,
			wantTrunc: true,
			wantURLs:  2,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := writeArchiveTemp(t, "in.cdx", tc.content)
			env := ImportEnv{Clock: fixedClock(), Bounds: tc.bounds}
			sink := NewSink()
			stats, err := NewArchiveCDXImporter().Import(context.Background(), env, p, sink)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if stats.ItemsProcessed != tc.wantProc || stats.ItemsFailed != tc.wantFailed {
				t.Fatalf("stats processed=%d failed=%d want %d/%d", stats.ItemsProcessed, stats.ItemsFailed, tc.wantProc, tc.wantFailed)
			}
			if stats.Truncated != tc.wantTrunc {
				t.Fatalf("truncated=%v want %v", stats.Truncated, tc.wantTrunc)
			}
			if stats.Truncated && !stats.StickyFlags["import_truncated"] {
				t.Fatalf("sticky import_truncated missing: %+v", stats.StickyFlags)
			}
			if len(sink.URLs) != tc.wantURLs {
				t.Fatalf("urls=%d want %d", len(sink.URLs), tc.wantURLs)
			}
		})
	}
}

func TestCDXCancellation(t *testing.T) {
	p := writeArchiveTemp(t, "in.cdx", classicCDX)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	sink := NewSink()
	stats, err := NewArchiveCDXImporter().Import(cctx, ImportEnv{Clock: fixedClock()}, p, sink)
	if err != context.Canceled {
		t.Fatalf("err %v want context.Canceled", err)
	}
	if len(stats.StickyFlags) != 0 {
		t.Fatalf("sticky flags on cancel: %+v", stats.StickyFlags)
	}
}

func TestCDXProvenanceAndMetadata(t *testing.T) {
	line := strings.SplitN(classicCDX, "\n", 2)[0]
	p := writeArchiveTemp(t, "prov.cdx", line+"\n")
	sink := NewSink()
	stats, err := NewArchiveCDXImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 1 || len(sink.ProvenanceRecords) != 1 {
		t.Fatalf("stats %+v sink %d", stats, len(sink.ProvenanceRecords))
	}
	rec := sink.ProvenanceRecords[0]
	if rec.Importer != "archive-cdx" {
		t.Fatalf("importer %q", rec.Importer)
	}
	if rec.OriginalTool != "wayback-cdx" {
		t.Fatalf("tool %q want wayback-cdx", rec.OriginalTool)
	}
	if rec.Filename != "prov.cdx" {
		t.Fatalf("filename %q", rec.Filename)
	}
	// readLines' raw capture is the verbatim logical line INCLUDING its
	// terminating newline — OriginalRecord must match byte-for-byte.
	if rec.OriginalRecord != line+"\n" {
		t.Fatalf("OriginalRecord drift:\n got %q\nwant %q", rec.OriginalRecord, line+"\n")
	}
	if rec.Identity == "" || rec.Identity != sink.URLs[0].Identity().String() {
		t.Fatalf("identity mismatch %q", rec.Identity)
	}
	for k, want := range map[string]string{
		"timestamp": "20200809173112",
		"mimetype":  "text/html",
		"status":    "200",
		"length":    "10421",
	} {
		if got := rec.Metadata[k]; got != want {
			t.Fatalf("metadata[%s]=%q want %q", k, got, want)
		}
	}
	if sink.URLs[0].Prov.Source != "wayback-cdx" {
		t.Fatalf("asset provenance source %q", sink.URLs[0].Prov.Source)
	}
}

// TestRegressionMED_CDXSurtlessMetadataColumns pins that surtless CDX rows
// (original URL leading, no SURT key) persist their TRUE columns: mimetype
// from field 2, status from field 3, length from field 5 — not the classic
// offsets shifted one too late (regression: mimetype stored "200"/status,
// status stored the digest). The interleaved subtest proves per-row column
// selection when both layouts share one file.
func TestRegressionMED_CDXSurtlessMetadataColumns(t *testing.T) {
	const surtlessLine = "https://example.com/plain 20200809173114 text/plain 200 DIGESTXX 900"

	t.Run("surtless row keeps true columns", func(t *testing.T) {
		p := writeArchiveTemp(t, "surtless.cdx", surtlessLine+"\n")
		sink := NewSink()
		stats, err := NewArchiveCDXImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 1 || stats.ItemsFailed != 0 || len(sink.URLs) != 1 {
			t.Fatalf("stats %+v urls=%d want processed=1 failed=0 urls=1", stats, len(sink.URLs))
		}
		rec := sink.ProvenanceRecords[0]
		for k, want := range map[string]string{
			"timestamp": "20200809173114", // field 1 in both layouts
			"mimetype":  "text/plain",     // field 2 (surtless)
			"status":    "200",            // field 3 (surtless)
			"length":    "900",            // field 5 (surtless)
		} {
			if got := rec.Metadata[k]; got != want {
				t.Fatalf("metadata[%s]=%q want %q (full map: %v)", k, got, want, rec.Metadata)
			}
		}
	})

	t.Run("interleaved layouts select columns per row", func(t *testing.T) {
		content := surtlessLine + "\n" +
			strings.SplitN(classicCDX, "\n", 2)[0] + "\n" +
			"https://example.com/plain2 20200809173115 text/csv 301 DIGESTYY 901\n"
		p := writeArchiveTemp(t, "mixed.cdx", content)
		sink := NewSink()
		stats, err := NewArchiveCDXImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 3 || stats.ItemsFailed != 0 || len(sink.URLs) != 3 {
			t.Fatalf("stats %+v urls=%d want processed=3 failed=0 urls=3", stats, len(sink.URLs))
		}
		wantMeta := []map[string]string{
			{
				"timestamp": "20200809173114",
				"mimetype":  "text/plain",
				"status":    "200",
				"length":    "900",
			},
			{
				"timestamp": "20200809173112",
				"mimetype":  "text/html",
				"status":    "200",
				"length":    "10421",
			},
			{
				"timestamp": "20200809173115",
				"mimetype":  "text/csv",
				"status":    "301",
				"length":    "901",
			},
		}
		for i, want := range wantMeta {
			got := sink.ProvenanceRecords[i].Metadata
			for k, w := range want {
				if g := got[k]; g != w {
					t.Fatalf("record %d metadata[%s]=%q want %q (full map: %v)", i, k, g, w, got)
				}
			}
		}
	})
}

func TestCDXGzipImport(t *testing.T) {
	p := writeGzipArchiveTemp(t, "in.cdx.gz", classicCDX+"com,example)/dup 20200809173118 https://example.com/ text/html 200 DUPP 1\n")
	sink := NewSink()
	stats, err := NewArchiveCDXImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 || len(sink.URLs) != 2 {
		t.Fatalf("processed=%d urls=%d want 2/2", stats.ItemsProcessed, len(sink.URLs))
	}
}

// --- WARC import --------------------------------------------------------------

func TestWARCImportTable(t *testing.T) {
	cases := []struct {
		name       string
		content    string
		bounds     Bounds
		wantProc   int
		wantFailed int
		wantTrunc  bool
		wantURLs   int
		wantErr    string
	}{
		{
			name: "valid two records dedup across types",
			content: buildWARC([]warcRec{
				{target: "https://example.com/", warcType: "response", body: []byte("<html>one</html>")},
				{target: "https://example.com/page", warcType: "request", body: nil},
				{target: "https://example.com/", warcType: "revisit", body: []byte("again")},
			}),
			wantProc: 2, wantURLs: 2,
		},
		{
			name: "record without target uri failed",
			content: buildWARC([]warcRec{
				{target: "", warcType: "metadata", body: []byte("nothing")},
				{target: "https://example.com/ok", warcType: "response", body: []byte("ok")},
			}),
			wantProc: 1, wantFailed: 1, wantURLs: 1,
		},
		{
			name: "invalid target uri failed",
			content: buildWARC([]warcRec{
				{target: "::::not-a-uri:::", warcType: "response", body: []byte("junk")},
			}),
			wantFailed: 1,
		},
		{
			name:     "empty file",
			content:  "",
			wantProc: 0, wantURLs: 0,
		},
		{
			name:    "garbage first line fails structurally",
			content: "hello world\r\nnot a warc\r\n",
			wantErr: "not a WARC file",
		},
		{
			name: "missing content-length resyncs to next record",
			content: "WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.com/a\r\n\r\n" +
				"junk-alpha\njunk-beta\n" +
				buildWARC([]warcRec{{target: "https://example.com/b", warcType: "response", body: []byte("bb")}}),
			wantProc: 2, wantFailed: 2, wantURLs: 2,
		},
		{
			name: "truncated payload is honest truncation",
			content: buildWARC([]warcRec{
				{target: "https://example.com/cut", warcType: "response", body: []byte("short"), lengthLie: 100000},
			}),
			wantProc: 1, wantTrunc: true, wantURLs: 1,
		},
		{
			name: "oversized header block failed but stream continues",
			content: buildWARC([]warcRec{
				{target: "https://example.com/big", extraHdr: "X-Junk: " + strings.Repeat("j", 40000) + "\r\n", body: []byte("payload")},
				{target: "https://example.com/next", warcType: "response", body: []byte("fine")},
			}),
			wantProc: 1, wantFailed: 1, wantTrunc: true, wantURLs: 1,
		},
		{
			name: "decompression cap aborts truncated",
			content: buildWARC([]warcRec{
				{target: "https://example.com/bomb", warcType: "response", body: bytes.Repeat([]byte("x"), 8192)},
			}),
			bounds:    Bounds{MaxDecompressedBytes: 256},
			wantProc:  1, // handle runs before payload discard; tail dropped
			wantTrunc: true,
			wantURLs:  1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := writeArchiveTemp(t, "in.warc", tc.content)
			env := ImportEnv{Clock: fixedClock(), Bounds: tc.bounds}
			sink := NewSink()
			stats, err := NewArchiveWARCImporter().Import(context.Background(), env, p, sink)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if stats.ItemsProcessed != tc.wantProc || stats.ItemsFailed != tc.wantFailed {
				t.Fatalf("stats processed=%d failed=%d want %d/%d", stats.ItemsProcessed, stats.ItemsFailed, tc.wantProc, tc.wantFailed)
			}
			if stats.Truncated != tc.wantTrunc {
				t.Fatalf("truncated=%v want %v", stats.Truncated, tc.wantTrunc)
			}
			if stats.Truncated && !stats.StickyFlags["import_truncated"] {
				t.Fatalf("sticky import_truncated missing: %+v", stats.StickyFlags)
			}
			if len(sink.URLs) != tc.wantURLs {
				t.Fatalf("urls=%d want %d", len(sink.URLs), tc.wantURLs)
			}
		})
	}
}

func TestWARCCancellation(t *testing.T) {
	content := buildWARC([]warcRec{
		{target: "https://example.com/x", warcType: "response", body: []byte("data")},
	})
	p := writeArchiveTemp(t, "cancel.warc", content)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	sink := NewSink()
	stats, err := NewArchiveWARCImporter().Import(cctx, ImportEnv{Clock: fixedClock()}, p, sink)
	if err != context.Canceled {
		t.Fatalf("err %v want context.Canceled", err)
	}
	if len(stats.StickyFlags) != 0 {
		t.Fatalf("sticky flags on cancel: %+v", stats.StickyFlags)
	}
}

func TestWARCGzipImportAndPayloadDiscard(t *testing.T) {
	body := "<html>" + strings.Repeat("secret-body-that-must-not-be-retained ", 50) + "</html>"
	content := buildWARC([]warcRec{
		{target: "https://example.com/gz", warcType: "response", body: []byte(body)},
	})
	p := writeGzipArchiveTemp(t, "in.warc.gz", content)
	sink := NewSink()
	stats, err := NewArchiveWARCImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 1 || len(sink.URLs) != 1 {
		t.Fatalf("processed=%d urls=%d want 1/1", stats.ItemsProcessed, len(sink.URLs))
	}
	rec := sink.ProvenanceRecords[0]
	if !strings.HasPrefix(rec.OriginalRecord, "WARC/1.0\r\n") {
		t.Fatalf("OriginalRecord not verbatim header block: %q", rec.OriginalRecord[:min(40, len(rec.OriginalRecord))])
	}
	if strings.Contains(rec.OriginalRecord, "secret-body") {
		t.Fatal("payload leaked into OriginalRecord")
	}
	if rec.Metadata["warc_type"] != "response" {
		t.Fatalf("warc_type metadata %q", rec.Metadata["warc_type"])
	}
	if rec.OriginalTool != "warc" {
		t.Fatalf("tool %q want warc", rec.OriginalTool)
	}
	// Verbatim exactness against the fixture's header block.
	wantBlock := "WARC/1.0\r\nWARC-Record-ID: <urn:test:rec-0>\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.com/gz\r\nContent-Length: " +
		fmt.Sprintf("%d", len(body)) + "\r\n\r\n"
	if rec.OriginalRecord != wantBlock {
		t.Fatalf("header block drift:\n got %q\nwant %q", rec.OriginalRecord, wantBlock)
	}
}

// --- streaming bounded memory ---------------------------------------------------

// TestWARCStreamingNoPerRecordRetention pins that streaming a large WARC of
// duplicate-target records retains nothing per record: the dedup trick keeps
// the retained asset set at two entries while every record is consumed
// (sentinel proves clean EOF).
func TestWARCStreamingNoPerRecordRetention(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	const dups = 60000
	var b strings.Builder
	for i := 0; i < dups; i++ {
		b.WriteString("WARC/1.0\r\nWARC-Target-URI: https://example.com/same\r\nContent-Length: 12\r\n\r\npayloadbytes\r\n\r\n")
	}
	b.WriteString(buildWARC([]warcRec{{target: "https://example.com/sentinel-last", warcType: "response", body: []byte("end")}}))
	path := writeArchiveTemp(t, "dup.warc", b.String())

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewArchiveWARCImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	if got := len(sink.URLs); got != 2 {
		t.Fatalf("urls %d want 2 (dedup + sentinel) — stream stopped early?", got)
	}
	// Dedup parity with the XML/JSON retention tests: duplicates are neither
	// processed nor failed, so only first occurrence + sentinel count.
	if stats.ItemsProcessed != 2 || stats.ItemsFailed != 0 || stats.Truncated {
		t.Fatalf("stats %+v want processed=2 failed=0 truncated=false", stats)
	}
	runtime.KeepAlive(sink)

	var heapDelta uint64
	if m2.HeapInuse > m1.HeapInuse {
		heapDelta = m2.HeapInuse - m1.HeapInuse
	}
	t.Logf("measured streaming overhead delta: %d bytes (%.2f MiB) over %d records (~%.1f MiB file)",
		heapDelta, float64(heapDelta)/(1<<20), dups+1, float64(b.Len())/(1<<20))
	const maxDelta = 8 << 20
	if heapDelta > maxDelta {
		t.Fatalf("streaming overhead delta %d exceeds %d — per-record retention?", heapDelta, maxDelta)
	}
}

// TestCDXStreamingNoPerRecordRetention applies the same pin to the CDX
// importer (readLines-based): duplicates collapse to one retained asset plus
// the sentinel, so any per-record retention shows up as heap growth.
func TestCDXStreamingNoPerRecordRetention(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	const dups = 60000
	var b strings.Builder
	dupLine := "com,example)/same 20200809173112 https://example.com/same text/html 200 SAMEDIGESTSAM 10421\n"
	for i := 0; i < dups; i++ {
		b.WriteString(dupLine)
	}
	b.WriteString("com,example)/sentinel-last 20200809173199 https://example.com/sentinel-last text/html 200 SENTINELLA 10\n")
	path := writeArchiveTemp(t, "dup.cdx", b.String())

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewArchiveCDXImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	if got := len(sink.URLs); got != 2 {
		t.Fatalf("urls %d want 2 (dedup + sentinel)", got)
	}
	if stats.ItemsProcessed != 2 || stats.ItemsFailed != 0 || stats.Truncated {
		t.Fatalf("stats %+v want processed=2 failed=0 truncated=false", stats)
	}
	runtime.KeepAlive(sink)

	var heapDelta uint64
	if m2.HeapInuse > m1.HeapInuse {
		heapDelta = m2.HeapInuse - m1.HeapInuse
	}
	t.Logf("measured streaming overhead delta: %d bytes (%.2f MiB) over %d lines (~%.1f MiB file)",
		heapDelta, float64(heapDelta)/(1<<20), dups+1, float64(b.Len())/(1<<20))
	const maxDelta = 8 << 20
	if heapDelta > maxDelta {
		t.Fatalf("streaming overhead delta %d exceeds %d — per-record retention?", heapDelta, maxDelta)
	}
}

// TestWARCProgressEmitted pins bounded progress emission through the observer.
func TestWARCProgressEmitted(t *testing.T) {
	rec := buildWARC([]warcRec{
		{target: "https://example.com/p", warcType: "response", body: bytes.Repeat([]byte("p"), 128*1024)},
	})
	path := writeArchiveTemp(t, "prog.warc", rec)
	obs := &countingObserver{}
	env := ImportEnv{Clock: fixedClock(), Observer: obs}
	sink := NewSink()
	if _, err := NewArchiveWARCImporter().Import(context.Background(), env, path, sink); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if obs.n == 0 {
		t.Fatal("no progress events emitted despite >64KiB streamed")
	}
}

// countingObserver counts progress events without ever blocking (observer
// contract parity with the event bus).
type countingObserver struct {
	n int
}

func (c *countingObserver) Observe(ev event.Event) {
	if ev.Kind != "" {
		c.n++
	}
}
