package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatDetectionWaterfall(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(NewPlainDomainsImporter())
	_ = r.Register(NewPlainSubdomainsImporter())
	_ = r.Register(NewPlainURLsImporter())
	_ = r.Register(NewPlainAliveImporter())
	_ = r.Register(NewPlainJSImporter())
	_ = r.Register(NewPlainIPsImporter())
	_ = r.Register(NewPlainCIDRsImporter())
	_ = r.Register(NewPlainGenericImporter())
	r.Seal()

	cases := []struct {
		name       string
		content    string
		ext        string
		wantTop    string
		wantClaims int
	}{
		{name: "domains txt", content: "example.com\napi.example.com\n", ext: ".txt", wantTop: "plain-domains"},
		{name: "urls txt", content: "https://example.com/a\nhttps://example.com/b\n", ext: ".txt", wantTop: "plain-urls"},
		{name: "ips txt", content: "1.2.3.4\n8.8.8.8\n2001:db8::1\n", ext: ".txt", wantTop: "plain-ips"},
		{name: "cidrs txt", content: "192.168.0.0/16\n10.0.0.0/8\n", ext: ".txt", wantTop: "plain-cidrs"},
		{name: "js txt", content: "https://example.com/app.js\nhttps://cdn.example.com/lib.js\n", ext: ".js", wantTop: "plain-js"},
		{name: "urls renamed dat", content: "https://example.com/a\nhttps://example.com/b\nhttps://example.com/c\n", ext: ".dat", wantTop: "plain-urls"},
		{name: "domains renamed dat", content: "example.com\nfoo.example.com\nbar.example.com\n", ext: ".dat", wantTop: "plain-domains"},
		{name: "ips renamed dat", content: "1.1.1.1\n2.2.2.2\n3.3.3.3\n", ext: ".dat", wantTop: "plain-ips"},
		{name: "xml signature not plain", content: "<?xml version=\"1.0\"?><root></root>", ext: ".txt", wantTop: "plain-generic", wantClaims: 1},
		{name: "json not plain", content: `{"key":"value"}`, ext: ".txt", wantTop: "plain-generic", wantClaims: 1},
		{name: "gzip magic not plain", content: string([]byte{0x1f, 0x8b, 0x08, 0x00}) + "gzip", ext: ".txt", wantTop: "plain-generic", wantClaims: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file"+tc.ext)
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			peek, err := peekFile(path)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			matches := r.Detect(path, peek)
			if len(matches) == 0 {
				t.Fatalf("no matches for %q", tc.name)
			}
			top := matches[0].Importer.Name()
			if tc.wantTop == "plain-generic" {
				// For xml/json/gzip, plain specific importers should not claim, only generic
				if top != "plain-generic" {
					t.Fatalf("want generic top but got %q", top)
				}
				if tc.wantClaims != 0 && len(matches) != tc.wantClaims {
					t.Fatalf("want %d claims, got %d", tc.wantClaims, len(matches))
				}
			} else {
				if top != tc.wantTop {
					t.Fatalf("want top %q, got %q (matches: %v)", tc.wantTop, top, func() []string {
						var s []string
						for _, m := range matches {
							s = append(s, m.Importer.Name())
						}
						return s
					}())
				}
			}
		})
	}
}

func TestPeekDoesNotOpenBeyond(t *testing.T) {
	// Verify CanImport never opens file beyond peek by ensuring Detect works with peek only
	// even if file path is nonexistent.
	r := NewRegistry()
	_ = r.Register(NewPlainURLsImporter())
	_ = r.Register(NewPlainGenericImporter())
	r.Seal()
	peek := []byte("https://example.com/a\n")
	matches := r.Detect("/nonexistent/path/file.dat", peek)
	if len(matches) == 0 {
		t.Fatalf("expected matches via peek alone")
	}
	// Ensure plain-urls claims it even though file does not exist and extension is .dat
	if matches[0].Importer.Name() != "plain-urls" {
		t.Fatalf("want plain-urls, got %s", matches[0].Importer.Name())
	}
}

// fullDetectionRegistry registers every importer family so gzipped-detection
// cases exercise the real waterfall ranking (plain vs json/xml vs archive).
func fullDetectionRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, imp := range []Importer{
		NewPlainDomainsImporter(),
		NewPlainSubdomainsImporter(),
		NewPlainURLsImporter(),
		NewPlainAliveImporter(),
		NewPlainJSImporter(),
		NewPlainIPsImporter(),
		NewPlainCIDRsImporter(),
		NewPlainGenericImporter(),
		NewJSONHttpxImporter(),
		NewJSONGenericImporter(),
		NewXMLBurpImporter(),
		NewXMLZapImporter(),
		NewArchiveCDXImporter(),
		NewArchiveWARCImporter(),
	} {
		if err := r.Register(imp); err != nil {
			t.Fatalf("register %s: %v", imp.Name(), err)
		}
	}
	r.Seal()
	return r
}

// hasSpecificPlainClaim reports whether any non-generic plain importer
// claimed the file — the anti-steal property for content owned by another
// family (JSON, XML, CDX, WARC).
func hasSpecificPlainClaim(matches []DetectMatch) bool {
	for _, m := range matches {
		if n := m.Importer.Name(); strings.HasPrefix(n, "plain-") && n != "plain-generic" {
			return true
		}
	}
	return false
}

// TestGzippedPlainDetection covers TODO NEW-60: a gzipped one-URL-per-line
// list is claimed by the plain family through one bounded inflation of the
// detection peek (inflatePeek ≤inflateCap), with confidence parity against
// the equivalent uncompressed content — while gzipped CDX/WARC/JSON/XML
// stays with its own family (anti-steal) and corrupt gzip declines honestly.
func TestGzippedPlainDetection(t *testing.T) {
	urls := "https://example.com/a\nhttps://example.com/b\nhttps://example.com/c\n"
	hosts := "example.com\napi.example.com\nwww.example.com\n"
	r := fullDetectionRegistry(t)

	detect := func(t *testing.T, path string) []DetectMatch {
		t.Helper()
		peek, err := peekFile(path)
		if err != nil {
			t.Fatalf("peek %s: %v", path, err)
		}
		return r.Detect(path, peek)
	}
	topName := func(t *testing.T, matches []DetectMatch) string {
		t.Helper()
		if len(matches) == 0 {
			t.Fatalf("no matches")
		}
		return matches[0].Importer.Name()
	}

	t.Run("gzipped urls txt.gz claims plain-urls with parity", func(t *testing.T) {
		gz := detect(t, writeGzipArchiveTemp(t, "waymore.txt.gz", urls))
		raw := detect(t, writeArchiveTemp(t, "waymore.txt", urls))
		if got := topName(t, gz); got != "plain-urls" {
			t.Fatalf("want plain-urls top, got %q", got)
		}
		if gz[0].Confidence != raw[0].Confidence {
			t.Fatalf("confidence parity broken: gzipped %.4f vs uncompressed %.4f",
				gz[0].Confidence, raw[0].Confidence)
		}
	})

	t.Run("gzipped urls renamed extension claims plain-urls by content", func(t *testing.T) {
		gz := detect(t, writeGzipArchiveTemp(t, "export.dat", urls))
		raw := detect(t, writeArchiveTemp(t, "export.dat", urls))
		if got := topName(t, gz); got != "plain-urls" {
			t.Fatalf("want plain-urls top, got %q", got)
		}
		if gz[0].Confidence != raw[0].Confidence {
			t.Fatalf("confidence parity broken: gzipped %.4f vs uncompressed %.4f",
				gz[0].Confidence, raw[0].Confidence)
		}
	})

	t.Run("gzipped host list claims plain-domains", func(t *testing.T) {
		gz := detect(t, writeGzipArchiveTemp(t, "subs.txt.gz", hosts))
		if got := topName(t, gz); got != "plain-domains" {
			t.Fatalf("want plain-domains top, got %q", got)
		}
	})

	t.Run("gzipped CDX still claimed by archive-cdx", func(t *testing.T) {
		matches := detect(t, writeGzipArchiveTemp(t, "export.cdx.gz", strings.Repeat(classicCDX, 3)))
		if got := topName(t, matches); got != "archive-cdx" {
			t.Fatalf("want archive-cdx top, got %q", got)
		}
		if hasSpecificPlainClaim(matches) {
			t.Fatalf("plain family stole gzipped CDX content")
		}
	})

	t.Run("gzipped WARC still claimed by archive-warc", func(t *testing.T) {
		matches := detect(t, writeGzipArchiveTemp(t, "capture.warc.gz",
			buildWARC([]warcRec{{target: "https://example.com/", warcType: "response", body: []byte("hi")}})))
		if got := topName(t, matches); got != "archive-warc" {
			t.Fatalf("want archive-warc top, got %q", got)
		}
		if hasSpecificPlainClaim(matches) {
			t.Fatalf("plain family stole gzipped WARC content")
		}
	})

	t.Run("gzipped JSON not stolen by plain family", func(t *testing.T) {
		matches := detect(t, writeGzipArchiveTemp(t, "httpx.jsonl.gz",
			`{"url":"https://example.com/","status_code":200}`+"\n"+
				`{"url":"https://example.com/b","status_code":404}`+"\n"))
		if hasSpecificPlainClaim(matches) {
			t.Fatalf("plain family stole gzipped JSON content")
		}
	})

	t.Run("gzipped XML not stolen by plain family", func(t *testing.T) {
		matches := detect(t, writeGzipArchiveTemp(t, "burp.xml.gz",
			`<?xml version="1.0"?><items><item><url>https://example.com/</url></item></items>`))
		if hasSpecificPlainClaim(matches) {
			t.Fatalf("plain family stole gzipped XML content")
		}
	})

	t.Run("corrupt gzip declines honestly to generic only", func(t *testing.T) {
		matches := detect(t, writeArchiveTemp(t, "broken.txt.gz", "\x1f\x8bdefinitely-not-gzip-payload"))
		if got := topName(t, matches); got != "plain-generic" {
			t.Fatalf("want plain-generic top for corrupt gzip, got %q", got)
		}
		if len(matches) != 1 {
			names := make([]string, 0, len(matches))
			for _, m := range matches {
				names = append(names, m.Importer.Name())
			}
			t.Fatalf("want exactly the generic fallback claim, got %d: %v", len(matches), names)
		}
	})
}
