package importer

import (
	"os"
	"path/filepath"
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
