package importer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func fixedClock() func() time.Time {
	fixed := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return fixed }
}

func TestPlainImportersTable(t *testing.T) {
	tests := []struct {
		name      string
		importer  Importer
		content   string
		wantP     int
		wantF     int
		wantKind  string // which sink slice should have entries
		wantCount int
		checkDup  bool
	}{
		{
			name:      "domains valid",
			importer:  NewPlainDomainsImporter(),
			content:   "example.com\napi.example.com\nEXAMPLE.COM\n",
			wantP:     2, // third is duplicate after case normalization
			wantF:     0,
			wantKind:  "domains",
			wantCount: 2,
		},
		{
			name:      "domains malformed",
			importer:  NewPlainDomainsImporter(),
			content:   "example.com\nnot a domain!\napi.example.com\n",
			wantP:     2,
			wantF:     1,
			wantKind:  "domains",
			wantCount: 2,
		},
		{
			name:      "domains empty",
			importer:  NewPlainDomainsImporter(),
			content:   "",
			wantP:     0,
			wantF:     0,
			wantKind:  "domains",
			wantCount: 0,
		},
		{
			name:      "domains duplicate dedup",
			importer:  NewPlainDomainsImporter(),
			content:   "example.com\nexample.com\nexample.com\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "domains",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:      "subdomains valid",
			importer:  NewPlainSubdomainsImporter(),
			content:   "www.example.com\napi.example.com\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "hosts",
			wantCount: 2,
		},
		{
			name:      "urls valid",
			importer:  NewPlainURLsImporter(),
			content:   "https://example.com/a\nhttp://example.com/b\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "urls malformed",
			importer:  NewPlainURLsImporter(),
			content:   "https://example.com/a\nnot-a-url\n",
			wantP:     1,
			wantF:     1,
			wantKind:  "urls",
			wantCount: 1,
		},
		{
			name:      "urls empty",
			importer:  NewPlainURLsImporter(),
			content:   "",
			wantP:     0,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 0,
		},
		{
			name:      "urls duplicate dedup canonical",
			importer:  NewPlainURLsImporter(),
			content:   "https://example.com/a\nhttps://example.com/a\nhttps://EXAMPLE.COM/a\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:      "alive hosts and urls",
			importer:  NewPlainAliveImporter(),
			content:   "www.example.com\nhttps://example.com/a\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "mixed",
			wantCount: 2,
		},
		{
			name:      "js valid",
			importer:  NewPlainJSImporter(),
			content:   "https://example.com/app.js\nhttps://example.com/lib.js\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "js",
			wantCount: 2,
		},
		{
			name:      "ips valid",
			importer:  NewPlainIPsImporter(),
			content:   "1.2.3.4\n8.8.8.8\n::1\n",
			wantP:     3,
			wantF:     0,
			wantKind:  "ips",
			wantCount: 3,
		},
		{
			name:      "ips malformed",
			importer:  NewPlainIPsImporter(),
			content:   "1.2.3.4\nnot-an-ip\n",
			wantP:     1,
			wantF:     1,
			wantKind:  "ips",
			wantCount: 1,
		},
		{
			name:      "ips duplicate dedup",
			importer:  NewPlainIPsImporter(),
			content:   "1.2.3.4\n1.2.3.4\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "ips",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:      "cidrs valid",
			importer:  NewPlainCIDRsImporter(),
			content:   "192.168.0.0/16\n10.0.0.0/8\n2001:db8::/32\n",
			wantP:     3,
			wantF:     0,
			wantKind:  "cidrs",
			wantCount: 3,
		},
		{
			name:      "cidrs malformed",
			importer:  NewPlainCIDRsImporter(),
			content:   "192.168.0.0/16\nnot-cidr\n",
			wantP:     1,
			wantF:     1,
			wantKind:  "cidrs",
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, tc.content)
			sink := NewSink()
			env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
			stats, err := tc.importer.Import(context.Background(), env, path, sink)
			if err != nil {
				t.Fatalf("Import error: %v", err)
			}
			if stats.ItemsProcessed != tc.wantP {
				t.Fatalf("ItemsProcessed %d, want %d", stats.ItemsProcessed, tc.wantP)
			}
			if stats.ItemsFailed != tc.wantF {
				t.Fatalf("ItemsFailed %d, want %d", stats.ItemsFailed, tc.wantF)
			}
			if stats.Truncated {
				t.Fatalf("unexpected Truncated")
			}
			var got int
			switch tc.wantKind {
			case "domains":
				got = len(sink.Domains)
			case "hosts":
				got = len(sink.Hosts)
			case "urls":
				got = len(sink.URLs)
			case "ips":
				got = len(sink.IPs)
			case "js":
				got = len(sink.JS)
			case "cidrs":
				got = len(sink.CIDRs)
			case "mixed":
				got = len(sink.Hosts) + len(sink.URLs)
			}
			if got != tc.wantCount {
				t.Fatalf("sink count %d, want %d (domains %d hosts %d urls %d ips %d js %d cidrs %d)", got, tc.wantCount, len(sink.Domains), len(sink.Hosts), len(sink.URLs), len(sink.IPs), len(sink.JS), len(sink.CIDRs))
			}
			if tc.checkDup && stats.ItemsProcessed != tc.wantCount {
				t.Fatalf("dedup check: processed %d vs wantCount %d", stats.ItemsProcessed, tc.wantCount)
			}
		})
	}
}

func TestPlainImporterLineOver32KiBTruncated(t *testing.T) {
	// Line >32 KiB should be counted as failed (ItemsFailed) and not abort
	longLine := strings.Repeat("a", 32*1024+1) // one byte over
	content := "example.com\n" + longLine + "\napi.example.com\n"
	path := writeTempFile(t, content)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2 processed, got %d", stats.ItemsProcessed)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed for oversized line, got %d", stats.ItemsFailed)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated true for oversized line")
	}
	if len(sink.Domains) != 2 {
		t.Fatalf("want 2 domains, got %d", len(sink.Domains))
	}
}

func TestPlainImporterHugeFileTruncated(t *testing.T) {
	// MaxOutput cap: 5 -> 10 lines -> truncated with incomplete flag per §0.6 (we surface Truncated+sticky, not failed outcome)
	content := ""
	for i := 0; i < 10; i++ {
		content += "host" + strings.Repeat("a", 5) + ".example.com\n"
	}
	// Actually generate distinct hosts
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("h" + strings.Repeat("x", 2) + "-" + string(rune('a'+i)) + ".example.com\n")
	}
	path := writeTempFile(t, b.String())
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 5}}
	imp := NewPlainSubdomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated")
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want import_truncated sticky")
	}
	if len(sink.Hosts) != 5 {
		t.Fatalf("want 5 hosts after cap, got %d", len(sink.Hosts))
	}
	// ItemsProcessed should be 5 (retained) not 10? In our implementation we still count processed as retained count.
	// We tail-drop without counting as failed; processed reflects retained.
	if stats.ItemsProcessed != 5 {
		t.Fatalf("want 5 processed retained, got %d", stats.ItemsProcessed)
	}
}

func TestPlainImporterEmptyFile(t *testing.T) {
	for _, imp := range []Importer{NewPlainDomainsImporter(), NewPlainURLsImporter(), NewPlainIPsImporter()} {
		t.Run(imp.Name(), func(t *testing.T) {
			path := writeTempFile(t, "")
			sink := NewSink()
			env := ImportEnv{Clock: fixedClock()}
			stats, err := imp.Import(context.Background(), env, path, sink)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if stats.ItemsProcessed != 0 || stats.ItemsFailed != 0 {
				t.Fatalf("empty file should have 0/0, got %d/%d", stats.ItemsProcessed, stats.ItemsFailed)
			}
			if stats.Truncated {
				t.Fatalf("empty should not be truncated")
			}
		})
	}
}

func TestPlainImporterBinaryOversized(t *testing.T) {
	// binary/malformed input: non-utf8 bytes and huge line
	content := string([]byte{0xff, 0xfe, 0x00, 0x01}) + "\nexample.com\n"
	path := writeTempFile(t, content)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewPlainDomainsImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 1 {
		t.Fatalf("want 1 processed, got %d", stats.ItemsProcessed)
	}
	if stats.ItemsFailed != 1 {
		t.Fatalf("want 1 failed for binary line, got %d", stats.ItemsFailed)
	}
}

func TestPlainImporterMixedPlainImport(t *testing.T) {
	// File with hosts+urls — both importers claim or primary+secondary
	// Use alive importer which accepts both, vs strict hosts/urls
	content := "www.example.com\nhttps://example.com/a\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	peek, _ := peekFile(path)
	r := NewRegistry()
	_ = r.Register(NewPlainSubdomainsImporter())
	_ = r.Register(NewPlainURLsImporter())
	_ = r.Register(NewPlainAliveImporter())
	r.Seal()
	matches := r.Detect(path, peek)
	if len(matches) == 0 {
		t.Fatalf("no matches for mixed")
	}
	// Alive should claim mixed with higher confidence? Check at least one claims
	foundAlive := false
	for _, m := range matches {
		if m.Importer.Name() == "plain-alive" {
			foundAlive = true
		}
	}
	if !foundAlive {
		t.Fatalf("alive importer should claim mixed file")
	}
	// Actually import via alive
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewPlainAliveImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2 processed, got %d", stats.ItemsProcessed)
	}
	if len(sink.Hosts) != 1 || len(sink.URLs) != 1 {
		t.Fatalf("want 1 host 1 url, got %d hosts %d urls", len(sink.Hosts), len(sink.URLs))
	}
}
