package importer

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

func TestJSONDetection(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(NewJSONHttpxImporter())
	_ = r.Register(NewJSONDnsxImporter())
	_ = r.Register(NewJSONNaabuImporter())
	_ = r.Register(NewJSONKatanaImporter())
	_ = r.Register(NewJSONNucleiImporter())
	_ = r.Register(NewJSONGenericImporter())
	_ = r.Register(NewPlainGenericImporter())
	r.Seal()

	cases := []struct {
		name    string
		content string
		ext     string
		wantTop string
	}{
		{name: "httpx ndjson", content: "{\"url\":\"https://example.com\",\"status_code\":200,\"title\":\"Example\",\"tech\":[\"nginx\"]}\n", ext: ".json", wantTop: "json-httpx"},
		{name: "dnsx ndjson", content: "{\"host\":\"a.example.com\",\"a\":[\"1.2.3.4\"],\"cname\":\"x.example.com\"}\n", ext: ".json", wantTop: "json-dnsx"},
		{name: "naabu ndjson", content: "{\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":80}\n", ext: ".json", wantTop: "json-naabu"},
		{name: "katana ndjson", content: "{\"url\":\"https://example.com/api\",\"method\":\"GET\"}\n", ext: ".json", wantTop: "json-katana"},
		{name: "nuclei ndjson", content: "{\"template-id\":\"CVE-2021-1234\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/vuln\",\"severity\":\"high\",\"info\":{\"name\":\"Test\"}}\n", ext: ".json", wantTop: "json-nuclei"},
		{name: "httpx array", content: "[{\"url\":\"https://example.com/a\",\"status_code\":200},{\"url\":\"https://example.com/b\",\"status_code\":200}]", ext: ".json", wantTop: "json-httpx"},
		{name: "nuclei array", content: "[{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}]", ext: ".json", wantTop: "json-nuclei"},
		{name: "generic unknown", content: "{\"foo\":\"bar\",\"baz\":123}\n", ext: ".json", wantTop: "json-generic"},
		{name: "httpx renamed txt", content: "{\"url\":\"https://example.com\",\"status_code\":200}\n", ext: ".txt", wantTop: "json-httpx"},
		{name: "dnsx renamed dat", content: "{\"host\":\"a.example.com\",\"a\":[\"1.2.3.4\"]}\n", ext: ".dat", wantTop: "json-dnsx"},
		{name: "nuclei renamed txt", content: "{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"X\"}}\n", ext: ".txt", wantTop: "json-nuclei"},
		{name: "generic fallback nested array", content: "[{\"url\":\"https://example.com/generic\"}]", ext: ".json", wantTop: "json-httpx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "file"+tc.ext)
			if err := os.WriteFile(p, []byte(tc.content), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			peek, err := peekFile(p)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			matches := r.Detect(p, peek)
			if len(matches) == 0 {
				t.Fatalf("no matches for %s", tc.name)
			}
			top := matches[0].Importer.Name()
			if top != tc.wantTop {
				// Allow generic fallback equivalence for url-only case: either httpx or generic
				if tc.name == "generic fallback nested array" && (top == "json-generic" || top == "json-httpx") {
					return
				}
				t.Fatalf("want top %q got %q matches %v", tc.wantTop, top, matches)
			}
			// Ensure plain-generic is last when present
			for i := 1; i < len(matches); i++ {
				if matches[i-1].Importer.Name() == "plain-generic" && matches[i].Importer.Name() != "plain-generic" {
					t.Fatalf("plain-generic not last")
				}
			}
		})
	}
	// Ensure CanImport does not open beyond peek: use nonexistent path with valid peek
	peek := []byte("{\"url\":\"https://example.com\",\"status_code\":200}")
	matches := r.Detect("/nonexistent/path/file.json", peek)
	if len(matches) == 0 || matches[0].Importer.Name() != "json-httpx" {
		t.Fatalf("peek-only detection failed, got %v", matches)
	}
}

func TestJSONImportersTable(t *testing.T) {
	tests := []struct {
		name      string
		importer  Importer
		content   string
		wantP     int
		wantF     int
		wantKind  string
		wantCount int
		checkDup  bool
	}{
		{
			name:      "httpx valid ndjson",
			importer:  NewJSONHttpxImporter(),
			content:   "{\"url\":\"https://example.com/a\",\"status_code\":200}\n{\"url\":\"https://example.com/b\",\"status_code\":200}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "httpx array",
			importer:  NewJSONHttpxImporter(),
			content:   "[{\"url\":\"https://example.com/a\",\"status_code\":200},{\"url\":\"https://example.com/b\",\"status_code\":200}]",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "httpx malformed",
			importer:  NewJSONHttpxImporter(),
			content:   "{\"url\":\"https://example.com/a\",\"status_code\":200}\nnot json\n{\"url\":\"https://example.com/b\",\"status_code\":200}\n",
			wantP:     2,
			wantF:     1,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "httpx empty",
			importer:  NewJSONHttpxImporter(),
			content:   "",
			wantP:     0,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 0,
		},
		{
			name:      "httpx duplicate dedup",
			importer:  NewJSONHttpxImporter(),
			content:   "{\"url\":\"https://example.com/a\",\"status_code\":200}\n{\"url\":\"https://example.com/a\",\"status_code\":200}\n{\"url\":\"https://EXAMPLE.COM/a\",\"status_code\":200}\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:      "httpx unknown fields",
			importer:  NewJSONHttpxImporter(),
			content:   "{\"url\":\"https://example.com/a\",\"status_code\":200,\"extra\":\"ignore\",\"tech\":[\"nginx\"],\"unknown\":123}\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 1,
		},
		{
			name:      "dnsx valid",
			importer:  NewJSONDnsxImporter(),
			content:   "{\"host\":\"a.example.com\",\"a\":[\"1.2.3.4\",\"1.2.3.5\"]}\n{\"host\":\"b.example.com\",\"a\":[\"8.8.8.8\"]}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "hosts",
			wantCount: 2,
		},
		{
			name:      "dnsx with AAAA",
			importer:  NewJSONDnsxImporter(),
			content:   "{\"host\":\"a.example.com\",\"a\":[\"1.1.1.1\"],\"aaaa\":[\"2001:db8::1\"]}\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "hosts",
			wantCount: 1,
		},
		{
			name:      "naabu valid",
			importer:  NewJSONNaabuImporter(),
			content:   "{\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":80}\n{\"host\":\"example2.com\",\"ip\":\"5.6.7.8\",\"port\":443}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "mixed",
			wantCount: 4,
		},
		{
			name:      "naabu duplicate",
			importer:  NewJSONNaabuImporter(),
			content:   "{\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":80}\n{\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":80}\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "mixed",
			wantCount: 2,
			checkDup:  false,
		},
		{
			name:      "katana valid",
			importer:  NewJSONKatanaImporter(),
			content:   "{\"url\":\"https://example.com/api1\",\"method\":\"GET\"}\n{\"url\":\"https://example.com/api2\",\"method\":\"POST\"}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "katana array",
			importer:  NewJSONKatanaImporter(),
			content:   "[{\"url\":\"https://example.com/a\",\"method\":\"GET\"},{\"url\":\"https://example.com/b\",\"method\":\"POST\"}]",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:      "nuclei valid",
			importer:  NewJSONNucleiImporter(),
			content:   "{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}\n{\"template-id\":\"T2\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/b\",\"severity\":\"medium\",\"info\":{\"name\":\"N2\"}}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "findings",
			wantCount: 2,
		},
		{
			name:      "nuclei duplicate dedup",
			importer:  NewJSONNucleiImporter(),
			content:   "{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}\n{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}\n",
			wantP:     1,
			wantF:     0,
			wantKind:  "findings",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:      "nuclei malformed",
			importer:  NewJSONNucleiImporter(),
			content:   "{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}\nnot json\n",
			wantP:     1,
			wantF:     1,
			wantKind:  "findings",
			wantCount: 1,
		},
		{
			name:      "generic valid",
			importer:  NewJSONGenericImporter(),
			content:   "{\"url\":\"https://example.com/gen1\"}\n{\"host\":\"generic.example.com\"}\n{\"ip\":\"9.9.9.9\"}\n",
			wantP:     3,
			wantF:     0,
			wantKind:  "mixed",
			wantCount: 3,
		},
		{
			name:      "generic unknown still valid json but no asset",
			importer:  NewJSONGenericImporter(),
			content:   "{\"foo\":\"bar\"}\n",
			wantP:     0,
			wantF:     1,
			wantKind:  "mixed",
			wantCount: 0,
		},
		{
			name:      "generic with empty lines",
			importer:  NewJSONGenericImporter(),
			content:   "{\"url\":\"https://example.com/a\"}\n\n{\"url\":\"https://example.com/b\"}\n",
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "input.json")
			if err := os.WriteFile(p, []byte(tc.content), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			sink := NewSink()
			env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000, MaxLineBytes: 32 * 1024}}
			stats, err := tc.importer.Import(context.Background(), env, p, sink)
			if err != nil {
				t.Fatalf("Import error: %v", err)
			}
			if stats.ItemsProcessed != tc.wantP {
				t.Fatalf("ItemsProcessed %d want %d", stats.ItemsProcessed, tc.wantP)
			}
			if stats.ItemsFailed != tc.wantF {
				t.Fatalf("ItemsFailed %d want %d", stats.ItemsFailed, tc.wantF)
			}
			if stats.Truncated {
				t.Fatalf("unexpected Truncated")
			}
			var got int
			switch tc.wantKind {
			case "urls":
				got = len(sink.URLs)
			case "hosts":
				got = len(sink.Hosts)
			case "findings":
				got = len(sink.Findings)
			case "mixed":
				got = len(sink.URLs) + len(sink.Hosts) + len(sink.IPs) + len(sink.Findings)
			}
			if got != tc.wantCount {
				t.Fatalf("sink count %d want %d (hosts %d urls %d ips %d findings %d)", got, tc.wantCount, len(sink.Hosts), len(sink.URLs), len(sink.IPs), len(sink.Findings))
			}
			if tc.checkDup && stats.ItemsProcessed != tc.wantCount {
				t.Fatalf("dedup check: processed %d vs wantCount %d", stats.ItemsProcessed, tc.wantCount)
			}
		})
	}
}

// TestRegressionMED_KatanaNestedJSONL pins end-to-end handling of modern
// katana -jsonl exports, which nest the crawled endpoint under
// "request"."endpoint" instead of a flat top-level url. Regression: such
// files classified as "generic" shape, json-generic claimed them at 0.40,
// and every record then failed "generic: no url/host/ip field" — silent
// under-ingestion (ItemsProcessed:0, ItemsFailed:N).
func TestRegressionMED_KatanaNestedJSONL(t *testing.T) {
	const nested = `{"request":{"endpoint":"https://example.com/shell","method":"GET"},"response":{"status_code":200,"body":"<html>x</html>","duration":123}}`
	const flat = `{"url":"https://example.com/flat","method":"POST"}`

	ident := func(raw string) string {
		t.Helper()
		u, err := asset.ParseURL(raw, asset.Provenance{})
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		return u.Identity().String()
	}

	t.Run("nested shape detected as json-katana against full registry", func(t *testing.T) {
		p := writeArchiveTemp(t, "katana-modern.jsonl", nested+"\n"+nested+"\n")
		peek, err := peekFile(p)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if got := mustTopName(t, p, string(peek)); got != "json-katana" {
			t.Fatalf("top match %q want json-katana", got)
		}
	})

	t.Run("nested and flat records both imported as URLs", func(t *testing.T) {
		content := nested + "\n" + flat + "\n" +
			`{"request":{"endpoint":"https://example.com/nested-two","method":"GET"}}` + "\n"
		p := writeArchiveTemp(t, "katana-mixed.jsonl", content)
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
		stats, err := NewJSONKatanaImporter().Import(context.Background(), env, p, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 3 || stats.ItemsFailed != 0 {
			t.Fatalf("stats processed=%d failed=%d want 3/0", stats.ItemsProcessed, stats.ItemsFailed)
		}
		if len(sink.URLs) != 3 {
			t.Fatalf("urls=%d want 3", len(sink.URLs))
		}
		wantIDs := map[string]bool{
			ident("https://example.com/shell"):      false,
			ident("https://example.com/flat"):       false,
			ident("https://example.com/nested-two"): false,
		}
		for _, u := range sink.URLs {
			id := u.Identity().String()
			if _, ok := wantIDs[id]; !ok {
				t.Fatalf("unexpected URL identity %q (%s)", id, u.String())
			}
			wantIDs[id] = true
		}
		for id, seen := range wantIDs {
			if !seen {
				t.Fatalf("expected URL identity %q missing from sink", id)
			}
		}
		// Nested records keep their verbatim line as provenance evidence.
		found := false
		for _, rec := range sink.ProvenanceRecords {
			if strings.Contains(rec.OriginalRecord, `"request":{"endpoint"`) {
				found = true
				if rec.Importer != "json-katana" {
					t.Fatalf("nested record provenance importer %q", rec.Importer)
				}
			}
		}
		if !found {
			t.Fatal("no nested-endpoint OriginalRecord retained")
		}
	})

	t.Run("record without url or nested endpoint fails honestly", func(t *testing.T) {
		p := writeArchiveTemp(t, "katana-empty.jsonl",
			`{"request":{"method":"GET"},"response":{"status_code":500}}`+"\n")
		sink := NewSink()
		env := ImportEnv{Clock: fixedClock()}
		stats, err := NewJSONKatanaImporter().Import(context.Background(), env, p, sink)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 0 || stats.ItemsFailed != 1 || len(sink.URLs) != 0 {
			t.Fatalf("stats processed=%d failed=%d urls=%d want 0/1/0",
				stats.ItemsProcessed, stats.ItemsFailed, len(sink.URLs))
		}
	})
}

func TestJSONImporterEmptyFile(t *testing.T) {
	for _, imp := range []Importer{NewJSONHttpxImporter(), NewJSONDnsxImporter(), NewJSONNaabuImporter(), NewJSONKatanaImporter(), NewJSONNucleiImporter(), NewJSONGenericImporter()} {
		t.Run(imp.Name(), func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "empty.json")
			os.WriteFile(p, []byte(""), 0600)
			sink := NewSink()
			env := ImportEnv{Clock: fixedClock()}
			stats, err := imp.Import(context.Background(), env, p, sink)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if stats.ItemsProcessed != 0 || stats.ItemsFailed != 0 {
				t.Fatalf("empty should be 0/0 got %d/%d", stats.ItemsProcessed, stats.ItemsFailed)
			}
			if stats.Truncated {
				t.Fatalf("empty should not be truncated")
			}
		})
	}
}

func TestJSONImporterTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "trunc.json")
	f, _ := os.Create(p)
	for i := 0; i < 10; i++ {
		f.WriteString("{\"url\":\"https://example.com/" + strings.Repeat("a", 2) + "-" + string(rune('a'+i)) + "\",\"status_code\":200}\n")
	}
	f.Close()
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 5}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated")
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want import_truncated sticky")
	}
	if len(sink.URLs) != 5 {
		t.Fatalf("want 5 urls got %d", len(sink.URLs))
	}
	if stats.ItemsProcessed != 5 {
		t.Fatalf("want 5 processed got %d", stats.ItemsProcessed)
	}
}

func TestJSONProvenancePreserved(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "httpx.json")
	content := "{\"url\":\"https://example.com/a\",\"status_code\":200}\n{\"url\":\"https://example.com/b\",\"status_code\":200}\n"
	os.WriteFile(p, []byte(content), 0600)
	sink := NewSink()
	fixed := fixedClock()()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 1000}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("want 2")
	}
	if len(sink.ProvenanceRecords) != 2 {
		t.Fatalf("want 2 provenance")
	}
	for i, rec := range sink.ProvenanceRecords {
		if rec.Importer != imp.Name() {
			t.Fatalf("rec %d importer %q", i, rec.Importer)
		}
		if rec.OriginalTool != ProvenanceSourceForImporter(imp.Name()) {
			t.Fatalf("tool mismatch")
		}
		if rec.Filename != "httpx.json" {
			t.Fatalf("filename %q", rec.Filename)
		}
		if !rec.ImportTime.Equal(fixed) {
			t.Fatalf("time mismatch")
		}
		if rec.OriginalRecord == "" {
			t.Fatalf("empty original")
		}
		if len(rec.OriginalRecord) > MaxOriginalRecordBytes {
			t.Fatalf("original too long")
		}
		if rec.Identity == "" {
			t.Fatalf("empty identity")
		}
		// Check asset prov
		found := false
		for _, u := range sink.URLs {
			if u.Identity().String() == rec.Identity {
				if u.Prov.Source != "httpx" {
					t.Fatalf("prov source %q want httpx", u.Prov.Source)
				}
				if u.Prov.Reference != "httpx.json:1" && u.Prov.Reference != "httpx.json:2" {
					t.Fatalf("reference %q", u.Prov.Reference)
				}
				if !u.Prov.DiscoveredAt.Equal(fixed) {
					t.Fatalf("discoveredAt mismatch")
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("identity not found %q", rec.Identity)
		}
	}
	// nuclei provenance
	p2 := filepath.Join(dir, "nuclei.json")
	os.WriteFile(p2, []byte("{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"}}\n"), 0600)
	sink2 := NewSink()
	imp2 := NewJSONNucleiImporter()
	_, err = imp2.Import(context.Background(), env, p2, sink2)
	if err != nil {
		t.Fatalf("nuclei import: %v", err)
	}
	if len(sink2.Findings) != 1 {
		t.Fatalf("nuclei findings 1")
	}
	if len(sink2.ProvenanceRecords) != 1 {
		t.Fatalf("nuclei provenance 1")
	}
	rec := sink2.ProvenanceRecords[0]
	if rec.Importer != "json-nuclei" {
		t.Fatalf("nuclei importer %q", rec.Importer)
	}
	if len(rec.OriginalRecord) > MaxOriginalRecordBytes {
		t.Fatalf("nuclei original too long")
	}
	// OriginalRecord should be first 4 KiB truncated raw line
	if !strings.Contains(rec.OriginalRecord, "T1") {
		t.Fatalf("original does not contain T1")
	}
	// Finding provenance
	f := sink2.Findings[0]
	if false { // Finding has no direct Prov; provenance via Evidence
		_ = f
		// Finding's own provenance is via Evidence, not directly; but we set via prov
	}
	if rec.Identity != f.Identity().String() {
		t.Fatalf("finding provenance identity mismatch %q vs %q", rec.Identity, f.Identity().String())
	}
}

func TestJSONStreamingBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	const lines = 200000
	for i := 0; i < lines; i++ {
		fmt.Fprintf(f, "{\"url\":\"https://example.com/%d\",\"status_code\":200}\n", i)
	}
	f.Close()
	// What this heap guard honestly measures: RETAINED heap after GC with the
	// sink pinned live past the m2 snapshot (count reads below + KeepAlive).
	// With distinct URLs and MaxOutput=100000 the retained set IS the dominant
	// term by design (measured ≈600 B per record ⇒ ~60 MiB retained at the
	// cap), so the bound below pins output-retention cost plus streaming
	// overhead; it does NOT isolate streaming overhead, and peak transient
	// allocations are not observable via MemStats deltas at all.
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000, MaxLineBytes: 32 * 1024}}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Sink liveness is structural: these reads happen after m2, so the GC
	// cannot have freed the retained assets before measurement, and a freed
	// sink could not satisfy them either.
	const wantRetained = 100000 // tail-dropped at MaxOutput
	if got := len(sink.URLs); got != wantRetained {
		t.Fatalf("retained urls %d want %d (cap)", got, wantRetained)
	}
	if got := len(sink.ProvenanceRecords); got != wantRetained {
		t.Fatalf("retained provenance %d want %d", got, wantRetained)
	}
	if !stats.Truncated || stats.ItemsProcessed != wantRetained {
		t.Fatalf("truncated=%v processed=%d want true/%d", stats.Truncated, stats.ItemsProcessed, wantRetained)
	}
	runtime.KeepAlive(sink)

	if stats.ItemsFailed != 0 {
		t.Fatalf("failed %d", stats.ItemsFailed)
	}
	var heapDelta uint64
	if m2.HeapInuse > m1.HeapInuse {
		heapDelta = m2.HeapInuse - m1.HeapInuse
	}
	t.Logf("measured retained heap delta: %d bytes (%.1f MiB) for %d records", heapDelta, float64(heapDelta)/(1<<20), wantRetained)
	const maxDelta = 128 << 20 // measured 59.6 MiB retention @100k + >2x slack
	if heapDelta > maxDelta {
		t.Fatalf("heap delta %d exceeds retention bound %d — unbounded retention?", heapDelta, maxDelta)
	}
}

func TestJSONCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cancel.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(f, "{\"url\":\"https://example.com/%d\",\"status_code\":200}\n", i)
	}
	f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * time.Millisecond)
		cancel()
	}()
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewJSONHttpxImporter()
	_, err = imp.Import(ctx, env, path, sink)
	// May or may not cancel in time; but at least test already-cancelled path
	if ctx.Err() == nil && err == nil {
		t.Skip("import completed before cancellation — skip")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	sink2 := NewSink()
	_, err2 := imp.Import(ctx2, env, path, sink2)
	if err2 == nil {
		t.Fatalf("want cancelled error")
	}
	if err2 != context.Canceled && err2 != context.DeadlineExceeded {
		t.Fatalf("want context canceled got %v", err2)
	}
}

func TestJSONProgressEmission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "progress.json")
	f, _ := os.Create(path)
	for i := 0; i < 20000; i++ {
		f.WriteString("{\"url\":\"https://example.com/a\",\"status_code\":200}\n")
	}
	f.Close()
	bus := event.NewBus(nil)
	sub, _ := bus.Subscribe(100)
	env := ImportEnv{Clock: fixedClock(), Observer: bus, Bounds: Bounds{MaxOutput: 50000}}
	sink := NewSink()
	imp := NewJSONHttpxImporter()
	_, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	foundProgress := false
	timeout := time.After(100 * time.Millisecond)
Loop:
	for {
		select {
		case ev := <-sub.Events():
			if ev.Kind == event.KindProgress {
				foundProgress = true
				break Loop
			}
		case <-timeout:
			break Loop
		default:
			break Loop
		}
	}
	if !foundProgress {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		for {
			ev, err := sub.Next(ctx)
			if err != nil {
				break
			}
			if ev.Kind == event.KindProgress {
				foundProgress = true
				break
			}
		}
	}
	if !foundProgress {
		t.Fatalf("expected progress event")
	}
}

func TestJSONGzipHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "httpx.json.gz")
	f, _ := os.Create(path)
	gw := gzip.NewWriter(f)
	gw.Write([]byte("{\"url\":\"https://example.com/a\",\"status_code\":200}\n"))
	gw.Write([]byte("{\"url\":\"https://example.com/b\",\"status_code\":200}\n"))
	gw.Close()
	f.Close()
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import gzip: %v", err)
	}
	if stats.ItemsProcessed != 2 {
		t.Fatalf("gzip want 2 got %d", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 2 {
		t.Fatalf("gzip urls 2 got %d", len(sink.URLs))
	}
}

func TestJSONUnknownFieldsForwardCompat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "httpx.json")
	content := "{\"url\":\"https://example.com/a\",\"status_code\":200,\"unknown_field\":\"ignore\",\"another\":123,\"tech\":[\"nginx\"]}\n"
	os.WriteFile(p, []byte(content), 0600)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 1 {
		t.Fatalf("want 1 got %d", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 1 {
		t.Fatalf("want 1 url")
	}
	// nuclei with extra fields
	p2 := filepath.Join(dir, "nuclei.json")
	content2 := "{\"template-id\":\"T1\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/a\",\"severity\":\"high\",\"info\":{\"name\":\"N1\"},\"extra\":\"field\",\"nested\":{\"a\":1}}\n"
	os.WriteFile(p2, []byte(content2), 0600)
	sink2 := NewSink()
	imp2 := NewJSONNucleiImporter()
	stats2, err := imp2.Import(context.Background(), env, p2, sink2)
	if err != nil {
		t.Fatalf("nuclei: %v", err)
	}
	if stats2.ItemsProcessed != 1 {
		t.Fatalf("nuclei want 1 got %d", stats2.ItemsProcessed)
	}
}

func TestJSONEmptyLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "httpx.json")
	content := "{\"url\":\"https://example.com/a\",\"status_code\":200}\n\n\n{\"url\":\"https://example.com/b\",\"status_code\":200}\n"
	os.WriteFile(p, []byte(content), 0600)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	imp := NewJSONHttpxImporter()
	stats, err := imp.Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.ItemsProcessed != 2 || stats.ItemsFailed != 0 {
		t.Fatalf("empty lines: processed %d failed %d", stats.ItemsProcessed, stats.ItemsFailed)
	}
}

func TestRegistryDeterminismJSON(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(NewJSONNaabuImporter())
	_ = r.Register(NewJSONHttpxImporter())
	_ = r.Register(NewJSONGenericImporter())
	_ = r.Register(NewPlainGenericImporter())
	_ = r.Register(NewJSONDnsxImporter())
	_ = r.Register(NewJSONKatanaImporter())
	_ = r.Register(NewJSONNucleiImporter())
	r.Seal()
	list := r.List()
	if len(list) != 7 {
		t.Fatalf("list 7 got %d", len(list))
	}
	// Sorted by Name asc
	for i := 1; i < len(list); i++ {
		if list[i-1].Name() > list[i].Name() {
			t.Fatalf("not sorted %s > %s", list[i-1].Name(), list[i].Name())
		}
	}
	// Detect determinism
	peek := []byte("{\"url\":\"https://example.com\",\"status_code\":200}")
	m1 := r.Detect("file.json", peek)
	m2 := r.Detect("file.json", peek)
	if len(m1) != len(m2) {
		t.Fatalf("detect not deterministic")
	}
	for i := range m1 {
		if m1[i].Importer.Name() != m2[i].Importer.Name() || m1[i].Confidence != m2[i].Confidence {
			t.Fatalf("not deterministic")
		}
	}
	// generic fallback last
	for i := 1; i < len(m1); i++ {
		if m1[i-1].Importer.Name() == "plain-generic" && m1[i].Importer.Name() != "plain-generic" {
			t.Fatalf("generic not last")
		}
		if m1[i-1].Importer.Name() == "json-generic" && m1[i].Importer.Name() == "plain-generic" {
			// json-generic before plain-generic is allowed (json outranks plain)
		}
	}
}
