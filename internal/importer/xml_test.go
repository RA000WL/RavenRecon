package importer

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// writeXMLTemp writes content to a fresh temp dir with the given extension.
func writeXMLTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// gzipTestWriter writes gzip-compressed fixtures into an underlying writer.
// The compressed stream must be closed via close before the file is read back.
type gzipTestWriter struct {
	gz *gzip.Writer
}

// gzipWriterFor wraps w in a gzipTestWriter for hermetic .gz fixtures.
func gzipWriterFor(w io.Writer) *gzipTestWriter {
	return &gzipTestWriter{gz: gzip.NewWriter(w)}
}

func (g *gzipTestWriter) write(p []byte) { _, _ = g.gz.Write(p) }

func (g *gzipTestWriter) close() { _ = g.gz.Close() }

// newFullRegistry registers every importer (plain + json + xml) exactly as the
// future ingest CLI is expected to compose them, then seals. Deterministic
// Detect ordering across all families is exercised with XML present.
func newFullRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, imp := range []Importer{
		NewPlainDomainsImporter(), NewPlainSubdomainsImporter(), NewPlainURLsImporter(),
		NewPlainAliveImporter(), NewPlainJSImporter(), NewPlainIPsImporter(),
		NewPlainCIDRsImporter(), NewPlainGenericImporter(),
		NewJSONHttpxImporter(), NewJSONDnsxImporter(), NewJSONNaabuImporter(),
		NewJSONKatanaImporter(), NewJSONNucleiImporter(), NewJSONGenericImporter(),
		NewXMLBurpImporter(), NewXMLZapImporter(),
	} {
		if err := r.Register(imp); err != nil {
			t.Fatalf("Register(%s): %v", imp.Name(), err)
		}
	}
	r.Seal()
	return r
}

func TestXMLDetection(t *testing.T) {
	r := newFullRegistry(t)

	cases := []struct {
		name    string
		content string
		ext     string
		wantTop string
	}{
		{
			name: "burp sitemap",
			content: `<?xml version="1.0"?><items><item><url>https://example.com/a</url></item>` +
				`<item><url>https://example.com/b</url></item></items>`,
			ext:     ".xml",
			wantTop: "xml-burp",
		},
		{
			name: "burp issues",
			content: `<?xml version="1.0"?><issues><issue><name>X</name><severity>Low</severity>` +
				`<host>https://example.com</host><path>/a</path></issue></issues>`,
			ext:     ".xml",
			wantTop: "xml-burp",
		},
		{
			name: "zap report",
			content: `<?xml version="1.0"?><OWASPZAPReport version="2.16.0"><site name="https://example.com">` +
				`<alerts><alertitem><pluginid>10038</pluginid><alert>CSP</alert><riskcode>2</riskcode>` +
				`<url>https://example.com/</url></alertitem></alerts></site></OWASPZAPReport>`,
			ext:     ".xml",
			wantTop: "xml-zap",
		},
		{
			name: "zap lowercase root variant",
			content: `<OwaspZapReport version="2.16.0"><site name="https://example.com"><alerts>` +
				`<alertitem><alert>A</alert><riskcode>1</riskcode><url>https://example.com/</url>` +
				`</alertitem></alerts></site></OwaspZapReport>`,
			ext:     ".xml",
			wantTop: "xml-zap",
		},
		{
			name: "burp sitemap renamed txt",
			content: `<?xml version="1.0"?><items><item><url>https://example.com/a</url></item>` +
				`<item><url>https://example.com/b</url></item></items>`,
			ext:     ".txt",
			wantTop: "xml-burp",
		},
		{
			name: "zap renamed dat",
			content: `<?xml version="1.0"?><OWASPZAPReport version="2.16.0"><site name="https://example.com">` +
				`<alerts><alertitem><alert>A</alert><riskcode>3</riskcode><url>https://example.com/</url>` +
				`</alertitem></alerts></site></OWASPZAPReport>`,
			ext:     ".dat",
			wantTop: "xml-zap",
		},
		{
			name:    "unknown xml falls through to generic",
			content: `<?xml version="1.0"?><nmaprun scanner="nmap"><host><addr>1.2.3.4</addr></host></nmaprun>`,
			ext:     ".xml",
			wantTop: "plain-generic",
		},
		{
			name:    "non-xml plain urls unaffected",
			content: "https://example.com/a\nhttps://example.com/b\n",
			ext:     ".txt",
			wantTop: "plain-urls",
		},
		{
			name:    "json still outranked by json importers not xml",
			content: `{"url":"https://example.com","status_code":200}` + "\n",
			ext:     ".json",
			wantTop: "json-httpx",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeXMLTemp(t, "file"+tc.ext, tc.content)
			peek, err := peekFile(p)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			matches := r.Detect(p, peek)
			if len(matches) == 0 {
				t.Fatalf("no matches")
			}
			var names []string
			for _, m := range matches {
				names = append(names, fmt.Sprintf("%s(%.2f)", m.Importer.Name(), m.Confidence))
			}
			top := matches[0].Importer.Name()
			if top != tc.wantTop {
				t.Fatalf("want top %q got %q (%v)", tc.wantTop, top, names)
			}
			// Generic fallback must stay last regardless of family.
			for i := 1; i < len(matches); i++ {
				prevIsGeneric := matches[i-1].Importer.Name() == "plain-generic"
				curIsGeneric := matches[i].Importer.Name() == "plain-generic"
				if prevIsGeneric && !curIsGeneric {
					t.Fatalf("plain-generic not last: %v", names)
				}
			}
		})
	}

	// Peek-only detection on a nonexistent path: content decides, never IO.
	peek := []byte("<?xml version=\"1.0\"?><issues><issue><name>N</name></issue>")
	matches := r.Detect("/nonexistent/path/issues.xml", peek)
	if len(matches) == 0 || matches[0].Importer.Name() != "xml-burp" {
		t.Fatalf("peek-only detection failed: %v", matches)
	}

	// Unknown XML must NOT be claimed by either XML importer even in isolation.
	pair := []Importer{NewXMLBurpImporter(), NewXMLZapImporter()}
	unk := []byte("<?xml version=\"1.0\"?><weirdroot><child/></weirdroot>")
	for _, imp := range pair {
		if conf, ok := imp.CanImport("x.xml", unk); ok {
			t.Fatalf("%s mis-claimed unknown XML (conf %.2f)", imp.Name(), conf)
		}
	}
}

func TestXMLImportersTable(t *testing.T) {
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
			name:     "burp sitemap valid",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><items>` +
				`<item><url>https://example.com/a</url></item>` +
				`<item><url>http://api.example.com/v1?x=1</url></item>` +
				`</items>`,
			wantP:     2,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:     "burp sitemap malformed element counted",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><items>` +
				`<item><url>https://example.com/good</url></item>` +
				`<item></item>` +
				`<item><url>https://example.com/good2</url></item>` +
				`</items>`,
			wantP:     2,
			wantF:     1,
			wantKind:  "urls",
			wantCount: 2,
		},
		{
			name:     "burp sitemap duplicate dedup",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><items>` +
				`<item><url>https://Example.com/dup</url></item>` +
				`<item><url>https://example.com/dup</url></item>` +
				`</items>`,
			wantP:     1,
			wantF:     0,
			wantKind:  "urls",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:     "burp issues valid",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><issues>` +
				`<issue><name>Content type is not specified</name><severity>Low</severity>` +
				`<host>https://api.example.com</host><path>/v1/users</path></issue>` +
				`<issue><name>Cross-domain POST</name><severity>Information</severity>` +
				`<host>https://api.example.com</host><path>/v1/submit</path></issue>` +
				`</issues>`,
			wantP:     2,
			wantF:     0,
			wantKind:  "findings",
			wantCount: 2,
		},
		{
			name:     "burp issues malformed element counted",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><issues>` +
				`<issue><name>NoHost</name><severity>Low</severity></issue>` +
				`<issue><name>OK</name><severity>High</severity>` +
				`<host>https://api.example.com</host><path>/ok</path></issue>` +
				`</issues>`,
			wantP:     1,
			wantF:     1,
			wantKind:  "findings",
			wantCount: 1,
		},
		{
			name:     "burp mixed shapes one file",
			importer: NewXMLBurpImporter(),
			content: `<?xml version="1.0"?><items>` +
				`<item><url>https://example.com/page</url></item>` +
				`<issue><name>Trace.htm</name><severity>Info</severity>` +
				`<host>https://example.com</host><path>/page</path></issue>` +
				`</items>`,
			wantP:     2,
			wantF:     0,
			wantKind:  "mixed",
			wantCount: 2,
		},
		{
			name:     "zap alerts valid",
			importer: NewXMLZapImporter(),
			content: `<?xml version="1.0"?><OWASPZAPReport version="2.16.0">` +
				`<site name="https://www.example.com"><alerts>` +
				`<alertitem><pluginid>10038</pluginid><alert>CSP: strict-dynamic</alert>` +
				`<riskcode>2</riskcode><url>https://www.example.com/index.html</url></alertitem>` +
				`<alertitem><pluginid>10015</pluginid><alert>Incomplete or No Cache-control Header Set</alert>` +
				`<riskcode>1</riskcode><url>https://www.example.com/app.css</url></alertitem>` +
				`</alerts></site></OWASPZAPReport>`,
			wantP:     2,
			wantF:     0,
			wantKind:  "findings",
			wantCount: 2,
		},
		{
			name:     "zap duplicate alert dedup",
			importer: NewXMLZapImporter(),
			content: `<?xml version="1.0"?><OWASPZAPReport version="2.16.0">` +
				`<site name="https://www.example.com"><alerts>` +
				`<alertitem><pluginid>40018</pluginid><alert>SQL Injection</alert>` +
				`<riskcode>3</riskcode><url>https://www.example.com/item</url></alertitem>` +
				`<alertitem><pluginid>40018</pluginid><alert>SQL Injection</alert>` +
				`<riskcode>3</riskcode><url>https://www.example.com/item</url></alertitem>` +
				`</alerts></site></OWASPZAPReport>`,
			wantP:     1,
			wantF:     0,
			wantKind:  "findings",
			wantCount: 1,
			checkDup:  true,
		},
		{
			name:     "zap malformed element counted",
			importer: NewXMLZapImporter(),
			content: `<?xml version="1.0"?><OWASPZAPReport version="2.16.0">` +
				`<site name="https://www.example.com"><alerts>` +
				`<alertitem><pluginid>2</pluginid><alert>No URL anywhere</alert></alertitem>` +
				`<alertitem><pluginid>10038</pluginid><alert>CSP</alert>` +
				`<riskcode>2</riskcode><url>https://www.example.com/x</url></alertitem>` +
				`</alerts></site></OWASPZAPReport>`,
			wantP:     1,
			wantF:     1,
			wantKind:  "findings",
			wantCount: 1,
		},
		{
			name:     "burp empty file 0/0",
			importer: NewXMLBurpImporter(),
			content:  ``,
			wantP:    0,
			wantF:    0,
			wantKind: "mixed",
		},
		{
			name:     "zap empty file 0/0",
			importer: NewXMLZapImporter(),
			content:  ``,
			wantP:    0,
			wantF:    0,
			wantKind: "mixed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeXMLTemp(t, "input.xml", tc.content)
			sink := NewSink()
			env := ImportEnv{Clock: fixedClock()}
			stats, err := tc.importer.Import(context.Background(), env, p, sink)
			if err != nil {
				t.Fatalf("Import: %v", err)
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
			case "findings":
				got = len(sink.Findings)
			case "mixed":
				got = len(sink.URLs) + len(sink.Findings) + len(sink.Hosts)
			}
			if got != tc.wantCount {
				t.Fatalf("sink count %d want %d (urls %d findings %d hosts %d)",
					got, tc.wantCount, len(sink.URLs), len(sink.Findings), len(sink.Hosts))
			}
			if tc.checkDup && stats.ItemsProcessed != tc.wantCount {
				t.Fatalf("dedup check: processed %d vs wantCount %d", stats.ItemsProcessed, tc.wantCount)
			}
		})
	}
}

// TestXMLSeverityAndRiskMapping pins the priority mapping end-to-end through
// real imports: Burp textual severity and ZAP numeric riskcode both land on
// the framework priority vocabulary.
func TestXMLSeverityAndRiskMapping(t *testing.T) {
	burpContent := `<?xml version="1.0"?><issues>` +
		`<issue><name>A</name><severity>Critical</severity><host>https://a.example.com</host><path>/a</path></issue>` +
		`<issue><name>B</name><severity>High</severity><host>https://b.example.com</host><path>/b</path></issue>` +
		`<issue><name>C</name><severity>Medium</severity><host>https://c.example.com</host><path>/c</path></issue>` +
		`<issue><name>D</name><severity>Low</severity><host>https://d.example.com</host><path>/d</path></issue>` +
		`<issue><name>E</name><severity>Information</severity><host>https://e.example.com</host><path>/e</path></issue>` +
		`</issues>`
	p := writeXMLTemp(t, "sev.xml", burpContent)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, p, sink)
	if err != nil || stats.ItemsProcessed != 5 {
		t.Fatalf("burp import: stats %+v err %v", stats, err)
	}
	wantByPath := map[string]string{"/a": "critical", "/b": "high", "/c": "medium", "/d": "low", "/e": "info"}
	for _, f := range sink.Findings {
		want, ok := wantByPath[f.Metadata["path"]]
		if !ok {
			t.Fatalf("unexpected finding path %q", f.Metadata["path"])
		}
		if f.Priority != want {
			t.Fatalf("burp severity path %s: priority %q want %q", f.Metadata["path"], f.Priority, want)
		}
	}

	zapContent := `<?xml version="1.0"?><OWASPZAPReport version="2.16.0"><site name="https://z.example.com"><alerts>` +
		`<alertitem><pluginid>1</pluginid><alert>R3</alert><riskcode>3</riskcode><url>https://z.example.com/r3</url></alertitem>` +
		`<alertitem><pluginid>2</pluginid><alert>R2</alert><riskcode>2</riskcode><url>https://z.example.com/r2</url></alertitem>` +
		`<alertitem><pluginid>3</pluginid><alert>R1</alert><riskcode>1</riskcode><url>https://z.example.com/r1</url></alertitem>` +
		`<alertitem><pluginid>4</pluginid><alert>R0</alert><riskcode>0</riskcode><url>https://z.example.com/r0</url></alertitem>` +
		`<alertitem><pluginid>5</pluginid><alert>RX</alert><riskcode>bogus</riskcode><url>https://z.example.com/rx</url></alertitem>` +
		`</alerts></site></OWASPZAPReport>`
	p2 := writeXMLTemp(t, "risk.xml", zapContent)
	sink2 := NewSink()
	stats2, err := NewXMLZapImporter().Import(context.Background(), env, p2, sink2)
	if err != nil || stats2.ItemsProcessed != 5 {
		t.Fatalf("zap import: stats %+v err %v", stats2, err)
	}
	wantByPlugin := map[string]string{"1": "high", "2": "medium", "3": "low", "4": "info", "5": "unknown"}
	for _, f := range sink2.Findings {
		plugin := f.Metadata["pluginid"]
		want, ok := wantByPlugin[plugin]
		if !ok {
			t.Fatalf("unexpected pluginid %q", plugin)
		}
		if f.Priority != want {
			t.Fatalf("zap riskcode plugin %s: priority %q want %q", plugin, f.Priority, want)
		}
	}
}

func TestXMLTruncatedMidElement(t *testing.T) {
	// File cut mid-record: honest truncation — processed records stay, the
	// partial record is neither silently dropped nor completed.
	content := `<?xml version="1.0"?><items>` +
		`<item><url>https://example.com/first</url></item>` +
		`<item><url>https://example.com/seco`
	p := writeXMLTemp(t, "trunc.xml", content)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated {
		t.Fatalf("want Truncated for mid-element EOF")
	}
	if stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want import_truncated sticky flag")
	}
	if stats.ItemsProcessed != 1 {
		t.Fatalf("processed %d want 1 (only complete record)", stats.ItemsProcessed)
	}
	if len(sink.URLs) != 1 {
		t.Fatalf("urls %d want 1", len(sink.URLs))
	}
}

func TestXMLMaxOutputTailDrop(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><items>`)
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, `<item><url>https://example.com/%d</url></item>`, i)
	}
	b.WriteString(`</items>`)
	p := writeXMLTemp(t, "cap.xml", b.String())
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 5}}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, p, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !stats.Truncated || stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("want truncated sticky, got %+v", stats)
	}
	if len(sink.URLs) != 5 || stats.ItemsProcessed != 5 {
		t.Fatalf("tail drop: urls %d processed %d want 5/5", len(sink.URLs), stats.ItemsProcessed)
	}
	if sink.truncatedNotSet() {
		t.Fatalf("sink truncation marker not set")
	}
}

func TestXMLProvenancePreserved(t *testing.T) {
	fixed := fixedClock()()
	// Burp issues → Finding provenance
	content := `<?xml version="1.0"?><issues>` +
		`<issue><name>Content type is not specified</name><severity>Low</severity>` +
		`<host>https://api.example.com</host><path>/v1/users</path></issue>` +
		`</issues>`
	p := writeXMLTemp(t, "burp_issues.xml", content)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, p, sink)
	if err != nil || stats.ItemsProcessed != 1 {
		t.Fatalf("import: %+v err %v", stats, err)
	}
	if len(sink.Findings) != 1 || len(sink.ProvenanceRecords) != 1 {
		t.Fatalf("findings %d provenance %d want 1/1", len(sink.Findings), len(sink.ProvenanceRecords))
	}
	rec := sink.ProvenanceRecords[0]
	f := sink.Findings[0]
	if rec.Importer != "xml-burp" {
		t.Fatalf("importer %q", rec.Importer)
	}
	if rec.OriginalTool != ProvenanceSourceForImporter("xml-burp") {
		t.Fatalf("tool %q", rec.OriginalTool)
	}
	if ProvenanceSourceForImporter("xml-burp") != "burpsuite" {
		t.Fatalf("source mapping changed unexpectedly: %q", ProvenanceSourceForImporter("xml-burp"))
	}
	if rec.Filename != "burp_issues.xml" {
		t.Fatalf("filename %q", rec.Filename)
	}
	if !rec.ImportTime.Equal(fixed) {
		t.Fatalf("time mismatch: %v", rec.ImportTime)
	}
	if !strings.Contains(rec.OriginalRecord, "<name>Content type is not specified</name>") {
		t.Fatalf("original record lost verbatim content: %q", rec.OriginalRecord)
	}
	if len(rec.OriginalRecord) > MaxOriginalRecordBytes {
		t.Fatalf("original record over cap")
	}
	if rec.Identity != f.Identity().String() {
		t.Fatalf("identity mismatch %q vs %q", rec.Identity, f.Identity().String())
	}
	// Evidence carries the provenance and cites the subject.
	if len(f.Evidence) != 1 {
		t.Fatalf("want 1 evidence")
	}
	ev := f.Evidence[0]
	if ev.Prov.Source != "burpsuite" {
		t.Fatalf("evidence prov source %q", ev.Prov.Source)
	}
	if ev.Prov.Reference != "burp_issues.xml:1" {
		t.Fatalf("evidence reference %q", ev.Prov.Reference)
	}
	if !ev.Prov.DiscoveredAt.Equal(fixed) {
		t.Fatalf("evidence discoveredAt mismatch")
	}
	// Subject resolution: scheme-carrying host + path joins via ParseURL.
	if !strings.Contains(f.Subject.String(), "api.example.com") {
		t.Fatalf("subject %q", f.Subject.String())
	}

	// ZAP alerts → Finding provenance
	zcontent := `<?xml version="1.0"?><OWASPZAPReport version="2.16.0"><site name="https://www.example.com"><alerts>` +
		`<alertitem><pluginid>10038</pluginid><alert>CSP: strict-dynamic</alert>` +
		`<riskcode>2</riskcode><url>https://www.example.com/index.html</url></alertitem>` +
		`</alerts></site></OWASPZAPReport>`
	p2 := writeXMLTemp(t, "zap.xml", zcontent)
	sink2 := NewSink()
	stats2, err := NewXMLZapImporter().Import(context.Background(), env, p2, sink2)
	if err != nil || stats2.ItemsProcessed != 1 {
		t.Fatalf("zap import: %+v err %v", stats2, err)
	}
	rec2 := sink2.ProvenanceRecords[0]
	if rec2.Importer != "xml-zap" || rec2.OriginalTool != "owaspzap" {
		t.Fatalf("zap provenance importer/tool: %q/%q", rec2.Importer, rec2.OriginalTool)
	}
	if rec2.Filename != "zap.xml" {
		t.Fatalf("zap filename %q", rec2.Filename)
	}
	if !strings.Contains(rec2.OriginalRecord, "<pluginid>10038</pluginid>") {
		t.Fatalf("zap original record lost verbatim content: %q", rec2.OriginalRecord)
	}
	if rec2.Identity != sink2.Findings[0].Identity().String() {
		t.Fatalf("zap identity mismatch")
	}
}

func TestXMLStreamingBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "big.xml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	const items = 200000
	fmt.Fprint(f, "<?xml version=\"1.0\"?><items>\n")
	for i := 0; i < items; i++ {
		fmt.Fprintf(f, "<item><url>https://example.com/%d</url></item>\n", i)
	}
	fmt.Fprint(f, "</items>\n")
	f.Close()

	// What this heap guard honestly measures: RETAINED heap after GC with the
	// sink pinned live past the m2 snapshot (count reads below + KeepAlive).
	// With distinct URLs the retained set IS the dominant term by design —
	// effectiveMaxOutput() assets + provenance sidecars (measured ≈560 B per
	// record ⇒ ~53 MiB retained at the 100k cap) — so the bound below pins
	// output-retention cost plus streaming overhead, it does NOT isolate
	// streaming overhead. That isolation is TestXMLStreamingNoPerRecordRetention.
	// Peak transient allocations are not observable via MemStats deltas at all.
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: MaxOutput}}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Sink liveness is structural: these reads happen after m2, so the GC
	// cannot have freed the retained assets before measurement, and a freed
	// sink could not satisfy them either.
	const wantRetained = items / 2 // tail-dropped at effectiveMaxOutput
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
	const maxDelta = 128 << 20 // measured 53.4 MiB retention @100k + >2x slack
	if heapDelta > maxDelta {
		t.Fatalf("heap delta %d exceeds retention bound %d — unbounded retention?", heapDelta, maxDelta)
	}
}

// TestXMLStreamingNoPerRecordRetention is the tight streaming-overhead guard:
// duplicate URLs dedup to a near-empty sink while the decoder still streams
// the whole multi-MiB file, so any per-record accumulation (raw windows,
// maps, buffers) would blow the small delta. The unique sentinel as the LAST
// record proves the decoder reached EOF instead of stopping early.
func TestXMLStreamingNoPerRecordRetention(t *testing.T) {
	if testing.Short() {
		t.Skip("skip bounded heap check in short")
	}
	if isRaceEnabled() {
		t.Skip("skip heap guard under -race")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.xml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	const dups = 150000
	fmt.Fprint(f, "<?xml version=\"1.0\"?><items>\n")
	for i := 0; i < dups; i++ {
		fmt.Fprint(f, "<item><url>https://example.com/same</url></item>\n")
	}
	fmt.Fprint(f, "<item><url>https://example.com/sentinel-last</url></item>\n")
	fmt.Fprint(f, "</items>\n")
	f.Close()

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: MaxOutput}}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// EOF proof: first occurrence stored + sentinel stored ⇒ decoder consumed
	// every record. Duplicates are neither processed nor failed (parity).
	if got := len(sink.URLs); got != 2 {
		t.Fatalf("urls %d want 2 (dedup + sentinel) — stream stopped early?", got)
	}
	if stats.ItemsProcessed != 2 || stats.ItemsFailed != 0 || stats.Truncated {
		t.Fatalf("stats %+v want processed=2 failed=0 truncated=false", stats)
	}
	runtime.KeepAlive(sink)

	var heapDelta uint64
	if m2.HeapInuse > m1.HeapInuse {
		heapDelta = m2.HeapInuse - m1.HeapInuse
	}
	t.Logf("measured streaming overhead delta: %d bytes (%.2f MiB) while streaming %d records (~%.1f MiB file)",
		heapDelta, float64(heapDelta)/(1<<20), dups+1, float64(dups)*50/(1<<20))
	// Machinery retention is tap window (36 KiB) + 8 KiB bufio + decoder
	// buffers + 2 assets; 8 MiB leaves wide-but-honest slack.
	const maxDelta = 8 << 20
	if heapDelta > maxDelta {
		t.Fatalf("streaming overhead delta %d exceeds %d — per-record retention?", heapDelta, maxDelta)
	}
}

// TestRegressionHIGH_XMLOriginalRecordExactWindow pins the provenance window
// to exactly [record start, record close): OriginalRecord must equal the
// verbatim record element across fine-grained padding sweeps that walk record
// offsets through every phase of the 8 KiB bufio / decoder buffer boundaries
// (pre-fix, raw was captured BEFORE DecodeElement so the window's upper bound
// was the decoder read-ahead position — fragments ending mid-URL or bleeding
// into the next record).
func TestRegressionHIGH_XMLOriginalRecordExactWindow(t *testing.T) {
	item := func(i int) string {
		return fmt.Sprintf("<item><url>https://example.com/%d</url></item>", i)
	}

	// --- Burp sitemap: exact-match sweeps ---
	// Sweep 1: every pad length in [0,2048] (fine-grained, crosses the 4 KiB
	// decoder-buffer phase range). Sweep 2: ±128 around the 8 KiB bufio
	// boundary. Padding sits BETWEEN records, so it belongs to no record and
	// the captured window must end at </item> exactly.
	sweeps := []struct {
		name   string
		lo, hi int
	}{
		{"fine", 0, 2048},
		{"bufio-boundary", 8192 - 128, 8192 + 128},
	}
	for _, sw := range sweeps {
		t.Run("items-"+sw.name, func(t *testing.T) {
			var b strings.Builder
			b.WriteString("<?xml version=\"1.0\"?><items>\n")
			n := 0
			for pad := sw.lo; pad <= sw.hi; pad++ {
				b.WriteString(strings.Repeat(" ", pad))
				b.WriteString(item(n))
				b.WriteString("\n")
				n++
			}
			b.WriteString("</items>\n")
			p := writeXMLTemp(t, "sweep.xml", b.String())
			sink := NewSink()
			stats, err := NewXMLBurpImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
			if err != nil || stats.ItemsFailed != 0 {
				t.Fatalf("import: %+v err %v", stats, err)
			}
			if len(sink.URLs) != n || len(sink.ProvenanceRecords) != n {
				t.Fatalf("urls %d prov %d want %d", len(sink.URLs), len(sink.ProvenanceRecords), n)
			}
			for i, rec := range sink.ProvenanceRecords {
				if want := item(i); rec.OriginalRecord != want {
					t.Fatalf("pad-sweep record %d: OriginalRecord drift\n got (%d B): %.120q\nwant (%d B): %q",
						i, len(rec.OriginalRecord), rec.OriginalRecord, len(want), want)
				}
				if !strings.HasSuffix(rec.OriginalRecord, "</url></item>") {
					t.Fatalf("record %d does not end at record close: %q", i, tail(rec.OriginalRecord))
				}
			}
		})
	}

	// --- Burp issues: suffix sweep (every 3rd pad + boundary band) ---
	{
		var b strings.Builder
		b.WriteString("<?xml version=\"1.0\"?><issues>\n")
		n := 0
		pads := map[int]bool{}
		for pad := 0; pad <= 512; pad += 1 {
			pads[pad] = true
		}
		for pad := 8192 - 64; pad <= 8192+64; pad++ {
			pads[pad] = true
		}
		padList := make([]int, 0, len(pads))
		for pad := range pads {
			padList = append(padList, pad)
		}
		sort.Ints(padList)
		for _, pad := range padList {
			fmt.Fprintf(&b, "%s<issue><name>Issue-%d</name><severity>Low</severity><host>api.example.com</host><path>/p/%d</path></issue>\n", strings.Repeat(" ", pad), n, n)
			n++
		}
		b.WriteString("</issues>\n")
		p := writeXMLTemp(t, "issues_sweep.xml", b.String())
		sink := NewSink()
		stats, err := NewXMLBurpImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
		if err != nil || stats.ItemsFailed != 0 {
			t.Fatalf("issues import: %+v err %v", stats, err)
		}
		if len(sink.Findings) != n || len(sink.ProvenanceRecords) != n {
			t.Fatalf("findings %d prov %d want %d", len(sink.Findings), len(sink.ProvenanceRecords), n)
		}
		for i, rec := range sink.ProvenanceRecords {
			if !strings.HasSuffix(rec.OriginalRecord, "</issue>") {
				t.Fatalf("issue %d does not end at </issue>: tail=%q", i, tail(rec.OriginalRecord))
			}
			if !strings.Contains(rec.OriginalRecord, fmt.Sprintf("<name>Issue-%d</name>", i)) {
				t.Fatalf("issue %d lost its own content: %.120q", i, rec.OriginalRecord)
			}
		}
	}

	// --- ZAP alertitem: boundary band ---
	{
		var b strings.Builder
		b.WriteString(`<?xml version="1.0"?><OWASPZAPReport version="2.16.0"><site name="https://www.example.com"><alerts>`)
		n := 0
		for pad := 4092; pad <= 4100; pad++ {
			fmt.Fprintf(&b, "%s<alertitem><pluginid>%d</pluginid><alert>A-%d</alert><riskcode>1</riskcode><url>https://www.example.com/%d</url></alertitem>", strings.Repeat(" ", pad), 40000+n, n, n)
			n++
		}
		b.WriteString(`</alerts></site></OWASPZAPReport>`)
		p := writeXMLTemp(t, "zap_sweep.xml", b.String())
		sink := NewSink()
		stats, err := NewXMLZapImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
		if err != nil || stats.ItemsFailed != 0 {
			t.Fatalf("zap import: %+v err %v", stats, err)
		}
		if len(sink.Findings) != n {
			t.Fatalf("zap findings %d want %d", len(sink.Findings), n)
		}
		for i, rec := range sink.ProvenanceRecords {
			if !strings.HasSuffix(rec.OriginalRecord, "</alertitem>") {
				t.Fatalf("alertitem %d does not end at </alertitem>: tail=%q", i, tail(rec.OriginalRecord))
			}
		}
	}

	// --- Oversized record: honest capped prefix, starting at record open ---
	{
		long := "<item><url>https://example.com/big/" + strings.Repeat("a", 6000) + "</url></item>"
		content := "<?xml version=\"1.0\"?><items>" + long + "</items>"
		p := writeXMLTemp(t, "big_item.xml", content)
		sink := NewSink()
		stats, err := NewXMLBurpImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
		if err != nil || stats.ItemsProcessed != 1 {
			t.Fatalf("big import: %+v err %v", stats, err)
		}
		got := sink.ProvenanceRecords[0].OriginalRecord
		if len(got) != MaxOriginalRecordBytes {
			t.Fatalf("capped OriginalRecord len %d want %d", len(got), MaxOriginalRecordBytes)
		}
		if !strings.HasPrefix(got, "<item><url>https://example.com/big/") {
			t.Fatalf("capped OriginalRecord lost record start: %.80q", got)
		}
	}
}

// tail returns the last min(n,len) bytes of s for compact failure output.
func tail(s string) string {
	if len(s) > 48 {
		return s[len(s)-48:]
	}
	return s
}

// TestRegressionMED_XMLStickyDecodeAbortsOnce pins the malformed-content
// contract: encoding/xml's Decoder.err is sticky, so the first XML-level
// undecodable record aborts the import with a structured error — counted as
// exactly ONE failure, never double-counted via the sticky re-report, and
// remaining records are honestly not processed.
func TestRegressionMED_XMLStickyDecodeAbortsOnce(t *testing.T) {
	cases := []struct {
		name    string
		poison  string
		wantMsg string
	}{
		{"undefined-entity", "&bogus;", "not XML-decodable"},
		{"invalid-utf8", "\xff\xfe", "not XML-decodable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := `<?xml version="1.0"?><issues>` +
				`<issue><name>Good One</name><severity>Low</severity><host>api.example.com</host><path>/a</path></issue>` +
				`<issue><name>` + tc.poison + `</name><severity>Low</severity><host>api.example.com</host><path>/b</path></issue>` +
				`<issue><name>Never Reached</name><severity>Low</severity><host>api.example.com</host><path>/c</path></issue>` +
				`</issues>`
			p := writeXMLTemp(t, "sticky.xml", content)
			sink := NewSink()
			stats, err := NewXMLBurpImporter().Import(context.Background(), ImportEnv{Clock: fixedClock()}, p, sink)
			if err == nil {
				t.Fatalf("want structured abort error, got nil (stats %+v)", stats)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("abort error %q want substring %q", err.Error(), tc.wantMsg)
			}
			if stats.ItemsFailed != 1 {
				t.Fatalf("ItemsFailed %d want 1 (counted once)", stats.ItemsFailed)
			}
			if stats.ItemsProcessed != 1 {
				t.Fatalf("ItemsProcessed %d want 1 (first good only)", stats.ItemsProcessed)
			}
			if len(sink.Findings) != 1 {
				t.Fatalf("findings %d want 1", len(sink.Findings))
			}
			if sink.Findings[0].RuleName != "Good One" {
				t.Fatalf("wrong finding retained %q", sink.Findings[0].RuleName)
			}
			if stats.Truncated {
				t.Fatalf("structured abort must not masquerade as truncation: %+v", stats)
			}
		})
	}
}

func TestXMLCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cancel.xml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fmt.Fprint(f, "<?xml version=\"1.0\"?><items>\n")
	for i := 0; i < 200000; i++ {
		fmt.Fprintf(f, "<item><url>https://example.com/%d</url></item>\n", i)
	}
	fmt.Fprint(f, "</items>\n")
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * time.Millisecond)
		cancel()
	}()
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	_, err = NewXMLBurpImporter().Import(ctx, env, path, sink)
	// Timing-dependent: if it completed before cancellation that's fine.
	if ctx.Err() != nil && err == nil {
		t.Fatalf("ctx cancelled but Import returned nil error")
	}
	// Already-cancelled context must fail fast deterministically (before IO).
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	sink2 := NewSink()
	_, err2 := NewXMLZapImporter().Import(ctx2, env, filepath.Join(dir, "cancel_zap.xml"), sink2)
	if err2 != context.Canceled {
		t.Fatalf("want context.Canceled got %v", err2)
	}
}

func TestXMLProgressEmission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "progress.xml")
	f, _ := os.Create(path)
	fmt.Fprint(f, "<?xml version=\"1.0\"?><items>\n")
	// Same URL repeatedly keeps the sink tiny while bytes flow past the
	// ProgressBytesInterval threshold.
	line := strings.Repeat(" ", 4096) + "<item><url>https://example.com/same</url></item>\n"
	for i := 0; i < 64; i++ {
		f.WriteString(line)
	}
	fmt.Fprint(f, "</items>\n")
	f.Close()
	bus := event.NewBus(nil)
	sub, _ := bus.Subscribe(100)
	env := ImportEnv{Clock: fixedClock(), Observer: bus}
	sink := NewSink()
	_, err := NewXMLBurpImporter().Import(context.Background(), env, path, sink)
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
		t.Fatalf("expected at least one progress event")
	}
}

func TestXMLGzipHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sitemap.xml.gz")
	f, _ := os.Create(path)
	gw := gzipWriterFor(f)
	gw.write([]byte("<?xml version=\"1.0\"?><items>" +
		"<item><url>https://example.com/a</url></item>" +
		"<item><url>https://example.com/b</url></item></items>"))
	gw.close()
	f.Close()
	sink := NewSink()
	env := ImportEnv{Clock: fixedClock()}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import gzip: %v", err)
	}
	if stats.ItemsProcessed != 2 || len(sink.URLs) != 2 {
		t.Fatalf("gzip: processed %d urls %d want 2/2", stats.ItemsProcessed, len(sink.URLs))
	}
}

func TestXMLDecompressedCapAbortsTruncated(t *testing.T) {
	// Gzip bomb guard parity with readLines/streamJSON: decompressed bytes
	// over MaxDecompressedBytes abort with Truncated=true instead of OOM.
	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.xml.gz")
	f, _ := os.Create(path)
	gw := gzipWriterFor(f)
	gw.write([]byte("<?xml version=\"1.0\"?><items>"))
	padding := strings.Repeat("<!-- pad -->", 1024) // ~13 KiB of inter-record bytes
	for i := 0; i < 600; i++ {
		gw.write([]byte(padding))
		fmt.Fprintf(gw.gz, "<item><url>https://example.com/%d</url></item>", i)
	}
	gw.write([]byte("</items>"))
	gw.close()
	f.Close()

	sink := NewSink()
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxDecompressedBytes: 64 * 1024}}
	stats, err := NewXMLBurpImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import bomb: %v", err)
	}
	if !stats.Truncated || stats.StickyFlags["import_truncated"] != true {
		t.Fatalf("decompressed cap did not truncate: %+v", stats)
	}
}

func TestXMLRegistryDeterminism(t *testing.T) {
	r := NewRegistry()
	// Register deliberately shuffled order including both XML importers.
	_ = r.Register(NewXMLZapImporter())
	_ = r.Register(NewPlainURLsImporter())
	_ = r.Register(NewJSONHttpxImporter())
	_ = r.Register(NewXMLBurpImporter())
	_ = r.Register(NewJSONGenericImporter())
	_ = r.Register(NewPlainGenericImporter())
	r.Seal()
	list := r.List()
	if len(list) != 6 {
		t.Fatalf("list %d want 6", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name() >= list[i].Name() {
			t.Fatalf("List not sorted Name asc: %s >= %s", list[i-1].Name(), list[i].Name())
		}
	}

	p := writeXMLTemp(t, "det.xml", `<?xml version="1.0"?><issues><issue><name>N</name><severity>Low</severity><host>https://example.com</host><path>/</path></issue></issues>`)
	peek, err := peekFile(p)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	m1 := r.Detect(p, peek)
	m2 := r.Detect(p, peek)
	if len(m1) != len(m2) {
		t.Fatalf("Detect length unstable")
	}
	for i := range m1 {
		if m1[i].Importer.Name() != m2[i].Importer.Name() || m1[i].Confidence != m2[i].Confidence {
			t.Fatalf("Detect unstable at %d", i)
		}
	}
	if m1[0].Importer.Name() != "xml-burp" {
		t.Fatalf("top %q want xml-burp", m1[0].Importer.Name())
	}
	for i := 1; i < len(m1); i++ {
		prev, cur := m1[i-1], m1[i]
		if prev.Confidence < cur.Confidence {
			t.Fatalf("confidence desc violated: %.2f < %.2f", prev.Confidence, cur.Confidence)
		}
		isGenPrev := prev.Importer.Name() == "plain-generic" || prev.Importer.Name() == "json-generic"
		isGenCur := cur.Importer.Name() == "plain-generic" || cur.Importer.Name() == "json-generic"
		if isGenPrev && !isGenCur {
			t.Fatalf("generic not last: %s before %s", prev.Importer.Name(), cur.Importer.Name())
		}
	}
}

// truncatedNotSet reports whether the sink-side sticky truncation marker is
// unset; TestXMLMaxOutputTailDrop asserts it IS set after a tail-drop.
func (s *Sink) truncatedNotSet() bool { return !s.truncated }

// TestXMLFixtureFiles runs the committed synthetic testdata fixtures through
// both detection and import end-to-end: pretty-printed multi-line exports
// (the shape real tools produce, unlike the inline one-liner cases above)
// must detect as their family and stream with every record accounted for.
func TestXMLFixtureFiles(t *testing.T) {
	r := newFullRegistry(t)
	cases := []struct {
		file     string
		wantTop  string
		importer Importer
		wantP    int
		wantKind string
		wantN    int
	}{
		{"xml_burp_sitemap.xml", "xml-burp", NewXMLBurpImporter(), 3, "urls", 3},
		{"xml_burp_issues.xml", "xml-burp", NewXMLBurpImporter(), 2, "findings", 2},
		{"xml_zap_report.xml", "xml-zap", NewXMLZapImporter(), 3, "findings", 3},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			peek, err := peekFile(path)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			matches := r.Detect(path, peek)
			if len(matches) == 0 || matches[0].Importer.Name() != tc.wantTop {
				t.Fatalf("detection: want top %q got %v", tc.wantTop, matches)
			}
			sink := NewSink()
			stats, err := tc.importer.Import(context.Background(), ImportEnv{Clock: fixedClock()}, path, sink)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if stats.ItemsProcessed != tc.wantP || stats.ItemsFailed != 0 || stats.Truncated {
				t.Fatalf("stats: %+v want processed=%d failed=0 truncated=false", stats, tc.wantP)
			}
			var got int
			switch tc.wantKind {
			case "urls":
				got = len(sink.URLs)
			case "findings":
				got = len(sink.Findings)
			}
			if got != tc.wantN {
				t.Fatalf("sink %s count %d want %d", tc.wantKind, got, tc.wantN)
			}
			if len(sink.ProvenanceRecords) != tc.wantN {
				t.Fatalf("provenance records %d want %d", len(sink.ProvenanceRecords), tc.wantN)
			}
			for _, rec := range sink.ProvenanceRecords {
				if rec.OriginalRecord == "" {
					t.Fatalf("%s: empty OriginalRecord for identity %s", tc.file, rec.Identity)
				}
				if !strings.Contains(rec.OriginalRecord, "<item>") &&
					!strings.Contains(rec.OriginalRecord, "<issue>") &&
					!strings.Contains(rec.OriginalRecord, "<alertitem>") {
					t.Fatalf("original record not verbatim XML: %q", rec.OriginalRecord)
				}
			}
		})
	}
}
