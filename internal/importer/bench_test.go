package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Benchmarks exercise the import path hermetically: synthetic corpora are
// generated in-test into temp directories (deterministic, fixed-width
// records so B/op is stable), the cache benchmarks use a real
// filesystem-backed cache in a temp dir, and nothing touches the network
// (AGENTS §12/§13). They run only under -bench and are skipped by the
// normal `go test ./...` gate.
//
// Baseline + gate protocol (testdata/bench/README.md): record with
//
//	go test -run '^$' -bench=. -benchmem -count=10 ./internal/importer/ \
//	  > testdata/bench/importer.txt
//
// and compare via cmd/benchgate. The cache benchmarks include real fsync'd
// cache writes/deletes, so their ns/op is machine-noisy; the benchgate hard
// metric is median B/op and allocs/op (>25%), which are allocation-shaped
// and stable — ns/op stays advisory per D4.

const benchRecordCount = 10000

// writeBenchCorpus writes data as a single file named name inside a fresh
// temp dir and returns the full path. Shared with memguard_test.go.
func writeBenchCorpus(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write corpus %s: %v", name, err)
	}
	return path
}

// newFullBenchRegistry registers the canonical 18-importer set exactly like
// newFullRegistry / the ingest stage composition point (doc.go checklist):
// 16 specific importers plus json-generic then plain-generic fallbacks.
func newFullBenchRegistry() *Registry {
	r := NewRegistry()
	for _, imp := range []Importer{
		NewPlainDomainsImporter(), NewPlainSubdomainsImporter(), NewPlainURLsImporter(),
		NewPlainAliveImporter(), NewPlainJSImporter(), NewPlainIPsImporter(),
		NewPlainCIDRsImporter(), NewJSONHttpxImporter(), NewJSONDnsxImporter(),
		NewJSONNaabuImporter(), NewJSONKatanaImporter(), NewJSONNucleiImporter(),
		NewXMLBurpImporter(), NewXMLZapImporter(),
		NewArchiveCDXImporter(), NewArchiveWARCImporter(),
		NewJSONGenericImporter(), NewPlainGenericImporter(),
	} {
		if err := r.Register(imp); err != nil {
			panic(fmt.Sprintf("bench registry Register(%s): %v", imp.Name(), err))
		}
	}
	r.Seal()
	return r
}

// validateOnce runs one untimed import and pins the workload shape so a
// benchmark can never silently measure an empty or truncated pass.
func validateOnce(b *testing.B, imp Importer, env ImportEnv, path string, wantProcessed int) {
	b.Helper()
	stats, err := imp.Import(context.Background(), env, path, NewSink())
	if err != nil {
		b.Fatalf("%s validation Import: %v", imp.Name(), err)
	}
	if stats.ItemsProcessed != wantProcessed || stats.ItemsFailed != 0 || stats.Truncated {
		b.Fatalf("%s validation: processed=%d failed=%d truncated=%v, want processed=%d failed=0 truncated=false",
			imp.Name(), stats.ItemsProcessed, stats.ItemsFailed, stats.Truncated, wantProcessed)
	}
}

// plainURLsCorpus builds n distinct fixed-width URL lines (~48 bytes each).
func plainURLsCorpus(n int) []byte {
	var buf bytes.Buffer
	buf.Grow(n * 48)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&buf, "https://host%05d.example.com/path%05d\n", i, i)
	}
	return buf.Bytes()
}

// httpxJSONLCorpus builds n distinct httpx NDJSON records.
func httpxJSONLCorpus(n int) []byte {
	var buf bytes.Buffer
	buf.Grow(n * 110)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&buf, "{\"url\":\"https://host%05d.example.com/p%05d\",\"status_code\":200,\"title\":\"Example\",\"tech\":[\"nginx\"]}\n", i, i)
	}
	return buf.Bytes()
}

// domainsCorpus builds n distinct fixed-width domain lines (~27 bytes each).
func domainsCorpus(n int) []byte {
	var buf bytes.Buffer
	buf.Grow(n * 28)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&buf, "host%05d.example.com\n", i)
	}
	return buf.Bytes()
}

// BenchmarkPlainURLs10K imports a 10k-line plain URL list end to end:
// streaming read → line classification → asset.ParseURL normalization →
// dedup → sink append + provenance sidecar. One fresh Sink per iteration,
// matching one cold file import.
func BenchmarkPlainURLs10K(b *testing.B) {
	path := writeBenchCorpus(b, "bench-urls.txt", plainURLsCorpus(benchRecordCount))
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000}}
	imp := NewPlainURLsImporter()
	validateOnce(b, imp, env, path, benchRecordCount)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := imp.Import(context.Background(), env, path, NewSink()); err != nil {
			b.Fatalf("Import: %v", err)
		}
	}
}

// BenchmarkJSONHTTPX10K imports 10k httpx JSONL records end to end:
// bounded NDJSON framing → per-record json.Decoder → ParseURL normalization
// → dedup → sink append + provenance sidecar with OriginalRecord capture.
func BenchmarkJSONHTTPX10K(b *testing.B) {
	path := writeBenchCorpus(b, "bench-httpx.jsonl", httpxJSONLCorpus(benchRecordCount))
	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000}}
	imp := NewJSONHttpxImporter()
	validateOnce(b, imp, env, path, benchRecordCount)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := imp.Import(context.Background(), env, path, NewSink()); err != nil {
			b.Fatalf("Import: %v", err)
		}
	}
}

// detectCandidate pairs a written file with its detection peek.
type detectCandidate struct {
	path string
	peek []byte
}

// buildDetectCandidates writes numPerShape files of every representative
// format family (.txt bare URLs / .txt domains / .jsonl httpx / .xml Burp
// sitemap / .cdx classic lines / .warc records / .dat unknown text) and
// buffers each file's first PeekSize bytes once — the exact work the ingest
// stage's detect() performs per file before Import.
func buildDetectCandidates(b *testing.B, numPerShape int) []detectCandidate {
	b.Helper()
	dir := b.TempDir()
	cdxLine := "com,example)/path%05d 20200809173112 https://example.com/path%05d text/html 200 P7VYB5Q2N4CEP2HJDJFO4M2XU3FJLY7A 10421\n"
	warcRec := "WARC/1.0\r\nWARC-Record-ID: <urn:test:rec-%05d>\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.com/%05d\r\nContent-Length: 5\r\n\r\nhello\r\n\r\n"
	specs := make([][]byte, 0, 7*numPerShape)
	names := make([]string, 0, 7*numPerShape)
	add := func(name string, gen func(i int) string) {
		for i := 0; i < numPerShape; i++ {
			specs = append(specs, []byte(gen(i)))
			names = append(names, fmt.Sprintf(name, i))
		}
	}
	add("urls-%05d.txt", func(i int) string { return string(plainURLsCorpus(50)) })
	add("domains-%05d.txt", func(i int) string {
		var buf bytes.Buffer
		for j := 0; j < 50; j++ {
			fmt.Fprintf(&buf, "h%02d.host%05d.example.com\n", j, i)
		}
		return buf.String()
	})
	add("scan-%05d.jsonl", func(i int) string { return string(httpxJSONLCorpus(50)) })
	add("burp-%05d.xml", func(i int) string {
		var buf bytes.Buffer
		buf.WriteString(`<?xml version="1.0"?><items>`)
		for j := 0; j < 20; j++ {
			fmt.Fprintf(&buf, `<item><url>https://host%02d.example.com/%05d</url><status>200</status></item>`, j, i)
		}
		buf.WriteString(`</items>`)
		return buf.String()
	})
	add("export-%05d.cdx", func(i int) string {
		var buf bytes.Buffer
		for j := 0; j < 50; j++ {
			fmt.Fprintf(&buf, cdxLine, j, j)
		}
		return buf.String()
	})
	add("capture-%05d.warc", func(i int) string {
		var buf bytes.Buffer
		for j := 0; j < 20; j++ {
			fmt.Fprintf(&buf, warcRec, j, j)
		}
		return buf.String()
	})
	add("notes-%05d.dat", func(i int) string {
		var buf bytes.Buffer
		for j := 0; j < 50; j++ {
			fmt.Fprintf(&buf, "operator note row %05d-%05d not asset shaped\n", i, j)
		}
		return buf.String()
	})

	out := make([]detectCandidate, 0, len(specs))
	for k, spec := range specs {
		p := filepath.Join(dir, names[k])
		if err := os.WriteFile(p, spec, 0600); err != nil {
			b.Fatalf("write candidate: %v", err)
		}
		peek, err := peekFile(p)
		if err != nil {
			b.Fatalf("peek %s: %v", p, err)
		}
		out = append(out, detectCandidate{path: p, peek: peek})
	}
	return out
}

// BenchmarkDetectFullRegistry measures mixed detection overhead: the full
// sealed 18-importer registry classifying 70 candidates across seven format
// families per iteration (10 files × 7 shapes). Each candidate costs a
// peek-buffered CanImport sweep over all 18 importers — the per-file fixed
// cost every ingest pays before any parsing.
func BenchmarkDetectFullRegistry(b *testing.B) {
	const numPerShape = 10
	candidates := buildDetectCandidates(b, numPerShape)
	reg := newFullBenchRegistry()

	// Validation pass: every candidate must be claimed by somebody (the
	// .dat notes fall through honestly to plain-generic).
	for _, c := range candidates {
		if matches := reg.Detect(c.path, c.peek); len(matches) == 0 {
			b.Fatalf("no claim for %s", c.path)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range candidates {
			if matches := reg.Detect(c.path, c.peek); len(matches) == 0 {
				b.Fatalf("no claim for %s", c.path)
			}
		}
	}
}

// ingestCacheFixture bundles everything the cold/hit benchmarks need: a
// small deterministic domain list, its derived key parts, and a real
// filesystem-backed cache.
type ingestCacheFixture struct {
	cache    *cache.FS
	key      cache.Key
	parts    CacheKeyParts
	filePath string
	imp      Importer
	env      ImportEnv
	bounds   Bounds
	data     []byte // marshaled ImportCacheData for the Put path
}

// newIngestCacheFixture creates the fixture with a 1k-domain corpus — small
// enough that CI stays bounded, large enough that parse/normalize work is
// visible next to the cache round trip.
func newIngestCacheFixture(b *testing.B) *ingestCacheFixture {
	b.Helper()
	dir := b.TempDir()
	c, err := cache.Open(filepath.Join(dir, "cache"))
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	f := &ingestCacheFixture{
		cache:  c,
		imp:    NewPlainDomainsImporter(),
		bounds: Bounds{MaxOutput: 100000},
	}
	f.env = ImportEnv{Clock: fixedClock(), Bounds: f.bounds}
	f.filePath = writeBenchCorpus(b, "domains.txt", domainsCorpus(1000))
	f.rekey(b)

	sink := NewSink()
	stats, err := f.imp.Import(context.Background(), f.env, f.filePath, sink)
	if err != nil {
		b.Fatalf("fixture Import: %v", err)
	}
	ids := make([]string, 0, len(sink.Domains))
	for _, d := range sink.Domains {
		ids = append(ids, d.Identity().String())
	}
	blob, err := json.Marshal(ImportCacheData{
		SchemaVersion: SchemaVersion,
		Importer:      f.imp.Name(),
		Target:        f.parts.Target,
		Identities:    ids,
		Stats:         stats,
	})
	if err != nil {
		b.Fatalf("marshal ImportCacheData: %v", err)
	}
	f.data = blob
	return f
}

func (f *ingestCacheFixture) rekey(b *testing.B) {
	b.Helper()
	parts, err := CacheKeyForFile(f.filePath, f.imp, f.bounds)
	if err != nil {
		b.Fatalf("CacheKeyForFile: %v", err)
	}
	f.parts = parts
	key, err := cache.NewKey(cache.KeyParts{
		Operation: parts.Operation,
		Target:    parts.Target,
		Config:    parts.Config,
		Tool:      cache.ToolInfo{Name: parts.ToolName, Version: parts.ToolVersion},
	})
	if err != nil {
		b.Fatalf("cache.NewKey: %v", err)
	}
	f.key = key
}

func (f *ingestCacheFixture) store(ctx context.Context, b *testing.B) {
	b.Helper()
	if err := f.cache.Put(ctx, f.key, cache.Record{
		Operation: f.parts.Operation,
		Target:    f.parts.Target,
		Tool:      cache.ToolInfo{Name: f.parts.ToolName, Version: f.parts.ToolVersion},
		Status:    cache.StatusCompleted,
		Data:      f.data,
	}); err != nil {
		b.Fatalf("cache.Put: %v", err)
	}
}

// BenchmarkIngestCold measures one full cold import through the real cache
// composition: content-hash key derivation → Get(miss) → Import → marshal →
// Put → Delete (the delete makes every iteration miss again; it is part of
// the measured cold-cycle cost). fsync latency dominates wall time here;
// the gateable metrics are B/op and allocs/op.
func BenchmarkIngestCold(b *testing.B) {
	f := newIngestCacheFixture(b)
	ctx := context.Background()

	// Validation: first cycle must observe miss → hit-after-put.
	out := f.cache.Get(ctx, f.key)
	if !out.IsMiss() {
		b.Fatalf("fixture pre-state = %s, want miss", out.State)
	}
	f.store(ctx, b)
	if out := f.cache.Get(ctx, f.key); !out.IsHit() {
		b.Fatalf("fixture post-put = %s, want hit", out.State)
	}
	if err := f.cache.Delete(ctx, f.key); err != nil {
		b.Fatalf("cache.Delete: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := f.cache.Get(ctx, f.key); !out.IsMiss() {
			b.Fatalf("iteration %d: state = %s, want miss", i, out.State)
		}
		sink := NewSink()
		stats, err := f.imp.Import(ctx, f.env, f.filePath, sink)
		if err != nil {
			b.Fatalf("Import: %v", err)
		}
		if stats.ItemsProcessed != 1000 {
			b.Fatalf("processed = %d, want 1000", stats.ItemsProcessed)
		}
		f.store(ctx, b)
		if out := f.cache.Get(ctx, f.key); !out.IsHit() {
			b.Fatalf("post-put state = %s, want hit", out.State)
		}
		if err := f.cache.Delete(ctx, f.key); err != nil {
			b.Fatalf("Delete: %v", err)
		}
	}
}

// BenchmarkIngestHit measures the warm path only: content-hash key
// derivation → Get(hit) → decode of the stored identities+stats payload —
// zero parse, zero normalize, zero write. This is what a repeat import of
// an unchanged file costs after caching.
func BenchmarkIngestHit(b *testing.B) {
	f := newIngestCacheFixture(b)
	ctx := context.Background()
	f.store(ctx, b)
	if out := f.cache.Get(ctx, f.key); !out.IsHit() {
		b.Fatalf("fixture warm-up state = %s, want hit", out.State)
	}

	validate := func(i int) {
		out := f.cache.Get(ctx, f.key)
		if !out.IsHit() {
			b.Fatalf("iteration %d: state = %s, want hit", i, out.State)
		}
		var got ImportCacheData
		if err := json.Unmarshal(out.Record.Data, &got); err != nil {
			b.Fatalf("decode cached payload: %v", err)
		}
		if got.Stats.ItemsProcessed != 1000 || len(got.Identities) != 1000 {
			b.Fatalf("cached payload processed=%d identities=%d, want 1000/1000",
				got.Stats.ItemsProcessed, len(got.Identities))
		}
	}
	validate(-1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validate(i)
	}
}
