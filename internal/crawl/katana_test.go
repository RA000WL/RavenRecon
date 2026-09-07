package crawl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// fakeRunner is a hermetic runner for tests.
type fakeRunner struct {
	script map[string]func(discovery.Cmd) (discovery.RunResult, error)
	calls  []discovery.Cmd
}

func newFakeRunner(script map[string]func(discovery.Cmd) (discovery.RunResult, error)) *fakeRunner {
	return &fakeRunner{script: script}
}

func (f *fakeRunner) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	f.calls = append(f.calls, cmd)
	key := cmd.Path
	if len(cmd.Args) > 0 {
		// Normalize key for lookup: join path and args for script matching.
		// Tests use full command string as key.
		key = cmd.Path + " " + joinArgs(cmd.Args)
	}
	// Try exact key, then fallback to path-only.
	if fn, ok := f.script[key]; ok {
		return fn(cmd)
	}
	if fn, ok := f.script[cmd.Path]; ok {
		return fn(cmd)
	}
	// Default: try to match by first arg for version probe etc.
	for k, fn := range f.script {
		if k == cmd.Path+" -version" && len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
			return fn(cmd)
		}
	}
	return discovery.RunResult{}, nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func fakeLookupOK(name string) (string, error) { return name, nil }
func fakeLookupMissing(name string) (string, error) {
	return "", &fakeLookupErr{name}
}

type fakeLookupErr struct{ name string }

func (e *fakeLookupErr) Error() string { return "executable " + e.name + " not found" }

func mustDomain(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain %q: %v", name, err)
	}
	return d
}
func mustHost(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost %q: %v", name, err)
	}
	return h
}
func mustURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL %q: %v", raw, err)
	}
	return u
}

func TestKatanaParseAndScopeFilter(t *testing.T) {
	// Fake runner returns two valid endpoints and one evil.
	script := map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			// Version probe?
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte("katana v1.2.3\n")}, nil
			}
			lines := []katanaRecord{
				{Endpoint: "https://example.com/api/a"},
				{Endpoint: "https://example.com/api/b"},
				{Endpoint: "https://evil.com/api/c"},
				{Endpoint: "not a url"},
				{Endpoint: ""},
			}
			var buf []byte
			for _, r := range lines {
				b, _ := json.Marshal(r)
				buf = append(buf, b...)
				buf = append(buf, '\n')
			}
			return discovery.RunResult{Stdout: buf}, nil
		},
	}
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	cfg := Config{Depth: 2, Timeout: 0, Concurrency: 1, RateLimit: 1}
	res, err := src.Crawl(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(res.URLs) != 2 {
		t.Fatalf("URLs = %d, want 2 (evil and malformed dropped)", len(res.URLs))
	}
	got := []string{res.URLs[0].String(), res.URLs[1].String()}
	sort.Strings(got)
	want := []string{"https://example.com/api/a", "https://example.com/api/b"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("URLs = %v, want %v", got, want)
	}
	// Malformed should be counted in diagnostics.
	foundMalformed := false
	for _, d := range res.Diagnostics {
		if len(d) > 0 && (d[0] == 'm' || d[0] == 'k') {
			foundMalformed = true
		}
	}
	if !foundMalformed {
		t.Errorf("Diagnostics = %v, want malformed count", res.Diagnostics)
	}
	if res.Truncated {
		t.Errorf("Truncated = true, want false")
	}
}

func TestKatanaMissingBinary(t *testing.T) {
	src := NewKatanaSource(newFakeRunner(nil), fakeLookupMissing)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{})
	if err != nil {
		t.Fatalf("Crawl missing binary should not error, got %v", err)
	}
	if len(res.URLs) != 0 {
		t.Errorf("URLs = %d, want 0 for missing binary", len(res.URLs))
	}
	if res.Truncated {
		t.Errorf("Truncated = true, want false for missing")
	}
	// NEW-85: the whole-run abort must carry the failure signal itself —
	// every requested host failed, and the engine says so explicitly
	// instead of leaving consumers to infer it from diagnostics presence.
	if res.FailedHosts != 1 {
		t.Errorf("FailedHosts = %d, want 1 (whole-run abort counts every host)", res.FailedHosts)
	}
}

func TestKatanaTruncationPerHost(t *testing.T) {
	// Generate 1001 URLs for one host → per-host cap 1000.
	script := map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte("katana v1.0.0\n")}, nil
			}
			var buf []byte
			for i := 0; i < 1001; i++ {
				rec := katanaRecord{Endpoint: "https://example.com/api/" + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10)) + "-" + string(rune(i/1000+48))}
				// Simpler: use index.
				rec.Endpoint = "https://example.com/api/" + itoa(i)
				b, _ := json.Marshal(rec)
				buf = append(buf, b...)
				buf = append(buf, '\n')
			}
			return discovery.RunResult{Stdout: buf}, nil
		},
	}
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 3})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(res.URLs) != 1000 {
		t.Fatalf("URLs = %d, want 1000 (per-host cap)", len(res.URLs))
	}
	if !res.Truncated {
		t.Errorf("Truncated = false, want true when per-host cap hit")
	}
}

func itoa(i int) string {
	return jsonNumber(i)
}
func jsonNumber(i int) string {
	// Simple itoa without importing strconv to keep test hermetic? Use fmt.
	// But we can use fmt.Sprint via helper.
	return fmtSprint(i)
}
func fmtSprint(i int) string {
	// Minimal itoa
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func TestKatanaTotalCap(t *testing.T) {
	// This test checks total cap handling indirectly via direct function call.
	// We generate a result with many URLs and verify truncation logic in Crawl
	// would cap at MaxTotalURLs. Testing via fake runner would be heavy (100k),
	// so we test dedupe and sorting determinism.
	script := map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte("v1.0.0\n")}, nil
			}
			// Return 3 URLs unsorted.
			records := []katanaRecord{
				{Endpoint: "https://example.com/z"},
				{Endpoint: "https://example.com/a"},
				{Endpoint: "https://example.com/m"},
			}
			var buf []byte
			for _, r := range records {
				b, _ := json.Marshal(r)
				buf = append(buf, b...)
				buf = append(buf, '\n')
			}
			return discovery.RunResult{Stdout: buf}, nil
		},
	}
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(res.URLs) != 3 {
		t.Fatalf("URLs = %d, want 3", len(res.URLs))
	}
	// Deterministic sorted order.
	want := []string{"https://example.com/a", "https://example.com/m", "https://example.com/z"}
	for i, w := range want {
		if res.URLs[i].String() != w {
			t.Errorf("URLs[%d] = %s, want %s", i, res.URLs[i].String(), w)
		}
	}
}

func TestKatanaDedupAndIPDrop(t *testing.T) {
	script := map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte("v1\n")}, nil
			}
			records := []katanaRecord{
				{Endpoint: "https://example.com/api/a"},
				{Endpoint: "https://example.com/api/a"}, // duplicate
				{Endpoint: "https://192.168.1.1/api/b"}, // IP literal -> drop
				{Endpoint: "https://example.com/api/c"},
			}
			var buf []byte
			for _, r := range records {
				b, _ := json.Marshal(r)
				buf = append(buf, b...)
				buf = append(buf, '\n')
			}
			return discovery.RunResult{Stdout: buf}, nil
		},
	}
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(res.URLs) != 2 {
		t.Fatalf("URLs = %d, want 2 (duplicate and IP dropped)", len(res.URLs))
	}
}

func TestKatanaDetectArgShape(t *testing.T) {
	// Verify katana is invoked with expected args (no -headless, aff=false, fs fqdn, etc.)
	var seenArgs []string
	script := map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte("v1\n")}, nil
			}
			seenArgs = cmd.Args
			return discovery.RunResult{Stdout: []byte(`{"endpoint":"https://example.com/a"}` + "\n")}, nil
		},
	}
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	_, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 2, Concurrency: 7, RateLimit: 123})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	// Pin the exact corrected argv (NEW-93 defect 1): the previously pinned
	// flags were broken — "-ps" is undefined in installed katana (every
	// invocation exited 2 at flag parsing) and "-retries" was renamed
	// "-retry". The pinned slice below matches the verified-working
	// invocation flag-for-flag.
	want := []string{
		"-u", "https://www.example.com",
		"-d", "2",
		"-jc", "-xhr",
		"-aff=false",
		"-fs", "fqdn",
		"-kf", "all",
		"-rl", "123",
		"-c", "7",
		"-timeout", fmt.Sprint(DefaultKatanaTimeout),
		"-retry", "1",
		"-jsonl",
		"-o", "-",
		"-silent",
	}
	if !reflect.DeepEqual(seenArgs, want) {
		t.Errorf("args = %v, want pinned argv %v", seenArgs, want)
	}
	// Never headless, never aff true; never the removed/renamed flags.
	for _, a := range seenArgs {
		if a == "-headless" || a == "-aff=true" || a == "-aff" || a == "-ps" || a == "-retries" {
			t.Errorf("args must never contain %q, got %v", a, seenArgs)
		}
	}
}

// TestKatanaParseRecordShapes pins NEW-93 defect 2 at the parser level:
// modern katana -jsonl nests the endpoint under request.endpoint; the
// legacy flat top-level shape keeps working; a line carrying neither shape
// stays malformed.
func TestKatanaParseRecordShapes(t *testing.T) {
	domain := mustDomain(t, "example.com")
	nested := `{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET","endpoint":"https://example.com/nested","raw":"GET /nested HTTP/1.1\r\nHost: example.com"},"response":{"status_code":200,"headers":{"Content-Type":"text/html"}}}`
	flat := `{"endpoint":"https://example.com/flat","source":"katana","tag":"href"}`
	neither := `{"request":{"method":"HEAD"},"response":{"status_code":301}}`
	out := []byte(strings.Join([]string{nested, flat, neither}, "\n") + "\n")
	urls, malformed, diag := parseKatanaOutput(out, domain)
	if malformed != 1 {
		t.Fatalf("malformed = %d, want 1 (only the shapeless line)", malformed)
	}
	if diag == "" {
		t.Errorf("diag = %q, want malformed-count diagnostic", diag)
	}
	var got []string
	for _, u := range urls {
		got = append(got, u.String())
	}
	sort.Strings(got)
	want := []string{"https://example.com/flat", "https://example.com/nested"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("urls = %v, want %v (both record shapes resolved)", got, want)
	}
}

// TestKatanaCrawlModernNestedJSONLYieldsUsableEndpoints pins the NEW-93
// failure mode end-to-end: a host emitting only modern nested-shape JSONL
// yields usable endpoints — its lines are not misclassified as malformed,
// so the host does not fail via the NEW-86 zero-usable-output semantics.
func TestKatanaCrawlModernNestedJSONLYieldsUsableEndpoints(t *testing.T) {
	script := katanaScript("v1.1.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		lines := []string{
			`{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET","endpoint":"https://example.com/api/a"},"response":{"status_code":200}}`,
			`{"timestamp":"2026-01-01T00:00:01Z","request":{"method":"GET","endpoint":"https://www.example.com/api/b"},"response":{"status_code":200}}`,
			`{"timestamp":"2026-01-01T00:00:02Z","request":{"method":"POST","endpoint":"https://evil.com/out"},"response":{"status_code":200}}`,
		}
		return discovery.RunResult{Stdout: []byte(strings.Join(lines, "\n") + "\n")}, nil
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 2, Cache: mem})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if res.FailedHosts != 0 {
		t.Fatalf("FailedHosts = %d, want 0 (nested-shape lines are usable output, not malformed)", res.FailedHosts)
	}
	if len(res.URLs) != 2 {
		t.Fatalf("URLs = %d (%v), want 2 in-domain nested endpoints", len(res.URLs), res.URLs)
	}
	var got []string
	for _, u := range res.URLs {
		got = append(got, u.String())
	}
	sort.Strings(got)
	want := []string{"https://example.com/api/a", "https://www.example.com/api/b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("urls = %v, want %v", got, want)
	}
}

// recordingCache is a hermetic in-memory Cache mirroring production lookup
// semantics: Get serves only StatusCompleted records as hits.
type recordingCache struct {
	mu   sync.Mutex
	recs map[cache.Key]cache.Record
	gets int
}

func newRecordingCache() *recordingCache {
	return &recordingCache{recs: make(map[cache.Key]cache.Record)}
}

func (c *recordingCache) Get(_ context.Context, key cache.Key) cache.Outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	rec, ok := c.recs[key]
	if !ok || rec.Status != cache.StatusCompleted {
		return cache.Outcome{State: cache.StateMiss}
	}
	r := rec
	return cache.Outcome{State: cache.StateHit, Record: &r}
}

func (c *recordingCache) Put(_ context.Context, key cache.Key, rec cache.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs[key] = rec
	return nil
}

func (c *recordingCache) Delete(_ context.Context, key cache.Key) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.recs, key)
	return nil
}

func (c *recordingCache) Clear(context.Context) error { return nil }

func (c *recordingCache) snapshot() (map[cache.Key]cache.Record, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[cache.Key]cache.Record, len(c.recs))
	for k, v := range c.recs {
		out[k] = v
	}
	return out, c.gets
}

// TestCrawlCacheKeyCoversTimeoutConcurrencyRateLimit pins §11 coverage:
// two effective configs differing only in one result-shaping bound must
// produce different keys (audit M-3/NEW-76/NEW-66).
func TestCrawlCacheKeyCoversTimeoutConcurrencyRateLimit(t *testing.T) {
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	base := effectiveConfig(Config{Depth: 2})
	k0, err := crawlCacheKey(domain, hosts, base, "v1")
	if err != nil {
		t.Fatalf("crawlCacheKey base: %v", err)
	}
	cases := map[string]func(*Config){
		"rate_limit":  func(c *Config) { c.RateLimit++ },
		"timeout":     func(c *Config) { c.Timeout += time.Second },
		"concurrency": func(c *Config) { c.Concurrency++ },
		"depth":       func(c *Config) { c.Depth++ },
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		k1, err := crawlCacheKey(domain, hosts, cfg, "v1")
		if err != nil {
			t.Fatalf("crawlCacheKey %s: %v", name, err)
		}
		if k1 == k0 {
			t.Errorf("key unchanged after mutating %s: keys must differ", name)
		}
	}
	// Normalization stability: the same effective config yields the same key.
	k2, err := crawlCacheKey(domain, hosts, effectiveConfig(Config{Depth: 2}), "v1")
	if err != nil {
		t.Fatalf("crawlCacheKey repeat: %v", err)
	}
	if k2 != k0 {
		t.Errorf("same effective config produced different keys")
	}
}

// katanaScript builds a fake runner script that answers the version probe
// and dispatches crawl invocations to fn.
func katanaScript(version string, fn func(cmd discovery.Cmd) (discovery.RunResult, error)) map[string]func(discovery.Cmd) (discovery.RunResult, error) {
	return map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"katana": func(cmd discovery.Cmd) (discovery.RunResult, error) {
			if len(cmd.Args) > 0 && cmd.Args[0] == "-version" {
				return discovery.RunResult{Stdout: []byte(version + "\n")}, nil
			}
			if fn == nil {
				return discovery.RunResult{}, nil
			}
			return fn(cmd)
		},
	}
}

// goodOutput is one valid JSONL endpoint record for example.com.
func goodOutput(endpoint string) []byte {
	b, _ := json.Marshal(katanaRecord{Endpoint: endpoint})
	return append(b, '\n')
}

// TestKatanaAllFailStoresIncompleteAndReexecutes pins NEW-62/H-1: a run in
// which every host invocation fails stores no completed record; the next run
// with the same cache re-executes instead of replaying a poisoned hit.
func TestKatanaAllFailStoresIncompleteAndReexecutes(t *testing.T) {
	var mu sync.Mutex
	crawlCalls := 0
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		mu.Lock()
		crawlCalls++
		mu.Unlock()
		return discovery.RunResult{}, fmt.Errorf("dial tcp: connection refused")
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	cfg := Config{Depth: 2, Cache: mem}
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")}

	res1, err := src.Crawl(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("first Crawl: %v", err)
	}
	if res1.FailedHosts != 2 {
		t.Fatalf("FailedHosts = %d, want 2", res1.FailedHosts)
	}
	if len(res1.URLs) != 0 {
		t.Fatalf("URLs = %d, want 0 from all-fail run", len(res1.URLs))
	}
	recs, _ := mem.snapshot()
	if len(recs) != 1 {
		t.Fatalf("stored %d records, want 1", len(recs))
	}
	for key, rec := range recs {
		if rec.Status == cache.StatusCompleted {
			t.Fatalf("all-fail run stored a completed record under %s", key)
		}
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("stored status = %q, want incomplete", rec.Status)
		}
	}

	// Second run with the same cache must re-execute every host.
	res2, err := src.Crawl(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("second Crawl: %v", err)
	}
	if res2.FailedHosts != 2 {
		t.Fatalf("second run FailedHosts = %d, want 2", res2.FailedHosts)
	}
	mu.Lock()
	got := crawlCalls
	mu.Unlock()
	if got != 4 {
		t.Fatalf("runner crawl calls = %d, want 4 (2 per run: re-executed, not replayed)", got)
	}
}

// TestKatanaPartialFailureStoresIncomplete pins the mixed case: URLs from
// healthy hosts are retained but the partial corpus never stores completed.
func TestKatanaPartialFailureStoresIncomplete(t *testing.T) {
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		for i, a := range cmd.Args {
			if a == "-u" && i+1 < len(cmd.Args) && cmd.Args[i+1] == "https://bad.example.com" {
				return discovery.RunResult{}, fmt.Errorf("killed by signal")
			}
		}
		return discovery.RunResult{Stdout: goodOutput("https://example.com/ok")}, nil
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "good.example.com"), mustHost(t, "bad.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 2, Cache: mem})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if res.FailedHosts != 1 {
		t.Fatalf("FailedHosts = %d, want 1", res.FailedHosts)
	}
	if len(res.URLs) != 1 || res.URLs[0].String() != "https://example.com/ok" {
		t.Fatalf("URLs = %v, want the healthy host's endpoint kept", res.URLs)
	}
	recs, _ := mem.snapshot()
	for _, rec := range recs {
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("partial-run status = %q, want incomplete", rec.Status)
		}
	}
}

// TestKatanaCancellationPreservesEngineError pins the LOW wave item: when ctx
// cancels mid-run the engine's per-host error detail survives both on the
// returned error and in Diagnostics, and nothing is stored as completed.
func TestKatanaCancellationPreservesEngineErrorAndDiagnostics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		cancel()
		return discovery.RunResult{}, fmt.Errorf("engine exploded: %w", context.Canceled)
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com"), mustHost(t, "alt.example.com")}
	res, err := src.Crawl(ctx, domain, hosts, Config{Depth: 2, Cache: mem})
	if err == nil {
		t.Fatal("cancelled run returned nil error, want cancellation surfaced")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want errors.Is(err, context.Canceled)", err)
	}
	if !strings.Contains(err.Error(), "engine exploded") {
		t.Fatalf("err = %v, want engine detail preserved via join", err)
	}
	found := false
	for _, d := range res.Diagnostics {
		if strings.Contains(d, "engine exploded") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Diagnostics = %v, want engine error detail preserved", res.Diagnostics)
	}
	recs, _ := mem.snapshot()
	if len(recs) != 0 {
		t.Fatalf("cancelled run stored %d records, want none", len(recs))
	}
}

// TestKatanaAllMalformedOutputStoresIncompleteAndReexecutes pins NEW-86:
// hosts that exit cleanly but emit only malformed JSONL have a broken
// output channel — they count toward FailedHosts, so an all-such-hosts run
// stores StatusIncomplete (never a poisoned completed-empty corpus) and the
// next run with the same cache re-executes.
func TestKatanaAllMalformedOutputStoresIncompleteAndReexecutes(t *testing.T) {
	var mu sync.Mutex
	crawlCalls := 0
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		mu.Lock()
		crawlCalls++
		mu.Unlock()
		// Exit 0; every emitted line is unparseable JSONL.
		return discovery.RunResult{Stdout: []byte("not json at all\n{\"broken\": \n")}, nil
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")}
	cfg := Config{Depth: 2, Cache: mem}

	res1, err := src.Crawl(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("first Crawl: %v", err)
	}
	if res1.FailedHosts != 2 {
		t.Fatalf("FailedHosts = %d, want 2 (all-malformed output is host failure)", res1.FailedHosts)
	}
	if len(res1.URLs) != 0 {
		t.Fatalf("URLs = %d, want 0 from all-malformed run", len(res1.URLs))
	}
	recs, _ := mem.snapshot()
	if len(recs) != 1 {
		t.Fatalf("stored %d records, want 1", len(recs))
	}
	for key, rec := range recs {
		if rec.Status == cache.StatusCompleted {
			t.Fatalf("all-malformed run stored a completed record under %s", key)
		}
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("stored status = %q, want incomplete", rec.Status)
		}
	}

	// Second run with the same cache must re-execute every host: an
	// incomplete record is never served as a hit.
	res2, err := src.Crawl(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("second Crawl: %v", err)
	}
	if res2.FailedHosts != 2 {
		t.Fatalf("second run FailedHosts = %d, want 2", res2.FailedHosts)
	}
	mu.Lock()
	got := crawlCalls
	mu.Unlock()
	if got != 4 {
		t.Fatalf("runner crawl calls = %d, want 4 (2 per run: re-executed, not replayed)", got)
	}
}

// TestKatanaMixedHealthyAndMalformedHostsStoresIncomplete pins the per-host
// classification of the NEW-86 semantic: only the garbage-output host fails;
// the healthy host's URLs are retained and the mixed corpus stores
// incomplete.
func TestKatanaMixedHealthyAndMalformedHostsStoresIncomplete(t *testing.T) {
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		for i, a := range cmd.Args {
			if a == "-u" && i+1 < len(cmd.Args) && cmd.Args[i+1] == "https://garbled.example.com" {
				return discovery.RunResult{Stdout: []byte("garbage line\n")}, nil // exit 0, all malformed
			}
		}
		return discovery.RunResult{Stdout: goodOutput("https://good.example.com/ok")}, nil
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "good.example.com"), mustHost(t, "garbled.example.com")}
	res, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 2, Cache: mem})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if res.FailedHosts != 1 {
		t.Fatalf("FailedHosts = %d, want 1 (only the garbled host failed)", res.FailedHosts)
	}
	if len(res.URLs) != 1 || res.URLs[0].String() != "https://good.example.com/ok" {
		t.Fatalf("URLs = %v, want the healthy host's endpoint kept", res.URLs)
	}
	recs, _ := mem.snapshot()
	if len(recs) != 1 {
		t.Fatalf("stored %d records, want 1", len(recs))
	}
	for _, rec := range recs {
		if rec.Status != cache.StatusIncomplete {
			t.Fatalf("mixed-run status = %q, want incomplete", rec.Status)
		}
	}
}

// TestKatanaMismatchedEnvelopeSelfHeals pins the self-healing boundary for
// tampered cache envelopes: a completed record stored under this key but
// carrying a different Operation or Target must be deleted and re-executed,
// never served (mirrors httpprobe lookupProbe envelope check).
func TestKatanaMismatchedEnvelopeSelfHeals(t *testing.T) {
	var mu sync.Mutex
	crawlCalls := 0
	script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
		mu.Lock()
		crawlCalls++
		mu.Unlock()
		return discovery.RunResult{Stdout: goodOutput("https://example.com/ok")}, nil
	})
	src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
	mem := newRecordingCache()
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	cfg := Config{Depth: 2, Cache: mem}

	if _, err := src.Crawl(context.Background(), domain, hosts, cfg); err != nil {
		t.Fatalf("seed Crawl: %v", err)
	}
	mu.Lock()
	if crawlCalls != 1 {
		mu.Unlock()
		t.Fatalf("seed crawl calls = %d, want 1", crawlCalls)
	}
	mu.Unlock()
	recs, _ := mem.snapshot()
	for k, rec := range recs {
		rec.Operation = "tampered.operation"
		rec.Target = "domain:evil.example"
		mem.mu.Lock()
		mem.recs[k] = rec
		mem.mu.Unlock()
	}
	if _, err := src.Crawl(context.Background(), domain, hosts, cfg); err != nil {
		t.Fatalf("re-run after envelope tamper: %v", err)
	}
	mu.Lock()
	got := crawlCalls
	mu.Unlock()
	if got != 2 {
		t.Fatalf("runner crawl calls = %d, want 2 (tampered envelope must re-execute, never serve)", got)
	}
}

// TestKatanaEmptyAndOutOfDomainOnlyStayCompleted guards the NEW-86
// semantic's other edge: a completed-empty cache store stays reachable when
// every host truly produced zero output AND zero malformed lines — katana
// ran cleanly and genuinely found nothing in scope. Such records replay as
// hits on the next run.
func TestKatanaEmptyAndOutOfDomainOnlyStayCompleted(t *testing.T) {
	t.Run("empty stdout replays from cache", func(t *testing.T) {
		var mu sync.Mutex
		crawlCalls := 0
		script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
			mu.Lock()
			crawlCalls++
			mu.Unlock()
			return discovery.RunResult{}, nil // exit 0, zero bytes out
		})
		src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
		mem := newRecordingCache()
		domain := mustDomain(t, "example.com")
		hosts := []asset.Host{mustHost(t, "www.example.com")}
		cfg := Config{Depth: 2, Cache: mem}
		res, err := src.Crawl(context.Background(), domain, hosts, cfg)
		if err != nil {
			t.Fatalf("Crawl: %v", err)
		}
		if res.FailedHosts != 0 {
			t.Fatalf("FailedHosts = %d, want 0 for a clean empty run", res.FailedHosts)
		}
		recs, _ := mem.snapshot()
		if len(recs) != 1 {
			t.Fatalf("stored %d records, want 1", len(recs))
		}
		for _, rec := range recs {
			if rec.Status != cache.StatusCompleted {
				t.Fatalf("clean-empty status = %q, want completed", rec.Status)
			}
		}
		// Second run replays the completed record without re-executing.
		res2, err := src.Crawl(context.Background(), domain, hosts, cfg)
		if err != nil {
			t.Fatalf("second Crawl: %v", err)
		}
		if len(res2.URLs) != 0 {
			t.Fatalf("second run URLs = %d, want 0", len(res2.URLs))
		}
		mu.Lock()
		got := crawlCalls
		mu.Unlock()
		if got != 1 {
			t.Fatalf("runner crawl calls = %d, want 1 (second run replayed the completed hit)", got)
		}
	})
	t.Run("out-of-domain-only output is not failure", func(t *testing.T) {
		script := katanaScript("v1.0.0", func(cmd discovery.Cmd) (discovery.RunResult, error) {
			// Valid JSONL, but every endpoint is out of scope — dropped by
			// the scope filter, not counted as malformed.
			return discovery.RunResult{Stdout: goodOutput("https://evil.com/out")}, nil
		})
		src := NewKatanaSource(newFakeRunner(script), fakeLookupOK)
		mem := newRecordingCache()
		domain := mustDomain(t, "example.com")
		hosts := []asset.Host{mustHost(t, "www.example.com")}
		res, err := src.Crawl(context.Background(), domain, hosts, Config{Depth: 2, Cache: mem})
		if err != nil {
			t.Fatalf("Crawl: %v", err)
		}
		if res.FailedHosts != 0 {
			t.Fatalf("FailedHosts = %d, want 0 (scope drops are not malformed lines)", res.FailedHosts)
		}
		recs, _ := mem.snapshot()
		for _, rec := range recs {
			if rec.Status != cache.StatusCompleted {
				t.Fatalf("out-of-domain-only status = %q, want completed", rec.Status)
			}
		}
	})
}
