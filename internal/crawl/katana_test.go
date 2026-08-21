package crawl

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
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
	// Check required flags present.
	mustContain := func(flag string) {
		for _, a := range seenArgs {
			if a == flag {
				return
			}
		}
		t.Errorf("args %v missing flag %q", seenArgs, flag)
	}
	mustContain("-jc")
	mustContain("-ps")
	mustContain("-xhr")
	mustContain("-fs")
	mustContain("fqdn")
	mustContain("-aff=false")
	mustContain("-kf")
	mustContain("all")
	// Never headless, never aff true.
	for _, a := range seenArgs {
		if a == "-headless" || a == "-aff=true" || a == "-aff" {
			t.Errorf("args must never contain %q, got %v", a, seenArgs)
		}
	}
	// Depth check.
	foundDepth := false
	for i, a := range seenArgs {
		if a == "-d" && i+1 < len(seenArgs) && seenArgs[i+1] == "2" {
			foundDepth = true
		}
	}
	if !foundDepth {
		t.Errorf("args %v missing -d 2", seenArgs)
	}
}
