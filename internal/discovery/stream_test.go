package discovery

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// streamCollector is a thread-safe OnHost sink: events arrive on pool worker
// goroutines in arrival order, so collection is mutex-guarded (race-covered).
type streamCollector struct {
	mu     sync.Mutex
	events []HostEvent
}

func (c *streamCollector) onHost(ev HostEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *streamCollector) snapshot() []HostEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]HostEvent(nil), c.events...)
}

func (c *streamCollector) lines() []string {
	evs := c.snapshot()
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Line()
	}
	return out
}

// TestStreamLineFormatPinned pins the single NEW-138 stream line format: one
// JSON object per line with exactly the keys host, source, discovered_at
// (RFC 3339, UTC), status, cached.
func TestStreamLineFormatPinned(t *testing.T) {
	h, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	ev := HostEvent{Source: "subfinder", Host: h, Status: OutCompleted, Cached: false}
	want := `{"host":"api.example.com","source":"subfinder","discovered_at":"2026-08-13T12:00:00Z","status":"completed","cached":false}`
	if got := ev.Line(); got != want {
		t.Fatalf("Line() = %q, want %q", got, want)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(ev.Line()), &decoded); err != nil {
		t.Fatalf("Line() is not valid JSON: %v", err)
	}
	if len(decoded) != 5 {
		t.Fatalf("Line() carries %d keys, want exactly 5 (host, source, discovered_at, status, cached): %q", len(decoded), ev.Line())
	}
	for _, k := range []string{"host", "source", "discovered_at", "status", "cached"} {
		if _, ok := decoded[k]; !ok {
			t.Fatalf("Line() missing key %q: %q", k, ev.Line())
		}
	}
	if strings.Contains(ev.Line(), "\n") {
		t.Fatalf("Line() must be a single line, got %q", ev.Line())
	}
}

// TestStreamEmitsIncrementalLinesAndIdenticalMerge runs the hermetic
// fake-source fixture with a stream collector: every per-source host must
// stream exactly once (incremental lines), and the final merged summary must
// equal the merge the existing determinism tests pin (byte-identical: sorted,
// deduplicated, earliest-provenance-wins).
func TestStreamEmitsIncrementalLinesAndIdenticalMerge(t *testing.T) {
	setChaosKey(t)
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	col := &streamCollector{}
	cfg.OnHost = col.onHost
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	// Incremental lines: 2 (subfinder) + 2 (assetfinder) + 2 (amass) + 1
	// (chaos) = 7 events, one per per-source host.
	evs := col.snapshot()
	if len(evs) != 7 {
		t.Fatalf("streamed events = %d, want 7 (one per per-source host)", len(evs))
	}
	perSource := map[string]int{}
	for _, ev := range evs {
		perSource[ev.Source]++
		if ev.Status != OutCompleted {
			t.Errorf("streamed %s/%s status = %s, want completed", ev.Source, ev.Host.Name, ev.Status)
		}
		if ev.Cached {
			t.Errorf("streamed %s/%s cached = true, want false on a fresh run", ev.Source, ev.Host.Name)
		}
		if ev.Host.Name == "" || ev.Source == "" {
			t.Errorf("streamed event missing host/source attribution: %+v", ev)
		}
		if ev.Host.Prov.DiscoveredAt.IsZero() {
			t.Errorf("streamed %s/%s missing provenance timestamp", ev.Source, ev.Host.Name)
		}
		// Every line must be valid single-line JSON with the pinned keys.
		var decoded map[string]any
		if err := json.Unmarshal([]byte(ev.Line()), &decoded); err != nil {
			t.Errorf("stream line is not valid JSON: %v", err)
		}
	}
	for src, want := range map[string]int{"subfinder": 2, "assetfinder": 2, "amass": 2, "chaos": 1} {
		if perSource[src] != want {
			t.Errorf("streamed %s events = %d, want %d", src, perSource[src], want)
		}
	}

	// Final merged summary unchanged: the exact set the merge tests pin.
	all := rep.All()
	want := []string{"api.example.com", "blog.example.com", "chaos.example.com", "mail.example.com", "www.example.com"}
	if len(all) != len(want) {
		t.Fatalf("merged hosts = %v, want %v", names(all), want)
	}
	for i := range all {
		if all[i].Name != want[i] {
			t.Fatalf("merged[%d] = %q, want %q", i, all[i].Name, want[i])
		}
	}
}

// TestStreamRepeatsDuplicatesWhileMergeDedups pins the NEW-138 dedup policy:
// the stream repeats a host seen by two sources (once per observing source,
// with that source's attribution); the final merge carries it once.
func TestStreamRepeatsDuplicatesWhileMergeDedups(t *testing.T) {
	setChaosKey(t)
	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Concurrency = 1 // deterministic arrival order for the count below
	col := &streamCollector{}
	cfg.OnHost = col.onHost
	rep := mustRun(t, mustDomain(t, "example.com"), cfg)

	// www.example.com is found by both subfinder and assetfinder.
	var streamed []string
	for _, ev := range col.snapshot() {
		if ev.Host.Name == "www.example.com" {
			streamed = append(streamed, ev.Source)
		}
	}
	if len(streamed) != 2 || streamed[0] != "subfinder" || streamed[1] != "assetfinder" {
		t.Fatalf("www.example.com streamed from %v, want [subfinder assetfinder] (repeat, not dedup)", streamed)
	}
	n := 0
	for _, h := range rep.All() {
		if h.Name == "www.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("merged www.example.com count = %d, want 1 (final merge dedups)", n)
	}
}

// TestShuffledArrivalYieldsIdenticalSummaryPinsOrderingContract runs the same
// hermetic fixture under two selection orders at concurrency 1 (where arrival
// order deterministically follows selection order): the merged summary must
// be byte-identical while the stream reflects the arrival order.
func TestShuffledArrivalYieldsIdenticalSummary(t *testing.T) {
	setChaosKey(t)
	run := func(sources []string) (summary string, stream []string) {
		t.Helper()
		r := newFakeRunner(t, fullScript())
		cfg := testConfig(r, newFakeLookup())
		cfg.Concurrency = 1
		cfg.Sources = sources
		col := &streamCollector{}
		cfg.OnHost = col.onHost
		rep := mustRun(t, mustDomain(t, "example.com"), cfg)
		var b strings.Builder
		for _, h := range rep.All() {
			b.WriteString(h.Name + "\n")
		}
		return b.String(), col.lines()
	}

	fwdSummary, fwdStream := run([]string{"subfinder", "assetfinder"})
	revSummary, revStream := run([]string{"assetfinder", "subfinder"})

	if fwdSummary != revSummary {
		t.Fatalf("merged summary differs across arrival orders:\n%s\n---\n%s", fwdSummary, revSummary)
	}
	if len(fwdStream) == 0 || len(revStream) == 0 {
		t.Fatal("expected non-empty streams on both runs")
	}
	// The stream reflects arrival order: the first line's source follows
	// the selection order of its run.
	firstSource := func(lines []string) string {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
			t.Fatalf("stream line is not valid JSON: %v", err)
		}
		src, _ := decoded["source"].(string)
		return src
	}
	if got := firstSource(fwdStream); got != "subfinder" {
		t.Fatalf("forward stream starts with source %q, want subfinder (arrival order)", got)
	}
	if got := firstSource(revStream); got != "assetfinder" {
		t.Fatalf("reversed stream starts with source %q, want assetfinder (arrival order)", got)
	}
}

// TestOnHostFiresForCachedHits verifies cache-served observations stream
// too (the emission point is the job finalization, hit or miss), flagged
// cached.
func TestOnHostFiresForCachedHits(t *testing.T) {
	setChaosKey(t)
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	newCfg := func() Config {
		r := newFakeRunner(t, fullScript())
		cfg := testConfig(r, newFakeLookup())
		cfg.Concurrency = 1
		cfg.Sources = []string{"subfinder"}
		cfg.Cache = c
		return cfg
	}
	target := mustDomain(t, "example.com")
	if _, err := Run(context.Background(), target, newCfg()); err != nil {
		t.Fatalf("prime run: %v", err)
	}
	col := &streamCollector{}
	cfg2 := newCfg()
	cfg2.OnHost = col.onHost
	rep, err := Run(context.Background(), target, cfg2)
	if err != nil {
		t.Fatalf("cached run: %v", err)
	}
	if !rep.Results[0].Cached {
		t.Fatal("second run must be served from cache")
	}
	evs := col.snapshot()
	if len(evs) != 2 {
		t.Fatalf("streamed events on a cache hit = %d, want 2 (hits stream too)", len(evs))
	}
	for _, ev := range evs {
		if !ev.Cached {
			t.Errorf("streamed %s/%s cached = false on a cache hit, want true", ev.Source, ev.Host.Name)
		}
		if !strings.Contains(ev.Line(), `"cached":true`) {
			t.Errorf("stream line missing cached:true: %q", ev.Line())
		}
	}
}
