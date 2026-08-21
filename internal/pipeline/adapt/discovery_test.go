package adapt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// discoveryFixedTime is the deterministic instant the fake clock reports. The
// adapter's clock bridge (Now = in.Clock.Now) must surface exactly this as
// every discovered host's provenance timestamp.
var discoveryFixedTime = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func init() {
	if os.Getenv("PDCP_API_KEY") == "" {
		_ = os.Setenv("PDCP_API_KEY", "testkey")
	}
}

// fakeClock is a deterministic runtime.Clock. Now returns the fixed
// instant; After returns a channel that never fires — the discovery adapter
// only reads Now (provenance timestamps), and nothing in the adapter or the
// discovery engine's pool waits on the injected clock.
type fakeClock struct{}

func (fakeClock) Now() time.Time { return discoveryFixedTime }

func (fakeClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }

var _ runtime.Clock = fakeClock{}

// fakeLookup resolves every tool name to itself, as if found on PATH.
func fakeLookup(name string) (string, error) { return name, nil }

// fakeCall records one discovery.Runner.Run invocation.
type fakeCall struct {
	cmd    discovery.Cmd
	limits discovery.Limits
}

// fakeRunner is a scripted discovery.Runner. Script entries are keyed by
// "path " + strings.Join(args, " "); an invocation with no script entry
// fails. It records every invocation so tests can assert which tools ran.
// Like the production ExecRunner, it returns the context error promptly
// when ctx is done.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []fakeCall
	script map[string]func(discovery.Cmd) (discovery.RunResult, error)

	// barrier, when non-nil, makes Run gate each discovery EXECUTION after
	// recording the call and before running its script: the invocation
	// blocks until arm(total) executions have arrived, then proceeds. Nil
	// (the default) is a no-op — every other test is unaffected. Detections
	// ("-version"/"-h") never gate.
	barrier *runnerBarrier
}

func newFakeRunner(script map[string]func(discovery.Cmd) (discovery.RunResult, error)) *fakeRunner {
	return &fakeRunner{script: script}
}

// isDiscoveryExecution classifies invocations the same way the engine's
// detection probes do: exactly the "-version"/"-h" argv forms are
// detections; every other invocation is a discovery execution. The runner
// barrier must gate only executions — detections run sequentially up front
// and must never block.
func isDiscoveryExecution(cmd discovery.Cmd) bool {
	return len(cmd.Args) > 0 && cmd.Args[0] != "-version" && cmd.Args[0] != "-h"
}

// runnerBarrier is a channel gate a fakeRunner can hold. arm(total)
// starts a fresh phase; wait blocks a gated invocation until total gated
// invocations have arrived, then passes. The fakeRunner records the call
// BEFORE wait, so when the gate opens every gated invocation is already
// inside Run — the overlap is structural, never by scheduler luck (a
// pre-entry wrapper cannot do this: the last arriver closes the gate and
// races ahead, and the woken goroutines sit on its P's runqueue until a
// lazy steal, so the closer's instant run completes first). Unarmed
// (total 0) wait passes through; arm(total) must not exceed the pool's
// worker count (a smaller pool would wait forever for arrivals that stay
// queued). The gate is a channel, never a sleep.
type runnerBarrier struct {
	mu      sync.Mutex
	total   int
	arrived int
	gate    chan struct{}
}

func (b *runnerBarrier) arm(total int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total = total
	b.arrived = 0
	b.gate = make(chan struct{})
}

// wait blocks until every gated invocation has arrived, or returns
// ctx.Err() when the caller's context fires first. Ungated invocations
// and unarmed barriers pass through.
func (b *runnerBarrier) wait(ctx context.Context, gated bool) error {
	if !gated {
		return nil
	}
	b.mu.Lock()
	if b.total <= 0 {
		b.mu.Unlock()
		return nil
	}
	b.arrived++
	if b.arrived == b.total {
		close(b.gate)
	}
	gate := b.gate
	b.mu.Unlock()
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// armBarrier starts a fresh barrier phase on f: the next total gated
// (non-detection) invocations all block inside Run until every one has
// arrived. Runners never armed keep a nil barrier and behave exactly as
// before.
func (f *fakeRunner) armBarrier(total int) {
	if f.barrier == nil {
		f.barrier = &runnerBarrier{}
	}
	f.barrier.arm(total)
}

// Run implements discovery.Runner.
func (f *fakeRunner) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	if ctx == nil {
		return discovery.RunResult{}, errors.New("fake runner: nil context")
	}
	if err := ctx.Err(); err != nil {
		return discovery.RunResult{}, err
	}
	key := cmd.Path + " " + strings.Join(cmd.Args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{cmd: cmd, limits: limits})
	f.mu.Unlock()
	if f.barrier != nil {
		if err := f.barrier.wait(ctx, isDiscoveryExecution(cmd)); err != nil {
			return discovery.RunResult{}, err
		}
	}
	fn, ok := f.script[key]
	if !ok {
		return discovery.RunResult{}, fmt.Errorf("fake runner: no script entry for %q", key)
	}
	return fn(cmd)
}

// called reports whether the runner was invoked with the given argv key
// ("path arg1 arg2 ...").
func (f *fakeRunner) called(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.cmd.Path+" "+strings.Join(c.cmd.Args, " ") == key {
			return true
		}
	}
	return false
}

// fakeCache is a hermetic in-memory cache.Cache that always misses and
// counts Put calls, proving the engine received the pipeline's cache
// instance.
type fakeCache struct {
	mu   sync.Mutex
	puts int
}

func (f *fakeCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	return cache.Outcome{State: cache.StateMiss}
}

func (f *fakeCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	return nil
}

func (f *fakeCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (f *fakeCache) Clear(ctx context.Context) error                 { return nil }

func (f *fakeCache) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

// standardScript returns canned responses for the four built-in tools'
// detection and discovery invocations against example.com, exactly matching
// the documented passive argv (subfinder -d <domain> -silent, assetfinder
// <domain>, amass enum -passive -d <domain>, chaos -d <domain> -silent -json).
func standardScript() map[string]func(discovery.Cmd) (discovery.RunResult, error) {
	return map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"subfinder -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("Current Version: v2.6.3\n")}, nil
		},
		"assetfinder -h": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stderr: []byte("Usage: assetfinder [domain]\n"), ExitCode: 2}, nil
		},
		"amass -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("v3.23.0\n")}, nil
		},
		"chaos -version": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("chaos v0.5.3\n")}, nil
		},
		"subfinder -d example.com -silent": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
		},
		"assetfinder example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("example.com\nwww.example.com\n")}, nil
		},
		"amass enum -passive -d example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("mail.example.com\n")}, nil
		},
		"chaos -d example.com -silent -json": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("{\"domain\":\"chaos.example.com\"}\n")}, nil
		},
	}
}

// newInput builds the minimal StageInput the adapter needs: a canonical
// target, default-resolved bounds (as the pipeline runner supplies them),
// an optional params map, and the fixed fake clock. Cache is nil unless a
// test sets it.
func newInput(t *testing.T, params map[string]string) pipeline.StageInput {
	t.Helper()
	return pipeline.StageInput{
		Target: discoveryMustDomain(t, "example.com"),
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  fakeClock{},
	}
}

func discoveryMustDomain(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("asset.NewDomain(%q): %v", name, err)
	}
	return d
}

func discoveryHostNames(hosts []asset.Host) []string {
	out := make([]string, len(hosts))
	for i, h := range hosts {
		out[i] = h.Name
	}
	return out
}

func TestDiscoveryStageName(t *testing.T) {
	// Nil hooks are the production default; Name must not touch them.
	stage := NewDiscoveryStage(nil, nil)
	if stage == nil {
		t.Fatal("NewDiscoveryStage(nil, nil) returned nil")
	}
	if stage.Name() != pipeline.StageDiscover {
		t.Fatalf("Name() = %q, want %q", stage.Name(), pipeline.StageDiscover)
	}
}

func TestDiscoveryStageHappyPath(t *testing.T) {
	runner := newFakeRunner(standardScript())
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false")
	}
	if len(res.StickyFlags) != 0 {
		t.Errorf("StickyFlags = %v, want empty", res.StickyFlags)
	}
	// 2 (subfinder) + 2 (assetfinder) + 1 (amass) + 1 (chaos) hosts; no malformed lines.
	if res.ItemsProcessed != 6 {
		t.Errorf("ItemsProcessed = %d, want 6", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	// report.All() merges by identity (www.example.com seen twice) and sorts
	// by canonical name; the bare target host is in-domain and retained.
	want := []string{"api.example.com", "chaos.example.com", "example.com", "mail.example.com", "www.example.com"}
	if got := discoveryHostNames(res.Additions.Hosts); !reflect.DeepEqual(got, want) {
		t.Errorf("Additions.Hosts = %v, want %v", got, want)
	}
	if len(res.Additions.Domains) != 0 || len(res.Additions.URLs) != 0 {
		t.Errorf("Additions.Domains/URLs = %d/%d, want empty (discovery reports hosts only)",
			len(res.Additions.Domains), len(res.Additions.URLs))
	}
	// Clock bridge: every host's provenance timestamp must be the injected
	// clock's Now, never the wall clock.
	for _, h := range res.Additions.Hosts {
		if !h.Prov.DiscoveredAt.Equal(discoveryFixedTime) {
			t.Errorf("host %s provenance DiscoveredAt = %v, want %v (clock bridge)", h.Name, h.Prov.DiscoveredAt, discoveryFixedTime)
		}
	}
}

func TestDiscoveryStageOutOfDomainFiltered(t *testing.T) {
	script := standardScript()
	script["amass enum -passive -d example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		// amass output includes out-of-domain hosts (noise lines, a
		// cross-domain record): the adapter must filter them at the boundary
		// before they can reach the shared corpus.
		return discovery.RunResult{Stdout: []byte("mail.example.com\nevil.com\nwww.example.org\n")}, nil
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
	for _, h := range res.Additions.Hosts {
		if !pipeline.InDomain(discoveryMustDomain(t, "example.com"), h) {
			t.Errorf("out-of-domain host leaked into Additions: %q", h.Name)
		}
	}
	want := []string{"api.example.com", "chaos.example.com", "example.com", "mail.example.com", "www.example.com"}
	if got := discoveryHostNames(res.Additions.Hosts); !reflect.DeepEqual(got, want) {
		t.Errorf("Additions.Hosts = %v, want %v", got, want)
	}
	// evil.com / www.example.org are valid hosts that merely fall outside the
	// declared scope — the filter is a scope filter, not a parser, so no
	// malformed count is attributed to them.
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	// ItemsProcessed stays the engine report's honest count (before the
	// boundary filter): 2 + 2 + 3 + 1 (chaos).
	if res.ItemsProcessed != 8 {
		t.Errorf("ItemsProcessed = %d, want 8 (the engine report's honest count)", res.ItemsProcessed)
	}
}

func TestDiscoveryStageSourcesParam(t *testing.T) {
	base := standardScript()

	tests := []struct {
		name   string
		params map[string]string
		want   []string // discovery argv keys the runner must have seen
		not    []string // discovery argv keys the runner must NOT have seen
	}{
		{
			name:   "absent param defaults to all built-in sources",
			params: nil,
			want:   []string{"subfinder -d example.com -silent", "assetfinder example.com", "amass enum -passive -d example.com", "chaos -d example.com -silent -json"},
		},
		{
			name:   "empty value defaults to all built-in sources",
			params: map[string]string{"sources": ""},
			want:   []string{"subfinder -d example.com -silent", "assetfinder example.com", "amass enum -passive -d example.com", "chaos -d example.com -silent -json"},
		},
		{
			name:   "comma-only value defaults to all built-in sources",
			params: map[string]string{"sources": ","},
			want:   []string{"subfinder -d example.com -silent", "assetfinder example.com", "amass enum -passive -d example.com", "chaos -d example.com -silent -json"},
		},
		{
			name:   "selection restricts the run",
			params: map[string]string{"sources": "subfinder,amass"},
			want:   []string{"subfinder -d example.com -silent", "amass enum -passive -d example.com"},
			not:    []string{"assetfinder example.com"},
		},
		{
			name:   "whitespace around names is trimmed",
			params: map[string]string{"sources": " subfinder , amass "},
			want:   []string{"subfinder -d example.com -silent", "amass enum -passive -d example.com"},
			not:    []string{"assetfinder example.com"},
		},
		{
			name:   "unknown params are ignored",
			params: map[string]string{"sources": "subfinder", "nonsense": "x", "": ""},
			want:   []string{"subfinder -d example.com -silent"},
			not:    []string{"assetfinder example.com", "amass enum -passive -d example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := newFakeRunner(base)
			stage := NewDiscoveryStage(runner, fakeLookup)
			res, err := stage.Run(context.Background(), newInput(t, tt.params))
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}
			if res.Outcome != pipeline.OutcomeCompleted {
				t.Errorf("Outcome = %q, want completed", res.Outcome)
			}
			for _, key := range tt.want {
				if !runner.called(key) {
					t.Errorf("runner was not invoked for %q", key)
				}
			}
			for _, key := range tt.not {
				if runner.called(key) {
					t.Errorf("runner was invoked for %q, want not", key)
				}
			}
		})
	}
}

func TestDiscoveryStageTruncationFlag(t *testing.T) {
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		// stdout hits the capture cap: the engine's documented truncation
		// marker (StdoutTruncated) becomes SourceResult.Truncated and the
		// source is classified OutPartial. The adapter must never swallow it.
		return discovery.RunResult{Stdout: []byte("api.example.com\n"), StdoutTruncated: true}, nil
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Errorf("Outcome = %q, want partial", res.Outcome)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true (truncation flags are never swallowed)")
	}
	if !res.StickyFlags[discoveryTruncatedFlag] {
		t.Errorf("StickyFlags = %v, want %q set", res.StickyFlags, discoveryTruncatedFlag)
	}
	// LOW-3 review finding: pin the literal flag name so a rename cannot
	// drift the constant away from the documented convention
	// (<engine>_<what>_truncated — never a bare generic).
	if !res.StickyFlags["discovery_truncated"] {
		t.Errorf("StickyFlags = %v, want the literal %q set", res.StickyFlags, "discovery_truncated")
	}
	// The truncated source's hosts are still honest retained output.
	want := []string{"api.example.com", "chaos.example.com", "example.com", "mail.example.com", "www.example.com"}
	if got := discoveryHostNames(res.Additions.Hosts); !reflect.DeepEqual(got, want) {
		t.Errorf("Additions.Hosts = %v, want %v", got, want)
	}
}

func TestDiscoveryStagePartialWithoutTruncation(t *testing.T) {
	script := standardScript()
	// Non-zero exit with usable output: partial per the engine, but no
	// capture-cap truncation marker (the engine's Truncated field stays
	// false) — the adapter must not invent a truncation flag.
	script["assetfinder example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{Stdout: []byte("www.example.com\n"), ExitCode: 1}, nil
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Errorf("Outcome = %q, want partial", res.Outcome)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false (a partial non-zero exit is not a capture-cap truncation)")
	}
	if len(res.StickyFlags) != 0 {
		t.Errorf("StickyFlags = %v, want empty", res.StickyFlags)
	}
}

func TestDiscoveryStageEngineError(t *testing.T) {
	// A discovery.Run-level error (not a per-source status): the sources
	// param names an unknown tool, which resolveSourceNames rejects before
	// anything executes.
	runner := newFakeRunner(standardScript())
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, map[string]string{"sources": "bogus"}))
	if err == nil {
		t.Fatal("Run returned nil error, want the wrapped engine error")
	}
	if !strings.Contains(err.Error(), "stage discover") {
		t.Errorf("error = %q, want the stage-context wrapper", err)
	}
	if !strings.Contains(err.Error(), "unknown source") {
		t.Errorf("error = %q, want the engine's own error text preserved", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Errorf("Outcome = %q, want failed", res.Outcome)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "stage discover") {
		t.Errorf("res.Err = %v, want the wrapped engine error", res.Err)
	}
	// Run must not panic on engine errors and must not fabricate items.
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counts = %d/%d, want 0/0 (nothing ran)", res.ItemsProcessed, res.ItemsFailed)
	}
}

func TestDiscoveryStagePerSourceFailure(t *testing.T) {
	// One source fails with no usable output (OutFailed); the others
	// complete. The stage folds with the pipeline's own precedence: failed +
	// completed = partial, never completed and never failed.
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{}, errors.New("tool exploded")
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Errorf("Outcome = %q, want partial (failed source among completed ones)", res.Outcome)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty (no capture-cap truncation)",
			res.Truncated, res.StickyFlags)
	}
}

func TestDiscoveryStageSkippedSources(t *testing.T) {
	// A tool MISSING at detection is skipped, never failed. The pipeline has
	// no "skipped" value, so the adapter maps it to the honesty value
	// incomplete: the retained set lacks the skipped source's contribution
	// and claiming completed would hide that it never ran.
	t.Run("all sources skipped", func(t *testing.T) {
		lookup := func(name string) (string, error) {
			return "", errors.New("not found: " + name)
		}
		runner := newFakeRunner(standardScript())
		stage := NewDiscoveryStage(runner, lookup)

		res, err := stage.Run(context.Background(), newInput(t, nil))
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeIncomplete {
			t.Errorf("Outcome = %q, want incomplete", res.Outcome)
		}
		if len(res.Additions.Hosts) != 0 {
			t.Errorf("Additions.Hosts = %v, want none (no source ran)", discoveryHostNames(res.Additions.Hosts))
		}
	})

	t.Run("one skipped among completed", func(t *testing.T) {
		lookup := func(name string) (string, error) {
			if name == "amass" {
				return "", errors.New("not found: amass")
			}
			return name, nil
		}
		runner := newFakeRunner(standardScript())
		stage := NewDiscoveryStage(runner, lookup)

		res, err := stage.Run(context.Background(), newInput(t, nil))
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeIncomplete {
			t.Errorf("Outcome = %q, want incomplete (a skipped source makes the retained set incomplete)", res.Outcome)
		}
		// The completed sources' hosts are still honest retained output.
		if len(res.Additions.Hosts) == 0 {
			t.Error("no hosts retained from the completed sources")
		}
	})
}

func TestDiscoveryStageCancellationPreCancelled(t *testing.T) {
	runner := newFakeRunner(standardScript())
	stage := NewDiscoveryStage(runner, fakeLookup)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := stage.Run(ctx, newInput(t, nil))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("res.Err = %v, want context.Canceled", res.Err)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counts = %d/%d, want 0/0 (no source ran)", res.ItemsProcessed, res.ItemsFailed)
	}
}

func TestDiscoveryStageCancellationMidRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	script := standardScript()
	jobStarted := make(chan struct{})
	var startedOnce sync.Once
	// The discovery job blocks inside the tool call until the run context
	// fires, exactly like a real tool observing cancellation; the engine
	// classifies the result OutCancelled.
	script["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		startedOnce.Do(func() { close(jobStarted) })
		<-ctx.Done()
		return discovery.RunResult{}, ctx.Err()
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	var res pipeline.StageResult
	var err error
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		res, err = stage.Run(ctx, newInput(t, nil))
	}()
	<-jobStarted
	cancel()
	<-runDone

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("res.Err = %v, want context.Canceled", res.Err)
	}
}

func TestDiscoveryStageAdditionsPreservedOnEngineError(t *testing.T) {
	if testing.Short() {
		t.Skip("17s real-time drain test; run the full suite for coverage")
	}
	// LOW-2 review finding: the discovery engine's ONLY populated-report+
	// error path is a forced pool shutdown (internal/discovery/pipeline.go) —
	// the report carries the honest retained observations of every source
	// that ran, and the adapter must merge them into Additions even on the
	// failed outcome (the runner merges a failed stage's additions).
	//
	// Drain-budget mechanics (internal/discovery/pipeline.go): Shutdown's
	// drain budget is cfg.Timeout + shutdownGrace (15 s) when Timeout > 0.
	// Timeout = 1 s → budget = 16 s. The subfinder job sleeps 17 s (a tool
	// that ignores cancellation; the pool cannot forcibly stop a goroutine),
	// so the drain expires at 16 s, the pool is forced down, and Shutdown
	// blocks until the job actually returns at ~17 s — discovery.Run then
	// returns the populated report alongside the shutdown error. This test
	// therefore takes ~17 s by design; the stage bound of 25 s fails fast on
	// a regression that wedges Run.
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		time.Sleep(17 * time.Second)
		return discovery.RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
	}
	runner := newFakeRunner(script)
	stage := NewDiscoveryStage(runner, fakeLookup)

	in := newInput(t, nil)
	in.Bounds.Timeout = time.Second // drain budget = 1s + 15s grace = 16s

	type outcome struct {
		res pipeline.StageResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := stage.Run(context.Background(), in)
		ch <- outcome{res, err}
	}()
	var o outcome
	select {
	case o = <-ch:
	case <-time.After(25 * time.Second):
		t.Fatal("stage Run did not finish within 25s (the forced shutdown must return)")
	}

	if o.err == nil {
		t.Fatal("Run returned nil error, want the wrapped pool-shutdown error")
	}
	if !strings.Contains(o.err.Error(), "stage discover") {
		t.Errorf("error = %q, want the stage-context wrapper", o.err)
	}
	if !strings.Contains(o.err.Error(), "pool shutdown") {
		t.Errorf("error = %q, want the engine's pool-shutdown detail preserved", o.err)
	}
	if o.res.Outcome != pipeline.OutcomeFailed {
		t.Errorf("Outcome = %q, want failed (engine error, stage context live)", o.res.Outcome)
	}
	// The sources that did run (assetfinder, amass, chaos) and the subfinder result
	// that completed right at the forced shutdown are all honest retained
	// output; the report is merged into Additions even on the failed outcome.
	want := []string{"api.example.com", "chaos.example.com", "example.com", "mail.example.com", "www.example.com"}
	if got := discoveryHostNames(o.res.Additions.Hosts); !reflect.DeepEqual(got, want) {
		t.Errorf("Additions.Hosts = %v, want %v (the engine report's honest retained output)", got, want)
	}
}

func TestDiscoveryStageCachePassThrough(t *testing.T) {
	t.Run("with cache", func(t *testing.T) {
		runner := newFakeRunner(standardScript())
		stage := NewDiscoveryStage(runner, fakeLookup)
		input := newInput(t, nil)
		c := &fakeCache{}
		input.Cache = c

		res, err := stage.Run(context.Background(), input)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("Outcome = %q, want completed", res.Outcome)
		}
		// The engine's cache-before-execute jobs observe the pipeline's cache
		// instance: versioned tools (subfinder, amass, chaos) store records on a
		// miss. assetfinder has no detectable version and is never cached.
		if n := c.putCount(); n != 3 {
			t.Errorf("cache Put count = %d, want 3 (subfinder + amass + chaos; assetfinder is never cached)", n)
		}
	})

	t.Run("nil cache is caching-disabled", func(t *testing.T) {
		runner := newFakeRunner(standardScript())
		stage := NewDiscoveryStage(runner, fakeLookup)

		res, err := stage.Run(context.Background(), newInput(t, nil))
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("Outcome = %q, want completed", res.Outcome)
		}
		if len(res.Additions.Hosts) == 0 {
			t.Error("no hosts discovered without a cache")
		}
	})
}

func TestDiscoveryStageThroughPipelineRun(t *testing.T) {
	// End-to-end through the pipeline runner: the adapter's StageResult must
	// survive normalizeResult (outcome, counts, additions) and merge into the
	// shared corpus deterministically.
	runner := newFakeRunner(standardScript())
	stage := NewDiscoveryStage(runner, fakeLookup)
	cfg := pipeline.ScanConfig{
		Target: discoveryMustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover},
	}

	report, err := pipeline.Run(context.Background(), cfg, nil, fakeClock{}, []pipeline.Stage{stage})
	if err != nil {
		t.Fatalf("pipeline.Run returned error: %v", err)
	}
	if report.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("report.Outcome = %q, want completed", report.Outcome)
	}
	if len(report.Stages) != 1 || report.Stages[0].Outcome != pipeline.OutcomeCompleted {
		t.Errorf("stage records = %+v, want one completed stage", report.Stages)
	}
	if report.ItemsProcessed != 6 || report.ItemsFailed != 0 {
		t.Errorf("report counts = %d/%d, want 6/0", report.ItemsProcessed, report.ItemsFailed)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("report Truncated/StickyFlags = %v/%v, want false/empty",
			report.Truncated, report.StickyFlags)
	}
	want := []string{"api.example.com", "chaos.example.com", "example.com", "mail.example.com", "www.example.com"}
	if got := discoveryHostNames(report.Hosts); !reflect.DeepEqual(got, want) {
		t.Errorf("report.Hosts = %v, want %v", got, want)
	}
}
