package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// fixedTime is the deterministic timestamp used by most fake environments.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// fakeClock is a mutex-guarded mutable clock for deterministic provenance and
// cache TTL tests. It is safe for concurrent use (jobs run on pool workers).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeLookup is a scripted LookupFunc. Names not present in paths or errs
// resolve to themselves (as if found in PATH).
type fakeLookup struct {
	paths map[string]string // name -> resolved path
	errs  map[string]error  // name -> lookup error
}

func (f fakeLookup) LookPath(name string) (string, error) {
	if err, ok := f.errs[name]; ok {
		return "", err
	}
	if p, ok := f.paths[name]; ok {
		return p, nil
	}
	return name, nil
}

func newFakeLookup() fakeLookup {
	return fakeLookup{paths: map[string]string{}, errs: map[string]error{}}
}

// fakeCall records one Runner.Run invocation.
type fakeCall struct {
	cmd    Cmd
	limits Limits
}

// fakeRunner is a scripted Runner for tests. Script entries are keyed by
// "path " + strings.Join(args, " "). It records every call, tracks the
// maximum number of concurrently active runs (for bounded-concurrency
// assertions), and can block selected commands on context cancellation.
type fakeRunner struct {
	mu    sync.Mutex
	t     *testing.T
	calls []fakeCall

	script map[string]func(Cmd) (RunResult, error)

	// blockKeys, when set, makes Run wait for ctx.Done and return ctx.Err()
	// for matching command keys, closing blockStarted (once) on entry.
	blockKeys    map[string]bool
	blockStarted chan struct{}
	blockOnce    sync.Once

	active        int
	maxConcurrent int
}

func newFakeRunner(t *testing.T, script map[string]func(Cmd) (RunResult, error)) *fakeRunner {
	return &fakeRunner{t: t, script: script}
}

func cmdKey(cmd Cmd) string {
	return cmd.Path + " " + strings.Join(cmd.Args, " ")
}

func (f *fakeRunner) Run(ctx context.Context, cmd Cmd, limits Limits) (RunResult, error) {
	if f == nil {
		return RunResult{}, errors.New("fake runner not configured")
	}
	if ctx == nil {
		return RunResult{}, errors.New("fake runner: nil context")
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{cmd: cmd, limits: limits})
	f.active++
	if f.active > f.maxConcurrent {
		f.maxConcurrent = f.active
	}
	key := cmdKey(cmd)
	block := f.blockKeys[key]
	f.mu.Unlock()
	if block {
		f.blockOnce.Do(func() {
			if f.blockStarted != nil {
				close(f.blockStarted)
			}
		})
		<-ctx.Done()
		return RunResult{}, ctx.Err()
	}
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	if fn, ok := f.script[key]; ok {
		return fn(cmd)
	}
	if len(cmd.Args) > 0 && (cmd.Args[0] == "-version" || cmd.Args[0] == "-h") {
		return RunResult{}, fmt.Errorf("fake runner: no script entry for %q", key)
	}
	return RunResult{}, fmt.Errorf("fake runner: no script entry for %q", key)
}

// discoverCallCount returns how many calls were not detection invocations
// (-version / -h), i.e. actual discovery executions.
func (f *fakeRunner) discoverCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if len(c.cmd.Args) == 0 {
			continue
		}
		switch c.cmd.Args[0] {
		case "-version", "-h":
		default:
			n++
		}
	}
	return n
}

func (f *fakeRunner) argCalls(flag string) []Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cmds []Cmd
	for _, c := range f.calls {
		if len(c.cmd.Args) > 0 && c.cmd.Args[0] == flag {
			cmds = append(cmds, c.cmd)
		}
	}
	return cmds
}

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// mustDomain builds a valid target domain for tests.
func mustDomain(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

// standardScript returns canned responses for all three tools against
// example.com, with an assetfinder -h invocation that exits 2 (Go's flag
// package behavior) while printing usage to stderr.
func standardScript() map[string]func(Cmd) (RunResult, error) {
	return map[string]func(Cmd) (RunResult, error){
		"subfinder -version": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("Current Version: v2.6.3\n")}, nil
		},
		"assetfinder -h": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("Usage: assetfinder [domain]\n"), ExitCode: 2}, nil
		},
		"amass -version": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("v3.23.0\n")}, nil
		},
	}
}

// testConfig returns a runnable Config bound to the fakes, with fixed time
// and a modest pool. The scripted fakeLookup is adapted to the LookupFunc
// seam via its method value.
func testConfig(runner Runner, lookup fakeLookup) Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 2
	cfg.QueueSize = 8
	cfg.Runner = runner
	cfg.LookPath = lookup.LookPath
	now := fixedTime
	cfg.Now = func() time.Time { return now }
	return cfg
}

// fakeCache is a hermetic in-memory Cache that always misses and scripts Put
// failures, so tests can exercise the pipeline's cache-write error path
// without the filesystem or a 16 MiB payload.
type fakeCache struct {
	mu     sync.Mutex
	putErr error
	puts   int
}

func (f *fakeCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	return cache.Outcome{State: cache.StateMiss}
}

func (f *fakeCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	return f.putErr
}

func (f *fakeCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (f *fakeCache) Clear(ctx context.Context) error                 { return nil }

func (f *fakeCache) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

// panicSource is a Source whose Detect always panics, used to verify
// detection panic containment (detectSafe).
type panicSource struct{ name string }

func (p panicSource) Name() string { return p.name }

func (p panicSource) Detect(ctx context.Context) Detection { panic("detect: boom") }

func (p panicSource) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	return DiscoverResult{}, nil
}
