package adapt

import (
	"context"
	"os"
	"sync"

	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// runStep is one scripted fake-runner response. When the response queue is
// exhausted, the LAST step repeats (so a version probe plus several
// identical run responses needs only two entries).
type runStep struct {
	out    []byte // captured stdout
	errOut []byte // captured stderr
	code   int    // exit code (runner contract: nil error + code)
	trunc  bool   // StdoutTruncated
	runErr error  // runner error (process never ran to completion)
	block  bool   // wait for ctx.Done, then return ctx.Err()
	panics bool   // panic instead of returning (hostile runner)
}

// fakeRunner is a scripted discovery.Runner. Every Run call consumes the
// next step (the last one repeats). Calls (path + argv) are recorded for
// assertions; whether the caller supplied a context deadline is recorded
// too, so detection-budget tests are deterministic.
type fakeRunner struct {
	mu       sync.Mutex
	steps    []runStep
	cur      int
	calls    []discovery.Cmd
	deadline bool
}

func newFakeRunner(steps ...runStep) *fakeRunner {
	return &fakeRunner{steps: steps}
}

// Run implements discovery.Runner.
func (f *fakeRunner) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	if _, ok := ctx.Deadline(); ok {
		f.deadline = true
	}
	i := f.cur
	if len(f.steps) > 0 && f.cur < len(f.steps)-1 {
		f.cur++
	}
	var step runStep
	if len(f.steps) > 0 {
		step = f.steps[i]
	}
	f.mu.Unlock()

	if step.panics {
		panic("fake runner panic")
	}
	if step.block {
		<-ctx.Done()
		return discovery.RunResult{}, ctx.Err()
	}
	if step.runErr != nil {
		return discovery.RunResult{}, step.runErr
	}
	return discovery.RunResult{
		Stdout:          step.out,
		Stderr:          step.errOut,
		ExitCode:        step.code,
		StdoutTruncated: step.trunc,
	}, nil
}

// callCount returns how many Run calls happened.
func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// argsOf returns the argv of the n-th call (0-based), or nil.
func (f *fakeRunner) argsOf(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n < 0 || n >= len(f.calls) {
		return nil
	}
	return f.calls[n].Args
}

// pathOf returns the executable path of the n-th call (0-based), or "".
func (f *fakeRunner) pathOf(n int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n < 0 || n >= len(f.calls) {
		return ""
	}
	return f.calls[n].Path
}

// sawDeadline reports whether any Run call observed a context deadline.
func (f *fakeRunner) sawDeadline() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline
}

// lookupStep is one scripted fake-lookup response; the last step repeats.
type lookupStep struct {
	path string
	err  error
}

// fakeLookup is a scripted discovery.LookupFunc, keyed by the requested
// name. A name with no script resolves to /fake/bin/<name>.
type fakeLookup struct {
	mu    sync.Mutex
	calls []string
	steps map[string][]lookupStep
	cur   map[string]int
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{steps: make(map[string][]lookupStep), cur: make(map[string]int)}
}

// Add scripts the k-th lookup of name to return path.
func (f *fakeLookup) Add(name, path string) {
	f.steps[name] = append(f.steps[name], lookupStep{path: path})
}

// AddErr scripts the k-th lookup of name to fail.
func (f *fakeLookup) AddErr(name string, err error) {
	f.steps[name] = append(f.steps[name], lookupStep{err: err})
}

// LookPath implements discovery.LookupFunc.
func (f *fakeLookup) LookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	steps := f.steps[name]
	i := f.cur[name]
	if len(steps) > 0 && f.cur[name] < len(steps)-1 {
		f.cur[name]++
	}
	if len(steps) == 0 {
		return "/fake/bin/" + name, nil
	}
	s := steps[i]
	return s.path, s.err
}

// requested returns the names looked up so far.
func (f *fakeLookup) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// asFunc adapts the fake to the discovery.LookupFunc named func type.
func (f *fakeLookup) asFunc() discovery.LookupFunc { return f.LookPath }

// subjsInterceptor is a runner that snapshots the subjs temp file DURING
// the execution call (existence, mode, content) and records the command.
// The temp file only exists while the tool runs, so the snapshot must
// happen inside Run.
type subjsInterceptor struct {
	mu      sync.Mutex
	cmd     discovery.Cmd
	existed bool
	mode    os.FileMode
	content []byte
	runErr  error
}

// Run implements discovery.Runner.
func (s *subjsInterceptor) Run(ctx context.Context, cmd discovery.Cmd, limits discovery.Limits) (discovery.RunResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmd = cmd
	if len(cmd.Args) == 6 && cmd.Args[4] == "-i" {
		fi, err := os.Stat(cmd.Args[5])
		if err == nil {
			s.existed = true
			s.mode = fi.Mode().Perm()
			if b, rerr := os.ReadFile(cmd.Args[5]); rerr == nil {
				s.content = b
			}
		}
	}
	if s.runErr != nil {
		return discovery.RunResult{}, s.runErr
	}
	return discovery.RunResult{Stdout: []byte("https://example.com/app.js\n")}, nil
}
