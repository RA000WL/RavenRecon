package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testTimeout bounds every potentially blocking test below; tests that exceed
// it fail instead of hanging the suite. All fakes are instant, so any
// timeout is a bug, not a scheduling artifact.
const testTimeout = 10 * time.Second

// mustFinish runs fn with a hard test-level bound, so a regression that
// hangs Resolve fails fast instead of wedging the package.
func mustFinish(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("%s did not finish within %s", what, testTimeout)
	}
}

// fakeResolver is a hermetic Resolver: scripted answers and errors per
// (host, record type), a call counter, and an optional auto-cancel hook that
// fires the run's cancel function on the first query — a deterministic
// mid-run cancellation without sleeps.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	calls   int

	// autoCancel, when non-nil, is invoked exactly once on the first query
	// (before the query blocks, when blocking is enabled).
	autoCancel func()
	// block, when true, makes every query wait until its context is done —
	// simulating a resolver that never answers.
	block bool

	// cancelAt, when > 0, makes the query numbered cancelAt (1-based) block
	// like block, invoking cancel while that query is in flight, and every
	// later query too. Blocked queries in this mode return the error shape
	// the production adapter (NetResolver) receives from the stdlib pure-Go
	// resolver when a query is cancelled mid-flight: a *net.DNSError
	// wrapping the context error (UnwrapErr), classified through
	// classifyQueryError exactly as NetResolver.Lookup does.
	cancelAt          int
	cancel            func()
	cancelFlagTimeout bool // stamp IsTimeout|IsTemporary on the shaped error
}

// newFakeResolver returns an empty fake resolver.
func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		answers: make(map[string][]string),
		errs:    make(map[string]error),
	}
}

// set scripts answers for one (host, record type) pair.
func (f *fakeResolver) set(host string, rt RecordType, answers ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host+"\x00"+string(rt)] = answers
}

// setErr scripts a typed error for one (host, record type) pair.
func (f *fakeResolver) setErr(host string, rt RecordType, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[host+"\x00"+string(rt)] = err
}

// setAutoCancel arms the one-shot run-cancellation hook.
func (f *fakeResolver) setAutoCancel(cancel func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.autoCancel = cancel
}

// setBlock makes every subsequent query block until its context is done.
func (f *fakeResolver) setBlock() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = true
}

// setCancelInFlight arms a deterministic mid-flight cancellation: the query
// numbered cancelAt (1-based) blocks, invokes cancel while it is in flight
// (so the cancellation lands inside the query, never between queries), and
// then returns the stdlib-shaped cancellation error described on cancelAt.
// Queries after cancelAt also block and return the same shape (the context
// is already cancelled). When flagTimeout is true the shaped *net.DNSError
// also carries IsTimeout|IsTemporary, mirroring the stdlib surface when the
// in-flight read fails at the per-attempt deadline. The error is classified
// through classifyQueryError — the identical function NetResolver.Lookup
// applies — so the fake surfaces what the production adapter would return.
func (f *fakeResolver) setCancelInFlight(cancelAt int, cancel func(), flagTimeout bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelAt = cancelAt
	f.cancel = cancel
	f.cancelFlagTimeout = flagTimeout
}

// callCount reports the number of queries issued.
func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Lookup implements Resolver.
func (f *fakeResolver) Lookup(ctx context.Context, host string, rt RecordType) ([]string, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	if f.autoCancel != nil {
		cancel := f.autoCancel
		f.autoCancel = nil
		cancel()
	}
	cancelAt := f.cancelAt
	blocked := f.block || (cancelAt > 0 && n >= cancelAt)
	scriptedCancel := f.cancel
	flagTimeout := f.cancelFlagTimeout
	ans := f.answers[host+"\x00"+string(rt)]
	err := f.errs[host+"\x00"+string(rt)]
	f.mu.Unlock()

	if blocked {
		if n == cancelAt && scriptedCancel != nil {
			// The cancellation lands while THIS query is in flight.
			scriptedCancel()
		}
		<-ctx.Done()
		if cancelAt > 0 {
			// The stdlib pure-Go resolver surface for a cancelled query: a
			// *net.DNSError wrapping the context error (UnwrapErr), with
			// IsTimeout|IsTemporary stamped when the in-flight read failed
			// at the per-attempt deadline. Classified exactly as the
			// production NetResolver adapter classifies it.
			cerr := ctx.Err()
			dnsErr := &net.DNSError{Err: cerr.Error(), Name: host}
			if flagTimeout {
				dnsErr.IsTimeout = true
				dnsErr.IsTemporary = true
			}
			dnsErr.UnwrapErr = cerr
			return nil, classifyQueryError(host, rt, dnsErr)
		}
		return nil, ctx.Err()
	}
	return ans, err
}

// fakeClock is a deterministic runtime.Clock. It starts at fixedTime and only
// advances when advance is called. After timers fire when advance passes
// their target, matching the runtime limiter's expectations.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters map[chan time.Time]time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, waiters: make(map[chan time.Time]time.Time)}
}

// Now implements runtime.Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements runtime.Clock.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters[ch] = c.now.Add(d)
	return ch
}

// advance moves the clock forward by d and fires every After timer whose
// target has been reached.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for ch, target := range c.waiters {
		if !target.After(c.now) {
			ch <- c.now
			delete(c.waiters, ch)
		}
	}
}

// fixedTime is the deterministic provenance timestamp used by tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// mustDomain normalizes a domain or fails the test.
func mustDomain(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

// mustHost normalizes a host or fails the test.
func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// testConfig returns a fast, deterministic Config for unit tests: the given
// resolver, no rate limiting, a short per-job timeout so a hung resolver
// fails fast, and modest pool bounds.
func testConfig(res Resolver) Config {
	cfg := DefaultConfig()
	cfg.Resolver = res
	cfg.Concurrency = 4
	cfg.QueueSize = 16
	cfg.Timeout = 5 * time.Second
	cfg.Rate = 0 // pacing disabled: unit tests assert the limiter separately
	return cfg
}

// typeResultFor returns the TypeResult for the given queried host and record
// type, or the zero TypeResult when absent.
func typeResultFor(hr HostResult, host asset.Host, rt RecordType) TypeResult {
	for _, tr := range hr.Types {
		if tr.Host.Identity() == host.Identity() && tr.Type == rt {
			return tr
		}
	}
	return TypeResult{}
}

// hostByName finds a host result by canonical name.
func hostByName(t testing.TB, rep Report, name string) HostResult {
	t.Helper()
	for _, hr := range rep.Results {
		if hr.Host.Name == name {
			return hr
		}
	}
	t.Fatalf("no result for host %q", name)
	return HostResult{}
}

// relationshipIDs renders a host result's relationships as sorted IDs for
// deterministic assertions.
func relationshipIDs(hr HostResult) []string {
	ids := make([]string, 0, len(hr.Relationships))
	for _, r := range hr.Relationships {
		ids = append(ids, r.ID())
	}
	sortStrings(ids)
	return ids
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ipNames renders IP assets as canonical strings.
func ipNames(ips []asset.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Addr.String())
	}
	return out
}

// hostNames renders host assets as canonical names.
func hostNames(hosts []asset.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return out
}

// requireEqualStrings fails when the slices differ in length or element
// order.
func requireEqualStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// verifyNoQueries asserts the resolver was never consulted.
func verifyNoQueries(t *testing.T, f *fakeResolver) {
	t.Helper()
	if n := f.callCount(); n != 0 {
		t.Fatalf("resolver was queried %d times; expected zero", n)
	}
}
