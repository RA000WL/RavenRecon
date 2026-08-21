package adapt

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// fixedTime is the deterministic provenance timestamp used by tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// fixedClock is a deterministic runtime.Clock for provenance timestamps.
// Rate limiting is disabled in every test below, so After is never consulted
// by the engine; it mirrors time.After to satisfy the interface.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                         { return c.now }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var _ runtime.Clock = fixedClock{}

// fakeResolver is a hermetic dns.Resolver: canned answers and typed errors
// per (host, record type), a per-host seen counter (tests assert out-of-domain
// input never reaches it), and an optional one-shot auto-cancel hook that
// fires the run's cancel function on the first query for deterministic
// mid-run cancellation. Unscripted (host, type) pairs resolve as NODATA
// (empty answers, nil error), the legitimate empty-answer convention.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	seen    map[string]int
	// autoCancel, when non-nil, is invoked exactly once on the first query;
	// that query then returns the typed cancellation surface the production
	// resolver would produce.
	autoCancel func()
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		answers: make(map[string][]string),
		errs:    make(map[string]error),
		seen:    make(map[string]int),
	}
}

// set scripts answers for one (host, record type) pair.
func (f *fakeResolver) set(host string, rt dns.RecordType, answers ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host+"\x00"+string(rt)] = answers
}

// setErr scripts a typed error for one (host, record type) pair.
func (f *fakeResolver) setErr(host string, rt dns.RecordType, err error) {
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

// seenHosts returns the hosts the resolver was queried for, as a set.
func (f *fakeResolver) seenHosts() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bool, len(f.seen))
	for h := range f.seen {
		out[h] = true
	}
	return out
}

// callCount reports the number of queries issued.
func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// seenCount reports how many queries were issued for one host (the seen
// map counts per host, one entry per (host, type) lookup). T5 uses it to
// prove cache-warm runs re-attempt only the failed host's queries.
func (f *fakeResolver) seenCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[host]
}

// Lookup implements dns.Resolver.
func (f *fakeResolver) Lookup(ctx context.Context, host string, rt dns.RecordType) ([]string, error) {
	f.mu.Lock()
	f.seen[host]++
	var cancel func()
	if f.autoCancel != nil {
		cancel = f.autoCancel
		f.autoCancel = nil
	}
	key := host + "\x00" + string(rt)
	ans, hasAns := f.answers[key]
	err := f.errs[key]
	f.mu.Unlock()

	if cancel != nil {
		cancel()
		// The production surface for a cancelled query: a typed QueryError
		// with Kind ErrCancelled, exactly as dns.classifyQueryError maps a
		// context error.
		return nil, &dns.QueryError{Kind: dns.ErrCancelled, Host: host, Type: rt, Err: ctx.Err()}
	}
	if err != nil {
		return nil, err
	}
	if !hasAns {
		return []string{}, nil // NODATA-style legitimate empty answer
	}
	return ans, nil
}

// failureErr is the typed resolver failure surface for one (host, type).
func failureErr(host string, rt dns.RecordType) error {
	return &dns.QueryError{
		Kind: dns.ErrFailure,
		Host: host,
		Type: rt,
		Err:  errors.New("synthetic resolver failure"),
	}
}

func mustDomain(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// dnsInput returns a StageInput with resolved defaults, a deterministic
// clock, and the given target/hosts.
func dnsInput(target asset.Domain, hosts []asset.Host) pipeline.StageInput {
	return pipeline.StageInput{
		Target: target,
		Hosts:  hosts,
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
}

// hostNames renders host assets as canonical names.
func hostNames(hosts []asset.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return out
}

// ipStrings renders IP assets as canonical address strings.
func ipStrings(ips []asset.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// requireEqualStrings fails when the slices differ in length or element order.
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

func TestDNSStageName(t *testing.T) {
	if got := NewDNSStage(nil).Name(); got != pipeline.StageDNS {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageDNS)
	}
}

// TestDNSStageResolvesInDomainHosts pins the happy path: in-domain hosts are
// resolved into additions (input hosts plus an in-domain CNAME target, merged
// and sorted), the outcome is completed, and the counters are honest. Unknown
// StageParams keys are ignored (the adapter documents no keys).
func TestDNSStageResolvesInDomainHosts(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	api := mustHost(t, "api.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("www.example.com", dns.TypeCNAME, "alias.example.com")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")

	in := dnsInput(target, []asset.Host{www, api})
	// Unknown StageParams must be ignored by construction.
	in.Config = map[string]string{"bogus_key": "x", "another_unknown": "y"}

	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated = %v, StickyFlags = %v; want false/nil", res.Truncated, res.StickyFlags)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 2/0", res.ItemsProcessed, res.ItemsFailed)
	}
	requireEqualStrings(t, "additions",
		hostNames(res.Additions.Hosts),
		[]string{"alias.example.com", "api.example.com", "www.example.com"})
	if len(res.Additions.Domains) != 0 || len(res.Additions.URLs) != 0 {
		t.Fatalf("additions domains/urls = %v/%v, want empty", res.Additions.Domains, res.Additions.URLs)
	}
	// T3d results wiring: the resolved addresses flow through the results
	// channel (the engine's merged AllIPs, sorted) — the dns stage's only
	// results contribution. IPs need no scope filter: an address is not
	// in- or out-of-domain.
	requireEqualStrings(t, "results IPs", ipStrings(res.Results.IPs),
		[]string{"93.184.216.34", "93.184.216.35"})
}

// TestDNSStageResultsIPsDeduped pins the results-channel dedup through the
// adapter: two hosts resolving to the SAME address produce exactly ONE
// canonical IP entry — the engine's merged AllIPs dedupes by Phase 2
// identity (earliest provenance wins) and the adapter copies that merged
// report verbatim, never rebuilding and never re-deduplicating.
func TestDNSStageResultsIPsDeduped(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	api := mustHost(t, "api.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.34")

	in := dnsInput(target, []asset.Host{www, api})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if res.ItemsProcessed != 2 {
		t.Fatalf("ItemsProcessed = %d, want 2 (both hosts were still processed)", res.ItemsProcessed)
	}
	requireEqualStrings(t, "results IPs", ipStrings(res.Results.IPs), []string{"93.184.216.34"})
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts),
		[]string{"api.example.com", "www.example.com"})
}

// TestDNSStageResultsDeterminism pins the determinism contract for the
// results channel: two identical runs (fixed clock, scripted resolver)
// produce DeepEqual StageResults including the IPs channel — the engine's
// merged, sorted canonical assets are stable across runs.
func TestDNSStageResultsDeterminism(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	api := mustHost(t, "api.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("www.example.com", dns.TypeCNAME, "alias.example.com")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")

	run := func() pipeline.StageResult {
		t.Helper()
		res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www, api}))
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		return res
	}
	res1, res2 := run(), run()
	if !reflect.DeepEqual(res1, res2) {
		t.Fatalf("two identical runs differ:\nrun 1: %+v\nrun 2: %+v", res1, res2)
	}
	if len(res1.Results.IPs) == 0 {
		t.Fatal("determinism pin exercised no results output (IPs empty)")
	}
}

// TestDNSStageFiltersOutOfDomainInputHosts pins the input boundary: an
// out-of-domain host in the corpus is filtered before the engine sees it —
// the fake resolver never receives a query for it — and the run completes
// normally over the in-domain remainder.
func TestDNSStageFiltersOutOfDomainInputHosts(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	evil := mustHost(t, "evil.com")
	evilSub := mustHost(t, "evil-example.com") // label-aware: never matches

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	in := dnsInput(target, []asset.Host{www, evil, evilSub})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	seen := fake.seenHosts()
	for _, out := range []string{"evil.com", "evil-example.com"} {
		if seen[out] {
			t.Fatalf("out-of-domain input host %q reached the resolver", out)
		}
	}
	if !seen["www.example.com"] {
		t.Fatalf("in-domain host %q was never resolved", "www.example.com")
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

// TestDNSStageFiltersOutOfDomainCNAMEAdditions pins the output boundary: a
// cross-domain CNAME target is a legitimate engine observation (the engine
// resolves its depth-1 addresses) but must never enter the corpus — it is
// filtered from Additions, while the in-domain host is retained.
func TestDNSStageFiltersOutOfDomainCNAMEAdditions(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeCNAME, "cdn.other-corp.net")

	in := dnsInput(target, []asset.Host{www})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	seen := fake.seenHosts()
	if !seen["cdn.other-corp.net"] {
		t.Fatal("engine never resolved the cross-domain CNAME target (the observation should exist, only the corpus addition is filtered)")
	}
	for _, name := range hostNames(res.Additions.Hosts) {
		if name == "cdn.other-corp.net" {
			t.Fatalf("cross-domain CNAME target %q leaked into additions", name)
		}
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

// TestDNSStageAllHostsFailed pins the all-failed fold: every host with no
// usable observation (dns.StatusFailed) folds to Outcome failed, and
// ItemsFailed equals ItemsProcessed.
func TestDNSStageAllHostsFailed(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	for _, rt := range []dns.RecordType{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		fake.setErr("www.example.com", rt, failureErr("www.example.com", rt))
	}

	in := dnsInput(target, []asset.Host{www})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
	// A failed host is still a reported host: the honest retained output.
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

// TestDNSStageMixedOutcomesPartial pins the mixed fold: completed hosts
// together with failed hosts fold to Outcome partial (never completed, never
// failed).
func TestDNSStageMixedOutcomesPartial(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	api := mustHost(t, "api.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	for _, rt := range []dns.RecordType{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		fake.setErr("api.example.com", rt, failureErr("api.example.com", rt))
	}

	in := dnsInput(target, []asset.Host{www, api})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomePartial)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 1 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 2/1", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestDNSStageCancelled pins cancellation before the engine runs: the engine
// rejects a pre-cancelled context, and the adapter reports Outcome cancelled
// with the context error, never failed.
func TestDNSStageCancelled(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := NewDNSStage(fake).Run(ctx, dnsInput(target, []asset.Host{www}))
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a context.Canceled error", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("resolver was queried %d times on a cancelled run; want 0", fake.callCount())
	}
}

// TestDNSStageMidRunCancellation pins mid-run cancellation: the engine
// returns a nil error on teardown (hosts are marked cancelled in the report),
// and the adapter still reports Outcome cancelled with the context error.
func TestDNSStageMidRunCancellation(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	api := mustHost(t, "api.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	ctx, cancel := context.WithCancel(context.Background())
	fake.setAutoCancel(cancel)

	in := dnsInput(target, []asset.Host{www, api})
	res, err := NewDNSStage(fake).Run(ctx, in)
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a context.Canceled error", err)
	}
}

// TestDNSStageCachePassedThrough pins the Cache pass-through: with a real
// filesystem cache, the first run populates per-(host, type) records and the
// second run performs ZERO resolver queries (every type is served from the
// cache), proving in.Cache reaches the engine config.
func TestDNSStageCachePassedThrough(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	c, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	stage := NewDNSStage(fake)
	in := dnsInput(target, []asset.Host{www})
	in.Cache = c

	res1, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run 1 returned error: %v", err)
	}
	if res1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("run 1 Outcome = %q, want %q", res1.Outcome, pipeline.OutcomeCompleted)
	}
	afterWarm := fake.callCount()
	if afterWarm == 0 {
		t.Fatal("run 1 made no resolver queries; the cache was expected to miss")
	}

	res2, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run 2 returned error: %v", err)
	}
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("run 2 Outcome = %q, want %q", res2.Outcome, pipeline.OutcomeCompleted)
	}
	if got := fake.callCount(); got != afterWarm {
		t.Fatalf("run 2 issued %d new resolver queries (total %d, want %d); cache was not passed through", got-afterWarm, got, afterWarm)
	}
	requireEqualStrings(t, "run 2 additions", hostNames(res2.Additions.Hosts), []string{"www.example.com"})
}

// TestDNSStageEmptyFilteredInputShortCircuits pins the empty filtered-input
// short-circuit decision: dns.Resolve treats an empty host list as VALID
// input (it returns an empty report without starting a pool), so the adapter
// short-circuits to completed with zero additions — observationally identical
// to calling the engine, with zero resolver calls. A cancelled context still
// wins over the short-circuit, and a non-canonical target falls through to
// the engine so its honest scope error is not masked.
func TestDNSStageEmptyFilteredInputShortCircuits(t *testing.T) {
	target := mustDomain(t, "example.com")

	t.Run("empty corpus", func(t *testing.T) {
		fake := newFakeResolver()
		res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, nil))
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
		}
		if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
			t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
		}
		if len(res.Additions.Hosts) != 0 || res.Truncated {
			t.Fatalf("additions = %v, truncated = %v; want empty/false", res.Additions.Hosts, res.Truncated)
		}
		if fake.callCount() != 0 {
			t.Fatalf("resolver was queried %d times; want 0", fake.callCount())
		}
	})

	t.Run("only out-of-domain hosts", func(t *testing.T) {
		fake := newFakeResolver()
		in := dnsInput(target, []asset.Host{mustHost(t, "evil.com"), mustHost(t, "evil.net")})
		res, err := NewDNSStage(fake).Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
		}
		if fake.callCount() != 0 {
			t.Fatalf("resolver was queried %d times; want 0", fake.callCount())
		}
	})

	t.Run("cancelled context wins over the short-circuit", func(t *testing.T) {
		fake := newFakeResolver()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := NewDNSStage(fake).Run(ctx, dnsInput(target, nil))
		if res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want a context.Canceled error", err)
		}
	})

	t.Run("non-canonical target falls through to the engine", func(t *testing.T) {
		fake := newFakeResolver()
		// Hand-built, non-canonical target ("Example.com" is not the form
		// asset.NewDomain produces): the short-circuit must not mask the
		// engine's own scope-validation error.
		in := dnsInput(asset.Domain{Name: "Example.com"}, nil)
		res, err := NewDNSStage(fake).Run(context.Background(), in)
		if res.Outcome != pipeline.OutcomeFailed {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
		}
		if err == nil || !strings.Contains(err.Error(), "stage dns:") {
			t.Fatalf("err = %v, want a wrapped stage error", err)
		}
		if fake.callCount() != 0 {
			t.Fatalf("resolver was queried %d times; want 0", fake.callCount())
		}
	})
}

// TestDNSStageTruncationFlagged pins the never-swallowed truncation flag: an
// answer set capped at dns.MaxAnswersPerType marks the type truncated, the
// host folds to engine-incomplete, and the stage reports Outcome partial
// (MEDIUM-1 outcome-mapping unification: an engine-incomplete host folds
// into the partial bucket — the adapters themselves never emit incomplete)
// with Truncated=true and the dnsAnswersTruncated sticky flag.
func TestDNSStageTruncationFlagged(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	answers := make([]string, 0, dns.MaxAnswersPerType+1)
	for i := 1; i <= dns.MaxAnswersPerType+1; i++ {
		answers = append(answers, fmt.Sprintf("192.0.2.%d", i))
	}
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, answers...)

	in := dnsInput(target, []asset.Host{www})
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want %q (a capped answer set is engine-incomplete, which folds to partial)", res.Outcome, pipeline.OutcomePartial)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (the retention cap was hit)")
	}
	if !res.StickyFlags[dnsAnswersTruncated] {
		t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, dnsAnswersTruncated)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 1/0", res.ItemsProcessed, res.ItemsFailed)
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

// TestDNSStageEngineErrorWrappedNoPanic pins the error contract: an engine
// error (here the engine's own rejection of a zero Concurrency, which a
// direct caller could pass) is wrapped with "stage dns: ...", forces Outcome
// failed, and never panics.
func TestDNSStageEngineErrorWrappedNoPanic(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	in := dnsInput(target, []asset.Host{www})
	in.Bounds = pipeline.StageConfig{} // zero Concurrency: the engine rejects it

	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if err == nil || !strings.Contains(err.Error(), "stage dns:") {
		t.Fatalf("err = %v, want a wrapped error containing %q", err, "stage dns:")
	}
	if !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("err = %v, want the engine's concurrency cause preserved", err)
	}
}

// --- Dnsx brute (opt-in) tests ---

func TestDNSBruteDisabledNoExtraCost(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	// No brute param: the stage must not issue any wildcard probe or brute
	// candidate queries. Only the explicitly listed host is resolved.
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")

	in := dnsInput(target, []asset.Host{mustHost(t, "www.example.com")})
	// No Config: brute disabled (default).
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	// The resolver should have been queried only for the input host's types
	// (A/AAAA/CNAME) and the CNAME target's A/AAAA if any — exactly 3 plus
	// 2 for the CNAME target if it existed. With no brute, the wildcard
	// probe host must never be queried.
	if seen := fake.seenHosts(); seen["ravenrecon-wildcard-check.example.com"] {
		t.Fatalf("wildcard probe host was queried despite brute being disabled (zero cost violation)")
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"www.example.com"})
	if len(res.Additions.Hosts) != 1 {
		t.Fatalf("brute hosts leaked with brute disabled: %v", hostNames(res.Additions.Hosts))
	}
}

func TestDNSBruteEnabledResolves(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	// Wildcard probe must NOT resolve (no wildcard) — leave unsripted (NODATA)
	// so IsWildcard returns false.
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")
	// The brute wordlist hosts are "www" and "api" via StageParams.
	in := dnsInput(target, nil)
	in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "www,api"}
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	requireEqualStrings(t, "brute additions", hostNames(res.Additions.Hosts), []string{"api.example.com", "www.example.com"})
	requireEqualStrings(t, "brute IPs", ipStrings(res.Results.IPs), []string{"93.184.216.34", "93.184.216.35"})
	if seen := fake.seenHosts(); !seen["ravenrecon-wildcard-check.example.com"] {
		t.Fatalf("wildcard probe host was not queried with brute enabled")
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("unexpected truncation flags: truncated=%v flags=%v", res.Truncated, res.StickyFlags)
	}
}

func TestDNSBruteEnabledDefaultWordlist(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")
	in := dnsInput(target, nil)
	in.Config = map[string]string{"dnsx_brute": "true"} // no wordlist -> default 10
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	// Default wordlist includes www and api, so at least those two should be
	// present; others are NODATA and filtered out (no IPs), so not in
	// additions.
	requireEqualStrings(t, "default wordlist brute", hostNames(res.Additions.Hosts), []string{"api.example.com", "www.example.com"})
}

func TestDNSBruteWildcardAborts(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	// Wildcard probe resolves -> brute must abort.
	fake.set("ravenrecon-wildcard-check.example.com", dns.TypeA, "5.6.7.8")
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")

	in := dnsInput(target, nil)
	in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "www,api"}
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(res.Additions.Hosts) != 0 {
		t.Fatalf("wildcard abort failed: brute hosts leaked: %v", hostNames(res.Additions.Hosts))
	}
	if !res.StickyFlags["dns_brute_wildcard"] {
		t.Fatalf("StickyFlags = %v, want dns_brute_wildcard set on wildcard abort", res.StickyFlags)
	}
	// Brute candidate hosts must NOT have been queried after the abort.
	if seen := fake.seenHosts(); seen["www.example.com"] || seen["api.example.com"] {
		t.Fatalf("brute candidates were queried despite wildcard abort: seen=%v", seen)
	}
}

func TestDNSBruteDedup(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")
	// Input already contains www; brute wordlist also contains www and api.
	// www must not be duplicated, api should be added.
	in := dnsInput(target, []asset.Host{www})
	in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "www,api"}
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	requireEqualStrings(t, "dedup", hostNames(res.Additions.Hosts), []string{"api.example.com", "www.example.com"})
	requireEqualStrings(t, "dedup IPs", ipStrings(res.Results.IPs), []string{"93.184.216.34", "93.184.216.35"})
}

func TestDNSBruteUnknownParamIgnored(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	in := dnsInput(target, []asset.Host{mustHost(t, "www.example.com")})
	in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "www", "bogus_key": "x", "another": "y"}
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	requireEqualStrings(t, "unknown param ignored", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

func TestDNSBrutePipelineE2E(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.set("api.example.com", dns.TypeA, "93.184.216.35")

	stage := NewDNSStage(fake)
	cfg := pipeline.ScanConfig{
		Target: target,
		Stages: []pipeline.StageName{pipeline.StageDNS},
		StageParams: map[pipeline.StageName]map[string]string{
			pipeline.StageDNS: {"dnsx_brute": "true", "dnsx_wordlist": "www,api"},
		},
	}
	report, err := pipeline.Run(context.Background(), cfg, nil, fixedClock{now: fixedTime}, []pipeline.Stage{stage})
	if err != nil {
		t.Fatalf("pipeline.Run error: %v", err)
	}
	if report.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("report.Outcome = %q, want completed", report.Outcome)
	}
	requireEqualStrings(t, "pipeline brute hosts", hostNames(report.Hosts), []string{"api.example.com", "www.example.com"})
	if len(report.Results.IPs) != 2 {
		t.Fatalf("report.Results.IPs = %v, want 2", ipStrings(report.Results.IPs))
	}
}

func TestDNSBruteEmptyCorpusWithBrute(t *testing.T) {
	target := mustDomain(t, "example.com")
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	in := dnsInput(target, nil)
	in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "www"}
	res, err := NewDNSStage(fake).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	requireEqualStrings(t, "empty corpus brute", hostNames(res.Additions.Hosts), []string{"www.example.com"})
}

// stallingResolver is a hermetic resolver for brute timeout tests: it
// returns quickly for the wildcard probe and for hosts listed in fast,
// otherwise it blocks until the query context is cancelled (BruteTimeout
// path) and returns a typed cancellation error. This simulates a resolver
// that stalls past BruteTimeout without actually sleeping 60s — the parent
// context has a shorter deadline so bruteCtx fires quickly.
type stallingResolver struct {
	mu    sync.Mutex
	fast  map[string][]string
	delay time.Duration
	seen  map[string]int
}

func newStallingResolver(fast map[string][]string, delay time.Duration) *stallingResolver {
	if fast == nil {
		fast = make(map[string][]string)
	}
	return &stallingResolver{fast: fast, delay: delay, seen: make(map[string]int)}
}

func (s *stallingResolver) Lookup(ctx context.Context, host string, rt dns.RecordType) ([]string, error) {
	s.mu.Lock()
	if s.seen == nil {
		s.seen = make(map[string]int)
	}
	s.seen[host]++
	fastKey := host + "\x00" + string(rt)
	ans, ok := s.fast[fastKey]
	s.mu.Unlock()
	// Wildcard probe must never stall — otherwise IsWildcard would block
	// and the test would not reach brute candidate resolution.
	if strings.HasPrefix(host, "ravenrecon-wildcard-check.") {
		return []string{}, nil
	}
	if ok {
		return ans, nil
	}
	select {
	case <-ctx.Done():
		return nil, &dns.QueryError{Kind: dns.ErrCancelled, Host: host, Type: rt, Err: ctx.Err()}
	case <-time.After(s.delay):
		return []string{}, nil
	}
}

// TestDNSBruteTimeoutTruncated is the NEW-23 regression: when
// dns.BruteTimeout fires mid-resolution the brute must not be recorded
// completed with no flag. It must set dns_brute_truncated + Truncated,
// downgrade outcome, and count only attempted hosts.
func TestDNSBruteTimeoutTruncated(t *testing.T) {
	target := mustDomain(t, "example.com")

	t.Run("all stalled cancelled", func(t *testing.T) {
		// All brute candidates stall past the parent deadline.
		sr := newStallingResolver(nil, 200*time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		in := dnsInput(target, nil)
		in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "a,b"}
		res, _ := NewDNSStage(sr).Run(ctx, in)
		if res.Outcome == pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = completed, want cancelled/partial for timeout-truncated brute (flag=%v truncated=%v)", res.StickyFlags, res.Truncated)
		}
		if !res.Truncated {
			t.Fatalf("Truncated = false, want true for brute timeout")
		}
		if !res.StickyFlags[dnsBruteTruncatedFlag] {
			t.Fatalf("StickyFlags = %v, want %q set for brute timeout", res.StickyFlags, dnsBruteTruncatedFlag)
		}
		// Attempted-only counters: both candidates were submitted and
		// attempted (Types non-empty with cancellation), so ItemsProcessed
		// is 2, not 0 and not wordlist length 0. Pre-fix returned 0 with
		// no flag.
		if res.ItemsProcessed != 2 {
			t.Fatalf("ItemsProcessed = %d, want 2 (attempted hosts)", res.ItemsProcessed)
		}
		if len(res.Additions.Hosts) != 0 {
			t.Fatalf("Additions.Hosts = %v, want empty (all stalled)", hostNames(res.Additions.Hosts))
		}
	})

	t.Run("mixed fast and stalled partial", func(t *testing.T) {
		fast := map[string][]string{
			"fast.example.com\x00A": {"93.184.216.34"},
		}
		sr := newStallingResolver(fast, 200*time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		in := dnsInput(target, nil)
		in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "fast,slow"}
		res, _ := NewDNSStage(sr).Run(ctx, in)
		if res.Outcome != pipeline.OutcomePartial {
			t.Fatalf("Outcome = %q, want %q for mixed success+timeout", res.Outcome, pipeline.OutcomePartial)
		}
		if !res.Truncated || !res.StickyFlags[dnsBruteTruncatedFlag] {
			t.Fatalf("Truncated=%v StickyFlags=%v, want truncated with %q", res.Truncated, res.StickyFlags, dnsBruteTruncatedFlag)
		}
		requireEqualStrings(t, "mixed hosts", hostNames(res.Additions.Hosts), []string{"fast.example.com"})
		if res.ItemsProcessed != 2 {
			t.Fatalf("ItemsProcessed = %d, want 2 (fast attempted + slow cancelled)", res.ItemsProcessed)
		}
		if res.ItemsFailed != 0 {
			t.Fatalf("ItemsFailed = %d, want 0", res.ItemsFailed)
		}
	})

	t.Run("overflow attempted only counters", func(t *testing.T) {
		// Many candidates, small queue/concurrency so some are never
		// attempted due to queue overflow when the deadline fires while
		// Submit is blocked. ItemsProcessed must be attempted-only, not
		// len(filtered).
		sr := newStallingResolver(nil, 200*time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		in := dnsInput(target, nil)
		in.Bounds.MaxConcurrency = 1
		in.Bounds.QueueSize = 2
		// 10 candidates, filtered will be 10, but only 1 running +2 queued can be submitted before timeout
		in.Config = map[string]string{"dnsx_brute": "true", "dnsx_wordlist": "w0,w1,w2,w3,w4,w5,w6,w7,w8,w9"}
		res, _ := NewDNSStage(sr).Run(ctx, in)
		if res.Outcome == pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = completed, want cancelled/partial for overflow timeout")
		}
		if !res.Truncated || !res.StickyFlags[dnsBruteTruncatedFlag] {
			t.Fatalf("Truncated=%v StickyFlags=%v, want truncated with %q", res.Truncated, res.StickyFlags, dnsBruteTruncatedFlag)
		}
		// Attempted hosts are those with Types non-empty (only the
		// running job had a chance to record Types). Pre-fix counted
		// len(filtered)=10.
		if res.ItemsProcessed == 10 {
			t.Fatalf("ItemsProcessed = 10, want <10 (attempted-only, not len(filtered))")
		}
		if res.ItemsProcessed <= 0 || res.ItemsProcessed > 3 {
			t.Fatalf("ItemsProcessed = %d, want 1..3 for overflow (attempted only)", res.ItemsProcessed)
		}
	})
}
