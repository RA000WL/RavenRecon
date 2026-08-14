package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// MaxAnswersPerType caps how many distinct answers are retained per
// (queried host, record type). The standard library already bounds DNS
// message sizes; this constant bounds what the pipeline retains and caches
// per host per type, so answer retention is bounded even for a hostile
// resolver. The cap is generous — far above any normal reconnaissance answer
// set — and is a fixed constant: it is deliberately NOT configuration, and it
// must never enter cache keys (see typeKey). Answers beyond the cap are
// dropped, the type is marked truncated, and a truncated set is stored and
// treated as incomplete — never as a completed result.
const MaxAnswersPerType = 64

// hostTypes is the stable per-host query plan for the input host itself, in
// this order. The direct CNAME target's A/AAAA (depth 1) follow in the same
// stable order when the CNAME query yields a non-self target.
var hostTypes = []RecordType{TypeA, TypeAAAA, TypeCNAME}

// targetTypes is the depth-1 address closure plan for a CNAME target.
var targetTypes = []RecordType{TypeA, TypeAAAA}

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a cancelled record). Cache writes are
// small atomic files; this budget only exists so a cancelled run cannot wedge
// shutdown on a pathological filesystem. Mirrors the Phase 4 convention.
const storeTimeout = 5 * time.Second

// shutdownGrace is added to the pool timeout to bound Shutdown's drain:
// jobs already respect their per-job deadline, so a clean drain needs at most
// the timeout plus one grace period. Mirrors the Phase 4 convention.
const shutdownGrace = 15 * time.Second

// shutdownForceBudget bounds Shutdown's drain when the pool per-job timeout
// is disabled (0). Mirrors the Phase 4 convention.
const shutdownForceBudget = 30 * time.Second

// Config configures one DNS resolution run.
type Config struct {
	// Concurrency and QueueSize configure the single runtime pool that owns
	// all scheduling for this run: exactly one job per input host is
	// submitted, and the pool owns concurrency, cancellation, per-job
	// deadlines, and shutdown. Concurrency must be positive.
	Concurrency int
	QueueSize   int

	// Timeout is the per-job deadline at pool level (0 disables it;
	// DefaultConfig sets a sane value). The deadline covers the central
	// query-limiter waits and the queries themselves.
	Timeout time.Duration

	// Rate and Burst configure the run's single central token-bucket
	// limiter (the runtime engine's Limiter), which paces OUTBOUND QUERIES:
	// every query that misses the cache waits for a token before dispatch,
	// so the aggregate query dispatch rate is bounded regardless of
	// concurrency. Rate <= 0 disables pacing; Burst < 1 means 1.
	//
	// The pool's own job-start rate limiting is disabled (Rate 0): per-query
	// pacing subsumes job-start pacing — every outbound operation is
	// individually gated — and the two would otherwise double-throttle each
	// other. The query limiter is the same token-bucket machinery the
	// runtime uses centrally, shared by every job of the run.
	//
	// The limiter controls ONLY RavenRecon's query dispatch pacing: the
	// system resolver performs its own server selection, retries, and
	// nameserver rotation per /etc/resolv.conf, and RavenRecon neither
	// controls nor claims to control any of that.
	Rate  float64
	Burst int

	// Cache, when non-nil, enables cache-before-execute per (host, record
	// type): each query first derives the Phase 3 key and returns the stored
	// result on a usable hit; on a miss it executes the query and stores a
	// statused record. Nil disables caching. A cache hit performs zero DNS
	// requests.
	Cache cache.Cache

	// Resolver performs the DNS queries. Nil means NewNetResolver (the
	// stdlib pure-Go resolver); tests inject hermetic fakes.
	Resolver Resolver

	// Clock is the time source for provenance timestamps and the central
	// query limiter. Nil means the wall clock; tests inject a fake clock
	// for deterministic assertions.
	Clock runtime.Clock
}

// DefaultConfig returns a Config with documented defaults. Concurrency and
// the per-job timeout are consistent with the Phase 4 conventions (the
// timeout matches exactly); the query rate is the documented conservative
// default for pacing outbound DNS queries.
func DefaultConfig() Config {
	return Config{
		Concurrency: 8,
		QueueSize:   256,
		Timeout:     30 * time.Second,
		Rate:        20,
		Burst:       1,
	}
}

// env is the per-run plumbing shared by every job. It is immutable after
// construction; the limiter and the cache are internally synchronized.
type env struct {
	resolver Resolver
	cache    cache.Cache
	limiter  *runtime.Limiter // nil when pacing is disabled
	clock    runtime.Clock
}

// Resolve resolves hosts within the declared target domain and returns the
// typed observations, Phase 2 assets, and relationships for every input host.
//
// The host list is validated at the boundary first: every input host must be
// a canonical Phase 2 host (asset.NewHost in canonical form) and the target
// domain itself or a subdomain of it. Any invalid or out-of-scope host
// rejects the whole call with an error BEFORE a single query is issued.
// Hosts are deduplicated by Phase 2 identity and processed in sorted
// canonical order.
//
// One bounded runtime.Pool owns all scheduling: exactly one job per host,
// per-job deadlines, context cancellation, and one central query limiter
// pacing outbound queries. Resolve's pool shutdown is the join point; the
// returned Report always carries whatever each job observed, including on
// cancellation or forced shutdown. When cfg.Cache is enabled, each
// (host, record type) query is cache-before-execute: a completed, unexpired
// record for the exact key serves the type without any DNS request.
func Resolve(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg Config) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("dns: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("dns: %w", err)
	}
	if err := validateScope(domain); err != nil {
		return Report{}, err
	}

	// Boundary: every input host must be canonical and in scope; rejection
	// happens before any pool or limiter exists. The Phase 4 validateTarget
	// pattern, implemented locally because internal/dns must not import
	// internal/discovery.
	hosts, err := normalizeInputHosts(hosts, domain)
	if err != nil {
		return Report{}, err
	}
	if len(hosts) == 0 {
		// Nothing to resolve: return an empty report without starting a
		// pool.
		return Report{Target: domain}, nil
	}

	e, err := buildEnv(cfg)
	if err != nil {
		return Report{}, err
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		// Job-start rate limiting is deliberately disabled: the central
		// query limiter paces every outbound query, which subsumes
		// job-start pacing (see Config.Rate).
		Rate:  0,
		Burst: 0,
	})
	if err != nil {
		return Report{}, fmt.Errorf("dns: create worker pool: %w", err)
	}

	// One slot per host, pre-initialized to cancelled: each job overwrites
	// only its own slot, so the slice is race-free, and a queued job dropped
	// by a forced shutdown (the runtime drops unstarted jobs without a
	// terminal event) keeps an honest cancelled status instead of a zero
	// value.
	results := make([]HostResult, len(hosts))
	for i := range hosts {
		results[i] = HostResult{Host: hosts[i], Status: StatusCancelled}
	}
	for i, h := range hosts {
		h := h
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			results[i] = resolveHost(jctx, h, e)
			return nil, nil
		}}); err != nil {
			results[i] = HostResult{
				Host:   h,
				Status: StatusCancelled,
				Err:    fmt.Errorf("dns: submit %s: %w", h.Name, err),
			}
			// The run context is done or the pool is closing; every host
			// behind this one was never submitted and keeps its initialized
			// cancelled status with the cause attached.
			for j := i + 1; j < len(hosts); j++ {
				results[j].Err = fmt.Errorf("dns: not submitted: %w", ctx.Err())
			}
			break
		}
	}

	// Shutdown is the join point: it drains every queued and in-flight job
	// before returning (bounded, so a job that ignores cancellation cannot
	// wedge the run forever).
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()

	report := Report{Target: domain, Results: results}
	if shutdownErr != nil {
		return report, fmt.Errorf("dns: pool shutdown: %w", shutdownErr)
	}
	return report, nil
}

// shutdownContext derives the bounded drain context for pool shutdown,
// mirroring the Phase 4 budget: timeout + shutdownGrace, or
// shutdownForceBudget when per-job deadlines are disabled.
func shutdownContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	budget := timeout + shutdownGrace
	if timeout <= 0 {
		budget = shutdownForceBudget
	}
	return context.WithTimeout(context.Background(), budget)
}

// buildEnv assembles the shared per-run plumbing and the single central
// query limiter (runtime.NewLimiter — the same token-bucket machinery the
// pool uses internally), so every job paces every outbound query through one
// limiter. Rate <= 0 disables pacing.
func buildEnv(cfg Config) (env, error) {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = NewNetResolver()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = wallClock{}
	}
	e := env{resolver: resolver, cache: cfg.Cache, clock: clock}
	if cfg.Rate > 0 {
		burst := cfg.Burst
		if burst < 1 {
			burst = 1
		}
		l, err := runtime.NewLimiter(cfg.Rate, float64(burst), runtime.WithClock(clock))
		if err != nil {
			return env{}, fmt.Errorf("dns: create query rate limiter: %w", err)
		}
		e.limiter = l
	}
	return e, nil
}

// wallClock is the production runtime.Clock backed by the wall clock,
// mirroring the runtime package's own production clock (which is
// unexported).
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// normalizeInputHosts validates and normalizes the input host list at the
// boundary: every host must be canonical and in scope (see
// validateInputHost); duplicates are removed by Phase 2 identity; the result
// is sorted by canonical name for deterministic processing and output.
// Rejects the whole list with the first offending host's cause — before any
// query.
func normalizeInputHosts(hosts []asset.Host, domain asset.Domain) ([]asset.Host, error) {
	seen := make(map[asset.Identity]bool, len(hosts))
	out := make([]asset.Host, 0, len(hosts))
	for _, h := range hosts {
		if err := validateInputHost(h, domain); err != nil {
			return nil, err
		}
		// validateInputHost guarantees h.Name is canonical; rebuild through
		// the asset model so provenance and original values are Phase 2
		// sanctioned.
		nh, err := asset.NewHost(h.Name, h.Prov)
		if err != nil {
			return nil, fmt.Errorf("dns: invalid host %q: %w", h.Name, err)
		}
		if seen[nh.Identity()] {
			continue
		}
		seen[nh.Identity()] = true
		out = append(out, nh)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// resolveHost resolves one input host: the host's own A/AAAA/CNAME, then —
// when the CNAME query completed with a non-self target — the direct
// target's A/AAAA at depth exactly 1. Every query is cache-before-execute
// when caching is enabled, and every outbound query waits on the central
// limiter first. Once the context is done, no further query is issued;
// un-attempted types are recorded cancelled (the runtime's convention for
// work that never started).
func resolveHost(ctx context.Context, host asset.Host, e env) HostResult {
	hr := HostResult{Host: host, Status: StatusCompleted}

	// 1. The input host's own records, in stable order.
	for _, rt := range hostTypes {
		if ctx.Err() != nil {
			hr.Types = append(hr.Types, cancelledType(host, rt, ctx.Err()))
			continue
		}
		hr.Types = append(hr.Types, resolveType(ctx, host, rt, e))
	}

	// 2. Direct CNAME target addresses, depth exactly 1: only when the
	// host's CNAME query completed with a non-self target. The target is a
	// DNS observation and may point anywhere (cross-domain CNAMEs are a
	// legitimate observation); its A/AAAA are resolved exactly once, never
	// deeper — no recursion, so CNAME loops are impossible by construction.
	for _, t := range cnameTargets(hr.Types) {
		for _, rt := range targetTypes {
			if ctx.Err() != nil {
				hr.Types = append(hr.Types, cancelledType(t, rt, ctx.Err()))
				continue
			}
			hr.Types = append(hr.Types, resolveType(ctx, t, rt, e))
		}
	}

	// 3. Assemble typed assets and relationships from the observations.
	hr.IPs, hr.Targets, hr.Relationships = assemble(hr.Types)
	hr.Status = classifyHost(hr.Types)
	return hr
}

// cancelledType builds the TypeResult for a type that was never attempted
// because the context was already done.
func cancelledType(host asset.Host, rt RecordType, err error) TypeResult {
	return TypeResult{Host: host, Type: rt, Status: TypeCancelled, Err: err}
}

// cnameTargets extracts the distinct, non-self CNAME targets from completed
// CNAME type results, sorted by canonical name.
func cnameTargets(types []TypeResult) []asset.Host {
	seen := make(map[asset.Identity]bool)
	var out []asset.Host
	for _, tr := range types {
		if tr.Type != TypeCNAME || tr.Status != TypeCompleted || tr.NXDOMAIN {
			continue
		}
		for _, h := range tr.Hosts {
			if h.Identity() == tr.Host.Identity() {
				continue // self-target: no observation
			}
			if seen[h.Identity()] {
				continue
			}
			seen[h.Identity()] = true
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// resolveType resolves one (queried host, record type) pair with
// cache-before-execute semantics: derive the Phase 3 key, serve the stored
// result on a usable hit (a hit performs zero DNS requests), otherwise wait
// on the central limiter, query the resolver, normalize and cap the answers,
// and store a statused record.
func resolveType(ctx context.Context, host asset.Host, rt RecordType, e env) TypeResult {
	tr := TypeResult{Host: host, Type: rt}

	if e.cache != nil {
		tr = lookupType(ctx, host, rt, tr, e)
		if tr.Status != "" {
			// A completed cache hit, or a key-build failure that already
			// classified the type; either way no query is issued.
			return tr
		}
	}
	if ctx.Err() != nil {
		// Cancelled before the query could be issued: report cancelled,
		// never success, and never issue a query.
		tr.Status = TypeCancelled
		tr.Err = ctx.Err()
		return tr
	}

	// Rate limiting: the central query limiter gates THIS query's dispatch,
	// so the aggregate outbound query rate is bounded regardless of
	// concurrency.
	if e.limiter != nil {
		if err := e.limiter.Wait(ctx); err != nil {
			tr.Status = cancelledOrTimedOut(err)
			tr.Err = fmt.Errorf("dns: %s %s: wait for rate limit: %w", host.Name, rt, err)
			return tr
		}
	}

	answers, err := e.resolver.Lookup(ctx, host.Name, rt)
	tr = applyAnswers(tr, answers, err, e.clock)

	if e.cache != nil {
		tr = storeType(ctx, host, rt, tr, e)
	}
	return tr
}

// lookupType is the cache-before-execute read side for one
// (host, record type) pair. It returns the type either served from a
// completed, validated, unexpired record (Status TypeCompleted, Cached
// true), or with an empty Status to fall through to execution (miss,
// expired, incomplete, or discarded unusable records — any diagnosis is
// joined into Err), or already classified failed when the key cannot be
// built.
func lookupType(ctx context.Context, host asset.Host, rt RecordType, tr TypeResult, e env) TypeResult {
	key, err := typeKey(host, rt)
	if err != nil {
		tr.Status = TypeFailed
		tr.Err = fmt.Errorf("dns: %s %s: build cache key: %w", host.Name, rt, err)
		return tr
	}
	out := e.cache.Get(ctx, key)
	if !out.IsHit() {
		// Miss / expired / incomplete / corrupt / schema-incompatible are
		// all "execute" outcomes; only a Get that carries a diagnosis
		// (StateError — the state payloads carry no Err) is surfaced, as a
		// warning, never as a failure: the run falls through to a fresh
		// query.
		if out.Err != nil {
			tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: cache get: %w", host.Name, rt, out.Err))
		}
		return tr
	}

	// Only a completed, unexpired record for the exact key is a hit (the
	// cache enforces that). The record's own identity fields must also match
	// the query — a record found under this key with different operation or
	// target fields could only be tampered with — and the payload is
	// cross-checked by decodeStoredType. A record failing either check is
	// deleted and recomputed in this same run (self-healing), so it is never
	// served as a hit and never wedges the type into repeated failures.
	if out.Record.Operation != Operation || out.Record.Target != host.Identity().String() {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: delete mismatched cached record: %w", host.Name, rt, delerr))
		}
		tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: discarded cached record with mismatched identity %q/%q",
			host.Name, rt, out.Record.Operation, out.Record.Target))
		return tr
	}
	st, derr := decodeStoredType(out.Record.Data, host, rt)
	if derr != nil {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: delete unusable cached record: %w", host.Name, rt, delerr))
		}
		tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: discarded unusable cached result: %w", host.Name, rt, derr))
		return tr
	}
	return typeResultFromStored(st, host, rt)
}

// applyAnswers classifies the raw resolver outcome into a TypeResult.
// NXDOMAIN-equivalent results are legitimate completed observations
// (matching the Phase 4 "empty-but-successful = legitimate completed"
// convention); timeouts, temporary failures, and other resolver failures are
// never success.
func applyAnswers(tr TypeResult, answers []string, err error, clock runtime.Clock) TypeResult {
	if err != nil {
		kind := ErrFailure
		var qe *QueryError
		if errors.As(err, &qe) {
			kind = qe.Kind
		}
		switch kind {
		case ErrCancelled:
			tr.Status = TypeCancelled
		case ErrTimeout:
			tr.Status = TypeTimedOut
		case ErrNotFound:
			tr.Status = TypeCompleted
			tr.NXDOMAIN = true
		default: // ErrTemporary, ErrFailure, untyped errors
			tr.Status = TypeFailed
		}
		tr.Err = err
		return tr
	}
	tr.Status = TypeCompleted
	tr.IPs, tr.Hosts, tr.Malformed, tr.Truncated = normalizeAnswers(tr.Type, answers, tr.Host, clock)
	return tr
}

// normalizeAnswers converts raw resolver answers into typed Phase 2 assets:
// every string is re-validated through asset.NewIP / asset.NewHost (a
// resolver can never inject non-canonical assets), answers are deduplicated
// by Phase 2 identity, sorted by canonical value, and capped at
// MaxAnswersPerType. Answers that fail normalization are counted malformed
// and dropped. For CNAME, self-targets (answers identical to the queried
// host) are dropped: a host "pointing at itself" is no observation.
func normalizeAnswers(rt RecordType, answers []string, queried asset.Host, clock runtime.Clock) (ips []asset.IP, hosts []asset.Host, malformed int, truncated bool) {
	prov := asset.Provenance{Source: "dns", DiscoveredAt: clock.Now().UTC()}
	var rawIPs []asset.IP
	var rawHosts []asset.Host
	seenIPs := make(map[asset.Identity]bool)
	seenHosts := make(map[asset.Identity]bool)
	for _, a := range answers {
		switch rt {
		case TypeA, TypeAAAA:
			ip, err := asset.NewIP(a, prov)
			if err != nil {
				malformed++
				continue
			}
			if seenIPs[ip.Identity()] {
				continue
			}
			seenIPs[ip.Identity()] = true
			rawIPs = append(rawIPs, ip)
		case TypeCNAME:
			h, err := asset.NewHost(a, prov)
			if err != nil {
				malformed++
				continue
			}
			if h.Identity() == queried.Identity() {
				continue // self-target: no observation
			}
			if seenHosts[h.Identity()] {
				continue
			}
			seenHosts[h.Identity()] = true
			rawHosts = append(rawHosts, h)
		}
	}
	sort.Slice(rawIPs, func(i, j int) bool { return rawIPs[i].Addr.String() < rawIPs[j].Addr.String() })
	sort.Slice(rawHosts, func(i, j int) bool { return rawHosts[i].Name < rawHosts[j].Name })
	if len(rawIPs) > MaxAnswersPerType {
		truncated = true
		rawIPs = rawIPs[:MaxAnswersPerType]
	}
	if len(rawHosts) > MaxAnswersPerType {
		truncated = true
		rawHosts = rawHosts[:MaxAnswersPerType]
	}
	return rawIPs, rawHosts, malformed, truncated
}

// storeType is the cache write side: it persists the type's terminal
// classification as a statused Phase 3 record (completed incl. NXDOMAIN /
// failed / cancelled / incomplete-for-truncated), so a failed or cancelled
// type is never stored as success and a later run can inspect the partial
// state. A cancelled run still persists its terminal record using a
// detached, bounded context so the write cannot wedge shutdown (Phase 4
// convention).
func storeType(ctx context.Context, host asset.Host, rt RecordType, tr TypeResult, e env) TypeResult {
	key, err := typeKey(host, rt)
	if err != nil {
		tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: build cache key: %w", host.Name, rt, err))
		return tr
	}
	st := storedType{
		Target:    host.Identity().String(),
		Type:      rt,
		NXDOMAIN:  tr.NXDOMAIN,
		Truncated: tr.Truncated,
		IPs:       tr.IPs,
		Hosts:     tr.Hosts,
		Malformed: tr.Malformed,
	}
	data, err := json.Marshal(st)
	if err != nil {
		tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: encode result: %w", host.Name, rt, err))
		return tr
	}
	rec := cache.Record{
		Operation: Operation,
		Target:    host.Identity().String(),
		Status:    typeStatusToCache(tr.Status, tr.Truncated),
		Meta:      map[string]string{"type": string(rt)},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := e.cache.Put(storeCtx, key, rec); perr != nil {
		tr.Err = errors.Join(tr.Err, fmt.Errorf("dns: %s %s: cache put: %w", host.Name, rt, perr))
	}
	return tr
}

// assemble derives the typed assets and relationships from a host's type
// results: IP assets and host->address edges for every successful A/AAAA
// observation (of the input host and of its direct CNAME targets), and CNAME
// target host assets with host->target edges for every successful CNAME
// observation. Relationships are deduplicated by edge identity and sorted
// deterministically.
func assemble(types []TypeResult) (ips []asset.IP, targets []asset.Host, rels []asset.Relationship) {
	relSet := make(map[asset.Relationship]bool)
	addRel := func(from asset.Identity, kind asset.RelationshipKind, to asset.Identity) {
		r, err := asset.NewRelationship(from, kind, to)
		if err != nil {
			// Cannot happen with validated identities; skip defensively.
			return
		}
		if relSet[r] {
			return
		}
		relSet[r] = true
		rels = append(rels, r)
	}
	for _, tr := range types {
		if tr.Status != TypeCompleted || tr.NXDOMAIN {
			continue
		}
		from := tr.Host.Identity()
		switch tr.Type {
		case TypeA, TypeAAAA:
			for _, ip := range tr.IPs {
				addRel(from, asset.RelationshipHostToIP, ip.Identity())
			}
			ips = append(ips, tr.IPs...)
		case TypeCNAME:
			for _, h := range tr.Hosts {
				addRel(from, asset.RelationshipHostToCNAME, h.Identity())
			}
			targets = append(targets, tr.Hosts...)
		}
	}
	return mergeIPs(ips), mergeHosts(targets), sortRelationships(rels)
}

// classifyHost maps a host's per-type outcomes to its overall status,
// deterministically, in priority order:
//
//   - any cancelled type -> cancelled (run teardown; never success)
//   - any truncated retention -> incomplete (the captured set is incomplete
//     by definition, Phase 4 convention)
//   - any timed-out type -> incomplete (partial results retained)
//   - failed with at least one completed type -> incomplete (partial)
//   - every attempted type failed -> failed
//   - otherwise (all types completed, including NXDOMAIN and legitimate
//     empty answers) -> completed
func classifyHost(types []TypeResult) Status {
	var completed, failed, timedOut, cancelled, truncated bool
	for _, tr := range types {
		switch tr.Status {
		case TypeCompleted:
			completed = true
		case TypeFailed:
			failed = true
		case TypeTimedOut:
			timedOut = true
		case TypeCancelled:
			cancelled = true
		}
		if tr.Truncated {
			truncated = true
		}
	}
	switch {
	case cancelled:
		return StatusCancelled
	case truncated:
		return StatusIncomplete
	case timedOut:
		return StatusIncomplete
	case failed && completed:
		return StatusIncomplete
	case failed:
		return StatusFailed
	default:
		return StatusCompleted
	}
}

// cancelledOrTimedOut maps a context error to a TypeStatus: a deadline is a
// timed-out type, any other cancellation is a cancelled type.
func cancelledOrTimedOut(err error) TypeStatus {
	if errors.Is(err, context.DeadlineExceeded) {
		return TypeTimedOut
	}
	return TypeCancelled
}
