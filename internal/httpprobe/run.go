package httpprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"syscall"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/version"
)

// Hard caps for one probe target. These are fixed constants, deliberately NOT
// configuration: they bound what the pipeline retains, so a hostile or
// misbehaving server can never grow memory or cache records without bound,
// and — like the DNS pipeline's answer cap — they must never enter cache
// keys: a completed entry written under the current caps stays valid under
// any future caps that only retain more, and truncated entries are stored
// incomplete (never served) under every cap.
const (
	// MaxRedirects bounds how many in-scope redirect hops one probe may
	// follow. The observed chain is recorded at most MaxRedirects+1 entries
	// (the followed hops plus the cap-exceeding hop, which is observed but
	// never requested). Exceeding the cap marks the probe truncated.
	MaxRedirects = 10

	// MaxHeaderBytes bounds the size of one response's header block. The
	// production transport enforces it via http.Transport's
	// MaxResponseHeaderBytes; a server that exceeds it aborts the response,
	// and the probe is truncated.
	MaxHeaderBytes = 64 << 10 // 64 KiB

	// MaxHeaders bounds how many response header entries are retained per
	// probe (the header block itself is byte-bounded by MaxHeaderBytes).
	// Retention beyond the cap is dropped and the probe is truncated.
	MaxHeaders = 128

	// MaxBodyBytes bounds how many response body bytes are counted per
	// probe (1 MiB per the 5B spec). Body content is never retained — bytes
	// are counted only — and a body larger than the cap marks the probe
	// truncated.
	MaxBodyBytes = 1 << 20 // 1 MiB

	// MaxConcurrentPerHost bounds how many requests one host may have in
	// flight concurrently. The current design submits exactly one job per
	// host and probes its two targets sequentially, so at most 1 concurrent
	// request per host is ever observed — below this cap. The constant is
	// the contract for future multi-target-per-host work: the actual bound
	// must never exceed it (the per-host concurrency test pins this).
	MaxConcurrentPerHost = 2
)

// requestTimeoutDefault is the per-request deadline applied around every
// outbound request (slowloris protection), on top of the transport's
// response-header timeout. The budget chain is strict and invariant:
// per-request 10 s ⊆ per-job 30 s ⊆ shutdown grace 15 s + force 30 s.
const requestTimeoutDefault = 10 * time.Second

// userAgent identifies RavenRecon's probes to the probed server.
var userAgent = "RavenRecon/" + version.Version

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

// Config configures one HTTP probing run.
type Config struct {
	// Concurrency and QueueSize configure the single runtime pool that owns
	// all scheduling for this run: exactly one job per input host is
	// submitted, and the pool owns concurrency, cancellation, per-job
	// deadlines, and shutdown. Concurrency must be positive.
	Concurrency int
	QueueSize   int

	// Timeout is the per-job deadline at pool level (0 disables it;
	// DefaultConfig sets a sane value). The deadline covers the central
	// request-limiter waits and the requests themselves.
	Timeout time.Duration

	// RequestTimeout is the per-request deadline applied around every
	// outbound request (slowloris protection; DefaultConfig sets 10 s), on
	// top of the transport's response-header timeout. Zero means the 10 s
	// default. It is clamped to Timeout when the job deadline is smaller,
	// so the budget chain request ⊆ job always holds.
	RequestTimeout time.Duration

	// Rate and Burst configure the run's single central token-bucket
	// limiter (the runtime engine's Limiter), which paces OUTBOUND
	// REQUESTS: every request that misses the cache waits for a token
	// before dispatch — including each followed redirect hop — so the
	// aggregate request dispatch rate is bounded regardless of
	// concurrency. Rate <= 0 disables pacing; Burst < 1 means 1.
	//
	// The pool's own job-start rate limiting is disabled (Rate 0): per-
	// request pacing subsumes job-start pacing — every outbound operation
	// is individually gated — and the two would otherwise double-throttle
	// each other.
	Rate  float64
	Burst int

	// Cache, when non-nil, enables cache-before-execute per probe target:
	// each probe first derives the Phase 3 key and returns the stored
	// result on a usable hit; on a miss it executes the probe and stores a
	// statused record. Nil disables caching. A cache hit performs zero
	// network requests.
	Cache cache.Cache

	// Transport performs the HTTP round trips. Nil means a bounded
	// production transport: a clone of http.DefaultTransport with
	// MaxResponseHeaderBytes set to MaxHeaderBytes, a 30 s response-header
	// timeout, and proxy support disabled (probing always goes direct;
	// environment proxies are never consulted, so a stray HTTP_PROXY
	// cannot silently reroute a recon run).
	//
	// An injected transport is used exactly as given — the caller owns its
	// timeouts and header caps. Tests inject hermetic loopback transports.
	Transport http.RoundTripper

	// Clock is the time source for provenance timestamps and the central
	// request limiter. Nil means the wall clock; tests inject a fake clock
	// for deterministic assertions.
	Clock runtime.Clock
}

// DefaultConfig returns a Config with documented defaults. Concurrency and
// the per-job timeout are consistent with the Phase 4 conventions (the
// timeout matches exactly); the request rate is the documented conservative
// default for pacing outbound HTTP requests.
func DefaultConfig() Config {
	return Config{
		Concurrency:    8,
		QueueSize:      256,
		Timeout:        30 * time.Second,
		RequestTimeout: requestTimeoutDefault,
		Rate:           20,
		Burst:          1,
	}
}

// env is the per-run plumbing shared by every job. It is immutable after
// construction; the limiter, the cache, and the transport are internally
// synchronized, and ips is read-only.
type env struct {
	transport http.RoundTripper
	cache     cache.Cache
	limiter   *runtime.Limiter // nil when pacing is disabled
	clock     runtime.Clock
	// requestTimeout is the per-request deadline applied around every
	// outbound request (0 disables it). It is clamped to the job timeout at
	// construction, so the budget chain request ⊆ job always holds.
	requestTimeout time.Duration
	// ips maps a canonical host name to its caller-provided resolved
	// address (a DNS-pipeline observation). Probing itself observes no
	// addresses; the map only feeds ip->port relationship edges.
	ips map[string]asset.IP
}

// Probe probes hosts within the declared target domain and returns the typed
// observations, Phase 2 assets, and relationships for every input host.
//
// The host list is validated at the boundary first: every input host must be
// a canonical Phase 2 host (asset.NewHost in canonical form) and the target
// domain itself or a subdomain of it. Any invalid or out-of-scope host
// rejects the whole call with an error BEFORE a single request is issued.
// Hosts are deduplicated by Phase 2 identity and processed in sorted
// canonical order.
//
// ips optionally carries the caller-provided resolved addresses for the
// hosts (for example the DNS pipeline's observations), keyed by canonical
// host name. Every key must itself be canonical and in scope, and every
// value a canonical Phase 2 IP asset; an invalid entry rejects the whole
// call. Probing dials through the configured transport — it never dials an
// address directly — and the provided addresses only attach ip->port
// relationship edges for ports observed open. At most one address per host
// can be attached (see "Known limitations").
//
// One bounded runtime.Pool owns all scheduling: exactly one job per host,
// per-job deadlines, context cancellation, and one central request limiter
// pacing outbound requests. Probe's pool shutdown is the join point; the
// returned Report always carries whatever each job observed, including on
// cancellation or forced shutdown. When cfg.Cache is enabled, each probe
// target is cache-before-execute: a completed, unexpired record for the
// exact key serves the target without any network request.
func Probe(ctx context.Context, domain asset.Domain, hosts []asset.Host, ips map[string]asset.IP, cfg Config) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("httpprobe: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("httpprobe: %w", err)
	}
	if err := validateScope(domain); err != nil {
		return Report{}, err
	}

	// Boundary: every input host must be canonical and in scope; rejection
	// happens before any pool or limiter exists. The Phase 4 validateTarget
	// pattern, implemented locally because internal/httpprobe must not
	// import internal/discovery.
	hosts, err := normalizeInputHosts(hosts, domain)
	if err != nil {
		return Report{}, err
	}
	if ips == nil {
		ips = make(map[string]asset.IP)
	}
	ips, err = normalizeInputIPs(ips, domain)
	if err != nil {
		return Report{}, err
	}
	if len(hosts) == 0 {
		// Nothing to probe: return an empty report without starting a
		// pool.
		return Report{Target: domain}, nil
	}

	e, err := buildEnv(cfg, ips)
	if err != nil {
		return Report{}, err
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		// Job-start rate limiting is deliberately disabled: the central
		// request limiter paces every outbound request, which subsumes
		// job-start pacing (see Config.Rate).
		Rate:  0,
		Burst: 0,
	})
	if err != nil {
		return Report{}, fmt.Errorf("httpprobe: create worker pool: %w", err)
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
			results[i] = probeHost(jctx, h, domain, e)
			return nil, nil
		}}); err != nil {
			results[i] = HostResult{
				Host:   h,
				Status: StatusCancelled,
				Err:    fmt.Errorf("httpprobe: submit %s: %w", h.Name, err),
			}
			// The run context is done or the pool is closing; every host
			// behind this one was never submitted and keeps its initialized
			// cancelled status with the cause attached.
			for j := i + 1; j < len(hosts); j++ {
				results[j].Err = fmt.Errorf("httpprobe: not submitted: %w", ctx.Err())
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
		return report, fmt.Errorf("httpprobe: pool shutdown: %w", shutdownErr)
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

// buildEnv assembles the shared per-run plumbing: the transport (production
// bounded default or the injected one), the single central request limiter
// (runtime.NewLimiter — the same token-bucket machinery the pool uses
// internally), and the caller-provided address map. Rate <= 0 disables
// pacing.
func buildEnv(cfg Config, ips map[string]asset.IP) (env, error) {
	transport := cfg.Transport
	if transport == nil {
		transport = newTransport()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = wallClock{}
	}
	// The effective per-request deadline: the 10 s spec default, clamped to
	// the job timeout when that is smaller, so the budget chain request ⊆
	// job never breaks even under a misconfigured Config.
	rt := cfg.RequestTimeout
	if rt == 0 {
		rt = requestTimeoutDefault
	}
	if cfg.Timeout > 0 && rt > cfg.Timeout {
		rt = cfg.Timeout
	}
	e := env{transport: transport, cache: cfg.Cache, clock: clock, requestTimeout: rt, ips: ips}
	if cfg.Rate > 0 {
		burst := cfg.Burst
		if burst < 1 {
			burst = 1
		}
		l, err := runtime.NewLimiter(cfg.Rate, float64(burst), runtime.WithClock(clock))
		if err != nil {
			return env{}, fmt.Errorf("httpprobe: create request rate limiter: %w", err)
		}
		e.limiter = l
	}
	return e, nil
}

// newTransport returns the bounded production transport: a clone of
// http.DefaultTransport with an explicit response-header byte cap, a
// response-header timeout, and direct connection only (environment proxies
// are never consulted).
//
// TLS handshake failures are tagged at the dial boundary: DialTLSContext
// performs the handshake and wraps ANY handshake error in the typed
// tlsHandshakeError sentinel, so classification never depends on matching
// error text (server-controlled bytes can reach error strings via
// textproto.ProtocolError and net/http's badStringError, so text matching
// is spoofable). Dial-level failures — connection refused, DNS failures,
// dial timeouts — happen in DialContext BEFORE the handshake and pass
// through untagged, keeping their own classification.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxResponseHeaderBytes = MaxHeaderBytes
	t.ResponseHeaderTimeout = 30 * time.Second
	t.Proxy = nil // direct only: a stray environment proxy must never silently reroute probing
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Dial through the transport's own DialContext so dial-level
		// failures (refused, DNS, timeout) keep the classification the
		// default TLS path gives them; only the handshake itself is
		// tagged.
		plain, err := t.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The transport normally derives ServerName from the request host
		// (addTLS); with a custom dialer the address is all we have.
		// tls.DialWithDialer infers it the same way.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg := t.TLSClientConfig.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" && net.ParseIP(host) == nil {
			cfg.ServerName = host
		}
		// The transport applies TLSHandshakeTimeout only on its own TLS
		// path (addTLS); the custom dialer must bound the handshake
		// itself. A timeout surfaces as context.DeadlineExceeded wrapped
		// in the sentinel and classifies failed/timeout, exactly like the
		// default path's handshake-timeout error.
		hsCtx := ctx
		var cancel context.CancelFunc
		if d := t.TLSHandshakeTimeout; d > 0 {
			hsCtx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
		tlsConn := tls.Client(plain, cfg)
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			plain.Close()
			return nil, &tlsHandshakeError{err: err}
		}
		return tlsConn, nil
	}
	return t
}

// tlsHandshakeError tags an error as a TLS handshake failure observed at the
// dial boundary (the production transport's DialTLSContext). Classification
// matches this type structurally — never error text — so a hostile server
// that embeds "tls:"-looking text in a malformed response cannot fabricate
// a TLS observation. Unwrap keeps the underlying stdlib error reachable for
// the typed checks (tls.AlertError, tls.RecordHeaderError,
// tls.CertificateVerificationError, the x509 set) and for context-error
// classification (cancellation and deadline checks run before the TLS
// checks, so a cancelled or timed-out handshake keeps its own outcome).
type tlsHandshakeError struct{ err error }

func (e *tlsHandshakeError) Error() string {
	return "httpprobe: tls handshake failed: " + e.err.Error()
}
func (e *tlsHandshakeError) Unwrap() error { return e.err }

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
// request.
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
			return nil, fmt.Errorf("httpprobe: invalid host %q: %w", h.Name, err)
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

// normalizeInputIPs validates the caller-provided resolved-address map at
// the boundary: every key must be a canonical host name in scope and every
// value a canonical Phase 2 IP asset. Rejects the whole call with the first
// offending entry's cause — before any request. A nil map is normalized to
// an empty map.
func normalizeInputIPs(ips map[string]asset.IP, domain asset.Domain) (map[string]asset.IP, error) {
	out := make(map[string]asset.IP, len(ips))
	for name, ip := range ips {
		if err := validateInputHost(asset.Host{Name: name}, domain); err != nil {
			return nil, fmt.Errorf("httpprobe: invalid resolved-address key: %w", err)
		}
		nip, err := asset.NewIP(ip.Addr.String(), ip.Prov)
		if err != nil {
			return nil, fmt.Errorf("httpprobe: invalid resolved address for %q: %w", name, err)
		}
		if nip.Addr.String() != ip.Addr.String() {
			return nil, fmt.Errorf("httpprobe: resolved address %q for %q is not in canonical form (normalized %q)",
				ip.Addr, name, nip.Addr)
		}
		out[name] = nip
	}
	return out, nil
}

// probeHost probes one input host's two targets — http://host/ and
// https://host/ — in stable order, then derives the typed assets and
// relationships via assemble. A target never attempted because the job
// context was already done is recorded cancelled (the runtime's convention
// for work that never started); the probe target URL itself is always
// recorded on the result regardless of outcome.
func probeHost(ctx context.Context, host asset.Host, domain asset.Domain, e env) HostResult {
	var probes []ProbeResult
	for _, scheme := range []string{"http", "https"} {
		target, err := probeTargetURL(host, scheme, e.clock)
		if err != nil {
			// Cannot happen with a canonical host and a fixed scheme;
			// record the defensive failure rather than dropping the
			// target.
			probes = append(probes, ProbeResult{
				Host: host, Scheme: scheme, Status: ProbeFailed,
				FailureReason: ReasonOther, Executed: true, Err: err,
			})
			continue
		}
		if ctx.Err() != nil {
			// Cancelled before this target could be attempted: report
			// cancelled, never success, and never issue a request.
			probes = append(probes, ProbeResult{
				Host: host, URL: target, Scheme: scheme, Status: ProbeCancelled,
				Executed: true, Err: ctx.Err(),
			})
			continue
		}
		probes = append(probes, probeTarget(ctx, host, target, domain, e, scheme))
	}
	return assemble(host, probes, &e)
}

// probeTargetURL builds the canonical probe target URL for one scheme:
// scheme://host/ (the canonical form removes the default port, so the probe
// target identity is url:http://host or url:https://host). The URL is the
// probe's identity and cache-key target; it is never a dial address — the
// transport resolves and dials.
func probeTargetURL(host asset.Host, scheme string, clock runtime.Clock) (asset.URL, error) {
	raw := scheme + "://" + host.Name + "/"
	return asset.ParseURL(raw, asset.Provenance{
		Source:       "http-probe",
		DiscoveredAt: clock.Now().UTC(),
	})
}

// probeTarget probes one probe target with cache-before-execute semantics:
// derive the Phase 3 key, serve the stored result on a usable hit (a hit
// performs zero network requests), otherwise wait on the central limiter,
// execute the bounded probe, and store a statused record.
func probeTarget(ctx context.Context, host asset.Host, target asset.URL, domain asset.Domain, e env, scheme string) ProbeResult {
	pr := ProbeResult{Host: host, URL: target, Scheme: scheme, Executed: true}

	if e.cache != nil {
		pr = lookupProbe(ctx, host, target, domain, pr, e)
		if pr.Status != "" {
			// A completed cache hit, or a key-build failure that already
			// classified the probe; either way no request is issued.
			return pr
		}
	}
	if ctx.Err() != nil {
		// Cancelled before the request could be issued: report cancelled,
		// never success, and never issue a request.
		pr.Status = ProbeCancelled
		pr.Err = ctx.Err()
		return pr
	}

	pr = doProbe(ctx, host, target, domain, e, pr)

	if e.cache != nil {
		pr = storeProbe(ctx, host, target, domain, pr, e)
	}
	return pr
}

// doProbe executes one bounded probe: a GET on the target, following only
// in-scope redirects (up to MaxRedirects), with bounded header retention and
// bounded body counting, and typed failure classification. Every outbound
// request — the probe itself and each followed redirect hop — waits on the
// central limiter first.
func doProbe(ctx context.Context, host asset.Host, target asset.URL, domain asset.Domain, e env, pr ProbeResult) ProbeResult {
	cur := target
	var hops []RedirectHop
	statusCode := 0
	finalURL := target
	var headers []HeaderEntry
	var size int64
	var hdrTrunc, bodyTrunc bool
	var reason FailureReason
	truncated := false
	probeErr := error(nil)
	var tlsDiag error // the terminal iteration's TLS capture diagnostic (5C)

	// The redirect walk: each iteration requests cur and decides whether to
	// follow. The final response's headers and body are retained (bounded);
	// intermediate redirect responses contribute only their Location.
	for {
		if err := waitForToken(ctx, e); err != nil {
			pr.Status, pr.FailureReason, pr.Err = classifyContextError(err)
			// The observed redirect chain and the URL the next request
			// would have targeted are retained here too: a probe cut off
			// during a token wait — after hops were followed — still
			// carries the last targeted URL as its final URL and the
			// observed hops, mirroring the round-trip error path below.
			// The TLS flag and metadata must not carry over from a
			// previously followed hop either: the terminal path completed
			// no handshake, so both are cleared here (the round-trip error
			// path below makes the same MEDIUM-5 reset).
			pr.FinalURL = cur
			pr.RedirectChain = hops
			pr.TLS = false
			pr.TLSMeta = nil
			return pr
		}

		// The per-request deadline covers the round trip AND the draining
		// of the response body: cancelling the request context before the
		// body is fully read aborts the read, so the deadline context must
		// outlive countBody. The deferred cancel fires when the iteration
		// ends; at most MaxRedirects+1 such contexts can be pending, each
		// firing at its own deadline or at doProbe's return — bounded, no
		// leak.
		reqCtx := ctx
		if e.requestTimeout > 0 {
			var cancel context.CancelFunc
			reqCtx, cancel = context.WithTimeout(ctx, e.requestTimeout)
			defer cancel()
		}
		// finalURL is the last URL actually requested: assign it before the
		// round trip so a failed request still records the URL it targeted
		// (the probe target, or the last followed hop) as the final URL —
		// consistent with the redirect chain, and required for stored
		// completed observations (conn_refused / tls / timeout) to be
		// re-validated and served as cache hits.
		finalURL = cur
		resp, err := roundTrip(reqCtx, cur, e)
		if err != nil {
			st, fr := classifyProbeError(ctx, err)
			pr.Status = st
			pr.FailureReason = fr
			pr.Truncated = st == ProbeTruncated
			pr.Err = err
			// The failed request still carries the URL it targeted as the
			// final URL, and the walk's observed redirect chain is retained —
			// both are set here because the early return bypasses the
			// post-loop assignments below (see the finalURL comment above).
			pr.FinalURL = cur
			pr.RedirectChain = hops
			// The TLS flag must not carry over from a previously followed
			// hop: the terminal request completed no handshake, so the flag
			// is false on this terminal path — a completed conn_refused/tls
			// observation with a stale true would contradict its own reason
			// and be refused by decodeStoredProbe forever (see cache.go).
			// The captured TLS metadata (5C) is cleared for the same
			// reason: no handshake completed, so nothing was observed.
			pr.TLS = false
			pr.TLSMeta = nil
			return pr
		}

		statusCode = resp.StatusCode
		tlsOK := resp.TLS != nil
		// The TLS flag is recorded on EVERY terminal path: the final
		// response, an out-of-scope redirect (observed, never requested),
		// and a cap-exceeding redirect each carry the handshake state of
		// the response that ended the walk — an https probe that completed
		// its handshake reports TLS=true no matter how the walk ends, and
		// the stored record carries the same value.
		pr.TLS = tlsOK
		// TLS metadata capture (5C): the leaf certificate of the handshake
		// that ended on THIS response. Like the flag, the metadata is
		// overwritten per iteration — a followed hop's handshake state can
		// never leak into the terminal observation — and the terminal
		// iteration's capture diagnostic (material drops, e.g. a chain
		// deeper than the asset model cap) is joined into the probe's
		// diagnostics only when this response ends the walk.
		if tlsOK {
			meta, cerr := captureTLS(resp.TLS, e.clock)
			pr.TLSMeta = meta
			tlsDiag = cerr
		} else {
			pr.TLSMeta = nil
			tlsDiag = nil
		}
		loc := resp.Header.Get("Location")

		if isRedirectCode(statusCode) && loc != "" {
			hop, inScope := recordHop(cur, loc, domain, e.clock)
			hops = append(hops, hop)
			if !inScope {
				// Out-of-scope target: observed, NEVER requested. The
				// redirect response itself is the final response.
				headers, hdrTrunc = boundedHeaders(resp.Header)
				size, bodyTrunc, err = countBody(resp.Body)
				probeErr = errors.Join(probeErr, err)
				truncated = truncated || hdrTrunc || bodyTrunc
				break
			}
			if len(hops) > MaxRedirects {
				// The cap-exceeding hop is observed but never requested;
				// the probe is truncated-incomplete by definition.
				headers, hdrTrunc = boundedHeaders(resp.Header)
				size, bodyTrunc, err = countBody(resp.Body)
				probeErr = errors.Join(probeErr, err)
				truncated = true
				reason = ReasonTooManyRedirects
				break
			}
			hops[len(hops)-1].Followed = true
			cur = hop.URL
			resp.Body.Close()
			continue
		}

		// Final response.
		headers, hdrTrunc = boundedHeaders(resp.Header)
		size, bodyTrunc, err = countBody(resp.Body)
		probeErr = errors.Join(probeErr, err)
		truncated = truncated || hdrTrunc || bodyTrunc
		break
	}

	pr.StatusCode = statusCode
	pr.FinalURL = finalURL
	pr.RedirectChain = hops
	pr.Headers = headers
	pr.ResponseSize = size
	pr.Truncated = truncated
	pr.FailureReason = reason
	pr.Err = errors.Join(probeErr, tlsDiag)
	if pr.Status == "" {
		if truncated {
			pr.Status = ProbeTruncated
		} else {
			pr.Status = ProbeCompleted
		}
	}
	return pr
}

// waitForToken gates one outbound request on the central limiter. A nil
// limiter passes through.
func waitForToken(ctx context.Context, e env) error {
	if e.limiter == nil {
		return nil
	}
	return e.limiter.Wait(ctx)
}

// roundTrip issues one GET request through the run's transport. The caller
// provides the context (in doProbe the per-request deadline context, which
// must outlive this call so the response body can be drained); the request
// carries the canonical target URL and a fixed RavenRecon user agent; the
// transport resolves and dials (or, in tests, routes to a hermetic server).
func roundTrip(ctx context.Context, target asset.URL, e env) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		// A canonical asset URL always builds; keep the defensive path.
		return nil, fmt.Errorf("httpprobe: build request for %s: %w", target, err)
	}
	req.Header.Set("User-Agent", userAgent)
	return e.transport.RoundTrip(req)
}

// isRedirectCode reports whether status is a followable redirect status.
func isRedirectCode(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// countBody drains a response body counting bytes, capped at MaxBodyBytes+1
// so truncation is detectable. Body content is never retained — bytes are
// counted only. The reported size is capped at MaxBodyBytes; exceeded
// reports that the body was larger than the cap (the probe is then
// truncated-incomplete by definition). Read failures after a response was
// received are returned as diagnostics, never as probe failures: the
// response itself is the observation.
func countBody(body io.ReadCloser) (size int64, exceeded bool, err error) {
	defer body.Close()
	n, rerr := io.Copy(io.Discard, io.LimitReader(body, MaxBodyBytes+1))
	if rerr != nil {
		err = fmt.Errorf("httpprobe: read body: %w", rerr)
	}
	if n > MaxBodyBytes {
		return MaxBodyBytes, true, err
	}
	return n, false, err
}

// classifyContextError maps a limiter-wait error to a probe outcome: a
// deadline is a failed timed-out probe, any other cancellation is a
// cancelled probe.
func classifyContextError(err error) (ProbeStatus, FailureReason, error) {
	if errors.Is(err, context.DeadlineExceeded) {
		return ProbeFailed, ReasonTimeout, err
	}
	return ProbeCancelled, ReasonOther, err
}

// classifyProbeError maps a round-trip error to a probe outcome, in a fixed
// priority order:
//
//   - context cancellation -> cancelled (our own teardown)
//   - deadline -> failed, timeout (the per-request deadline, the per-job
//     deadline, or the transport's response-header timeout fired)
//   - DNS resolution failure -> failed, dns (the dial could not resolve the
//     hostname; a DNS timeout is a timeout)
//   - net-level timeout -> failed, timeout
//   - connection refused -> COMPLETED, conn_refused: a legitimate negative
//     observation, the service is absent on this port
//   - TLS handshake failure (including certificate verification failures) ->
//     COMPLETED, tls: a legitimate negative observation, https is not
//     served on this endpoint from RavenRecon's trust perspective. Tagged
//     structurally at the dial boundary (tlsHandshakeError) or matched by
//     typed stdlib errors — never by error text: the stdlib embeds raw
//     server bytes in some error strings (textproto.ProtocolError quotes
//     the offending header line; net/http's badStringError quotes the
//     status line), so text matching is spoofable.
//   - response-header block over the transport cap -> truncated. The
//     stdlib aborts such responses with the EXACT message
//     "net/http: server response headers exceeded <cap> bytes; aborted"
//     where <cap> is the transport's MaxResponseHeaderBytes (ours:
//     MaxHeaderBytes); the abort replaces whatever read error occurred
//     and is then %w-wrapped by the transport, so the check walks the %w
//     chain and requires exact equality with that message on some wrapped
//     error — never a substring: a server-tainted error (for example a
//     malformed header line containing the same words) can never
//     fabricate truncation. If a future stdlib changes the message or
//     stops wrapping it, this degrades to failed/other — the safe
//     direction (a genuine cap hit is then re-probed instead of being
//     served as a completed observation).
//   - anything else -> failed, other
func classifyProbeError(ctx context.Context, err error) (ProbeStatus, FailureReason) {
	if errors.Is(err, context.Canceled) {
		return ProbeCancelled, ReasonOther
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ProbeFailed, ReasonTimeout
	}
	if ctx.Err() != nil {
		// The job context fired while the request was in flight; the
		// surfaced error may not wrap the context error directly.
		st, fr, _ := classifyContextError(ctx.Err())
		return st, fr
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return ProbeFailed, ReasonTimeout
		}
		return ProbeFailed, ReasonDNS
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ProbeFailed, ReasonTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ProbeCompleted, ReasonConnRefused
	}
	if isTLSError(err) {
		return ProbeCompleted, ReasonTLS
	}
	// The stdlib transport aborts a response whose header block exceeds
	// MaxResponseHeaderBytes with a fixed, EXACT message embedding OUR cap
	// (net/http/transport.go: "net/http: server response headers exceeded
	// %d bytes; aborted" with the transport's MaxResponseHeaderBytes). The
	// abort REPLACES whatever read error occurred — the server's own bytes
	// never survive into it — and the transport then wraps it with %w
	// ("net/http: HTTP/1.x transport connection broken: ..."), so a
	// round-trip error surfaces several wraps deep. The check therefore
	// walks the %w chain and requires exact equality with the
	// stdlib-constructed message on SOME wrapped error; it is never a
	// substring match on the top-level text, because every error class
	// that embeds server bytes (textproto.ProtocolError, net/http's
	// badStringError) quotes or prefixes the text and a hostile server
	// could otherwise fabricate truncation. Checked last: no network error
	// carries this message. If a future stdlib changes the message or
	// stops wrapping it, this degrades to failed/other — the safe
	// direction (a genuine cap hit is then re-probed instead of being
	// served as a completed observation).
	if isHeaderCapAbort(err) {
		return ProbeTruncated, ReasonNone
	}
	return ProbeFailed, ReasonOther
}

// isHeaderCapAbort reports whether err — or any error it wraps through the
// stdlib's %w layers (persistConn.roundTrip's "HTTP/1.x transport connection
// broken" wrap, and *url.Error's wrap when a client is used) — is exactly
// the header-cap abort message. Exact equality on a wrapped error, never a
// substring of the top-level text: the abort message is constructed by the
// stdlib from OUR cap and replaces the (server-tainted) read error, so a
// hostile server can neither produce the exact message nor inject it into
// the chain.
func isHeaderCapAbort(err error) bool {
	want := fmt.Sprintf("net/http: server response headers exceeded %d bytes; aborted", MaxHeaderBytes)
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == want {
			return true
		}
	}
	return false
}

// isTLSError reports whether err stems from a TLS handshake failure:
// the dial-boundary sentinel (the production transport's DialTLSContext
// tags every handshake error), protocol alerts, record-header failures
// ("first record does not look like a TLS handshake"), certificate
// verification failures, or the x509 error set. Classification is strictly
// structural — there is deliberately NO error-text fallback: the stdlib
// embeds raw server bytes in some error strings, so matching "tls:" text
// would let a hostile server fabricate a TLS observation (and with it an
// open-port report and a completed cache record).
func isTLSError(err error) bool {
	var hsErr *tlsHandshakeError
	if errors.As(err, &hsErr) {
		return true
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return true
	}
	var invalidErr *x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return true
	}
	var unknownErr *x509.UnknownAuthorityError
	if errors.As(err, &unknownErr) {
		return true
	}
	var hostnameErr *x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var rootsErr *x509.SystemRootsError
	if errors.As(err, &rootsErr) {
		return true
	}
	return false
}
