package crawl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// Operation is the cache operation name for katana crawling.
const Operation = "crawl.katana"

// Limits.
const (
	// MaxTotalURLs is the global cap for URLs retained per crawl operation.
	MaxTotalURLs = 100000
	// MaxPerHostURLs is the per-host cap.
	MaxPerHostURLs = 1000
	// DefaultDepth is the default crawl depth (katana -d).
	DefaultDepth = 3
	// DefaultConcurrency is the default katana concurrency (-c).
	DefaultConcurrency = 10
	// DefaultRateLimit is the default katana rate limit (-rl).
	DefaultRateLimit = 150
	// DefaultPerToolTimeout is the per-tool execution timeout (2m).
	DefaultPerToolTimeout = 2 * time.Minute
	// DefaultKatanaTimeout is the katana internal request timeout (-timeout 5).
	DefaultKatanaTimeout = 5
)

// Config controls one crawl invocation.
type Config struct {
	// Depth is the crawl depth (katana -d). 0 means DefaultDepth; values >3
	// are clamped to 3 (never -headless, never -aff true, depth ≤3).
	Depth int
	// Timeout is the per-tool execution timeout that encloses each katana
	// process. 0 means DefaultPerToolTimeout (2m, always on).
	Timeout time.Duration
	// Concurrency is the katana concurrency (-c). 0 means DefaultConcurrency.
	Concurrency int
	// RateLimit is the katana rate limit (-rl). 0 means DefaultRateLimit.
	RateLimit int
	// Cache, when non-nil, enables cache-before-execute. Nil disables caching.
	Cache cache.Cache
}

// Result is the outcome of one crawl operation.
type Result struct {
	// URLs are the canonical URLs discovered, deduplicated by Identity and
	// sorted by canonical string (deterministic).
	URLs []asset.URL
	// Diagnostics are human-readable notes (malformed lines, truncation, etc.).
	Diagnostics []string
	// Truncated reports that the retained set was cut at a cap.
	Truncated bool
	// FailedHosts counts hosts whose katana run failed outright: a runner
	// error (including a per-tool timeout), a non-zero exit without any
	// usable output, or an invocation that produced zero usable endpoints
	// while emitting malformed/unparseable lines (a broken output channel).
	// Whole-run cancellation is not counted here — it is reported via the
	// returned error. A whole-run abort before any per-host attempt (e.g.
	// a missing binary) counts every requested host. A non-zero count
	// means the corpus is partial: such results are stored as
	// cache.StatusIncomplete, never as StatusCompleted, so a broken run can
	// never serve as a completed cache hit and the next run re-executes.
	FailedHosts int
}

// Source adapts one active crawl corpus producer.
type Source interface {
	Crawl(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg Config) (Result, error)
}

// KatanaSource runs the katana binary when present.
type KatanaSource struct {
	runner   discovery.Runner
	lookPath discovery.LookupFunc
}

// NewKatanaSource constructs a KatanaSource. Nil runner means
// discovery.ExecRunner (production); nil lookPath means exec.LookPath.
func NewKatanaSource(runner discovery.Runner, lookPath discovery.LookupFunc) *KatanaSource {
	return &KatanaSource{runner: runner, lookPath: lookPath}
}

var _ Source = (*KatanaSource)(nil)

// katanaRequest mirrors the nested request object of modern katana -jsonl
// output. Only Endpoint is consumed; unknown fields (and the whole
// "response" object) are skipped by the struct decoder without retention.
type katanaRequest struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
}

// katanaRecord is one JSONL line emitted by katana -jsonl. Older versions
// emit the endpoint at the top level; modern versions nest it under
// request.endpoint (NEW-93 defect 2). Both shapes resolve.
type katanaRecord struct {
	Endpoint string         `json:"endpoint"`
	Source   string         `json:"source"`
	Tag      string         `json:"tag"`
	Request  *katanaRequest `json:"request"`
}

// resolvedEndpoint returns this record's endpoint: the legacy top-level
// field when set, otherwise the nested request.endpoint.
func (r *katanaRecord) resolvedEndpoint() string {
	if ep := strings.TrimSpace(r.Endpoint); ep != "" {
		return ep
	}
	if r.Request != nil {
		return strings.TrimSpace(r.Request.Endpoint)
	}
	return ""
}

// storedCrawl is the cache payload for a crawl operation.
type storedCrawl struct {
	Domain      string      `json:"domain"`
	URLs        []asset.URL `json:"urls"`
	Truncated   bool        `json:"truncated,omitempty"`
	Diagnostics []string    `json:"diagnostics,omitempty"`
}

// effectiveConfig returns cfg with zero fields resolved to defaults.
func effectiveConfig(cfg Config) Config {
	if cfg.Depth <= 0 {
		cfg.Depth = DefaultDepth
	}
	if cfg.Depth > 3 {
		cfg.Depth = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultPerToolTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}
	return cfg
}

// Crawl implements Source.
func (s *KatanaSource) Crawl(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg Config) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("crawl: context must not be nil")
	}
	// Validate domain via single normalization point.
	if _, err := asset.NewDomain(domain.Name, asset.Provenance{}); err != nil || domain.Name == "" {
		return Result{}, fmt.Errorf("crawl: invalid domain %q: %w", domain.Name, err)
	}
	canon, _ := asset.NewDomain(domain.Name, asset.Provenance{})
	if canon.Name != domain.Name {
		return Result{}, fmt.Errorf("crawl: domain %q is not canonical (expected %q)", domain.Name, canon.Name)
	}
	cfg = effectiveConfig(cfg)
	// Scope: filter hosts to in-domain canonical hosts; drop empties.
	hosts = filterHosts(domain, hosts)
	if len(hosts) == 0 {
		return Result{}, nil
	}
	// Deterministic host order: sorted by canonical name.
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	// Deduplicate hosts by identity (already canonical, but keep first-seen).
	hosts = dedupeHosts(hosts)

	lookPath := s.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	runner := s.runner
	if runner == nil {
		runner = discovery.ExecRunner{}
	}
	// Binary existence check: like Chaos, missing binary is StatusMissing, not error.
	katanaPath, err := lookPath("katana")
	if err != nil {
		// Missing binary: return an empty result with an explicit whole-run
		// failure signal, not an error. FailedHosts carries the abort
		// itself (NEW-85) so consumers never have to infer failure from
		// diagnostics presence.
		return Result{
			Diagnostics: []string{"katana not found: " + err.Error()},
			FailedHosts: len(hosts),
		}, nil
	}
	// Version detection for cache key (like discovery: version probe).
	version := detectKatanaVersion(ctx, runner, katanaPath)
	// Cache lookup: only when version known (Version=="" → no cache, like assetfinder).
	if cfg.Cache != nil && version != "" {
		key, kerr := crawlCacheKey(domain, hosts, cfg, version)
		if kerr == nil {
			out := cfg.Cache.Get(ctx, key)
			if out.IsHit() && out.Record != nil && out.Record.Status == cache.StatusCompleted {
				var sc storedCrawl
				if jerr := json.Unmarshal(out.Record.Data, &sc); jerr == nil {
					// Re-validate URLs through single normalization point before serving.
					valid := true
					for _, u := range sc.URLs {
						if _, perr := asset.ParseURL(u.String(), asset.Provenance{}); perr != nil {
							valid = false
							break
						}
						if h, ok := urlHost(u); !ok || !asset.InDomain(h.Name, domain.Name) {
							valid = false
							break
						}
					}
					if valid && sc.Domain == domain.Identity().String() {
						return Result{URLs: sc.URLs, Diagnostics: sc.Diagnostics, Truncated: sc.Truncated}, nil
					}
					// Self-heal: delete corrupt record best-effort and fall through.
					_ = cfg.Cache.Delete(ctx, key)
				}
			}
		}
	}

	// Execute crawl per host, bounded.
	var allCandidates []asset.URL
	var diagnostics []string
	malformed := 0
	truncated := false
	failedHosts := 0
	// hostErrs preserves the engine's per-host failure errors so a mid-run
	// cancellation can return them joined with ctx.Err() instead of
	// discarding the detail.
	var hostErrs []error

	// For determinism, process hosts in sorted order sequentially (bounded).
	for _, h := range hosts {
		if ctx.Err() != nil {
			return Result{URLs: allCandidates, Diagnostics: diagnostics, Truncated: truncated, FailedHosts: failedHosts},
				errors.Join(append(hostErrs, ctx.Err())...)
		}
		// Build katana argv: separate args, never shell-joined.
		targetURL := "https://" + h.Name
		args := []string{
			"-u", targetURL,
			"-d", fmt.Sprint(cfg.Depth),
			"-jc", "-xhr",
			"-aff=false",
			"-fs", "fqdn",
			"-kf", "all",
			"-rl", fmt.Sprint(cfg.RateLimit),
			"-c", fmt.Sprint(cfg.Concurrency),
			"-timeout", fmt.Sprint(DefaultKatanaTimeout),
			"-retry", "1",
			"-jsonl",
			"-o", "-",
			"-silent",
		}
		// Per-tool timeout encloses runner only (2m default).
		runCtx := ctx
		var cancel context.CancelFunc
		if cfg.Timeout > 0 {
			runCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		}
		res, rerr := runner.Run(runCtx, discovery.Cmd{Path: katanaPath, Args: args}, discovery.Limits{MaxOutput: discovery.DefaultMaxOutput})
		if cancel != nil {
			cancel()
		}
		if rerr != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("katana %s: %v", h.Name, rerr))
			if ctx.Err() == nil {
				// Not a whole-run cancellation: this host genuinely failed
				// (runner error or per-tool timeout).
				failedHosts++
			}
			// Always preserve the engine's error so a mid-run cancellation
			// returns it joined with the cancellation cause instead of
			// discarding the detail.
			hostErrs = append(hostErrs, fmt.Errorf("katana %s: %w", h.Name, rerr))
			continue
		}
		// Parse JSONL output: 4 MiB bounded capture.
		parsed, m, diag := parseKatanaOutput(res.Stdout, domain)
		malformed += m
		if diag != "" {
			diagnostics = append(diagnostics, diag)
		}
		// Per-host cap: deduplicate by identity, sort, cap at 1000.
		parsed = dedupeURLs(parsed)
		sort.Slice(parsed, func(i, j int) bool { return parsed[i].String() < parsed[j].String() })
		if len(parsed) > MaxPerHostURLs {
			parsed = parsed[:MaxPerHostURLs]
			truncated = true
			diagnostics = append(diagnostics, fmt.Sprintf("host %s truncated at %d", h.Name, MaxPerHostURLs))
		}
		allCandidates = append(allCandidates, parsed...)
		if res.StdoutTruncated {
			truncated = true
			diagnostics = append(diagnostics, fmt.Sprintf("host %s stdout truncated", h.Name))
		}
		// Non-zero exit with usable output is partial but we keep it; without
		// output the host counts as failed.
		if res.ExitCode != 0 && len(parsed) == 0 && !res.StdoutTruncated {
			diagnostics = append(diagnostics, fmt.Sprintf("katana %s exited %d", h.Name, res.ExitCode))
			failedHosts++
			hostErrs = append(hostErrs, fmt.Errorf("katana %s exited %d", h.Name, res.ExitCode))
			continue
		}
		// Exit-clean (or truncated stdout) with nothing usable among the
		// emitted lines — every line was malformed/unparseable: the host's
		// output channel is broken, the same failure class as a non-zero
		// exit without usable output (NEW-86). Counting it here keeps a
		// completed-empty cache store reachable only when every host truly
		// produced zero output AND zero errors/malformed lines.
		if m > 0 && len(parsed) == 0 {
			diagnostics = append(diagnostics,
				fmt.Sprintf("katana %s produced no usable endpoints (%d malformed line(s))", h.Name, m))
			failedHosts++
			hostErrs = append(hostErrs,
				fmt.Errorf("katana %s produced no usable endpoints (%d malformed line(s))", h.Name, m))
		}
	}
	if malformed > 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("malformed lines: %d", malformed))
	}
	// Global dedup, sort, total cap.
	allCandidates = dedupeURLs(allCandidates)
	sort.Slice(allCandidates, func(i, j int) bool { return allCandidates[i].String() < allCandidates[j].String() })
	if len(allCandidates) > MaxTotalURLs {
		allCandidates = allCandidates[:MaxTotalURLs]
		truncated = true
		diagnostics = append(diagnostics, fmt.Sprintf("total truncated at %d", MaxTotalURLs))
	}
	result := Result{URLs: allCandidates, Diagnostics: diagnostics, Truncated: truncated, FailedHosts: failedHosts}

	// A run interrupted by context cancellation is never reported as a clean
	// success: return the engine's per-host failure errors joined with the
	// cancellation cause so no detail is discarded (the partial corpus and
	// diagnostics still travel on the Result).
	if ctx.Err() != nil {
		return result, errors.Join(append(hostErrs, ctx.Err())...)
	}

	// Cache store policy: a run with failed hosts is partial — store it as
	// StatusIncomplete so it is never replayed as a completed hit (the cache
	// serves only StatusCompleted records) and the next run re-executes.
	// Truncated with the flag set is still completed (carve-out).
	//
	// FailedHosts classes: runner error; non-zero exit without usable
	// output; zero usable endpoints with malformed lines (NEW-86); and
	// whole-run aborts such as a missing binary (NEW-85). Consequently a
	// StatusCompleted record with an empty corpus is only ever written when
	// EVERY host ran cleanly — zero errors, zero unusable exits, zero
	// malformed lines: katana genuinely found nothing in scope.
	status := cache.StatusCompleted
	if result.FailedHosts > 0 {
		status = cache.StatusIncomplete
	}
	if cfg.Cache != nil && version != "" {
		if key, kerr := crawlCacheKey(domain, hosts, cfg, version); kerr == nil {
			sc := storedCrawl{Domain: domain.Identity().String(), URLs: result.URLs, Truncated: result.Truncated, Diagnostics: result.Diagnostics}
			if data, merr := json.Marshal(sc); merr == nil {
				rec := cache.Record{
					Operation: Operation,
					Target:    domain.Identity().String(),
					Tool:      cache.ToolInfo{Name: "katana", Version: version},
					Status:    status,
					Data:      data,
				}
				// Store with detached context if original cancelled (best-effort).
				storeCtx := ctx
				if ctx.Err() != nil {
					var cancel context.CancelFunc
					storeCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
				}
				_ = cfg.Cache.Put(storeCtx, key, rec)
			}
		}
	}
	return result, nil
}

// detectKatanaVersion tries to get katana version via "katana -version".
func detectKatanaVersion(ctx context.Context, runner discovery.Runner, katanaPath string) string {
	lookCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := runner.Run(lookCtx, discovery.Cmd{Path: katanaPath, Args: []string{"-version"}}, discovery.Limits{MaxOutput: 4 << 10})
	if err != nil {
		return ""
	}
	out := string(res.Stdout)
	if out == "" {
		out = string(res.Stderr)
	}
	out = strings.TrimSpace(out)
	// Extract semver-like token.
	// Simple pattern: vX.Y.Z
	for _, field := range strings.Fields(out) {
		if strings.Contains(field, ".") && (field[0] == 'v' || field[0] == 'V' || (field[0] >= '0' && field[0] <= '9')) {
			// Trim surrounding punctuation.
			f := strings.Trim(field, ",;()[]\"'")
			if f != "" {
				return f
			}
		}
	}
	// Fallback: try to find version substring via bytes.
	// Use discovery's tolerant pattern inline.
	// If still empty, return "" → no cache.
	return ""
}

// crawlCacheKey derives the cache key for a crawl operation. cfg must be
// effective (post-normalization): every value that shapes katana's retained
// output participates in the key — depth, the per-tool timeout budget, and
// the -c/-rl pacing flags (§11: keys cover every result-affecting input) —
// alongside the host scope and tool version.
func crawlCacheKey(domain asset.Domain, hosts []asset.Host, cfg Config, version string) (cache.Key, error) {
	// scopeHash: hex sha256 of sorted host names joined by ",".
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Name
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(names, ",")))
	scopeHash := hex.EncodeToString(h[:])
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    domain.Identity().String(),
		Config: map[string]string{
			"depth":       fmt.Sprint(cfg.Depth),
			"scope":       scopeHash,
			"timeout":     cfg.Timeout.String(),
			"concurrency": fmt.Sprint(cfg.Concurrency),
			"rate_limit":  fmt.Sprint(cfg.RateLimit),
		},
		Tool: cache.ToolInfo{Name: "katana", Version: version},
	})
}

// parseKatanaOutput parses katana JSONL stdout into URLs, counting malformed.
func parseKatanaOutput(stdout []byte, domain asset.Domain) ([]asset.URL, int, string) {
	var urls []asset.URL
	malformed := 0
	// Use bytes split to avoid unbounded memory.
	lines := bytes.Split(stdout, []byte{'\n'})
	for _, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		var rec katanaRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			malformed++
			continue
		}
		ep := rec.resolvedEndpoint()
		if ep == "" {
			malformed++
			continue
		}
		u, err := asset.ParseURL(ep, asset.Provenance{Source: "katana"})
		if err != nil {
			malformed++
			continue
		}
		// Scope filter: in-domain only, drop IP literals, zero URLs.
		if u.IsZero() {
			malformed++
			continue
		}
		h, ok := urlHost(u)
		if !ok {
			malformed++
			continue
		}
		if !asset.InDomain(h.Name, domain.Name) {
			// Out-of-domain: drop, not malformed.
			continue
		}
		urls = append(urls, u)
	}
	var diag string
	if malformed > 0 {
		diag = fmt.Sprintf("katana parse malformed: %d", malformed)
	}
	return urls, malformed, diag
}

// dedupeURLs deduplicates by Identity, keeping first-seen.
func dedupeURLs(in []asset.URL) []asset.URL {
	seen := make(map[asset.Identity]struct{}, len(in))
	out := make([]asset.URL, 0, len(in))
	for _, u := range in {
		id := u.Identity()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, u)
	}
	return out
}

// dedupeHosts deduplicates hosts by Identity.
func dedupeHosts(in []asset.Host) []asset.Host {
	seen := make(map[asset.Identity]struct{}, len(in))
	out := make([]asset.Host, 0, len(in))
	for _, h := range in {
		id := h.Identity()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, h)
	}
	return out
}

// filterHosts keeps only in-domain hosts.
func filterHosts(domain asset.Domain, hosts []asset.Host) []asset.Host {
	out := make([]asset.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.Name == "" {
			continue
		}
		if asset.InDomain(h.Name, domain.Name) {
			out = append(out, h)
		}
	}
	return out
}

// urlHost extracts canonical hostname from URL asset.
func urlHost(u asset.URL) (asset.Host, bool) {
	hp := u.HostPort
	if host, _, err := net.SplitHostPort(hp); err == nil {
		hp = host
	}
	hp = strings.TrimPrefix(hp, "[")
	hp = strings.TrimSuffix(hp, "]")
	if _, err := netip.ParseAddr(hp); err == nil {
		return asset.Host{}, false // IP literal: never in-domain
	}
	h, err := asset.NewHost(hp, asset.Provenance{})
	if err != nil {
		return asset.Host{}, false
	}
	return h, true
}
