package adapt

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/crawl"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// crawlTruncatedFlag is the sticky-flag name this adapter records when the
// crawl engine cut its retained set at a cap.
const crawlTruncatedFlag = "crawl_truncated"

// crawlStage adapts the active crawl engine (internal/crawl) to the pipeline
// Stage contract.
type crawlStage struct {
	src crawl.Source
}

var _ pipeline.Stage = (*crawlStage)(nil)

// NewCrawlStage constructs the crawl pipeline stage. src is the crawl source
// seam (nil = production KatanaSource with discovery.ExecRunner and
// exec.LookPath). Tests inject hermetic fakes through this seam — never
// through StageParams.
func NewCrawlStage(src crawl.Source) pipeline.Stage {
	if src == nil {
		src = crawl.NewKatanaSource(nil, nil)
	}
	return &crawlStage{src: src}
}

// Name implements pipeline.Stage.
func (s *crawlStage) Name() pipeline.StageName { return pipeline.StageCrawl }

// Run implements pipeline.Stage.
func (s *crawlStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	if !targetCanonical(in.Target) {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: target %q is not canonical (build it with asset.NewDomain — the single normalization point)", s.Name(), in.Target.Name)
	}
	// Input hosts: alive hosts from httpprobe (already filtered at httpprobe output,
	// but re-filter here for safety). If no hosts, try to derive hosts from URLs
	// as fallback (so a seed that only has URLs can still be crawled).
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)
	if len(hosts) == 0 {
		// Derive hosts from URLs corpus if present (e.g., when httpprobe was skipped).
		seen := make(map[string]struct{})
		for _, u := range in.URLs {
			h, ok := urlHostCrawl(u)
			if !ok {
				continue
			}
			if !pipeline.InDomain(in.Target, h) {
				continue
			}
			if _, dup := seen[h.Name]; dup {
				continue
			}
			seen[h.Name] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	// Empty filtered input: short-circuit with completed and zero work — but only
	// for a canonical target (mirroring dns/httpprobe adapters). A non-canonical
	// target falls through so the engine's own honesty is not masked.
	if len(hosts) == 0 && targetCanonical(in.Target) {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// StageParams: crawl_depth, crawl_timeout, crawl_concurrency, crawl_rate_limit,
	// crawl_per_tool_timeout (alias for crawl_timeout). Unknown keys ignored.
	depth, err := crawlDepthParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	timeout, err := crawlTimeoutParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	concurrency, err := crawlConcurrencyParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	rateLimit, err := crawlRateLimitParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	// Also respect pipeline bounds for concurrency if StageParams did not override:
	// in.Bounds.MaxConcurrency is the stage pool concurrency (used by other adapters);
	// for crawl, it can also serve as katana concurrency when no explicit param.
	if _, hasConc := in.Config["crawl_concurrency"]; !hasConc && in.Bounds.MaxConcurrency > 0 && concurrency == crawl.DefaultConcurrency {
		concurrency = in.Bounds.MaxConcurrency
	}

	cfg := crawl.Config{
		Depth:       depth,
		Timeout:     timeout,
		Concurrency: concurrency,
		RateLimit:   rateLimit,
		Cache:       in.Cache,
	}

	result, err := s.src.Crawl(ctx, in.Target, hosts, cfg)
	if err != nil {
		if ctx.Err() != nil {
			joined := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: joined}, joined
		}
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
	}
	if ctx.Err() != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return pipeline.StageResult{
			Outcome:   pipeline.OutcomeCancelled,
			Err:       wrapped,
			Additions: pipeline.StageAdditions{URLs: filterURLsCrawl(in.Target, result.URLs)},
		}, wrapped
	}

	// Output: Additions.URLs = deduplicated, in-domain filtered, sorted, capped.
	urls := filterURLsCrawl(in.Target, result.URLs)
	// Deduplicate against incoming corpus is handled by runner's mergeCorpus,
	// but we also cap here deterministically.
	truncated := result.Truncated
	if len(urls) > crawl.MaxTotalURLs {
		urls = urls[:crawl.MaxTotalURLs]
		truncated = true
	}
	res := pipeline.StageResult{
		Outcome:        pipeline.OutcomeCompleted,
		ItemsProcessed: len(hosts),
		ItemsFailed:    0,
		Additions:      pipeline.StageAdditions{URLs: urls},
	}
	if truncated {
		res.Truncated = true
		res.StickyFlags = map[string]bool{crawlTruncatedFlag: true}
	}
	// Also propagate any diagnostics as? Not needed.

	return res, nil
}

func crawlDepthParam(params map[string]string) (int, error) {
	v, ok := params["crawl_depth"]
	if !ok {
		return crawl.DefaultDepth, nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return crawl.DefaultDepth, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid crawl_depth %q: %w", v, err)
	}
	if n <= 0 || n > 3 {
		return 0, fmt.Errorf("crawl_depth must be 1..3, got %d", n)
	}
	return n, nil
}

func crawlTimeoutParam(params map[string]string) (time.Duration, error) {
	// Accept both crawl_timeout and crawl_per_tool_timeout (alias).
	for _, key := range []string{"crawl_timeout", "crawl_per_tool_timeout", "crawl_per_tool_timeout_default"} {
		if v, ok := params[key]; ok {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return 0, fmt.Errorf("invalid %s %q: %w", key, v, err)
			}
			if d < 0 {
				return 0, fmt.Errorf("%s must not be negative, got %s", key, d)
			}
			if d == 0 {
				return crawl.DefaultPerToolTimeout, nil
			}
			return d, nil
		}
	}
	return crawl.DefaultPerToolTimeout, nil
}

func crawlConcurrencyParam(params map[string]string) (int, error) {
	v, ok := params["crawl_concurrency"]
	if !ok {
		return crawl.DefaultConcurrency, nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return crawl.DefaultConcurrency, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid crawl_concurrency %q: %w", v, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("crawl_concurrency must be > 0, got %d", n)
	}
	return n, nil
}

func crawlRateLimitParam(params map[string]string) (int, error) {
	if _, ok := params["crawl_rate_limit"]; !ok {
		if _, ok := params["crawl_rl"]; !ok {
			return crawl.DefaultRateLimit, nil
		}
	}
	// Normal path
	if v, ok := params["crawl_rate_limit"]; ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return crawl.DefaultRateLimit, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid crawl_rate_limit %q: %w", v, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("crawl_rate_limit must be > 0, got %d", n)
		}
		return n, nil
	}
	if v, ok := params["crawl_rl"]; ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return crawl.DefaultRateLimit, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid crawl_rl %q: %w", v, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("crawl_rl must be > 0, got %d", n)
		}
		return n, nil
	}
	return crawl.DefaultRateLimit, nil
}

// filterURLsCrawl drops every URL whose canonical host is out-of-domain, an IP
// literal, or not representable as a canonical asset.Host. Mirrors
// httpprobe.go filterURLs.
func filterURLsCrawl(declared asset.Domain, urls []asset.URL) []asset.URL {
	out := make([]asset.URL, 0, len(urls))
	for _, u := range urls {
		h, ok := urlHostCrawl(u)
		if !ok {
			continue
		}
		if pipeline.InDomain(declared, h) {
			out = append(out, u)
		}
	}
	return out
}

func urlHostCrawl(u asset.URL) (asset.Host, bool) {
	hp := u.HostPort
	if host, _, err := net.SplitHostPort(hp); err == nil {
		hp = host
	}
	hp = strings.TrimPrefix(hp, "[")
	hp = strings.TrimSuffix(hp, "]")
	if _, err := netip.ParseAddr(hp); err == nil {
		return asset.Host{}, false
	}
	h, err := asset.NewHost(hp, asset.Provenance{})
	if err != nil {
		return asset.Host{}, false
	}
	return h, true
}
