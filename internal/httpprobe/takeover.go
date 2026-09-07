package httpprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Takeover confirmation (NEW-122): for in-scope hosts whose DNS shape
// suggests a dangling CNAME, fetch the host's own root pages and match
// the bodies against curated provider fingerprint strings. A dangling
// host's root response usually IS the provider's error page
// ("There isn't a GitHub Pages site here.", Heroku "No such app", S3
// "NoSuchBucket"), so a match upgrades a DNS-shape guess into a
// provider-confirmed lead — still an informational indicator (recon
// only, AGENTS §0.1: no validity, exploitability, or claimability
// judgment), never a vulnerability claim.
//
// This is liveness observation at the same privilege as every other
// probe: bounded GETs, redirects never followed, bodies bounded and
// never retained beyond the match. Deliberately UNCACHED: confirmation
// claims are freshness-critical (a claimed name flipping to legitimate
// content must not replay a stale confirmation), candidate sets are tiny
// (dangling hosts per run), and confirmed matches flow downstream as
// evidence — coherent through the snapshot fingerprint like every other
// evidence record.

const (
	// maxTakeoverBodyBytes bounds one confirmation response body read
	// for fingerprint search. A body exceeding the cap without an
	// observed fingerprint ends as unconfirmed (absence under truncation
	// proves nothing); a fingerprint observed before the cap still
	// confirms, flagged Truncated.
	maxTakeoverBodyBytes = 32 << 10
)

// TakeoverFingerprint is one provider's curated body-substring set: any
// substring matching (case-insensitive) confirms the provider serves
// the page. Strings are short, distinctive page markers — curated like
// the triage wordlists, needing field validation over time, documented
// as informational indicators rather than proof.
type TakeoverFingerprint struct {
	// Provider is the stable provider id (github-pages, heroku, aws-s3).
	Provider string
	// Substrings are the match markers, in priority order.
	Substrings []string
}

// takeoverFingerprints is the curated provider table, in deterministic
// match priority.
//
// Forgeability note (review wave 2026-09-03): a hostile target serving
// its own page containing one of these strings self-forges a match —
// but forging requires serving content on the dangling name, which is
// most of a takeover already. Matches stay informational indicators
// (recon only, AGENTS §0.1): they prioritize manual review, never claim
// exploitability. Case-insensitive matching tolerates minor page
// variations; the curated strings need field validation over time like
// any fingerprint table.
//
// Coverage analysis (NEW-128, 2026-09-03): the table deliberately stops
// at three providers. Of the pack's remaining DNS suffixes: Azure
// (azurewebsites/blob/cloudapp) and ELB unclaimed names NXDOMAIN (no
// HTTP possible — nothing to confirm); CloudFront serves a generic
// 403 ("ERROR: The request could not be satisfied") also shown for
// policy blocks (confirming on it would be a WAF false-positive
// factory); Shopify's unavailable page marks frozen stores, not
// unclaimed ones (wrong signal); Fastly's "unknown domain" page is the
// single plausible addition pending field verification of the exact
// string. herokudns.com is already covered (same Heroku router page).
// S3-endpoint confirmation needs out-of-domain fetches and stays
// deferred behind the scope wall.
var takeoverFingerprints = []TakeoverFingerprint{
	{
		Provider:   "github-pages",
		Substrings: []string{"There isn't a GitHub Pages site here."},
	},
	{
		Provider:   "heroku",
		Substrings: []string{"No such app"},
	},
	{
		Provider:   "aws-s3",
		Substrings: []string{"NoSuchBucket"},
	},
}

// TakeoverVerdict is the confirmation observation for one host.
type TakeoverVerdict struct {
	// Host is the canonical input host.
	Host asset.Host
	// Confirmed reports a provider fingerprint observed in a root body.
	Confirmed bool
	// Provider is the matched provider id, "" unless confirmed.
	Provider string
	// Fingerprint is the matched table substring, "" unless confirmed.
	Fingerprint string
	// Status is the first response status received (first-wins in scheme order, 0 when none).
	Status int
	// Truncated marks a body-cap hit: an unconfirmed verdict on this
	// record rests on a partial read.
	Truncated bool
	// Err carries the transport cause when no response was received on
	// either scheme. Nil for probes that received an HTTP response
	// (matched or not — both are completed observations).
	Err error
	// ErrMsg is the serialized form of Err.
	ErrMsg string
}

// TakeoverReport is the complete outcome of a ConfirmTakeoverHosts run.
type TakeoverReport struct {
	Target  asset.Domain      `json:"target"`
	Results []TakeoverVerdict `json:"results"`
}

// matchTakeoverProvider returns the first table match in a body
// (case-insensitive), in table and substring order — deterministic.
func matchTakeoverProvider(body string) (provider, fingerprint string, ok bool) {
	low := strings.ToLower(body)
	for _, fp := range takeoverFingerprints {
		for _, s := range fp.Substrings {
			if s == "" {
				continue
			}
			if strings.Contains(low, strings.ToLower(s)) {
				return fp.Provider, s, true
			}
		}
	}
	return "", "", false
}

// ConfirmTakeoverHosts fetches root pages for in-scope hosts and matches
// provider fingerprints: https://host/ then http://host/ per host (both
// schemes always — mirrors root probing, no short-circuit cleverness),
// redirects never followed, bodies bounded by maxTakeoverBodyBytes.
// Hosts validate exactly like Probe inputs (canonical, in-domain —
// out-of-scope hosts reject the whole call before any request). One
// bounded runtime.Pool owns all scheduling; results sort by hostname.
func ConfirmTakeoverHosts(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg Config) (TakeoverReport, error) {
	if ctx == nil {
		return TakeoverReport{}, fmt.Errorf("httpprobe: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return TakeoverReport{}, fmt.Errorf("httpprobe: %w", err)
	}
	if err := validateScope(domain); err != nil {
		return TakeoverReport{}, err
	}
	norm, err := normalizeInputHosts(hosts, domain)
	if err != nil {
		return TakeoverReport{}, err
	}
	if len(norm) == 0 {
		return TakeoverReport{Target: domain}, nil
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = liveRequestTimeoutDefault
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = liveConcurrencyDefault
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = cfg.Concurrency
	}
	e, err := buildEnv(cfg, map[string]asset.IP{})
	if err != nil {
		return TakeoverReport{}, err
	}
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        0,
		Burst:       0,
		// Forward the instrumentation sink; nil disables pool events.
		// The stateless Deriver converts completed job results into
		// canonical derived events at the pool-job boundary.
		Observer: cfg.Observer,
		Deriver:  Deriver{},
	})
	if err != nil {
		return TakeoverReport{}, fmt.Errorf("httpprobe: create worker pool: %w", err)
	}
	results := make([]TakeoverVerdict, len(norm))
	for i, h := range norm {
		results[i] = TakeoverVerdict{Host: h, Err: context.Canceled}
	}
	for i, h := range norm {
		i := i
		h := h
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			results[i] = confirmOneHost(jctx, h, e)
			return results[i], nil
		}}); err != nil {
			results[i] = TakeoverVerdict{Host: h, Err: fmt.Errorf("httpprobe: submit %s: %w", h.Name, err)}
			for j := i + 1; j < len(norm); j++ {
				results[j] = TakeoverVerdict{Host: norm[j], Err: fmt.Errorf("httpprobe: not submitted: %w", ctx.Err())}
			}
			break
		}
	}
	shutCtx, cancel := shutdownContext(cfg.Timeout)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()
	sort.Slice(results, func(i, j int) bool { return results[i].Host.Name < results[j].Host.Name })
	report := TakeoverReport{Target: domain, Results: results}
	if shutdownErr != nil {
		return report, fmt.Errorf("httpprobe: pool shutdown: %w", shutdownErr)
	}
	return report, nil
}

// confirmOneHost fetches one host's roots and matches fingerprints.
// Both schemes are always attempted when reachable (mirrors root
// probing — no short-circuit cleverness, so request behavior never
// leaks the verdict); the first match in scheme order wins,
// deterministically.
func confirmOneHost(ctx context.Context, host asset.Host, e env) TakeoverVerdict {
	rec := TakeoverVerdict{Host: host}
	if ctx.Err() != nil {
		rec.Err = ctx.Err()
		rec.ErrMsg = rec.Err.Error()
		return rec
	}
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		raw := scheme + "://" + host.Name + "/"
		target, err := asset.ParseURL(raw, asset.Provenance{Source: "http-probe"})
		if err != nil {
			lastErr = err
			continue
		}
		status, body, truncated, rerr := fetchConfirmBody(ctx, target, e)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if status != 0 && rec.Status == 0 {
			rec.Status = status
		}
		if truncated {
			rec.Truncated = true
		}
		if !rec.Confirmed {
			if provider, fp, ok := matchTakeoverProvider(body); ok {
				rec.Confirmed = true
				rec.Provider = provider
				rec.Fingerprint = fp
			}
		}
		lastErr = nil
	}
	if !rec.Confirmed && rec.Status == 0 && lastErr != nil {
		rec.Err = lastErr
		rec.ErrMsg = lastErr.Error()
	}
	return rec
}

// fetchConfirmBody performs one bounded GET: limiter wait, single
// request, body read capped at maxTakeoverBodyBytes+1. Redirects are
// never followed (RoundTrip is direct). It returns the status (0 when
// no response), the body within the cap, whether the cap hit, and the
// transport error (nil on a received response).
func fetchConfirmBody(ctx context.Context, target asset.URL, e env) (int, string, bool, error) {
	if err := waitForToken(ctx, e); err != nil {
		return 0, "", false, err
	}
	reqCtx := ctx
	if e.requestTimeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, e.requestTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, "", false, fmt.Errorf("httpprobe: confirm %s: build request: %w", target.String(), err)
	}
	req.Header.Set("User-Agent", userAgent)
	applySessionHeaders(req, e.reqHeaders)
	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		return 0, "", false, err
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTakeoverBodyBytes+1))
	if rerr != nil {
		return resp.StatusCode, "", false, rerr
	}
	if int64(len(body)) > maxTakeoverBodyBytes {
		return resp.StatusCode, string(body[:maxTakeoverBodyBytes]), true, nil
	}
	return resp.StatusCode, string(body), false, nil
}

// TakeoverEvidenceIndicatorPrefix namespaces confirmation indicators
// inside the shared evidence channel (MethodHTML):
// "takeover_page:<provider>".
const TakeoverEvidenceIndicatorPrefix = "takeover_page:"

// TakeoverEvidence builds the evidence record for one confirmed provider
// match: MethodHTML (observed in page content), the namespaced
// indicator, the matched substring value, sourced at the confirmed
// host's identity. Only curated providers with their exact table
// substrings are buildable — anything else is rejected, so foreign or
// tampered records can never enter the channel through this constructor.
func TakeoverEvidence(source asset.Identity, provider, fingerprint string) (asset.Evidence, error) {
	known := false
	for _, fp := range takeoverFingerprints {
		if fp.Provider != provider {
			continue
		}
		known = true
		matched := false
		for _, s := range fp.Substrings {
			if s == fingerprint {
				matched = true
				break
			}
		}
		if !matched {
			return asset.Evidence{}, fmt.Errorf("httpprobe: takeover evidence fingerprint %q is not curated for %q", fingerprint, provider)
		}
		break
	}
	if !known {
		return asset.Evidence{}, fmt.Errorf("httpprobe: takeover evidence provider %q is not curated", provider)
	}
	return asset.NewEvidence(asset.MethodHTML, TakeoverEvidenceIndicatorPrefix+provider, fingerprint, source, asset.Provenance{Source: "http-probe"})
}

// ParseTakeoverEvidence reads the writer contract back: provider id for
// confirmation evidence records, refusing everything else (other
// methods, other indicators, uncurated providers or substrings), so
// foreign evidence sharing the snapshot channel can never influence a
// confirmation consumer.
func ParseTakeoverEvidence(ev asset.Evidence) (string, bool) {
	if ev.Method != asset.MethodHTML {
		return "", false
	}
	provider, ok := strings.CutPrefix(ev.Indicator, TakeoverEvidenceIndicatorPrefix)
	if !ok || provider == "" {
		return "", false
	}
	for _, fp := range takeoverFingerprints {
		if fp.Provider != provider {
			continue
		}
		for _, s := range fp.Substrings {
			if s == ev.Value {
				return provider, true
			}
		}
		return "", false
	}
	return "", false
}
