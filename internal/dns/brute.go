package dns

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// MaxBruteHostsPerDomain caps how many brute candidates are retained per
// domain. It mirrors discovery's MaxPerSource (5000) — a generous, fixed
// bound so a hostile or misconfigured wordlist can never exhaust memory or
// flood the resolver. The cap is a fixed constant, never configuration, and
// must never enter cache keys (see typeKey in cache.go for the same
// rationale). Candidates beyond the cap are dropped before any query is
// issued.
const MaxBruteHostsPerDomain = 5000

// MaxBruteWordlistEntries caps how many wordlist entries are considered per
// domain. A wordlist longer than this is truncated at ingestion — the
// retained set is incomplete by definition, but wordlist truncation is
// treated as a pre-resolution bound, not as a DNS truncation (AGENTS §0.6).
const MaxBruteWordlistEntries = 5000

// BruteTimeout bounds the wall-clock time spent resolving brute candidates
// for one domain, covering limiter waits and queries. The stage as a whole
// may have its own deadline (in.Bounds.Timeout); this timeout is the
// per-domain brute budget applied around the brute Resolve.
const BruteTimeout = 60 * time.Second

// DefaultBruteWordlist is the small embedded wordlist used when the operator
// enables brute without supplying a custom wordlist. Ten common labels keep
// hermetic tests deterministic and cheap.
var DefaultBruteWordlist = []string{
	"www", "api", "dev", "staging", "test",
	"admin", "vpn", "internal", "prod", "stage",
}

// wildcardProbeLabel is the hostname label used for wildcard detection.
// A subdomain that should not exist is queried; if it resolves, the zone
// is wildcarded and brute is aborted to prevent *.example.com → 1.2.3.4
// inflation. The label is intentionally long and distinctive to avoid
// colliding with real hosts.
const wildcardProbeLabel = "ravenrecon-wildcard-check"

// WildcardProbeLabel is exported for tests that need to script the probe
// host predictably (the hermetic fakes).
const WildcardProbeLabel = wildcardProbeLabel

// GenerateBruteCandidates builds the brute candidate hosts for domain from
// wordlist. Each wordlist entry becomes "<label>.<domain>" normalized
// through the single Phase 2 builder (asset.NewHost). The function is
// deterministic, bounded, and allocation-limited:
//
//   - wordlist entries are trimmed, empty entries dropped
//   - invalid labels (via asset.NewHost) are dropped, never emitted
//   - deduplication is by Phase 2 identity, sorting by canonical name
//   - wordlist length is capped at MaxBruteWordlistEntries
//   - output length is capped at MaxBruteHostsPerDomain
//
// The provenance of every returned host is Source "dns-brute" — the
// caller may re-stamp DiscoveredAt through its own clock if desired; the
// identity and Name are what matter for dedup and resolution.
func GenerateBruteCandidates(domain asset.Domain, wordlist []string) []asset.Host {
	if domain.Name == "" {
		return nil
	}
	if len(wordlist) == 0 {
		return nil
	}
	if len(wordlist) > MaxBruteWordlistEntries {
		wordlist = wordlist[:MaxBruteWordlistEntries]
	}
	seen := make(map[asset.Identity]bool, len(wordlist))
	out := make([]asset.Host, 0, len(wordlist))
	prov := asset.Provenance{Source: "dns-brute"}
	for _, w := range wordlist {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		name := w + "." + domain.Name
		h, err := asset.NewHost(name, prov)
		if err != nil {
			continue
		}
		id := h.Identity()
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, h)
		if len(out) >= MaxBruteHostsPerDomain {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// wildcardProbeHost returns the host used to test whether domain is
// wildcarded. The host is deterministic for a given domain so hermetic
// fakes can script it predictably.
func wildcardProbeHost(domain asset.Domain) asset.Host {
	name := wildcardProbeLabel + "." + domain.Name
	h, _ := asset.NewHost(name, asset.Provenance{Source: "dns-brute-wildcard"})
	return h
}

// WildcardProbeHost returns the host used to test whether domain is
// wildcarded. Exported for adapt tests.
func WildcardProbeHost(domain asset.Domain) asset.Host {
	return wildcardProbeHost(domain)
}

// IsWildcard probes whether domain has a DNS wildcard. It issues a single
// A query for a hostname that should not exist (wildcardProbeHost). If the
// query returns one or more answers without error, the zone is considered
// wildcarded and brute must be aborted. NXDOMAIN (ErrNotFound) and empty
// answers (NODATA) both mean no wildcard. Any other resolver failure is
// treated as non-wildcard to avoid false aborts (a failing resolver must
// not suppress brute). Cancellation and deadline errors are returned so the
// caller can propagate them.
func IsWildcard(ctx context.Context, domain asset.Domain, resolver Resolver) (bool, error) {
	if ctx == nil {
		return false, errors.New("dns: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if domain.Name == "" {
		return false, nil
	}
	if resolver == nil {
		resolver = NewNetResolver()
	}
	probe := wildcardProbeHost(domain)
	answers, err := resolver.Lookup(ctx, probe.Name, TypeA)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if kind, ok := KindOf(err); ok {
			switch kind {
			case ErrNotFound:
				return false, nil
			case ErrCancelled:
				return false, err
			default:
				return false, nil
			}
		}
		return false, nil
	}
	if len(answers) > 0 {
		return true, nil
	}
	return false, nil
}
