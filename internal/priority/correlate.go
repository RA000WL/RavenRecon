package priority

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Correlation bounds (fixed constants; output is bounded by construction:
// at most maxCorrelationGroups groups, each with at most
// maxMembersPerGroup members, each member with at most maxFactors factors).
const (
	// maxCorrelationGroups bounds the number of groups Correlate emits.
	maxCorrelationGroups = 1024
	// maxMembersPerGroup bounds the members retained per group.
	maxMembersPerGroup = 64
)

// Group is one correlated cluster of scored surfaces: every member derives
// to the same grouping anchor. Groups are pure value types produced by
// Correlate; they never mutate and carry no state.
type Group struct {
	// Anchor is the canonical grouping identity every member derived to
	// (a domain: identity for name-anchored groups, an ip: identity for
	// address-anchored groups, or the member's own identity for singleton
	// fallback groups).
	Anchor asset.Identity `json:"anchor"`

	// Members are the retained member surfaces, sorted (score desc, then
	// identity asc, then the byte-wise serialized surface asc — a total
	// order; equal serialized bytes imply equal values) and capped at
	// maxMembersPerGroup.
	Members []SurfaceAsset `json:"members"`

	// SharedIndicators is the intersection of the factor-name sets of all
	// retained members, sorted: the indicators EVERY member of the group
	// exhibits. For a single-member group it is that member's full factor
	// list.
	SharedIndicators []string `json:"shared_indicators,omitempty"`

	// Score is the aggregate priority of the group (see Correlate for the
	// exact formula), rounded to 4 decimals.
	Score float64 `json:"score"`

	// Confidence is the aggregate observed-evidence confidence of the
	// group (uncapped combination of the union's confidence factors),
	// rounded to 4 decimals.
	Confidence float64 `json:"confidence"`

	// Level is the gated classification of Score under the same threshold
	// and category-gate rules as single surfaces.
	Level PriorityLevel `json:"level"`

	// Truncated reports that the group had more members than
	// maxMembersPerGroup; the retained set is the highest-scoring,
	// tie-broken by identity.
	Truncated bool `json:"truncated,omitempty"`
}

// Correlate groups scored surfaces into deterministic correlation clusters.
//
// Grouping keys are derived exclusively through the Phase 2 asset
// normalizers — there is no second normalization implementation:
//
//   - URL, endpoint, JavaScript, and source-map surfaces resolve to their
//     canonical URL through asset.ParseURL (endpoints drop their "METHOD "
//     prefix — the shape asset.Endpoint itself defines), then to the URL's
//     canonical host;
//   - the host is canonicalized through asset.NewHost (or asset.NewIP for
//     address literals, which asset.NewHost rejects by design);
//   - a name host with three or more labels anchors at its first-label-
//     dropped parent (label arithmetic on an already-canonical name, then
//     re-validated through asset.NewDomain); a two-label or shorter name
//     anchors at itself (as a domain). "a.api.example.com" and
//     "b.api.example.com" therefore group together under example.com's
//     child "api.example.com", while "www.example.com" and
//     "api.example.com" both group under "example.com";
//   - host and domain surfaces anchor through the same parent-domain rule,
//     so a host and the URLs observed on it land in ONE group;
//   - IP surfaces anchor at themselves (asset.NewIP);
//   - any surface whose anchor cannot be derived (unknown kind, identity
//     that does not re-parse canonically) forms an honest singleton group
//     anchored at its own identity — never a panic, never a hand-rolled
//     key.
//
// Aggregate formula — the SAME combine math as single-surface scoring
// (compose), applied to the UNION of all retained members' factor lists:
//
//	group.score      = round4(1 − ∏_g (1 − w_g))    over factor groups g
//	w_g              = min(cap_g, 1 − ∏_f (1 − w_f))    over g's factors f
//	cap_g            = confidenceGroupCap for the confidence group,
//	                   perCategoryCap for every indicator category
//	group.confidence = round4(1 − ∏_f (1 − w_f))    over the union's
//	                   confidence factors (uncapped, mirroring
//	                   SurfaceAsset.Confidence)
//	group.level      = levelFor(group.score, distinct indicator categories)
//
// Repeated factors (two members carrying the same indicator) combine
// within their group exactly as multiple factors of one category do in
// single-surface scoring — repeat evidence strengthens the aggregate up to
// the cap, never past it.
//
// Determinism: identical input slices produce bit-for-bit identical
// output; groups sort by (score desc, anchor asc) — a total order, since
// anchors are unique per group by construction — and members by
// (score desc, identity asc, serialized surface asc). The member order is
// a total order even for duplicate identities (unreachable through the
// engine, which dedups identities, but Correlate is an exported function):
// the final tie-break compares the byte-wise serialized surface — struct
// field order is fixed, so equal bytes imply equal values. Empty input
// yields empty output; no clock, no I/O, no randomness.
//
// Bounds: at most maxCorrelationGroups groups are retained. The boolean
// return value reports that run-level cut (groups beyond the cap, the
// highest-scoring kept first, are dropped); member-level cuts within a
// retained group are flagged per group by Group.Truncated. Both flags are
// honest: a truncated result is never silently presented as complete.
func Correlate(surfaces []SurfaceAsset) ([]Group, bool) {
	if len(surfaces) == 0 {
		return nil, false
	}

	// Bucket by anchor. First-encountered order is irrelevant: every
	// emission below re-sorts deterministically.
	buckets := make(map[string][]SurfaceAsset, len(surfaces))
	anchors := make(map[string]asset.Identity, len(surfaces))
	for i := range surfaces {
		anchor := correlationAnchor(surfaces[i].Identity)
		key := anchor.String()
		if _, ok := anchors[key]; !ok {
			anchors[key] = anchor
		}
		buckets[key] = append(buckets[key], surfaces[i])
	}

	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	groups := make([]Group, 0, len(buckets))
	for _, key := range keys {
		members := buckets[key]
		sort.SliceStable(members, func(i, j int) bool {
			if members[i].Score != members[j].Score {
				return members[i].Score > members[j].Score
			}
			ii, jj := members[i].Identity.String(), members[j].Identity.String()
			if ii != jj {
				return ii < jj
			}
			// Duplicate identities (impossible via the engine's dedup, but
			// the exported function must be deterministic): the byte-wise
			// serialized surface decides — equal bytes imply equal values,
			// so the order never depends on the input permutation.
			return marshalSurface(&members[i]) < marshalSurface(&members[j])
		})
		g := Group{Anchor: anchors[key]}
		if len(members) > maxMembersPerGroup {
			g.Truncated = true
			members = members[:maxMembersPerGroup]
		}
		g.Members = members

		var union []Factor
		shared := factorNameSet(members[0])
		for _, m := range members {
			union = append(union, m.Factors...)
			shared = intersectSets(shared, factorNameSet(m))
		}
		g.SharedIndicators = sortedStringSet(shared)
		score, _, confidence, categories := compose(union)
		g.Score = score
		g.Confidence = confidence
		g.Level = levelFor(score, categories)
		groups = append(groups, g)
	}

	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Score != groups[j].Score {
			return groups[i].Score > groups[j].Score
		}
		return groups[i].Anchor.String() < groups[j].Anchor.String()
	})
	truncated := len(groups) > maxCorrelationGroups
	if truncated {
		groups = groups[:maxCorrelationGroups]
	}
	return groups, truncated
}

// correlationAnchor derives the grouping anchor of one identity through
// the Phase 2 normalizers (see Correlate for the full rule). It never
// panics: any value that does not re-canonicalize falls back to a
// singleton anchor at the identity itself (never a shared "invalid" key).
func correlationAnchor(id asset.Identity) asset.Identity {
	anchor := func() asset.Identity {
		switch id.Kind {
		case asset.KindURL, asset.KindJavaScript, asset.KindSourceMap:
			if u, err := asset.ParseURL(id.Value, asset.Provenance{}); err == nil {
				return hostAnchor(u.HostPort)
			}
		case asset.KindEndpoint:
			// Endpoint identity values are "METHOD url" (asset.Endpoint's own
			// canonical shape); the URL follows the first space.
			if _, raw, ok := strings.Cut(id.Value, " "); ok {
				if u, err := asset.ParseURL(raw, asset.Provenance{}); err == nil {
					return hostAnchor(u.HostPort)
				}
			}
		case asset.KindHost, asset.KindDomain:
			return hostAnchor(id.Value)
		case asset.KindIP:
			if ip, err := asset.NewIP(id.Value, asset.Provenance{}); err == nil {
				return ip.Identity()
			}
		}
		return asset.Identity{}
	}()
	if anchor.IsZero() {
		return id
	}
	return anchor
}

// hostAnchor maps one canonical host (possibly with a port, possibly a
// bracketed IPv6 literal — the forms asset.URL.HostPort produces) to its
// grouping anchor: the IP identity for address literals, or the
// first-label-dropped parent domain for names.
func hostAnchor(hostPort string) asset.Identity {
	host := hostOfHostPort(hostPort)
	if addr, err := netip.ParseAddr(host); err == nil {
		if ip, err := asset.NewIP(addr.String(), asset.Provenance{}); err == nil {
			return ip.Identity()
		}
		return asset.Identity{}
	}
	h, err := asset.NewHost(host, asset.Provenance{})
	if err != nil {
		return asset.Identity{}
	}
	parent := h.Name
	if labels := strings.Split(h.Name, "."); len(labels) > 2 {
		parent = strings.Join(labels[1:], ".")
	}
	if d, err := asset.NewDomain(parent, asset.Provenance{}); err == nil {
		return d.Identity()
	}
	return h.Identity()
}

// hostOfHostPort extracts the bare host from the canonical HostPort forms
// ("host", "host:port", "[v6]", "[v6]:port"). This is parsing of a value
// the asset layer already canonicalized, not a second normalization.
func hostOfHostPort(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	if strings.HasPrefix(hostPort, "[") && strings.HasSuffix(hostPort, "]") {
		return hostPort[1 : len(hostPort)-1]
	}
	return hostPort
}

// factorNameSet returns the set of a surface's factor names.
func factorNameSet(s SurfaceAsset) map[string]struct{} {
	out := make(map[string]struct{}, len(s.Factors))
	for _, f := range s.Factors {
		out[f.Name] = struct{}{}
	}
	return out
}

// intersectSets returns the intersection of two sets.
func intersectSets(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a))
	for k := range a {
		if _, ok := b[k]; ok {
			out[k] = struct{}{}
		}
	}
	return out
}

// sortedStringSet returns the set's members sorted.
func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
