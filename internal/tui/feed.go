package tui

import (
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// Feed bounds (fixed constants; a hostile stream cannot inflate them).
const (
	// maxFeedItems bounds the interesting-asset feed ring.
	maxFeedItems = 64
	// maxErrorGroups bounds the error feed's category table.
	maxErrorGroups = 32
	// maxFeedLabelBytes bounds one feed item's stored label/detail.
	maxFeedLabelBytes = 200
	// labelMarker marks a truncated feed label; its width is accounted
	// for in the truncation bound, so a truncated label never exceeds
	// maxFeedLabelBytes.
	labelMarker = "…"
)

// feedItem is one displayed feed entry. Label and Detail are sanitized at
// ingestion and display-truncated to maxFeedLabelBytes, so hostile payloads
// can neither corrupt the terminal nor inflate the frame. key is the
// dedupe key of the item (stored so eviction can forget it).
type feedItem struct {
	at     time.Time
	kind   event.Kind
	label  string
	detail string
	key    string
}

// InterestingFeed is the bounded, rate-limited, deduplicated feed of
// high-value observations. Admission is a display-only heuristic over REAL
// event payload fields:
//
//   - AssetDiscovered: endpoint classes GQL/WS/SSE (asset.Endpoint.Method
//     projection), admin-ish paths (a small display table over the
//     asset.URL.Path projection), source_map assets, secret_candidate
//     assets with Confidence >= 0.8 (the secret engine's High threshold),
//     and technology assets;
//   - FindingCreated: priorities high/critical (detect.FindingPriority);
//   - RecommendationCreated: level high (priority.PriorityLevel) with a
//     factor weight >= 0.6 (priority.Factor.Weight).
//
// Rate limiting is a token bucket (InterestingRate tokens/s, burst 1, the
// same shape as the runtime engine's central limiter). Deduplication keys
// on identity+kind (AssetDiscovered: asset kind + identity; FindingCreated:
// finding identity; RecommendationCreated: surface identity + text — two
// distinct recommendations on one surface are both high-value and both
// shown). The dedupe set is exactly the set of keys currently in the ring,
// so memory stays bounded by maxFeedItems; a re-observed identity can
// re-enter after its item was evicted.
type InterestingFeed struct {
	items      []feedItem // ring
	start      int
	len        int
	keys       map[string]struct{}
	limiter    tokenBucket
	admitted   uint64
	rejected   uint64 // rate-limit rejections
	duplicates uint64 // dedupe rejections
}

// tokenBucket is the interesting-feed admission limiter: capacity 1, refill
// rate tokens per second, starting full (the first candidate is admitted
// immediately). Deterministic under an injected clock.
type tokenBucket struct {
	rate    float64
	tokens  float64
	last    time.Time
	started bool
}

// allow consumes one token when available. A non-positive rate rejects
// everything; a NaN rate is treated the same (NaN compares false against
// everything, so without the explicit guard a NaN rate would reach the
// refill arithmetic and silently reject every candidate after the first —
// the feed would starve without reporting it). Callers that route rates
// through the controller already normalize NaN away; this guard is for
// direct NewState users.
func (b *tokenBucket) allow(at time.Time) bool {
	if b.rate <= 0 || math.IsNaN(b.rate) {
		return false
	}
	if !b.started {
		b.started = true
		b.last = at
		b.tokens = 1 // burst 1: the bucket starts full
	}
	elapsed := at.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(1, b.tokens+elapsed*b.rate)
		b.last = at
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// newInterestingFeed builds the feed with the given admission rate
// (tokens per second; the bucket starts full). The ring is allocated up
// front: the first admitted event can never panic.
func newInterestingFeed(rate float64) *InterestingFeed {
	return &InterestingFeed{
		items:   make([]feedItem, maxFeedItems),
		keys:    make(map[string]struct{}, maxFeedItems),
		limiter: tokenBucket{rate: rate},
	}
}

// add evaluates one event for admission. It reports whether the event was
// admitted to the ring.
func (f *InterestingFeed) add(ev event.Event) bool {
	key, label, detail, ok := interesting(ev)
	if !ok {
		return false
	}
	if !f.limiter.allow(ev.At) {
		f.rejected++
		return false
	}
	if _, dup := f.keys[key]; dup {
		f.duplicates++
		return false
	}
	item := feedItem{
		at:     ev.At,
		kind:   ev.Kind,
		label:  truncateLabel(label),
		detail: truncateLabel(detail),
		key:    key,
	}
	if f.len == maxFeedItems {
		// Ring full: evict the oldest item and forget its key.
		old := f.items[f.start]
		delete(f.keys, old.key)
		f.start = (f.start + 1) % maxFeedItems
		f.len--
	}
	idx := (f.start + f.len) % maxFeedItems
	f.items[idx] = item
	f.len++
	f.keys[key] = struct{}{}
	f.admitted++
	return true
}

// interesting classifies one event as a feed candidate. The heuristic is
// display-only: it reads only the real payload fields and never influences
// execution. The dedupe key is identity+kind grounded in the payload.
func interesting(ev event.Event) (key, label, detail string, ok bool) {
	switch p := ev.Payload.(type) {
	case event.AssetDiscovered:
		switch p.Kind {
		case "endpoint":
			switch p.Method {
			case "GQL":
				return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "graphql endpoint", true
			case "WS":
				return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "websocket endpoint", true
			case "SSE":
				return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "server-sent events endpoint", true
			}
			if adminPath(p.Path) {
				return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "admin-ish path", true
			}
		case "source_map":
			return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "source map exposed", true
		case "secret_candidate":
			if p.Confidence >= 0.8 {
				return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "high-confidence secret", true
			}
		case "technology":
			return "asset|" + p.Kind + "|" + p.Identity, p.Identity, "technology detected", true
		}
	case event.FindingCreated:
		if p.Priority == "high" || p.Priority == "critical" {
			return "finding|" + p.Identity, p.Identity, "finding " + p.Priority + " (" + p.RuleID + ")", true
		}
	case event.RecommendationCreated:
		if p.Level == "high" && p.Weight >= 0.6 {
			return "recommendation|" + p.Identity + "|" + p.Text, p.Identity, "high-value recommendation", true
		}
	}
	return "", "", "", false
}

// adminSegments is the display-only admin-ish path table (a small subset of
// the priority engine's interestingness vocabulary, reimplemented here ONLY
// for display: the TUI never scores anything). It matches path segments
// case-insensitively.
var adminSegments = map[string]bool{
	"admin": true, "administrator": true, "console": true, "dashboard": true,
	"debug": true, "manage": true, "manager": true, "management": true,
	"internal": true, "staging": true, "dev": true, "test": true,
	"api-docs": true, "swagger": true, "actuator": true, "metrics": true,
	"jenkins": true, "kibana": true, "graphql": true, "upload": true,
	"backup": true, "wp-admin": true, "phpmyadmin": true,
}

// adminPath reports whether a canonical URL path contains an admin-ish
// segment. Path is the real asset.URL.Path projection; the check is
// display-only.
func adminPath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if adminSegments[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// Dropped returns how many candidates admission control rejected (rate
// limit plus dedupe), so feed loss is measurable, never silent.
func (f *InterestingFeed) Dropped() uint64 { return f.rejected + f.duplicates }

// snapshot returns the feed items newest-first (deterministic render
// order).
func (f *InterestingFeed) snapshot() []feedItem {
	out := make([]feedItem, 0, f.len)
	for i := 0; i < f.len; i++ {
		out = append(out, f.items[(f.start+i)%maxFeedItems])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// errorGroup is one category's slice of the error feed: every event in the
// category collapses into the count, the latest example, and the highest
// severity seen (deduplicated by construction — one row per category).
type errorGroup struct {
	category  string
	count     int
	latestMsg string
	latestAt  time.Time
	severity  event.Severity
}

// ErrorFeed groups Warning/Error events by category, bounded at
// maxErrorGroups. On overflow the group with the oldest latest event is
// evicted (ties: lexicographically smallest category), and the eviction is
// counted — loss is measurable, never silent.
type ErrorFeed struct {
	groups  map[string]*errorGroup
	dropped uint64
}

func newErrorFeed() *ErrorFeed {
	return &ErrorFeed{groups: make(map[string]*errorGroup)}
}

// severityRank orders the severity vocabulary for the error feed's
// "highest severity seen" aggregation. The event model's ranking is
// unexported; this display-only table mirrors its three-level vocabulary
// (info < warning < error), and unknown severities rank below info.
func severityRank(s event.Severity) int {
	switch s {
	case event.SeverityInfo:
		return 1
	case event.SeverityWarning:
		return 2
	case event.SeverityError:
		return 3
	default:
		return 0
	}
}

// add records one warning/error event under its category.
func (f *ErrorFeed) add(category, message string, sev event.Severity, at time.Time) {
	g, ok := f.groups[category]
	if !ok {
		if len(f.groups) == maxErrorGroups {
			f.evictOldest()
		}
		g = &errorGroup{category: category}
		f.groups[category] = g
	}
	g.count++
	g.latestMsg = message
	g.latestAt = at
	if severityRank(sev) > severityRank(g.severity) {
		g.severity = sev
	}
}

// Dropped returns how many error groups were evicted past the group
// bound, so feed loss is measurable, never silent.
func (f *ErrorFeed) Dropped() uint64 { return f.dropped }

// evictOldest drops the group with the oldest latest event (deterministic;
// ties break by category name).
func (f *ErrorFeed) evictOldest() {
	var victim *errorGroup
	for _, g := range f.groups {
		if victim == nil || g.latestAt.Before(victim.latestAt) ||
			(g.latestAt.Equal(victim.latestAt) && g.category < victim.category) {
			victim = g
		}
	}
	if victim != nil {
		delete(f.groups, victim.category)
		f.dropped++
	}
}

// snapshot returns the groups sorted by category (deterministic render
// order).
func (f *ErrorFeed) snapshot() []errorGroup {
	out := make([]errorGroup, 0, len(f.groups))
	for _, g := range f.groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].category < out[j].category })
	return out
}

// truncateLabel bounds a display label to maxFeedLabelBytes bytes,
// rune-safe, with the explicit marker. The bound includes the marker, so
// a truncated label never exceeds maxFeedLabelBytes (the frame line
// bound depends on it).
func truncateLabel(s string) string {
	if len(s) <= maxFeedLabelBytes {
		return s
	}
	prefix := s[:maxFeedLabelBytes-len(labelMarker)]
	for len(prefix) > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix)
		if r != utf8.RuneError || size > 1 {
			break // a complete rune (U+FFFD decodes with size 3)
		}
		prefix = prefix[:len(prefix)-1] // drop the torn byte
	}
	return prefix + labelMarker
}
