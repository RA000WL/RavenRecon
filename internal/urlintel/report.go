package urlintel

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Status classifies one canonical URL's outcome within a run.
//
// Completed entries carry the full observation (sources, timestamps,
// endpoint, parameters, relationships). Cancelled entries were consumed from
// the source but never processed (run teardown). Malformed raw lines are not
// entries at all: they are counted on the Report and never cached.
type Status string

const (
	// StatusCompleted: the URL was processed (freshly extracted or served
	// from a completed cache record).
	StatusCompleted Status = "completed"
	// StatusCancelled: the URL was read from the source but its work never
	// executed (run cancellation or forced shutdown). Never success.
	StatusCancelled Status = "cancelled"
	// StatusFailed: processing could not produce a usable observation (for
	// example a cache-key build failure). Never cached as success.
	StatusFailed Status = "failed"
)

// String returns the stable status label.
func (s Status) String() string { return string(s) }

// URLEntry is the merged emit record for one canonical URL.
//
// It is the merge-at-emit unit: observations of the same canonical URL from
// multiple adapters (each cached under its own per-(URL, adapter) key) merge
// into ONE entry per run. Sources are unioned in first-observation order,
// FirstSeen is the minimum and LastSeen the maximum observation time,
// parameters are merged via asset.MergeParameters, endpoints are deduplicated
// by Phase 2 identity, and relationships are deduplicated by edge identity.
type URLEntry struct {
	// URL is the canonical Phase 2 URL asset (the entry's identity).
	URL asset.URL

	// Host is the canonical host asset derived from the URL's host, zero
	// when the URL's host is an IP literal (IPs are not hosts in the Phase 2
	// model, so no host asset and no host_to_url edge exist for them).
	Host asset.Host

	// Status classifies the outcome (see Status).
	Status Status

	// Cached reports that the observation was served from a completed cache
	// record without any extraction work.
	Cached bool

	// Sources is the unioned, deduplicated list of sources (adapter names)
	// that observed this URL, in first-observation order.
	Sources []string

	// FirstSeen is the earliest observation time of this URL.
	FirstSeen time.Time

	// LastSeen is the latest observation time of this URL.
	LastSeen time.Time

	// Endpoints are the classified endpoints (GET on the canonical URL),
	// deduplicated by Phase 2 identity. At most one today: GET is the only
	// observable method in 6B inputs (see doc.go, "Endpoint classification").
	Endpoints []asset.Endpoint

	// Parameters are the parameters observed in the URL's query, merged by
	// Phase 2 identity and sorted.
	Parameters []asset.Parameter

	// Overflow reports that parameters were dropped because the per-URL
	// parameter cap (maxParametersPerURL) was reached. The record is still
	// completed, but the observed parameter set is incomplete.
	Overflow bool

	// Relationships are the typed graph edges of this entry: host_to_url,
	// url_to_endpoint, url_to_parameter, and endpoint_to_parameter,
	// deduplicated by edge identity.
	Relationships []asset.Relationship

	// Err carries the cause for cancelled and failed entries, plus joined
	// non-fatal diagnostics (for example cache read/write warnings) for
	// completed ones. The join is bounded: at most maxErrorsPerEntry
	// individual errors are retained per entry and further errors are only
	// counted (see boundedErrs), so repeated observations of one URL can
	// never grow this string without bound.
	Err error
}

// maxErrorsPerEntry bounds how many individual errors one URLEntry.Err
// retains across merges. Beyond the cap, further errors are only counted
// and a single tail line reports the total, so a stream repeating the same
// URL with a persistently failing cache can never grow the entry's Err
// string without bound. It mirrors the run-level diagnostic cap
// (maxRunDiagnostics) at the per-entry level: the cap applies AT THE JOIN
// SITE (mergeEntries), regardless of how many observations merge into one
// entry. The value is a small fixed constant, deliberately not
// configuration.
const maxErrorsPerEntry = 8

// boundedErrs is the bounded per-entry error accumulator, stored as a
// URLEntry.Err value. It retains the first maxErrorsPerEntry individual
// errors in arrival order and counts every further error; Error renders the
// retained errors plus a single tail line. Unwrap exposes the retained
// errors so errors.Is/errors.As keep working through the bound. Instances
// are immutable after construction (joinEntryErrors copies on write, so a
// merge never mutates an error value shared by another copy of the entry).
type boundedErrs struct {
	errs   []error
	excess int
}

// Error implements error. It renders each retained error on its own line,
// followed by a single tail line when errors were dropped beyond the cap.
func (b *boundedErrs) Error() string {
	var sb strings.Builder
	for i, err := range b.errs {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(err.Error())
	}
	if b.excess > 0 {
		sb.WriteString(fmt.Sprintf("\n... and %d more error(s)", b.excess))
	}
	return sb.String()
}

// Unwrap exposes the retained errors for errors.Is/errors.As traversal.
func (b *boundedErrs) Unwrap() []error { return b.errs }

// joinEntryErrors folds src's error into dst's, applying the per-entry cap
// at the join site: the first maxErrorsPerEntry individual errors are
// retained joined; every further error is only counted and reported by a
// single tail line (see boundedErrs). The resulting Err string is therefore
// bounded regardless of how many observations merge into one entry — a
// repeated URL with a persistently failing cache cannot accumulate an
// unboundedly growing joined error (errors.Join alone would rebuild a
// growing tree per observation, O(N²) in copy work).
func joinEntryErrors(dst, src error) error {
	if src == nil {
		// The common case: most observations carry no error, and the fold
		// must stay a no-op so per-observation cost stays O(1).
		return dst
	}
	if dst == nil {
		return src
	}
	var existing *boundedErrs
	if errors.As(dst, &existing) {
		b := &boundedErrs{
			errs:   append([]error(nil), existing.errs...),
			excess: existing.excess,
		}
		if len(b.errs) < maxErrorsPerEntry {
			b.errs = append(b.errs, src)
		} else {
			b.excess++
		}
		return b
	}
	return &boundedErrs{errs: []error{dst, src}}
}

// isPlaceholder reports whether e is a pre-registered cancelled entry that
// carries no observation (see IngestInto's pre-registration). A placeholder
// is replaced wholesale by the first real observation of the same URL.
func isPlaceholder(e URLEntry) bool {
	return e.Status == StatusCancelled && e.FirstSeen.IsZero() && len(e.Sources) == 0
}

// mergeEntries merges src's observation of the same URL into dst. Rules:
//
//   - a placeholder dst is replaced wholesale by a real src;
//   - a cancelled src never downgrades a completed dst;
//   - completed wins over failed, failed over cancelled for Status;
//   - sources are unioned in first-observation (append) order;
//   - FirstSeen = min, LastSeen = max;
//   - endpoints and relationships are deduplicated by identity;
//   - parameters are merged via asset.MergeParameters;
//   - Overflow and Err are sticky (OR / bounded Join; see joinEntryErrors).
func mergeEntries(dst *URLEntry, src URLEntry) {
	if isPlaceholder(*dst) && !isPlaceholder(src) {
		*dst = src
		return
	}
	if isPlaceholder(src) {
		// A placeholder adds no observation, but it may carry the cause
		// (a real cancelled entry is indistinguishable from a placeholder by
		// design — both carry no observation data). Keep its Err when dst
		// has none, so the honest cancellation reason survives the merge.
		if dst.Err == nil && src.Err != nil {
			dst.Err = src.Err
		}
		return
	}
	switch {
	case src.Status == StatusCompleted:
		dst.Status = StatusCompleted
	case src.Status == StatusFailed && dst.Status != StatusCompleted:
		dst.Status = StatusFailed
	}
	for _, s := range src.Sources {
		if !containsString(dst.Sources, s) {
			dst.Sources = append(dst.Sources, s)
		}
	}
	// A failed dst carries zero timestamps (extraction never ran); a real
	// observation must fill them in, not compare against the zero time (which
	// would always lose and leave FirstSeen zero forever).
	if dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	for _, ep := range src.Endpoints {
		if !containsEndpoint(dst.Endpoints, ep) {
			dst.Endpoints = append(dst.Endpoints, ep)
		}
	}
	mergedParams, mergedOverflow := mergeParameterLists(dst.Parameters, src.Parameters)
	dst.Parameters = mergedParams
	// Overflow is sticky across observations, and mergeParameterLists itself
	// re-enforces maxParametersPerURL on the merged list (a NEW parameter
	// identity arriving when the merged list is already at the cap is
	// dropped and flags the entry, mirroring extractParams).
	dst.Overflow = dst.Overflow || src.Overflow || mergedOverflow
	for _, r := range src.Relationships {
		if !containsRelationship(dst.Relationships, r) {
			dst.Relationships = append(dst.Relationships, r)
		}
	}
	if hostIsZero(dst.Host) && !hostIsZero(src.Host) {
		dst.Host = src.Host
	}
	// Err is joined with the per-entry cap applied at this join site, so a
	// repeated URL with a persistently failing cache cannot grow the
	// entry's Err string without bound (see joinEntryErrors).
	dst.Err = joinEntryErrors(dst.Err, src.Err)
	dst.Cached = dst.Cached || src.Cached
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func containsEndpoint(eps []asset.Endpoint, ep asset.Endpoint) bool {
	for _, e := range eps {
		if e.Identity() == ep.Identity() {
			return true
		}
	}
	return false
}

func containsRelationship(rs []asset.Relationship, r asset.Relationship) bool {
	for _, x := range rs {
		if x.ID() == r.ID() {
			return true
		}
	}
	return false
}

// mergeParameterLists unions two parameter lists by Phase 2 identity using
// asset.MergeParameters: a's order first, then b's new parameters in
// first-seen order; a parameter present in both merges via MergeParameters
// (values unioned, timestamps min/max, sources unioned, Truncated sticky).
//
// The per-URL parameter cap (maxParametersPerURL) is re-enforced on the
// MERGED list, mirroring extractParams: when the merged list already holds
// maxParametersPerURL distinct parameters and a NEW parameter identity
// arrives, the new parameter is dropped and the returned overflow flag is
// set (the caller flags the entry Overflow, which stays sticky). This keeps
// the documented memory bound — "each entry's payload is bounded by the
// per-URL caps" — true for merged entries too, not just single
// observations. Parameters already present in both lists never grow the
// list, so same-identity merges are never affected by the cap.
func mergeParameterLists(a, b []asset.Parameter) ([]asset.Parameter, bool) {
	if len(b) == 0 {
		return a, false
	}
	out := make([]asset.Parameter, len(a), len(a)+len(b))
	copy(out, a)
	byID := make(map[asset.Identity]int, len(out)+len(b))
	for i, p := range out {
		byID[p.Identity()] = i
	}
	overflow := false
	for _, p := range b {
		if idx, ok := byID[p.Identity()]; ok {
			if m, err := asset.MergeParameters(out[idx], p); err == nil {
				out[idx] = m
			}
			continue
		}
		if len(out) >= maxParametersPerURL {
			// The merged list is already at the cap: the new identity is
			// dropped and the entry flagged, exactly like extraction.
			overflow = true
			continue
		}
		byID[p.Identity()] = len(out)
		out = append(out, p)
	}
	return out, overflow
}

// normalize sorts every entry's variable-length slices deterministically:
// endpoints and parameters by Phase 2 identity, relationships by edge
// identity. Sources keep their first-observation order (see URLEntry).
func (e *URLEntry) normalize() {
	sort.Slice(e.Endpoints, func(i, j int) bool {
		return e.Endpoints[i].Identity().String() < e.Endpoints[j].Identity().String()
	})
	sort.Slice(e.Parameters, func(i, j int) bool {
		return e.Parameters[i].Identity().String() < e.Parameters[j].Identity().String()
	})
	sort.Slice(e.Relationships, func(i, j int) bool {
		return e.Relationships[i].ID() < e.Relationships[j].ID()
	})
}

// Accumulator is the merge-at-emit state of one or more Ingest runs. It is
// keyed by canonical URL identity: observations of the same URL from any
// number of adapters merge into one entry, which is exactly the two-level
// design (cache stores per (URL, adapter) records; emit merges per URL).
//
// An Accumulator is safe for concurrent use: IngestInto merges worker
// results into it under a mutex, and successive IngestInto calls with the
// same accumulator (one per adapter) produce the cross-adapter merged view.
//
// Memory: the accumulator holds at most one entry per distinct canonical URL
// observed in the run(s); each entry's payload is bounded by the per-URL
// caps (maxParametersPerURL parameters, the Phase 2 per-parameter value cap,
// at most one endpoint today) and its joined Err is bounded by
// maxErrorsPerEntry plus a count tail. Consumers that must stream
// arbitrarily many distinct URLs without retention use the Config.Emit hook
// instead and never materialize a Report.
type Accumulator struct {
	mu        sync.Mutex
	byURL     map[asset.Identity]*URLEntry
	malformed int
}

// NewAccumulator returns an empty accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{byURL: make(map[asset.Identity]*URLEntry)}
}

// merge folds one per-line observation into the accumulator under the lock.
func (a *Accumulator) merge(src URLEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dst := a.byURL[src.URL.Identity()]
	if dst == nil {
		c := src
		a.byURL[src.URL.Identity()] = &c
		return
	}
	mergeEntries(dst, src)
}

// addMalformed counts one rejected raw line.
func (a *Accumulator) addMalformed() {
	a.mu.Lock()
	a.malformed++
	a.mu.Unlock()
}

// Malformed returns the number of raw lines rejected so far.
func (a *Accumulator) Malformed() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.malformed
}

// Report materializes the merged view: every entry normalized (sorted
// endpoints, parameters, relationships), entries sorted by canonical URL
// string, and the malformed line count. It is deterministic for a given set
// of observations regardless of processing order.
func (a *Accumulator) Report() Report {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := make([]URLEntry, 0, len(a.byURL))
	for _, e := range a.byURL {
		entries = append(entries, *e)
	}
	for i := range entries {
		entries[i].normalize()
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].URL.String() < entries[j].URL.String()
	})
	return Report{Entries: entries, Malformed: a.malformed}
}

// Report is the aggregated outcome of one or more Ingest runs: the merged,
// deterministically ordered emit entries plus run-level counters. It is a
// plain snapshot; the Accumulator owns the live merge state.
type Report struct {
	// Entries holds one entry per distinct canonical URL, sorted by
	// canonical URL string. Every slice inside an entry is sorted (sources
	// keep first-observation order).
	Entries []URLEntry

	// Malformed counts raw lines rejected at the ingest boundary (parse
	// failures, oversized lines, control-character garbage). Malformed
	// lines are never cached and never appear as entries.
	Malformed int
}

// AllURLs merges every entry's URL asset across the report, deduplicated by
// Phase 2 identity via asset.MergeURLs and sorted by canonical form.
func (r Report) AllURLs() []asset.URL {
	urls := make([]asset.URL, 0, len(r.Entries))
	for _, e := range r.Entries {
		if e.URL.Identity().IsZero() {
			continue
		}
		urls = append(urls, e.URL)
	}
	return mergeURLs(urls)
}

// AllHosts merges every entry's host asset across the report (IP-literal
// URLs contribute none), sorted by canonical name.
func (r Report) AllHosts() []asset.Host {
	hosts := make([]asset.Host, 0, len(r.Entries))
	for _, e := range r.Entries {
		if hostIsZero(e.Host) {
			continue
		}
		hosts = append(hosts, e.Host)
	}
	return mergeHosts(hosts)
}

// AllEndpoints merges every entry's endpoints across the report,
// deduplicated by Phase 2 identity and sorted.
func (r Report) AllEndpoints() []asset.Endpoint {
	var eps []asset.Endpoint
	for _, e := range r.Entries {
		eps = append(eps, e.Endpoints...)
	}
	return mergeEndpoints(eps)
}

// AllParameters merges every entry's parameters across the report,
// deduplicated by Phase 2 identity and sorted.
func (r Report) AllParameters() []asset.Parameter {
	var params []asset.Parameter
	for _, e := range r.Entries {
		params = append(params, e.Parameters...)
	}
	return mergeParametersAll(params)
}

// AllRelationships merges every entry's relationships across the report,
// deduplicated by edge identity and sorted.
func (r Report) AllRelationships() []asset.Relationship {
	var rels []asset.Relationship
	for _, e := range r.Entries {
		rels = append(rels, e.Relationships...)
	}
	return sortRelationships(rels)
}

// mergeURLs deduplicates URLs by Phase 2 identity using asset.MergeURLs.
func mergeURLs(urls []asset.URL) []asset.URL {
	byID := make(map[asset.Identity]int)
	var out []asset.URL
	for _, u := range urls {
		if idx, ok := byID[u.Identity()]; ok {
			if m, err := asset.MergeURLs(out[idx], u); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[u.Identity()] = len(out)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// mergeHosts deduplicates hosts by Phase 2 identity using asset.MergeHosts.
func mergeHosts(hosts []asset.Host) []asset.Host {
	byID := make(map[asset.Identity]int)
	var out []asset.Host
	for _, h := range hosts {
		if idx, ok := byID[h.Identity()]; ok {
			if m, err := asset.MergeHosts(out[idx], h); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[h.Identity()] = len(out)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// mergeEndpoints deduplicates endpoints by Phase 2 identity using
// asset.MergeEndpoints.
func mergeEndpoints(eps []asset.Endpoint) []asset.Endpoint {
	byID := make(map[asset.Identity]int)
	var out []asset.Endpoint
	for _, ep := range eps {
		if idx, ok := byID[ep.Identity()]; ok {
			if m, err := asset.MergeEndpoints(out[idx], ep); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[ep.Identity()] = len(out)
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity().String() < out[j].Identity().String() })
	return out
}

// mergeParametersAll deduplicates parameters by Phase 2 identity using
// asset.MergeParameters.
func mergeParametersAll(params []asset.Parameter) []asset.Parameter {
	byID := make(map[asset.Identity]int)
	var out []asset.Parameter
	for _, p := range params {
		if idx, ok := byID[p.Identity()]; ok {
			if m, err := asset.MergeParameters(out[idx], p); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[p.Identity()] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity().String() < out[j].Identity().String() })
	return out
}

// sortRelationships orders relationships deterministically by identity.
func sortRelationships(rs []asset.Relationship) []asset.Relationship {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID() < rs[j].ID() })
	return rs
}
