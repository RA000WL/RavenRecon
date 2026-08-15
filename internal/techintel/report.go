package techintel

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Status is the outcome of one observation's processing.
type Status string

const (
	// StatusCompleted marks an observation whose work finished (fresh
	// analysis or a served cache hit).
	StatusCompleted Status = "completed"
	// StatusCancelled marks an observation whose work never executed
	// (cancellation during the bounded drain).
	StatusCancelled Status = "cancelled"
	// StatusFailed marks an observation that could not be processed (for
	// example a cache-key failure). Err carries the bounded cause.
	StatusFailed Status = "failed"
)

// Valid reports whether s is a known entry status.
func (s Status) Valid() bool {
	switch s {
	case StatusCompleted, StatusCancelled, StatusFailed:
		return true
	}
	return false
}

// TechnologyResult is one detected technology with its confidence score and
// level.
type TechnologyResult struct {
	Technology asset.Technology `json:"technology"`
	Score      float64          `json:"score"`
	Level      ConfidenceLevel  `json:"level"`

	// versionOrdinal is the flat DB order (1-based) of the version-bearing
	// indicator that produced this result's version, or 0 when the result
	// carries no version. It is not serialized through JSON (cache records
	// persist it in a parallel array, see record.go) and serves only the
	// deterministic equal-score merge tie-break.
	versionOrdinal int
}

// ReportEntry is the full result of one processed observation. ID is the
// observation identity (endpoint identity when an endpoint is attached,
// otherwise the URL identity); URL/Endpoint mirror the observation. Entries
// are the unit of cache records and of the merge accumulator.
type ReportEntry struct {
	ID            asset.Identity       `json:"id"`
	URL           asset.URL            `json:"url"`
	Endpoint      *asset.Endpoint      `json:"endpoint,omitempty"`
	StatusCode    int                  `json:"status_code,omitempty"`
	Status        Status               `json:"status"`
	Technologies  []TechnologyResult   `json:"technologies,omitempty"`
	Evidence      []asset.Evidence     `json:"evidence,omitempty"`
	Relationships []asset.Relationship `json:"relationships,omitempty"`
	Conflicts     int                  `json:"conflicts,omitempty"`
	Truncated     bool                 `json:"truncated,omitempty"`
	Overflow      Overflow             `json:"overflow,omitempty"`
	FirstSeen     time.Time            `json:"first_seen,omitempty"`
	LastSeen      time.Time            `json:"last_seen,omitempty"`
	Cached        bool                 `json:"cached,omitempty"`
	// Err is the bounded failure cause for StatusFailed entries. It is never
	// serialized, so it never enters cache records.
	Err error `json:"-"`

	// techEvidence links each technology ID to the evidence IDs that fired
	// it. Unexported: rebuilt deterministically from stored records on
	// cache hits and carried through merges.
	techEvidence map[string][]string

	// source is the observation source name (o.Source, already defaulted at
	// ingest). Unexported: it is the deterministic second key of the
	// failed-entry Err tie-break and is never serialized.
	source string
}

// ReportObservations are the per-status observation counts of one report.
type ReportObservations struct {
	Completed int
	Cancelled int
	Failed    int
	Malformed int
}

// Report aggregates every observation of one Ingest run. Everything is
// deterministic: technologies sorted by identity, evidence by identity,
// relationships by edge identity.
type Report struct {
	Observations  ReportObservations
	Technologies  []asset.Technology
	Levels        map[string]ConfidenceLevel
	Evidence      []asset.Evidence
	Relationships []asset.Relationship
	Conflicts     int
	Truncated     bool
	Overflow      Overflow
	Metrics       MetricsSnapshot
}

// accumulator is the merge store for one run: one merged entry per
// observation identity, plus the malformed counter. Safe for concurrent
// use: the reader pre-registers placeholders while workers merge.
type accumulator struct {
	mu        sync.Mutex
	entries   map[string]*ReportEntry
	malformed int
}

func newAccumulator() *accumulator {
	return &accumulator{entries: make(map[string]*ReportEntry)}
}

// preRegister reserves a cancelled placeholder for an observation identity
// so that a dropped job (forced shutdown) appears honestly as cancelled.
// The first real merge replaces it.
func (a *accumulator) preRegister(o Observation) {
	id := o.identity().String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.entries[id]; !ok {
		e := placeholderEntry(o)
		a.entries[id] = &e
	}
}

// merge folds one processed entry into the accumulator under its identity.
func (a *accumulator) merge(id string, e *ReportEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.entries[id]; ok {
		merged, err := mergeEntries(prev, e)
		if err == nil {
			a.entries[id] = merged
		}
		return
	}
	cp := *e
	a.entries[id] = &cp
}

// addMalformed counts one malformed observation.
func (a *accumulator) addMalformed() {
	a.mu.Lock()
	a.malformed++
	a.mu.Unlock()
}

// snapshot returns the merged entries sorted by identity and the malformed
// count.
func (a *accumulator) snapshot() ([]ReportEntry, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ReportEntry, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, a.malformed
}

// placeholderEntry is the cancelled placeholder pre-registered per
// observation identity. Cancelled placeholders carry the observation's own
// timestamps and source like every other entry, so a dropped job's entry
// participates honestly in the deterministic merge tie-breaks.
func placeholderEntry(o Observation) ReportEntry {
	e := ReportEntry{ID: o.identity(), URL: o.URL, Status: StatusCancelled, FirstSeen: o.ObservedAt, source: o.Source}
	if o.Endpoint != nil {
		ep := *o.Endpoint
		e.Endpoint = &ep
	}
	return e
}

// mergeEntries merges two observations of the SAME identity into one entry.
// Status resolves failed > completed > cancelled; technologies merge per
// technology identity (higher score wins the quality; on a score TIE the
// merged contributor is chosen by the deterministic tie-break chain — a
// version-bearing contributor outranks a version-less one, then the
// earliest ObservedAt, then the lowest source name, then the DB order of
// the version-bearing indicator, then the version string, then the level —
// so the merged result is identical regardless of the merge order); the
// failed entry's Err comes from the deterministic failed-contributor chain
// (earliest FirstSeen, then lowest source name, then lowest error text);
// evidence and relationships dedupe by identity; timestamps widen;
// Truncated/Overflow/Cached are sticky.
func mergeEntries(a, b *ReportEntry) (*ReportEntry, error) {
	if a == nil && b == nil {
		return nil, errors.New("techintel: merge of two nil entries")
	}
	if a == nil {
		cp := *b
		return &cp, nil
	}
	if b == nil {
		cp := *a
		return &cp, nil
	}

	m := *a
	switch {
	case a.Status == StatusFailed || b.Status == StatusFailed:
		m.Status = StatusFailed
	case a.Status == StatusCompleted || b.Status == StatusCompleted:
		m.Status = StatusCompleted
	default:
		m.Status = StatusCancelled
	}
	if m.Status == StatusFailed {
		m.Err = failedErr(a, b)
	}

	m.Technologies = mergeTechnologyResults(a.Technologies, b.Technologies)
	if m.Endpoint == nil && b.Endpoint != nil {
		ep := *b.Endpoint
		m.Endpoint = &ep
	}
	if m.source == "" && b.source != "" {
		m.source = b.source
	}
	if !b.FirstSeen.IsZero() && (m.FirstSeen.IsZero() || b.FirstSeen.Before(m.FirstSeen)) {
		m.FirstSeen = b.FirstSeen
	}
	if b.LastSeen.After(m.LastSeen) {
		m.LastSeen = b.LastSeen
	}
	m.Evidence = mergeEvidence(a.Evidence, b.Evidence)
	m.Relationships = mergeRelationships(a.Relationships, b.Relationships)
	m.techEvidence = mergeTechEvidence(a.techEvidence, b.techEvidence)
	m.Conflicts = a.Conflicts + b.Conflicts
	m.Truncated = a.Truncated || b.Truncated
	m.Overflow.Technologies = a.Overflow.Technologies || b.Overflow.Technologies
	m.Overflow.Indicators = a.Overflow.Indicators || b.Overflow.Indicators
	m.Overflow.Cookies = a.Overflow.Cookies || b.Overflow.Cookies
	m.Cached = a.Cached || b.Cached
	return &m, nil
}

// mergeTechnologyResults folds two per-observation technology lists into
// one deterministic list: merged per technology identity; the higher score
// wins the quality (a version-less winner inherits the only version in
// play); on a score TIE the merged contributor is the one winning the
// tie-break chain, so the result is identical regardless of the merge
// order (and identical between fresh-only runs and cache-served runs, since
// the version-bearing indicator's DB ordinal is persisted in records). The
// merged list is then sorted score desc, name asc.
func mergeTechnologyResults(a, b []TechnologyResult) []TechnologyResult {
	byID := make(map[string]TechnologyResult, len(a)+len(b))
	var order []string
	addAll := func(list []TechnologyResult) {
		for _, tr := range list {
			key := tr.Technology.ID()
			prev, ok := byID[key]
			if !ok {
				byID[key] = tr
				order = append(order, key)
				continue
			}
			if tr.Score > prev.Score {
				// Higher score wins the quality; a version-less winner
				// inherits the only version in play.
				merged := tr
				if merged.Technology.Version == "" && prev.Technology.Version != "" {
					merged.Technology.Version = prev.Technology.Version
				}
				byID[key] = merged
			} else if tr.Score == prev.Score && technologyChainBetter(tr, prev) {
				byID[key] = tr
			}
		}
	}
	addAll(a)
	addAll(b)

	out := make([]TechnologyResult, 0, len(order))
	for _, key := range order {
		out = append(out, byID[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Technology.Name < out[j].Technology.Name
	})
	return out
}

// technologyChainBetter is the deterministic equal-score tie-break between
// two same-identity technology contributors, in exact priority order:
//
//  1. a version-bearing contributor outranks a version-less one (the only
//     version in play always survives);
//  2. the earliest ObservedAt wins (Technology.Prov.DiscoveredAt);
//  3. the lowest source name wins (Technology.Prov.Source);
//  4. the first in DB order of the version-bearing indicator wins
//     (TechnologyResult.versionOrdinal — the flat 1-based position of the
//     indicator in the fingerprint database; cache-served contributors
//     carry the ordinal persisted in their record);
//  5. the lexicographically lowest version string wins (final tie among
//     cache-served contributors whose orphans are otherwise identical);
//  6. the lexicographically lowest level wins (the last possible key — a
//     total deterministic order).
//
// The chain is a strict total order over version-bearers, so merging in
// either order folds to the same contributor. (Two contributors that tie on
// every key are observationally identical.)
func technologyChainBetter(tr, prev TechnologyResult) bool {
	trHas := tr.Technology.Version != ""
	prevHas := prev.Technology.Version != ""
	if trHas != prevHas {
		return trHas
	}
	if !tr.Technology.Prov.DiscoveredAt.Equal(prev.Technology.Prov.DiscoveredAt) {
		return tr.Technology.Prov.DiscoveredAt.Before(prev.Technology.Prov.DiscoveredAt)
	}
	if tr.Technology.Prov.Source != prev.Technology.Prov.Source {
		return tr.Technology.Prov.Source < prev.Technology.Prov.Source
	}
	if tr.versionOrdinal != prev.versionOrdinal {
		return tr.versionOrdinal < prev.versionOrdinal
	}
	if tr.Technology.Version != prev.Technology.Version {
		return tr.Technology.Version < prev.Technology.Version
	}
	return tr.Level < prev.Level
}

// failedErr selects the merged Err of two failed-contributing entries with
// the deterministic failed chain: the failed entry with the earliest
// FirstSeen (the observation's own ObservedAt) wins; then the lowest source
// name; then the lowest error text — a total order, so the merged Err never
// depends on the merge order.
func failedErr(a, b *ReportEntry) error {
	aFailed := a.Status == StatusFailed
	bFailed := b.Status == StatusFailed
	switch {
	case aFailed && bFailed:
		if failedEntryChainBetter(b, a) {
			return b.Err
		}
		return a.Err
	case aFailed:
		return a.Err
	case bFailed:
		return b.Err
	}
	return nil
}

// failedEntryChainBetter is the deterministic order between two failed
// entries: earliest FirstSeen, then lowest source name, then lowest error
// text.
func failedEntryChainBetter(x, y *ReportEntry) bool {
	if !x.FirstSeen.Equal(y.FirstSeen) {
		return x.FirstSeen.Before(y.FirstSeen)
	}
	if x.source != y.source {
		return x.source < y.source
	}
	return errText(x.Err) < errText(y.Err)
}

// errText returns the error text of a possibly-nil error ("" for nil).
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// mergeEvidence dedupes evidence by identity and sorts by identity.
func mergeEvidence(a, b []asset.Evidence) []asset.Evidence {
	byID := make(map[string]asset.Evidence, len(a)+len(b))
	for _, ev := range a {
		byID[ev.ID()] = ev
	}
	for _, ev := range b {
		byID[ev.ID()] = ev
	}
	out := make([]asset.Evidence, 0, len(byID))
	for _, ev := range byID {
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// mergeRelationships dedupes relationships by edge identity and sorts by
// identity.
func mergeRelationships(a, b []asset.Relationship) []asset.Relationship {
	byID := make(map[string]asset.Relationship, len(a)+len(b))
	for _, r := range a {
		byID[r.ID()] = r
	}
	for _, r := range b {
		byID[r.ID()] = r
	}
	out := make([]asset.Relationship, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// mergeTechEvidence unions per-technology evidence ID lists. analyze.go's
// appendUnique keeps each list deduplicated.
func mergeTechEvidence(a, b map[string][]string) map[string][]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string][]string, len(a)+len(b))
	for k, ids := range a {
		for _, id := range ids {
			out[k] = appendUnique(out[k], id)
		}
	}
	for k, ids := range b {
		for _, id := range ids {
			out[k] = appendUnique(out[k], id)
		}
	}
	return out
}

// normalizeEntry makes an entry's collections deterministic in place:
// technologies score desc then name asc, evidence and relationships by
// identity.
func normalizeEntry(e *ReportEntry) {
	sort.SliceStable(e.Technologies, func(i, j int) bool {
		if e.Technologies[i].Score != e.Technologies[j].Score {
			return e.Technologies[i].Score > e.Technologies[j].Score
		}
		return e.Technologies[i].Technology.Name < e.Technologies[j].Technology.Name
	})
	sort.Slice(e.Evidence, func(i, j int) bool { return e.Evidence[i].ID() < e.Evidence[j].ID() })
	sort.Slice(e.Relationships, func(i, j int) bool { return e.Relationships[i].ID() < e.Relationships[j].ID() })
}

// buildReport aggregates the run's entries into the deterministic Report:
// per-status counts, one merged Technology per identity (merged
// Prov.Confidence is the MAX contributing score; the merged level is the
// max-score contributor's, first observation wins ties; the first-seen
// version survives), evidence deduped by identity, relationships deduped by
// edge identity, total conflicts, sticky Truncated/Overflow flags, and the
// metrics snapshot.
func buildReport(entries []ReportEntry, malformed int, metrics MetricsSnapshot) Report {
	rep := Report{Levels: make(map[string]ConfidenceLevel)}
	rep.Observations.Malformed = malformed
	rep.Metrics = metrics

	techByID := make(map[string]asset.Technology)
	levelByID := make(map[string]ConfidenceLevel)

	for _, e := range entries {
		switch e.Status {
		case StatusCompleted:
			rep.Observations.Completed++
		case StatusCancelled:
			rep.Observations.Cancelled++
		case StatusFailed:
			rep.Observations.Failed++
		}
		rep.Conflicts += e.Conflicts
		rep.Truncated = rep.Truncated || e.Truncated
		rep.Overflow.Technologies = rep.Overflow.Technologies || e.Overflow.Technologies
		rep.Overflow.Indicators = rep.Overflow.Indicators || e.Overflow.Indicators
		rep.Overflow.Cookies = rep.Overflow.Cookies || e.Overflow.Cookies

		for _, tr := range e.Technologies {
			key := tr.Technology.ID()
			prev, ok := techByID[key]
			if !ok {
				t := tr.Technology
				t.Prov.Confidence = tr.Score
				techByID[key] = t
				levelByID[key] = tr.Level
				continue
			}
			if tr.Score > prev.Prov.Confidence {
				t := prev
				t.Prov.Confidence = tr.Score
				techByID[key] = t
				levelByID[key] = tr.Level
			} else if tr.Score == prev.Prov.Confidence && prev.Version == "" && tr.Technology.Version != "" {
				t := prev
				t.Version = tr.Technology.Version
				techByID[key] = t
			}
		}
	}

	rep.Technologies = make([]asset.Technology, 0, len(techByID))
	for _, t := range techByID {
		rep.Technologies = append(rep.Technologies, t)
	}
	sort.Slice(rep.Technologies, func(i, j int) bool {
		return rep.Technologies[i].Name < rep.Technologies[j].Name
	})
	rep.Levels = levelByID

	evByID := make(map[string]asset.Evidence)
	for _, e := range entries {
		for _, ev := range e.Evidence {
			evByID[ev.ID()] = ev
		}
	}
	rep.Evidence = make([]asset.Evidence, 0, len(evByID))
	for _, ev := range evByID {
		rep.Evidence = append(rep.Evidence, ev)
	}
	sort.Slice(rep.Evidence, func(i, j int) bool { return rep.Evidence[i].ID() < rep.Evidence[j].ID() })

	relByID := make(map[string]asset.Relationship)
	for _, e := range entries {
		for _, r := range e.Relationships {
			relByID[r.ID()] = r
		}
	}
	rep.Relationships = make([]asset.Relationship, 0, len(relByID))
	for _, r := range relByID {
		rep.Relationships = append(rep.Relationships, r)
	}
	sort.Slice(rep.Relationships, func(i, j int) bool { return rep.Relationships[i].ID() < rep.Relationships[j].ID() })

	return rep
}

// hostOrZero derives the host asset of a URL, or a zero Host when the URL
// has no hostname worth an edge (IP literals, empty hosts).
func hostOrZero(u asset.URL) asset.Host {
	host := u.HostPort
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// A trailing colon is a port separator only when it is outside IPv6
		// brackets.
		if !strings.Contains(host[i:], "]") {
			host = host[:i]
		}
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" {
		return asset.Host{}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return asset.Host{} // host edges are for hostnames only
	}
	h, err := asset.NewHost(host, asset.Provenance{})
	if err != nil {
		return asset.Host{}
	}
	return h
}

// graphOf builds the asset-graph edges for one observation: host/URL/endpoint
// to every retained technology, and technology to every evidence record that
// fired it. Edges are deterministic in technology order (score desc, name
// asc) and evidence order.
func graphOf(o Observation, technologies []TechnologyResult, techEvidence map[string][]string) []asset.Relationship {
	var out []asset.Relationship
	urlID := o.URL.Identity()
	host := hostOrZero(o.URL)

	for _, t := range technologies {
		techID := t.Technology.Identity()
		if !host.Identity().IsZero() {
			if r, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToTechnology, techID); err == nil {
				out = append(out, r)
			}
		}
		if r, err := asset.NewRelationship(urlID, asset.RelationshipURLToTechnology, techID); err == nil {
			out = append(out, r)
		}
		if o.Endpoint != nil {
			if r, err := asset.NewRelationship(o.Endpoint.Identity(), asset.RelationshipEndpointToTechnology, techID); err == nil {
				out = append(out, r)
			}
		}
		for _, evID := range techEvidence[t.Technology.ID()] {
			evIdentity := asset.Identity{Kind: asset.KindEvidence, Value: evID}
			if r, err := asset.NewRelationship(techID, asset.RelationshipTechnologyToEvidence, evIdentity); err == nil {
				out = append(out, r)
			}
		}
	}
	return out
}
