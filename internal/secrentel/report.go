package secrentel

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Status is the outcome of one document's processing.
type Status string

const (
	// StatusCompleted marks a document whose scan finished (fresh scan or a
	// served cache hit) over an untruncated document.
	StatusCompleted Status = "completed"
	// StatusIncomplete marks an honest truncated scan: the scanned prefix's
	// candidates are reported, but the document exceeded the fixed size cap
	// and the scan is incomplete by definition — stored incomplete, never
	// served from cache.
	StatusIncomplete Status = "incomplete"
	// StatusCancelled marks a document whose work never executed.
	StatusCancelled Status = "cancelled"
	// StatusFailed marks a document that could not be processed (for example
	// a cache-key failure).
	StatusFailed Status = "failed"
)

// Valid reports whether s is a known entry status.
func (s Status) Valid() bool {
	switch s {
	case StatusCompleted, StatusIncomplete, StatusCancelled, StatusFailed:
		return true
	}
	return false
}

// edgeSourceSnapshot records how source→candidate edges are rebuilt for a
// document (from fresh scans, stored records, and merges).
type edgeSourceSnapshot struct {
	From    asset.Identity
	Kind    asset.RelationshipKind
	Present bool
}

// ReportEntry is the full result of one processed document. ID is the scan
// identity (kind "document"); entries are the unit of cache records and of
// the merge accumulator.
type ReportEntry struct {
	ID            asset.Identity       `json:"id"`
	Status        Status               `json:"status"`
	Doc           DocumentRef          `json:"doc"`
	CandidateSrc  asset.Identity       `json:"candidate_source"`
	EdgeSrc       edgeSourceSnapshot   `json:"-"`
	Secrets       []scannedCandidate   `json:"-"`
	Evidence      []asset.Evidence     `json:"evidence,omitempty"`
	Relationships []asset.Relationship `json:"relationships,omitempty"`
	Counts        scanCounts           `json:"counts,omitempty"`
	Truncated     bool                 `json:"truncated,omitempty"`
	Overflow      bool                 `json:"overflow,omitempty"`
	FirstSeen     time.Time            `json:"first_seen,omitempty"`
	LastSeen      time.Time            `json:"last_seen,omitempty"`
	Sources       []string             `json:"sources,omitempty"`
	Cached        bool                 `json:"cached,omitempty"`

	// Err is the bounded failure cause for StatusFailed entries; never
	// serialized.
	Err error `json:"-"`
}

// DocumentStats are the per-status document counts of one report.
type DocumentStats struct {
	Completed  int `json:"completed"`
	Incomplete int `json:"incomplete"`
	Cancelled  int `json:"cancelled"`
	Failed     int `json:"failed"`
	Malformed  int `json:"malformed"`
}

// QueueEntry is one candidate recommended for later verification. The queue
// is offline bookkeeping only: nothing is executed, contacted, or validated
// here, and the queue itself is never cached — it is derived
// deterministically from the report's secrets at build time.
type QueueEntry struct {
	CandidateID string    `json:"candidate_id"`
	Type        string    `json:"type"`
	Provider    string    `json:"provider,omitempty"`
	Score       float64   `json:"score"`
	Level       Level     `json:"level"`
	Priority    int       `json:"priority"` // 1-based rank in queue order
	EnqueuedAt  time.Time `json:"enqueued_at"`
}

// Queue membership and bounds (fixed constants, deliberately not
// configuration).
const (
	// queueMinLevel is the minimum level that enters the verification queue.
	queueMinLevel = LevelMedium
	// maxQueueEntries bounds the queue; overflow is counted.
	maxQueueEntries = 512
)

// Report aggregates every document of one Ingest run. Everything is
// deterministic: secrets by score desc then candidate ID, evidence and
// relationships by identity, the queue in priority order.
type Report struct {
	Documents     DocumentStats        `json:"documents"`
	Secrets       []SecretResult       `json:"secrets"`
	Evidence      []asset.Evidence     `json:"evidence,omitempty"`
	Relationships []asset.Relationship `json:"relationships,omitempty"`
	Queue         []QueueEntry         `json:"queue,omitempty"`
	QueueOverflow int                  `json:"queue_overflow,omitempty"`
	Truncated     bool                 `json:"truncated,omitempty"`
	Overflow      bool                 `json:"overflow,omitempty"`
	Metrics       MetricsSnapshot      `json:"metrics"`
}

// accumulator is the merge store for one run: one merged entry per scan
// identity, plus the malformed counter. Safe for concurrent use.
type accumulator struct {
	mu        sync.Mutex
	entries   map[string]*ReportEntry
	malformed int
}

func newAccumulator() *accumulator {
	return &accumulator{entries: make(map[string]*ReportEntry)}
}

// preRegister reserves a cancelled placeholder so a dropped job (forced
// shutdown) appears honestly as cancelled.
func (a *accumulator) preRegister(sd scannedDocument) {
	id := sd.identity.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.entries[id]; !ok {
		a.entries[id] = &ReportEntry{
			ID:           sd.identity,
			Status:       StatusCancelled,
			Doc:          sd.ref(),
			CandidateSrc: sd.candidateSource(),
			EdgeSrc:      edgeSourceOf(&sd),
			FirstSeen:    sd.observedAt,
			Sources:      []string{sd.source},
		}
	}
}

// merge folds one processed entry into the accumulator under its identity.
func (a *accumulator) merge(id string, e *ReportEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.entries[id]; ok {
		if merged, err := mergeEntries(prev, e); err == nil {
			a.entries[id] = merged
		}
		return
	}
	cp := *e
	a.entries[id] = &cp
}

// addMalformed counts one malformed document.
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

// mergeEntries merges two entries of the SAME scan identity (the identity
// covers every result-relevant input, so both sides describe the same scan).
// Status resolves failed > incomplete > completed > cancelled; secrets merge
// per candidate ID (higher score wins; exact ties resolve by the joined
// pattern-ID list — a total order, so merge order never matters); counts
// stay with the merged entry (identical scans report identical counts);
// evidence and relationships dedupe by identity; sources union in
// first-observation order; timestamps widen; flags are sticky.
func mergeEntries(a, b *ReportEntry) (*ReportEntry, error) {
	if a == nil && b == nil {
		return nil, errors.New("secrentel: merge of two nil entries")
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
		if a.Status == StatusFailed && a.Err != nil {
			m.Err = a.Err
		} else if b.Err != nil {
			m.Err = b.Err
		}
	case a.Status == StatusIncomplete || b.Status == StatusIncomplete:
		m.Status = StatusIncomplete
	case a.Status == StatusCompleted || b.Status == StatusCompleted:
		m.Status = StatusCompleted
	default:
		m.Status = StatusCancelled
	}

	m.Secrets = mergeCandidates(a.Secrets, b.Secrets)
	m.Evidence = mergeEvidenceList(a.Evidence, b.Evidence)
	m.Relationships = mergeRelationshipList(a.Relationships, b.Relationships)
	m.Sources = unionStrings(a.Sources, b.Sources)
	// The pre-registered placeholder carries zero counts; the processed
	// contributor's accounting must survive the merge. Two processed
	// contributors describe the same (deterministic) scan, so keeping the
	// first non-zero side is order-independent.
	if scanCountsTotal(a.Counts) == 0 && scanCountsTotal(b.Counts) > 0 {
		m.Counts = b.Counts
	}
	if !b.FirstSeen.IsZero() && (m.FirstSeen.IsZero() || b.FirstSeen.Before(m.FirstSeen)) {
		m.FirstSeen = b.FirstSeen
	}
	if b.LastSeen.After(m.LastSeen) {
		m.LastSeen = b.LastSeen
	}
	m.Truncated = a.Truncated || b.Truncated
	m.Overflow = a.Overflow || b.Overflow
	m.Cached = a.Cached || b.Cached
	if !m.EdgeSrc.Present && b.EdgeSrc.Present {
		m.EdgeSrc = b.EdgeSrc
	}
	if m.CandidateSrc.IsZero() && !b.CandidateSrc.IsZero() {
		m.CandidateSrc = b.CandidateSrc
	}
	return &m, nil
}

// scanCountsTotal sums one counts record (merge bookkeeping only).
func scanCountsTotal(c scanCounts) int {
	return c.SuppressedFP + c.DroppedNegative + c.DroppedValidator +
		c.DroppedEntropy + c.DroppedLength + c.DroppedDuplicateValue + c.OverflowDropped
}

// mergeCandidates folds two candidate lists into one deterministic list,
// merged by candidate ID. The higher score wins; on an exact tie the lower
// joined pattern-ID list wins.
func mergeCandidates(a, b []scannedCandidate) []scannedCandidate {
	byID := make(map[string]scannedCandidate, len(a)+len(b))
	add := func(c scannedCandidate) {
		prev, ok := byID[c.id]
		if !ok || candidateBetter(c, prev) {
			byID[c.id] = c
		}
	}
	for _, c := range a {
		add(c)
	}
	for _, c := range b {
		add(c)
	}
	out := make([]scannedCandidate, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].id < out[j].id
	})
	return out
}

// candidateBetter is the deterministic same-ID tie-break: higher score,
// then lower joined pattern IDs, then lower level string.
func candidateBetter(c, prev scannedCandidate) bool {
	if c.confidence.Score != prev.confidence.Score {
		return c.confidence.Score > prev.confidence.Score
	}
	cj, pj := joinStrings(c.patternIDs, "+"), joinStrings(prev.patternIDs, "+")
	if cj != pj {
		return cj < pj
	}
	return string(c.confidence.Level) < string(prev.confidence.Level)
}

// mergeEvidenceList dedupes evidence by identity and sorts by identity.
func mergeEvidenceList(a, b []asset.Evidence) []asset.Evidence {
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

// mergeRelationshipList dedupes relationships by edge identity and sorts.
func mergeRelationshipList(a, b []asset.Relationship) []asset.Relationship {
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

// unionStrings unions two bounded lists preserving first-observation order.
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// buildReport aggregates the run's merged entries into the deterministic
// Report: per-status counts, cross-document secret merging with the repeat
// factor, evidence/relationship dedup, and the offline verification queue.
func buildReport(entries []ReportEntry, malformed int, metrics MetricsSnapshot, clock runtime.Clock) Report {
	rep := Report{Metrics: metrics}
	rep.Documents.Malformed = malformed

	type agg struct {
		result  SecretResult
		docIDs  map[string]struct{}
		sources []string
		cached  bool
	}
	byCand := make(map[string]*agg)

	for _, e := range entries {
		switch e.Status {
		case StatusCompleted:
			rep.Documents.Completed++
		case StatusIncomplete:
			rep.Documents.Incomplete++
		case StatusCancelled:
			rep.Documents.Cancelled++
		case StatusFailed:
			rep.Documents.Failed++
		}
		rep.Truncated = rep.Truncated || e.Truncated
		rep.Overflow = rep.Overflow || e.Overflow

		if e.Status != StatusCompleted && e.Status != StatusIncomplete {
			continue
		}
		for i := range e.Secrets {
			c := &e.Secrets[i]
			a, ok := byCand[c.id]
			if !ok {
				a = &agg{
					result:  c.resultOf(e.Doc, 1, e.Sources, e.Cached),
					docIDs:  map[string]struct{}{e.ID.String(): {}},
					sources: e.Sources,
					cached:  e.Cached,
				}
				byCand[c.id] = a
				continue
			}
			a.docIDs[e.ID.String()] = struct{}{}
			a.sources = unionStrings(a.sources, e.Sources)
			a.cached = a.cached || e.Cached
			if c.confidence.Score > a.result.Confidence.Score {
				a.result = c.resultOf(e.Doc, len(a.docIDs), a.sources, a.cached)
			}
		}
	}

	secrets := make([]SecretResult, 0, len(byCand))
	for _, a := range byCand {
		r := a.result
		r.Observations = len(a.docIDs)
		r.Sources = a.sources
		r.Cached = a.cached
		secrets = append(secrets, r)
	}

	// Cross-document REPEATED OBSERVATION: the same (type, value) observed
	// under different source identities (each keeps its own candidate
	// identity — attribution is never merged away) links its sibling
	// candidates and widens the observation count.
	pairKey := func(s SecretResult) string { return s.Type.String() + "\x00" + s.Value }
	byPair := make(map[string][]int)
	for i := range secrets {
		k := pairKey(secrets[i])
		byPair[k] = append(byPair[k], i)
	}
	for _, idxs := range byPair {
		if len(idxs) < 2 {
			continue
		}
		var allIDs []string
		observations := 0
		for _, i := range idxs {
			allIDs = append(allIDs, secrets[i].Candidate.ID())
			observations += secrets[i].Observations
		}
		for _, i := range idxs {
			r := &secrets[i]
			r.Observations = observations
			for _, id := range allIDs {
				if id != r.Candidate.ID() {
					r.Related = append(r.Related, Related{CandidateID: id, Relation: "repeat"})
				}
			}
		}
	}
	// One repeat pass: any candidate observed (directly or through its
	// value siblings) in two or more documents gains the repeat factor —
	// recompute is identical for cache-served and fresh candidates (the
	// pure-endpoint URL clamp re-applies, so a repeated bucket URL can
	// never escape its Low ceiling).
	for i := range secrets {
		r := &secrets[i]
		if r.Observations >= 2 && r.Confidence.Level != LevelUnknown {
			r.Confidence = applyRepeatFactor(r.Confidence, r.Type, string(r.Family), r.FPFlags)
		}
	}
	sort.SliceStable(secrets, func(i, j int) bool {
		if secrets[i].Confidence.Score != secrets[j].Confidence.Score {
			return secrets[i].Confidence.Score > secrets[j].Confidence.Score
		}
		return secrets[i].Candidate.ID() < secrets[j].Candidate.ID()
	})
	rep.Secrets = secrets
	rep.Queue, rep.QueueOverflow = buildQueue(secrets, clock.Now().UTC())

	evByID := make(map[string]asset.Evidence)
	relByID := make(map[string]asset.Relationship)
	for _, e := range entries {
		for _, ev := range e.Evidence {
			evByID[ev.ID()] = ev
		}
		for _, r := range e.Relationships {
			relByID[r.ID()] = r
		}
	}
	rep.Evidence = make([]asset.Evidence, 0, len(evByID))
	for _, ev := range evByID {
		rep.Evidence = append(rep.Evidence, ev)
	}
	sort.Slice(rep.Evidence, func(i, j int) bool { return rep.Evidence[i].ID() < rep.Evidence[j].ID() })
	rep.Relationships = make([]asset.Relationship, 0, len(relByID))
	for _, r := range relByID {
		rep.Relationships = append(rep.Relationships, r)
	}
	sort.Slice(rep.Relationships, func(i, j int) bool { return rep.Relationships[i].ID() < rep.Relationships[j].ID() })
	return rep
}

// buildQueue derives the offline verification queue: every secret at or
// above queueMinLevel with NO false-positive flags, in deterministic
// priority order (the report's order). Overflow beyond maxQueueEntries is
// counted, never silently dropped. Nothing here contacts anything.
func buildQueue(secrets []SecretResult, now time.Time) ([]QueueEntry, int) {
	var queue []QueueEntry
	overflow := 0
	for _, s := range secrets {
		if len(s.FPFlags) > 0 {
			continue
		}
		if s.Confidence.Level.rank() < queueMinLevel.rank() {
			continue
		}
		if len(queue) >= maxQueueEntries {
			overflow++
			continue
		}
		queue = append(queue, QueueEntry{
			CandidateID: s.Candidate.ID(),
			Type:        string(s.Type),
			Provider:    s.Provider,
			Score:       s.Confidence.Score,
			Level:       s.Confidence.Level,
			EnqueuedAt:  now,
		})
	}
	for i := range queue {
		queue[i].Priority = i + 1
	}
	return queue, overflow
}
