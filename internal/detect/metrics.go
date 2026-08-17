package detect

import (
	"sort"
	"sync"
	"time"
)

// Metrics accumulates the run's rule execution counters: per-rule statistics
// (execution time, findings, errors, timeouts, panics, cache hits and
// misses) and the run aggregates. It is safe for concurrent use; a nil
// *Metrics is a no-op.
type Metrics struct {
	mu sync.Mutex

	executions int
	hits       int
	misses     int
	errors     int
	timeouts   int
	panics     int
	findings   int

	perRule map[string]*RuleStats
}

// RuleStats is one rule's accumulated statistics.
type RuleStats struct {
	// ID is the rule's canonical ID.
	ID string

	// Executions counts fresh detector executions (cache hits excluded).
	Executions int

	// TotalTime is the cumulative detector execution time.
	TotalTime time.Duration

	// Findings counts validated findings the rule produced.
	Findings int

	// Errors, Timeouts, and Panics count the failure classes.
	Errors   int
	Timeouts int
	Panics   int

	// CacheHits and CacheMisses count the rule's cache outcomes.
	CacheHits   int
	CacheMisses int
}

// MetricsSnapshot is a consistent point-in-time copy of the counters with
// the per-rule statistics sorted by rule ID.
type MetricsSnapshot struct {
	Executions  int
	CacheHits   int
	CacheMisses int
	Errors      int
	Timeouts    int
	Panics      int
	Findings    int
	Rules       []RuleStats
}

// mut runs f under the metrics lock; a nil Metrics is a no-op.
func (m *Metrics) mut(f func()) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f()
}

// statsOf returns the stats entry for id, creating it if needed. Callers
// must hold the metrics lock.
func (m *Metrics) statsOf(id string) *RuleStats {
	if m.perRule == nil {
		m.perRule = make(map[string]*RuleStats)
	}
	if rs, ok := m.perRule[id]; ok {
		return rs
	}
	rs := &RuleStats{ID: id}
	m.perRule[id] = rs
	return rs
}

// Snapshot returns a consistent copy of the counters. A nil Metrics
// snapshots as all zeros.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := MetricsSnapshot{
		Executions: m.executions, CacheHits: m.hits, CacheMisses: m.misses,
		Errors: m.errors, Timeouts: m.timeouts, Panics: m.panics,
		Findings: m.findings,
	}
	if len(m.perRule) > 0 {
		s.Rules = make([]RuleStats, 0, len(m.perRule))
		for _, rs := range m.perRule {
			s.Rules = append(s.Rules, *rs)
		}
		sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].ID < s.Rules[j].ID })
	}
	return s
}

// recordExecution records one fresh detector execution of rule id that took
// d and produced n validated findings.
func (m *Metrics) recordExecution(id string, d time.Duration, n int) {
	m.mut(func() {
		m.executions++
		m.findings += n
		rs := m.statsOf(id)
		rs.Executions++
		rs.TotalTime += d
		rs.Findings += n
	})
}

// recordFailure records one failed execution of rule id in class kind
// ("error", "timeout", or "panic").
func (m *Metrics) recordFailure(id, kind string) {
	m.mut(func() {
		rs := m.statsOf(id)
		switch kind {
		case "timeout":
			m.timeouts++
			rs.Timeouts++
		case "panic":
			m.panics++
			rs.Panics++
		default:
			m.errors++
			rs.Errors++
		}
	})
}

// recordCache records one cache outcome for rule id.
func (m *Metrics) recordCache(id string, hit bool) {
	m.mut(func() {
		rs := m.statsOf(id)
		if hit {
			m.hits++
			rs.CacheHits++
		} else {
			m.misses++
			rs.CacheMisses++
		}
	})
}

// fold merges a finished run's internal counters into a caller-provided
// Metrics (the engine always counts into its own instance and folds it into
// the caller's, if any).
func (m *Metrics) fold(src MetricsSnapshot) {
	m.mut(func() {
		m.executions += src.Executions
		m.hits += src.CacheHits
		m.misses += src.CacheMisses
		m.errors += src.Errors
		m.timeouts += src.Timeouts
		m.panics += src.Panics
		m.findings += src.Findings
		for _, rs := range src.Rules {
			dst := m.statsOf(rs.ID)
			dst.Executions += rs.Executions
			dst.TotalTime += rs.TotalTime
			dst.Findings += rs.Findings
			dst.Errors += rs.Errors
			dst.Timeouts += rs.Timeouts
			dst.Panics += rs.Panics
			dst.CacheHits += rs.CacheHits
			dst.CacheMisses += rs.CacheMisses
		}
	})
}
