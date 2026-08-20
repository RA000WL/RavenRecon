package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// Quality signal vocabulary for the discovery data-quality gate.
const (
	// SignalOverCap marks a source whose fresh result exceeded MaxPerSource:
	// the retained set was truncated to the first MaxPerSource names and the
	// excess was dropped (honest truncation, never silent).
	SignalOverCap = "over_cap"
	// SignalDivergence marks a source whose fresh retained count exceeded the
	// configured ratio times the median of the OTHER producing sources'
	// counts (see QualityConfig.DivergenceMinCount).
	SignalDivergence = "divergence"
)

// ValidQualitySignal reports whether s is a known gate signal.
func ValidQualitySignal(s string) bool {
	return s == SignalOverCap || s == SignalDivergence
}

// QualityConfig configures the per-source discovery data-quality gate.
//
// The zero value is meaningful: NormalizeQualityConfig maps zero/negative
// fields to the documented defaults, mirroring the OptionsFromConfig pattern
// elsewhere in this package. The gate is deterministic: thresholds are
// constants, no wall-clock reading, no burst/anomaly detection (the field
// trial's "same-timestamp burst" is framework-assigned time and is
// meaningless — documented explicitly OUT of scope).
type QualityConfig struct {
	// MaxPerSource bounds the hosts retained from a single fresh source
	// result. Excess names are truncated (first MaxPerSource kept) and
	// recorded as an over_cap issue. 0 means the default (50000).
	MaxPerSource int

	// DivergenceRatio is the multiplier over the median of the other
	// producing sources' counts beyond which a source is flagged. A source
	// fires divergence only when its count exceeds ratio x median (strictly
	// greater: the exact boundary does not fire). 0 means the default (10).
	DivergenceRatio float64

	// DivergenceMinCount is the minimum outlier count for a divergence
	// signal (count > DivergenceMinCount, strictly greater): tiny targets
	// with few hosts never fire divergence. 0 means the default (100).
	DivergenceMinCount int

	// AbortOnFlag, when true, makes the RUN fail (structured error naming
	// the source + signal) when any issue fires. Default false: flag +
	// continue is the default policy (recon over paranoia); abort is
	// available to embedders.
	AbortOnFlag bool
}

// DefaultQualityConfig returns the documented gate defaults.
func DefaultQualityConfig() QualityConfig {
	return QualityConfig{
		MaxPerSource:       50000,
		DivergenceRatio:    10,
		DivergenceMinCount: 100,
		AbortOnFlag:        false,
	}
}

// NormalizeQualityConfig maps zero/negative fields to the documented
// defaults. AbortOnFlag is a bool; zero (false) is the documented default
// and is left unchanged.
func NormalizeQualityConfig(qc QualityConfig) QualityConfig {
	d := DefaultQualityConfig()
	if qc.MaxPerSource <= 0 {
		qc.MaxPerSource = d.MaxPerSource
	}
	if qc.DivergenceRatio <= 0 {
		qc.DivergenceRatio = d.DivergenceRatio
	}
	if qc.DivergenceMinCount <= 0 {
		qc.DivergenceMinCount = d.DivergenceMinCount
	}
	return qc
}

// QualityIssue is one gate finding for one source.
//
// Signal is one of SignalOverCap or SignalDivergence. Count is the source's
// retained host count at evaluation time (for over_cap: the FRESH count
// before truncation). Others lists the OTHER producing sources' retained
// counts in selection order (only for divergence; nil for over_cap).
type QualityIssue struct {
	Source string `json:"source"`
	Signal string `json:"signal"`
	Count  int    `json:"count"`
	Others []int  `json:"others,omitempty"`
}

// applyQualityGate runs the per-source quality gate AFTER tool output, on the
// filled per-source slot array, and BEFORE the report is assembled/merged
// (selection order is preserved: the gate never reorders results — it
// truncates a fresh source's Hosts in place and appends per-slot issues).
//
// The gate is evaluated once per run at the join point:
//
//   - Pass 1 (cap): every FRESH source with more than MaxPerSource hosts is
//     truncated to the first MaxPerSource hosts (deterministic: per-source
//     host lists are sorted) and records an over_cap issue with the original
//     count. Cached slots are never re-truncated: their stored data already
//     reflects the run that produced it (replay path).
//   - Pass 2 (divergence): for every FRESH producing source, divergence is
//     computed from the retained counts of all producing sources (fresh
//     post-cap and replayed): zero-producing sources never skew the median;
//     the median of the OTHER sources (standard median: even count averages
//     the middle two) must be computable over at least 2 other producing
//     sources, i.e. the run needs >= 3 producing sources — otherwise
//     divergence cannot fire (documented: "2 vs 37k" with only two sources
//     does not fire divergence; the cap is the safety net).
//
// Returns the aggregated issues in selection order (per-slot, over_cap
// before divergence).
func applyQualityGate(results []SourceResult, qc QualityConfig) []QualityIssue {
	// Pass 1: cap truncation.
	for i := range results {
		res := &results[i]
		if res.Cached {
			continue
		}
		if n := len(res.Hosts); n > qc.MaxPerSource {
			res.Hosts = res.Hosts[:qc.MaxPerSource]
			res.QualityIssues = append(res.QualityIssues, QualityIssue{
				Source: res.Source,
				Signal: SignalOverCap,
				Count:  n,
			})
		}
	}

	// Pass 2: divergence, only when at least three sources produced hosts.
	producing := 0
	for i := range results {
		if len(results[i].Hosts) > 0 {
			producing++
		}
	}
	if producing >= 3 {
		for i := range results {
			res := &results[i]
			if res.Cached || len(res.Hosts) == 0 {
				continue
			}
			others := otherProducingCounts(results, i)
			med := median(others)
			if float64(len(res.Hosts)) > float64(qc.DivergenceMinCount) &&
				float64(len(res.Hosts)) > qc.DivergenceRatio*med {
				res.QualityIssues = append(res.QualityIssues, QualityIssue{
					Source: res.Source,
					Signal: SignalDivergence,
					Count:  len(res.Hosts),
					Others: others,
				})
			}
		}
	}

	var out []QualityIssue
	for i := range results {
		out = append(out, results[i].QualityIssues...)
	}
	return out
}

// otherProducingCounts returns the retained host counts of the OTHER
// producing sources in selection order. Non-producing sources are excluded
// (they must not skew the median). The result is a fresh slice.
func otherProducingCounts(results []SourceResult, idx int) []int {
	var out []int
	for i := range results {
		if i == idx || len(results[i].Hosts) == 0 {
			continue
		}
		out = append(out, len(results[i].Hosts))
	}
	return out
}

// median returns the standard median of xs: the middle value when the sorted
// length is odd, the average of the two middle values when even. The empty
// median is 0 (callers only invoke it with >= 2 values, but a 0 median
// cannot fire a ratio comparison anyway).
func median(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]int(nil), xs...)
	sort.Ints(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return float64(sorted[mid])
	}
	return (float64(sorted[mid-1]) + float64(sorted[mid])) / 2
}

// qualityGateError builds the structured abort error naming every issue's
// source + signal. It contains no secret material.
func qualityGateError(issues []QualityIssue, qc QualityConfig) error {
	parts := make([]string, 0, len(issues))
	for _, iss := range issues {
		switch iss.Signal {
		case SignalOverCap:
			parts = append(parts, fmt.Sprintf("source %s: signal %s (count %d over cap %d)", iss.Source, iss.Signal, iss.Count, qc.MaxPerSource))
		case SignalDivergence:
			parts = append(parts, fmt.Sprintf("source %s: signal %s (count %d over ratio %g x median %v)", iss.Source, iss.Signal, iss.Count, qc.DivergenceRatio, median(iss.Others)))
		default:
			parts = append(parts, fmt.Sprintf("source %s: signal %s (count %d)", iss.Source, iss.Signal, iss.Count))
		}
	}
	return fmt.Errorf("discovery: quality gate: %s", strings.Join(parts, "; "))
}
