package tui

import "time"

// rateWindow is the fixed window of the rolling throughput averages: a rate
// at time t is the count delta between the oldest sample at or after t-
// rateWindow and the newest sample, divided by the elapsed time from that
// oldest sample to t. It is a fixed constant, deliberately not
// configuration.
const rateWindow = 10 * time.Second

// maxRateSamples bounds the per-metric sample ring. With the 10 s window
// this supports up to 12.8 recorded events per millisecond before the
// oldest in-window samples are approximated away (drop-oldest, counted in
// Dropped) — far beyond any realistic event rate, while keeping the memory
// of every metric structurally bounded regardless of input.
const maxRateSamples = 128

// metric identifies one rolling rate series.
type metric int

// The throughput metrics. The first eight are the rendered per-second
// rates; metricTasks backs the ETA estimator only and is never rendered.
const (
	metricAssets metric = iota
	metricURLs
	metricRequests
	metricJS
	metricRules
	metricRelationships
	metricCacheHits
	metricCacheMisses
	metricTasks
	metricCount
)

// metricNames is the deterministic render order of the displayed metrics.
var metricNames = map[metric]string{
	metricAssets:        "assets",
	metricURLs:          "urls",
	metricRequests:      "requests",
	metricJS:            "js",
	metricRules:         "rules",
	metricRelationships: "relationships",
	metricCacheHits:     "cache-hits",
	metricCacheMisses:   "cache-misses",
}

// displayedMetrics is the fixed render order of the per-second rates.
var displayedMetrics = []metric{
	metricAssets, metricURLs, metricRequests, metricJS, metricRules,
	metricRelationships, metricCacheHits, metricCacheMisses,
}

// rateSample is one (time, cumulative count) observation on a series.
type rateSample struct {
	at  time.Time
	cum int
}

// rateSeries is one metric's fixed-window rolling history: a bounded ring
// of samples in strictly increasing time order. The cumulative counts come
// from event deltas (each relevant event records one more unit), so the
// rate at any time is exactly the windowed slope of the count function.
type rateSeries struct {
	samples []rateSample // ring buffer
	start   int          // index of the oldest sample
	len     int          // number of live samples
	dropped uint64       // samples dropped by the ring cap
}

// record appends one unit of the metric at time at: the cumulative count
// grows by one and a sample is stored, then samples older than at-
// rateWindow are pruned and the ring cap is enforced.
func (r *rateSeries) record(at time.Time) {
	cum := 0
	if r.len > 0 {
		cum = r.samples[(r.start+r.len-1)%cap(r.samples)].cum
	}
	cum++
	r.append(rateSample{at: at, cum: cum})
	r.prune(at)
}

// recordCum appends an explicit cumulative count at time at (used by the
// task series, whose cumulative count comes from Progress.Completed rather
// than from one event per unit).
func (r *rateSeries) recordCum(at time.Time, cum int) {
	r.append(rateSample{at: at, cum: cum})
	r.prune(at)
}

// append stores one sample, dropping the oldest when the ring is full.
func (r *rateSeries) append(s rateSample) {
	if cap(r.samples) == 0 {
		r.samples = make([]rateSample, maxRateSamples)
	}
	if r.len == cap(r.samples) {
		r.start = (r.start + 1) % cap(r.samples)
		r.len--
		r.dropped++
	}
	r.samples[(r.start+r.len)%cap(r.samples)] = s
	r.len++
}

// prune drops samples strictly older than at-rateWindow.
func (r *rateSeries) prune(at time.Time) {
	cutoff := at.Add(-rateWindow)
	for r.len > 0 {
		oldest := r.samples[r.start]
		if !oldest.at.Before(cutoff) {
			break
		}
		r.start = (r.start + 1) % cap(r.samples)
		r.len--
	}
}

// rate returns the fixed-window rolling average at time now: the count
// delta between the oldest in-window sample and the newest, divided by the
// time from the oldest sample to now. Fewer than two in-window samples
// yield 0 (insufficient signal — a single event does not fabricate a rate).
func (r *rateSeries) rate(now time.Time) float64 {
	r.prune(now)
	if r.len < 2 {
		return 0
	}
	first := r.samples[r.start]
	last := r.samples[(r.start+r.len-1)%cap(r.samples)]
	dt := now.Sub(first.at).Seconds()
	if dt <= 0 {
		return 0
	}
	return float64(last.cum-first.cum) / dt
}

// Rates holds every metric's rolling series. It is single-consumer (the
// State owning it is single-consumer); no locking is needed.
type Rates struct {
	series [metricCount]rateSeries
}

// record advances one metric by one unit at time at.
func (r *Rates) record(m metric, at time.Time) {
	r.series[m].record(at)
}

// recordCum advances a metric to an explicit cumulative count (tasks).
func (r *Rates) recordCum(m metric, at time.Time, cum int) {
	r.series[m].recordCum(at, cum)
}

// rate returns the rolling rate of one metric at time now.
func (r *Rates) rate(m metric, now time.Time) float64 {
	return r.series[m].rate(now)
}

// dropped returns the total number of samples the ring cap dropped across
// every metric (the documented approximation bound at extreme rates).
func (r *Rates) dropped() uint64 {
	var d uint64
	for i := range r.series {
		d += r.series[i].dropped
	}
	return d
}
