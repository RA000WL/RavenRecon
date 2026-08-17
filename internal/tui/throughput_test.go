package tui

import (
	"math"
	"testing"
	"time"
)

func nearly(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestRateSeriesHandComputedWindow pins the fixed-window slope with a
// hand-computed example: 10 events at 1/s from t+1s to t+10s; at t+11s the
// oldest in-window sample is t+1s (cum 1) and the newest is t+10s (cum 10),
// so the rate is (10-1)/(11-1) = 0.9/s.
func TestRateSeriesHandComputedWindow(t *testing.T) {
	var r rateSeries
	t0 := testBase
	for i := 1; i <= 10; i++ {
		r.record(t0.Add(time.Duration(i) * time.Second))
	}
	got := r.rate(t0.Add(11 * time.Second))
	if !nearly(got, 0.9) {
		t.Fatalf("rate = %v, want 0.9", got)
	}
}

// TestRateSeriesWindowPrune pins that samples outside the 10s window stop
// contributing: 12 samples at 1/s from t to t+11s; at t+12s the samples at
// t and t+1s are pruned, leaving t+2s..t+11s: (12-3)/(12-2) = 0.9/s.
func TestRateSeriesWindowPrune(t *testing.T) {
	var r rateSeries
	t0 := testBase
	for i := 0; i <= 11; i++ {
		r.record(t0.Add(time.Duration(i) * time.Second))
	}
	got := r.rate(t0.Add(12 * time.Second))
	if !nearly(got, 0.9) {
		t.Fatalf("rate = %v, want 0.9", got)
	}
}

// TestRateSeriesInsuffcientSignal pins that fewer than two in-window
// samples never fabricate a rate.
func TestRateSeriesInsuffcientSignal(t *testing.T) {
	var r rateSeries
	t0 := testBase
	if got := r.rate(t0); got != 0 {
		t.Fatalf("empty series rate = %v, want 0", got)
	}
	r.record(t0)
	if got := r.rate(t0.Add(time.Second)); got != 0 {
		t.Fatalf("single-sample series rate = %v, want 0", got)
	}
}

// TestRateSeriesZeroSpan pins the dt <= 0 guard (same-instant samples,
// and a now before the first sample).
func TestRateSeriesZeroSpan(t *testing.T) {
	var r rateSeries
	t0 := testBase
	r.record(t0)
	r.record(t0) // same instant: cum 2, dt 0
	if got := r.rate(t0); got != 0 {
		t.Fatalf("zero-span rate = %v, want 0", got)
	}
	r.record(t0.Add(time.Second))
	if got := r.rate(t0); got != 0 {
		t.Fatalf("now before first sample rate = %v, want 0", got)
	}
}

// TestRateSeriesCumulativePins recordCum (the ETA's task series): the rate
// is the slope of the declared cumulative counts. Hand-computed: samples
// (t+5s, cum 8) and (t+11s, cum 10); at t+11s the rate is (10-8)/(11-5)
// = 1/3 per second.
func TestRateSeriesCumulative(t *testing.T) {
	var r rateSeries
	t0 := testBase
	r.recordCum(t0.Add(5*time.Second), 8)
	r.recordCum(t0.Add(11*time.Second), 10)
	got := r.rate(t0.Add(11 * time.Second))
	if !nearly(got, 1.0/3.0) {
		t.Fatalf("rate = %v, want 1/3", got)
	}
}

// TestRateSeriesRingCap pins the bounded sample ring: past maxRateSamples
// the oldest samples are dropped and counted.
func TestRateSeriesRingCap(t *testing.T) {
	var r rateSeries
	t0 := testBase
	for i := 0; i < maxRateSamples+50; i++ {
		r.record(t0.Add(time.Duration(i) * time.Millisecond))
	}
	if r.dropped != 50 {
		t.Fatalf("dropped = %d, want 50", r.dropped)
	}
	if r.len != maxRateSamples {
		t.Fatalf("len = %d, want %d", r.len, maxRateSamples)
	}
}

// TestRatesPerMetricIndependence pins that metrics do not bleed into each
// other and that the aggregate dropped counter sums across metrics.
func TestRatesPerMetricIndependence(t *testing.T) {
	var rates Rates
	t0 := testBase
	rates.record(metricAssets, t0)
	rates.record(metricAssets, t0.Add(time.Second))
	rates.record(metricRequests, t0)
	if got := rates.rate(metricAssets, t0.Add(2*time.Second)); !nearly(got, 0.5) {
		t.Fatalf("assets rate = %v, want 0.5", got)
	}
	if got := rates.rate(metricRequests, t0.Add(2*time.Second)); got != 0 {
		t.Fatalf("requests rate = %v, want 0 (single sample)", got)
	}
	for i := 0; i < maxRateSamples+7; i++ {
		rates.record(metricJS, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if rates.dropped() != 7 {
		t.Fatalf("aggregate dropped = %d, want 7", rates.dropped())
	}
}

// TestDisplayedMetricsOrder pins the deterministic render order and that
// every displayed metric has a name.
func TestDisplayedMetricsOrder(t *testing.T) {
	want := []metric{
		metricAssets, metricURLs, metricRequests, metricJS, metricRules,
		metricRelationships, metricCacheHits, metricCacheMisses,
	}
	if len(displayedMetrics) != len(want) {
		t.Fatalf("displayed metrics len = %d, want %d", len(displayedMetrics), len(want))
	}
	for i, m := range displayedMetrics {
		if m != want[i] {
			t.Fatalf("displayedMetrics[%d] = %d, want %d", i, m, want[i])
		}
		if metricNames[m] == "" {
			t.Fatalf("metric %d has no display name", m)
		}
	}
}
