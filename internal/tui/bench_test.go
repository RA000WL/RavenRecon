package tui

import (
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// This file benchmarks the TUI library's hot paths — the renderer frame
// build, the replay history at cap, the final summary generation, and the
// throughput computation — each with allocation stats (B/op, allocs/op).
// Every benchmark is hermetic and deterministic: it uses the scripted
// stream over testBase and an injected resource sampler, never the wall
// clock, the terminal, or the network.

// benchState applies the scripted run stream to a fresh state.
func benchState() *State {
	s := NewState(highRate)
	for _, e := range scriptedRun() {
		s.Apply(e)
	}
	return s
}

// BenchmarkTuiRenderFrame measures the live frame build for a fully applied
// run stream: the whole Render pipeline (progress, workers, throughput,
// resources, feeds, errors) into one bounded frame. The resource sampler is
// injected so the benchmark never touches the OS.
func BenchmarkTuiRenderFrame(b *testing.B) {
	b.ReportAllocs()
	s := benchState()
	s.sample = func() Resources { return Resources{HeapBytes: 1 << 20, Goroutines: 3, OpenFDs: 4} }
	now := testBase.Add(30 * time.Second)
	opts := Options{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame := Render(s, now, opts)
		if frame == "" {
			b.Fatal("empty frame")
		}
	}
}

// BenchmarkTuiRenderFinalFrame measures the final summary frame: the live
// frame plus the summary block (RenderFinal), the frame the controller
// writes exactly once at the end of a run.
func BenchmarkTuiRenderFinalFrame(b *testing.B) {
	b.ReportAllocs()
	s := benchState()
	s.sample = func() Resources { return Resources{HeapBytes: 1 << 20, Goroutines: 3, OpenFDs: 4} }
	now := testBase.Add(30 * time.Second)
	opts := Options{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame := RenderFinal(s, now, opts)
		if frame == "" {
			b.Fatal("empty frame")
		}
	}
}

// BenchmarkTuiHistoryAppendAtCap measures history insertion once the replay
// ring is full: every append evicts the oldest event and counts the drop,
// so the benchmark pins the steady-state per-event cost of the bounded
// replay buffer.
func BenchmarkTuiHistoryAppendAtCap(b *testing.B) {
	b.ReportAllocs()
	h, err := NewHistory(1024)
	if err != nil {
		b.Fatal(err)
	}
	ev := event.New(event.KindTaskSubmitted, testBase, event.TaskSubmitted{JobID: 1})
	for i := 0; i < h.Cap(); i++ {
		h.Append(ev)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Append(ev)
	}
}

// BenchmarkTuiSummary measures the final run summary computation over a
// fully applied run stream (the counter projection RenderFinal's summary
// block is built from).
func BenchmarkTuiSummary(b *testing.B) {
	b.ReportAllocs()
	s := benchState()
	var sum Summary
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum = s.Summary()
	}
	// Keep the computation observable.
	_ = sum
}

// BenchmarkTuiThroughputRate measures the fixed-window rolling rate
// computation over a full sample ring (128 samples in-window): the prune
// walk plus the slope over the oldest/newest samples, the per-render cost
// of every throughput metric.
func BenchmarkTuiThroughputRate(b *testing.B) {
	b.ReportAllocs()
	var rates Rates
	t0 := testBase
	for i := 0; i < maxRateSamples; i++ {
		rates.recordCum(metricTasks, t0.Add(time.Duration(i)*time.Millisecond), i+1)
	}
	// Touch every metric so the rings are measured at a realistic
	// multiplicity (the renderer computes a rate per displayed metric).
	for m := metric(0); m < metricCount; m++ {
		rates.record(m, t0.Add(time.Duration(maxRateSamples)*time.Millisecond))
	}
	now := t0.Add(time.Duration(maxRateSamples+1) * time.Millisecond)
	var r float64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = rates.rate(metricTasks, now)
	}
	// Keep the computation observable.
	_ = r
}

// BenchmarkTuiThroughputRecord measures recording one event-time sample on
// one metric series (the per-event cost of the throughput monitor).
func BenchmarkTuiThroughputRecord(b *testing.B) {
	b.ReportAllocs()
	var rates Rates
	at := testBase
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rates.record(metricAssets, at)
	}
}
