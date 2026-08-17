package event

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// BenchmarkBusPublishFanout measures publish throughput with a draining
// consumer: one subscriber reads as fast as it can while the benchmark
// publishes. This is the canonical "event layer must not slow the run" shape
// (v1.2 acceptance): the bus cost per publish is the stamp/validate/sequence
// path plus one bounded enqueue per subscriber.
func BenchmarkBusPublishFanout(b *testing.B) {
	b.ReportAllocs()
	bus := NewBus(nil)
	sub, err := bus.Subscribe(4096)
	if err != nil {
		b.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			if _, err := sub.Next(ctx); err != nil {
				return
			}
		}
	}()
	ev := New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ev)
	}
	b.StopTimer()
	sub.Close()
	wg.Wait()
	bus.Close()
}

// BenchmarkBusPublishDrop measures the full-buffer drop path: a subscriber
// that never reads, so every publish past the buffer is dropped and counted.
// This is the "slow consumer must not stall a producer" shape.
func BenchmarkBusPublishDrop(b *testing.B) {
	b.ReportAllocs()
	bus := NewBus(nil)
	sub, err := bus.Subscribe(1)
	if err != nil {
		b.Fatal(err)
	}
	defer sub.Close()
	defer bus.Close()
	ev := New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ev)
	}
}

// BenchmarkBusPublishFanoutFourSubscribers measures the fanout shape the TUI
// controller and loggers will use: one publish, four bounded enqueues.
func BenchmarkBusPublishFanoutFourSubscribers(b *testing.B) {
	b.ReportAllocs()
	bus := NewBus(nil)
	defer bus.Close()
	subs := make([]*Subscriber, 4)
	for i := range subs {
		s, err := bus.Subscribe(4096)
		if err != nil {
			b.Fatal(err)
		}
		subs[i] = s
	}
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s *Subscriber) {
			defer wg.Done()
			ctx := context.Background()
			for {
				if _, err := s.Next(ctx); err != nil {
					return
				}
			}
		}(s)
	}
	ev := New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ev)
	}
	b.StopTimer()
	for _, s := range subs {
		s.Close()
	}
	wg.Wait()
}

// BenchmarkBusPublishPaced measures the publish path at realistic scan event
// rates (100, 1k, and 10k events per second) with a draining consumer: the
// per-op time is dominated by the pacing sleep, so the meaningful numbers
// are the allocation costs (B/op, allocs/op), which are rate-independent.
func BenchmarkBusPublishPaced(b *testing.B) {
	for _, rate := range []float64{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("%.0f_per_sec", rate), func(b *testing.B) {
			b.ReportAllocs()
			bus := NewBus(nil)
			sub, err := bus.Subscribe(4096)
			if err != nil {
				b.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := context.Background()
				for {
					if _, err := sub.Next(ctx); err != nil {
						return
					}
				}
			}()
			ev := New(KindTaskSubmitted, time.Unix(1_700_000_000, 0), TaskSubmitted{JobID: 1})
			interval := time.Duration(float64(time.Second) / rate)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bus.Publish(ev)
				time.Sleep(interval)
			}
			b.StopTimer()
			sub.Close()
			wg.Wait()
			bus.Close()
		})
	}
}
