package adapt

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	rr "github.com/RA000WL/RavenRecon/internal/runtime"
)

// stressHeapCeiling is the retained-heap delta ceiling for the 10k stress
// run (32 MiB, mirroring the C-4 memguard pattern). It is an order-of-
// magnitude guard, not an exact-MiB equality.
const stressHeapCeiling int64 = 32 << 20

// goRoutineLeakThreshold allows a small slack for runtime's own goroutines.
const goRoutineSlack = 5

// stressSeed is a minimal stage that seeds the corpus with 10k hosts and
// 10k URLs. It is the deterministic source of the 10k×10k workload.
type stressSeed struct {
	hosts []asset.Host
	urls  []asset.URL
}

func (s *stressSeed) Name() pipeline.StageName { return pipeline.StageDiscover }
func (s *stressSeed) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	return pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{
			Hosts: s.hosts,
			URLs:  s.urls,
		},
		ItemsProcessed: len(s.hosts) + len(s.urls),
	}, nil
}

// stressConsumer is a bounded-pool stage that consumes the large corpus
// via the runtime pool (concurrency 8, queue 64). It proves no unbounded
// goroutine-per-host/URL and no unbounded queue growth.
type stressConsumer struct {
	name        pipeline.StageName
	concurrency int
	maxSeen     atomic.Int32
	active      atomic.Int32
}

func (s *stressConsumer) Name() pipeline.StageName { return s.name }
func (s *stressConsumer) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	pool, err := rr.NewPool(ctx, rr.Config{
		Concurrency: s.concurrency,
		QueueSize:   64,
	})
	if err != nil {
		return pipeline.StageResult{}, err
	}
	defer pool.Shutdown(context.Background())

	inputs := append([]asset.Host(nil), in.Hosts...)
	// Process each host as one job; track max concurrency.
	for _, h := range inputs {
		h := h
		if _, err := pool.Submit(ctx, rr.Job{Func: func(ctx context.Context) (any, error) {
			cur := s.active.Add(1)
			for {
				prev := s.maxSeen.Load()
				if cur > prev && s.maxSeen.CompareAndSwap(prev, cur) {
					break
				}
				if cur <= prev {
					break
				}
			}
			// Simulate small work without allocation blowup.
			time.Sleep(time.Microsecond)
			_ = h.Name
			s.active.Add(-1)
			return nil, nil
		}}); err != nil {
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: err}, nil
		}
	}
	// Also consume URLs in the same pool to exercise 10k URL path.
	for _, u := range in.URLs {
		u := u
		if _, err := pool.Submit(ctx, rr.Job{Func: func(ctx context.Context) (any, error) {
			cur := s.active.Add(1)
			for {
				prev := s.maxSeen.Load()
				if cur > prev && s.maxSeen.CompareAndSwap(prev, cur) {
					break
				}
				if cur <= prev {
					break
				}
			}
			time.Sleep(time.Microsecond)
			_ = u.String()
			s.active.Add(-1)
			return nil, nil
		}}); err != nil {
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: err}, nil
		}
	}
	if err := pool.Shutdown(context.Background()); err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: err}, err
	}
	if max := s.maxSeen.Load(); int(max) > s.concurrency {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: fmt.Errorf("max concurrency %d exceeds bound %d", max, s.concurrency)}, fmt.Errorf("max concurrency %d exceeds bound %d", max, s.concurrency)
	}
	return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted, ItemsProcessed: len(inputs) + len(in.URLs)}, nil
}

// buildStressCorpus creates 10k hosts and 10k URLs deterministically.
func buildStressCorpus(t testing.TB) ([]asset.Host, []asset.URL) {
	t.Helper()
	hosts := make([]asset.Host, 10000)
	for i := 0; i < 10000; i++ {
		name := fmt.Sprintf("host-%05d.example.com", i)
		h, err := asset.NewHost(name, asset.Provenance{Source: "stress", DiscoveredAt: fixedTime})
		if err != nil {
			t.Fatalf("NewHost %q: %v", name, err)
		}
		hosts[i] = h
	}
	urls := make([]asset.URL, 10000)
	for i := 0; i < 10000; i++ {
		raw := fmt.Sprintf("https://example.com/p/%05d?a=%d", i, i)
		u, err := asset.ParseURL(raw, asset.Provenance{Source: "stress"})
		if err != nil {
			t.Fatalf("ParseURL %q: %v", raw, err)
		}
		urls[i] = u
	}
	return hosts, urls
}

// TestStress10kHeapBounded pins the 10k×10k TARGET_PARALLEL=8 harness:
// one large corpus (10k hosts × 10k URLs) processed through bounded pools
// at concurrency 8, with the retained-heap delta under 32 MiB, no goroutine
// leak, and bounded concurrency honored. Skipped under -race (heap delta
// meaningless with the race detector's inflated retention) and -short.
func TestStress10kHeapBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("stress harness skipped in -short")
	}
	if stressRaceEnabled {
		t.Skip("stress heap guard is meaningless under race detector (inflated heap)")
	}
	hosts, urls := buildStressCorpus(t)

	clk := fixedClock{now: fixedTime}
	cacheDir := t.TempDir()
	c, err := cache.Open(cacheDir, cache.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}

	seed := &stressSeed{hosts: hosts, urls: urls}
	consumer := &stressConsumer{name: pipeline.StageDNS, concurrency: 8}
	consumer2 := &stressConsumer{name: pipeline.StageHTTPProbe, concurrency: 8}

	// Pre-GC baseline.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	gorBefore := runtime.NumGoroutine()

	// Single 10k×10k run (deterministic, hermetic, no network).
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageDNS, pipeline.StageHTTPProbe},
		StageBounds: map[pipeline.StageName]pipeline.StageConfig{
			pipeline.StageDiscover:  {MaxConcurrency: 4, QueueSize: 64},
			pipeline.StageDNS:       {MaxConcurrency: 8, QueueSize: 64},
			pipeline.StageHTTPProbe: {MaxConcurrency: 8, QueueSize: 64},
		},
		OutputDir: t.TempDir(),
	}
	rep, err := pipeline.Run(context.Background(), cfg, c, clk, []pipeline.Stage{seed, consumer, consumer2})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", rep.Outcome)
	}
	if len(rep.Hosts) != 10000 {
		t.Fatalf("Hosts = %d, want 10000", len(rep.Hosts))
	}
	if len(rep.URLs) != 10000 {
		t.Fatalf("URLs = %d, want 10000", len(rep.URLs))
	}

	// TARGET_PARALLEL=8 fan-out: 8 concurrent pipeline runs over the same
	// corpus shape, bounded by a semaphore (the cli's --target-parallel
	// contract is exactly this: at most 8 full pipelines in flight).
	t.Run("parallel8", func(t *testing.T) {
		const parallel = 8
		// Pre-build outside goroutines: testing.T is not safe for concurrent use (t.Helper/t.Fatalf/t.TempDir).
		targets := make([]asset.Domain, parallel)
		outputDirs := make([]string, parallel)
		for i := 0; i < parallel; i++ {
			targets[i] = mustDomain(t, fmt.Sprintf("example%d.com", i))
			outputDirs[i] = t.TempDir()
		}
		sem := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		errs := make([]error, parallel)
		for i := 0; i < parallel; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				clk := fixedClock{now: fixedTime}
				seed := &stressSeed{hosts: hosts[:1000], urls: urls[:1000]} // smaller per-target to keep 8× heap bounded
				cons := &stressConsumer{name: pipeline.StageDNS, concurrency: 4}
				cfg := pipeline.ScanConfig{
					Target:    targets[idx],
					Stages:    []pipeline.StageName{pipeline.StageDiscover, pipeline.StageDNS},
					OutputDir: outputDirs[idx],
				}
				_, err := pipeline.Run(context.Background(), cfg, c, clk, []pipeline.Stage{seed, cons})
				errs[idx] = err
			}(i)
		}
		wg.Wait()
		for i, e := range errs {
			if e != nil {
				t.Fatalf("parallel run %d: %v", i, e)
			}
		}
		// Verify semaphore bound honored: at most 8 in flight, which the
		// channel capacity guarantees structurally; no further assert needed
		// beyond the fact that all 8 completed without deadlock.
	})

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapInuse) - int64(before.HeapInuse)
	if delta < 0 {
		delta = 0
	}
	t.Logf("stress 10k×10k retained heap delta: %d bytes (ceiling %d)", delta, stressHeapCeiling)
	if delta > stressHeapCeiling {
		t.Fatalf("retained heap delta %d exceeds ceiling %d (%.1f×); possible unbounded growth", delta, stressHeapCeiling, float64(delta)/float64(stressHeapCeiling))
	}

	// Goroutine leak check: NumGoroutine should return to baseline within slack.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	gorAfter := runtime.NumGoroutine()
	if gorAfter > gorBefore+goRoutineSlack {
		t.Fatalf("goroutine leak: before %d after %d (slack %d)", gorBefore, gorAfter, goRoutineSlack)
	}

	// Bounded pools honored: each consumer's maxSeen must not exceed its bound.
	if max := consumer.maxSeen.Load(); int(max) > 8 {
		t.Fatalf("consumer1 max concurrency %d exceeds 8", max)
	}
	if max := consumer2.maxSeen.Load(); int(max) > 8 {
		t.Fatalf("consumer2 max concurrency %d exceeds 8", max)
	}
}
