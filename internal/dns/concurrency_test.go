package dns

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestResolveConcurrent exercises the bounded pool across many hosts:
// every host resolves, all answers are present, and the result set is exact
// (deterministic counts even though the jobs interleave). Race-cleanliness
// is asserted by the -race validation runs.
func TestResolveConcurrent(t *testing.T) {
	const n = 200
	f := newFakeResolver()
	var hosts []asset.Host
	for i := 0; i < n; i++ {
		name := "h" + itoa(i) + ".example.com"
		hosts = append(hosts, mustHost(t, name))
		f.set(name, TypeA, mkV4(i), mkV4(i+n))
		f.set(name, TypeAAAA, v6(i))
		f.set(name, TypeCNAME, "c"+itoa(i)+".example.net")
		f.set("c"+itoa(i)+".example.net", TypeA, mkV4(i))
		f.set("c"+itoa(i)+".example.net", TypeAAAA, v6(i+n))
	}

	cfg := testConfig(f)
	cfg.Concurrency = 16
	cfg.QueueSize = 64

	rep := runOne(t, f, cfg, hosts)
	if len(rep.Results) != n {
		t.Fatalf("results = %d, want %d", len(rep.Results), n)
	}
	// Exactly 5 queries per host (host A/AAAA/CNAME + target A/AAAA).
	if got := f.callCount(); got != n*5 {
		t.Fatalf("calls = %d, want %d", got, n*5)
	}
	errors := 0
	for _, hr := range rep.Results {
		if hr.Status != StatusCompleted {
			errors++
			continue
		}
		a := typeResultFor(hr, hr.Host, TypeA)
		c := typeResultFor(hr, hr.Host, TypeCNAME)
		if len(a.IPs) != 2 || len(c.Hosts) != 1 {
			errors++
		}
	}
	if errors != 0 {
		t.Fatalf("%d hosts did not complete cleanly", errors)
	}
}

// v6 renders a synthetic documentation-range IPv6 address (2001:db8::).
func v6(i int) string {
	return "2001:db8::" + itoa(i%100000+1)
}

// TestResolveNoGoroutineLeakAfterShutdown verifies that a completed run
// leaves no goroutines behind: the pool's workers terminate at Shutdown and
// no job leaks a goroutine (the runtime guarantees every pool-owned goroutine
// has terminated; this test proves the pipeline's end-to-end wiring).
func TestResolveNoGoroutineLeakAfterShutdown(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.set("www.example.com", TypeAAAA, "2001:db8::1")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.set("origin.example.net", TypeAAAA, "2001:db8::1")
	cfg := testConfig(f)
	cfg.Concurrency = 8
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	// Warm up so runtime internals (test framework, GC) are settled.
	runOne(t, f, cfg, hosts)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	mustFinish(t, "Resolve", func() {
		if _, err := Resolve(context.Background(), mustDomain(t, "example.com"), hosts, cfg); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})
	waitForGoroutines(t, baseline, 5*time.Second)
}

// TestResolveNoGoroutineLeakAfterCancellation verifies the same guarantee on
// the cancellation path: a run cancelled mid-flight unwinds completely and
// leaves no goroutines behind.
func TestResolveNoGoroutineLeakAfterCancellation(t *testing.T) {
	f := newFakeResolver()
	f.setBlock()
	ctx, cancel := context.WithCancel(context.Background())
	f.setAutoCancel(cancel)

	cfg := testConfig(f)
	cfg.Concurrency = 8
	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "api.example.com"),
		mustHost(t, "mail.example.com"),
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	mustFinish(t, "Resolve", func() {
		if _, err := Resolve(ctx, mustDomain(t, "example.com"), hosts, cfg); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})
	waitForGoroutines(t, baseline, 5*time.Second)
}

// waitForGoroutines patience-waits until the goroutine count returns to at
// most baseline+2 (bounded patience, never timing-fragile: it only fails on
// a genuine leak).
func waitForGoroutines(t *testing.T, baseline int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := runtime.NumGoroutine()
	t.Fatalf("goroutines = %d after run (baseline %d); possible leak", n, baseline)
}

// TestResolveRateLimiterGatesEveryQuery verifies the central query limiter
// with a frozen clock: with Burst 1, exactly one query may ever dispatch —
// every later query blocks on the limiter until its job deadline. This is
// deterministic (no sleeps): the fake clock never advances, so tokens can
// never refill.
func TestResolveRateLimiterGatesEveryQuery(t *testing.T) {
	f := newFakeResolver()
	f.set("a.example.com", TypeA, "192.0.2.1")
	f.set("b.example.com", TypeA, "192.0.2.2")

	clk := newFakeClock(fixedTime)
	cfg := testConfig(f)
	cfg.Rate = 1                         // one token per second...
	cfg.Burst = 1                        // ...and the clock never advances: exactly one query ever
	cfg.Timeout = 500 * time.Millisecond // jobs give up fast on the frozen limiter
	cfg.Clock = clk

	hosts := []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")}
	mustFinish(t, "Resolve", func() {
		_, err := Resolve(context.Background(), mustDomain(t, "example.com"), hosts, cfg)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})
	// Exactly ONE query dispatched in total: the only burst token.
	if got := f.callCount(); got != 1 {
		t.Fatalf("calls = %d, want exactly 1 (burst=1, clock frozen)", got)
	}
}

// TestResolveRateLimiterDisabled verifies Rate <= 0 disables pacing: all
// queries dispatch immediately.
func TestResolveRateLimiterDisabled(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	cfg := testConfig(f) // Rate 0 from testConfig

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	if got := f.callCount(); got != 3 {
		t.Fatalf("calls = %d, want 3 (pacing disabled)", got)
	}
	hr := hostByName(t, rep, "www.example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
}
