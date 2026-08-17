package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// recorder is a thread-safe Observer that records every event in order
// (mirrors the runtime pool's observer test harness).
type recorder struct {
	mu  sync.Mutex
	evs []event.Event
}

func (r *recorder) Observe(ev event.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) events() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event.Event, len(r.evs))
	copy(out, r.evs)
	return out
}

// TestCacheObserverNilDefaultZeroChange pins the off switch: a cache opened
// without WithObserver carries a nil observer, and its Get outcomes are the
// documented states across the plain paths (miss, hit, expired).
func TestCacheObserverNilDefaultZeroChange(t *testing.T) {
	now := time.Unix(1_000_000_000, 0).UTC()
	c, err := Open(t.TempDir(), WithTTL(10*time.Second), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.observer != nil {
		t.Fatal("a cache opened without WithObserver must carry a nil observer")
	}
	key := mustKey(t, baseParts("op", "host:example.com"))

	if o := c.Get(context.Background(), key); o.State != StateMiss {
		t.Fatalf("expected StateMiss, got %s", o.State)
	}
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if o := c.Get(context.Background(), key); !o.IsHit() {
		t.Fatalf("expected hit, got %s", o.State)
	}
	now = now.Add(10*time.Second + time.Nanosecond)
	if o := c.Get(context.Background(), key); o.State != StateExpired {
		t.Fatalf("expected StateExpired, got %s", o.State)
	}
}

// exerciseOutcomes runs one deterministic operation sequence against a
// fresh cache (TTL 10 s, injected clock) and returns every Get outcome in
// order: miss, hit, expired, incomplete, corrupt, schema-incompatible,
// error (fabricated key), error (cancelled context).
func exerciseOutcomes(t *testing.T, opts ...Option) []Outcome {
	t.Helper()
	now := time.Unix(1_000_000_000, 0).UTC()
	opts = append(opts, WithTTL(10*time.Second), WithClock(func() time.Time { return now }))
	c, err := Open(t.TempDir(), opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))
	var out []Outcome
	rec := func(o Outcome) { out = append(out, o) }

	// miss
	rec(c.Get(context.Background(), key))
	// hit
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rec(c.Get(context.Background(), key))
	// expired (TTL evaluation precedes status)
	now = now.Add(10*time.Second + time.Nanosecond)
	rec(c.Get(context.Background(), key))
	// incomplete (rewind the clock so the entry is unexpired)
	now = time.Unix(1_000_000_000, 0).UTC()
	partial := completedRecord("op", "host:example.com", nil)
	partial.Status = StatusIncomplete
	if err := c.Put(context.Background(), key, partial); err != nil {
		t.Fatalf("Put incomplete: %v", err)
	}
	rec(c.Get(context.Background(), key))
	// corrupt (self-healed on read)
	writeEntryFixture(t, c, key, []byte("this is not json {{{"))
	rec(c.Get(context.Background(), key))
	// schema-incompatible (self-healed on read)
	old := completedRecord("op", "host:example.com", nil)
	old.SchemaVersion = SchemaVersion + 10
	buf, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writeEntryFixture(t, c, key, buf)
	rec(c.Get(context.Background(), key))
	// error: fabricated key
	rec(c.Get(context.Background(), Key("../../etc/passwd")))
	// error: cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec(c.Get(ctx, key))
	return out
}

// TestCacheObserverInstrumentationDoesNotChangeOutcomes runs the same
// operation sequence against two fresh caches — one with a nil observer,
// one with a recording observer — and requires identical outcomes: the
// instrumentation is purely additive, and every Get still publishes
// exactly one event.
func TestCacheObserverInstrumentationDoesNotChangeOutcomes(t *testing.T) {
	plain := exerciseOutcomes(t)
	rec := &recorder{}
	observed := exerciseOutcomes(t, WithObserver(rec))

	if len(plain) != len(observed) {
		t.Fatalf("outcome counts differ: %d vs %d", len(plain), len(observed))
	}
	for i := range plain {
		a, b := plain[i], observed[i]
		if a.State != b.State || a.IsHit() != b.IsHit() || (a.Record != nil) != (b.Record != nil) {
			t.Fatalf("outcome %d diverges with instrumentation: %+v vs %+v", i, a, b)
		}
	}
	if evs := rec.events(); len(evs) != len(plain) {
		t.Fatalf("want exactly one event per Get (%d), got %d", len(plain), len(evs))
	}
}

// TestCacheObserverEmitsGroundedHitAndMissEvents pins the emitted events
// one by one: exactly one cache_hit/cache_miss per Get, in lookup order,
// with every payload field derived from the REAL outcome of that Get (Key
// = the cache key digest, State = Outcome.State.String(), Hit =
// Outcome.IsHit()), the kind consistent with Hit, the timestamp from the
// cache's injected clock, and every event valid.
func TestCacheObserverEmitsGroundedHitAndMissEvents(t *testing.T) {
	now := time.Unix(1_000_000_000, 0).UTC()
	rec := &recorder{}
	c, err := Open(t.TempDir(), WithTTL(10*time.Second), WithClock(func() time.Time { return now }), WithObserver(rec))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))

	check := func(wantKind event.Kind, out Outcome, at time.Time, k Key) {
		t.Helper()
		evs := rec.events()
		if len(evs) == 0 {
			t.Fatal("no event emitted for the lookup")
		}
		ev := evs[len(evs)-1]
		if ev.Kind != wantKind {
			t.Fatalf("kind = %s, want %s", ev.Kind, wantKind)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("emitted event invalid: %v", err)
		}
		if !ev.At.Equal(at) {
			t.Fatalf("event time = %s, want the cache clock time %s", ev.At, at)
		}
		pl, ok := ev.Payload.(event.CacheAccess)
		if !ok {
			t.Fatalf("payload type = %T, want CacheAccess", ev.Payload)
		}
		if pl.Key != string(k) {
			t.Fatalf("payload key = %q, want the cache key %q", pl.Key, string(k))
		}
		if pl.State != out.State.String() {
			t.Fatalf("payload state = %q, want Outcome.State.String() %q", pl.State, out.State.String())
		}
		if pl.Hit != out.IsHit() {
			t.Fatalf("payload hit = %v, want Outcome.IsHit() %v", pl.Hit, out.IsHit())
		}
	}

	// miss
	check(event.KindCacheMiss, c.Get(context.Background(), key), now, key)
	// hit
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	check(event.KindCacheHit, c.Get(context.Background(), key), now, key)
	// expired
	now = now.Add(10*time.Second + time.Nanosecond)
	check(event.KindCacheMiss, c.Get(context.Background(), key), now, key)
	// incomplete (rewind the clock so the entry is unexpired)
	now = time.Unix(1_000_000_000, 0).UTC()
	partial := completedRecord("op", "host:example.com", nil)
	partial.Status = StatusIncomplete
	if err := c.Put(context.Background(), key, partial); err != nil {
		t.Fatalf("Put incomplete: %v", err)
	}
	check(event.KindCacheMiss, c.Get(context.Background(), key), now, key)
	// corrupt
	writeEntryFixture(t, c, key, []byte("this is not json {{{"))
	check(event.KindCacheMiss, c.Get(context.Background(), key), now, key)
	// schema-incompatible
	old := completedRecord("op", "host:example.com", nil)
	old.SchemaVersion = SchemaVersion + 10
	buf, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writeEntryFixture(t, c, key, buf)
	check(event.KindCacheMiss, c.Get(context.Background(), key), now, key)
	// error: fabricated key
	badKey := Key("../../etc/passwd")
	check(event.KindCacheMiss, c.Get(context.Background(), badKey), now, badKey)
	// error: cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check(event.KindCacheMiss, c.Get(ctx, key), now, key)

	// Exactly one event per Get, in lookup order: miss, hit, then misses.
	evs := rec.events()
	wantKinds := []event.Kind{
		event.KindCacheMiss, event.KindCacheHit,
		event.KindCacheMiss, event.KindCacheMiss, event.KindCacheMiss,
		event.KindCacheMiss, event.KindCacheMiss, event.KindCacheMiss,
	}
	if len(evs) != len(wantKinds) {
		t.Fatalf("want %d events (one per Get), got %d", len(wantKinds), len(evs))
	}
	for i, ev := range evs {
		if ev.Kind != wantKinds[i] {
			t.Fatalf("event %d kind = %s, want %s (lookup order preserved)", i, ev.Kind, wantKinds[i])
		}
	}
}

// TestCacheObserverEventsFlowThroughBus pins the canonical wiring
// cache -> Bus -> Subscriber: the emitted events pass bus validation
// (nothing rejected), are delivered in sequence order, and carry the
// grounded payloads end to end.
func TestCacheObserverEventsFlowThroughBus(t *testing.T) {
	now := time.Unix(1_000_000_000, 0).UTC()
	bus := event.NewBus(nil)
	defer bus.Close()
	sub, err := bus.Subscribe(64)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	c, err := Open(t.TempDir(), WithClock(func() time.Time { return now }), WithObserver(bus))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))

	c.Get(context.Background(), key) // miss
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	c.Get(context.Background(), key) // hit

	if bus.Invalid() != 0 {
		t.Fatalf("bus rejected %d emitted events", bus.Invalid())
	}
	sub.Close()
	var evs []event.Event
	for {
		ev, err := sub.Next(context.Background())
		if err != nil {
			break
		}
		evs = append(evs, ev)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 delivered events, got %d", len(evs))
	}
	if evs[0].Kind != event.KindCacheMiss || evs[0].Sequence != 1 {
		t.Fatalf("event 0 = %s seq %d, want cache_miss seq 1", evs[0].Kind, evs[0].Sequence)
	}
	if pl := evs[0].Payload.(event.CacheAccess); pl.State != "miss" || pl.Hit || pl.Key != string(key) {
		t.Fatalf("miss payload = %+v, want state miss hit=false key %q", pl, string(key))
	}
	if evs[1].Kind != event.KindCacheHit || evs[1].Sequence != 2 {
		t.Fatalf("event 1 = %s seq %d, want cache_hit seq 2", evs[1].Kind, evs[1].Sequence)
	}
	if pl := evs[1].Payload.(event.CacheAccess); pl.State != "hit" || !pl.Hit || pl.Key != string(key) {
		t.Fatalf("hit payload = %+v, want state hit hit=true key %q", pl, string(key))
	}
	if evs[1].At.Equal(now) == false {
		t.Fatalf("delivered timestamp = %s, want the cache clock %s", evs[1].At, now)
	}
}

// TestCacheObserverNonBlockingUnderLoad pins that emission never blocks a
// cache operation: with a real Bus whose single subscriber has a
// one-slot buffer and nobody drains it, concurrent lookups still complete
// promptly, every Get emits exactly one event (bus sequence count), the
// bus drops and counts overflow instead of stalling producers, and the
// delivered event is valid.
func TestCacheObserverNonBlockingUnderLoad(t *testing.T) {
	bus := event.NewBus(nil)
	defer bus.Close()
	sub, err := bus.Subscribe(1) // buffer 1, never drained during the run
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	c, err := Open(t.TempDir(), WithObserver(bus))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := mustKey(t, baseParts("op", "host:example.com"))
	if err := c.Put(context.Background(), key, completedRecord("op", "host:example.com", nil)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	const workers = 8
	const perWorker = 250
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perWorker; i++ {
					c.Get(context.Background(), key)
				}
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cache operations blocked on event emission (full subscriber buffer)")
	}

	if got := bus.Seq(); got != workers*perWorker {
		t.Fatalf("bus sequenced %d events, want %d (exactly one per Get)", got, workers*perWorker)
	}
	if bus.Invalid() != 0 {
		t.Fatalf("bus rejected %d emitted events", bus.Invalid())
	}
	if bus.Drops() == 0 {
		t.Fatal("expected drops: a full subscriber buffer must drop, never block the cache")
	}

	// The single delivered event is the first publish, before the buffer
	// filled; it is valid and carries the grounded hit payload.
	sub.Close()
	var evs []event.Event
	for {
		ev, err := sub.Next(context.Background())
		if err != nil {
			break
		}
		evs = append(evs, ev)
	}
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 delivered event (buffer 1, nobody drains), got %d", len(evs))
	}
	if evs[0].Sequence != 1 {
		t.Fatalf("delivered sequence = %d, want 1", evs[0].Sequence)
	}
	if evs[0].Kind != event.KindCacheHit {
		t.Fatalf("delivered kind = %s, want cache_hit", evs[0].Kind)
	}
	if pl := evs[0].Payload.(event.CacheAccess); !pl.Hit || pl.State != "hit" || pl.Key != string(key) {
		t.Fatalf("delivered payload = %+v, want state hit hit=true key %q", pl, string(key))
	}
}

// TestCacheObserverConcurrentMixedOps exercises the emit path under
// concurrent Get/Put/Delete over a small key set; the -race detector pins
// that observer reads and emissions are race-free, and every recorded
// event stays valid with a kind consistent with its payload.
func TestCacheObserverConcurrentMixedOps(t *testing.T) {
	rec := &recorder{}
	c, err := Open(t.TempDir(), WithObserver(rec))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const nKeys = 4
	keys := make([]Key, nKeys)
	for i := 0; i < nKeys; i++ {
		keys[i] = mustKey(t, KeyParts{Operation: "op", Target: fmt.Sprintf("host:h%d.example.com", i)})
	}

	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				k := keys[(w+i)%nKeys]
				c.Get(context.Background(), k)
				if i%3 == 0 {
					_ = c.Put(context.Background(), k, completedRecord("op", "x", nil))
				}
				c.Get(context.Background(), k)
				if i%4 == 0 {
					_ = c.Delete(context.Background(), k)
				}
			}
		}(w)
	}
	wg.Wait()

	evs := rec.events()
	if len(evs) == 0 {
		t.Fatal("expected events from concurrent lookups")
	}
	for i, ev := range evs {
		if err := ev.Validate(); err != nil {
			t.Fatalf("event %d invalid: %v", i, err)
		}
		pl, ok := ev.Payload.(event.CacheAccess)
		if !ok {
			t.Fatalf("event %d payload type = %T, want CacheAccess", i, ev.Payload)
		}
		if (ev.Kind == event.KindCacheHit) != pl.Hit {
			t.Fatalf("event %d: kind %s contradicts Hit=%v", i, ev.Kind, pl.Hit)
		}
		switch pl.State {
		case "hit", "miss", "expired", "corrupt", "schema-incompatible", "incomplete", "error":
		default:
			t.Fatalf("event %d: payload state %q outside the outcome vocabulary", i, pl.State)
		}
	}
}
