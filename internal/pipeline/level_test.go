package pipeline

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// leveledFakeStage is a Stage with a declared execution level.
type leveledFakeStage struct {
	name  StageName
	level int
	run   func(ctx context.Context, in StageInput) (StageResult, error)
}

func (s *leveledFakeStage) Name() StageName { return s.name }

func (s *leveledFakeStage) Level() int { return s.level }

func (s *leveledFakeStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	return s.run(ctx, in)
}

func TestPlanGroups(t *testing.T) {
	cases := []struct {
		name   string
		levels []int
		want   [][]int
	}{
		{"empty", nil, nil},
		{"singleton barrier", []int{-1}, [][]int{{0}}},
		{"singleton level", []int{2}, [][]int{{0}}},
		{"all barriers sequential", []int{-1, -1, -1}, [][]int{{0}, {1}, {2}}},
		{"same level groups", []int{1, 1, 1}, [][]int{{0, 1, 2}}},
		{"ascending levels solo", []int{0, 1, 2}, [][]int{{0}, {1}, {2}}},
		{"no reorder across levels", []int{2, 1, 1}, [][]int{{0}, {1, 2}}},
		{"barrier splits", []int{1, 1, -1, 1, 1}, [][]int{{0, 1}, {2}, {3, 4}}},
		{"barrier head and tail", []int{-1, 3, 3, -1}, [][]int{{0}, {1, 2}, {3}}},
		{"separated same levels stay solo", []int{1, 2, 1}, [][]int{{0}, {1}, {2}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got [][]int
			for _, g := range planGroups(tc.levels) {
				got = append(got, g.indices)
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("planGroups(%v) = %v, want %v", tc.levels, got, tc.want)
			}
		})
	}
}

// TestRunGroupOverlap proves same-level stages actually overlap in time:
// neither member completes before both have started.
func TestRunGroupOverlap(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	mk := func(name StageName) *leveledFakeStage {
		return &leveledFakeStage{name: name, level: 1, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			entered <- string(name)
			select {
			case <-release:
			case <-ctx.Done():
				return StageResult{Outcome: OutcomeCancelled}, ctx.Err()
			}
			return StageResult{Outcome: OutcomeCompleted, ItemsProcessed: 1}, nil
		}}
	}
	done := make(chan RunReport, 1)
	go func() {
		rep, err := run(t, validConfig(t, StageDNS, StageURLIntel),
			[]Stage{mk(StageDNS), mk(StageURLIntel)})
		if err != nil {
			t.Errorf("Run: %v", err)
			done <- RunReport{}
			return
		}
		done <- rep
	}()
	// Both members must enter before either may finish.
	seen := map[string]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < 2 {
		select {
		case n := <-entered:
			seen[n] = true
		case <-timeout:
			t.Fatalf("members did not overlap (entered %v); same-level stages must run concurrently", seen)
		}
	}
	close(release)
	select {
	case rep := <-done:
		if rep.Outcome != OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", rep.Outcome)
		}
		if len(rep.Stages) != 2 || rep.Stages[0].Name != StageDNS || rep.Stages[1].Name != StageURLIntel {
			t.Fatalf("records out of selection order: %+v", rep.Stages)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not finish after release")
	}
}

func TestRunGroupCompletionOrderIrrelevant(t *testing.T) {
	build := func(reverse bool) (RunReport, error) {
		firstDone := make(chan struct{})
		// Real stage names (selection must validate); levels come from
		// the fakes, both level 1. Hosts differ per member so the merge
		// order is observable.
		mkHost := func(name StageName, host string, wait, signal bool) *leveledFakeStage {
			return &leveledFakeStage{name: name, level: 1, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				if wait {
					<-firstDone
				}
				if signal {
					close(firstDone)
				}
				h, err := asset.NewHost(host, asset.Provenance{Source: "test"})
				if err != nil {
					return StageResult{Outcome: OutcomeFailed}, err
				}
				return StageResult{Outcome: OutcomeCompleted, ItemsProcessed: 1,
					Additions: StageAdditions{Hosts: []asset.Host{h}}}, nil
			}}
		}
		return run(t, validConfig(t, StageDNS, StageURLIntel), []Stage{
			mkHost(StageDNS, "a.example.com", reverse, !reverse),
			mkHost(StageURLIntel, "b.example.com", !reverse, reverse),
		})
	}
	fwd, err := build(false)
	if err != nil {
		t.Fatalf("forward Run: %v", err)
	}
	rev, err := build(true)
	if err != nil {
		t.Fatalf("reverse Run: %v", err)
	}
	strip := func(r RunReport) RunReport {
		for i := range r.Stages {
			r.Stages[i].Duration = 0
		}
		return r
	}
	fwd, rev = strip(fwd), strip(rev)
	if !reflect.DeepEqual(fwd, rev) {
		t.Fatalf("reverse completion changed the report:\nforward: %+v\nreverse: %+v", fwd, rev)
	}
	if len(rev.Hosts) != 2 || rev.Hosts[0].Name != "a.example.com" || rev.Hosts[1].Name != "b.example.com" {
		t.Fatalf("corpus merge not in selection order: %+v", rev.Hosts)
	}
}

// TestRunBarrierSolo proves unlevelled stages split groups: the barrier
// runs strictly between its neighbors in selection order.
func TestRunBarrierSolo(t *testing.T) {
	var order []StageName
	mk := func(name StageName, level int) Stage {
		if level < 0 {
			return recordStage(name, &order)
		}
		return &leveledFakeStage{name: name, level: level, run: func(ctx context.Context, in StageInput) (StageResult, error) {
			order = append(order, name)
			return StageResult{Outcome: OutcomeCompleted}, nil
		}}
	}
	_, err := run(t, validConfig(t, StageDNS, StageCrawl, StageURLIntel),
		[]Stage{mk(StageDNS, 1), mk(StageCrawl, -1), mk(StageURLIntel, 1)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(order, []StageName{StageDNS, StageCrawl, StageURLIntel}) {
		t.Fatalf("execution order = %v, want selection order with a solo barrier", order)
	}
}
func TestRunStageInputCarriesObserver(t *testing.T) {
	obs := &recordingObserver{}
	var got event.Observer
	st := &fakeStage{name: StageDNS, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		got = in.Observer
		return StageResult{Outcome: OutcomeCompleted}, nil
	}}
	cfg := validConfig(t, StageDNS)
	cfg.Observer = obs
	if _, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{st}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got == nil {
		t.Fatal("StageInput.Observer is nil; the runner must forward cfg.Observer")
	}
	if got != event.Observer(obs) {
		t.Error("StageInput.Observer is not the configured observer")
	}
}
