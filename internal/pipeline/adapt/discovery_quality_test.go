package adapt

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// poisonedScript returns a script where subfinder returns a large burst (50001)
// causing over_cap. Other tools return small sane results.
func poisonedScript() map[string]func(discovery.Cmd) (discovery.RunResult, error) {
	s := standardScript()
	s["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		var b []byte
		for i := 0; i < 50001; i++ {
			// h00000.example.com style, sorted
			name := formatPoisonHost(i)
			b = append(b, name...)
			b = append(b, '\n')
		}
		return discovery.RunResult{Stdout: b}, nil
	}
	return s
}

func formatPoisonHost(i int) string {
	const pad = 5
	b := make([]byte, 0, pad+1+12)
	b = append(b, 'h')
	num := itoaPadPoison(i, pad)
	b = append(b, num...)
	b = append(b, '.')
	b = append(b, "example.com"...)
	return string(b)
}

func itoaPadPoison(n, width int) string {
	b := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		b[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(b)
}

func TestDiscoveryStageQualityGateFlagged(t *testing.T) {
	runner := newFakeRunner(poisonedScript())
	stage := NewDiscoveryStage(runner, fakeLookup)
	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if res.Outcome == pipeline.OutcomeFailed {
		t.Fatalf("Outcome = failed, want not failed (flagged != failed)")
	}
	if !res.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, discoveryQualityFlag)
	}
	if !res.StickyFlags["discovery_quality_flagged"] {
		t.Fatalf("literal flag missing: %v", res.StickyFlags)
	}
	// Truncated not set (quality flag alone does not imply truncated)
	if res.Truncated {
		t.Errorf("Truncated = true, want false (quality flag alone)")
	}
	// Outcome unchanged: should be completed (other sources complete, subfinder completed with over_cap handled as completed+flag)
	// foldReportOutcome sees all completed -> completed
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (flagged != failed)", res.Outcome)
	}
	// Additions should be capped to 50000 + other hosts filtered
	// subfinder capped 50000, assetfinder 2, amass 1 => 4 unique after dedup? Actually poisoned 50000 + 2 +1, but poisoned hosts overlap maybe not; they are h00000.. etc vs example.com etc. So total processed includes capped count? ItemsProcessed counts hosts per source (capped)
	// We just verify additions non-empty and contains poisoned hosts
	found := false
	for _, h := range res.Additions.Hosts {
		if h.Name == "h00000.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("poisoned host not in Additions: %v", discoveryHostNames(res.Additions.Hosts)[:5])
	}
	// Ensure the 50000 cap respected: no h50000
	for _, h := range res.Additions.Hosts {
		if h.Name == "h50000.example.com" {
			t.Fatalf("over_cap host h50000 leaked into Additions")
		}
	}
}

func TestDiscoveryStageQualityGateDivergenceFlagged(t *testing.T) {
	// 3 sources 1/2/37000 via script override
	s := standardScript()
	s["subfinder -d example.com -silent"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{Stdout: []byte("a.example.com\n")}, nil // 1
	}
	s["assetfinder example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{Stdout: []byte("b.example.com\nc.example.com\n")}, nil // 2
	}
	s["amass enum -passive -d example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		var b []byte
		for i := 0; i < 37000; i++ {
			b = append(b, formatPoisonHost(i)...)
			b = append(b, '\n')
			// need unique subdomains within example.com, our poison hosts already unique
		}
		// also need to ensure amass hosts are distinct from others? It's okay
		return discovery.RunResult{Stdout: b}, nil
	}
	runner := newFakeRunner(s)
	stage := NewDiscoveryStage(runner, fakeLookup)
	res, err := stage.Run(context.Background(), newInput(t, nil))
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if !res.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("divergence flag missing: %v", res.StickyFlags)
	}
	if res.Outcome == pipeline.OutcomeFailed {
		t.Fatalf("divergence should not fail by default")
	}
}

func TestDiscoveryStageQualityGateAbortOnFlag(t *testing.T) {
	runner := newFakeRunner(poisonedScript())
	stage := NewDiscoveryStage(runner, fakeLookup)
	params := map[string]string{"quality_abort_on_flag": "true"}
	res, err := stage.Run(context.Background(), newInput(t, params))
	if err == nil {
		t.Fatalf("abort Run err = nil, want structured qualityGateError")
	}
	if !strings.Contains(err.Error(), "quality gate") || !strings.Contains(err.Error(), "over_cap") {
		t.Fatalf("abort err = %q, want quality gate + over_cap", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed on abort", res.Outcome)
	}
	if !res.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("abort StickyFlags = %v, want quality flag even on failed", res.StickyFlags)
	}
	// Additions still preserved even on failed (LOW-2)
	if len(res.Additions.Hosts) == 0 {
		t.Fatal("abort Additions empty, want honest retained set")
	}
}

func TestDiscoveryStageQualityGateThroughPipeline(t *testing.T) {
	runner := newFakeRunner(poisonedScript())
	stage := NewDiscoveryStage(runner, fakeLookup)
	cfg := pipeline.ScanConfig{
		Target: discoveryMustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover},
	}
	rep, err := pipeline.Run(context.Background(), cfg, nil, fakeClock{}, []pipeline.Stage{stage})
	if err != nil {
		t.Fatalf("pipeline.Run err = %v", err)
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (flagged)", rep.Outcome)
	}
	if len(rep.Stages) != 1 {
		t.Fatalf("Stages %v", rep.Stages)
	}
	sr := rep.Stages[0]
	if !sr.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("StageRecord flags = %v, want quality flagged", sr.StickyFlags)
	}
	// RunReport StickyFlags propagation is via stage flags? Check stage flag present
	// The runner's report.Truncated is ORed, but StickyFlags at report level is not merged from stage;
	// we assert stage flag is preserved, which is the JSON-report-relevant location.
	// Also ensure pipeline Hosts are capped
	for _, h := range rep.Hosts {
		if h.Name == "h50000.example.com" {
			t.Fatalf("capped host leaked into pipeline corpus")
		}
	}
	// Determinism: second identical run DeepEquals
	runner2 := newFakeRunner(poisonedScript())
	stage2 := NewDiscoveryStage(runner2, fakeLookup)
	rep2, _ := pipeline.Run(context.Background(), cfg, nil, fakeClock{}, []pipeline.Stage{stage2})
	if !reflect.DeepEqual(rep.Stages[0].StickyFlags, rep2.Stages[0].StickyFlags) || !reflect.DeepEqual(rep.Hosts, rep2.Hosts) {
		t.Fatalf("determinism broken")
	}
}

func TestDiscoveryQualityFlag_IsStageLevel(t *testing.T) {
	runner := newFakeRunner(poisonedScript())
	stage := NewDiscoveryStage(runner, fakeLookup)
	cfg := pipeline.ScanConfig{
		Target: discoveryMustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover},
	}
	rep, err := pipeline.Run(context.Background(), cfg, nil, fakeClock{}, []pipeline.Stage{stage})
	if err != nil {
		t.Fatalf("pipeline.Run err = %v", err)
	}
	if len(rep.Stages) != 1 {
		t.Fatalf("Stages = %d, want 1", len(rep.Stages))
	}
	sr := rep.Stages[0]
	if !sr.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("StageRecord.StickyFlags = %v, want %q set (stage-level flag)", sr.StickyFlags, discoveryQualityFlag)
	}
	if !sr.StickyFlags["discovery_quality_flagged"] {
		t.Fatalf("literal StageRecord flag missing: %v", sr.StickyFlags)
	}
	// Pin current behavior: RunReport.StickyFlags is NOT auto-merged from stage flags.
	// The flag lives in StageRecord.StickyFlags (like priority_groups_truncated);
	// consumers must check stage flags explicitly.
	if rep.StickyFlags != nil && rep.StickyFlags[discoveryQualityFlag] {
		t.Fatalf("RunReport.StickyFlags = %v, want NOT to contain %q (stage-level only, like priority_groups_truncated)", rep.StickyFlags, discoveryQualityFlag)
	}
	if rep.StickyFlags != nil && rep.StickyFlags["discovery_quality_flagged"] {
		t.Fatalf("RunReport literal flag leaked: %v", rep.StickyFlags)
	}
}
