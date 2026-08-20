package discovery

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// helper to make n hosts named h00000.example.com .. sorted already.
func makeHosts(t *testing.T, n int, domain string) []asset.Host {
	t.Helper()
	hosts := make([]asset.Host, n)
	for i := 0; i < n; i++ {
		name := assetHostName(i, domain)
		h, err := asset.NewHost(name, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewHost %q: %v", name, err)
		}
		hosts[i] = h
	}
	return hosts
}

func assetHostName(i int, domain string) string {
	// zero-padded so lexical order == numeric order
	return formatHost(i, domain)
}

func formatHost(i int, domain string) string {
	// 5-digit zero pad covers up to 99999
	const pad = 5
	s := make([]byte, 0, pad+1+len(domain))
	num := itoaPad(i, pad)
	s = append(s, 'h')
	s = append(s, num...)
	s = append(s, '.')
	s = append(s, domain...)
	return string(s)
}

func itoaPad(n, width int) string {
	b := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		b[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(b)
}

func TestNormalizeQualityConfigDefaults(t *testing.T) {
	zero := QualityConfig{}
	got := NormalizeQualityConfig(zero)
	want := DefaultQualityConfig()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize zero = %+v, want %+v", got, want)
	}
	neg := QualityConfig{MaxPerSource: -1, DivergenceRatio: -1, DivergenceMinCount: -5}
	got = NormalizeQualityConfig(neg)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize negative = %+v, want %+v", got, want)
	}
	// Non-zero values stay
	custom := QualityConfig{MaxPerSource: 10, DivergenceRatio: 2.5, DivergenceMinCount: 5, AbortOnFlag: true}
	got = NormalizeQualityConfig(custom)
	if !reflect.DeepEqual(got, custom) {
		t.Fatalf("custom normalize = %+v, want %+v", got, custom)
	}
}

func TestQualityGateCap_OverCap(t *testing.T) {
	hosts := makeHosts(t, 50001, "example.com")
	// Use large other counts to avoid divergence firing (median large => ratio*median >50000)
	res := []SourceResult{
		{Source: "subfinder", Hosts: hosts},
		{Source: "assetfinder", Hosts: makeHosts(t, 40000, "example.com")},
		{Source: "amass", Hosts: makeHosts(t, 45000, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(res[0].Hosts) != 50000 {
		t.Fatalf("hosts after cap = %d, want 50000", len(res[0].Hosts))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want 1 over_cap", issues)
	}
	iss := issues[0]
	if iss.Source != "subfinder" || iss.Signal != SignalOverCap || iss.Count != 50001 {
		t.Fatalf("issue = %+v, want over_cap count 50001", iss)
	}
	if iss.Others != nil {
		t.Fatalf("over_cap Others = %v, want nil", iss.Others)
	}
	// Per-slot issues also present
	if len(res[0].QualityIssues) != 1 || res[0].QualityIssues[0].Signal != SignalOverCap {
		t.Fatalf("per-slot issues = %v", res[0].QualityIssues)
	}
	// Ensure deterministic first 50000 kept (h00000 .. h49999)
	if res[0].Hosts[0].Name != "h00000.example.com" || res[0].Hosts[49999].Name != "h49999.example.com" {
		t.Fatalf("truncated hosts not first 50000: first %q last %q", res[0].Hosts[0].Name, res[0].Hosts[49999].Name)
	}
}

func TestQualityGateCap_ExactCapNoFire(t *testing.T) {
	hosts := makeHosts(t, 50000, "example.com")
	res := []SourceResult{{Source: "subfinder", Hosts: hosts}}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none at exact cap", issues)
	}
	if len(res[0].Hosts) != 50000 {
		t.Fatalf("hosts = %d, want 50000", len(res[0].Hosts))
	}
}

func TestQualityGateCap_CachedNeverTruncated(t *testing.T) {
	hosts := makeHosts(t, 50001, "example.com")
	res := []SourceResult{{Source: "subfinder", Hosts: hosts, Cached: true}}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("cached over cap should not fire, got %v", issues)
	}
	if len(res[0].Hosts) != 50001 {
		t.Fatalf("cached hosts must not be truncated: %d", len(res[0].Hosts))
	}
}

func TestQualityGateDivergence_Fires(t *testing.T) {
	// 3 producing sources: 1, 2, 37000 in selection order
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 2, "example.com")},
		{Source: "amass", Hosts: makeHosts(t, 37000, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want 1 divergence", issues)
	}
	iss := issues[0]
	if iss.Source != "amass" || iss.Signal != SignalDivergence || iss.Count != 37000 {
		t.Fatalf("issue = %+v", iss)
	}
	// Others must be in selection order: subfinder 1, assetfinder 2
	wantOthers := []int{1, 2}
	if !reflect.DeepEqual(iss.Others, wantOthers) {
		t.Fatalf("Others = %v, want %v (selection order)", iss.Others, wantOthers)
	}
	// Median of [1,2] = 1.5, ratio 10 => 15, 37000 > 15 and >100 => fires
}

func TestQualityGateDivergence_NotFire_TwoProducing(t *testing.T) {
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 37000, "example.com")},
		// third source zero producing -> not counted
		{Source: "amass", Hosts: nil},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("with 2 producing, divergence must not fire, got %v", issues)
	}
}

func TestQualityGateDivergence_NotFire_ExactBoundary(t *testing.T) {
	// Need count == ratio*median exactly, should NOT fire (strictly greater)
	// Choose others [10,20] median 15, ratio 10 => 150. Set count 150 exactly.
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 10, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 20, "example.com")},
		{Source: "amass", Hosts: makeHosts(t, 150, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("exact boundary must not fire, got %v", issues)
	}
	// One more should fire
	res[2].Hosts = makeHosts(t, 151, "example.com")
	issues = applyQualityGate(res, qc)
	if len(issues) != 1 {
		t.Fatalf("151 should fire, got %v", issues)
	}
}

func TestQualityGateDivergence_NotFire_UnderMinCount(t *testing.T) {
	// DivergenceMinCount 100, count 50 should not fire even if ratio exceeded
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "amass", Hosts: makeHosts(t, 50, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("count 50 <= min 100 must not fire, got %v", issues)
	}
	// count 101 should fire if ratio also exceeded
	res[2].Hosts = makeHosts(t, 101, "example.com")
	issues = applyQualityGate(res, qc)
	// median 1 => 10, 101>10 && >100 => fires
	if len(issues) != 1 {
		t.Fatalf("101 should fire, got %v", issues)
	}
}

func TestQualityGateDivergence_MedianAveraging(t *testing.T) {
	// Others [20,40,60,80] sorted median = (40+60)/2=50, ratio 10 => 500
	// Count 500 exact boundary not fire, 501 fires; both >100 so min count satisfied
	res := []SourceResult{
		{Source: "s1", Hosts: makeHosts(t, 20, "example.com")},
		{Source: "s2", Hosts: makeHosts(t, 40, "example.com")},
		{Source: "s3", Hosts: makeHosts(t, 60, "example.com")},
		{Source: "s4", Hosts: makeHosts(t, 80, "example.com")},
		{Source: "outlier", Hosts: makeHosts(t, 500, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("500 at exact boundary must not fire, got %v", issues)
	}
	res[4].Hosts = makeHosts(t, 501, "example.com")
	issues = applyQualityGate(res, qc)
	if len(issues) != 1 || issues[0].Source != "outlier" {
		t.Fatalf("501 should fire, got %v", issues)
	}
	// Verify Others for outlier are [20,40,60,80] in selection order
	if !reflect.DeepEqual(issues[0].Others, []int{20, 40, 60, 80}) {
		t.Fatalf("Others = %v, want [20,40,60,80]", issues[0].Others)
	}
}

func TestQualityGateDivergence_ZeroProducingNotSkewMedian(t *testing.T) {
	// 4 slots: s1 1 host, s2 2 hosts, s3 zero, outlier 37000
	// Only 3 producing (1,2,37000) => median 1.5 => fires
	// Zero must be excluded
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 2, "example.com")},
		{Source: "amass", Hosts: nil},
		{Source: "extra", Hosts: makeHosts(t, 37000, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 1 || issues[0].Source != "extra" {
		t.Fatalf("zero-producing must not skew median, got %v", issues)
	}
	if !reflect.DeepEqual(issues[0].Others, []int{1, 2}) {
		t.Fatalf("Others = %v, want [1,2]", issues[0].Others)
	}
}

func TestQualityGateDeterminism(t *testing.T) {
	makeCase := func() []SourceResult {
		return []SourceResult{
			{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
			{Source: "assetfinder", Hosts: makeHosts(t, 2, "example.com")},
			{Source: "amass", Hosts: makeHosts(t, 37000, "example.com")},
		}
	}
	qc := DefaultQualityConfig()
	a := makeCase()
	issuesA := applyQualityGate(a, qc)
	b := makeCase()
	issuesB := applyQualityGate(b, qc)
	if !reflect.DeepEqual(issuesA, issuesB) {
		t.Fatalf("determinism: %v != %v", issuesA, issuesB)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("results determinism: %v != %v", a, b)
	}
}

func TestQualityGateOldSchemaDecode(t *testing.T) {
	target := mustDomain(t, "example.com")
	// Marshal old storedResult without quality_issues
	type oldStored struct {
		Source    string       `json:"source"`
		Version   string       `json:"version,omitempty"`
		Target    string       `json:"target"`
		Hosts     []asset.Host `json:"hosts"`
		Truncated bool         `json:"truncated,omitempty"`
	}
	old := oldStored{Source: "subfinder", Version: "v2.6.3", Target: target.Identity().String(), Hosts: makeHosts(t, 2, "example.com")}
	b, _ := json.Marshal(old)
	sr, err := decodeStored(b, target, "subfinder")
	if err != nil {
		t.Fatalf("decode old schema: %v", err)
	}
	if len(sr.QualityIssues) != 0 {
		t.Fatalf("old schema QualityIssues = %v, want nil", sr.QualityIssues)
	}
}

func TestQualityGateCachedReplaySticky(t *testing.T) {
	c := openTestCache(t)
	target := mustDomain(t, "example.com")
	// Use small cap to avoid heavy 50k generation: MaxPerSource 10, 11 hosts triggers over_cap,
	// DivergenceMinCount 100 ensures 11 does not fire divergence.
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		var b []byte
		for i := 0; i < 11; i++ {
			b = append(b, formatHost(i, "example.com")...)
			b = append(b, '\n')
		}
		return RunResult{Stdout: b}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c
	cfg.Quality = QualityConfig{MaxPerSource: 10, DivergenceRatio: 10, DivergenceMinCount: 100}
	rep1 := mustRun(t, target, cfg)
	if len(rep1.QualityIssues) == 0 {
		t.Fatalf("first run QualityIssues = %v, want over_cap", rep1.QualityIssues)
	}
	if len(rep1.Results[0].Hosts) != 10 {
		t.Fatalf("first run hosts = %d, want 10 capped", len(rep1.Results[0].Hosts))
	}
	if rep1.Results[0].QualityIssues[0].Signal != SignalOverCap || rep1.Results[0].QualityIssues[0].Count != 11 {
		t.Fatalf("first run signal = %+v", rep1.Results[0].QualityIssues)
	}
	// Second run served from cache: should replay same capped hosts + sticky issues, no re-truncation
	rep2 := mustRun(t, target, cfg)
	if !rep2.Results[0].Cached {
		t.Fatal("second run not cached")
	}
	if len(rep2.Results[0].Hosts) != 10 {
		t.Fatalf("cached hosts = %d, want 10", len(rep2.Results[0].Hosts))
	}
	if len(rep2.QualityIssues) == 0 || len(rep2.Results[0].QualityIssues) == 0 {
		t.Fatalf("cached QualityIssues missing: report %v per-slot %v", rep2.QualityIssues, rep2.Results[0].QualityIssues)
	}
	if rep2.QualityIssues[0].Signal != SignalOverCap || rep2.QualityIssues[0].Count != 11 {
		t.Fatalf("cached issue = %+v", rep2.QualityIssues[0])
	}
	if len(rep2.QualityIssues) != 1 {
		t.Fatalf("cached issues count = %d, want 1", len(rep2.QualityIssues))
	}
}

func TestQualityGateAbortOnFlag(t *testing.T) {
	script := standardScript()
	script["subfinder -d example.com -silent"] = func(Cmd) (RunResult, error) {
		var b []byte
		for i := 0; i < 50001; i++ {
			b = append(b, formatHost(i, "example.com")...)
			b = append(b, '\n')
		}
		return RunResult{Stdout: b}, nil
	}
	r := newFakeRunner(t, script)
	cfg := testConfig(r, newFakeLookup())
	cfg.Quality = QualityConfig{MaxPerSource: 50000, DivergenceRatio: 10, DivergenceMinCount: 100, AbortOnFlag: true}
	_, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err == nil || !contains(err.Error(), "quality gate") {
		t.Fatalf("abort err = %v, want quality gate", err)
	}
	if !contains(err.Error(), "over_cap") {
		t.Fatalf("abort err missing signal: %v", err)
	}
}

func TestQualityGateDivergence_WithCachedMedian(t *testing.T) {
	// Two cached producing sources (1, 2) contribute to median; fresh outlier 37000 should fire.
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com"), Cached: true},
		{Source: "assetfinder", Hosts: makeHosts(t, 2, "example.com"), Cached: true},
		{Source: "amass", Hosts: makeHosts(t, 37000, "example.com")},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want 1 divergence (cached median replay)", issues)
	}
	iss := issues[0]
	if iss.Source != "amass" || iss.Signal != SignalDivergence || iss.Count != 37000 {
		t.Fatalf("issue = %+v, want amass divergence count 37000", iss)
	}
	wantOthers := []int{1, 2}
	if !reflect.DeepEqual(iss.Others, wantOthers) {
		t.Fatalf("Others = %v, want %v (selection order, cached median)", iss.Others, wantOthers)
	}
	// Verify median 1.5: divergence threshold is 10*1.5=15, 37000>15 and >100 => fires.
	// Also verify per-slot issue was appended to the fresh outlier only.
	if len(res[2].QualityIssues) != 1 || res[2].QualityIssues[0].Signal != SignalDivergence {
		t.Fatalf("fresh slot QualityIssues = %v, want 1 divergence", res[2].QualityIssues)
	}
	if len(res[0].QualityIssues) != 0 || len(res[1].QualityIssues) != 0 {
		t.Fatalf("cached slots must have no new issues: subfinder %v assetfinder %v", res[0].QualityIssues, res[1].QualityIssues)
	}
}

func TestQualityGateDivergence_CachedOutlierNotFlagged(t *testing.T) {
	// Fresh 1, fresh 2, cached 37000: producing=3 but cached outlier must be skipped (res.Cached).
	res := []SourceResult{
		{Source: "subfinder", Hosts: makeHosts(t, 1, "example.com")},
		{Source: "assetfinder", Hosts: makeHosts(t, 2, "example.com")},
		{Source: "amass", Hosts: makeHosts(t, 37000, "example.com"), Cached: true},
	}
	qc := DefaultQualityConfig()
	issues := applyQualityGate(res, qc)
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want 0 (cached outlier must be skipped)", issues)
	}
	if len(res[2].QualityIssues) != 0 {
		t.Fatalf("cached outlier slot QualityIssues = %v, want none", res[2].QualityIssues)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestStoredResultQualityIssuesRoundTrip(t *testing.T) {
	target := mustDomain(t, "example.com")
	sr := storedResult{
		Source: "subfinder", Version: "v1", Target: target.Identity().String(),
		Hosts:         makeHosts(t, 2, "example.com"),
		QualityIssues: []QualityIssue{{Source: "subfinder", Signal: SignalOverCap, Count: 50001}},
	}
	b, _ := json.Marshal(sr)
	decoded, err := decodeStored(b, target, "subfinder")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.QualityIssues) != 1 || decoded.QualityIssues[0].Signal != SignalOverCap {
		t.Fatalf("roundtrip QualityIssues = %v", decoded.QualityIssues)
	}
}
