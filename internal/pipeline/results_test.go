package pipeline

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// --- asset builders for the results channel tests (synthetic values only) ---

func mustIP(t *testing.T, s string) asset.IP {
	t.Helper()
	ip, err := asset.NewIP(s, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP(%q): %v", s, err)
	}
	return ip
}

func mustPort(t *testing.T, n int, proto string) asset.Port {
	t.Helper()
	p, err := asset.NewPort(n, proto, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewPort(%d, %q): %v", n, proto, err)
	}
	return p
}

func mustService(t *testing.T, name string, port asset.Port) asset.Service {
	t.Helper()
	s, err := asset.NewService(name, port, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewService(%q): %v", name, err)
	}
	return s
}

func mustEndpoint(t *testing.T, method, rawURL string) asset.Endpoint {
	t.Helper()
	e, err := asset.NewEndpoint(method, rawURL, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEndpoint(%q, %q): %v", method, rawURL, err)
	}
	return e
}

func mustJavaScript(t *testing.T, rawURL string) asset.JavaScript {
	t.Helper()
	j, err := asset.NewJavaScript(rawURL, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript(%q): %v", rawURL, err)
	}
	return j
}

func mustParameter(t *testing.T, name, location, value, source string) asset.Parameter {
	t.Helper()
	p, err := asset.NewParameter(name, location, value, source, testTime, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewParameter(%q, %q): %v", name, location, err)
	}
	return p
}

func mustTechnology(t *testing.T, name string, category asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, category, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTechnology(%q, %q): %v", name, category, err)
	}
	return tech
}

func mustSecret(t *testing.T, value string, source asset.Identity) asset.SecretCandidate {
	t.Helper()
	s, err := asset.NewSecretCandidate(asset.SecretTypeJWT, value, source, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSecretCandidate(%q): %v", value, err)
	}
	return s
}

func mustEvidence(t *testing.T, indicator, value string, source asset.Identity) asset.Evidence {
	t.Helper()
	e, err := asset.NewEvidence(asset.MethodHeader, indicator, value, source, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence(%q): %v", indicator, err)
	}
	return e
}

func mustFinding(t *testing.T, ruleID string, subject asset.Identity) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodHeader, ruleID+"-indicator", "value", subject, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleID,
		Category:   "test",
		Subject:    subject,
		Confidence: 1,
		Evidence:   []asset.Evidence{ev},
		Priority:   "info",
		Status:     "open",
		Created:    testTime,
		Updated:    testTime,
	})
	if err != nil {
		t.Fatalf("NewFinding(%q): %v", ruleID, err)
	}
	return f
}

func mustTLSCert(t *testing.T, fingerprint string) asset.TLSCertificate {
	t.Helper()
	c, err := asset.NewTLSCertificate(fingerprint, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTLSCertificate(%q): %v", fingerprint, err)
	}
	return c
}

func mustSourceMap(t *testing.T, rawURL string) asset.SourceMap {
	t.Helper()
	m, err := asset.NewSourceMap(rawURL, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSourceMap(%q): %v", rawURL, err)
	}
	return m
}

func mustRelationship(t *testing.T, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	r, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return r
}

// resultsStage returns a completed stage that reports exactly the given
// result additions.
func resultsStage(name StageName, res Results) *fakeStage {
	return &fakeStage{
		name: name,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			return StageResult{Outcome: OutcomeCompleted, Results: res}, nil
		},
	}
}

// captureStage returns a stage that records the merged results it received
// (deep-copied) and then reports its own additions.
func captureStage(name StageName, add Results, got *Results) *fakeStage {
	return &fakeStage{
		name: name,
		run: func(ctx context.Context, in StageInput) (StageResult, error) {
			*got = Results{
				IPs:             append([]asset.IP(nil), in.Results.IPs...),
				Ports:           append([]asset.Port(nil), in.Results.Ports...),
				Services:        append([]asset.Service(nil), in.Results.Services...),
				Endpoints:       append([]asset.Endpoint(nil), in.Results.Endpoints...),
				JavaScript:      append([]asset.JavaScript(nil), in.Results.JavaScript...),
				Parameters:      append([]asset.Parameter(nil), in.Results.Parameters...),
				Technologies:    append([]asset.Technology(nil), in.Results.Technologies...),
				Secrets:         append([]asset.SecretCandidate(nil), in.Results.Secrets...),
				Evidence:        append([]asset.Evidence(nil), in.Results.Evidence...),
				Findings:        append([]asset.Finding(nil), in.Results.Findings...),
				TLSCertificates: append([]asset.TLSCertificate(nil), in.Results.TLSCertificates...),
				SourceMaps:      append([]asset.SourceMap(nil), in.Results.SourceMaps...),
				Relationships:   append([]asset.Relationship(nil), in.Results.Relationships...),
				Surfaces:        append([]priority.SurfaceAsset(nil), in.Results.Surfaces...),
				Groups:          append([]priority.Group(nil), in.Results.Groups...),
				AttackPaths:     append([]priority.AttackPath(nil), in.Results.AttackPaths...),
			}
			return StageResult{Outcome: OutcomeCompleted, Results: add}, nil
		},
	}
}

func emptyResults() Results { return Results{} }

// TestMergeResultsFirstSeenDedupAcrossStages pins the core merge contract:
// identical identities from two stages collapse to the FIRST, order stays
// first-seen, and every channel key family dedups on its canonical identity
// (asset Identity() strings, Relationship.ID(), and the priority
// Identity/Anchor/Root fields).
func TestMergeResultsFirstSeenDedupAcrossStages(t *testing.T) {
	host1 := mustHost(t, "api.example.com")
	ip1 := mustIP(t, "192.168.1.10")
	ip2 := mustIP(t, "192.168.1.11")
	port1 := mustPort(t, 80, "tcp")
	svc1 := mustService(t, "nginx", port1)
	ep1 := mustEndpoint(t, "GET", "https://api.example.com/login")
	js1 := mustJavaScript(t, "https://api.example.com/app.js")
	p1 := mustParameter(t, "q", "query", "v", "url")
	tech1 := mustTechnology(t, "nginx", asset.CategoryServer)
	sec1 := mustSecret(t, "eyJhbGciOiJIUzI1NiJ9", host1.Identity())
	ev1 := mustEvidence(t, "x-nginx-version", "1.25", host1.Identity())
	f1 := mustFinding(t, "test.rule", host1.Identity())
	cert1 := mustTLSCert(t, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	sm1 := mustSourceMap(t, "https://api.example.com/app.js.map")
	rel1 := mustRelationship(t, host1.Identity(), asset.RelationshipHostToIP, ip1.Identity())
	revRel := mustRelationship(t, ip1.Identity(), asset.RelationshipHostToIP, host1.Identity())
	surf1 := priority.SurfaceAsset{Identity: host1.Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}
	group1 := priority.Group{Anchor: host1.Identity(), Score: 0.5, Level: priority.LevelLow}
	path1 := priority.AttackPath{Root: host1.Identity(), Score: 0.5, Level: priority.LevelLow}

	stage1 := resultsStage(StageDiscover, Results{
		IPs:             []asset.IP{ip1},
		Services:        []asset.Service{svc1},
		Endpoints:       []asset.Endpoint{ep1},
		JavaScript:      []asset.JavaScript{js1},
		Parameters:      []asset.Parameter{p1},
		Technologies:    []asset.Technology{tech1},
		Secrets:         []asset.SecretCandidate{sec1},
		Evidence:        []asset.Evidence{ev1},
		Findings:        []asset.Finding{f1},
		TLSCertificates: []asset.TLSCertificate{cert1},
		SourceMaps:      []asset.SourceMap{sm1},
		Relationships:   []asset.Relationship{rel1, revRel},
		Surfaces:        []priority.SurfaceAsset{surf1},
		Groups:          []priority.Group{group1},
		AttackPaths:     []priority.AttackPath{path1},
	})
	// Stage 2 re-emits every identity (duplicates — all dropped) plus one
	// NEW entry per channel. rel1 (same edge) is dropped; revRel's reverse
	// edge (ip -> host, same kind) is a DIFFERENT ID and survives as new.
	stage2 := resultsStage(StageDNS, Results{
		IPs:             []asset.IP{ip1, ip2},
		Services:        []asset.Service{svc1},
		Endpoints:       []asset.Endpoint{ep1},
		JavaScript:      []asset.JavaScript{js1},
		Parameters:      []asset.Parameter{p1},
		Technologies:    []asset.Technology{tech1},
		Secrets:         []asset.SecretCandidate{sec1},
		Evidence:        []asset.Evidence{ev1},
		Findings:        []asset.Finding{f1},
		TLSCertificates: []asset.TLSCertificate{cert1},
		SourceMaps:      []asset.SourceMap{sm1},
		Relationships:   []asset.Relationship{rel1},
		Surfaces:        []priority.SurfaceAsset{surf1},
		Groups:          []priority.Group{group1},
		AttackPaths:     []priority.AttackPath{path1},
	})

	report, err := run(t, validConfig(t, StageDiscover, StageDNS), []Stage{stage1, stage2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	r := report.Results
	if !reflect.DeepEqual(r.IPs, []asset.IP{ip1, ip2}) {
		t.Errorf("IPs = %v, want [ip1 ip2] (first-seen, dup dropped)", r.IPs)
	}
	if !reflect.DeepEqual(r.Services, []asset.Service{svc1}) {
		t.Errorf("Services = %v, want [svc1]", r.Services)
	}
	if !reflect.DeepEqual(r.Endpoints, []asset.Endpoint{ep1}) {
		t.Errorf("Endpoints = %v, want [ep1]", r.Endpoints)
	}
	if !reflect.DeepEqual(r.JavaScript, []asset.JavaScript{js1}) {
		t.Errorf("JavaScript = %v, want [js1]", r.JavaScript)
	}
	if !reflect.DeepEqual(r.Parameters, []asset.Parameter{p1}) {
		t.Errorf("Parameters = %v, want [p1]", r.Parameters)
	}
	if !reflect.DeepEqual(r.Technologies, []asset.Technology{tech1}) {
		t.Errorf("Technologies = %v, want [tech1]", r.Technologies)
	}
	if !reflect.DeepEqual(r.Secrets, []asset.SecretCandidate{sec1}) {
		t.Errorf("Secrets = %v, want [sec1]", r.Secrets)
	}
	if !reflect.DeepEqual(r.Evidence, []asset.Evidence{ev1}) {
		t.Errorf("Evidence = %v, want [ev1]", r.Evidence)
	}
	if !reflect.DeepEqual(r.Findings, []asset.Finding{f1}) {
		t.Errorf("Findings = %v, want [f1]", r.Findings)
	}
	if !reflect.DeepEqual(r.TLSCertificates, []asset.TLSCertificate{cert1}) {
		t.Errorf("TLSCertificates = %v, want [cert1]", r.TLSCertificates)
	}
	if !reflect.DeepEqual(r.SourceMaps, []asset.SourceMap{sm1}) {
		t.Errorf("SourceMaps = %v, want [sm1]", r.SourceMaps)
	}
	// rel1 (host->ip) is first-seen from stage 1; stage 2's re-emission is
	// dropped; the reverse edge is a distinct ID and was added by stage 1
	// already, so the channel holds both edges in stage-1 order.
	if !reflect.DeepEqual(r.Relationships, []asset.Relationship{rel1, revRel}) {
		t.Errorf("Relationships = %v, want [rel1 revRel]", r.Relationships)
	}
	if !reflect.DeepEqual(r.Surfaces, []priority.SurfaceAsset{surf1}) {
		t.Errorf("Surfaces = %v, want [surf1]", r.Surfaces)
	}
	if !reflect.DeepEqual(r.Groups, []priority.Group{group1}) {
		t.Errorf("Groups = %v, want [group1]", r.Groups)
	}
	if !reflect.DeepEqual(r.AttackPaths, []priority.AttackPath{path1}) {
		t.Errorf("AttackPaths = %v, want [path1]", r.AttackPaths)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty (no cap hit)", report.Truncated, report.StickyFlags)
	}
}

// TestMergeResultsKindNamespacePins that two asset kinds sharing the same
// value string never collide: the "kind:" prefix namespaces the dedup key.
func TestMergeResultsKindNamespacePins(t *testing.T) {
	js := mustJavaScript(t, "https://api.example.com/app.js")
	sm := mustSourceMap(t, "https://api.example.com/app.js.map")
	// jsSame shares the source map's URL string but is a DIFFERENT asset
	// kind (javascript), so it dedups within the JavaScript channel only
	// against the same-kind identity — and never against the source map.
	jsSame := mustJavaScript(t, "https://api.example.com/app.js.map")
	stage := resultsStage(StageDiscover, Results{
		JavaScript: []asset.JavaScript{js, jsSame},
		SourceMaps: []asset.SourceMap{sm},
	})
	report, err := run(t, validConfig(t, StageDiscover), []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(report.Results.JavaScript, []asset.JavaScript{js, jsSame}) {
		t.Errorf("JavaScript = %v, want [js jsSame] (distinct javascript identities)", report.Results.JavaScript)
	}
	if len(report.Results.SourceMaps) != 1 || report.Results.SourceMaps[0].URL.String() != "https://api.example.com/app.js.map" {
		t.Errorf("SourceMaps = %v, want the source map retained (different kind, no collision)", report.Results.SourceMaps)
	}
}

// TestMergeResultsPerChannelDedupNamespacing pins the per-channel dedup
// rule: the same canonical asset identity carried by DIFFERENT channels
// (a Group anchored at a host identity, an AttackPath rooted at the same
// host identity, and a SurfaceAsset keyed by it) must all be retained —
// the shared seen map is namespaced per channel, never shared across them.
func TestMergeResultsPerChannelDedupNamespacing(t *testing.T) {
	hostID := mustHost(t, "api.example.com").Identity()
	ipID := mustIP(t, "192.168.1.10").Identity()
	surf := priority.SurfaceAsset{Identity: hostID, Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}
	group := priority.Group{Anchor: hostID, Score: 0.5, Level: priority.LevelLow}
	path := priority.AttackPath{Root: hostID, Score: 0.5, Level: priority.LevelLow}
	ipSurf := priority.SurfaceAsset{Identity: ipID, Kind: asset.KindIP, Score: 0.3, Level: priority.LevelLow}
	ip := mustIP(t, "192.168.1.10")

	stage := resultsStage(StageDiscover, Results{
		IPs:         []asset.IP{ip},
		Surfaces:    []priority.SurfaceAsset{surf, ipSurf},
		Groups:      []priority.Group{group},
		AttackPaths: []priority.AttackPath{path},
	})
	report, err := run(t, validConfig(t, StageDiscover), []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Results.IPs) != 1 {
		t.Errorf("IPs = %v, want the one IP", report.Results.IPs)
	}
	// The ip:-keyed surface must not be dropped as a "duplicate" of the
	// IPs channel entry, nor the host-keyed surface/group/path each other.
	if len(report.Results.Surfaces) != 2 {
		t.Errorf("Surfaces = %v, want both surfaces (per-channel dedup)", report.Results.Surfaces)
	}
	if len(report.Results.Groups) != 1 {
		t.Errorf("Groups = %v, want the group retained", report.Results.Groups)
	}
	if len(report.Results.AttackPaths) != 1 {
		t.Errorf("AttackPaths = %v, want the path retained", report.Results.AttackPaths)
	}
}

// TestMergeResultsNilAndEmptyAdditionsLegal pins that nil Results and empty
// non-nil slices are legal and mean "nothing added": no channels, no flags.
func TestMergeResultsNilAndEmptyAdditionsLegal(t *testing.T) {
	t.Run("nil Results", func(t *testing.T) {
		report, err := run(t, validConfig(t, StageDiscover), []Stage{resultsStage(StageDiscover, Results{})})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !reflect.DeepEqual(report.Results, Results{}) {
			t.Errorf("Results = %+v, want all-empty", report.Results)
		}
		if report.Truncated || len(report.StickyFlags) != 0 {
			t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty", report.Truncated, report.StickyFlags)
		}
	})
	t.Run("empty non-nil slices", func(t *testing.T) {
		stage := resultsStage(StageDiscover, Results{IPs: []asset.IP{}, Technologies: []asset.Technology{}})
		report, err := run(t, validConfig(t, StageDiscover), []Stage{stage})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Results.IPs) != 0 || len(report.Results.Technologies) != 0 {
			t.Errorf("Results = %+v, want empty channels", report.Results)
		}
		if report.Truncated || len(report.StickyFlags) != 0 {
			t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty", report.Truncated, report.StickyFlags)
		}
	})
}

// TestRunResultsCapSingleChannel pins the carve-out: a channel capped at a
// small MaxOutput (via StageBounds) keeps the first cap entries, sets its
// <channel>_truncated sticky flag + report.Truncated, leaves uncapped
// channels untouched, and does NOT touch the stage's own outcome.
func TestRunResultsCapSingleChannel(t *testing.T) {
	ips := []asset.IP{mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.3"), mustIP(t, "10.0.0.4"), mustIP(t, "10.0.0.5")}
	techs := []asset.Technology{
		mustTechnology(t, "nginx", asset.CategoryServer),
		mustTechnology(t, "react", asset.CategoryFramework),
	}
	stage := resultsStage(StageDiscover, Results{IPs: ips, Technologies: techs})
	cfg := validConfig(t, StageDiscover)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: 3}}
	report, err := run(t, cfg, []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantIPs := []asset.IP{ips[0], ips[1], ips[2]}
	if !reflect.DeepEqual(report.Results.IPs, wantIPs) {
		t.Errorf("IPs = %v, want the first 3 (cap 3, first-seen kept)", report.Results.IPs)
	}
	if !reflect.DeepEqual(report.Results.Technologies, techs) {
		t.Errorf("Technologies = %v, want both (uncapped channel untouched)", report.Results.Technologies)
	}
	if !report.Truncated {
		t.Error("report.Truncated must be set when a channel was capped")
	}
	if !report.StickyFlags["ips_truncated"] {
		t.Errorf("StickyFlags = %v, want ips_truncated set", report.StickyFlags)
	}
	if report.StickyFlags["technologies_truncated"] {
		t.Error("technologies_truncated must not be set (uncapped channel)")
	}
	if len(report.StickyFlags) != 1 {
		t.Errorf("StickyFlags = %v, want exactly ips_truncated", report.StickyFlags)
	}
	// Carve-out: the stage's own outcome is untouched — completed + flag
	// marks the retained set incomplete, never silently completed.
	if report.Stages[0].Outcome != OutcomeCompleted {
		t.Errorf("Stages[0].Outcome = %q, want completed (carve-out)", report.Stages[0].Outcome)
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed with the ips_truncated flag (carve-out)", report.Outcome)
	}
}

// TestRunResultsCapMultipleChannels pins the fixed channel-name vocabulary:
// two capped channels in one merge report both flags, and uncapped channels
// stay flag-free.
func TestRunResultsCapMultipleChannels(t *testing.T) {
	eps := []asset.Endpoint{
		mustEndpoint(t, "GET", "https://a.example.com/1"),
		mustEndpoint(t, "GET", "https://a.example.com/2"),
		mustEndpoint(t, "GET", "https://a.example.com/3"),
		mustEndpoint(t, "GET", "https://a.example.com/4"),
	}
	groups := []priority.Group{
		{Anchor: mustHost(t, "a.example.com").Identity(), Score: 0.9, Level: priority.LevelHigh},
		{Anchor: mustHost(t, "b.example.com").Identity(), Score: 0.8, Level: priority.LevelHigh},
		{Anchor: mustHost(t, "c.example.com").Identity(), Score: 0.7, Level: priority.LevelHigh},
	}
	paths := []priority.AttackPath{
		{Root: mustHost(t, "a.example.com").Identity(), Score: 0.9, Level: priority.LevelHigh},
	}
	stage := resultsStage(StageDiscover, Results{Endpoints: eps, Groups: groups, AttackPaths: paths})
	cfg := validConfig(t, StageDiscover)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: 2}}
	report, err := run(t, cfg, []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Results.Endpoints) != 2 || len(report.Results.Groups) != 2 || len(report.Results.AttackPaths) != 1 {
		t.Errorf("channels after cap = %d/%d/%d, want 2/2/1",
			len(report.Results.Endpoints), len(report.Results.Groups), len(report.Results.AttackPaths))
	}
	for _, flag := range []string{"endpoints_truncated", "groups_truncated"} {
		if !report.StickyFlags[flag] {
			t.Errorf("StickyFlags = %v, want %s set", report.StickyFlags, flag)
		}
	}
	if report.StickyFlags["attack_paths_truncated"] {
		t.Error("attack_paths_truncated must not be set (uncapped channel)")
	}
	if !report.Truncated {
		t.Error("report.Truncated must be set")
	}
}

// TestMergeResultsCappedNamesFixedOrder pins the merge's return value at the
// unit level: capped channel names come back in fixed channel order, only
// the channels the cap actually cut.
func TestMergeResultsCappedNamesFixedOrder(t *testing.T) {
	dst := Results{}
	seen := make(map[string]struct{})
	add := Results{
		IPs:       []asset.IP{mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.3")},
		Ports:     []asset.Port{mustPort(t, 80, "tcp"), mustPort(t, 443, "tcp")},
		Services:  []asset.Service{mustService(t, "nginx", mustPort(t, 80, "tcp")), mustService(t, "nginx", mustPort(t, 443, "tcp"))},
		Endpoints: []asset.Endpoint{mustEndpoint(t, "GET", "https://a.example.com/")},
	}
	capped := mergeResults(&dst, add, seen, 1)
	want := []string{"ips", "ports", "services"}
	if !reflect.DeepEqual(capped, want) {
		t.Errorf("capped = %v, want %v (fixed channel order, endpoints uncapped)", capped, want)
	}
	if len(dst.Endpoints) != 1 {
		t.Errorf("Endpoints = %v, want the single endpoint (uncapped)", dst.Endpoints)
	}
}

// TestMergeChannelNegativeCap pins the defensive branch: a negative cap
// retains nothing and reports the cut (mirroring capCorpus's keep<0 clamp).
func TestMergeChannelNegativeCap(t *testing.T) {
	seen := make(map[string]struct{})
	cur := []asset.IP{mustIP(t, "10.0.0.1")}
	out, cut := mergeChannel(cur, nil, seen, "ips", -1, func(a asset.IP) string { return a.Identity().String() })
	if !cut || len(out) != 0 {
		t.Errorf("mergeChannel(-1) = %d entries, cut=%v; want 0 entries, cut=true", len(out), cut)
	}
}

// TestRunResultsVisibilityAtStageTurn pins the visibility contract: a
// stage's StageInput.Results equals the merged state of the EARLIER stages
// (and excludes its own additions); the first stage sees an empty channel.
func TestRunResultsVisibilityAtStageTurn(t *testing.T) {
	ip1 := mustIP(t, "192.168.1.10")
	ip2 := mustIP(t, "192.168.1.11")
	ip3 := mustIP(t, "192.168.1.12")
	tech1 := mustTechnology(t, "nginx", asset.CategoryServer)
	tech2 := mustTechnology(t, "react", asset.CategoryFramework)

	var discoverSeen, dnsSeen, probeSeen Results
	discover := captureStage(StageDiscover, Results{IPs: []asset.IP{ip1}}, &discoverSeen)
	dns := captureStage(StageDNS, Results{Technologies: []asset.Technology{tech1}, IPs: []asset.IP{ip2}}, &dnsSeen)
	probe := captureStage(StageHTTPProbe, Results{Technologies: []asset.Technology{tech2}, IPs: []asset.IP{ip1, ip3}}, &probeSeen)

	report, err := run(t, validConfig(t, StageDiscover, StageDNS, StageHTTPProbe), []Stage{discover, dns, probe})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// discover runs first: empty channel, nothing to see.
	if !reflect.DeepEqual(discoverSeen, Results{}) {
		t.Errorf("discover saw Results = %+v, want empty", discoverSeen)
	}
	// dns sees discover's ip1 only — never its own tech1/ip2.
	if !reflect.DeepEqual(dnsSeen.IPs, []asset.IP{ip1}) || len(dnsSeen.Technologies) != 0 {
		t.Errorf("dns saw IPs=%v Technologies=%v, want [ip1] / none (excludes its own additions)",
			dnsSeen.IPs, dnsSeen.Technologies)
	}
	// probe sees discover+merged dns: ip1, ip2 and tech1 — never its own.
	if !reflect.DeepEqual(probeSeen.IPs, []asset.IP{ip1, ip2}) {
		t.Errorf("probe saw IPs = %v, want [ip1 ip2]", probeSeen.IPs)
	}
	if !reflect.DeepEqual(probeSeen.Technologies, []asset.Technology{tech1}) {
		t.Errorf("probe saw Technologies = %v, want [tech1] (its own tech2 excluded)", probeSeen.Technologies)
	}
	// Final merged channel: first-seen order across all three stages.
	if !reflect.DeepEqual(report.Results.IPs, []asset.IP{ip1, ip2, ip3}) {
		t.Errorf("report IPs = %v, want [ip1 ip2 ip3]", report.Results.IPs)
	}
	if !reflect.DeepEqual(report.Results.Technologies, []asset.Technology{tech1, tech2}) {
		t.Errorf("report Technologies = %v, want [tech1 tech2]", report.Results.Technologies)
	}
}

// TestRunReportResultsFinalMerged pins that RunReport.Results is exactly the
// final merged state (all channels, first-seen order, deduped).
func TestRunReportResultsFinalMerged(t *testing.T) {
	port1 := mustPort(t, 80, "tcp")
	port2 := mustPort(t, 443, "tcp")
	svc1 := mustService(t, "nginx", port1)
	svc2 := mustService(t, "nginx", port2)
	host := mustHost(t, "api.example.com")

	stage1 := resultsStage(StageDiscover, Results{Ports: []asset.Port{port1, port2}})
	stage2 := resultsStage(StageDNS, Results{Services: []asset.Service{svc1, svc2}, Ports: []asset.Port{port2}})
	stage3 := resultsStage(StageHTTPProbe, Results{Services: []asset.Service{svc2}, Secrets: []asset.SecretCandidate{
		mustSecret(t, "eyJhbGciOiJIUzI1NiJ9", host.Identity()),
	}})

	report, err := run(t, validConfig(t, StageDiscover, StageDNS, StageHTTPProbe), []Stage{stage1, stage2, stage3})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(report.Results.Ports, []asset.Port{port1, port2}) {
		t.Errorf("Ports = %v, want [port1 port2]", report.Results.Ports)
	}
	if !reflect.DeepEqual(report.Results.Services, []asset.Service{svc1, svc2}) {
		t.Errorf("Services = %v, want [svc1 svc2]", report.Results.Services)
	}
	if len(report.Results.Secrets) != 1 {
		t.Errorf("Secrets = %v, want one candidate", report.Results.Secrets)
	}
}

// TestRunFailedStageResultsStillMerged pins the mirror of the corpus
// semantics: a failed stage's retained results are still merged and the
// next stage sees them.
func TestRunFailedStageResultsStillMerged(t *testing.T) {
	tech1 := mustTechnology(t, "nginx", asset.CategoryServer)
	stage1 := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeFailed, Err: errors.New("tool crashed mid-run"), Results: Results{
			Technologies: []asset.Technology{tech1},
		}}, nil
	}}
	var dnsSeen Results
	stage2 := captureStage(StageDNS, Results{}, &dnsSeen)
	report, err := run(t, validConfig(t, StageDiscover, StageDNS), []Stage{stage1, stage2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stages[0].Outcome != OutcomeFailed {
		t.Errorf("Stages[0].Outcome = %q, want failed", report.Stages[0].Outcome)
	}
	if !reflect.DeepEqual(dnsSeen.Technologies, []asset.Technology{tech1}) {
		t.Errorf("dns saw Technologies = %v, want the failed stage's retained output", dnsSeen.Technologies)
	}
	if !reflect.DeepEqual(report.Results.Technologies, []asset.Technology{tech1}) {
		t.Errorf("report Technologies = %v, want the failed stage's retained output", report.Results.Technologies)
	}
}

// TestRunPreCancelledResultsEmpty pins the pre-cancelled contract: zero
// additions, empty Results, no flags.
func TestRunPreCancelledResultsEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Run(ctx, validConfig(t, StageDiscover, StageDNS), nil, newFakeClock(testTime),
		[]Stage{resultsStage(StageDiscover, Results{IPs: []asset.IP{mustIP(t, "10.0.0.1")}}), resultsStage(StageDNS, Results{})})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Outcome != OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", report.Outcome)
	}
	if !reflect.DeepEqual(report.Results, Results{}) {
		t.Errorf("Results = %+v, want all-empty (no stage ran)", report.Results)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty", report.Truncated, report.StickyFlags)
	}
}

// TestRunResultsDeterminism pins the determinism contract: two identical
// runs produce DeepEqual RunReports including Results and StickyFlags.
func TestRunResultsDeterminism(t *testing.T) {
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: 2}}
	stages := func() []Stage {
		return []Stage{
			resultsStage(StageDiscover, Results{
				IPs: []asset.IP{mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.3")},
				Groups: []priority.Group{
					{Anchor: mustHost(t, "a.example.com").Identity(), Score: 0.9, Level: priority.LevelHigh},
					{Anchor: mustHost(t, "b.example.com").Identity(), Score: 0.8, Level: priority.LevelHigh},
				},
			}),
			resultsStage(StageDNS, Results{
				IPs: []asset.IP{mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.4")},
			}),
		}
	}
	r1, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	r2, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Errorf("runs differ (Results/StickyFlags must be deterministic):\n%+v\n%+v", r1, r2)
	}
}

// TestMergeResultsCapPermanence pins the corpus-mirroring permanence rule:
// entries cut by a cap stay first-seen and cannot re-enter the channel,
// even through a later stage with a larger cap; a later stage with a
// smaller cap re-cuts the channel and re-flags it.
func TestMergeResultsCapPermanence(t *testing.T) {
	ips := []asset.IP{
		mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.3"),
		mustIP(t, "10.0.0.4"), mustIP(t, "10.0.0.5"),
	}
	stage1 := resultsStage(StageDiscover, Results{IPs: ips})
	stage2 := resultsStage(StageDNS, Results{IPs: []asset.IP{ips[3], ips[4], mustIP(t, "10.0.0.6")}})
	cfg := validConfig(t, StageDiscover, StageDNS)
	cfg.StageBounds = map[StageName]StageConfig{
		StageDiscover: {MaxOutput: 2},
		StageDNS:      {MaxOutput: 100000},
	}
	report, err := run(t, cfg, []Stage{stage1, stage2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []asset.IP{ips[0], ips[1], mustIP(t, "10.0.0.6")}
	if !reflect.DeepEqual(report.Results.IPs, want) {
		t.Errorf("IPs = %v, want %v (cut entries stay first-seen, cannot re-enter)", report.Results.IPs, want)
	}
	if !report.StickyFlags["ips_truncated"] {
		t.Error("ips_truncated must be set (stage 1's cap cut the channel)")
	}

	t.Run("smaller later cap re-cuts the channel", func(t *testing.T) {
		stage1 := resultsStage(StageDiscover, Results{IPs: []asset.IP{ips[0], ips[1], ips[2]}})
		stage2 := resultsStage(StageDNS, Results{})
		cfg := validConfig(t, StageDiscover, StageDNS)
		cfg.StageBounds = map[StageName]StageConfig{
			StageDiscover: {MaxOutput: 100000},
			StageDNS:      {MaxOutput: 2},
		}
		report, err := run(t, cfg, []Stage{stage1, stage2})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []asset.IP{ips[0], ips[1]}
		if !reflect.DeepEqual(report.Results.IPs, want) {
			t.Errorf("IPs = %v, want %v (stage 2's smaller cap re-cut)", report.Results.IPs, want)
		}
		if !report.StickyFlags["ips_truncated"] {
			t.Error("ips_truncated must be set (stage 2's smaller cap cut the channel)")
		}
	})
}

// TestMergeResultsDefensiveCopy pins that the runner never aliases a
// stage's result slices: mutating the stage's returned Results after Run
// returns cannot reach the report.
func TestMergeResultsDefensiveCopy(t *testing.T) {
	ip1 := mustIP(t, "10.0.0.1")
	var res StageResult
	stage := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		res = StageResult{Outcome: OutcomeCompleted, Results: Results{IPs: []asset.IP{ip1}}}
		return res, nil
	}}
	report, err := run(t, validConfig(t, StageDiscover), []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	res.Results.IPs[0] = mustIP(t, "10.9.9.9")
	if len(report.Results.IPs) != 1 || report.Results.IPs[0].String() != "10.0.0.1" {
		t.Errorf("report Results aliased the stage's slices: %+v", report.Results.IPs)
	}
}

// TestRunResultsWithCorpusCapCombined pins that the results-channel flags
// coexist with corpus_capped in one run: both cuts are recorded honestly.
func TestRunResultsWithCorpusCapCombined(t *testing.T) {
	u, err := asset.ParseURL("https://a.example.com/", asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	stage := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeCompleted, Additions: StageAdditions{
			Hosts: []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com"), mustHost(t, "c.example.com")},
			URLs:  []asset.URL{u},
		}, Results: Results{
			IPs: []asset.IP{mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2"), mustIP(t, "10.0.0.3")},
		}}, nil
	}}
	cfg := validConfig(t, StageDiscover)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxCorpusSize: 2, MaxOutput: 2}}
	report, err := run(t, cfg, []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.StickyFlags["corpus_capped"] {
		t.Error("corpus_capped must be set")
	}
	if !report.StickyFlags["ips_truncated"] {
		t.Error("ips_truncated must be set")
	}
	if !report.Truncated {
		t.Error("Truncated must be set")
	}
	if len(report.Results.IPs) != 2 {
		t.Errorf("IPs = %v, want the first 2", report.Results.IPs)
	}
}

// TestMergeResultsAllSixteenChannels pins the full 16-channel surface at the
// unit level: every channel merges independently in one call.
func TestMergeResultsAllSixteenChannels(t *testing.T) {
	host := mustHost(t, "api.example.com")
	ip := mustIP(t, "192.168.1.10")
	port := mustPort(t, 80, "tcp")
	add := Results{
		IPs:             []asset.IP{ip},
		Ports:           []asset.Port{port},
		Services:        []asset.Service{mustService(t, "nginx", port)},
		Endpoints:       []asset.Endpoint{mustEndpoint(t, "GET", "https://api.example.com/x")},
		JavaScript:      []asset.JavaScript{mustJavaScript(t, "https://api.example.com/app.js")},
		Parameters:      []asset.Parameter{mustParameter(t, "q", "query", "v", "url")},
		Technologies:    []asset.Technology{mustTechnology(t, "nginx", asset.CategoryServer)},
		Secrets:         []asset.SecretCandidate{mustSecret(t, "eyJhbGciOiJIUzI1NiJ9", host.Identity())},
		Evidence:        []asset.Evidence{mustEvidence(t, "x-nginx", "1.25", host.Identity())},
		Findings:        []asset.Finding{mustFinding(t, "test.rule", host.Identity())},
		TLSCertificates: []asset.TLSCertificate{mustTLSCert(t, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")},
		SourceMaps:      []asset.SourceMap{mustSourceMap(t, "https://api.example.com/app.js.map")},
		Relationships:   []asset.Relationship{mustRelationship(t, host.Identity(), asset.RelationshipHostToIP, ip.Identity())},
		Surfaces:        []priority.SurfaceAsset{{Identity: host.Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}},
		Groups:          []priority.Group{{Anchor: host.Identity(), Score: 0.5, Level: priority.LevelLow}},
		AttackPaths:     []priority.AttackPath{{Root: host.Identity(), Score: 0.5, Level: priority.LevelLow}},
	}
	dst := Results{}
	seen := make(map[string]struct{})
	capped := mergeResults(&dst, add, seen, 100000)
	if len(capped) != 0 {
		t.Errorf("capped = %v, want none (cap 100000)", capped)
	}
	// One entry per channel, each merged into its own field.
	if len(dst.IPs) != 1 || len(dst.Ports) != 1 || len(dst.Services) != 1 ||
		len(dst.Endpoints) != 1 || len(dst.JavaScript) != 1 || len(dst.Parameters) != 1 ||
		len(dst.Technologies) != 1 || len(dst.Secrets) != 1 || len(dst.Evidence) != 1 ||
		len(dst.Findings) != 1 || len(dst.TLSCertificates) != 1 || len(dst.SourceMaps) != 1 ||
		len(dst.Relationships) != 1 || len(dst.Surfaces) != 1 || len(dst.Groups) != 1 ||
		len(dst.AttackPaths) != 1 {
		t.Errorf("channel lengths = %d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d, want 1 each",
			len(dst.IPs), len(dst.Ports), len(dst.Services), len(dst.Endpoints), len(dst.JavaScript),
			len(dst.Parameters), len(dst.Technologies), len(dst.Secrets), len(dst.Evidence),
			len(dst.Findings), len(dst.TLSCertificates), len(dst.SourceMaps), len(dst.Relationships),
			len(dst.Surfaces), len(dst.Groups), len(dst.AttackPaths))
	}
	// Merging the same additions again dedups: still one entry per channel.
	mergeResults(&dst, add, seen, 100000)
	if len(dst.IPs) != 1 || len(dst.Technologies) != 1 || len(dst.Relationships) != 1 {
		t.Errorf("re-merge grew channels: %d/%d/%d, want 1/1/1",
			len(dst.IPs), len(dst.Technologies), len(dst.Relationships))
	}
}

// TestMergeResultsFullVocabularyPinned pins the complete 16-name channel
// vocabulary in one table test: every channel merged with 2 entries at
// cap 1 returns its name in the exact documented fixed order, and a
// runner run with one stage adding 2 entries per channel at MaxOutput 1
// records every <channel>_truncated sticky flag + Truncated. Any typo in
// the vocabulary strings in results.go — or in the flag construction in
// run.go — fails the exact-list DeepEqual or the per-name flag lookups
// below.
func TestMergeResultsFullVocabularyPinned(t *testing.T) {
	// The documented 16-name vocabulary, fixed order (mergeResults +
	// run.go's "<name>_truncated" construction).
	want := []string{
		"ips", "ports", "services", "endpoints", "javascript", "parameters",
		"technologies", "secrets", "evidence", "findings", "tls_certificates",
		"source_maps", "relationships", "surfaces", "groups", "attack_paths",
	}
	host := mustHost(t, "api.example.com")
	ip1 := mustIP(t, "192.168.1.10")
	ip2 := mustIP(t, "192.168.1.11")
	port1 := mustPort(t, 80, "tcp")
	port2 := mustPort(t, 443, "tcp")
	add := Results{
		IPs:   []asset.IP{ip1, ip2},
		Ports: []asset.Port{port1, port2},
		Services: []asset.Service{
			mustService(t, "nginx", port1),
			mustService(t, "nginx", port2),
		},
		Endpoints: []asset.Endpoint{
			mustEndpoint(t, "GET", "https://api.example.com/a"),
			mustEndpoint(t, "GET", "https://api.example.com/b"),
		},
		JavaScript: []asset.JavaScript{
			mustJavaScript(t, "https://api.example.com/a.js"),
			mustJavaScript(t, "https://api.example.com/b.js"),
		},
		Parameters: []asset.Parameter{
			mustParameter(t, "q", "query", "v", "url"),
			mustParameter(t, "p", "query", "w", "url"),
		},
		Technologies: []asset.Technology{
			mustTechnology(t, "nginx", asset.CategoryServer),
			mustTechnology(t, "react", asset.CategoryFramework),
		},
		Secrets: []asset.SecretCandidate{
			mustSecret(t, "eyJhbGciOiJIUzI1NiJ9.a", host.Identity()),
			mustSecret(t, "eyJhbGciOiJIUzI1NiJ9.b", host.Identity()),
		},
		Evidence: []asset.Evidence{
			mustEvidence(t, "x-nginx-version", "1.25", host.Identity()),
			mustEvidence(t, "x-react-version", "18", host.Identity()),
		},
		Findings: []asset.Finding{
			mustFinding(t, "test.a", host.Identity()),
			mustFinding(t, "test.b", host.Identity()),
		},
		TLSCertificates: []asset.TLSCertificate{
			mustTLSCert(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			mustTLSCert(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		SourceMaps: []asset.SourceMap{
			mustSourceMap(t, "https://api.example.com/a.js.map"),
			mustSourceMap(t, "https://api.example.com/b.js.map"),
		},
		Relationships: []asset.Relationship{
			mustRelationship(t, host.Identity(), asset.RelationshipHostToIP, ip1.Identity()),
			mustRelationship(t, host.Identity(), asset.RelationshipHostToIP, ip2.Identity()),
		},
		Surfaces: []priority.SurfaceAsset{
			{Identity: host.Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow},
			{Identity: ip1.Identity(), Kind: asset.KindIP, Score: 0.3, Level: priority.LevelLow},
		},
		Groups: []priority.Group{
			{Anchor: host.Identity(), Score: 0.5, Level: priority.LevelLow},
			{Anchor: ip1.Identity(), Score: 0.3, Level: priority.LevelLow},
		},
		AttackPaths: []priority.AttackPath{
			{Root: host.Identity(), Score: 0.5, Level: priority.LevelLow},
			{Root: ip1.Identity(), Score: 0.3, Level: priority.LevelLow},
		},
	}

	// Unit level: one merge at cap 1 cuts every channel; the returned
	// names must be the documented 16-name vocabulary in EXACT fixed
	// order (a typo'd channel string in results.go fails the DeepEqual).
	dst := Results{}
	seen := make(map[string]struct{})
	if got := mergeResults(&dst, add, seen, 1); !reflect.DeepEqual(got, want) {
		t.Errorf("capped = %v, want %v (full 16-name vocabulary, fixed order)", got, want)
	}

	// Runner level: one stage adding 2 entries per channel at MaxOutput 1
	// records every <channel>_truncated flag + Truncated (a typo'd flag
	// construction in run.go fails the per-name lookups below).
	stage := resultsStage(StageDiscover, add)
	cfg := validConfig(t, StageDiscover)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: 1}}
	report, err := run(t, cfg, []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Truncated {
		t.Error("report.Truncated must be set (every channel capped)")
	}
	for _, name := range want {
		if !report.StickyFlags[name+"_truncated"] {
			t.Errorf("StickyFlags[%q] = %v, want true (every cut channel must flag)", name+"_truncated", report.StickyFlags[name+"_truncated"])
		}
	}
	if len(report.StickyFlags) != len(want) {
		t.Errorf("StickyFlags = %v, want exactly the %d <channel>_truncated flags", report.StickyFlags, len(want))
	}
}

// TestRunResultsNoFlagWithoutCut pins that a run whose channels never hit a
// cap records no flags and no Truncated — even when MaxOutput is small.
func TestRunResultsNoFlagWithoutCut(t *testing.T) {
	stage := resultsStage(StageDiscover, Results{IPs: []asset.IP{mustIP(t, "10.0.0.1"), mustIP(t, "10.0.0.2")}})
	cfg := validConfig(t, StageDiscover)
	cfg.StageBounds = map[StageName]StageConfig{StageDiscover: {MaxOutput: 2}}
	report, err := run(t, cfg, []Stage{stage})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("Truncated/StickyFlags = %v/%v, want false/empty (cap not hit)", report.Truncated, report.StickyFlags)
	}
	if len(report.Results.IPs) != 2 {
		t.Errorf("IPs = %v, want both (at cap, nothing cut)", report.Results.IPs)
	}
}

// TestRunResultsStageNotRunNoMerge pins that stages that never run (the run
// context is cancelled before their turn) contribute nothing to the channel.
func TestRunResultsStageNotRunNoMerge(t *testing.T) {
	started := make(chan struct{})
	blocker := &fakeStage{name: StageDiscover, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		close(started)
		<-ctx.Done()
		return StageResult{Outcome: OutcomeCancelled}, nil
	}}
	stage2 := resultsStage(StageDNS, Results{IPs: []asset.IP{mustIP(t, "10.0.0.1")}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	report, err := Run(ctx, validConfig(t, StageDiscover, StageDNS), nil, newFakeClock(testTime), []Stage{blocker, stage2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stages[0].Outcome != OutcomeCancelled || report.Stages[1].Outcome != OutcomeCancelled {
		t.Errorf("outcomes = %q/%q, want cancelled/cancelled", report.Stages[0].Outcome, report.Stages[1].Outcome)
	}
	if !reflect.DeepEqual(report.Results, Results{}) {
		t.Errorf("Results = %+v, want all-empty (no stage's results were merged)", report.Results)
	}
}
