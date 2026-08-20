package adapt

// T3d3 integration coverage: ONE end-to-end run composing every adapter
// milestone T3d3 wires (discover EXCLUDED by contract — the seed stage
// below stands in for it), plus the runner-level pins the T3d3 contract
// demands: the FIND-2 first-seen-per-anchor collapse on the Groups and
// AttackPaths channels, and the priority correlation-cut §0.6 chain
// (flag survives the stage result → StageRecord → RunReport).
//
// The run is fully hermetic: a fake resolver, a canned HTTP transport, a
// scripted gau runner, a loopback HTTP server serving synthetic script
// bodies, the package's synthetic secret database and priority catalogs,
// a hermetic detect registry, and a capture reporter. Synthetic values
// only (AGENTS §0.8).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// t3dFakeStage is a hermetic pipeline.Stage with a fixed name and a fixed
// result: the runner-level fake the T3d3 tests use to seed the corpus and
// to pin merge semantics.
type t3dFakeStage struct {
	name pipeline.StageName
	res  pipeline.StageResult
}

// Name implements pipeline.Stage.
func (s *t3dFakeStage) Name() pipeline.StageName { return s.name }

// Run implements pipeline.Stage.
func (s *t3dFakeStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	return s.res, nil
}

// t3dSeedStage is the corpus seed: the discovery adapter is excluded from
// this milestone's integration run by contract, so a fake stage under the
// discover name emits the declared domain and the in-scope hosts the
// remaining engines consume.
func t3dSeedStage(t *testing.T) pipeline.Stage {
	t.Helper()
	return &t3dFakeStage{
		name: pipeline.StageDiscover,
		res: pipeline.StageResult{
			Outcome: pipeline.OutcomeCompleted,
			Additions: pipeline.StageAdditions{
				Domains: []asset.Domain{mustDomain(t, "example.com")},
				Hosts: []asset.Host{
					mustHost(t, "www.example.com"),
					mustHost(t, "api.example.com"),
					mustHost(t, "admin.example.com"),
				},
			},
		},
	}
}

// t3dScriptBodies are the synthetic script bodies the integration run's
// loopback server serves. app.js carries an import edge, a REST endpoint,
// a synthetic AWS access key (awsKey(7) — the package's canonical
// synthetic value, detected by both the jsintel engine and the secrentel
// test database), a react technology marker, and a sourceMappingURL
// reference; lib.js carries a synthetic Google-style API key and a webpack
// marker; shared.js (the resolved import target) contributes no string
// literals.
func t3dScriptBodies() map[string]string {
	key := awsKey(7)
	return map[string]string{
		"/app.js": `import "./shared.js";
const api = "/api/v1/users";
const key = "` + key + `";
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = true;
//# sourceMappingURL=/app.js.map
`,
		"/lib.js": `const orders = "/api/v2/orders";
const gkey = "AIzaSyA-test-key-123456789012345678901234";
window.__webpack_require__ = {};
`,
		"/shared.js": `window.ready = true;
`,
	}
}

// t3dJSLoopback starts the loopback server serving t3dScriptBodies plus a
// fallback body for every other path (the corpus root/graphql URLs the
// other stages produced), so every fetch in the integration run completes.
// The rewrite transport forwards the canonical URLs to it — the engine
// never leaves the loopback.
func t3dJSLoopback(t *testing.T) (*httptest.Server, *rewriteTransport) {
	t.Helper()
	bodies := t3dScriptBodies()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			body = "window.ready = true;\n"
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &rewriteTransport{base: srv.URL}
}

// t3dTechListingRule builds the hermetic detect rule the integration run
// exercises: it executes only when the snapshot carries technologies
// (RequiredAssetTypes) and emits ONE synthetic finding whose subject is
// the first technology identity — proving the detect stage consumed the
// earlier stages' results-channel technologies end-to-end. The engine
// rejects findings that cite assets the snapshot never produced, so the
// subject is always one of the snapshot's own identities (observed-corpus
// rule, mirroring internal/detect/examples).
func t3dTechListingRule(t *testing.T) detect.Rule {
	t.Helper()
	const (
		ruleID      = "t3d.integration.tech-listing"
		ruleName    = "Integration Technology Listing"
		ruleVersion = "1.0.0"
	)
	rule := newDetectRule(t, ruleID, func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
		if len(dctx.Technologies) == 0 {
			return nil, nil
		}
		subject := dctx.Technologies[0].Identity()
		ev, err := asset.NewEvidence(asset.MethodDetection, ruleID,
			"integration test technology listing signal", subject,
			asset.Provenance{Source: "integration-test"})
		if err != nil {
			return nil, err
		}
		f, err := asset.NewFinding(asset.Finding{
			RuleID:     ruleID,
			RuleName:   ruleName,
			Category:   detect.CategoryInformation.String(),
			Subject:    subject,
			Confidence: 0.9,
			Evidence:   []asset.Evidence{ev},
			Priority:   detect.PriorityInfo.String(),
			Status:     detect.StatusOpen.String(),
			Created:    dctx.Clock.Now(), // the injected clock keeps the run deterministic
		})
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	})
	// The framework's validateFinding contract ties the finding's
	// RuleName/Category to the executing rule's own metadata: align them.
	rule.Name = ruleName
	rule.Version = ruleVersion
	rule.Category = detect.CategoryInformation
	rule.Inputs = []detect.RuleInput{detect.InputTechnology}
	rule.RequiredAssetTypes = []asset.Kind{asset.KindTechnology}
	return rule
}

// TestT3dEndToEndRun is the T3d3 integration test: ONE full pipeline run
// through the real dns, httpprobe, urlintel, techintel, jsintel,
// secrentel, priority, detect, and report stages (discover EXCLUDED, the
// seed stage standing in), with every engine hermetic. It pins:
//
//   - the RunReport outcome vocabulary (every stage completed, the run
//     completed, zero failures, no truncation flags);
//   - every results channel populated by its producers (IPs from dns;
//     ports/services/endpoints/relationships from httpprobe; parameters
//     from urlintel; technologies/evidence from techintel; JavaScript,
//     source maps, endpoints, secrets, technologies, evidence from
//     jsintel; secrets/evidence from secrentel; surfaces/groups/attack
//     paths from priority; findings from detect);
//   - the document flow jsintel → secrentel: the retained app.js body
//     (carrying the synthetic key) reaches the secrentel stage, whose
//     candidate deduplicates with jsintel's own by canonical identity;
//   - the report stage's full Context composition: every corpus and
//     results channel reaches the report model;
//   - determinism: two identical runs produce DeepEqual RunReports.
func TestT3dEndToEndRun(t *testing.T) {
	target := mustDomain(t, "example.com")

	// 1) DNS: hermetic resolver, one A record per seeded host.
	resolver := newFakeResolver()
	resolver.set("www.example.com", dns.TypeA, "93.184.216.34")
	resolver.set("api.example.com", dns.TypeA, "93.184.216.35")
	resolver.set("admin.example.com", dns.TypeA, "93.184.216.36")

	// 2) HTTP probing: canned 200 responses. No TLS handshake happens, so
	// the TLSCertificates channel stays empty (the T3d2 channel test pins
	// the same behavior).
	tr := &cannedTransport{}
	for _, host := range []string{"www.example.com", "api.example.com", "admin.example.com"} {
		cannedHost(tr, host, cannedResponse{
			status:  200,
			body:    "<!doctype html><html><body>hello</body></html>",
			headers: map[string]string{"Content-Type": "text/html"},
		})
	}

	// 3) urlintel: scripted gau for the declared domain. The duplicate
	// app.js line pins first-seen dedup through the whole pipeline.
	runner := newFakeRunner(gauLines("example.com",
		"http://www.example.com/app.js",
		"http://api.example.com/lib.js?v=2",
		"http://www.example.com/graphql",
		"http://www.example.com/app.js",
	))

	// 4) jsintel: the loopback serving the synthetic script bodies.
	_, jsTransport := t3dJSLoopback(t)

	// 5) detect: hermetic registry with the technology-listing rule.
	detectReg := newDetectRegistry(t, t3dTechListingRule(t))

	// 6) report: hermetic capture reporter recording the model the engine
	// built from the stage's Context — the assertion surface for the full
	// Context composition.
	var model *report.Model
	reportReg := newReportRegistry(t, captureReporter("capture", func(m *report.Model) { model = m }))

	interesting, risk := priorityCatalogs(t)
	secretDB := testSecretDB(t)

	cfg := pipeline.ScanConfig{
		Target: target,
		Stages: []pipeline.StageName{
			pipeline.StageDiscover, pipeline.StageDNS, pipeline.StageHTTPProbe,
			pipeline.StageURLIntel, pipeline.StageTechIntel, pipeline.StageJSIntel,
			pipeline.StageSecretIntel, pipeline.StagePriority, pipeline.StageDetect,
			pipeline.StageReport,
		},
	}
	clk := fixedClock{now: fixedTime}
	stages := func(outputDir string) []pipeline.Stage {
		cfg.OutputDir = outputDir
		return []pipeline.Stage{
			t3dSeedStage(t),
			NewDNSStage(resolver),
			NewHTTPProbeStage(tr),
			NewURLIntelStage(runner, fakeLookup),
			NewTechIntelStage(nil), // production fingerprint database
			NewJSIntelStage(jsTransport),
			NewSecretIntelStage(secretDB),
			NewPriorityStage(interesting, risk),
			NewDetectStage(detectReg),
			NewReportStage(reportReg),
		}
	}

	// Each run commits into its own output directory: the report engine
	// commits atomically and the runs must not interfere.
	r1, err := pipeline.Run(context.Background(), cfg, nil, clk, stages(t.TempDir()))
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}

	// --- Run-level outcome vocabulary ---
	if r1.Outcome != pipeline.OutcomeCompleted {
		for i, sr := range r1.Stages {
			t.Logf("stage %d %s: outcome=%s processed=%d failed=%d truncated=%v flags=%v err=%v",
				i, sr.Name, sr.Outcome, sr.ItemsProcessed, sr.ItemsFailed, sr.Truncated, sr.StickyFlags, sr.Err)
		}
		t.Fatalf("Outcome = %q, want completed", r1.Outcome)
	}
	for i, sr := range r1.Stages {
		if sr.Outcome != pipeline.OutcomeCompleted {
			t.Errorf("stage %d (%s) outcome = %q, want completed", i, sr.Name, sr.Outcome)
		}
	}
	if r1.Truncated {
		t.Error("Truncated = true, want false (no cap fired anywhere in the run)")
	}
	if len(r1.StickyFlags) != 0 {
		t.Errorf("StickyFlags = %v, want empty", r1.StickyFlags)
	}
	if r1.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", r1.ItemsFailed)
	}

	// --- Corpus: the seed's domain + hosts, the probed URLs, and the
	// urlintel additions, first-seen deduped. ---
	if len(r1.Domains) != 1 || r1.Domains[0].Name != "example.com" {
		t.Errorf("Domains = %+v, want [example.com]", r1.Domains)
	}
	if got := len(r1.Hosts); got != 3 {
		t.Errorf("Hosts = %d, want 3 (www/api/admin)", got)
	}
	urlSet := make(map[string]bool)
	for _, u := range r1.URLs {
		urlSet[u.Identity().String()] = true
	}
	for _, want := range []string{
		mustURL(t, "http://www.example.com/app.js").Identity().String(),
		mustURL(t, "http://api.example.com/lib.js?v=2").Identity().String(),
		mustURL(t, "http://www.example.com/graphql").Identity().String(),
	} {
		if !urlSet[want] {
			t.Errorf("URL corpus missing %s (got %d URLs)", want, len(r1.URLs))
		}
	}
	if len(r1.URLs) < 6 {
		t.Errorf("URLs = %d, want >= 6 (3 urlintel additions + the probed root URLs)", len(r1.URLs))
	}

	// --- Results channels, producer by producer. ---
	res := r1.Results
	if got := len(res.IPs); got != 3 {
		t.Errorf("IPs = %d, want 3 (one canonical A record per seeded host)", got)
	}
	if len(res.Ports) < 2 || len(res.Services) < 2 {
		t.Errorf("Ports/Services = %d/%d, want >= 2/2 (http/https observed on the probed hosts)",
			len(res.Ports), len(res.Services))
	}
	if len(res.Endpoints) < 3 {
		t.Errorf("Endpoints = %d, want >= 3 (probed roots + urlintel paths + jsintel REST endpoints)", len(res.Endpoints))
	}
	if got := len(res.TLSCertificates); got != 0 {
		t.Errorf("TLSCertificates = %d, want 0 (the canned transport performs no TLS handshake)", got)
	}
	if got := len(res.Parameters); got != 1 {
		t.Errorf("Parameters = %d, want 1 (the query parameter of lib.js?v=2)", got)
	} else if res.Parameters[0].Name != "v" {
		t.Errorf("Parameter = %+v, want name %q", res.Parameters[0], "v")
	}
	if len(res.Technologies) < 3 {
		t.Errorf("Technologies = %d, want >= 3 (graphql from techintel + react/webpack from jsintel)", len(res.Technologies))
	}
	if len(res.JavaScript) < 4 {
		t.Errorf("JavaScript = %d, want >= 4 (app.js, lib.js, shared.js, and the fetched root URLs)", len(res.JavaScript))
	}
	if len(res.SourceMaps) < 1 {
		t.Errorf("SourceMaps = %d, want >= 1 (app.js.map)", len(res.SourceMaps))
	}
	secretValues := make(map[string]bool)
	secretTypes := make(map[asset.SecretType]bool)
	for _, s := range res.Secrets {
		secretValues[s.Value] = true
		secretTypes[s.Type] = true
	}
	if !secretValues[awsKey(7)] {
		t.Errorf("Secrets missing value %q (got %d entries)", awsKey(7), len(res.Secrets))
	}
	// jsintel's Google candidate is retained at the engine's bounded
	// candidate value cap, so the exact string is engine-defined; the type
	// and the AWS value are the contract here.
	if len(res.Secrets) != 2 || !secretTypes[asset.SecretTypeGoogle] {
		t.Errorf("Secrets = %d entries / types %v, want 2 entries incl. the google candidate (aws key + google key)",
			len(res.Secrets), secretTypes)
	}
	if len(res.Evidence) < 1 {
		t.Errorf("Evidence = %d, want >= 1 (techintel/jsintel/secrentel all produce evidence)", len(res.Evidence))
	}
	if len(res.Relationships) < 1 {
		t.Errorf("Relationships = %d, want >= 1", len(res.Relationships))
	}
	if got := len(res.Findings); got != 1 {
		t.Fatalf("Findings = %d, want 1 (the technology-listing rule emitted one)", got)
	}
	if res.Findings[0].RuleID != "t3d.integration.tech-listing" {
		t.Errorf("finding RuleID = %q, want t3d.integration.tech-listing", res.Findings[0].RuleID)
	}
	if res.Findings[0].Subject.Kind != asset.KindTechnology {
		t.Errorf("finding subject = %s, want a technology identity from the snapshot", res.Findings[0].Subject)
	}
	if got := len(res.Surfaces); got != 16 {
		t.Errorf("Surfaces = %d, want 16 (1 domain + 3 hosts + 12 URLs — 9 urlintel + 3 jsintel feedback, one surface per completed asset)", got)
	}
	if got := len(res.Groups); got != 1 {
		t.Fatalf("Groups = %d, want 1 (every surface anchors at example.com)", got)
	}
	if got := res.Groups[0].Anchor.String(); got != "domain:example.com" {
		t.Errorf("group anchor = %s, want domain:example.com", got)
	}
	if got := len(res.Groups[0].Members); got != 16 {
		t.Errorf("group members = %d, want 16", got)
	}
	if got := len(res.AttackPaths); got != 1 {
		t.Fatalf("AttackPaths = %d, want 1 (the admin host is a factor-carrying group member)", got)
	}
	if got := res.AttackPaths[0].Root.String(); got != "domain:example.com" {
		t.Errorf("attack path root = %s, want domain:example.com", got)
	}

	// --- Documents: jsintel produced them, secrentel consumed them. The
	// retained app.js body carries the synthetic key. ---
	docByID := make(map[string]pipeline.Document)
	for _, d := range r1.Documents {
		docByID[d.Identity.String()] = d
	}
	appJS, err := asset.NewJavaScript("http://www.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	appDoc, ok := docByID[appJS.Identity().String()]
	if !ok {
		t.Fatalf("Documents missing the app.js document (got %d documents)", len(r1.Documents))
	}
	if appDoc.Truncated || !strings.Contains(string(appDoc.Content), awsKey(7)) {
		t.Errorf("app.js document: Truncated=%v, content carries the synthetic key = %v",
			appDoc.Truncated, strings.Contains(string(appDoc.Content), awsKey(7)))
	}
	if got := r1.Stages[6].ItemsProcessed; got != len(r1.Documents) {
		t.Errorf("secrentel ItemsProcessed = %d, want %d (every pipeline document scanned)", got, len(r1.Documents))
	}
	if got := r1.Stages[5].ItemsProcessed; got != len(r1.Documents) {
		t.Errorf("jsintel ItemsProcessed = %d, want %d (one processed entry per document)", got, len(r1.Documents))
	}

	// --- The report stage: the full Context reached the report model. ---
	if model == nil {
		t.Fatal("report model never captured")
	}
	if model.Target != "example.com" {
		t.Errorf("model.Target = %q, want example.com", model.Target)
	}
	if !model.StartedAt.Equal(fixedTime) || !model.EndedAt.Equal(fixedTime) {
		t.Errorf("model bracket = %v..%v, want %v..%v", model.StartedAt, model.EndedAt, fixedTime, fixedTime)
	}
	if len(model.Domains) != 1 || len(model.Hosts) != 3 || len(model.URLs) < 6 {
		t.Errorf("model corpus = %d domains / %d hosts / %d URLs, want 1/3/>=6",
			len(model.Domains), len(model.Hosts), len(model.URLs))
	}
	modelChannels := []struct {
		name  string
		count int
	}{
		{"IPs", len(model.IPs)}, {"Ports", len(model.Ports)}, {"Services", len(model.Services)},
		{"Endpoints", len(model.Endpoints)}, {"JavaScript", len(model.JavaScript)},
		{"Parameters", len(model.Parameters)}, {"Technologies", len(model.Technologies)},
		{"Secrets", len(model.Secrets)}, {"Evidence", len(model.Evidence)},
		{"Findings", len(model.Findings)}, {"SourceMaps", len(model.SourceMaps)},
		{"Relationships", len(model.Relationships)}, {"Surfaces", len(model.Surfaces)},
		{"Groups", len(model.Groups)}, {"AttackPaths", len(model.AttackPaths)},
	}
	for _, ch := range modelChannels {
		if ch.count < 1 {
			t.Errorf("model %s = %d, want >= 1 (the report Context carries the whole results channel)", ch.name, ch.count)
		}
	}
	if got := len(model.TLSCertificates); got != 0 {
		t.Errorf("model TLSCertificates = %d, want 0 (no TLS observations in the canned run)", got)
	}

	// --- Determinism: an identical second run DeepEquals the first. ---
	r2, err := pipeline.Run(context.Background(), cfg, nil, clk, stages(t.TempDir()))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("two identical runs differ:\nrun 1: %+v\nrun 2: %+v", r1, r2)
	}
}

// TestResultsGroupsFirstSeenPerAnchorCollapse pins FIND-2: the Groups and
// AttackPaths merge keys on the anchor/root only, so DISTINCT groups that
// share an anchor collapse to the FIRST stage's group — the retained group
// set never holds two groups for one anchor, and the later stage's group
// (and its members) never merge into the winner.
func TestResultsGroupsFirstSeenPerAnchorCollapse(t *testing.T) {
	anchor := mustHost(t, "api.example.com").Identity()
	member := priority.SurfaceAsset{Identity: mustHost(t, "a.api.example.com").Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}
	stage1 := &t3dFakeStage{name: pipeline.StageDNS, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Results: pipeline.Results{
			Groups: []priority.Group{{
				Anchor:  anchor,
				Members: []priority.SurfaceAsset{member},
				Score:   0.5,
				Level:   priority.LevelLow,
			}},
		},
	}}
	stage2 := &t3dFakeStage{name: pipeline.StageHTTPProbe, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Results: pipeline.Results{
			Groups: []priority.Group{{
				Anchor:  anchor,
				Members: []priority.SurfaceAsset{{Identity: mustHost(t, "b.api.example.com").Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}},
				Score:   0.9,
				Level:   priority.LevelHigh,
			}},
		},
	}}
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDNS, pipeline.StageHTTPProbe},
	}
	rep, err := pipeline.Run(context.Background(), cfg, nil, fixedClock{now: fixedTime},
		[]pipeline.Stage{stage1, stage2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", rep.Outcome)
	}
	if got := len(rep.Results.Groups); got != 1 {
		t.Fatalf("Groups = %d, want 1 (the second stage's group collapses onto the first-seen anchor)", got)
	}
	g := rep.Results.Groups[0]
	if g.Anchor.String() != anchor.String() || g.Score != 0.5 || g.Level != priority.LevelLow {
		t.Errorf("merged group = %+v, want the FIRST stage's group (anchor %s, score 0.5, level low)", g, anchor)
	}
	if got := len(g.Members); got != 1 {
		t.Fatalf("merged group members = %d, want 1 (the later group's members never merge in)", got)
	}
	if got := g.Members[0].Identity.String(); got != "host:a.api.example.com" {
		t.Errorf("merged group member = %s, want host:a.api.example.com (first-seen wins)", got)
	}

	// The same first-seen-per-root contract holds for AttackPaths.
	root := anchor
	stage1.res.Results.AttackPaths = []priority.AttackPath{{
		Root:  root,
		Score: 0.5,
		Level: priority.LevelLow,
	}}
	stage2.res.Results.AttackPaths = []priority.AttackPath{{
		Root:  root,
		Score: 0.9,
		Level: priority.LevelHigh,
	}}
	rep, err = pipeline.Run(context.Background(), cfg, nil, fixedClock{now: fixedTime},
		[]pipeline.Stage{stage1, stage2})
	if err != nil {
		t.Fatalf("Run (attack paths): %v", err)
	}
	if got := len(rep.Results.AttackPaths); got != 1 {
		t.Fatalf("AttackPaths = %d, want 1 (first-seen per root)", got)
	}
	p := rep.Results.AttackPaths[0]
	if p.Root.String() != root.String() || p.Score != 0.5 || p.Level != priority.LevelLow {
		t.Errorf("merged attack path = %+v, want the FIRST stage's path (root %s, score 0.5, level low)", p, root)
	}
}

// TestPriorityTruncationFlagSurvivesRunReport pins the §0.6 chain for the
// priority adapter's correlation cut end-to-end through the runner: the
// engine caches per-surface records only and the adapter re-derives the
// group set from the replayed surfaces on every path, so the cut
// re-computes deterministically and the completed-with-flag carve-out is
// legal — the priority_groups_truncated flag survives the stage result →
// StageRecord → RunReport chain and is never swallowed.
func TestPriorityTruncationFlagSurvivesRunReport(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	var hosts []asset.Host
	for i := 0; i < 1025; i++ {
		// Each host anchors at its own parent (x.pN.example.com →
		// pN.example.com): 1025 distinct anchors, one beyond the engine's
		// fixed maxCorrelationGroups = 1024.
		hosts = append(hosts, mustHost(t, fmt.Sprintf("x.p%d.example.com", i)))
	}
	seed := &t3dFakeStage{name: pipeline.StageDiscover, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{
			Hosts: hosts,
		},
	}}
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StagePriority},
	}
	rep, err := pipeline.Run(context.Background(), cfg, nil, fixedClock{now: fixedTime},
		[]pipeline.Stage{seed, NewPriorityStage(interesting, risk)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (every asset scored; only the group set was cut)", rep.Outcome)
	}
	if !rep.Truncated {
		t.Fatal("Truncated = false, want true (the correlation cut fired and must reach the RunReport)")
	}
	sr := rep.Stages[1]
	if sr.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("priority stage outcome = %q, want completed (the completed-with-flag carve-out, AGENTS §0.6)", sr.Outcome)
	}
	if !sr.StickyFlags[priorityGroupsTruncated] {
		t.Errorf("priority StageRecord StickyFlags = %v, want %s set", sr.StickyFlags, priorityGroupsTruncated)
	}
	if got := len(rep.Results.Surfaces); got != 1025 {
		t.Errorf("Surfaces = %d, want 1025 (the correlation cut never drops surfaces)", got)
	}
	if got := len(rep.Results.Groups); got != 1024 {
		t.Errorf("Groups = %d, want 1024 (the fixed group cap)", got)
	}
}
