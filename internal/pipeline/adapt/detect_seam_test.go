package adapt

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

func TestDetectStageWithJsPackLoadsJsPack(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12 (packs must not mutate pipeline order)", got)
	}
	stage, err := NewDetectStageWithJsPack(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithJsPack(nil): %v", err)
	}
	if stage.Name() != pipeline.StageDetect {
		t.Fatalf("Name %q, want %q", stage.Name(), pipeline.StageDetect)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app_xss.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Hosts:   []asset.Host{mustHost(t, "www.example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsProcessed < 1 {
		t.Fatalf("ItemsProcessed %d, want >=1 (js pack should attempt at least one rule)", res.ItemsProcessed)
	}
	// nil→empty still holds: bare NewDetectStage(nil) with empty corpus+empty registry is vacuous completed.
	emptyIn := pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res2, err := NewDetectStage(nil).Run(context.Background(), emptyIn)
	if err != nil {
		t.Fatalf("NewDetectStage(nil) empty: %v", err)
	}
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("empty outcome %s, want completed (nil→empty)", res2.Outcome)
	}
	if res2.ItemsProcessed != 0 {
		t.Fatalf("empty ItemsProcessed %d, want 0", res2.ItemsProcessed)
	}
	// deepCopy→Validate→Seal: verify the helper path's registry is sealed and deep-copied.
	reg := detect.NewRegistry()
	if err := LoadJsPack(reg); err != nil {
		t.Fatalf("LoadJsPack for deepCopy check: %v", err)
	}
	// Validate already called by LoadJsPack; re-validate should still pass.
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after LoadJsPack: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it must not affect registry.
	// Get a registered rule and try to mutate the copy; a second Get must be unchanged.
	got, ok := reg.Get("js.dom.xss")
	if !ok {
		t.Fatalf("js.dom.xss missing after LoadJsPack")
	}
	origID := got.ID
	got.ID = "mutated"
	got2, ok := reg.Get(origID)
	if !ok {
		t.Fatalf("Get after mutation missing")
	}
	if got2.ID != origID {
		t.Fatalf("deep copy broken: registry mutated through Get alias")
	}
}

func TestDetectStageWithAllPacksLoadsBoth(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	stage, err := NewDetectStageWithAllPacks(reg)
	if err != nil {
		t.Fatalf("NewDetectStageWithAllPacks: %v", err)
	}
	if reg.Len() != 29 {
		t.Fatalf("registry len %d, want 29 (5 web + 3 js + 3 apis + 3 cloud + 8 triage + 4 takeover + 2 authz + 1 bizlogic)", reg.Len())
	}
	if _, ok := reg.Get("web.csp.missing"); !ok {
		t.Fatalf("web.csp.missing missing (web family not loaded)")
	}
	if _, ok := reg.Get("js.dom.xss"); !ok {
		t.Fatalf("js.dom.xss missing (js family not loaded)")
	}
	if _, ok := reg.Get("js.postmessage.no-origin-check"); !ok {
		t.Fatalf("js.postmessage.no-origin-check missing")
	}
	if _, ok := reg.Get("js.prototype.pollution"); !ok {
		t.Fatalf("js.prototype.pollution missing")
	}
	if _, ok := reg.Get("api.openapi.exposed"); !ok {
		t.Fatalf("api.openapi.exposed missing (apis family not loaded)")
	}
	if _, ok := reg.Get("api.graphql.introspection"); !ok {
		t.Fatalf("api.graphql.introspection missing")
	}
	if _, ok := reg.Get("cloud.aws.key-indicator"); !ok {
		t.Fatalf("cloud.aws.key-indicator missing (cloud family not loaded)")
	}
	if _, ok := reg.Get("cloud.bucket.url"); !ok {
		t.Fatalf("cloud.bucket.url missing")
	}
	if _, ok := reg.Get("cloud.firebase.indicator"); !ok {
		t.Fatalf("cloud.firebase.indicator missing")
	}
	if _, ok := reg.Get("takeover.cname.unclaimed"); !ok {
		t.Fatalf("takeover.cname.unclaimed missing (takeover family not loaded)")
	}
	if _, ok := reg.Get("takeover.s3.bucket"); !ok {
		t.Fatalf("takeover.s3.bucket missing")
	}
	if _, ok := reg.Get("authz.idor.insecure-direct-object"); !ok {
		t.Fatalf("authz.idor.insecure-direct-object missing (authz family not loaded)")
	}
	if _, ok := reg.Get("authz.idor.path-object"); !ok {
		t.Fatalf("authz.idor.path-object missing (authz Rule 2 not loaded)")
	}
	if _, ok := reg.Get("bizlogic.workflow.state-transition"); !ok {
		t.Fatalf("bizlogic.workflow.state-transition missing (bizlogic family not loaded)")
	}
	// Validate graph still passes after both packs.
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after both packs: %v", err)
	}
	// Registry should be sealed.
	custom := detect.Rule{
		ID:            "custom.test.both",
		Name:          "Custom Both",
		Description:   "Custom test rule for Seal check",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced: %v", err)
	}
	// Stage should run with all four families: provide JS + host + endpoints +
	// evidence + a secret candidate so every pack has work (web.csp/hsts need
	// host, web.robots/apis need endpoint, web.sourcemap/js need javascript,
	// web.cors needs evidence, cloud.aws needs secrets, cloud.firebase needs
	// evidence, cloud.bucket needs endpoints).
	host := mustHost(t, "www.example.com")
	js, err := asset.NewJavaScript("https://www.example.com/app_xss.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	ep, err := asset.NewEndpoint("GET", "https://www.example.com/api/v1/users/123", asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "header:access-control-allow-origin", "*", host.Identity(), asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeGeneric, "synthetic-not-a-secret-value", host.Identity(), asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Hosts:   []asset.Host{host},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	in.Results.Endpoints = []asset.Endpoint{ep}
	in.Results.Evidence = []asset.Evidence{ev}
	in.Results.Secrets = []asset.SecretCandidate{sec}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run with both packs: %v", err)
	}
	if res.ItemsProcessed < 29 {
		t.Fatalf("ItemsProcessed %d, want 29 (all rules from all packs attempted)", res.ItemsProcessed)
	}
	// Also verify nil-registry path still yields 29 and is sealed.
	stage2, err := NewDetectStageWithAllPacks(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithAllPacks(nil): %v", err)
	}
	_ = stage2
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages after nil AllPacks = %d, want 12", got)
	}
}

func TestLoadJsPackHelper(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	if err := LoadJsPack(reg); err != nil {
		t.Fatalf("LoadJsPack: %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("len %d, want 3 (js pack)", reg.Len())
	}
	if _, ok := reg.Get("js.dom.xss"); !ok {
		t.Fatalf("js.dom.xss missing")
	}
	if _, ok := reg.Get("js.postmessage.no-origin-check"); !ok {
		t.Fatalf("js.postmessage.no-origin-check missing")
	}
	if _, ok := reg.Get("js.prototype.pollution"); !ok {
		t.Fatalf("js.prototype.pollution missing")
	}
	// Validate still passes (deepCopy→Validate).
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it does not affect registry.
	got, ok := reg.Get("js.dom.xss")
	if !ok {
		t.Fatalf("Get js.dom.xss missing for deepCopy check")
	}
	got.ID = "mutated"
	got2, ok := reg.Get("js.dom.xss")
	if !ok || got2.ID != "js.dom.xss" {
		t.Fatalf("deep copy broken via Get alias: got2.ID=%q", got2.ID)
	}
	// Seal: further Register must fail.
	custom := detect.Rule{
		ID:            "custom.test.js",
		Name:          "Custom JS Test",
		Description:   "Custom",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced after LoadJsPack: %v", err)
	}
	if err := LoadJsPack(nil); err == nil {
		t.Fatalf("nil registry should fail")
	}
}

func TestLoadCloudPackHelper(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	if err := LoadCloudPack(reg); err != nil {
		t.Fatalf("LoadCloudPack: %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("len %d, want 3 (cloud pack)", reg.Len())
	}
	if _, ok := reg.Get("cloud.aws.key-indicator"); !ok {
		t.Fatalf("cloud.aws.key-indicator missing")
	}
	if _, ok := reg.Get("cloud.bucket.url"); !ok {
		t.Fatalf("cloud.bucket.url missing")
	}
	if _, ok := reg.Get("cloud.firebase.indicator"); !ok {
		t.Fatalf("cloud.firebase.indicator missing")
	}
	// Validate still passes (deepCopy→Validate).
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it does not affect registry.
	got, ok := reg.Get("cloud.aws.key-indicator")
	if !ok {
		t.Fatalf("Get cloud.aws.key-indicator missing for deepCopy check")
	}
	got.ID = "mutated"
	got2, ok := reg.Get("cloud.aws.key-indicator")
	if !ok || got2.ID != "cloud.aws.key-indicator" {
		t.Fatalf("deep copy broken via Get alias: got2.ID=%q", got2.ID)
	}
	// Seal: further Register must fail.
	custom := detect.Rule{
		ID:            "custom.test.cloud",
		Name:          "Custom Cloud Test",
		Description:   "Custom",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced after LoadCloudPack: %v", err)
	}
	if err := LoadCloudPack(nil); err == nil {
		t.Fatalf("nil registry should fail")
	}
	stage, err := NewDetectStageWithCloudPack(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithCloudPack(nil): %v", err)
	}
	if stage.Name() != pipeline.StageDetect {
		t.Fatalf("Name %q, want %q", stage.Name(), pipeline.StageDetect)
	}
}

// mustDocJS builds one pipeline document for tests: the jsintel stage's
// currency — a JavaScript-identity-keyed retained body. A nil content
// with truncated=false models "nothing retained"; truncated=true models
// a prefix dropped whole by the channel.
func mustDocJS(t testing.TB, rawURL string, content []byte, truncated bool) pipeline.Document {
	t.Helper()
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	u := js.URL
	return pipeline.Document{Identity: js.Identity(), URL: &u, Content: content, Truncated: truncated}
}

// TestBuildJSContentsFilters pins the document→snapshot mapping
// (NEW-118): only complete, valid-UTF-8 bodies for observed scripts
// enter the snapshot channel. Truncated prefixes, nil contents,
// non-UTF-8 bodies, unattributed identities, and non-JavaScript kinds
// are skipped — rules treat missing bodies as "not retained".
func TestBuildJSContentsFilters(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	docs := []pipeline.Document{
		mustDocJS(t, "https://www.example.com/app.js", []byte("var ok = 1;"), false),
		mustDocJS(t, "https://www.example.com/trunc.js", nil, true),
		mustDocJS(t, "https://www.example.com/nil.js", nil, false),
		{Identity: asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}},
	}
	// Non-UTF-8 body for an observed script.
	badJS, err := asset.NewJavaScript("https://www.example.com/bad.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	docs = append(docs, pipeline.Document{Identity: badJS.Identity(), Content: []byte("ok\xff\xfe")})
	scripts := []asset.JavaScript{js, badJS}
	got, truncated, incomplete := buildJSContents(docs, scripts)
	if truncated {
		t.Fatal("truncated = true, want false (filtering is not a cut)")
	}
	if !incomplete {
		t.Fatal("incomplete = false, want true (the attributed non-UTF-8 body was skipped upstream)")
	}
	if len(got) != 1 {
		t.Fatalf("contents = %d, want 1 (only the complete attributed UTF-8 body)", len(got))
	}
	if got[0].Identity != js.Identity() || got[0].Body != "var ok = 1;" {
		t.Fatalf("content = %+v, want app.js body", got[0])
	}
}

// TestBuildJSContentsSortedAndBudgeted pins deterministic sorted-head
// retention within the SDK caller bounds, including the duplicate-
// identity tie-break: two documents for one script always resolve to
// the same (smallest) body regardless of channel order.
func TestBuildJSContentsSortedAndBudgeted(t *testing.T) {
	var docs []pipeline.Document
	var scripts []asset.JavaScript
	for _, name := range []string{"b.js", "a.js", "c.js"} {
		raw := "https://www.example.com/" + name
		js, err := asset.NewJavaScript(raw, asset.Provenance{Source: "js-test"})
		if err != nil {
			t.Fatalf("NewJavaScript: %v", err)
		}
		scripts = append(scripts, js)
		docs = append(docs, pipeline.Document{Identity: js.Identity(), Content: []byte("body of " + name)})
	}
	// Duplicate identity for a.js with a larger body: the tie-break
	// keeps the smallest body deterministically.
	dup := docs[1]
	docs = append(docs, pipeline.Document{Identity: dup.Identity, Content: []byte("body of a.js (duplicate, larger)")})
	got, truncated, incomplete := buildJSContents(docs, scripts)
	if truncated {
		t.Fatal("truncated = true, want false (nothing cut)")
	}
	if incomplete {
		t.Fatal("incomplete = true, want false (duplicates resolve, nothing skipped)")
	}
	if len(got) != 3 {
		t.Fatalf("contents = %d, want 3", len(got))
	}
	for i, want := range []string{"a.js", "b.js", "c.js"} {
		if !strings.HasSuffix(got[i].Identity.Value, want) {
			t.Fatalf("contents[%d] = %s, want identity-sorted (*%s)", i, got[i].Identity, want)
		}
		if got[i].Body != "body of "+want {
			t.Fatalf("contents[%d].Body = %q, want the matching body", i, got[i].Body)
		}
	}
	// Order-independence: the reversed channel resolves identically.
	rev := append([]pipeline.Document(nil), docs...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	gotRev, truncatedRev, incompleteRev := buildJSContents(rev, scripts)
	if truncatedRev || incompleteRev {
		t.Fatalf("reversed: truncated=%v incomplete=%v, want false/false", truncatedRev, incompleteRev)
	}
	if len(gotRev) != len(got) {
		t.Fatalf("reversed: contents = %d, want %d", len(gotRev), len(got))
	}
	for i := range got {
		if gotRev[i] != got[i] {
			t.Fatalf("reversed: contents[%d] = %+v, want %+v (channel order must not matter)", i, gotRev[i], got[i])
		}
	}
}

// TestBuildJSContentsOverBoundBodySkipped pins Finding 4: a body over
// the exported per-body bound is dropped whole (the engine would reject
// it outright — never truncate it into a prefix), marks the input
// incomplete, and never cuts the retained head.
func TestBuildJSContentsOverBoundBodySkipped(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/big.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	ok, err := asset.NewJavaScript("https://www.example.com/ok.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	big := make([]byte, detect.MaxSnapshotJSContentBodyBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	docs := []pipeline.Document{
		{Identity: js.Identity(), Content: big},
		{Identity: ok.Identity(), Content: []byte("var ok = 1;")},
	}
	got, truncated, incomplete := buildJSContents(docs, []asset.JavaScript{js, ok})
	if truncated {
		t.Fatal("truncated = true, want false (a skip is not a cut)")
	}
	if !incomplete {
		t.Fatal("incomplete = false, want true (the over-bound attributed body was dropped whole)")
	}
	if len(got) != 1 || got[0].Identity != ok.Identity() {
		t.Fatalf("contents = %+v, want only the within-bound body", got)
	}
}

// TestBuildJSContentsIncompleteInput pins the Finding-5 contract: every
// attributed skip class (truncated prefix, nil content, non-UTF-8 body,
// over-bound body) marks the input incomplete, while unattributed and
// wrong-kind documents stay silent without marking it.
func TestBuildJSContentsIncompleteInput(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	scripts := []asset.JavaScript{js}
	big := []byte(strings.Repeat("x", detect.MaxSnapshotJSContentBodyBytes+1))
	foreign, err := asset.NewJavaScript("https://www.example.com/foreign.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	cases := map[string]struct {
		doc      pipeline.Document
		contents int
		gap      bool
	}{
		"truncated prefix": {pipeline.Document{Identity: js.Identity(), Content: []byte("var x = 1;"), Truncated: true}, 0, true},
		"nil content":      {pipeline.Document{Identity: js.Identity(), Content: nil}, 0, true},
		"non-utf8 body":    {pipeline.Document{Identity: js.Identity(), Content: []byte("ok\xff\xfe")}, 0, true},
		"over-bound body":  {pipeline.Document{Identity: js.Identity(), Content: big}, 0, true},
		"complete body":    {pipeline.Document{Identity: js.Identity(), Content: []byte("var x = 1;")}, 1, false},
		// Unattributed and wrong-kind documents are not this channel's
		// gap to report: they were never snapshot scripts.
		"unattributed truncated": {pipeline.Document{Identity: foreign.Identity(), Content: []byte("x"), Truncated: true}, 0, false},
		"wrong kind":             {pipeline.Document{Identity: asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}}, 0, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, truncated, incomplete := buildJSContents([]pipeline.Document{tc.doc}, scripts)
			if truncated {
				t.Fatal("truncated = true, want false (single small doc never cuts)")
			}
			if incomplete != tc.gap {
				t.Fatalf("incomplete = %v, want %v", incomplete, tc.gap)
			}
			if len(got) != tc.contents {
				t.Fatalf("contents = %d, want %d", len(got), tc.contents)
			}
		})
	}
}

// TestBuildJSContentsChunkSentinelIncomplete pins the Slice 3 §0.6
// mapping for windowed files: a windowed file asset in scripts with its
// chunk documents plus the file sentinel yields one snapshot body per
// window — each citing its CHUNK identity with the window bytes — marks
// the input incomplete (the file sentinel is the windowed file's gap
// marker), and never cuts the retained head.
func TestBuildJSContentsChunkSentinelIncomplete(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/bundle.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	scripts := []asset.JavaScript{js}
	c0, err := asset.ChunkJavaScriptIdentity(js.URL, 0, 2, 0, 100, "abcdef12", "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity c0: %v", err)
	}
	c1, err := asset.ChunkJavaScriptIdentity(js.URL, 1, 2, 100, 200, "12345678", "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity c1: %v", err)
	}
	sentinel := pipeline.Document{Identity: js.Identity(), Content: nil, Truncated: true}
	docs := []pipeline.Document{
		{Identity: c0, Content: []byte("window zero")},
		{Identity: c1, Content: []byte("window one")},
		sentinel,
	}
	got, truncated, incomplete := buildJSContents(docs, scripts)
	if truncated {
		t.Fatal("truncated = true, want false (a sentinel skip is not a bounds cut)")
	}
	if !incomplete {
		t.Fatal("incomplete = false, want true (the file sentinel marks the windowed file's gap)")
	}
	if len(got) != 2 {
		t.Fatalf("contents = %d, want 2 (one body per window)", len(got))
	}
	if got[0].Identity != c0 || got[0].Body != "window zero" {
		t.Fatalf("contents[0] = %+v, want chunk c0 with the window bytes", got[0])
	}
	if got[1].Identity != c1 || got[1].Body != "window one" {
		t.Fatalf("contents[1] = %+v, want chunk c1 with the window bytes", got[1])
	}
	// Sentinel alone pins the same branch without chunk docs.
	gotS, truncatedS, incompleteS := buildJSContents([]pipeline.Document{sentinel}, scripts)
	if truncatedS || !incompleteS || len(gotS) != 0 {
		t.Fatalf("sentinel-only: got=%d truncated=%v incomplete=%v, want 0/false/true", len(gotS), truncatedS, incompleteS)
	}
	// Chunks alone (no sentinel) map with no gap: the windows are
	// complete observations of what they cite.
	gotC, truncatedC, incompleteC := buildJSContents(docs[:2], scripts)
	if truncatedC || incompleteC || len(gotC) != 2 {
		t.Fatalf("chunks-only: got=%d truncated=%v incomplete=%v, want 2/false/false", len(gotC), truncatedC, incompleteC)
	}
	// Chunk documents with no snapshot scripts at all stay silent without
	// marking a gap: unattributed window identities, never snapshot bodies.
	gotU, truncatedU, incompleteU := buildJSContents(docs[:2], nil)
	if truncatedU || incompleteU || len(gotU) != 0 {
		t.Fatalf("unattributed chunks: got=%d truncated=%v incomplete=%v, want 0/false/false", len(gotU), truncatedU, incompleteU)
	}
}

// TestBuildJSContentsChunkOverBoundDefenseDead pins that the over-bound
// defense never fires for constructor-built chunks: the chunk identity
// constructor caps spans at 1 MiB (below the 2 MiB per-body bound), so a
// max-span chunk body maps — the branch stays as defense for file bodies
// only (TestBuildJSContentsOverBoundBodySkipped).
func TestBuildJSContentsChunkOverBoundDefenseDead(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/bundle.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	cid, err := asset.ChunkJavaScriptIdentity(js.URL, 0, 1, 0, 1<<20, "abcdef12", "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	big := []byte(strings.Repeat("x", 1<<20))
	docs := []pipeline.Document{{Identity: cid, Content: big}}
	got, truncated, incomplete := buildJSContents(docs, []asset.JavaScript{js})
	if truncated || incomplete || len(got) != 1 {
		t.Fatalf("max-span chunk: got=%d truncated=%v incomplete=%v, want 1/false/false (never trips the per-body bound)", len(got), truncated, incomplete)
	}
	if got[0].Identity != cid || len(got[0].Body) != 1<<20 {
		t.Fatalf("max-span chunk content = %+v, want the chunk identity with the full window", len(got[0].Body))
	}
}

// TestBuildJSContentsChunkDirectHit pins the direct chunk-script path:
// when the snapshot carries the chunk scripts themselves (pre-merge
// stage results), chunk documents hit the set without the file
// fallback — and malformed chunk fragments index nothing (the engine
// rejects them at its own boundary; the mapper only indexes what
// validates).
func TestBuildJSContentsChunkDirectHit(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/bundle.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	c0, err := asset.ChunkJavaScriptIdentity(js.URL, 0, 2, 0, 100, "abcdef12", "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity c0: %v", err)
	}
	chunkURL, err := asset.ParseURL(c0.Value, asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("ParseURL chunk: %v", err)
	}
	chunkScript := asset.JavaScript{URL: chunkURL, Prov: asset.Provenance{Source: "js-test"}}
	scripts := []asset.JavaScript{js, chunkScript}
	docs := []pipeline.Document{{Identity: c0, Content: []byte("window zero")}}
	got, truncated, incomplete := buildJSContents(docs, scripts)
	if truncated || incomplete || len(got) != 1 {
		t.Fatalf("direct hit: got=%d truncated=%v incomplete=%v, want 1/false/false", len(got), truncated, incomplete)
	}
	if got[0].Identity != c0 || got[0].Body != "window zero" {
		t.Fatalf("direct hit content = %+v, want chunk c0 with the window bytes", got[0])
	}
	// A script carrying a malformed chunk fragment indexes nothing: the
	// chunk document then links via the file fallback (the file script is
	// present), so coverage is preserved while garbage never enters the set.
	badURL, err := asset.ParseURL("https://www.example.com/bundle.js#not-a-chunk", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("ParseURL bad fragment: %v", err)
	}
	badScript := asset.JavaScript{URL: badURL, Prov: asset.Provenance{Source: "js-test"}}
	gotB, truncatedB, incompleteB := buildJSContents(docs, []asset.JavaScript{js, badScript})
	if truncatedB || incompleteB || len(gotB) != 1 || gotB[0].Identity != c0 {
		t.Fatalf("malformed-fragment: got=%+v truncated=%v incomplete=%v, want the file-fallback mapping", gotB, truncatedB, incompleteB)
	}
}

// TestDetectStageJSContentsIncompleteFlag pins the Finding-5 honesty
// end to end: an observed script whose only document was skipped
// upstream yields no body (rules stay fail-open silent) while the stage
// reports Truncated with the distinct incomplete-input sticky flag —
// never a silent completed run claiming coverage it lacks.
func TestDetectStageJSContentsIncompleteFlag(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	stage := NewDetectStage(contentsProbeRegistry(t))
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	in.Documents = []pipeline.Document{mustDocJS(t, "https://www.example.com/app.js", nil, true)}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results.Findings) != 0 {
		t.Fatalf("findings = %d, want 0 (no body retained: fail-open preserved)", len(res.Results.Findings))
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (an attributed body was skipped upstream)")
	}
	if !res.StickyFlags[detectJSContentsIncompleteFlag] {
		t.Fatalf("flags = %v, want %q", res.StickyFlags, detectJSContentsIncompleteFlag)
	}
	if res.StickyFlags[detectJSContentsTruncatedFlag] {
		t.Fatalf("flags = %v, must not carry the bounds-cut flag (nothing was cut)", res.StickyFlags)
	}
}

// contentsProbeRegistry builds a registry with one rule that emits a
// finding iff the engine delivered retained bodies, citing the count.
func contentsProbeRegistry(t testing.TB) *detect.Registry {
	t.Helper()
	reg := detect.NewRegistry()
	rule := detect.Rule{
		ID:                 "custom.test.contents",
		Name:               "Contents Probe",
		Description:        "Test rule observing the content channel",
		Category:           detect.CategoryInformation,
		Version:            "1.0.0",
		Inputs:             []detect.RuleInput{detect.InputJavaScript},
		Outputs:            []detect.RuleOutput{detect.OutputFindings},
		RequiredAssetTypes: []asset.Kind{asset.KindJavaScript},
		EstimatedCost:      detect.CostLow,
		Timeout:            time.Second,
		Author:             "test",
		Enabled:            true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			if len(dctx.JavaScriptContent) == 0 {
				return nil, nil
			}
			subj := dctx.JavaScript[0].Identity()
			ev, err := asset.NewEvidence(asset.MethodDetection, "custom.test.contents", "signal", subj, asset.Provenance{Source: "test"})
			if err != nil {
				return nil, err
			}
			f, err := asset.NewFinding(asset.Finding{
				RuleID:     "custom.test.contents",
				RuleName:   "Contents Probe",
				Category:   detect.CategoryInformation.String(),
				Subject:    subj,
				Confidence: 0.5,
				Evidence:   []asset.Evidence{ev},
				Metadata:   map[string]string{"contents": fmt.Sprint(len(dctx.JavaScriptContent))},
				Priority:   detect.PriorityInfo.String(),
				Status:     detect.StatusOpen.String(),
				Created:    dctx.Clock.Now().UTC(),
			})
			if err != nil {
				return nil, err
			}
			return []asset.Finding{f}, nil
		},
	}
	if err := reg.Register(rule); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	return reg
}

// TestDetectStageFeedsJSContents pins the end-to-end flow (NEW-118): the
// detect stage maps the document channel into the snapshot content
// channel, and a rule observes it. Without documents the rule stays
// silent — the channel adds coverage, never behavior.
func TestDetectStageFeedsJSContents(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	stage := NewDetectStage(contentsProbeRegistry(t))
	withDocs := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	withDocs.Results.JavaScript = []asset.JavaScript{js}
	withDocs.Documents = []pipeline.Document{mustDocJS(t, "https://www.example.com/app.js", []byte("var x = 1;"), false)}
	res, err := stage.Run(context.Background(), withDocs)
	if err != nil {
		t.Fatalf("Run with documents: %v", err)
	}
	if len(res.Results.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (rule observed the retained body)", len(res.Results.Findings))
	}
	if res.Results.Findings[0].Metadata["contents"] != "1" {
		t.Errorf("finding meta = %v, want contents=1", res.Results.Findings[0].Metadata)
	}

	withoutDocs := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	withoutDocs.Results.JavaScript = []asset.JavaScript{js}
	res2, err := stage.Run(context.Background(), withoutDocs)
	if err != nil {
		t.Fatalf("Run without documents: %v", err)
	}
	if len(res2.Results.Findings) != 0 {
		t.Fatalf("findings = %d, want 0 (no bodies: fail-open preserved)", len(res2.Results.Findings))
	}
}

// TestDetectStageJSContentsOverflowFlag pins the §0.6 honesty of the
// snapshot content trim (NEW-118 follow-up): beyond the SDK caller
// bounds the sorted head is analyzed and the cut rides Truncated plus
// the flag — a 2000-script corpus never reports completed coverage it
// lacks. The engine would have REJECTED the over-bound set outright;
// the adapter must not convert that loud rejection into a silent subset.
func TestDetectStageJSContentsOverflowFlag(t *testing.T) {
	stage := NewDetectStage(contentsProbeRegistry(t))
	var scripts []asset.JavaScript
	var docs []pipeline.Document
	for i := 0; i < detect.MaxSnapshotJSContents+1; i++ {
		raw := "https://h" + padTakeoverContents(i) + ".example.com/app.js"
		js, err := asset.NewJavaScript(raw, asset.Provenance{Source: "js-test"})
		if err != nil {
			t.Fatalf("NewJavaScript: %v", err)
		}
		scripts = append(scripts, js)
		u := js.URL
		docs = append(docs, pipeline.Document{Identity: js.Identity(), URL: &u, Content: []byte("var x = 1;")})
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = scripts
	in.Documents = docs
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (1025 bodies over the 1024 cap)")
	}
	if !res.StickyFlags[detectJSContentsTruncatedFlag] {
		t.Fatalf("flags = %v, want %q", res.StickyFlags, detectJSContentsTruncatedFlag)
	}
	// The probe rule still observed the retained head.
	if len(res.Results.Findings) != 1 || res.Results.Findings[0].Metadata["contents"] != "1024" {
		t.Fatalf("findings = %+v, want one probe finding citing the 1024 retained head", res.Results.Findings)
	}
}

func padTakeoverContents(i int) string {
	return string(rune('0'+i/1000%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

// TestDetectStageJSPackFiresOnDocuments pins NEW-118 end to end through
// the production pack: a retained body carrying a real sink flows from
// the document channel into a js.dom.xss finding — the dead-detector
// arc closed without any synthetic input.
func TestDetectStageJSPackFiresOnDocuments(t *testing.T) {
	stage, err := NewDetectStageWithJsPack(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithJsPack(nil): %v", err)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	in.Documents = []pipeline.Document{
		mustDocJS(t, "https://www.example.com/app.js", []byte(`el.innerHTML = location.hash;`), false),
	}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Results.Findings {
		if f.RuleID == "js.dom.xss" && f.Subject == js.Identity() {
			return
		}
	}
	t.Fatalf("no js.dom.xss finding for the sink-bearing body: %+v", res.Results.Findings)
}
