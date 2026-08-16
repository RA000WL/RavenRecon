package priority

import (
	"math"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestLoadProductionCatalogs(t *testing.T) {
	ic, err := LoadInterestingness()
	if err != nil {
		t.Fatalf("LoadInterestingness: %v", err)
	}
	rc, err := LoadRisk()
	if err != nil {
		t.Fatalf("LoadRisk: %v", err)
	}
	if ic.SchemaVersion() != SchemaVersion || rc.SchemaVersion() != SchemaVersion {
		t.Error("schema version mismatch")
	}
	if ic.Name() != "interestingness" || rc.Name() != "risk" {
		t.Errorf("catalog names = %q/%q", ic.Name(), rc.Name())
	}
	if ic.Len() != 40 {
		t.Errorf("interestingness catalog has %d entries; want exactly 40", ic.Len())
	}
	if rc.Len() != 13 {
		t.Errorf("risk catalog has %d entries; want exactly 13", rc.Len())
	}

	for _, c := range []*Catalog{ic, rc} {
		seen := map[string]bool{}
		entries := c.Entries()
		for i, e := range entries {
			if e.ID == "" || seen[e.ID] {
				t.Fatalf("empty or duplicate ID %q", e.ID)
			}
			seen[e.ID] = true
			if i > 0 && entries[i-1].ID >= e.ID {
				t.Errorf("catalog %q not sorted by ID: %q >= %q", c.Name(), entries[i-1].ID, e.ID)
			}
			if e.Weight <= 0 || e.Weight > 1 {
				t.Errorf("entry %q weight %v out of (0,1]", e.ID, e.Weight)
			}
			if !e.Field.Valid() {
				t.Errorf("entry %q invalid field %q", e.ID, e.Field)
			}
			if e.Regex != "" && e.MatchRe() == nil {
				t.Errorf("entry %q regex not compiled", e.ID)
			}
		}

		// Fresh copies: mutating the returned slice never affects the catalog.
		mut := c.Entries()
		for i := range mut {
			mut[i].ID = "tampered"
		}
		if c.Entries()[0].ID == "tampered" {
			t.Errorf("catalog %q Entries must return a fresh copy", c.Name())
		}
	}

	// Compile-once: accessors share one regex instance.
	e1, _ := ic.ByID("staging-path")
	e2, ok := ic.ByID("staging-path")
	if !ok || e1.MatchRe() == nil {
		t.Fatal("staging-path regex missing")
	}
	if e1.MatchRe() != e2.MatchRe() {
		t.Error("compiled regexes must be shared (compile-once)")
	}
	if _, ok := ic.ByID("no-such-entry"); ok {
		t.Error("unknown ID must not resolve")
	}
}

func TestSpecFamiliesRepresented(t *testing.T) {
	// Every indicator family from the spec, asserted through a
	// representative signal that must produce a factor in the right
	// category.
	cases := []struct {
		name     string
		signal   Signal
		wantName string // factor name prefix (group:category)
	}{
		{"admin", Signal{Path: "/admin/login"}, "interestingness:admin"},
		{"internal", Signal{Path: "/_internal/api"}, "interestingness:internal"},
		{"debug", Signal{Path: "/debug/vars"}, "interestingness:debug"},
		{"graphql", Signal{Path: "/api/graphql"}, "interestingness:graphql"},
		{"api", Signal{Path: "/api/users"}, "interestingness:api"},
		{"versioned api", Signal{Path: "/api/v2/orders"}, "interestingness:versioned_api"},
		{"swagger", Signal{Path: "/swagger-ui/index.html"}, "interestingness:api_docs"},
		{"openapi", Signal{Path: "/openapi.json"}, "interestingness:api_docs"},
		{"well-known", Signal{Path: "/.well-known/security.txt"}, "interestingness:well_known"},
		{"staging", Signal{Path: "/staging/app.js"}, "interestingness:staging"},
		{"dev", Signal{Path: "/dev/portal"}, "interestingness:dev"},
		{"test", Signal{Path: "/sandbox/env"}, "interestingness:test"},
		{"actuator", Signal{Path: "/actuator/health"}, "interestingness:actuator"},
		{"metrics", Signal{Path: "/_metrics"}, "interestingness:metrics"},
		{"kibana", Signal{Path: "/app/kibana"}, "interestingness:kibana"},
		{"jenkins", Signal{Path: "/jenkins/job/build"}, "interestingness:jenkins"},
		{"prometheus", Signal{Path: "/prometheus/graph"}, "interestingness:prometheus"},
		{"source map path", Signal{Path: "/static/app.js.map"}, "interestingness:source_map"},
		{"source map kind", Signal{Kind: "source_map", Path: "/x"}, "interestingness:source_map"},
		{"large js bundle", Signal{Kind: "javascript", JSBundleBytes: 1 << 21}, "interestingness:large_js_bundle"},
		{"build manifest", Signal{Path: "/static/js/runtime-main.chunk.js"}, "interestingness:build_manifest"},
		{"webpack", Signal{Path: "/assets/webpack.bundle.js"}, "interestingness:build_manifest"},
		{"auth page", Signal{Path: "/users/sso/login"}, "interestingness:authentication"},
		{"auth tech name", Signal{Technologies: []TechSignal{{Name: "auth0", Category: "authentication", Confidence: 0.9}}}, "interestingness:authentication"},
		{"upload path", Signal{Path: "/upload/avatars"}, "interestingness:upload"},
		{"upload param", Signal{ParameterNames: []string{"attachment"}}, "interestingness:upload"},
		{"file management", Signal{Path: "/files/download"}, "interestingness:file_management"},
		{"search", Signal{Path: "/search"}, "interestingness:search"},
		{"search param", Signal{ParameterNames: []string{"query"}}, "interestingness:search"},
		{"messaging path", Signal{Path: "/ws/chat"}, "interestingness:messaging"},
		{"websocket endpoint", Signal{EndpointMethod: "WS"}, "interestingness:messaging"},
		{"payment", Signal{Path: "/checkout/payment"}, "interestingness:payment"},
		{"payment tech", Signal{Technologies: []TechSignal{{Name: "stripe", Category: "payment", Confidence: 0.8}}}, "interestingness:payment"},
		{"account", Signal{Path: "/user/settings"}, "interestingness:account"},
		{"admin panel", Signal{Path: "/dashboard/console"}, "interestingness:admin_panel"},
		{"devtools", Signal{Path: "/graphiql"}, "interestingness:developer_tools"},

		{"high-value secret", Signal{Secrets: []SecretSignal{{Type: "aws", Confidence: 0.9}}}, "risk:high_value_secret"},
		{"privileged auth tech", Signal{Technologies: []TechSignal{{Name: "okta", Category: "authentication", Confidence: 0.9}}}, "risk:privileged_auth_tech"},
		{"cloud tech", Signal{Technologies: []TechSignal{{Name: "aws", Category: "cloud_provider", Confidence: 0.9}}}, "risk:cloud_infrastructure"},
		{"internal host label", Signal{Hostname: "api.internal.example.com"}, "risk:internal_exposure"},
		{"private address", Signal{Hostname: "10.0.4.12"}, "risk:internal_exposure"},
		{"private address 172", Signal{Hostname: "172.20.1.5"}, "risk:internal_exposure"},
		{"management port", Signal{Port: 9090}, "risk:management_interface"},
		{"management service", Signal{Service: "grafana"}, "risk:management_interface"},
		{"feature flag", Signal{ParameterNames: []string{"feature_flag"}}, "risk:feature_flag"},
		{"legacy api", Signal{Path: "/api/beta/export"}, "risk:legacy_api"},
		{"developer tooling risk", Signal{Path: "/swagger-ui"}, "risk:developer_tooling"},
		{"disclosure header", Signal{Headers: []string{"X-Powered-By: Express"}, Path: "/"}, "risk:disclosure_header"},
	}
	ic, rc := mustCatalogs(t)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sig := tt.signal
			sig.Identity = testIdentity()
			if sig.Kind == "" {
				sig.Kind = "url"
			}
			out, err := ScoreSurface(sig, ic, rc)
			if err != nil {
				t.Fatalf("ScoreSurface: %v", err)
			}
			for _, f := range out.Factors {
				if strings.HasPrefix(f.Name, tt.wantName) {
					return
				}
			}
			t.Errorf("no %q factor; got %v", tt.wantName, factorNames(out))
		})
	}
}

func TestBoundaryRegexesDoNotOvermatch(t *testing.T) {
	ic, rc := mustCatalogs(t)
	for _, path := range []string{"/devices", "/testimonials", "/stagger/config"} {
		sig := Signal{Identity: testIdentity(), Kind: "url", Path: path}
		out, err := ScoreSurface(sig, ic, rc)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range out.Factors {
			for _, banned := range []string{"interestingness:dev", "interestingness:test", "interestingness:staging"} {
				if strings.HasPrefix(f.Name, banned) {
					t.Errorf("path %q falsely matched %s", path, f.Name)
				}
			}
		}
	}
}

// TestRenderedBoundAtMaximum is the Round-2 gate's compile-time
// rendered-reason bound regression: a MAXIMUM-size template (exactly
// bound − maxTermBytes + len("%s") bytes) combined with a MAXIMUM-length
// term (exactly maxTermBytes) compiles, and its rendered reason and
// recommendation land exactly ON the bound — never over it. One template
// byte more fails the load, so no catalog edit can smuggle an over-bound
// rendered text past validation.
func TestRenderedBoundAtMaximum(t *testing.T) {
	pad := func(n int) string { return strings.Repeat("x", n) }
	maxTerm := pad(maxTermBytes)
	// A template of exactly bound − maxTermBytes + len("%s") bytes carrying
	// one %s seam: its worst-case render is exactly the bound.
	maxReasonTmpl := "%s " + pad(maxIndicatorReasonBytes-maxTermBytes+2-3)
	maxRecTmpl := "%s " + pad(maxIndicatorRecommendationBytes-maxTermBytes+2-3)

	base := Indicator{
		ID: "max-template", Category: "max", Weight: 0.5, Field: FieldPath,
	}
	term := base
	term.Terms = []string{maxTerm}
	term.Reason = maxReasonTmpl
	term.Recommendation = maxRecTmpl
	if _, err := CompileForTest("test", []Indicator{term}); err != nil {
		t.Fatalf("maximum template with maximum term must compile: %v", err)
	}
	if got := len(term.Reason) - 2 + len(maxTerm); got != maxIndicatorReasonBytes {
		t.Fatalf("test construction error: worst-case rendered reason is %d, want exactly %d", got, maxIndicatorReasonBytes)
	}
	renderedReason := strings.Replace(term.Reason, "%s", maxTerm, 1)
	if len(renderedReason) != maxIndicatorReasonBytes {
		t.Errorf("rendered reason = %d bytes, want exactly the bound %d", len(renderedReason), maxIndicatorReasonBytes)
	}
	if len(renderedReason) > maxReasonBytes {
		t.Errorf("rendered reason %d exceeds the factor-side bound %d", len(renderedReason), maxReasonBytes)
	}
	renderedRec := strings.Replace(term.Recommendation, "%s", maxTerm, 1)
	if len(renderedRec) != maxIndicatorRecommendationBytes {
		t.Errorf("rendered recommendation = %d bytes, want exactly the bound %d", len(renderedRec), maxIndicatorRecommendationBytes)
	}

	// One byte over on either template fails the load.
	over := term
	over.Reason = maxReasonTmpl + "x"
	if _, err := CompileForTest("test", []Indicator{over}); err == nil || !strings.Contains(err.Error(), "worst-case rendered reason") {
		t.Errorf("over-bound reason template must fail the load: %v", err)
	}
	over = term
	over.Recommendation = maxRecTmpl + "x"
	if _, err := CompileForTest("test", []Indicator{over}); err == nil || !strings.Contains(err.Error(), "worst-case rendered recommendation") {
		t.Errorf("over-bound recommendation template must fail the load: %v", err)
	}

	// Non-term entries use both texts verbatim: exactly the bound passes,
	// one byte over fails.
	verbatim := Indicator{
		ID: "verbatim", Category: "max", Weight: 0.5, Field: FieldKind, Kind: "url",
		Reason:         pad(maxIndicatorReasonBytes),
		Recommendation: pad(maxIndicatorRecommendationBytes),
	}
	if _, err := CompileForTest("test", []Indicator{verbatim}); err != nil {
		t.Errorf("bound-sized verbatim texts must compile: %v", err)
	}
	over2 := verbatim
	over2.Reason = pad(maxIndicatorReasonBytes + 1)
	if _, err := CompileForTest("test", []Indicator{over2}); err == nil || !strings.Contains(err.Error(), "reason is over") {
		t.Errorf("over-bound verbatim reason must fail: %v", err)
	}
	over3 := verbatim
	over3.Recommendation = pad(maxIndicatorRecommendationBytes + 1)
	if _, err := CompileForTest("test", []Indicator{over3}); err == nil || !strings.Contains(err.Error(), "recommendation is over") {
		t.Errorf("over-bound verbatim recommendation must fail: %v", err)
	}

	// The substitution seam itself is contractual: a term entry without %s
	// in a template, and a non-term entry with any percent sign, both fail.
	noSeam := term
	noSeam.Reason = strings.Replace(term.Reason, "%s", "", 1)
	if _, err := CompileForTest("test", []Indicator{noSeam}); err == nil || !strings.Contains(err.Error(), "must carry exactly one %s") {
		t.Errorf("term entry without a %%s seam must fail: %v", err)
	}
	strayVerb := verbatim
	strayVerb.Reason = "verbatim with %s inside"
	if _, err := CompileForTest("test", []Indicator{strayVerb}); err == nil || !strings.Contains(err.Error(), "percent sign") {
		t.Errorf("non-term entry carrying a percent sign must fail: %v", err)
	}
}

// TestTemplateVerbContract is the Round-2 gate's verb-contract regression:
// score-time rendering substitutes the matched term for exactly ONE %s per
// template (matchCatalog's strings.Replace with n=1), so a template with a
// second verb — or ANY other percent sign (%q, %d, %v, %%, …) — would
// compile and then leak a raw verb into the emitted factor's
// Reason/Recommendation. Every such shape must fail the load with an error
// naming the offending field, on the term path AND the verbatim (non-term)
// path; one seam per template still compiles.
func TestTemplateVerbContract(t *testing.T) {
	base := Indicator{
		ID: "verbs", Category: "verbs", Weight: 0.5, Field: FieldPath,
		Terms: []string{"/a"},
	}
	verbatim := Indicator{
		ID: "verbatim-verbs", Category: "verbs", Weight: 0.5, Field: FieldKind,
		Kind: "url",
	}
	term := func(reason, rec string) func(*Indicator) {
		return func(e *Indicator) { e.Reason = reason; e.Recommendation = rec }
	}
	cases := []struct {
		name    string
		base    Indicator
		mutate  func(*Indicator)
		field   string
		wantSub string
	}{
		{"two verbs in reason", base, term("matched %s and also %s", "review %s"),
			"reason", "exactly one %s"},
		{"two verbs in recommendation", base, term("matched %s", "review %s and also %s"),
			"recommendation", "exactly one %s"},
		{"percent-q verb in reason", base, term("matched %s quoting %q", "review %s"),
			"reason", "%q"},
		{"percent-q verb in recommendation", base, term("matched %s", "review %s quoting %q"),
			"recommendation", "%q"},
		{"percent-d verb in reason", base, term("matched %s count %d", "review %s"),
			"reason", "beyond the single %s"},
		{"percent-v verb in recommendation", base, term("matched %s", "review %s value %v"),
			"recommendation", "beyond the single %s"},
		{"percent-percent in reason", base, term("matched %s 100%% sure", "review %s"),
			"reason", "beyond the single %s"},
		{"percent-d verb in verbatim reason", verbatim, term("matched count %d", "review the asset"),
			"reason", "percent sign"},
		{"percent-percent in verbatim recommendation", verbatim, term("review the asset", "review it 100%%"),
			"recommendation", "percent sign"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.base
			e.Reason = "matched %s"
			e.Recommendation = "review %s"
			if len(tt.base.Terms) == 0 {
				e.Reason = "matched the asset"
				e.Recommendation = "review the asset"
			}
			tt.mutate(&e)
			_, err := CompileForTest("test", []Indicator{e})
			if err == nil {
				t.Fatalf("template violating the verb contract must fail the load")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Errorf("error %q does not name the offending field %q", err, tt.field)
			}
		})
	}

	// One seam per template still compiles.
	ok := base
	ok.Reason = "matched %s"
	ok.Recommendation = "review %s"
	if _, err := CompileForTest("test", []Indicator{ok}); err != nil {
		t.Errorf("one-verb templates must compile: %v", err)
	}
}

// TestProductionRecommendationTemplates extends the reason-template guard
// to every production recommendation (all 53 entries): non-empty, within
// the compile bound in the worst rendered case, the %s substitution
// contract identical to reasons, and — the no-boilerplate rule — each
// recommendation references the evidence type its indicator matches on.
func TestProductionRecommendationTemplates(t *testing.T) {
	// One keyword per signal field that a recommendation citing that
	// evidence type must contain.
	keywords := map[SignalField][]string{
		FieldPath:           {"path"},
		FieldHost:           {"host"},
		FieldTechName:       {"technology"},
		FieldTechCategory:   {"technology", "category"},
		FieldServiceName:    {"service"},
		FieldPort:           {"port"},
		FieldParameterName:  {"parameter"},
		FieldSecretType:     {"secret"},
		FieldHeader:         {"header"},
		FieldJSBundleSize:   {"bundle"},
		FieldKind:           {"asset"},
		FieldEndpointMethod: {"endpoint", "websocket"},
	}

	ic, rc := mustCatalogs(t)
	total := 0
	for _, c := range []*Catalog{ic, rc} {
		for _, e := range c.Entries() {
			total++
			if e.Recommendation == "" {
				t.Errorf("catalog %q entry %q has an empty recommendation", c.Name(), e.ID)
				continue
			}
			kws := keywords[e.Field]
			lower := lowercaseASCII(e.Recommendation)
			ok := false
			for _, k := range kws {
				if strings.Contains(lower, k) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("catalog %q entry %q recommendation %q does not reference its evidence type (field %s; expected one of %v)",
					c.Name(), e.ID, e.Recommendation, e.Field, kws)
			}
			if len(e.Terms) == 0 {
				if strings.Contains(e.Recommendation, "%") {
					t.Errorf("catalog %q entry %q non-templated recommendation contains a percent sign", c.Name(), e.ID)
				}
				continue
			}
			if !strings.Contains(e.Recommendation, "%s") {
				t.Errorf("catalog %q entry %q term-matcher recommendation lacks a %%s seam", c.Name(), e.ID)
				continue
			}
			rendered := strings.Replace(e.Recommendation, "%s", e.Terms[0], 1)
			if !strings.Contains(rendered, e.Terms[0]) {
				t.Errorf("catalog %q entry %q rendered recommendation %q does not contain the matched term %q", c.Name(), e.ID, rendered, e.Terms[0])
			}
			if strings.Contains(rendered, "%") {
				t.Errorf("catalog %q entry %q rendered recommendation %q contains a raw percent sign", c.Name(), e.ID, rendered)
			}
			if worst := len(e.Recommendation) - 2 + maxTermBytes; worst > maxRecommendationBytes {
				t.Errorf("catalog %q entry %q worst-case rendered recommendation %d exceeds %d", c.Name(), e.ID, worst, maxRecommendationBytes)
			}
		}
	}
	if total != 53 {
		t.Errorf("production catalogs carry %d entries, want exactly 53", total)
	}
}

// TestCatalogDigest pins the catalog fingerprint contract: stable across
// loads, sensitive to every scoring-relevant entry edit (so any catalog
// change invalidates cached scores through the Round-2 key), and distinct
// per catalog.
func TestCatalogDigest(t *testing.T) {
	icA, err := LoadInterestingness()
	if err != nil {
		t.Fatal(err)
	}
	rcA, err := LoadRisk()
	if err != nil {
		t.Fatal(err)
	}
	icB, _ := LoadInterestingness()
	rcB, _ := LoadRisk()
	if icA.Digest() != icB.Digest() || rcA.Digest() != rcB.Digest() {
		t.Error("digest must be stable across loads")
	}
	if icA.Digest() == rcA.Digest() {
		t.Error("distinct catalogs must have distinct digests")
	}
	if got, want := CatalogsDigest(icA, rcA), CatalogsDigest(icB, rcB); got != want || got == "" {
		t.Errorf("combined digest = %q/%q, want equal non-empty", got, want)
	}
	if CatalogsDigest(nil, rcA) != "" || CatalogsDigest(icA, nil) != "" {
		t.Error("nil catalogs must yield an empty combined digest")
	}

	base := Indicator{
		ID: "e", Category: "c", Weight: 0.5, Field: FieldPath,
		Terms: []string{"/x"}, Reason: "reason %s", Recommendation: "guidance %s",
	}
	cat, err := CompileForTest("t", []Indicator{base})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Indicator){
		"weight":         func(e *Indicator) { e.Weight = 0.6 },
		"term":           func(e *Indicator) { e.Terms = []string{"/y"} },
		"reason":         func(e *Indicator) { e.Reason = "other %s" },
		"recommendation": func(e *Indicator) { e.Recommendation = "other guidance %s" },
		"category":       func(e *Indicator) { e.Category = "c2" },
	}
	for name, mutate := range mutations {
		e := base
		mutate(&e)
		mutated, err := CompileForTest("t", []Indicator{e})
		if err != nil {
			t.Fatalf("%s mutation must compile: %v", name, err)
		}
		if mutated.Digest() == cat.Digest() {
			t.Errorf("digest must change on a %s edit", name)
		}
	}
}

// TestProductionReasonTemplates guards the explainability contract for every
// production entry: a term-matcher reason's single %s is substituted with the
// matched term, and no emitted reason may carry a raw percent sign.
func TestProductionReasonTemplates(t *testing.T) {
	ic, rc := mustCatalogs(t)
	for _, c := range []*Catalog{ic, rc} {
		for _, e := range c.Entries() {
			if e.Reason == "" {
				t.Errorf("catalog %q entry %q has an empty reason", c.Name(), e.ID)
				continue
			}
			if len(e.Terms) == 0 {
				// Regex/size/kind matchers use the reason verbatim — it must
				// already be percent-free.
				if strings.Contains(e.Reason, "%") {
					t.Errorf("catalog %q entry %q non-templated reason %q contains a percent sign", c.Name(), e.ID, e.Reason)
				}
				continue
			}
			rendered := strings.Replace(e.Reason, "%s", e.Terms[0], 1)
			if !strings.Contains(rendered, e.Terms[0]) {
				t.Errorf("catalog %q entry %q reason %q rendered as %q does not contain the matched term %q", c.Name(), e.ID, e.Reason, rendered, e.Terms[0])
			}
			if strings.Contains(rendered, "%") {
				t.Errorf("catalog %q entry %q rendered reason %q contains a raw percent sign", c.Name(), e.ID, rendered)
			}
		}
	}
}

func mustCatalogs(t *testing.T) (*Catalog, *Catalog) {
	t.Helper()
	ic, err := LoadInterestingness()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := LoadRisk()
	if err != nil {
		t.Fatal(err)
	}
	return ic, rc
}

// testIdentity returns a fixed canonical identity for test signals.
func testIdentity() asset.Identity {
	return asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/app"}
}

func factorNames(s SurfaceAsset) []string {
	out := make([]string, 0, len(s.Factors))
	for _, f := range s.Factors {
		out = append(out, f.Name)
	}
	return out
}

func TestCompileForTestValidation(t *testing.T) {
	base := Indicator{
		ID: "admin-path", Category: "admin", Weight: 0.5, Field: FieldPath,
		Terms: []string{"/admin"}, Reason: "administrative path segment %s observed", Recommendation: "review the administrative path %s",
	}
	cases := []struct {
		name    string
		mutate  func(*Indicator)
		wantSub string
	}{
		{"empty id", func(e *Indicator) { e.ID = "" }, "empty or over"},
		{"uppercase id", func(e *Indicator) { e.ID = "Admin-Path" }, "lowercase"},
		{"empty category", func(e *Indicator) { e.Category = "" }, "category is empty"},
		{"zero weight", func(e *Indicator) { e.Weight = 0 }, "weight"},
		{"weight over one", func(e *Indicator) { e.Weight = 1.5 }, "weight"},
		{"nan weight", func(e *Indicator) { e.Weight = math.NaN() }, "weight"},
		{"unknown field", func(e *Indicator) { e.Field = SignalField("bogus") }, "unknown field"},
		{"no matcher", func(e *Indicator) { e.Terms = nil }, "exactly one matcher"},
		{"two matchers", func(e *Indicator) { e.Regex = "/admin" }, "exactly one matcher"},
		{"empty term", func(e *Indicator) { e.Terms = []string{""} }, "empty term"},
		{"uppercase term", func(e *Indicator) { e.Terms = []string{"/Admin"} }, "must be lowercase"},
		{"oversized term", func(e *Indicator) { e.Terms = []string{strings.Repeat("a", maxTermBytes+1)} }, "over"},
		{"too many terms", func(e *Indicator) { e.Terms = make([]string, maxTermsPerIndicator+1) }, "terms over bound"},
		{"bad regex", func(e *Indicator) { e.Terms = nil; e.Regex = "(" }, "does not compile"},
		{"empty reason", func(e *Indicator) { e.Reason = "" }, "reason is empty"},
		{"size on wrong field", func(e *Indicator) { e.Terms = nil; e.MinJSBytes = 100 }, "min_js_bytes"},
		{"negative min_js_bytes", func(e *Indicator) { e.MinJSBytes = -5 }, "must not be negative"},
		{"kind on wrong field", func(e *Indicator) { e.Terms = nil; e.Kind = "url" }, "kind matcher"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := base
			tt.mutate(&e)
			_, err := CompileForTest("test", []Indicator{e})
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// Duplicate IDs fail.
	if _, err := CompileForTest("test", []Indicator{base, base}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate IDs must fail: %v", err)
	}

	// Size and kind matchers are valid on their own fields.
	size := Indicator{ID: "big-js", Category: "large_js_bundle", Weight: 0.3, Field: FieldJSBundleSize, MinJSBytes: 1024, Reason: "large bundle", Recommendation: "review the large bundle"}
	if _, err := CompileForTest("test", []Indicator{size}); err != nil {
		t.Errorf("size matcher must validate: %v", err)
	}
	kind := Indicator{ID: "sm", Category: "source_map", Weight: 0.5, Field: FieldKind, Kind: "source_map", Reason: "source map", Recommendation: "review the source map asset"}
	if _, err := CompileForTest("test", []Indicator{kind}); err != nil {
		t.Errorf("kind matcher must validate: %v", err)
	}
}
