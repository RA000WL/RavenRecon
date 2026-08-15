package fingerprints

import (
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestIndicatorKindValidAndParse(t *testing.T) {
	all := []IndicatorKind{
		IndicatorHeader, IndicatorCookie, IndicatorHTMLRegex,
		IndicatorHTMLSubstring, IndicatorMetaName, IndicatorGenerator,
		IndicatorScriptName, IndicatorScriptPath, IndicatorCSSPath,
		IndicatorAttribute, IndicatorEndpointPath, IndicatorTLSIssuer,
		IndicatorTLSCN, IndicatorTLSALPN, IndicatorDNSCNAME, IndicatorSourceMapPath,
	}
	if len(all) != 16 {
		t.Fatalf("indicator kinds = %d, want 16", len(all))
	}

	// Every kind is valid, round-trips through ParseIndicatorKind, and its
	// String form is the canonical lowercase value.
	for _, k := range all {
		if !k.Valid() {
			t.Errorf("%q must be Valid", k)
		}
		got, err := ParseIndicatorKind(string(k))
		if err != nil {
			t.Errorf("ParseIndicatorKind(%q): %v", k, err)
			continue
		}
		if got != k || got.String() != string(k) {
			t.Errorf("round trip %q -> %q", k, got)
		}
	}

	// Duplicate values would break the enum's uniqueness (and thus the
	// evidence identity mapping).
	for i, a := range all {
		for j, b := range all {
			if i != j && a == b {
				t.Errorf("duplicate indicator kind value %q", a)
			}
		}
	}

	for _, bad := range []string{"", "HEADER", "header ", "header/value", "bogus", "html_regex "} {
		if _, err := ParseIndicatorKind(bad); err == nil {
			t.Errorf("ParseIndicatorKind(%q) must fail", bad)
		}
		if IndicatorKind(bad).Valid() {
			t.Errorf("%q must not be Valid", bad)
		}
	}
}

func TestIndicatorKindTier(t *testing.T) {
	spoofable := []IndicatorKind{IndicatorHeader, IndicatorCookie, IndicatorDNSCNAME}
	structural := []IndicatorKind{
		IndicatorHTMLRegex, IndicatorHTMLSubstring, IndicatorMetaName,
		IndicatorGenerator, IndicatorScriptName, IndicatorScriptPath,
		IndicatorCSSPath, IndicatorAttribute, IndicatorEndpointPath,
		IndicatorTLSIssuer, IndicatorTLSCN, IndicatorTLSALPN, IndicatorSourceMapPath,
	}

	for _, k := range spoofable {
		if got := k.Tier(); got != TierSpoofable {
			t.Errorf("%q tier = %q, want %q", k, got, TierSpoofable)
		}
	}
	for _, k := range structural {
		if got := k.Tier(); got != TierStructural {
			t.Errorf("%q tier = %q, want %q", k, got, TierStructural)
		}
	}
}

func TestLoadAndSchemaVersion(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", SchemaVersion)
	}

	d, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Version() != SchemaVersion {
		t.Errorf("Version() = %d, want %d", d.Version(), SchemaVersion)
	}
	if d.Len() < 120 {
		t.Errorf("DB has %d fingerprints, want at least 120", d.Len())
	}
}

// TestLoadCategoriesAllRepresented pins that every one of the 21
// asset.TechnologyCategory values has at least one fingerprint.
func TestLoadCategoriesAllRepresented(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	present := map[asset.TechnologyCategory]bool{}
	for _, fp := range d.Fingerprints() {
		present[fp.Category] = true
	}
	for _, c := range asset.KnownCategories() {
		if !present[c] {
			t.Errorf("category %q has no fingerprints", c)
		}
	}
}

// TestLoadSpecTechnologiesPresent pins every technology named in the Phase
// 6.5 spec lists (deliverable 3) to a fingerprint with its canonical
// category. Go is deliberately absent: net/http emits no documented marker.
func TestLoadSpecTechnologiesPresent(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]asset.TechnologyCategory{}
	for _, fp := range d.Fingerprints() {
		got[fp.Name] = fp.Category
	}

	want := map[string]asset.TechnologyCategory{
		// frameworks.go
		"react": asset.CategoryFramework, "next.js": asset.CategoryFramework,
		"vue": asset.CategoryFramework, "nuxt": asset.CategoryFramework,
		"angular": asset.CategoryFramework, "svelte": asset.CategoryFramework,
		"solid": asset.CategoryFramework, "remix": asset.CategoryFramework,
		"astro": asset.CategoryFramework, "qwik": asset.CategoryFramework,
		"laravel": asset.CategoryFramework, "django": asset.CategoryFramework,
		"rails": asset.CategoryFramework, "spring": asset.CategoryFramework,
		"asp.net": asset.CategoryFramework, "express": asset.CategoryFramework,
		"nestjs": asset.CategoryFramework, "fastapi": asset.CategoryFramework,
		"flask": asset.CategoryFramework, "phoenix": asset.CategoryFramework,
		"gin": asset.CategoryFramework, "fiber": asset.CategoryFramework,
		"echo": asset.CategoryFramework,
		// buildtools.go
		"webpack": asset.CategoryBuildTool, "vite": asset.CategoryBuildTool,
		"parcel": asset.CategoryBuildTool, "rollup": asset.CategoryBuildTool,
		"rspack": asset.CategoryBuildTool, "turbopack": asset.CategoryBuildTool,
		"requirejs": asset.CategoryBuildTool, "systemjs": asset.CategoryBuildTool,
		"esbuild": asset.CategoryBuildTool,
		// servers.go
		"nginx": asset.CategoryServer, "apache": asset.CategoryServer,
		"iis": asset.CategoryServer, "litespeed": asset.CategoryServer,
		"caddy": asset.CategoryServer, "openresty": asset.CategoryServer,
		"haproxy": asset.CategoryProxy, "varnish": asset.CategoryProxy,
		"squid": asset.CategoryProxy, "envoy": asset.CategoryProxy,
		"traefik": asset.CategoryProxy,
		// cdns.go
		"cloudflare": asset.CategoryCDN, "akamai": asset.CategoryCDN,
		"fastly": asset.CategoryCDN, "cloudfront": asset.CategoryCDN,
		"bunny": asset.CategoryCDN, "azure front door": asset.CategoryCDN,
		"google cdn": asset.CategoryCDN,
		"imperva":    asset.CategoryWAF, "sucuri": asset.CategoryWAF,
		"incapsula": asset.CategoryWAF, "f5": asset.CategoryWAF,
		"cloudflare waf": asset.CategoryWAF,
		// clouds.go
		"aws": asset.CategoryCloudProvider, "azure": asset.CategoryCloudProvider,
		"google cloud": asset.CategoryCloudProvider,
		"digitalocean": asset.CategoryCloudProvider, "fly.io": asset.CategoryCloudProvider,
		"railway": asset.CategoryCloudProvider, "render": asset.CategoryCloudProvider,
		"heroku": asset.CategoryCloudProvider, "netlify": asset.CategoryCloudProvider,
		"vercel": asset.CategoryCloudProvider,
		// auth.go
		"auth0": asset.CategoryAuthentication, "firebase": asset.CategoryAuthentication,
		"okta": asset.CategoryAuthentication, "aws cognito": asset.CategoryAuthentication,
		"azure ad": asset.CategoryAuthentication, "keycloak": asset.CategoryAuthentication,
		"nextauth":           asset.CategoryAuthentication,
		"laravel session":    asset.CategoryAuthentication,
		"django session":     asset.CategoryAuthentication,
		"rails session":      asset.CategoryAuthentication,
		"spring session":     asset.CategoryAuthentication,
		"express session":    asset.CategoryAuthentication,
		"php session cookie": asset.CategoryAuthentication,
		// apis.go
		"graphql": asset.CategoryGraphQL, "apollo": asset.CategoryGraphQL,
		"relay":    asset.CategoryGraphQL,
		"grpc-web": asset.CategoryAPIGateway, "json-rpc": asset.CategoryAPIGateway,
		"soap": asset.CategoryAPIGateway, "openapi": asset.CategoryAPIGateway,
		"swagger ui": asset.CategoryAPIGateway, "rest-generic": asset.CategoryAPIGateway,
		"kong": asset.CategoryAPIGateway, "tyk": asset.CategoryAPIGateway,
		"amazon api gateway":   asset.CategoryAPIGateway,
		"azure api management": asset.CategoryAPIGateway,
		// cms.go
		"wordpress": asset.CategoryCMS, "drupal": asset.CategoryCMS,
		"joomla": asset.CategoryCMS, "shopify": asset.CategoryCMS,
		"squarespace": asset.CategoryCMS, "wix": asset.CategoryCMS,
		"ghost": asset.CategoryCMS, "hugo": asset.CategoryCMS,
		"gatsby": asset.CategoryCMS, "jekyll": asset.CategoryCMS,
		// infra.go
		"mysql": asset.CategoryDatabase, "postgresql": asset.CategoryDatabase,
		"mongodb": asset.CategoryDatabase, "redis": asset.CategoryDatabase,
		"sqlite": asset.CategoryDatabase, "mariadb": asset.CategoryDatabase,
		"mssql": asset.CategoryDatabase, "oracle": asset.CategoryDatabase,
		"elasticsearch": asset.CategorySearchEngine, "algolia": asset.CategorySearchEngine,
		"meilisearch": asset.CategorySearchEngine, "typesense": asset.CategorySearchEngine,
		"solr":     asset.CategorySearchEngine,
		"rabbitmq": asset.CategoryMessageQueue, "kafka": asset.CategoryMessageQueue,
		"sqs":     asset.CategoryMessageQueue,
		"grafana": asset.CategoryMonitoring, "prometheus": asset.CategoryMonitoring,
		"datadog": asset.CategoryMonitoring, "sentry": asset.CategoryMonitoring,
		"new relic": asset.CategoryMonitoring,
		"s3":        asset.CategoryStorage, "gcs": asset.CategoryStorage,
		"azure blob": asset.CategoryStorage, "cloudflare r2": asset.CategoryStorage,
		"backblaze b2": asset.CategoryStorage,
		"docker":       asset.CategoryContainer, "containerd": asset.CategoryContainer,
		"kubernetes": asset.CategoryOrchestration, "ecs": asset.CategoryOrchestration,
		"nomad":            asset.CategoryOrchestration,
		"google analytics": asset.CategoryAnalytics, "matomo": asset.CategoryAnalytics,
		"plausible": asset.CategoryAnalytics, "fathom": asset.CategoryAnalytics,
		"hotjar": asset.CategoryAnalytics, "segment": asset.CategoryAnalytics,
		"mixpanel": asset.CategoryAnalytics,
		// languages.go
		"php": asset.CategoryLanguage, "python": asset.CategoryLanguage,
		"node.js": asset.CategoryRuntime, "java": asset.CategoryLanguage,
		"ruby": asset.CategoryLanguage, ".net": asset.CategoryLanguage,
	}

	if len(got) != len(want) {
		t.Errorf("DB has %d fingerprints, spec table has %d", len(got), len(want))
	}
	for name, cat := range want {
		if tc, ok := got[name]; !ok {
			t.Errorf("spec technology %q missing from DB", name)
		} else if tc != cat {
			t.Errorf("spec technology %q category = %q, want %q", name, tc, cat)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("DB has unexpected fingerprint %q", name)
		}
	}
}

func TestFingerprintsSortedAndDeterministic(t *testing.T) {
	a, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	first := a.Fingerprints()
	second := b.Fingerprints()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two Load() calls produced different databases")
	}

	for i := 1; i < len(first); i++ {
		prev, cur := first[i-1], first[i]
		if cur.Name < prev.Name || (cur.Name == prev.Name && cur.Category < prev.Category) {
			t.Fatalf("fingerprints not sorted at %d: %q/%q then %q/%q", i, prev.Category, prev.Name, cur.Category, cur.Name)
		}
	}

	// Fingerprints() must be fresh deep copies: mutating the returned slice
	// must not affect the DB.
	mutated := a.Fingerprints()
	mutated[0].Name = "tampered"
	mutated[0].Indicators[0].Weight = 0
	again := a.Fingerprints()
	if reflect.DeepEqual(mutated, again) {
		t.Error("Fingerprints() must return a fresh deep copy")
	}
}

func TestLoadValidationErrors(t *testing.T) {
	valid := Fingerprint{
		Name:     "validtech",
		Category: asset.CategoryFramework,
		Indicators: []Indicator{
			{Kind: IndicatorHeader, Match: "x-valid-tech", Weight: 0.8},
		},
	}
	try := func(name string, mutate func(*Fingerprint), wantSub string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			fp := valid
			fp.Indicators = append([]Indicator(nil), valid.Indicators...)
			mutate(&fp)
			if _, err := newRawDB([]Fingerprint{fp}); err == nil {
				t.Fatal("expected validation error")
			} else if !strings.Contains(err.Error(), wantSub) {
				t.Errorf("error %q does not contain %q", err, wantSub)
			}
		})
	}

	try("empty name", func(fp *Fingerprint) { fp.Name = "" }, "name must not be empty")
	try("bad category", func(fp *Fingerprint) { fp.Category = asset.TechnologyCategory("bogus") }, "unknown technology category")
	try("empty category", func(fp *Fingerprint) { fp.Category = "" }, "unknown technology category")
	try("no indicators", func(fp *Fingerprint) { fp.Indicators = nil }, "at least one indicator")

	try("invalid indicator kind", func(fp *Fingerprint) {
		fp.Indicators[0].Kind = IndicatorKind("bogus")
	}, "invalid indicator kind")
	try("empty match", func(fp *Fingerprint) {
		fp.Indicators[0].Match = ""
	}, "must not be empty")
	try("weight zero", func(fp *Fingerprint) {
		fp.Indicators[0].Weight = 0
	}, `0 < weight <= 1`)
	try("weight negative", func(fp *Fingerprint) {
		fp.Indicators[0].Weight = -0.5
	}, `0 < weight <= 1`)
	try("weight above one", func(fp *Fingerprint) {
		fp.Indicators[0].Weight = 1.5
	}, `0 < weight <= 1`)

	try("invalid html_regex match", func(fp *Fingerprint) {
		fp.Indicators = append(fp.Indicators, Indicator{Kind: IndicatorHTMLRegex, Match: "(", Weight: 0.5})
	}, "not a valid regex")
	try("invalid generator match", func(fp *Fingerprint) {
		fp.Indicators = append(fp.Indicators, Indicator{Kind: IndicatorGenerator, Match: "[", Weight: 0.5})
	}, "not a valid regex")

	try("empty version pattern", func(fp *Fingerprint) {
		fp.Indicators[0].Version = &VersionSpec{Pattern: "", Group: 1}
	}, "must not be empty")
	try("invalid version pattern", func(fp *Fingerprint) {
		fp.Indicators[0].Version = &VersionSpec{Pattern: "(", Group: 1}
	}, "not a valid regex")
	try("negative version group", func(fp *Fingerprint) {
		fp.Indicators[0].Version = &VersionSpec{Pattern: `v([0-9]+)`, Group: -1}
	}, "must not be negative")

	// Duplicate names across entries are rejected.
	first := valid
	second := valid
	second.Name = "other"
	second.Indicators[0].Match = "x-other-tech"
	third := valid
	if _, err := newRawDB([]Fingerprint{first, second, third}); err == nil ||
		!strings.Contains(err.Error(), `duplicate fingerprint name "validtech"`) {
		t.Errorf("duplicate name error = %v", err)
	}

	// A valid raw entry compiles.
	d, err := newRawDB([]Fingerprint{valid})
	if err != nil {
		t.Fatalf("valid raw entry must compile: %v", err)
	}
	if d.Len() != 1 {
		t.Errorf("Len() = %d, want 1", d.Len())
	}
}

func TestVersionReCompileOnceAndNil(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seenVersion := false
	seenNil := false
	for _, fp := range d.Fingerprints() {
		for _, ind := range fp.Indicators {
			if ind.Version == nil {
				if ind.VersionRe() != nil {
					t.Errorf("%s/%s: VersionRe must be nil when no version spec", fp.Name, ind.Match)
				}
				seenNil = true
				continue
			}
			seenVersion = true
			r1 := ind.VersionRe()
			r2 := ind.VersionRe()
			if r1 == nil || r1 != r2 {
				t.Errorf("%s/%s: VersionRe must return the same compiled instance, got %v / %v", fp.Name, ind.Match, r1, r2)
			}
			// The returned regex behaves like the documented pattern.
			if r1.String() != ind.Version.Pattern {
				t.Errorf("%s/%s: compiled pattern %q != declared pattern %q", fp.Name, ind.Match, r1.String(), ind.Version.Pattern)
			}
		}
	}
	if !seenVersion || !seenNil {
		t.Errorf("test must cover both versioned and unversioned indicators (seenVersion=%v seenNil=%v)", seenVersion, seenNil)
	}
}

func TestVersionExtraction(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// indFor finds the first indicator of the given kind whose Match is
	// contained in the fingerprint.
	indFor := func(t *testing.T, fp Fingerprint, kind IndicatorKind, matchSub string) Indicator {
		t.Helper()
		for _, ind := range fp.Indicators {
			if ind.Kind == kind && strings.Contains(ind.Match, matchSub) {
				return ind
			}
		}
		t.Fatalf("%s: no %s indicator containing %q", fp.Name, kind, matchSub)
		return Indicator{}
	}

	cases := []struct {
		name     string
		fpName   string
		kind     IndicatorKind
		matchSub string
		value    string // the observed value, passed to VersionRe as-is
		want     string
	}{
		{"nginx server banner", "nginx", IndicatorHeader, "server: nginx", "server: nginx/1.25.3 (Ubuntu)", "1.25.3"},
		{"apache server banner", "apache", IndicatorHeader, "server: apache", "server: Apache/2.4.57 (Ubuntu)", "2.4.57"},
		{"asp.net version header", "asp.net", IndicatorHeader, "x-aspnet-version", "x-aspnet-version: 4.0.30319", "4.0.30319"},
		{"php version header", "php", IndicatorHeader, "x-powered-by: php", "x-powered-by: PHP/8.2.12", "8.2.12"},
		{"wordpress generator", "wordpress", IndicatorGenerator, "WordPress", "WordPress 6.4.2", "6.4.2"},
		{"astro generator", "astro", IndicatorGenerator, "Astro", "Astro v4.16.1", "4.16.1"},
		{"angular ng-version attribute", "angular", IndicatorAttribute, "ng-version", "ng-version=\"17.2.0\"", "17.2.0"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fp := dbWithName(t, d, tt.fpName)
			ind := indFor(t, fp, tt.kind, tt.matchSub)
			re := ind.VersionRe()
			if re == nil {
				t.Fatalf("%s/%s: expected a version pattern", fp.Name, ind.Match)
			}
			sub := re.FindStringSubmatch(tt.value)
			if len(sub) <= ind.Version.Group {
				t.Fatalf("version pattern %q did not match %q (submatch %v)", ind.Version.Pattern, tt.value, sub)
			}
			if got := sub[ind.Version.Group]; got != tt.want {
				t.Errorf("version = %q, want %q (pattern %q on %q)", got, tt.want, ind.Version.Pattern, tt.value)
			}
		})
	}
}

func TestIndicatorPresenceMatches(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// indFor finds the first indicator of the given kind whose Match equals
	// the given match string.
	indFor := func(t *testing.T, fp Fingerprint, kind IndicatorKind, match string) Indicator {
		t.Helper()
		for _, ind := range fp.Indicators {
			if ind.Kind == kind && ind.Match == match {
				return ind
			}
		}
		t.Fatalf("%s: no %s indicator matching %q", fp.Name, kind, match)
		return Indicator{}
	}

	// The matching contract: literal Match values are case-insensitive
	// substrings of the observation. These fixtures pin the contract
	// exactly as the engine pass must implement it.
	cases := []struct {
		name   string
		fpName string
		kind   IndicatorKind
		match  string
		value  []string // observed values; at least one must contain Match
	}{
		{"cloudflare cf-ray presence", "cloudflare", IndicatorHeader, "cf-ray", []string{"cf-ray: 899103b0e9d1e6b2-EWR"}},
		{"cloudflare server banner", "cloudflare", IndicatorHeader, "server: cloudflare", []string{"Server: cloudflare"}},
		{"express x-powered-by", "express", IndicatorHeader, "x-powered-by: express", []string{"X-Powered-By: Express"}},
		{"phoenix session cookie", "phoenix", IndicatorCookie, "phx_session", []string{"phx_session=abc123; Path=/"}},
		{"react bundle", "react", IndicatorScriptName, "react.js", []string{"https://cdn.example.com/static/js/react.js"}},
		{"wordpress generator content", "wordpress", IndicatorGenerator, "WordPress", []string{"WordPress 6.4.2"}},
		{"cloudflare waf challenge page", "cloudflare waf", IndicatorHTMLSubstring, "cf-error-details", []string{"<div class=\"cf-error-details\">...</div>"}},
		{"grafana cookie", "grafana", IndicatorCookie, "grafana_session", []string{"grafana_session=deadbeef"}},
		{"vite dev client", "vite", IndicatorScriptPath, "/@vite/", []string{"src=\"/@vite/client\""}},
		{"akamai cname", "akamai", IndicatorDNSCNAME, "akamaized.net", []string{"www.example.com.edgesuite.net.akamaized.net"}},
		{"google cdn tls issuer", "google cdn", IndicatorTLSIssuer, "google trust services", []string{"CN=WR2,O=Google Trust Services"}},
		{"s3 bucket region header", "s3", IndicatorHeader, "x-amz-bucket-region", []string{"x-amz-bucket-region: us-east-1"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fp := dbWithName(t, d, tt.fpName)
			ind := indFor(t, fp, tt.kind, tt.match)
			found := false
			for _, v := range tt.value {
				if strings.Contains(strings.ToLower(v), strings.ToLower(ind.Match)) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("indicator %q (%s) did not match any of %v", ind.Match, ind.Kind, tt.value)
			}
		})
	}
}

func TestMatchReCompileOnceAndNil(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seenHTMLRegex, seenGenerator := false, false
	seenLiteral := false
	for _, fp := range d.Fingerprints() {
		for _, ind := range fp.Indicators {
			if ind.Kind != IndicatorHTMLRegex && ind.Kind != IndicatorGenerator {
				// Literal kinds never carry a compiled match regex.
				if ind.MatchRe() != nil {
					t.Errorf("%s/%s: MatchRe must be nil for %s kind", fp.Name, ind.Match, ind.Kind)
				}
				seenLiteral = true
				continue
			}
			if ind.Kind == IndicatorHTMLRegex {
				seenHTMLRegex = true
			} else {
				seenGenerator = true
			}
			r1 := ind.MatchRe()
			r2 := ind.MatchRe()
			if r1 == nil || r1 != r2 {
				t.Errorf("%s/%s: MatchRe must return the same compiled instance, got %v / %v", fp.Name, ind.Match, r1, r2)
			}
			// The returned regex behaves like the declared Match.
			if r1.String() != ind.Match {
				t.Errorf("%s/%s: compiled match %q != declared match %q", fp.Name, ind.Match, r1.String(), ind.Match)
			}
		}
	}
	// The test must cover every branch: both regex kinds and at least one
	// literal kind.
	if !seenHTMLRegex || !seenGenerator || !seenLiteral {
		t.Errorf("test must cover both regex kinds and literal kinds (html_regex=%v generator=%v literal=%v)",
			seenHTMLRegex, seenGenerator, seenLiteral)
	}
}

func TestDataSanityAcrossDB(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	allKinds := map[IndicatorKind]bool{}
	counts := map[asset.TechnologyCategory]int{}
	spoobableSeen, structuralSeen := false, false
	totalIndicators := 0
	for _, fp := range d.Fingerprints() {
		if fp.Name != strings.ToLower(fp.Name) || strings.Contains(fp.Name, "  ") {
			t.Errorf("fingerprint %q must be canonical lowercase", fp.Name)
		}
		counts[fp.Category]++
		for _, ind := range fp.Indicators {
			totalIndicators++
			allKinds[ind.Kind] = true
			if ind.Weight <= 0 || ind.Weight > 1 {
				t.Errorf("%s/%s: weight %v out of range", fp.Name, ind.Match, ind.Weight)
			}
			if ind.Kind.Tier() == TierSpoofable {
				spoobableSeen = true
			} else {
				structuralSeen = true
			}
		}
	}

	// Both tiers occur in the production DB.
	if !spoobableSeen || !structuralSeen {
		t.Errorf("DB must contain both tiers (spoofable=%v structural=%v)", spoobableSeen, structuralSeen)
	}

	// Every one of the 16 indicator kinds is actually used by some
	// fingerprint (the enum reflects reality).
	for _, k := range []IndicatorKind{
		IndicatorHeader, IndicatorCookie, IndicatorHTMLRegex,
		IndicatorHTMLSubstring, IndicatorMetaName, IndicatorGenerator,
		IndicatorScriptName, IndicatorScriptPath, IndicatorCSSPath,
		IndicatorAttribute, IndicatorEndpointPath, IndicatorTLSIssuer,
		IndicatorTLSCN, IndicatorTLSALPN, IndicatorDNSCNAME, IndicatorSourceMapPath,
	} {
		if !allKinds[k] {
			t.Errorf("indicator kind %q is not used by any fingerprint", k)
		}
	}

	// Every category present; report the coverage table on failure only.
	for _, c := range asset.KnownCategories() {
		if counts[c] == 0 {
			t.Errorf("category %q has no fingerprints", c)
		}
	}
	t.Logf("total fingerprints: %d, total indicators: %d", d.Len(), totalIndicators)
}

// dbWithName returns the fingerprint with the given name from a compiled DB.
func dbWithName(t *testing.T, d *DB, name string) Fingerprint {
	t.Helper()
	for _, fp := range d.Fingerprints() {
		if fp.Name == name {
			return fp
		}
	}
	t.Fatalf("fingerprint %q not found in DB", name)
	return Fingerprint{}
}
