package report

import (
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// fixedTime is the deterministic clock every fixture uses: reports must
// not read the wall clock, so every timestamp in tests is explicit.
var fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// fixedProv returns a deterministic provenance record.
func fixedProv(source string) asset.Provenance {
	return asset.Provenance{Source: source, DiscoveredAt: fixedTime, Reference: "ref-1", Confidence: 0.8}
}

// hostAsset builds a canonical host or fails the test.
func hostAsset(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, fixedProv("test"))
	if err != nil {
		t.Fatalf("host fixture %q: %v", name, err)
	}
	return h
}

// urlAsset builds a canonical URL or fails the test.
func urlAsset(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, fixedProv("test"))
	if err != nil {
		t.Fatalf("url fixture %q: %v", raw, err)
	}
	return u
}

// surfaceFixture builds a minimal valid scored surface.
func surfaceFixture(t *testing.T, rawURL string, score float64) priority.SurfaceAsset {
	t.Helper()
	u := urlAsset(t, rawURL)
	return priority.SurfaceAsset{
		Identity:        u.Identity(),
		Kind:            asset.KindURL,
		Score:           score,
		Level:           priority.LevelMedium,
		Interestingness: score / 2,
		Confidence:      0.4,
		Factors: []priority.Factor{{
			Name:           "interestingness:admin",
			Weight:         score / 2,
			Evidence:       []string{u.Identity().String()},
			Reason:         "admin panel path observed on the surface",
			Recommendation: "Inventory admin interfaces and record their authentication requirements",
		}},
		FirstSeen: fixedTime,
		ScoredAt:  fixedTime,
	}
}

// findingFixture builds a minimal canonical finding.
func findingFixture(t *testing.T, ruleID string, subject asset.Identity, conf float64) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDetection, "detect:"+ruleID, "observed", subject, fixedProv("detect"))
	if err != nil {
		t.Fatalf("evidence fixture: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleID + " rule",
		Category:   "exposure",
		Subject:    subject,
		Confidence: conf,
		Evidence:   []asset.Evidence{ev},
		Priority:   "medium",
		Status:     "open",
		Created:    fixedTime,
	})
	if err != nil {
		t.Fatalf("finding fixture: %v", err)
	}
	return f
}

// testContext builds the canonical mixed corpus every renderer test uses.
func testContext(t *testing.T) Context {
	t.Helper()
	host := hostAsset(t, "www.example.com")
	hostDup := hostAsset(t, "www.example.com")
	otherHost := hostAsset(t, "api.example.com")

	ip, err := asset.NewIP("192.0.2.10", fixedProv("dns"))
	if err != nil {
		t.Fatalf("ip fixture: %v", err)
	}
	port, err := asset.NewPort(443, "tcp", fixedProv("probe"))
	if err != nil {
		t.Fatalf("port fixture: %v", err)
	}
	service, err := asset.NewService("https", port, fixedProv("probe"))
	if err != nil {
		t.Fatalf("service fixture: %v", err)
	}
	adminURL := urlAsset(t, "https://www.example.com/admin?refresh=1")
	apiURL := urlAsset(t, "https://api.example.com/v1/users")
	endpoint, err := asset.NewEndpoint("GET", "https://www.example.com/admin", fixedProv("urlintel"))
	if err != nil {
		t.Fatalf("endpoint fixture: %v", err)
	}
	script, err := asset.NewJavaScript("https://www.example.com/static/app.js", fixedProv("jsintel"))
	if err != nil {
		t.Fatalf("javascript fixture: %v", err)
	}
	param, err := asset.NewParameter("refresh", "query", "1", "urlintel", fixedTime, fixedProv("urlintel"))
	if err != nil {
		t.Fatalf("parameter fixture: %v", err)
	}
	tech, err := asset.NewTechnology("nginx", "server", fixedProv("techintel"))
	if err != nil {
		t.Fatalf("technology fixture: %v", err)
	}
	secret, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "aws-documented-example-key", script.Identity(), fixedProv("secrentel"))
	if err != nil {
		t.Fatalf("secret fixture: %v", err)
	}
	evidence, err := asset.NewEvidence(asset.MethodHeader, "header:server", "nginx", host.Identity(), fixedProv("techintel"))
	if err != nil {
		t.Fatalf("evidence fixture: %v", err)
	}
	cert, err := asset.NewTLSCertificate("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4", fixedProv("probe"))
	if err != nil {
		t.Fatalf("tls certificate fixture: %v", err)
	}
	smap, err := asset.NewSourceMap("https://www.example.com/static/app.js.map", fixedProv("jsintel"))
	if err != nil {
		t.Fatalf("source map fixture: %v", err)
	}
	hostToURL, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToURL, adminURL.Identity())
	if err != nil {
		t.Fatalf("relationship fixture: %v", err)
	}

	surface := surfaceFixture(t, "https://www.example.com/admin?refresh=1", 0.75)
	group := priority.Group{
		Anchor:  host.Identity(),
		Members: []priority.SurfaceAsset{surface},
		Score:   0.75,
		Level:   priority.LevelMedium,
	}
	attackPath := priority.AttackPath{
		Root: host.Identity(),
		Steps: []priority.PathStep{
			{Identity: host.Identity(), Kind: asset.KindHost, Reason: "correlated under host anchor"},
			{Identity: surface.Identity, Kind: asset.KindURL, FactorName: "interestingness:admin",
				Reason: "admin panel path observed on the surface", Evidence: []string{surface.Identity.String()}},
		},
		Score: 0.75,
		Level: priority.LevelMedium,
	}

	return Context{
		Target:          "example.com",
		StartedAt:       fixedTime,
		EndedAt:         fixedTime.Add(90 * time.Second),
		Domains:         []asset.Domain{{Name: "example.com", Prov: fixedProv("discovery")}},
		Hosts:           []asset.Host{host, hostDup, otherHost},
		IPs:             []asset.IP{ip},
		Ports:           []asset.Port{port},
		Services:        []asset.Service{service},
		URLs:            []asset.URL{adminURL, apiURL},
		Endpoints:       []asset.Endpoint{endpoint},
		JavaScript:      []asset.JavaScript{script},
		Parameters:      []asset.Parameter{param},
		Technologies:    []asset.Technology{tech},
		Secrets:         []asset.SecretCandidate{secret},
		Evidence:        []asset.Evidence{evidence},
		Findings:        []asset.Finding{findingFixture(t, "rule-exposure-1", host.Identity(), 0.9)},
		TLSCertificates: []asset.TLSCertificate{cert},
		SourceMaps:      []asset.SourceMap{smap},
		Relationships:   []asset.Relationship{hostToURL},
		Surfaces:        []priority.SurfaceAsset{surface},
		Groups:          []priority.Group{group},
		AttackPaths:     []priority.AttackPath{attackPath},
		Errors: []ErrorRecord{
			{Category: CategoryDNS, Stage: "dns", Message: "lookup timeout for api.example.com", Count: 2},
			{Category: CategoryDNS, Stage: "dns", Message: "lookup timeout for api.example.com", Count: 3},
			{Category: CategoryHTTP, Stage: "http.probe", Message: "connection refused"},
		},
		Runtime:   RuntimeStats{Workers: 8, Jobs: 12, JobsCompleted: 11, WorkerTime: Ms(2500 * time.Millisecond)},
		Cache:     CacheStats{Hits: 4, Misses: 8},
		Execution: ExecStats{Rules: 3, Executions: 3, Errors: 1, CacheHits: 1, CacheMisses: 2},
	}
}

// testModel builds the canonical model from testContext.
func testModel(t *testing.T) *Model {
	t.Helper()
	m, err := NewModel(testContext(t))
	if err != nil {
		t.Fatalf("test model: %v", err)
	}
	return m
}
