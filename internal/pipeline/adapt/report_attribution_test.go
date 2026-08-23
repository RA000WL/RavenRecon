package adapt

import (
	"net/http"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/importer"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// attributionUniverse builds the small report.Context the edge tests share:
// the canonical example.com corpus plus three RESULTS-channel assets beyond
// domains/hosts/URLs (an IP, a JavaScript file, and a finding) so the
// projection's "identities come from every channel, not just the corpus"
// semantics is exercised against real identities.
type attributionUniverse struct {
	ctx    report.Context
	hostID string
	ipID   string
	jsID   string
	findID string
	urlID  string
	domID  string
	evilID string // an out-of-scope host the boundary filters removed
}

func newAttributionUniverse(t *testing.T) attributionUniverse {
	t.Helper()

	host := mustHost(t, "www.example.com")
	ip, err := asset.NewIP("192.0.2.10", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "x-synthetic-header", "value", host.Identity(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	finding, err := asset.NewFinding(asset.Finding{
		RuleID:     "synthetic.rule",
		RuleName:   "Synthetic Rule",
		Category:   "exposure",
		Subject:    host.Identity(),
		Confidence: 0.9,
		Evidence:   []asset.Evidence{ev},
		Priority:   "info",
		Status:     "open",
		Created:    fixedTime,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	url := mustURL(t, "https://www.example.com/login")

	u := attributionUniverse{
		hostID: host.Identity().String(),
		ipID:   ip.Identity().String(),
		jsID:   js.Identity().String(),
		findID: finding.Identity().String(),
		urlID:  url.Identity().String(),
		domID:  "domain:example.com",
		evilID: mustHost(t, "evil.com").Identity().String(),
	}
	u.ctx = report.Context{
		Target:     "example.com",
		StartedAt:  fixedTime,
		EndedAt:    fixedTime,
		Domains:    []asset.Domain{mustDomain(t, "example.com")},
		Hosts:      []asset.Host{host},
		URLs:       []asset.URL{url},
		IPs:        []asset.IP{ip},
		JavaScript: []asset.JavaScript{js},
		Findings:   []asset.Finding{finding},
	}
	return u
}

// TestReportAttributionProjectionEdges pins the attributionFromProvenance /
// reportContextIdentities edge semantics at adapter level (T12 review
// MEDIUM-1): first record per identity wins, empty identities never project,
// boundary-filtered (target-absent) identities drop here rather than reaching
// the model, and results-channel identities beyond the URL corpus project
// like any other asset.
func TestReportAttributionProjectionEdges(t *testing.T) {
	u := newAttributionUniverse(t)
	known := reportContextIdentities(u.ctx)

	table := []struct {
		name         string
		records      []importer.ProvenanceRecord
		wantKeys     []string
		wantImporter map[string]string // surviving identity -> expected Importer
		wantNil      bool              // true: the result must be a nil map
	}{
		{
			name: "first record wins when two files import the same identity",
			records: []importer.ProvenanceRecord{
				{Identity: u.hostID, Importer: "plain-domains", OriginalTool: "amass", Filename: "first.txt", ImportTime: fixedTime, Confidence: 0.8},
				{Identity: u.hostID, Importer: "json-httpx", OriginalTool: "httpx", Filename: "second.txt", ImportTime: fixedTime.Add(time.Minute), Confidence: 0.9},
			},
			wantKeys:     []string{u.hostID},
			wantImporter: map[string]string{u.hostID: "plain-domains"},
		},
		{
			name: "empty identity record is skipped",
			records: []importer.ProvenanceRecord{
				{Identity: "", Importer: "plain-urls", Filename: "ghost.txt", ImportTime: fixedTime, Confidence: 0.5},
				{Identity: u.urlID, Importer: "plain-urls", Filename: "real.txt", ImportTime: fixedTime, Confidence: 0.5},
			},
			wantKeys:     []string{u.urlID},
			wantImporter: map[string]string{u.urlID: "plain-urls"},
		},
		{
			name: "boundary-filtered target-absent identity drops at adapter level",
			records: []importer.ProvenanceRecord{
				{Identity: u.evilID, Importer: "plain-domains", Filename: "out-of-scope.txt", ImportTime: fixedTime, Confidence: 0.9},
				{Identity: u.domID, Importer: "plain-domains", Filename: "in-scope.txt", ImportTime: fixedTime, Confidence: 0.9},
			},
			wantKeys:     []string{u.domID},
			wantImporter: map[string]string{u.domID: "plain-domains"},
		},
		{
			name: "results-channel identities beyond URLs project",
			records: []importer.ProvenanceRecord{
				{Identity: u.ipID, Importer: "json-httpx", Filename: "ips.json", ImportTime: fixedTime, Confidence: 0.7},
				{Identity: u.jsID, Importer: "plain-js", Filename: "js.txt", ImportTime: fixedTime, Confidence: 0.6},
				{Identity: u.findID, Importer: "plain-urls", Filename: "mixed.txt", ImportTime: fixedTime, Confidence: 0.5},
			},
			wantKeys:     []string{u.ipID, u.jsID, u.findID},
			wantImporter: map[string]string{u.ipID: "json-httpx", u.jsID: "plain-js", u.findID: "plain-urls"},
		},
		{
			name: "no surviving record yields a nil map",
			records: []importer.ProvenanceRecord{
				{Identity: u.evilID, Importer: "plain-domains", Filename: "out-of-scope.txt", ImportTime: fixedTime, Confidence: 0.9},
			},
			wantKeys: nil,
			wantNil:  true,
		},
		{
			name:     "empty sidecar yields a nil map",
			records:  nil,
			wantKeys: nil,
			wantNil:  true,
		},
	}

	for _, row := range table {
		t.Run(row.name, func(t *testing.T) {
			got := attributionFromProvenance(row.records, known)

			gotKeys := make([]string, 0, len(got))
			for k := range got {
				gotKeys = append(gotKeys, k)
			}
			sort.Strings(gotKeys)
			wantKeys := append([]string(nil), row.wantKeys...)
			sort.Strings(wantKeys)
			requireEqualStrings(t, "projected identities", gotKeys, wantKeys)

			if row.wantNil && got != nil {
				t.Errorf("projection = %+v, want nil (nothing survived)", got)
			}
			for id, wantImporter := range row.wantImporter {
				entry, ok := got[id]
				if !ok {
					t.Fatalf("identity %q missing from projection", id)
				}
				if entry.Importer != wantImporter {
					t.Errorf("identity %q Importer = %q, want %q", id, entry.Importer, wantImporter)
				}
			}
		})
	}

	// First-wins precision: the surviving entry carries the FIRST record's
	// full field set verbatim — no merge with later duplicates.
	got := attributionFromProvenance([]importer.ProvenanceRecord{
		{Identity: u.hostID, Importer: "plain-domains", OriginalTool: "amass", Filename: "first.txt", ImportTime: fixedTime, Confidence: 0.8},
		{Identity: u.hostID, Importer: "json-httpx", OriginalTool: "httpx", Filename: "second.txt", ImportTime: fixedTime.Add(time.Minute), Confidence: 0.9},
	}, known)
	entry := got[u.hostID]
	if entry.OriginalTool != "amass" || entry.Filename != "first.txt" || !entry.ImportedAt.Equal(fixedTime) || entry.Confidence != 0.8 {
		t.Errorf("first-wins entry = %+v, want the FIRST record verbatim (amass/first.txt/%v/0.8)", entry, fixedTime)
	}
}

// TestReportContextIdentitiesParityAllKinds pins that EVERY asset kind the
// report model carries survives attribution projection (T12 review MEDIUM-2
// drift guard): one asset per kind is built through the existing model
// constructors, composed into a report.Context exactly the way the stage
// composes it, and each identity must appear in reportContextIdentities AND
// project through attributionFromProvenance with its provenance fields
// intact. A future kind added to the model but missed here fails loudly
// instead of silently dropping its provenance records into false
// "discovered" origins.
func TestReportContextIdentitiesParityAllKinds(t *testing.T) {
	host := mustHost(t, "www.example.com")
	ip, err := asset.NewIP("192.0.2.10", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	port, err := asset.NewPort(443, "tcp", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewPort: %v", err)
	}
	svc, err := asset.NewService("https", port, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	url := mustURL(t, "https://www.example.com/login")
	ep, err := asset.NewEndpoint("GET", "https://www.example.com/login", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	param, err := asset.NewParameter("q", "query", "v", "url", fixedTime, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	tech, err := asset.NewTechnology("nginx", asset.CategoryServer, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "AKIA0123456789ABCDEF", host.Identity(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "x-synthetic-header", "value", host.Identity(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	finding, err := asset.NewFinding(asset.Finding{
		RuleID:     "synthetic.rule",
		RuleName:   "Synthetic Rule",
		Category:   "exposure",
		Subject:    host.Identity(),
		Confidence: 0.9,
		Evidence:   []asset.Evidence{ev},
		Priority:   "info",
		Status:     "open",
		Created:    fixedTime,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	cert, err := asset.NewTLSCertificate("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTLSCertificate: %v", err)
	}
	sm, err := asset.NewSourceMap("https://www.example.com/app.js.map", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSourceMap: %v", err)
	}
	rel, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	// A distinct URL for the liveness record so its projection is asserted
	// independently of the URLs-channel asset (sharing one would collapse
	// both into a single first-wins identity by design).
	liveURL := mustURL(t, "https://www.example.com/live-target")
	live := httpprobe.LiveRecord{URL: liveURL, Status: http.StatusOK}

	// The explicit enumeration: one identity per asset kind. LiveRecords
	// attribute through their URL (the record itself carries no identity);
	// relationships and the priority outputs carry none at all.
	kinds := []struct {
		name string
		id   string
	}{
		{"Domain", mustDomain(t, "example.com").Identity().String()},
		{"Host", host.Identity().String()},
		{"IP", ip.Identity().String()},
		{"Port", port.Identity().String()},
		{"Service", svc.Identity().String()},
		{"URL", url.Identity().String()},
		{"Endpoint", ep.Identity().String()},
		{"JavaScript", js.Identity().String()},
		{"Parameter", param.Identity().String()},
		{"Technology", tech.Identity().String()},
		{"SecretCandidate", sec.Identity().String()},
		{"Evidence", ev.Identity().String()},
		{"Finding", finding.Identity().String()},
		{"TLSCertificate", cert.Identity().String()},
		{"SourceMap", sm.Identity().String()},
		{"LiveRecord (via its URL)", liveURL.Identity().String()},
	}

	rctx := report.Context{
		Target:          "example.com",
		StartedAt:       fixedTime,
		EndedAt:         fixedTime,
		Domains:         []asset.Domain{mustDomain(t, "example.com")},
		Hosts:           []asset.Host{host},
		IPs:             []asset.IP{ip},
		Ports:           []asset.Port{port},
		Services:        []asset.Service{svc},
		URLs:            []asset.URL{url},
		Endpoints:       []asset.Endpoint{ep},
		JavaScript:      []asset.JavaScript{js},
		Parameters:      []asset.Parameter{param},
		Technologies:    []asset.Technology{tech},
		Secrets:         []asset.SecretCandidate{sec},
		Evidence:        []asset.Evidence{ev},
		Findings:        []asset.Finding{finding},
		TLSCertificates: []asset.TLSCertificate{cert},
		SourceMaps:      []asset.SourceMap{sm},
		Relationships:   []asset.Relationship{rel},
		Surfaces:        []priority.SurfaceAsset{{Identity: host.Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}},
		LiveRecords:     []httpprobe.LiveRecord{live},
	}

	known := reportContextIdentities(rctx)

	// Every enumerated kind's identity must be in the collector's universe…
	for _, k := range kinds {
		if _, ok := known[k.id]; !ok {
			t.Errorf("%s identity %q missing from reportContextIdentities — its provenance records would be dropped and the asset would report a false discovered origin", k.name, k.id)
		}
	}

	// …and every kind must SURVIVE projection: one provenance record per
	// identity goes in, every identity comes back out with its fields intact.
	records := make([]importer.ProvenanceRecord, 0, len(kinds))
	for _, k := range kinds {
		records = append(records, importer.ProvenanceRecord{
			Identity:     k.id,
			Importer:     "test-importer",
			OriginalTool: "synthetic-tool",
			Filename:     k.name + ".txt",
			ImportTime:   fixedTime,
			Confidence:   0.75,
		})
	}
	projected := attributionFromProvenance(records, known)
	if projected == nil {
		t.Fatal("projection = nil, want every kind's record to survive")
	}
	for _, k := range kinds {
		entry, ok := projected[k.id]
		if !ok {
			t.Errorf("%s identity %q did not survive projection", k.name, k.id)
			continue
		}
		if entry.Importer != "test-importer" || entry.OriginalTool != "synthetic-tool" || entry.Filename != k.name+".txt" || !entry.ImportedAt.Equal(fixedTime) || entry.Confidence != 0.75 {
			t.Errorf("%s projection = %+v, want the record's fields verbatim", k.name, entry)
		}
	}

	// Drift guard (the load-bearing part): walk EVERY exported slice field of
	// report.Context reflectively and collect the identities reachable
	// through an Identity() asset.Identity method (plus LiveRecord's URL).
	// The reflective set must equal reportContextIdentities' output EXACTLY —
	// in BOTH directions. When a future asset kind / context channel is added
	// to the model but reportContextIdentities is not extended, this fails
	// naming the dropped identity instead of silently discarding its
	// provenance.
	reflected := reflectContextIdentities(t, rctx)
	if len(reflected) == 0 {
		t.Fatal("reflective sweep found no identities — the sweep itself is broken")
	}
	for id := range reflected {
		if _, ok := known[id]; !ok {
			t.Errorf("context channel carries identity %q that reportContextIdentities does not collect — extend reportContextIdentities or the kind loses its provenance", id)
		}
	}
	for id := range known {
		if _, ok := reflected[id]; !ok {
			t.Errorf("reportContextIdentities emits %q which no context channel carries — a stale or spurious identity source", id)
		}
	}
	if len(reflected) != len(known) {
		t.Errorf("identity sets differ in size: reflected %d vs collected %d", len(reflected), len(known))
	}

	// Negative controls: relationship and priority-output entries carry no
	// asset identities, so their subject/anchor values must NOT leak into the
	// universe as bare strings (they are host-kind identities here and ARE
	// present — but only because Host is in the corpus; the count bound below
	// proves nothing extra was invented for them).
	if len(known) != len(kinds) {
		t.Errorf("universe size = %d, want exactly %d (one identity per kind, nothing else)", len(known), len(kinds))
	}
}

// reflectContextIdentities mirrors reportContextIdentities' contract WITHOUT
// duplicating its field list: it walks ctx's exported struct-slice fields and
// collects every element identity reachable through an Identity() method
// returning asset.Identity, special-casing httpprobe.LiveRecord (which
// attributes through its URL). Fields whose element type has no such method —
// relationships, the priority outputs, error records — contribute nothing,
// matching the documented contract.
func reflectContextIdentities(t *testing.T, ctx report.Context) map[string]struct{} {
	t.Helper()
	out := make(map[string]struct{})
	identityType := reflect.TypeOf(asset.Identity{})
	liveRecordType := reflect.TypeOf(httpprobe.LiveRecord{})

	v := reflect.ValueOf(ctx)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.CanInterface() || field.Kind() != reflect.Slice {
			continue
		}
		elem := field.Type().Elem()
		switch elem {
		case liveRecordType:
			for j := 0; j < field.Len(); j++ {
				url := field.Index(j).FieldByName("URL").Interface().(asset.URL)
				out[url.Identity().String()] = struct{}{}
			}
		default:
			m, ok := elem.MethodByName("Identity")
			if !ok || m.Type.NumIn() != 1 || m.Type.NumOut() != 1 || m.Type.Out(0) != identityType {
				continue // no asset identity (relationships, priority outputs, error records)
			}
			for j := 0; j < field.Len(); j++ {
				id := field.Index(j).MethodByName("Identity").Call(nil)[0].Interface().(asset.Identity)
				out[id.String()] = struct{}{}
			}
		}
	}
	return out
}
