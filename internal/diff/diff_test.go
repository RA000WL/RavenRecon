package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
)

func mustHost(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

func mustURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

func writeModel(t *testing.T, dir, name string, m *report.Model) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestDiffAddedRemoved(t *testing.T) {
	old := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "gone.example.com")},
		URLs:          []asset.URL{mustURL(t, "https://a.example.com/")},
	}
	cur := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "new.example.com")},
		URLs: []asset.URL{
			mustURL(t, "https://a.example.com/"),
			mustURL(t, "https://new.example.com/robots.txt"),
		},
	}
	dir := t.TempDir()
	oldM, err := LoadReport(writeModel(t, dir, "old.json", old))
	if err != nil {
		t.Fatalf("LoadReport old: %v", err)
	}
	curM, err := LoadReport(writeModel(t, dir, "new.json", cur))
	if err != nil {
		t.Fatalf("LoadReport new: %v", err)
	}
	oldS, err := SnapshotOf(oldM)
	if err != nil {
		t.Fatalf("SnapshotOf old: %v", err)
	}
	curS, err := SnapshotOf(curM)
	if err != nil {
		t.Fatalf("SnapshotOf new: %v", err)
	}
	d, err := Diff(oldS, curS)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(d.Added["hosts"]) != 1 || !strings.Contains(d.Added["hosts"][0], "new.example.com") {
		t.Errorf("added hosts = %v, want [new.example.com]", d.Added["hosts"])
	}
	if len(d.Removed["hosts"]) != 1 || !strings.Contains(d.Removed["hosts"][0], "gone.example.com") {
		t.Errorf("removed hosts = %v, want [gone.example.com]", d.Removed["hosts"])
	}
	if len(d.Added["urls"]) != 1 || !strings.Contains(d.Added["urls"][0], "robots.txt") {
		t.Errorf("added urls = %v, want [robots.txt]", d.Added["urls"])
	}
	if d.Empty() {
		t.Error("delta must not be empty")
	}
	if got := d.AddedCount(); got != 2 {
		t.Errorf("AddedCount = %d, want 2", got)
	}
	// Every non-mentioned dataset stays non-nil but empty.
	for _, kind := range datasetKinds {
		if d.Added[kind] == nil || d.Removed[kind] == nil {
			t.Errorf("dataset %q has nil added/removed", kind)
		}
	}
}

func TestDiffEmptyOnIdenticalDigests(t *testing.T) {
	m := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Digest:        "abc123",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
	}
	dir := t.TempDir()
	p1 := writeModel(t, dir, "a.json", m)
	p2 := writeModel(t, dir, "b.json", m)
	m1, err := LoadReport(p1)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := LoadReport(p2)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := SnapshotOf(m1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SnapshotOf(m2)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Diff(s1, s2)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !d.Empty() {
		t.Errorf("identical reports must diff empty: %+v", d)
	}
	if !strings.Contains(d.Summary(), "no changes") {
		t.Errorf("empty summary must say no changes: %q", d.Summary())
	}
}

func TestDiffRejectsTargetMismatch(t *testing.T) {
	b := Snapshot{Target: "a.example.com", Sets: map[string][]string{}, Surfaces: map[string]SurfaceState{}}
	c := Snapshot{Target: "b.example.com", Sets: map[string][]string{}, Surfaces: map[string]SurfaceState{}}
	if _, err := Diff(b, c); err == nil {
		t.Fatal("cross-target diff must be rejected")
	}
}

func TestDiffRejectsSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"schema_version": report.SchemaVersion + 1, "target": "example.com"})
	path := filepath.Join(dir, "future.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil {
		t.Fatal("future schema version must be rejected")
	}
	if _, err := LoadReport(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file must be rejected")
	}
}

func TestDiffSurfaceMovements(t *testing.T) {
	b := Snapshot{
		Target: "example.com", Sets: map[string][]string{},
		Surfaces: map[string]SurfaceState{
			"url:https://a.example.com/admin": {Level: priority.LevelMedium, Score: 0.6},
			"url:https://a.example.com/gone":  {Level: priority.LevelHigh, Score: 0.9},
			"url:https://a.example.com/same":  {Level: priority.LevelLow, Score: 0.3},
		},
	}
	c := Snapshot{
		Target: "example.com", Sets: map[string][]string{},
		Surfaces: map[string]SurfaceState{
			"url:https://a.example.com/admin": {Level: priority.LevelHigh, Score: 0.85},
			"url:https://a.example.com/new":   {Level: priority.LevelHigh, Score: 0.9},
			"url:https://a.example.com/same":  {Level: priority.LevelLow, Score: 0.3},
		},
	}
	d, err := Diff(b, c)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %+v, want exactly the admin movement", d.Changed)
	}
	ch := d.Changed[0]
	if ch.OldLevel != "medium" || ch.NewLevel != "high" {
		t.Errorf("movement = %v -> %v, want medium -> high", ch.OldLevel, ch.NewLevel)
	}
	// Gone/new surfaces are NOT movements (presence axes cover datasets;
	// surface-only additions surface via their datasets, never here).
	for _, ch := range d.Changed {
		if strings.Contains(ch.Identity, "gone") || strings.Contains(ch.Identity, "/new") {
			t.Errorf("presence-only surface listed as movement: %v", ch)
		}
	}
	if !strings.Contains(d.Summary(), "1 surface movement") {
		t.Errorf("summary must cite the movement: %q", d.Summary())
	}
}

func TestDiffRenders(t *testing.T) {
	d := &Delta{
		Target:         "example.com",
		BaselineDigest: "base-digest-0000000000000000",
		CurrentDigest:  "cur-digest-1111111111111111",
		Added:          map[string][]string{},
		Removed:        map[string][]string{},
		Changed:        []SurfaceChange{},
	}
	for _, kind := range datasetKinds {
		d.Added[kind] = []string{}
		d.Removed[kind] = []string{}
	}
	d.Added["hosts"] = []string{"host:new.example.com"}
	d.Removed["urls"] = []string{"url:https://a.example.com/old"}
	dir := t.TempDir()
	jp := filepath.Join(dir, "delta.json")
	if err := WriteJSON(jp, d); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("delta.json is not JSON: %v", err)
	}
	if back["target"] != "example.com" {
		t.Errorf("target = %v", back["target"])
	}
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	md, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"new.example.com", "old", "New attack surface", "Removed"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("delta.md lacks %q:\n%s", want, md)
		}
	}
}

func TestHandoffOf(t *testing.T) {
	host := mustHost(t, "www.example.com")
	root := mustURL(t, "https://www.example.com/")
	deep := mustURL(t, "https://www.example.com/app.js")
	tech, err := asset.NewTechnology("nginx", asset.CategoryServer, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	edge, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToTechnology, tech.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodDetection, "tri", "sig", root.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	finding, err := asset.NewFinding(asset.Finding{
		RuleID: "tri.x", RuleName: "Tri", Category: "information",
		Subject: root.Identity(), Confidence: 0.8, Evidence: []asset.Evidence{ev},
		Priority: "high", Status: "open", Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	m := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{host},
		URLs:          []asset.URL{root, deep},
		Technologies:  []asset.Technology{tech},
		Relationships: []asset.Relationship{edge},
		Findings:      []asset.Finding{finding},
	}
	h := HandoffOf(m)
	if len(h.Targets) != 1 || h.Targets[0] != "https://www.example.com/" {
		t.Errorf("targets = %v, want only the root URL", h.Targets)
	}
	got := h.Tech["host:www.example.com"]
	if len(got) != 1 || got[0] != "nginx" {
		t.Errorf("tech = %v, want [nginx]", h.Tech)
	}
	if len(h.Severity) != 1 {
		t.Fatalf("severity entries = %d, want 1", len(h.Severity))
	}
	for id, sev := range h.Severity {
		if sev != "high" {
			t.Errorf("severity[%s] = %q, want high", id, sev)
		}
	}
	dir := t.TempDir()
	if err := WriteHandoff(dir, h); err != nil {
		t.Fatalf("WriteHandoff: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "https://www.example.com/\n" {
		t.Errorf("targets.txt = %q", raw)
	}
}

func TestLoadReportRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil {
		t.Fatal("corrupt JSON must be rejected")
	}
}

func TestLoadReportRejectsOldSchema(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"schema_version": report.SchemaVersion - 1, "target": "example.com"})
	path := filepath.Join(dir, "old-schema.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil {
		t.Fatal("stale schema version must be rejected, never coerced")
	}
}

func TestLoadReportRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: declares maxReportBytes+1 without writing it (fast,
	// hermetic) — the stat gate must fail closed before any decode.
	if err := f.Truncate(maxReportBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil {
		t.Fatal("over-bound input must be rejected fail-closed")
	}
}

func TestSnapshotOfRejectsNonCanonical(t *testing.T) {
	if _, err := SnapshotOf(nil); err == nil {
		t.Fatal("nil model must be rejected")
	}
	dir := t.TempDir()
	// Hand-rolled (never builder-normalized) host: LoadReport decodes it
	// fine, SnapshotOf must fail loudly naming the snapshot target.
	bad := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{{Name: "not a host!!"}},
	}
	m, err := LoadReport(writeModel(t, dir, "bad.json", bad))
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if _, err := SnapshotOf(m); err == nil {
		t.Fatal("non-canonical stored entry must fail the snapshot, never drift the delta")
	} else if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("snapshot error must name the offender target, got: %v", err)
	}
}

func TestSnapshotCoversDomainsIPsCerts(t *testing.T) {
	d, err := asset.NewDomain("example.com", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := asset.NewIP("93.184.216.34", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := asset.NewTLSCertificate("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	m := &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "example.com",
		Domains: []asset.Domain{d}, IPs: []asset.IP{ip}, TLSCertificates: []asset.TLSCertificate{cert},
	}
	dir := t.TempDir()
	loaded, err := LoadReport(writeModel(t, dir, "m.json", m))
	if err != nil {
		t.Fatal(err)
	}
	s, err := SnapshotOf(loaded)
	if err != nil {
		t.Fatalf("SnapshotOf: %v", err)
	}
	for kind, want := range map[string]string{
		"domains": "example.com", "ips": "93.184.216.34", "tls_certificates": "a1b2c3d4",
	} {
		if len(s.Sets[kind]) != 1 || !strings.Contains(s.Sets[kind][0], want) {
			t.Errorf("snapshot %s = %v, want one entry containing %q", kind, s.Sets[kind], want)
		}
	}
}

func TestHandoffEmptyTargets(t *testing.T) {
	host := mustHost(t, "www.example.com")
	deep := mustURL(t, "https://www.example.com/app.js")
	m := &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "example.com",
		Hosts: []asset.Host{host}, URLs: []asset.URL{deep},
	}
	h := HandoffOf(m)
	if len(h.Targets) != 0 {
		t.Errorf("targets = %v, want empty (no root URL observed)", h.Targets)
	}
	if h.Tech == nil || h.Severity == nil {
		t.Error("tech/severity maps must stay non-nil when empty")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "feed")
	if err := WriteHandoff(out, h); err != nil {
		t.Fatalf("WriteHandoff: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Errorf("targets.txt = %q, want empty", raw)
	}
}

func TestHandoffEmptyModel(t *testing.T) {
	h := HandoffOf(&report.Model{SchemaVersion: report.SchemaVersion, Target: "example.com"})
	if len(h.Targets) != 0 || len(h.Tech) != 0 || len(h.Severity) != 0 {
		t.Errorf("empty model must yield an empty handoff: %+v", h)
	}
	dir := t.TempDir()
	if err := WriteHandoff(filepath.Join(dir, "feed"), h); err != nil {
		t.Fatalf("empty handoff must still write both files: %v", err)
	}
	for _, name := range []string{"targets.txt", "handoff.json"} {
		if _, err := os.Stat(filepath.Join(dir, "feed", name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
}

func TestSeverityCoercion(t *testing.T) {
	for level, want := range map[string]string{
		"critical": "critical", "high": "high", "medium": "medium",
		"low": "low", "info": "info",
		"": "info", "weird": "info", "HIGH": "info", "Critical": "info",
	} {
		if got := priorityToSeverity(level); got != want {
			t.Errorf("priorityToSeverity(%q) = %q, want %q", level, got, want)
		}
	}
}

func TestHandoffQueryRootExcluded(t *testing.T) {
	root := mustURL(t, "https://www.example.com/")
	queryRoot := mustURL(t, "https://www.example.com/?x=1")
	deep := mustURL(t, "https://www.example.com/app.js")
	m := &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "example.com",
		URLs: []asset.URL{root, queryRoot, deep},
	}
	h := HandoffOf(m)
	if len(h.Targets) != 1 || h.Targets[0] != "https://www.example.com/" {
		t.Errorf("targets = %v, want only the bare root (query roots are parameterized observations)", h.Targets)
	}
}

func TestWriteNestedOutput(t *testing.T) {
	d := &Delta{
		Target: "example.com", Added: map[string][]string{},
		Removed: map[string][]string{}, Changed: []SurfaceChange{},
	}
	for _, kind := range datasetKinds {
		d.Added[kind] = []string{}
		d.Removed[kind] = []string{}
	}
	dir := t.TempDir()
	if err := WriteJSON(filepath.Join(dir, "a", "b", "delta.json"), d); err != nil {
		t.Fatalf("WriteJSON nested: %v", err)
	}
	if err := WriteMarkdown(filepath.Join(dir, "a", "b", "delta.md"), d); err != nil {
		t.Fatalf("WriteMarkdown nested: %v", err)
	}
	h := HandoffOf(&report.Model{SchemaVersion: report.SchemaVersion, Target: "example.com"})
	if err := WriteHandoff(filepath.Join(dir, "x", "y", "feed"), h); err != nil {
		t.Fatalf("WriteHandoff nested: %v", err)
	}
}

func TestCLIDiffMismatchPaths(t *testing.T) {
	// Mirrors runDiff's exact call order (load, load, snapshot, snapshot,
	// diff): a cross-target pair must fail the comparison, never coerce.
	dir := t.TempDir()
	a := writeModel(t, dir, "a.json", &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "a.example.com",
		Hosts: []asset.Host{mustHost(t, "x.a.example.com")},
	})
	b := writeModel(t, dir, "b.json", &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "b.example.com",
		Hosts: []asset.Host{mustHost(t, "x.b.example.com")},
	})
	ma, err := LoadReport(a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := LoadReport(b)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := SnapshotOf(ma)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := SnapshotOf(mb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Diff(sa, sb); err == nil {
		t.Fatal("cross-target comparison must be rejected")
	}
}

func TestDuplicateIdentities(t *testing.T) {
	h := mustHost(t, "dup.example.com")
	u := mustURL(t, "https://dup.example.com/")
	m := &report.Model{
		SchemaVersion: report.SchemaVersion, Target: "example.com",
		Hosts: []asset.Host{h, h}, URLs: []asset.URL{u, u},
	}
	dir := t.TempDir()
	loaded, err := LoadReport(writeModel(t, dir, "dup.json", m))
	if err != nil {
		t.Fatal(err)
	}
	s, err := SnapshotOf(loaded)
	if err != nil {
		t.Fatalf("SnapshotOf: %v", err)
	}
	if len(s.Sets["hosts"]) != 1 || len(s.Sets["urls"]) != 1 {
		t.Errorf("duplicates must merge by identity: hosts=%v urls=%v", s.Sets["hosts"], s.Sets["urls"])
	}
	single, err := SnapshotOf(&report.Model{
		SchemaVersion: report.SchemaVersion, Target: "example.com",
		Hosts: []asset.Host{h}, URLs: []asset.URL{u},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Diff(s, single)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() {
		t.Errorf("duplicated vs single must diff empty: %+v", d)
	}
	// stringSetDiff stays duplicate-free even for hand-rolled inputs.
	added, removed := stringSetDiff([]string{"a", "a"}, []string{"b", "b"})
	if len(added) != 1 || len(removed) != 1 {
		t.Errorf("stringSetDiff dup handling: added=%v removed=%v", added, removed)
	}
}

func TestMarkdownRenderBound(t *testing.T) {
	added := make([]string, 0, maxRenderIdentities+50)
	for i := 0; i < maxRenderIdentities+50; i++ {
		added = append(added, "host:h"+string(rune('a'+i%26))+".example.com")
	}
	d := &Delta{
		Target: "example.com", Added: map[string][]string{},
		Removed: map[string][]string{}, Changed: []SurfaceChange{},
	}
	for _, kind := range datasetKinds {
		d.Added[kind] = []string{}
		d.Removed[kind] = []string{}
	}
	d.Added["hosts"] = added
	dir := t.TempDir()
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "+50 more (complete list in delta.json)") {
		t.Errorf("bounded render must mark the cut explicitly:\n%s", md)
	}
	if !strings.Contains(d.Summary(), "hosts: +") {
		t.Errorf("summary counts stay exact: %q", d.Summary())
	}
	jp := filepath.Join(dir, "delta.json")
	if err := WriteJSON(jp, d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back["added"].(map[string]any)["hosts"].([]any)) != maxRenderIdentities+50 {
		t.Error("delta.json must stay complete (bounded end-to-end by input, never cut here)")
	}
}

// TestDiffDomainsIPsCertsAddedRemoved pins the generic presence loop on
// the three attack-surface datasets the hosts/urls tests never touch:
// domains, ips, and tls_certificates each report their own added/removed
// identities (one kept, one added, one removed per kind).
func TestDiffDomainsIPsCertsAddedRemoved(t *testing.T) {
	mustDomain := func(name string) asset.Domain {
		t.Helper()
		d, err := asset.NewDomain(name, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewDomain(%q): %v", name, err)
		}
		return d
	}
	mustIP := func(s string) asset.IP {
		t.Helper()
		ip, err := asset.NewIP(s, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewIP(%q): %v", s, err)
		}
		return ip
	}
	mustCert := func(fp string) asset.TLSCertificate {
		t.Helper()
		c, err := asset.NewTLSCertificate(fp, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewTLSCertificate: %v", err)
		}
		return c
	}
	const (
		oldCert  = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
		keepCert = "b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5b2c3d4e5"
		newCert  = "c3d4e5f6c3d4e5f6c3d4e5f6c3d4e5f6c3d4e5f6c3d4e5f6c3d4e5f6c3d4e5f6"
	)
	old := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Domains:       []asset.Domain{mustDomain("example.com"), mustDomain("gone.example.com")},
		IPs:           []asset.IP{mustIP("93.184.216.34"), mustIP("192.0.2.1")},
		TLSCertificates: []asset.TLSCertificate{
			mustCert(oldCert), mustCert(keepCert),
		},
	}
	cur := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Domains:       []asset.Domain{mustDomain("example.com"), mustDomain("new.example.com")},
		IPs:           []asset.IP{mustIP("93.184.216.34"), mustIP("203.0.113.7")},
		TLSCertificates: []asset.TLSCertificate{
			mustCert(keepCert), mustCert(newCert),
		},
	}
	dir := t.TempDir()
	oldM, err := LoadReport(writeModel(t, dir, "old.json", old))
	if err != nil {
		t.Fatalf("LoadReport old: %v", err)
	}
	curM, err := LoadReport(writeModel(t, dir, "new.json", cur))
	if err != nil {
		t.Fatalf("LoadReport new: %v", err)
	}
	oldS, err := SnapshotOf(oldM)
	if err != nil {
		t.Fatalf("SnapshotOf old: %v", err)
	}
	curS, err := SnapshotOf(curM)
	if err != nil {
		t.Fatalf("SnapshotOf new: %v", err)
	}
	d, err := Diff(oldS, curS)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for kind, want := range map[string][2]string{
		"domains":          [2]string{"new.example.com", "gone.example.com"},
		"ips":              [2]string{"203.0.113.7", "192.0.2.1"},
		"tls_certificates": [2]string{newCert[:12], oldCert[:12]},
	} {
		added, removed := want[0], want[1]
		if len(d.Added[kind]) != 1 || !strings.Contains(d.Added[kind][0], added) {
			t.Errorf("added %s = %v, want one entry containing %q", kind, d.Added[kind], added)
		}
		if len(d.Removed[kind]) != 1 || !strings.Contains(d.Removed[kind][0], removed) {
			t.Errorf("removed %s = %v, want one entry containing %q", kind, d.Removed[kind], removed)
		}
	}
	if d.Empty() {
		t.Error("delta must not be empty")
	}
}
