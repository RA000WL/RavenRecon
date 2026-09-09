package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/report"
)

var takeoverTestTime = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// mustTakeoverFinding builds one synthetic canonical takeover finding
// (synthetic values only, fixed clock) for hermetic bloom tests.
func mustTakeoverFinding(t *testing.T, ruleID, hostName, provider string) asset.Finding {
	t.Helper()
	h := mustHost(t, hostName)
	ev, err := asset.NewEvidence(asset.MethodDetection, "detect:"+ruleID, "observed", h.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	var meta map[string]string
	if provider != "" {
		meta = map[string]string{"provider": provider}
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleID + " rule",
		Category:   "information",
		Subject:    h.Identity(),
		Confidence: 0.6,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   "info",
		Status:     "open",
		Created:    takeoverTestTime,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// takeoverModels builds two synthetic report exports sharing host a's
// unclaimed/github.io finding while churning host b's: baseline tracks
// unclaimed/herokuapp.com, current tracks
// provider-confirmed/herokuapp.com instead.
func takeoverModels(t *testing.T) (old, cur *report.Model) {
	t.Helper()
	old = &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "a.example.com", "github.io"),
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "b.example.com", "herokuapp.com"),
		},
	}
	cur = &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "a.example.com", "github.io"),
			mustTakeoverFinding(t, "takeover.cname.provider-confirmed", "b.example.com", "herokuapp.com"),
		},
	}
	return old, cur
}

func takeoverDelta(t *testing.T, old, cur *report.Model) *Delta {
	t.Helper()
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
	return d
}

// TestTakeoverBloomAddedRemovedByProvider pins the acceptance shape:
// added/removed provider-confirmed + unclaimed counts by provider, in
// deterministic (rule, provider) order.
func TestTakeoverBloomAddedRemovedByProvider(t *testing.T) {
	old, cur := takeoverModels(t)
	d := takeoverDelta(t, old, cur)
	if d.Takeover == nil {
		t.Fatalf("bloom nil, want tracked (takeover findings on both sides)")
	}
	if len(d.Takeover.Added) != 1 || len(d.Takeover.Removed) != 1 {
		t.Fatalf("bloom = %+v, want exactly one added + one removed cell", d.Takeover)
	}
	added := d.Takeover.Added[0]
	if added.Rule != "takeover.cname.provider-confirmed" || added.Provider != "herokuapp.com" || added.Count != 1 {
		t.Errorf("added = %+v, want provider-confirmed/herokuapp.com x1", added)
	}
	removed := d.Takeover.Removed[0]
	if removed.Rule != "takeover.cname.unclaimed" || removed.Provider != "herokuapp.com" || removed.Count != 1 {
		t.Errorf("removed = %+v, want unclaimed/herokuapp.com x1", removed)
	}
	if d.Takeover.AddedTotal() != 1 || d.Takeover.RemovedTotal() != 1 {
		t.Errorf("totals +%d/-%d, want +1/-1", d.Takeover.AddedTotal(), d.Takeover.RemovedTotal())
	}
	if d.Takeover.Empty() {
		t.Error("bloom with cells must not be empty")
	}
	// The bloom projects the findings axis: the underlying presence
	// delta still carries the same identities, and the bloom never
	// changes the emptiness/count contract.
	if d.Empty() {
		t.Error("delta with takeover churn must not be empty")
	}
	if got := d.AddedCount(); got != 1 {
		t.Errorf("AddedCount = %d, want 1 (the provider-confirmed identity)", got)
	}

	summary := d.Summary()
	for _, want := range []string{
		"takeover: +1/-1",
		"takeover added: takeover.cname.provider-confirmed provider=herokuapp.com x1",
		"takeover removed: takeover.cname.unclaimed provider=herokuapp.com x1",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}

	dir := t.TempDir()
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	md, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"## Takeover",
		"- added `takeover.cname.provider-confirmed provider=herokuapp.com x1`",
		"- removed `takeover.cname.unclaimed provider=herokuapp.com x1`",
	} {
		if !strings.Contains(string(md), want) {
			t.Errorf("delta.md lacks %q:\n%s", want, md)
		}
	}

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
	bloom, ok := back["takeover"].(map[string]any)
	if !ok {
		t.Fatalf("delta.json lacks the takeover projection: %v", back)
	}
	if len(bloom["added"].([]any)) != 1 || len(bloom["removed"].([]any)) != 1 {
		t.Errorf("delta.json bloom = %v, want one cell per side", bloom)
	}
}

// TestTakeoverBloomDeterministicOrder pins sorted (rule, provider)
// cells across several providers, plus byte-stable JSON over reruns.
func TestTakeoverBloomDeterministicOrder(t *testing.T) {
	old := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
	}
	cur := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts: []asset.Host{
			mustHost(t, "a.example.com"),
			mustHost(t, "s1.example.com"), mustHost(t, "s2.example.com"),
			mustHost(t, "s3.example.com"), mustHost(t, "s4.example.com"),
		},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "s1.example.com", "shopify.com"),
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "s2.example.com", "github.io"),
			mustTakeoverFinding(t, "takeover.cname.provider-confirmed", "s3.example.com", "herokuapp.com"),
			mustTakeoverFinding(t, "takeover.cname.provider-confirmed", "s4.example.com", "github.io"),
		},
	}
	d := takeoverDelta(t, old, cur)
	if d.Takeover == nil {
		t.Fatalf("bloom nil, want tracked")
	}
	wantAdded := []TakeoverCount{
		{Rule: "takeover.cname.provider-confirmed", Provider: "github.io", Count: 1},
		{Rule: "takeover.cname.provider-confirmed", Provider: "herokuapp.com", Count: 1},
		{Rule: "takeover.cname.unclaimed", Provider: "github.io", Count: 1},
		{Rule: "takeover.cname.unclaimed", Provider: "shopify.com", Count: 1},
	}
	if len(d.Takeover.Added) != len(wantAdded) {
		t.Fatalf("added = %+v, want %+v", d.Takeover.Added, wantAdded)
	}
	for i, want := range wantAdded {
		if d.Takeover.Added[i] != want {
			t.Errorf("added[%d] = %+v, want %+v", i, d.Takeover.Added[i], want)
		}
	}
	if len(d.Takeover.Removed) != 0 {
		t.Errorf("removed = %+v, want empty (pure-addition run)", d.Takeover.Removed)
	}
	// Byte-stable JSON across reruns.
	dir := t.TempDir()
	jp := filepath.Join(dir, "delta.json")
	if err := WriteJSON(jp, d); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(jp)
	d2 := takeoverDelta(t, old, cur)
	if err := WriteJSON(jp, d2); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(jp)
	if string(first) != string(second) {
		t.Fatalf("bloom JSON not byte-stable:\n%s\n%s", first, second)
	}
}

// TestTakeoverBloomAbsentWhenEmpty pins the documented choice:
// reports with no takeover findings (or only non-takeover findings)
// carry a nil bloom — the human section is absent, never an empty
// block — while delta.json records the explicit null.
func TestTakeoverBloomAbsentWhenEmpty(t *testing.T) {
	old := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
	}
	cur := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")},
	}
	d := takeoverDelta(t, old, cur)
	if d.Takeover != nil {
		t.Fatalf("bloom = %+v, want nil (no takeover findings on either side)", d.Takeover)
	}
	if strings.Contains(d.Summary(), "takeover") {
		t.Errorf("summary must not carry a takeover section when untracked:\n%s", d.Summary())
	}
	dir := t.TempDir()
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(mp)
	if strings.Contains(string(md), "Takeover") {
		t.Errorf("delta.md must not carry a Takeover section when untracked:\n%s", md)
	}
	jp := filepath.Join(dir, "delta.json")
	if err := WriteJSON(jp, d); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(jp)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	v, ok := back["takeover"]
	if !ok {
		t.Fatalf("delta.json must carry the fixed takeover key (null when untracked): %v", back)
	}
	if v != nil {
		t.Errorf("delta.json takeover = %v, want null when untracked", v)
	}

	// Non-takeover findings alone still leave the bloom absent.
	h := mustHost(t, "a.example.com")
	ev, err := asset.NewEvidence(asset.MethodDetection, "detect:other", "observed", h.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := asset.NewFinding(asset.Finding{
		RuleID: "triage.xss", RuleName: "XSS", Category: "information",
		Subject: h.Identity(), Confidence: 0.6, Evidence: []asset.Evidence{ev},
		Priority: "info", Status: "open", Created: takeoverTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	withOther := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{h},
		Findings:      []asset.Finding{other},
	}
	d2 := takeoverDelta(t, old, withOther)
	if d2.Takeover != nil {
		t.Fatalf("non-takeover findings must not track a bloom: %+v", d2.Takeover)
	}
}

// TestTakeoverBloomTrackedUnchanged pins the middle state: takeover
// present on a side with no count change yields a non-nil but empty
// bloom. A fully empty delta stays one line (no section); a delta that
// is non-empty elsewhere names the tracked-no-change explicitly.
func TestTakeoverBloomTrackedUnchanged(t *testing.T) {
	base := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "a.example.com", "github.io"),
		},
	}
	twin := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "a.example.com", "github.io"),
		},
	}
	d := takeoverDelta(t, base, twin)
	if !d.Empty() {
		t.Fatalf("identical takeover reports must diff empty: %+v", d)
	}
	if d.Takeover == nil {
		t.Fatalf("bloom nil, want tracked-but-unchanged (takeover on both sides)")
	}
	if !d.Takeover.Empty() {
		t.Fatalf("bloom = %+v, want empty cells", d.Takeover)
	}
	if strings.Contains(d.Summary(), "takeover") {
		t.Errorf("fully empty delta must stay one line (no takeover section):\n%s", d.Summary())
	}

	moved := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.unclaimed", "a.example.com", "github.io"),
		},
	}
	d2 := takeoverDelta(t, base, moved)
	if d2.Empty() {
		t.Fatalf("host addition must not diff empty")
	}
	if d2.Takeover == nil || !d2.Takeover.Empty() {
		t.Fatalf("bloom = %+v, want tracked-but-unchanged alongside the host change", d2.Takeover)
	}
	if !strings.Contains(d2.Summary(), "takeover: +0/-0") {
		t.Errorf("summary must name the tracked-no-change explicitly:\n%s", d2.Summary())
	}
	dir := t.TempDir()
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d2); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(mp)
	if !strings.Contains(string(md), "Takeover tracked, no count change.") {
		t.Errorf("delta.md must name the tracked-no-change explicitly:\n%s", md)
	}
}

// TestTakeoverBloomUnknownProvider pins the deterministic fallback:
// a takeover finding without provider metadata counts under "unknown"
// instead of vanishing silently.
func TestTakeoverBloomUnknownProvider(t *testing.T) {
	old := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
	}
	cur := &report.Model{
		SchemaVersion: report.SchemaVersion,
		Target:        "example.com",
		Hosts:         []asset.Host{mustHost(t, "a.example.com")},
		Findings: []asset.Finding{
			mustTakeoverFinding(t, "takeover.cname.dangling", "a.example.com", ""),
		},
	}
	d := takeoverDelta(t, old, cur)
	if d.Takeover == nil {
		t.Fatalf("bloom nil, want tracked (provider-less takeover finding still counts)")
	}
	if len(d.Takeover.Added) != 1 {
		t.Fatalf("added = %+v, want one unknown-provider cell", d.Takeover.Added)
	}
	got := d.Takeover.Added[0]
	if got.Rule != "takeover.cname.dangling" || got.Provider != "unknown" || got.Count != 1 {
		t.Errorf("added = %+v, want dangling/unknown x1", got)
	}
	if !strings.Contains(d.Summary(), "provider=unknown x1") {
		t.Errorf("summary must cite the unknown cell:\n%s", d.Summary())
	}
}

// TestTakeoverBloomRenderUncapped pins the accepted render asymmetry
// (see the TODO at Delta.Summary): takeover bloom cells render complete
// in both human outputs with no maxRenderIdentities cut and no "+N more"
// marker — one cell per distinct (rule, provider) keeps shipped-pack
// cardinality in the single digits, and delta.json carries the complete
// bloom either way.
func TestTakeoverBloomRenderUncapped(t *testing.T) {
	const cells = maxRenderIdentities + 5
	added := make([]TakeoverCount, 0, cells)
	for i := 0; i < cells; i++ {
		added = append(added, TakeoverCount{
			Rule:     "takeover.cname.unclaimed",
			Provider: fmt.Sprintf("provider-%04d.example", i),
			Count:    1,
		})
	}
	sortTakeoverCells(added)
	// The bloom never affects Empty, so one presence change on a real
	// axis keeps the delta non-empty for the Markdown path.
	d := &Delta{
		Target:  "example.com",
		Added:   map[string][]string{"hosts": {"b.example.com"}},
		Removed: map[string][]string{},
		Takeover: &TakeoverBloom{
			Added:   added,
			Removed: []TakeoverCount{},
		},
	}
	sum := d.Summary()
	for _, c := range added {
		if !strings.Contains(sum, formatTakeoverCell(c)) {
			t.Fatalf("summary drops bloom cell %s (takeover renders uncapped)", formatTakeoverCell(c))
		}
	}
	if strings.Contains(sum, "more (complete list in delta.json)") {
		t.Fatalf("summary must not cut the takeover bloom:\n%s", sum)
	}
	dir := t.TempDir()
	mp := filepath.Join(dir, "delta.md")
	if err := WriteMarkdown(mp, d); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(mp)
	for _, c := range added {
		if !strings.Contains(string(md), formatTakeoverCell(c)) {
			t.Fatalf("delta.md drops bloom cell %s (takeover renders uncapped)", formatTakeoverCell(c))
		}
	}
	if strings.Contains(string(md), "more (complete list in delta.json)") {
		t.Fatalf("delta.md must not cut the takeover bloom:\n%s", md)
	}
	// delta.json stays the complete record regardless.
	jp := filepath.Join(dir, "delta.json")
	if err := WriteJSON(jp, d); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(jp)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	tk, ok := back["takeover"].(map[string]any)
	if !ok {
		t.Fatalf("delta.json must carry the takeover bloom: %v", back)
	}
	got, ok := tk["added"].([]any)
	if !ok || len(got) != cells {
		t.Fatalf("delta.json added cells %v, want %d complete cells", tk["added"], cells)
	}
}
