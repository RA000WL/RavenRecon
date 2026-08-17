package detect

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testSubjectURL is the canonical subject asset every fixture finding cites.
var testSubjectURL = "https://example.com/admin"

// testSnapshot builds a small canonical corpus.
func testSnapshot(t testing.TB) Snapshot {
	t.Helper()
	u, err := asset.ParseURL(testSubjectURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	host, err := asset.NewHost("example.com", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	tech, err := asset.NewTechnology("nginx", "server", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "server", "nginx",
		u.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	endpoint, err := asset.NewEndpoint("GET", testSubjectURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return Snapshot{
		Assets:       []asset.Identity{u.Identity(), host.Identity()},
		Evidence:     []asset.Evidence{ev},
		Technologies: []asset.Technology{tech},
		Endpoints:    []asset.Endpoint{endpoint},
	}
}

// ruleOptions mutates a fixture rule.
type ruleOptions struct {
	deps     []string
	detector Detector
	category Category
	author   string
	version  string
	name     string
	id       string
	timeout  time.Duration
	inputs   []RuleInput
	outputs  []RuleOutput
	cost     Cost
	required []asset.Kind
	desc     string
}

// makeRule builds a valid fixture rule; nil detector defaults to a detector
// that emits one canonical finding about the fixture subject.
func makeRule(t testing.TB, id string, opts *ruleOptions) Rule {
	t.Helper()
	if opts == nil {
		opts = &ruleOptions{}
	}
	detector := opts.detector
	if detector == nil {
		detector = findingDetector(t, id, "Rule "+id, CategoryInformation, 1)
	}
	r := Rule{
		ID:            id,
		Name:          "Rule " + id,
		Description:   "Synthetic test rule " + id,
		Category:      CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []RuleInput{InputAssets},
		Outputs:       []RuleOutput{OutputFindings},
		Detector:      detector,
		EstimatedCost: CostLow,
		Timeout:       5 * time.Second,
		Author:        "ravenrecon-test",
		Enabled:       true,
	}
	if opts.id != "" {
		r.ID = opts.id
	}
	if opts.name != "" {
		r.Name = opts.name
	}
	if opts.desc != "" {
		r.Description = opts.desc
	}
	if opts.category != "" {
		r.Category = opts.category
	}
	if opts.version != "" {
		r.Version = opts.version
	}
	if opts.author != "" {
		r.Author = opts.author
	}
	if opts.timeout != 0 {
		r.Timeout = opts.timeout
	}
	if opts.inputs != nil {
		r.Inputs = opts.inputs
	}
	if opts.outputs != nil {
		r.Outputs = opts.outputs
	}
	if opts.cost != "" {
		r.EstimatedCost = opts.cost
	}
	if len(opts.deps) > 0 {
		r.Dependencies = opts.deps
	}
	if len(opts.required) > 0 {
		r.RequiredAssetTypes = opts.required
	}
	return r
}

// makeRuleDisabled builds a disabled fixture rule.
func makeRuleDisabled(t testing.TB, id string) Rule {
	r := makeRule(t, id, nil)
	r.Enabled = false
	return r
}

// findingDetector returns a detector emitting n canonical findings about the
// fixture subject, attributed to the given rule metadata.
func findingDetector(t testing.TB, ruleID, ruleName string, category Category, n int) Detector {
	t.Helper()
	return func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		findings := make([]asset.Finding, 0, n)
		for i := 0; i < n; i++ {
			f, err := testFinding(dctx, ruleID, ruleName, category, i)
			if err != nil {
				return nil, err
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

// testFinding builds one canonical finding about the fixture subject.
func testFinding(dctx *Context, ruleID, ruleName string, category Category, seq int) (asset.Finding, error) {
	return subjectFinding(dctx, ruleID, ruleName, category,
		asset.Identity{Kind: asset.KindURL, Value: testSubjectURL}, seq)
}

// subjectFinding builds one canonical finding about an arbitrary subject
// (the run-cap tests cite many distinct observed subjects).
func subjectFinding(dctx *Context, ruleID, ruleName string, category Category, subject asset.Identity, seq int) (asset.Finding, error) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	if dctx != nil && dctx.Clock != nil {
		now = dctx.Clock.Now().UTC()
	}
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID,
		fmt.Sprintf("synthetic signal %d on the subject", seq), subject, asset.Provenance{Source: "detect"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   category.String(),
		Subject:    subject,
		Confidence: 0.5,
		Evidence:   []asset.Evidence{ev},
		Priority:   PriorityMedium.String(),
		Status:     StatusOpen.String(),
		Created:    now,
	})
}

// newTestRegistry registers every rule and fails the test on the first
// rejection.
func newTestRegistry(t testing.TB, rules ...Rule) *Registry {
	t.Helper()
	reg := NewRegistry()
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("register rule %q: %v", r.ID, err)
		}
	}
	return reg
}

// countStatus counts the results with the given status.
func countStatus(rep Report, status RuleStatus) int {
	n := 0
	for _, r := range rep.Rules {
		if r.Status == status {
			n++
		}
	}
	return n
}

// resultOf returns the result of one rule.
func resultOf(t *testing.T, rep Report, id string) RuleResult {
	t.Helper()
	for _, r := range rep.Rules {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("rule %q missing from the report", id)
	return RuleResult{}
}

// recordingLogger captures every log entry (concurrency-safe).
type recordingLogger struct {
	mu      sync.Mutex
	entries []LogEntry
}

func (l *recordingLogger) Log(level LogLevel, ruleID, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, LogEntry{Level: level, Rule: ruleID, Message: message})
}

func (l *recordingLogger) snapshot() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}
