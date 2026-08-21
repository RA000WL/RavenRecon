package report

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

func nan() float64         { return math.NaN() }
func errCanceled() error   { return context.Canceled }
func errDeadline() error   { return context.DeadlineExceeded }
func errDNS() error        { return &net.DNSError{Err: "no such host", Name: "x.example.com"} }
func errPermission() error { return &os.PathError{Op: "open", Path: "x", Err: fs.ErrPermission} }
func errGeneric() error    { return errors.New("boom") }

func TestNewModelNormalizesAndSorts(t *testing.T) {
	m := testModel(t)
	if m.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", m.SchemaVersion, SchemaVersion)
	}
	if got := len(m.Hosts); got != 2 {
		t.Fatalf("hosts = %d, want 2 (duplicates merged)", got)
	}
	for i := 1; i < len(m.Hosts); i++ {
		if m.Hosts[i-1].Identity().String() >= m.Hosts[i].Identity().String() {
			t.Fatalf("hosts not sorted by identity: %q >= %q", m.Hosts[i-1].Name, m.Hosts[i].Name)
		}
	}
	if m.Stats.HostCount != 2 || m.Stats.URLCount != 2 || m.Stats.FindingCount != 1 {
		t.Fatalf("statistics counts wrong: %+v", m.Stats)
	}
	if m.Stats.Duration != 90_000 {
		t.Fatalf("duration = %d ms, want 90000", m.Stats.Duration)
	}
	if m.Summary.Target != "example.com" || m.Summary.Hosts != 2 || m.Summary.CacheHits != 4 {
		t.Fatalf("run summary wrong: %+v", m.Summary)
	}
}

func TestNewModelDeterministic(t *testing.T) {
	base := testContext(t)
	m1, err := NewModel(base)
	if err != nil {
		t.Fatalf("model 1: %v", err)
	}
	// Shuffle and duplicate entries: the same multiset must produce the
	// same model (digest included).
	shuffled := base
	shuffled.Hosts = []asset.Host{base.Hosts[2], base.Hosts[0], base.Hosts[1], base.Hosts[0]}
	shuffled.URLs = []asset.URL{base.URLs[1], base.URLs[0]}
	shuffled.Errors = []ErrorRecord{base.Errors[2], base.Errors[1], base.Errors[0]}
	m2, err := NewModel(shuffled)
	if err != nil {
		t.Fatalf("model 2: %v", err)
	}
	if m1.Digest != m2.Digest {
		t.Fatalf("digest changed under input reordering: %s vs %s", m1.Digest, m2.Digest)
	}
	if m1.Stats.AssetCount != m2.Stats.AssetCount {
		t.Fatalf("asset count changed under input reordering")
	}
}

func TestNewModelDigestCoversInputs(t *testing.T) {
	base := testContext(t)
	m1, err := NewModel(base)
	if err != nil {
		t.Fatalf("model 1: %v", err)
	}
	changed := base
	changed.Hosts = append(changed.Hosts, hostAsset(t, "extra.example.com"))
	m2, err := NewModel(changed)
	if err != nil {
		t.Fatalf("model 2: %v", err)
	}
	if m1.Digest == m2.Digest {
		t.Fatalf("digest did not change when the corpus changed")
	}
	errChanged := base
	errChanged.Errors = append(errChanged.Errors, ErrorRecord{Category: CategoryTLS, Stage: "tls", Message: "handshake failure"})
	m3, err := NewModel(errChanged)
	if err != nil {
		t.Fatalf("model 3: %v", err)
	}
	if m1.Digest == m3.Digest {
		t.Fatalf("digest did not change when the error log changed")
	}

	// Content-only changes (identity unchanged, exported bytes change)
	// must move the digest: the render-cache key rides on it, and a stale
	// key would serve the previous run's bytes.
	cases := []struct {
		name   string
		mutate func(t *testing.T, c *Context)
	}{
		{
			name: "technology version",
			mutate: func(t *testing.T, c *Context) {
				tech, err := asset.WithVersion(c.Technologies[0], "1.18.0")
				if err != nil {
					t.Fatalf("tech fixture: %v", err)
				}
				c.Technologies = []asset.Technology{tech}
			},
		},
		{
			name: "javascript content hash",
			mutate: func(t *testing.T, c *Context) {
				js := c.JavaScript[0]
				js.ContentHash = strings.Repeat("ab", 32)
				c.JavaScript = []asset.JavaScript{js}
			},
		},
		{
			name: "finding confidence",
			mutate: func(t *testing.T, c *Context) {
				f := c.Findings[0]
				f.Confidence = 0.4
				c.Findings = []asset.Finding{f}
			},
		},
		{
			name: "surface factor list",
			mutate: func(t *testing.T, c *Context) {
				s := c.Surfaces[0]
				s.Factors = append(s.Factors, priority.Factor{
					Name:           "interestingness:login",
					Weight:         0.3,
					Evidence:       []string{s.Identity.String()},
					Reason:         "login panel path observed on the surface",
					Recommendation: "Inventory authentication interfaces and record their requirements",
				})
				c.Surfaces = []priority.SurfaceAsset{s}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testContext(t)
			tc.mutate(t, &c)
			m, err := NewModel(c)
			if err != nil {
				t.Fatalf("model: %v", err)
			}
			if m.Digest == m1.Digest {
				t.Fatalf("digest did not change when only %s changed", tc.name)
			}
		})
	}
}

func TestNewModelErrorSummary(t *testing.T) {
	m := testModel(t)
	if m.Errors.Total != 6 {
		t.Fatalf("error total = %d, want 6 (2+3 merged + 1)", m.Errors.Total)
	}
	if m.Errors.Unique != 2 {
		t.Fatalf("error unique = %d, want 2", m.Errors.Unique)
	}
	if len(m.Errors.Categories) != 2 {
		t.Fatalf("categories = %d, want 2 (dns, http)", len(m.Errors.Categories))
	}
	if m.Errors.Categories[0].Category != CategoryDNS || m.Errors.Categories[0].Total != 5 {
		t.Fatalf("dns category wrong: %+v", m.Errors.Categories[0])
	}
	if m.Errors.Categories[1].Category != CategoryHTTP || m.Errors.Categories[1].Total != 1 {
		t.Fatalf("http category wrong: %+v", m.Errors.Categories[1])
	}
}

func TestNewModelRecommendationsProjection(t *testing.T) {
	m := testModel(t)
	if len(m.Recommendations) != 1 {
		t.Fatalf("recommendations = %d, want 1", len(m.Recommendations))
	}
	rec := m.Recommendations[0]
	if rec.Factor != "interestingness:admin" || rec.Text == "" || len(rec.Evidence) != 1 {
		t.Fatalf("recommendation wrong: %+v", rec)
	}
	if rec.Surface != m.Surfaces[0].Identity {
		t.Fatalf("recommendation surface does not match the scored surface")
	}
}

func TestNewModelSurfaceOrderingAndDedup(t *testing.T) {
	low := surfaceFixture(t, "https://a.example.com/x", 0.2)
	high := surfaceFixture(t, "https://b.example.com/y", 0.9)
	highDup := high
	highDup.Score = 0.1 // same identity, lower score: the dedup must keep 0.9
	m, err := NewModel(Context{Surfaces: []priority.SurfaceAsset{low, high, highDup}})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if len(m.Surfaces) != 2 {
		t.Fatalf("surfaces = %d, want 2", len(m.Surfaces))
	}
	if m.Surfaces[0].Identity != high.Identity || m.Surfaces[0].Score != 0.9 {
		t.Fatalf("highest surface first and retained: got %+v", m.Surfaces[0])
	}
	if m.Surfaces[1].Identity != low.Identity {
		t.Fatalf("second surface wrong: %+v", m.Surfaces[1])
	}
}

func TestNewModelRejectsNonCanonicalInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Context)
		want   string
	}{
		{
			name: "non-canonical host",
			mutate: func(c *Context) {
				c.Hosts = []asset.Host{{Name: "WWW.Example.COM", Prov: fixedProv("t")}}
			},
			want: "not canonical",
		},
		{
			name: "zero host identity",
			mutate: func(c *Context) {
				c.Hosts = []asset.Host{{Prov: fixedProv("t")}}
			},
			want: "report: host 0",
		},
		{
			name: "non-canonical url",
			mutate: func(c *Context) {
				u := urlAsset(t, "https://www.example.com/a")
				u.Path = ""
				c.URLs = []asset.URL{u}
			},
			want: "report: url 0",
		},
		{
			name: "finding without evidence",
			mutate: func(c *Context) {
				c.Findings = []asset.Finding{{RuleID: "r", RuleName: "n", Category: "c",
					Subject: hostAsset(t, "x.example.com").Identity(), Priority: "low", Status: "open", Created: fixedTime}}
			},
			want: "no evidence",
		},
		{
			name: "invalid error category",
			mutate: func(c *Context) {
				c.Errors = []ErrorRecord{{Category: ErrorCategory("bogus"), Stage: "s", Message: "m"}}
			},
			want: "invalid category",
		},
		{
			name: "surface with NaN score",
			mutate: func(c *Context) {
				s := surfaceFixture(t, "https://n.example.com/x", 0.5)
				s.Score = nan()
				c.Surfaces = []priority.SurfaceAsset{s}
			},
			want: "NaN",
		},
		{
			name: "surface with invalid level",
			mutate: func(c *Context) {
				s := surfaceFixture(t, "https://n.example.com/x", 0.5)
				s.Level = priority.PriorityLevel("extreme")
				c.Surfaces = []priority.SurfaceAsset{s}
			},
			want: "is invalid",
		},
		{
			name: "ended before started",
			mutate: func(c *Context) {
				c.StartedAt = fixedTime
				c.EndedAt = fixedTime.Add(-time.Second)
			},
			want: "precedes started-at",
		},
		{
			name: "negative cache stats",
			mutate: func(c *Context) {
				c.Cache = CacheStats{Hits: -1}
			},
			want: "negative value",
		},
		{
			name: "over-bound host list",
			mutate: func(c *Context) {
				c.Hosts = make([]asset.Host, maxModelHosts+1)
			},
			want: "over bound",
		},
		{
			name: "target with control character",
			mutate: func(c *Context) {
				c.Target = "example\x00.com"
			},
			want: "control character",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := testContext(t)
			tc.mutate(&base)
			_, err := NewModel(base)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestNewModelUnicodePassesThrough(t *testing.T) {
	// Unicode reaches the model through evidence values and error messages
	// (hostnames are ASCII-only by the asset model's contract).
	ev, err := asset.NewEvidence(asset.MethodHTML, "html:generator", "Généré Par Ünïcode 框架 v1", hostAsset(t, "u.example.com").Identity(), fixedProv("t"))
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	m, err := NewModel(Context{
		Target:    "example.com",
		StartedAt: fixedTime,
		EndedAt:   fixedTime,
		Evidence:  []asset.Evidence{ev},
		Errors:    []ErrorRecord{{Category: CategoryParsing, Stage: "parse", Message: "无效的响应 – retry", Count: 1}},
	})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if m.Evidence[0].Value != "Généré Par Ünïcode 框架 v1" {
		t.Fatalf("unicode evidence value mangled: %q", m.Evidence[0].Value)
	}
	if m.Errors.Categories[0].Samples[0].Message != "无效的响应 – retry" {
		t.Fatalf("unicode error message mangled: %q", m.Errors.Categories[0].Samples[0].Message)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("short", 512); got != "short" {
		t.Fatalf("short value changed: %q", got)
	}
	long := strings.Repeat("é", 600) // 1200 bytes
	got := truncateRunes(long, maxErrorMessageBytes)
	if len(got) > maxErrorMessageBytes {
		t.Fatalf("truncated value over bound: %d", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated value lacks marker: %q", got[len(got)-10:])
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorCategory
	}{
		{"nil", nil, CategoryUnknown},
		{"cancelled", errCanceled(), CategoryCancellation},
		{"deadline", errDeadline(), CategoryTimeout},
		{"dns", errDNS(), CategoryDNS},
		{"permission", errPermission(), CategoryPermission},
		{"unknown", errGeneric(), CategoryUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Fatalf("ClassifyError = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKnownErrorCategoriesSorted(t *testing.T) {
	cats := KnownErrorCategories()
	for i := 1; i < len(cats); i++ {
		if cats[i-1] >= cats[i] {
			t.Fatalf("categories not sorted: %q >= %q", cats[i-1], cats[i])
		}
	}
	for _, c := range cats {
		if !c.Valid() {
			t.Fatalf("known category %q reports invalid", c)
		}
	}
}

// TestReportHonestDuration pins OPT-P0-5: the report's run duration is
// honest wall-clock (pipeline's StartAt/EndAt via the injected clock),
// not the summary-write time. A model bracketed 5s apart must carry
// Duration 5s (5000 ms) in both Statistics and RunSummary, the JSON
// export must render duration_ms 5000, and the digest must remain stable
// when only wall-clock timing changes (identical content, different
// brackets, same digest — the render-cache key is content-addressed).
func TestReportHonestDuration(t *testing.T) {
	start := fixedTime
	end := fixedTime.Add(5 * time.Second)

	// Honest 5s bracket.
	c1 := testContext(t)
	c1.StartedAt = start
	c1.EndedAt = end
	m1, err := NewModel(c1)
	if err != nil {
		t.Fatalf("model honest: %v", err)
	}
	if m1.StartedAt != start || m1.EndedAt != end {
		t.Fatalf("model bracket = %v..%v, want %v..%v", m1.StartedAt, m1.EndedAt, start, end)
	}
	if m1.Stats.Duration != 5000 {
		t.Fatalf("statistics duration = %d ms, want 5000", m1.Stats.Duration)
	}
	if m1.Summary.Duration != 5000 {
		t.Fatalf("summary duration = %d ms, want 5000", m1.Summary.Duration)
	}
	if !m1.Summary.StartedAt.Equal(start) || !m1.Summary.EndedAt.Equal(end) {
		t.Fatalf("summary bracket = %v..%v, want %v..%v", m1.Summary.StartedAt, m1.Summary.EndedAt, start, end)
	}
	if !m1.Summary.EndedAt.After(m1.Summary.StartedAt) {
		t.Fatalf("summary EndAt %v not after StartAt %v", m1.Summary.EndedAt, m1.Summary.StartedAt)
	}

	// JSON export carries the honest wall-clock: started_at < ended_at
	// and duration_ms 5000 (the machine-readable report the pipeline
	// exposes). The digest input excludes wall-clock, so the JSON is
	// the only place the honest duration surfaces.
	jsonRep := builtin(t, "json")
	parts := renderToMem(t, jsonRep, m1)
	raw, ok := parts[""]
	if !ok || len(raw) == 0 {
		t.Fatalf("json render produced no bytes")
	}
	var doc struct {
		StartedAt time.Time  `json:"started_at"`
		EndedAt   time.Time  `json:"ended_at"`
		Stats     Statistics `json:"statistics"`
		Summary   RunSummary `json:"summary"`
		Digest    string     `json:"digest"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode json export: %v", err)
	}
	if doc.Stats.Duration != 5000 {
		t.Fatalf("json statistics duration_ms = %d, want 5000", doc.Stats.Duration)
	}
	if doc.Summary.Duration != 5000 {
		t.Fatalf("json summary duration_ms = %d, want 5000", doc.Summary.Duration)
	}
	if !doc.Summary.StartedAt.Equal(start) || !doc.Summary.EndedAt.Equal(end) {
		t.Fatalf("json summary bracket = %v..%v, want %v..%v", doc.Summary.StartedAt, doc.Summary.EndedAt, start, end)
	}
	if doc.Summary.Duration == 0 {
		t.Fatalf("json summary duration_ms 0, want >0 (honest wall-clock)")
	}

	// Digest stability: identical content with a different wall-clock
	// bracket must produce the same digest. The wall-clock is
	// presentation-only — it never perturbs the cache key.
	c2 := testContext(t)
	c2.StartedAt = start.Add(1 * time.Hour)
	c2.EndedAt = c2.StartedAt.Add(5 * time.Second)
	m2, err := NewModel(c2)
	if err != nil {
		t.Fatalf("model second bracket: %v", err)
	}
	if m2.Stats.Duration != 5000 || m2.Summary.Duration != 5000 {
		t.Fatalf("second bracket duration = %d / %d, want 5000", m2.Stats.Duration, m2.Summary.Duration)
	}
	if m1.Digest != m2.Digest {
		t.Fatalf("digest changed when only wall-clock timing changed: %s vs %s (timing must be excluded from digest)", m1.Digest, m2.Digest)
	}
	// WorkerTime jitter must also not perturb the digest: same logical
	// report with different worker-time still digests equal.
	c3 := testContext(t)
	c3.StartedAt = start
	c3.EndedAt = end
	c3.Runtime.WorkerTime = Ms(1234 * time.Millisecond)
	m3, err := NewModel(c3)
	if err != nil {
		t.Fatalf("model worker-time variant: %v", err)
	}
	if m3.Digest != m1.Digest {
		t.Fatalf("digest changed when only worker-time changed: %s vs %s (worker-time must be excluded)", m1.Digest, m3.Digest)
	}
	// Zero bracket stays honest: duration 0, digest still stable.
	c0 := testContext(t)
	c0.StartedAt = start
	c0.EndedAt = start
	m0, err := NewModel(c0)
	if err != nil {
		t.Fatalf("model zero bracket: %v", err)
	}
	if m0.Stats.Duration != 0 || m0.Summary.Duration != 0 {
		t.Fatalf("zero bracket duration = %d / %d, want 0", m0.Stats.Duration, m0.Summary.Duration)
	}
	if m0.Digest != m1.Digest {
		t.Fatalf("digest changed between zero and honest bracket: %s vs %s (wall-clock must be excluded)", m0.Digest, m1.Digest)
	}
}
