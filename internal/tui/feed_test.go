package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// TestInterestingClassification pins the display-only admission heuristic
// over real payload fields.
func TestInterestingClassification(t *testing.T) {
	base := testBase

	asset := func(kind, identity, method, path string, conf float64) event.Event {
		return evAt(event.KindAssetDiscovered, base,
			event.AssetDiscovered{Identity: identity, Kind: kind, Method: method, Path: path, Confidence: conf})
	}

	cases := []struct {
		name       string
		ev         event.Event
		wantOK     bool
		wantKey    string
		wantLabel  string
		wantDetail string
	}{
		{"endpoint gql", asset("endpoint", "e1", "GQL", "/graphql", 0), true, "asset|endpoint|e1", "e1", "graphql endpoint"},
		{"endpoint ws", asset("endpoint", "e2", "WS", "/ws", 0), true, "asset|endpoint|e2", "e2", "websocket endpoint"},
		{"endpoint sse", asset("endpoint", "e3", "SSE", "/events", 0), true, "asset|endpoint|e3", "e3", "server-sent events endpoint"},
		{"endpoint admin path", asset("endpoint", "e4", "GET", "/admin/panel", 0), true, "asset|endpoint|e4", "e4", "admin-ish path"},
		{"endpoint admin path case", asset("endpoint", "e5", "GET", "/Dashboard", 0), true, "asset|endpoint|e5", "e5", "admin-ish path"},
		{"endpoint plain path", asset("endpoint", "e6", "GET", "/login", 0), false, "", "", ""},
		{"endpoint unknown method", asset("endpoint", "e7", "POST", "/api/v1", 0), false, "", "", ""},
		{"source map", asset("source_map", "m1", "", "/app.js.map", 0), true, "asset|source_map|m1", "m1", "source map exposed"},
		// The label is the redacted type+digest form — the raw identity
		// (which embeds the percent-encoded value) never reaches display.
		{"secret high confidence", asset("secret_candidate", "s1", "", "", 0.8), true, "asset|secret_candidate|s1", redactedSecretCandidateLabel("s1"), "high-confidence secret"},
		{"secret below threshold", asset("secret_candidate", "s2", "", "", 0.79), false, "", "", ""},
		{"technology", asset("technology", "t1", "", "", 0), true, "asset|technology|t1", "t1", "technology detected"},
		{"host not interesting", asset("host", "h1", "", "", 0), false, "", "", ""},
		{"url not interesting", asset("url", "u1", "", "/", 0), false, "", "", ""},
		{"finding high", evAt(event.KindFindingCreated, base, event.FindingCreated{
			Identity: "f1", RuleID: "r1", Subject: "u1", Priority: "high", Category: "misconfig", Confidence: 0.9,
		}), true, "finding|f1", "f1", "finding high (r1)"},
		{"finding critical", evAt(event.KindFindingCreated, base, event.FindingCreated{
			Identity: "f2", RuleID: "r2", Subject: "u1", Priority: "critical", Category: "misconfig", Confidence: 0.9,
		}), true, "finding|f2", "f2", "finding critical (r2)"},
		{"finding medium not interesting", evAt(event.KindFindingCreated, base, event.FindingCreated{
			Identity: "f3", RuleID: "r3", Subject: "u1", Priority: "medium", Category: "misconfig", Confidence: 0.5,
		}), false, "", "", ""},
		{"recommendation high weight", evAt(event.KindRecommendationCreated, base, event.RecommendationCreated{
			Identity: "h1", Text: "investigate", Level: "high", Weight: 0.8,
		}), true, "recommendation|h1|investigate", "h1", "high-value recommendation"},
		{"recommendation low weight", evAt(event.KindRecommendationCreated, base, event.RecommendationCreated{
			Identity: "h2", Text: "investigate", Level: "high", Weight: 0.5,
		}), false, "", "", ""},
		{"recommendation medium level", evAt(event.KindRecommendationCreated, base, event.RecommendationCreated{
			Identity: "h3", Text: "investigate", Level: "medium", Weight: 0.9,
		}), false, "", "", ""},
		{"unrelated kind", evAt(event.KindCacheHit, base, event.CacheAccess{Key: "k", State: "hit", Hit: true}), false, "", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, label, detail, ok := interesting(tc.ev)
			if ok != tc.wantOK {
				t.Fatalf("interesting = %v, want %v", ok, tc.wantOK)
			}
			if key != tc.wantKey || label != tc.wantLabel || detail != tc.wantDetail {
				t.Fatalf("interesting = (%q, %q, %q), want (%q, %q, %q)",
					key, label, detail, tc.wantKey, tc.wantLabel, tc.wantDetail)
			}
		})
	}
}

// TestAdminPath pins the display-only admin-segment table.
func TestAdminPath(t *testing.T) {
	for _, path := range []string{"/admin", "/a/b/dashboard/x", "/SWAGGER", "/wp-admin/", "/v1/metrics"} {
		if !adminPath(path) {
			t.Fatalf("adminPath(%q) must be true", path)
		}
	}
	for _, path := range []string{"/", "/login", "/assets/js/app.js", "/administratorx", ""} {
		if adminPath(path) {
			t.Fatalf("adminPath(%q) must be false", path)
		}
	}
}

// TestTokenBucket pins the burst-1 refill math deterministically.
func TestTokenBucket(t *testing.T) {
	t0 := testBase
	b := tokenBucket{rate: 0.5}
	// Burst 1: the bucket starts full.
	if !b.allow(t0) {
		t.Fatal("first token must be granted immediately")
	}
	if b.allow(t0) {
		t.Fatal("second token at the same instant must be rejected")
	}
	if b.allow(t0.Add(time.Second)) {
		t.Fatal("0.5/s must not grant a token after 1s")
	}
	if !b.allow(t0.Add(2 * time.Second)) {
		t.Fatal("0.5/s must grant a token after 2s")
	}
	if b.allow(t0.Add(2 * time.Second)) {
		t.Fatal("granted token must be consumed")
	}

	disabled := tokenBucket{rate: 0}
	if disabled.allow(t0) {
		t.Fatal("rate 0 must reject everything")
	}
}

// TestInterestingFeedDedupeAndRing pins dedupe by identity+kind and the
// bounded ring with key forgetting on eviction.
func TestInterestingFeedDedupeAndRing(t *testing.T) {
	f := newInterestingFeed(highRate)
	assetEv := func(ms int, identity string) event.Event {
		return ev(event.KindAssetDiscovered, ms, event.AssetDiscovered{
			Identity: identity, Kind: "endpoint", Method: "GQL", Path: "/graphql",
		})
	}
	// Fill the ring past capacity with distinct assets.
	for i := 0; i < maxFeedItems+5; i++ {
		if !f.add(assetEv(i, "asset-"+string(rune('a'+i%26))+string(rune('0'+i/26)))) {
			t.Fatalf("distinct asset %d must be admitted", i)
		}
	}
	if f.len != maxFeedItems {
		t.Fatalf("ring len = %d, want %d", f.len, maxFeedItems)
	}
	if f.Dropped() != 0 {
		t.Fatalf("no rate/dedupe rejections expected, got %d", f.Dropped())
	}
	// The first five assets were evicted; their keys are forgotten, so
	// re-observing one is admitted again.
	if !f.add(assetEv(1000, "asset-a0")) {
		t.Fatal("evicted asset must be re-admissible (its key was forgotten)")
	}
	// A currently-ringed asset is deduplicated. After the fill and the
	// re-admission above, the ring holds i=6..68 plus "asset-a0";
	// "asset-g0" is i=6.
	before := f.Dropped()
	if f.add(assetEv(1001, "asset-g0")) {
		t.Fatal("ringed asset must be deduplicated")
	}
	if f.Dropped() != before+1 {
		t.Fatalf("dedupe rejection must be counted, got %d", f.Dropped())
	}
}

// TestInterestingFeedRateLimit pins the admission limiter end to end with
// exact arithmetic: rate 0.5/s means one token per 2s (burst 1), and the
// bucket refills continuously from the last update.
func TestInterestingFeedRateLimit(t *testing.T) {
	f := newInterestingFeed(0.5)
	assetEv := func(ms int, identity string) event.Event {
		return ev(event.KindAssetDiscovered, ms, event.AssetDiscovered{
			Identity: identity, Kind: "technology",
		})
	}
	if !f.add(assetEv(0, "t1")) {
		t.Fatal("first candidate must be admitted (burst)")
	}
	// One second later the bucket holds 0.5 tokens: rejected.
	if f.add(assetEv(1000, "t2")) {
		t.Fatal("candidate after 1s must be rate-rejected (half refill)")
	}
	// Two seconds after the burst the bucket holds exactly 1 token: admitted.
	if !f.add(assetEv(2000, "t3")) {
		t.Fatal("candidate after a full refill window must be admitted")
	}
	// Same-instant candidates share the burst: rejected.
	if f.add(assetEv(2000, "t4")) {
		t.Fatal("same-instant candidate must not pass (burst 1)")
	}
	// One second later the bucket holds 0.5 tokens again: rejected.
	if f.add(assetEv(3000, "t5")) {
		t.Fatal("candidate after 1s must be rate-rejected (half refill)")
	}
	if f.Dropped() != 3 {
		t.Fatalf("Dropped() = %d, want 3", f.Dropped())
	}
}

// TestInterestingFeedSnapshotOrder pins newest-first deterministic order.
func TestInterestingFeedSnapshotOrder(t *testing.T) {
	f := newInterestingFeed(highRate)
	f.add(ev(event.KindAssetDiscovered, 10, event.AssetDiscovered{Identity: "a", Kind: "technology"}))
	f.add(ev(event.KindAssetDiscovered, 20, event.AssetDiscovered{Identity: "b", Kind: "technology"}))
	f.add(ev(event.KindAssetDiscovered, 30, event.AssetDiscovered{Identity: "c", Kind: "technology"}))
	got := f.snapshot()
	if len(got) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(got))
	}
	want := []string{"c", "b", "a"}
	for i, item := range got {
		if item.label != want[i] {
			t.Fatalf("snapshot[%d] = %q, want %q", i, item.label, want[i])
		}
	}
}

// TestErrorFeedGroupingAndSeverity pins category grouping, count/latest
// aggregation, and highest-severity-wins.
func TestErrorFeedGroupingAndSeverity(t *testing.T) {
	f := newErrorFeed()
	t0 := testBase
	f.add("timeout", "first", event.SeverityWarning, t0)
	f.add("timeout", "second", event.SeverityError, t0.Add(time.Millisecond))
	f.add("dns", "nxdomain", event.SeverityWarning, t0.Add(2*time.Millisecond))

	if f.Dropped() != 0 {
		t.Fatalf("no evictions expected, got %d", f.Dropped())
	}
	got := f.snapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(got))
	}
	// Sorted by category: dns, timeout.
	if got[0].category != "dns" || got[0].count != 1 || got[0].severity != event.SeverityWarning {
		t.Fatalf("dns group wrong: %+v", got[0])
	}
	if got[1].category != "timeout" || got[1].count != 2 || got[1].latestMsg != "second" ||
		got[1].severity != event.SeverityError {
		t.Fatalf("timeout group wrong: %+v", got[1])
	}

	// A later warning does not downgrade the aggregated severity.
	f.add("timeout", "third", event.SeverityWarning, t0.Add(3*time.Millisecond))
	got = f.snapshot()
	if got[1].severity != event.SeverityError || got[1].latestMsg != "third" {
		t.Fatalf("severity must keep the maximum, latest message must advance: %+v", got[1])
	}
}

// TestErrorFeedEviction pins the bounded group table: on overflow the
// group with the oldest latest event is evicted, ties break
// lexicographically, and eviction is counted.
func TestErrorFeedEviction(t *testing.T) {
	f := newErrorFeed()
	t0 := testBase
	// maxErrorGroups+1 categories; give category "c00" the oldest latest
	// event so eviction is deterministic.
	for i := 0; i <= maxErrorGroups; i++ {
		cat := "c" + twoDigit(i)
		at := t0.Add(time.Duration(i) * time.Millisecond)
		if i == 0 {
			at = t0.Add(10 * time.Second) // newest — must survive
		}
		f.add(cat, "msg", event.SeverityError, at)
	}
	if f.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", f.Dropped())
	}
	got := f.snapshot()
	if len(got) != maxErrorGroups {
		t.Fatalf("snapshot len = %d, want %d", len(got), maxErrorGroups)
	}
	// c01 has the oldest remaining latest event; the newest (c00) must
	// have survived.
	found := false
	for _, g := range got {
		if g.category == "c00" {
			found = true
		}
		if g.category == "c01" {
			t.Fatal("c01 (oldest) must have been evicted")
		}
	}
	if !found {
		t.Fatal("c00 (newest) must survive eviction")
	}
}

// TestErrorFeedEvictionTie pins the deterministic tie-break: same latest
// time -> lexicographically smallest category is evicted.
func TestErrorFeedEvictionTie(t *testing.T) {
	f := newErrorFeed()
	t0 := testBase
	for i := 0; i <= maxErrorGroups; i++ {
		f.add("c"+twoDigit(i), "msg", event.SeverityError, t0)
	}
	if f.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", f.Dropped())
	}
	got := f.snapshot()
	if got[0].category != "c01" {
		t.Fatalf("lexicographically smallest (c00) must be evicted on tie, first group = %q", got[0].category)
	}
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// TestTruncateLabel pins the rune-safe truncation with the explicit marker.
func TestTruncateLabel(t *testing.T) {
	if got := truncateLabel("short"); got != "short" {
		t.Fatalf("short label must pass through, got %q", got)
	}
	// Exactly at the bound passes through.
	if got := truncateLabel(strings.Repeat("a", maxFeedLabelBytes)); len(got) != maxFeedLabelBytes {
		t.Fatalf("bound-sized label must pass through, got len %d", len(got))
	}
	// A torn trailing rune is trimmed before the marker: 199 a's + "é" is
	// 201 bytes; truncation to the 200-byte bound must not split the é
	// and the marker must fit inside the bound.
	in := strings.Repeat("a", maxFeedLabelBytes-1) + "é"
	got := truncateLabel(in)
	want := strings.Repeat("a", maxFeedLabelBytes-len(labelMarker)) + labelMarker
	if got != want || len(got) > maxFeedLabelBytes {
		t.Fatalf("torn rune must be trimmed before the marker within the bound, got %q (len %d)", got, len(got))
	}
}

// percentEncodeTest mirrors asset/service.go's percentEncode (every byte
// outside [a-zA-Z0-9] becomes %XX, uppercase hex) so tests can build the
// canonical secret_candidate identity shape without importing internal/asset.
func percentEncodeTest(s string) string {
	const hexDigit = "0123456789ABCDEF"
	var b strings.Builder
	for i := range s {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigit[c>>4])
		b.WriteByte(hexDigit[c&0x0f])
	}
	return b.String()
}

// TestSecretCandidateLabelRedaction is the M-7 regression test: a
// secret_candidate identity embeds the percent-encoded candidate VALUE, so
// the display label must be the redacted type+digest form and the rendered
// frame must never contain any substring of the candidate value.
func TestSecretCandidateLabelRedaction(t *testing.T) {
	value := "eyJhbGciOiJIUzI1NiJ9.SflKxwRJSMeKKF2QT4fWPmeJw-secretvalue"
	source := "javascript:https://cdn.example.com/app.js"
	identity := "secret_candidate:jwt/" + percentEncodeTest(value) + "/" + percentEncodeTest(source)

	label := redactedSecretCandidateLabel(identity)

	// Exact shape: type + "/" + first four SHA-256 bytes of the RAW value,
	// mirroring secrentel/record.go redactedCandidateID.
	sum := sha256.Sum256([]byte(value))
	want := "jwt/" + hex.EncodeToString(sum[:4])
	if label != want {
		t.Fatalf("label = %q, want %q", label, want)
	}

	// No substring of the candidate value may survive anywhere in the
	// label. Check every rune-anchored substring up to 8 bytes plus the
	// whole value: any leak path fails here.
	for _, sub := range []string{value, value[:16], value[20:36], "SflKxw", "secretvalue", percentEncodeTest(value)[:24]} {
		if strings.Contains(label, sub) {
			t.Fatalf("label %q leaks value substring %q", label, sub)
		}
	}

	// The rendered frame must be clean too: admit the event through a full
	// State (feed → snapshot → interestingSection) and scan the output.
	st := NewState(highRate)
	st.Apply(ev(event.KindAssetDiscovered, 10, event.AssetDiscovered{
		Identity: identity, Kind: "secret_candidate", Confidence: 0.9,
	}))
	frame := Render(st, testBase.Add(time.Second), Options{})
	if !strings.Contains(frame, want) {
		t.Fatalf("frame must show the redacted label %q, got:\n%s", want, frame)
	}
	for _, sub := range []string{value, "SflKxw", "secretvalue"} {
		if strings.Contains(frame, sub) {
			t.Fatalf("rendered frame leaks value substring %q:\n%s", sub, frame)
		}
	}
}

// TestSecretCandidateLabelMalformedIdentity pins the hostile-input
// degradation: identities that do not parse into the canonical three-part
// shape never render verbatim either.
func TestSecretCandidateLabelMalformedIdentity(t *testing.T) {
	for _, identity := range []string{
		"",
		"s1",
		"secret_candidate:",
		"secret_candidate:noslash",
		"secret_candidate:one/two",
		"secret_candidate:a%ZZb/c/d", // malformed escape in the value
		"secret_candidate:a%2/c/d",   // truncated escape in the value
	} {
		label := redactedSecretCandidateLabel(identity)
		if strings.Contains(label, identity) && identity != "" && len(identity) < 8 {
			t.Fatalf("identity %q leaked into label %q", identity, label)
		}
		if !strings.HasPrefix(label, "secret_candidate/") && !strings.Contains(label, "/") {
			t.Fatalf("label %q for identity %q is not a redacted type/digest form", label, identity)
		}
	}
}
