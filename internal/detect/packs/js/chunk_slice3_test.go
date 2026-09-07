package js

import (
	"context"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// chunkScriptSlice3 builds a chunk-carrying script asset the way the
// jsintel stage does: the chunk URL parsed from the constructor-built
// chunk identity (fragment cites the window, Identity() stays the file).
func chunkScriptSlice3(t testing.TB, file asset.URL, index, total int, start, end int64, hashPrefix string) (asset.JavaScript, asset.Identity) {
	t.Helper()
	cid, err := asset.ChunkJavaScriptIdentity(file, index, total, start, end, hashPrefix, "w512-o8-v1")
	if err != nil {
		t.Fatalf("ChunkJavaScriptIdentity: %v", err)
	}
	curl, err := asset.ParseURL(cid.Value, asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("ParseURL chunk: %v", err)
	}
	return asset.JavaScript{URL: curl, Prov: asset.Provenance{Source: "js-test"}}, cid
}

func runJSPackSlice3(t testing.TB, snap detect.Snapshot) detect.Report {
	t.Helper()
	reg := registerJSPack(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// TestJSChunkOverlapSinkCollapsesToOneFinding pins the Slice 3
// subject normalization: a sink planted in the overlap of two windows
// (same file offset in both bodies, different chunk-local offsets,
// different surrounding bytes) yields EXACTLY ONE finding citing the
// FILE with the file-relative offset — overlap-identical signals share
// finding identity and MergeFindings collapses them.
func TestJSChunkOverlapSinkCollapsesToOneFinding(t *testing.T) {
	js := mustJS(t, "https://www.example.com/bundle.js")
	sink := "el.innerHTML = location.hash;"
	// Overlap [900,1000): the "innerhtml" needle at file offset 953 in
	// both windows (3 bytes into the "el.innerHTML ..." statement).
	body0 := strings.Repeat("a", 950) + sink + strings.Repeat("a", 1000-950-len(sink))
	body1 := strings.Repeat("b", 50) + sink + strings.Repeat("b", 1000-50-len(sink))
	if strings.Index(body0, sink) != 950 || strings.Index(body1, sink) != 50 {
		t.Fatalf("fixture sink locals = %d/%d, want 950/50", strings.Index(body0, sink), strings.Index(body1, sink))
	}
	c0, cid0 := chunkScriptSlice3(t, js.URL, 0, 2, 0, 1000, "abcdef12")
	c1, cid1 := chunkScriptSlice3(t, js.URL, 1, 2, 900, 1900, "12345678")
	snap := detect.Snapshot{
		JavaScript: []asset.JavaScript{js, c0, c1},
		JavaScriptContent: []detect.JavaScriptContent{
			{Identity: cid0, Body: body0},
			{Identity: cid1, Body: body1},
		},
	}
	rep := runJSPackSlice3(t, snap)
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d (%+v), want EXACTLY ONE (overlap collapse)", len(rep.Findings), rep.Findings)
	}
	f := rep.Findings[0]
	if f.RuleID != ruleDomXSS {
		t.Fatalf("rule = %q, want %q", f.RuleID, ruleDomXSS)
	}
	if f.Subject != js.Identity() {
		t.Fatalf("subject = %q, want the FILE %q (never a chunk)", f.Subject, js.Identity())
	}
	if _, _, _, _, _, _, _, err := asset.ParseChunkIdentity(f.Subject); err == nil {
		t.Fatalf("subject %q parses as a chunk (must be the file)", f.Subject)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("evidence = %d, want 1 (identical records collapse)", len(f.Evidence))
	}
	if want := "js pack signal: " + ruleDomXSS + " @953"; f.Evidence[0].Value != want {
		t.Fatalf("evidence value = %q, want %q (file-relative offset)", f.Evidence[0].Value, want)
	}
	if f.Evidence[0].Source != js.Identity() {
		t.Fatalf("evidence source = %q, want the FILE %q", f.Evidence[0].Source, js.Identity())
	}
	if f.Metadata["offset"] != "953" || f.Metadata["signal"] != "dom_xss" {
		t.Fatalf("metadata = %v, want offset=953 signal=dom_xss", f.Metadata)
	}
	if f.Truncated {
		t.Fatal("Truncated = true, want false (no union was cut)")
	}
}

// TestJSChunkDistinctOffsetsUnion pins the same-file union: sinks at two
// DIFFERENT file offsets yield ONE finding (shared rule@file identity)
// with BOTH offsets retained in the evidence union.
func TestJSChunkDistinctOffsetsUnion(t *testing.T) {
	js := mustJS(t, "https://www.example.com/bundle.js")
	sink := "el.innerHTML = location.hash;"
	body0 := sink + strings.Repeat("a", 500) // needle at file offset 3
	body1 := strings.Repeat("b", 100) + sink // needle chunk-local 103, span 900 → file 1003
	c0, cid0 := chunkScriptSlice3(t, js.URL, 0, 2, 0, 600, "abcdef12")
	c1, cid1 := chunkScriptSlice3(t, js.URL, 1, 2, 900, 1500, "12345678")
	snap := detect.Snapshot{
		JavaScript: []asset.JavaScript{js, c0, c1},
		JavaScriptContent: []detect.JavaScriptContent{
			{Identity: cid0, Body: body0},
			{Identity: cid1, Body: body1},
		},
	}
	rep := runJSPackSlice3(t, snap)
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (shared identity unions)", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Subject != js.Identity() {
		t.Fatalf("subject = %q, want the FILE %q", f.Subject, js.Identity())
	}
	got := map[string]bool{}
	for _, ev := range f.Evidence {
		got[ev.Value] = true
	}
	for _, want := range []string{"js pack signal: " + ruleDomXSS + " @3", "js pack signal: " + ruleDomXSS + " @1003"} {
		if !got[want] {
			t.Fatalf("evidence values = %v, want both %q and its pair (union retains every offset)", f.Evidence, want)
		}
	}
}

// TestJSChunkFileBodyOffsetZeroSpan pins the file path of the same
// arithmetic: a file body contributes span 0, so the offset is the
// in-body sink index — uniform with chunks (offset = local + span).
func TestJSChunkFileBodyOffsetZeroSpan(t *testing.T) {
	prefix := "var setup = 1;\n"
	cases := []struct {
		rule   string
		rawURL string
		body   string
		needle string
	}{
		{ruleDomXSS, "https://www.example.com/off_xss.js", prefix + "el.innerHTML = location.hash;\n", "innerhtml"},
		{rulePostMessage, "https://www.example.com/off_pm.js", prefix + `window.addEventListener("message", function(e){ console.log(e.data); });` + "\n", "addeventlistener"},
		{ruleProtoPollute, "https://www.example.com/off_proto.js", prefix + "obj.__proto__.polluted = true;\n", "__proto__"},
	}
	for _, tc := range cases {
		rep := runJSPackSlice3(t, snapWithBody(t, tc.rawURL, tc.body))
		want := itoaSlice3(int64(strings.Index(strings.ToLower(tc.body), tc.needle)))
		var found bool
		for _, f := range rep.Findings {
			if f.RuleID != tc.rule {
				continue
			}
			found = true
			if f.Metadata["offset"] != want {
				t.Fatalf("rule %s: offset = %q, want %q (in-body index, span 0)", tc.rule, f.Metadata["offset"], want)
			}
			if wantEv := "js pack signal: " + tc.rule + " @" + want; f.Evidence[0].Value != wantEv {
				t.Fatalf("rule %s: evidence = %q, want %q", tc.rule, f.Evidence[0].Value, wantEv)
			}
		}
		if !found {
			t.Fatalf("rule %s: no finding for the sink body", tc.rule)
		}
	}
}

func itoaSlice3(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
