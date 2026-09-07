package adapt

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// satChunkBody is the saturation chunk size: exactly one production
// window (512 KiB). 129 such chunks sum past the 64 MiB snapshot
// budget (129×512 KiB = 66,060,288 + head room), so the sorted head is
// exactly the 128 smallest chunk identities (128×512 KiB = 64 MiB =
// MaxSnapshotJSContentBytes, the boundary itself).
const satChunkBodyBytes = 512 << 10

// saturationFixture builds 26 windowed files × 5 chunk documents (130
// chunks, last dropped → 129) plus one file sentinel each, with file
// scripts only (the post-merge detect-stage shape: the runner's
// first-seen corpus merge keeps the file and drops chunk scripts
// sharing its Identity).
func saturationFixture(t *testing.T) ([]pipeline.Document, []asset.JavaScript) {
	t.Helper()
	var docs []pipeline.Document
	var scripts []asset.JavaScript
	var files []asset.JavaScript
	for f := 0; f < 26; f++ {
		raw := fmt.Sprintf("https://www.example.com/sat%02d.js", f)
		js, err := asset.NewJavaScript(raw, asset.Provenance{Source: "js-test"})
		if err != nil {
			t.Fatalf("NewJavaScript: %v", err)
		}
		scripts = append(scripts, js)
		files = append(files, js)
	}
	// 130 chunk documents in file/index order; the last is dropped so
	// the set lands one past the head (129 of 130).
	n := 0
	for _, js := range files {
		for i := 0; i < 5; i++ {
			start := int64(i * (satChunkBodyBytes - (8 << 10)))
			end := start + satChunkBodyBytes
			cid, err := asset.ChunkJavaScriptIdentity(js.URL, i, 5, start, end, "abcdef12", "w512-o8-v1")
			if err != nil {
				t.Fatalf("ChunkJavaScriptIdentity: %v", err)
			}
			n++
			if n > 129 {
				continue
			}
			docs = append(docs, pipeline.Document{Identity: cid, Content: []byte(strings.Repeat("x", satChunkBodyBytes))})
		}
	}
	// One file sentinel per windowed file (nil, truncated): the gap markers.
	for _, js := range files {
		docs = append(docs, pipeline.Document{Identity: js.Identity(), Content: nil, Truncated: true})
	}
	if len(docs) != 129+26 {
		t.Fatalf("docs = %d, want 155 (129 chunks + 26 sentinels)", len(docs))
	}
	return docs, scripts
}

// TestBuildJSContentsSaturationTruncates pins the Slice 3 displacement
// budget: past 64 MiB the sorted head (exactly 128 window bodies at the
// boundary) is analyzed, the cut rides truncated (never a silent
// subset), the sentinels ride incomplete_input, and channel order never
// matters.
func TestBuildJSContentsSaturationTruncates(t *testing.T) {
	docs, scripts := saturationFixture(t)
	got, truncated, incomplete := buildJSContents(docs, scripts)
	if !truncated {
		t.Fatal("truncated = false, want true (129×512 KiB past the 64 MiB budget)")
	}
	if !incomplete {
		t.Fatal("incomplete = false, want true (26 file sentinels mark the windowed gaps)")
	}
	if len(got) != 128 {
		t.Fatalf("contents = %d, want 128 (the sorted head at exactly 64 MiB)", len(got))
	}
	var total int
	for _, jc := range got {
		total += len(jc.Body)
	}
	if total != detect.MaxSnapshotJSContentBytes {
		t.Fatalf("head bytes = %d, want %d (the boundary itself)", total, detect.MaxSnapshotJSContentBytes)
	}
	// Sorted-head determinism: the reversed channel resolves
	// byte-identically (same 128 chunk identities, same bodies).
	rev := append([]pipeline.Document(nil), docs...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	gotRev, truncatedRev, incompleteRev := buildJSContents(rev, scripts)
	if !truncatedRev || !incompleteRev {
		t.Fatalf("reversed: truncated=%v incomplete=%v, want true/true", truncatedRev, incompleteRev)
	}
	if !reflect.DeepEqual(gotRev, got) {
		t.Fatal("reversed channel resolved a different head (sorted-head cut must be deterministic)")
	}
}

// TestDetectStageSaturationFlags pins the saturation honesty end to
// end: the stage reports Truncated with detect_js_contents_truncated
// (the bounds cut) plus detect_js_contents_incomplete_input (the
// sentinels) — completed WITH flags, never a silent completed run —
// while the probe rule still observes the retained 128-body head.
func TestDetectStageSaturationFlags(t *testing.T) {
	docs, scripts := saturationFixture(t)
	stage := NewDetectStage(contentsProbeRegistry(t))
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = scripts
	in.Documents = docs
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (rules completed; flags carry the cut, not the outcome)", res.Outcome)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (bytes cut + gaps)")
	}
	if !res.StickyFlags[detectJSContentsTruncatedFlag] {
		t.Fatalf("flags = %v, want %q (sorted-head cut)", res.StickyFlags, detectJSContentsTruncatedFlag)
	}
	if !res.StickyFlags[detectJSContentsIncompleteFlag] {
		t.Fatalf("flags = %v, want %q (sentinel gaps)", res.StickyFlags, detectJSContentsIncompleteFlag)
	}
	if len(res.Results.Findings) != 1 || res.Results.Findings[0].Metadata["contents"] != "128" {
		t.Fatalf("findings = %+v, want one probe finding citing the 128 retained head", res.Results.Findings)
	}
}

// TestBuildJSContentsNumericWindowOrder pins the Slice 3 review F2
// sort key: with 11 chunk documents the retained bodies must order
// 0,1,2,...,10 — string order would emit 0,1,10,2,...,9 ("10/.." <
// "2/.."). The snapshot carries the file script only (the post-merge
// production shape), so every chunk links via its file; the channel is
// reversed to prove the order comes from the sorter, not the caller.
func TestBuildJSContentsNumericWindowOrder(t *testing.T) {
	js, err := asset.NewJavaScript("https://www.example.com/many.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	const total = 11
	var docs []pipeline.Document
	for i := 0; i < total; i++ {
		cid, err := asset.ChunkJavaScriptIdentity(js.URL, i, total, int64(i*100), int64(i*100+100), "abcdef12", "w512-o8-v1")
		if err != nil {
			t.Fatalf("ChunkJavaScriptIdentity: %v", err)
		}
		docs = append(docs, pipeline.Document{Identity: cid, Content: []byte(fmt.Sprintf("body-%02d", i))})
	}
	for i, j := 0, len(docs)-1; i < j; i, j = i+1, j-1 {
		docs[i], docs[j] = docs[j], docs[i]
	}
	got, truncated, incomplete := buildJSContents(docs, []asset.JavaScript{js})
	if truncated || incomplete {
		t.Fatalf("truncated=%v incomplete=%v, want false/false (11 small attributed bodies, nothing cut or skipped)", truncated, incomplete)
	}
	if len(got) != total {
		t.Fatalf("contents = %d, want %d", len(got), total)
	}
	for pos, jc := range got {
		_, index, _, _, _, _, _, err := asset.ParseChunkIdentity(jc.Identity)
		if err != nil {
			t.Fatalf("contents[%d] identity %s does not parse: %v", pos, jc.Identity, err)
		}
		if index != pos {
			t.Fatalf("contents[%d] carries window index %d, want numeric order 0..%d", pos, index, total-1)
		}
		if jc.Body != fmt.Sprintf("body-%02d", pos) {
			t.Fatalf("contents[%d].Body = %q, want the matching window body", pos, jc.Body)
		}
	}
}

// TestChunkTailSinkDetectEndToEnd is the Slice 3 acceptance: a synthetic
// 5 MiB bundle with a DOM XSS sink in the tail window (of the retained
// 2 MiB prefix) yields a js.dom.xss finding citing the FILE — through
// the real jsintel → detect stages, hermetic — with cold/warm finding
// parity (the warm run re-fetches and hits per-chunk analysis, but the
// findings are byte-identical).
func TestChunkTailSinkDetectEndToEnd(t *testing.T) {
	const total = 5 << 20
	body := make([]byte, total)
	for i := range body {
		body[i] = 'x'
	}
	// Tail sink deep in the last prefix window w4 [2064384,2097152):
	// the needle lands at file offset sinkAt+4 (";el." prefix).
	const sinkAt = 2080000
	sink := ";el.innerHTML=location.hash;"
	copy(body[sinkAt:], sink)
	const wantOffset = sinkAt + 4 // "innerhtml" starts past ";el."

	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: string(body)})

	c, err := cache.Open(t.TempDir(), cache.WithClock(jsFixedClock{}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	bundleURL := jsMustURL(t, "http://www.example.com/bundle.js")
	jsIn := jsStageInput(t, "example.com", []asset.URL{bundleURL}, nil, c)

	runDetect := func(docs []pipeline.Document, scripts []asset.JavaScript) pipeline.StageResult {
		t.Helper()
		stage, err := NewDetectStageWithJsPack(nil)
		if err != nil {
			t.Fatalf("NewDetectStageWithJsPack: %v", err)
		}
		in := pipeline.StageInput{
			Target:  mustDomain(t, "example.com"),
			Domains: []asset.Domain{mustDomain(t, "example.com")},
			Bounds:  pipeline.DefaultStageConfig(),
			Clock:   fixedClock{now: fixedTime},
		}
		in.Results.JavaScript = scripts
		in.Documents = docs
		res, err := stage.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("detect Run: %v", err)
		}
		return res
	}
	// mergeResults keeps the first-seen asset per Identity: the jsintel
	// stage emits the file before its chunks, so the run corpus carries
	// the file (chunk scripts drop). Reproduce that merge here so the
	// detect input is the honest post-merge shape.
	mergeScripts := func(all []asset.JavaScript) []asset.JavaScript {
		seen := map[string]struct{}{}
		var out []asset.JavaScript
		for _, js := range all {
			k := js.Identity().String()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, js)
		}
		return out
	}

	jsCold, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), jsIn)
	if err != nil {
		t.Fatalf("jsintel cold Run: %v", err)
	}
	if jsCold.Outcome != pipeline.OutcomePartial {
		t.Fatalf("jsintel cold Outcome = %q, want partial (windowed)", jsCold.Outcome)
	}
	if len(jsCold.Documents) != 6 {
		t.Fatalf("jsintel cold Documents = %d, want 6 (5 chunks + sentinel)", len(jsCold.Documents))
	}
	// The tail sink must ride the last chunk's bytes.
	if !strings.Contains(string(jsCold.Documents[4].Content), sink) {
		t.Fatal("last chunk does not contain the tail sink")
	}
	fileScripts := mergeScripts(jsCold.Results.JavaScript)
	if len(fileScripts) != 1 {
		t.Fatalf("merged scripts = %d, want 1 (the file survives first-seen)", len(fileScripts))
	}
	fileID := fileScripts[0].Identity()

	detCold := runDetect(jsCold.Documents, fileScripts)
	if !detCold.Truncated || !detCold.StickyFlags[detectJSContentsIncompleteFlag] {
		t.Fatalf("detect cold Truncated/flags = %v/%v, want true/incomplete_input (sentinel gap)", detCold.Truncated, detCold.StickyFlags)
	}
	if detCold.StickyFlags[detectJSContentsTruncatedFlag] {
		t.Fatalf("detect cold flags = %v, must not carry the bounds-cut flag (5 chunks ≈ 2.5 MiB « 64 MiB)", detCold.StickyFlags)
	}
	var xss []struct {
		subject string
		offset  string
		ev      string
	}
	for _, f := range detCold.Results.Findings {
		if f.RuleID != "js.dom.xss" {
			t.Fatalf("unexpected finding %q (filler must fire nothing else)", f.RuleID)
		}
		if _, _, _, _, _, _, _, perr := asset.ParseChunkIdentity(f.Subject); perr == nil {
			t.Fatalf("finding subject %q is a chunk (must cite the FILE)", f.Subject)
		}
		xss = append(xss, struct {
			subject string
			offset  string
			ev      string
		}{f.Subject.String(), f.Metadata["offset"], f.Evidence[0].Value})
	}
	if len(xss) != 1 {
		t.Fatalf("js.dom.xss findings = %d, want 1 (tail sink only)", len(xss))
	}
	if xss[0].subject != fileID.String() {
		t.Fatalf("finding subject = %q, want the FILE %q", xss[0].subject, fileID)
	}
	if xss[0].offset != fmt.Sprint(wantOffset) {
		t.Fatalf("finding offset = %q, want %d (chunk-local + span start)", xss[0].offset, wantOffset)
	}
	if wantEv := "js pack signal: js.dom.xss @" + fmt.Sprint(wantOffset); xss[0].ev != wantEv {
		t.Fatalf("finding evidence = %q, want %q", xss[0].ev, wantEv)
	}

	// Warm run: re-fetch (truncated never served) with per-chunk
	// analysis hits, byte-identical chunk documents — and byte-identical
	// findings.
	before := tr.requestCount()
	jsWarm, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), jsIn)
	if err != nil {
		t.Fatalf("jsintel warm Run: %v", err)
	}
	if got := tr.requestCount(); got != before+1 {
		t.Fatalf("warm requests = %d, want %d (fetch re-runs warm)", got, before+1)
	}
	if len(jsWarm.Documents) != len(jsCold.Documents) {
		t.Fatalf("warm documents = %d, want %d", len(jsWarm.Documents), len(jsCold.Documents))
	}
	for i := range jsCold.Documents {
		if jsWarm.Documents[i].Identity != jsCold.Documents[i].Identity ||
			string(jsWarm.Documents[i].Content) != string(jsCold.Documents[i].Content) {
			t.Fatalf("warm doc %d differs (must re-tile identically)", i)
		}
	}
	detWarm := runDetect(jsWarm.Documents, mergeScripts(jsWarm.Results.JavaScript))
	coldJSON, _ := json.Marshal(detCold.Results.Findings)
	warmJSON, _ := json.Marshal(detWarm.Results.Findings)
	if string(coldJSON) != string(warmJSON) {
		t.Fatalf("warm findings drift:\ncold %s\nwarm %s", coldJSON, warmJSON)
	}
}
