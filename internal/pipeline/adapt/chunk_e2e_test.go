package adapt

import (
	"context"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// TestChunkTailSecretEndToEnd is the Slice 1 acceptance: a synthetic 5 MiB
// bundle with a secret in the tail window (of the retained 2 MiB prefix)
// yields a secrentel candidate citing the FILE (not a chunk), through the
// real jsintel → secrentel stages, hermetic. It also pins the
// overlap-duplicate dedup: a secret straddling the w0/w1 overlap appears in
// two windows but merges to ONE candidate with source=file,
// first-seen-wins in index order.
func TestChunkTailSecretEndToEnd(t *testing.T) {
	overlapSecret := awsKey(7)
	tailSecret := awsKey(42)
	// 5 MiB bundle: filler with secrets placed inside the retained 2 MiB
	// prefix (the file tail beyond 2 MiB is dropped honestly — the "tail
	// window" here is the prefix's last window, index 4).
	const total = 5 << 20
	body := make([]byte, total)
	for i := range body {
		body[i] = 'x'
	}
	// Overlap secret lies in the w0/w1 overlap [516096,524288) so bytes
	// appear in both windows (dedup source).
	copy(body[520000:], overlapSecret)
	// Tail secret deep in the last prefix window w4 [2064384,2097152).
	copy(body[2080000:], tailSecret)
	bodyStr := string(body)

	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: bodyStr})

	c, err := cache.Open(t.TempDir(), cache.WithClock(jsFixedClock{}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	jsIn := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/bundle.js")}, nil, c)
	jsRes, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), jsIn)
	if err != nil {
		t.Fatalf("jsintel Run: %v", err)
	}
	if jsRes.Outcome != pipeline.OutcomePartial {
		t.Fatalf("jsintel Outcome = %q, want partial (windowed)", jsRes.Outcome)
	}
	// Pipeline path ≤5 chunks/file + sentinel: 5 chunk docs + sentinel.
	if len(jsRes.Documents) != 6 {
		t.Fatalf("jsintel Documents = %d, want 6 (5 chunks + sentinel)", len(jsRes.Documents))
	}
	// Tail secret must be in the last chunk's bytes (index 4).
	lastChunk := jsRes.Documents[4]
	if !strings.Contains(string(lastChunk.Content), tailSecret) {
		t.Fatalf("last chunk does not contain the tail secret")
	}
	// Overlap secret must be in two consecutive windows (dedup source).
	containing := 0
	for i := 0; i < 5; i++ {
		if strings.Contains(string(jsRes.Documents[i].Content), overlapSecret) {
			containing++
		}
	}
	if containing != 2 {
		t.Fatalf("overlap secret in %d windows, want 2 (straddles w0/w1)", containing)
	}
	// Secrentel stage over the jsintel documents (includes sentinel, which
	// must be skipped): candidates cite the FILE.
	secIn := secretInput(t, jsRes.Documents...)
	secIn.Cache = c
	secRes, err := NewSecretIntelStage(testSecretDB(t)).Run(context.Background(), secIn)
	if err != nil {
		t.Fatalf("secrentel Run: %v", err)
	}
	byValue := make(map[string]asset.SecretCandidate)
	for _, s := range secRes.Results.Secrets {
		byValue[s.Value] = s
	}
	for _, want := range []string{overlapSecret, tailSecret} {
		got, ok := byValue[want]
		if !ok {
			t.Fatalf("secret %q missing from secrentel results (got %v)", want, secRes.Results.Secrets)
		}
		if wantID := "javascript:http://www.example.com/bundle.js"; got.Source.String() != wantID {
			t.Fatalf("secret %q source = %q, want file %q (cite file, not chunk)", want, got.Source, wantID)
		}
	}
	// Overlap duplicate collapses: exactly one candidate per distinct value,
	// and exactly two total (the dedup holds end-to-end — no residual
	// stage duplicates beyond the per-value collapse).
	if len(byValue) != 2 {
		t.Fatalf("distinct candidates = %d, want 2 (overlap deduped, tail found)", len(byValue))
	}
	if len(secRes.Results.Secrets) != 2 {
		t.Fatalf("total candidates = %d, want 2 (overlap duplicate collapses end-to-end, not just per-value)", len(secRes.Results.Secrets))
	}

	// Cold/warm pin (Slice 2 deferral — warm recomputes): a second jsintel
	// run re-fetches (truncated never served) and reproduces byte-identical
	// chunk documents.
	before := tr.requestCount()
	jsRes2, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), jsIn)
	if err != nil {
		t.Fatalf("jsintel warm Run: %v", err)
	}
	if got := tr.requestCount(); got != before+1 {
		t.Fatalf("warm requests = %d, want %d (fetch re-runs warm)", got, before+1)
	}
	if len(jsRes2.Documents) != len(jsRes.Documents) {
		t.Fatalf("warm documents = %d, want %d (byte-identical re-tiling)", len(jsRes2.Documents), len(jsRes.Documents))
	}
	for i := range jsRes.Documents {
		if jsRes.Documents[i].Identity != jsRes2.Documents[i].Identity ||
			string(jsRes.Documents[i].Content) != string(jsRes2.Documents[i].Content) {
			t.Fatalf("warm doc %d differs (must re-tile identically)", i)
		}
	}
}
