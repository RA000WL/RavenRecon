package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// mustDocument builds a document channel entry with the canonical identity
// of the JavaScript asset at rawURL and the given content (synthetic test
// values only).
func mustDocument(t *testing.T, rawURL, content string) Document {
	t.Helper()
	j := mustJavaScript(t, rawURL)
	return Document{Identity: j.Identity(), Content: []byte(content)}
}

func TestMergeDocumentsFirstSeenDedup(t *testing.T) {
	d1 := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	d2 := mustDocument(t, "https://cdn.example.com/vendor.js", "var b = 2;")
	seen := make(map[string]struct{})
	got, cut := mergeDocuments(nil, []Document{d1, d2, d1, d2}, seen, 100)
	if cut != nil {
		t.Errorf("cut = %v, want nil (cap did not cut)", cut)
	}
	want := []Document{d1, d2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %+v, want %+v (first-seen wins, stable order)", got, want)
	}
	// The returned slice must not alias the input slice.
	if len(got) > 0 && &got[0] == &d1 {
		t.Error("merged slice aliases the input slice")
	}
}

func TestMergeDocumentsCapTailDrop(t *testing.T) {
	d1 := mustDocument(t, "https://cdn.example.com/a.js", "a")
	d2 := mustDocument(t, "https://cdn.example.com/b.js", "b")
	d3 := mustDocument(t, "https://cdn.example.com/c.js", "c")
	seen := make(map[string]struct{})
	got, cut := mergeDocuments(nil, []Document{d1, d2, d3}, seen, 2)
	if !reflect.DeepEqual(cut, []string{"documents"}) {
		t.Errorf("cut = %v, want [documents]", cut)
	}
	want := []Document{d1, d2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %+v, want %+v (tail dropped, first-seen order kept)", got, want)
	}
	// No cut when the merge fits the cap.
	got, cut = mergeDocuments(got, nil, seen, 2)
	if cut != nil {
		t.Errorf("cut = %v, want nil on a no-op merge", cut)
	}
}

func TestMergeDocumentsCutPermanence(t *testing.T) {
	// A document cut away by a small cap stays first-seen and can never
	// re-enter the channel, even through a later stage with a larger cap
	// (identical to the corpus/results caps' permanence).
	d1 := mustDocument(t, "https://cdn.example.com/a.js", "a")
	d2 := mustDocument(t, "https://cdn.example.com/b.js", "b")
	d3 := mustDocument(t, "https://cdn.example.com/c.js", "c")
	seen := make(map[string]struct{})
	got, _ := mergeDocuments(nil, []Document{d1, d2, d3}, seen, 2)
	if !reflect.DeepEqual(got, []Document{d1, d2}) {
		t.Fatalf("first merge = %+v, want [d1 d2]", got)
	}
	// Later stage re-emits the cut entry plus a new one, with a larger cap.
	got, cut := mergeDocuments(got, []Document{d3, mustDocument(t, "https://cdn.example.com/d.js", "d")}, seen, 100)
	if cut != nil {
		t.Errorf("cut = %v, want nil", cut)
	}
	want := []Document{d1, d2, mustDocument(t, "https://cdn.example.com/d.js", "d")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %+v, want %+v (cut entries stay first-seen)", got, want)
	}
}

func TestMergeDocumentsReCut(t *testing.T) {
	// A larger earlier cap keeps everything; a smaller later cap re-cuts.
	d1 := mustDocument(t, "https://cdn.example.com/a.js", "a")
	d2 := mustDocument(t, "https://cdn.example.com/b.js", "b")
	d3 := mustDocument(t, "https://cdn.example.com/c.js", "c")
	seen := make(map[string]struct{})
	got, cut := mergeDocuments(nil, []Document{d1, d2}, seen, 5)
	if cut != nil {
		t.Fatalf("cut = %v, want nil", cut)
	}
	got, cut = mergeDocuments(got, []Document{d3}, seen, 2)
	if !reflect.DeepEqual(cut, []string{"documents"}) {
		t.Errorf("cut = %v, want [documents] (re-cut)", cut)
	}
	if !reflect.DeepEqual(got, []Document{d1, d2}) {
		t.Errorf("merged = %+v, want [d1 d2] (tail re-cut)", got)
	}
}

func TestMergeDocumentsOverCapContentDroppedWhole(t *testing.T) {
	// Hostile-producer guard: content over MaxDocumentBytes is dropped
	// WHOLE — Content nil + Truncated — never a partial prefix, and the
	// document still merges (its identity and URL remain honest).
	j := mustJavaScript(t, "https://cdn.example.com/big.js")
	over := make([]byte, MaxDocumentBytes+1)
	for i := range over {
		over[i] = 'x'
	}
	big := Document{Identity: j.Identity(), Content: over}
	caller := []Document{big}

	seen := make(map[string]struct{})
	got, cut := mergeDocuments(nil, caller, seen, 10)
	if cut != nil {
		t.Errorf("cut = %v, want nil (re-bound is not a cap cut)", cut)
	}
	if len(got) != 1 {
		t.Fatalf("merged = %d entries, want 1 (over-cap document still merges)", len(got))
	}
	if got[0].Content != nil {
		t.Error("over-cap content must be dropped whole (nil), never a partial prefix")
	}
	if !got[0].Truncated {
		t.Error("over-cap document must be marked Truncated")
	}
	if got[0].Identity != big.Identity {
		t.Error("over-cap document must keep its identity")
	}
	// The caller's slice is never mutated.
	if caller[0].Content == nil || caller[0].Truncated || len(caller[0].Content) != MaxDocumentBytes+1 {
		t.Error("merge mutated the caller's slice")
	}
	// A re-merge of the re-bound document dedups by identity as usual.
	got, cut = mergeDocuments(got, caller, seen, 10)
	if cut != nil || len(got) != 1 {
		t.Errorf("re-merge = %d entries cut %v, want 1/nil (identity dedup)", len(got), cut)
	}
}

func TestMergeDocumentsInBoundContentByReference(t *testing.T) {
	// In-bound content is merged by reference, never copied (the document
	// channel's currency is handed over, like the corpus — the consumed
	// slice aliases the caller's backing array).
	d := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	caller := []Document{d}
	seen := make(map[string]struct{})
	got, cut := mergeDocuments(nil, caller, seen, 10)
	if cut != nil || len(got) != 1 {
		t.Fatalf("merge = %d entries cut %v, want 1/nil", len(got), cut)
	}
	if len(got[0].Content) == 0 || &got[0].Content[0] != &caller[0].Content[0] {
		t.Error("in-bound content must be merged by reference (never copied)")
	}
}

func TestMergeDocumentsNilAndEmpty(t *testing.T) {
	seen := make(map[string]struct{})
	// Nil additions are a no-op.
	got, cut := mergeDocuments(nil, nil, seen, 10)
	if cut != nil || len(got) != 0 {
		t.Errorf("nil merge = %d entries cut %v, want 0/nil", len(got), cut)
	}
	// Truncated small-content documents still merge (the merge is not the
	// filtering point — the secrentel stage skips them when consuming).
	d := mustDocument(t, "https://cdn.example.com/t.js", "t")
	d.Truncated = true
	got, cut = mergeDocuments(got, []Document{d}, seen, 10)
	if cut != nil || len(got) != 1 || !got[0].Truncated {
		t.Errorf("truncated-document merge = %+v cut %v, want merged + Truncated preserved", got, cut)
	}
}

func TestRunDocumentsChannelPropagation(t *testing.T) {
	d1 := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	d2 := mustDocument(t, "https://cdn.example.com/vendor.js", "var b = 2;")

	producer := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		if len(in.Documents) != 0 {
			t.Errorf("jsintel received documents: %d, want 0 (never sees its own)", len(in.Documents))
		}
		return StageResult{Outcome: OutcomeCompleted, Documents: []Document{d1, d2}}, nil
	}}
	var consumerSeen []Document
	consumer := &fakeStage{name: StageSecretIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		consumerSeen = append(consumerSeen, in.Documents...)
		return StageResult{Outcome: OutcomeCompleted}, nil
	}}
	report, err := run(t, validConfig(t, StageJSIntel, StageSecretIntel), []Stage{producer, consumer})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(consumerSeen, []Document{d1, d2}) {
		t.Errorf("consumer input = %+v, want [d1 d2] (first-seen order)", consumerSeen)
	}
	if !reflect.DeepEqual(report.Documents, []Document{d1, d2}) {
		t.Errorf("report.Documents = %+v, want [d1 d2]", report.Documents)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("flags = %v truncated %v, want none", report.StickyFlags, report.Truncated)
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", report.Outcome)
	}
}

func TestRunDocumentsResultsSeenIsolation(t *testing.T) {
	// The documents seen-map and the results seen-map are physically
	// isolated: a document whose canonical identity string coincides with
	// an identity carried by a results channel in the SAME run must never
	// dedup against it. Three coincident-identity forms are pinned: the
	// SecretCandidate whose Source is the document's own identity, and the
	// JavaScript asset whose identity string is BYTE-IDENTICAL to the
	// document's — the form a shared or un-namespaced seen map would
	// collide on. All three entries must survive into RunReport.
	doc := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	// The candidate's Source is the document's canonical identity (the
	// jsintel dedup contract: the same value observed in that asset).
	secret := mustSecret(t, "eyJhbGciOiJIUzI1NiJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", doc.Identity)
	// The JavaScript asset with the identical canonical identity: the
	// document channel's producer (the jsintel stage) is also the
	// JavaScript channel's producer, so the two channels legitimately
	// carry the same canonical identity in one run.
	js := mustJavaScript(t, "https://cdn.example.com/app.js")
	producer := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeCompleted,
			Documents: []Document{doc},
			Results: Results{
				JavaScript: []asset.JavaScript{js},
				Secrets:    []asset.SecretCandidate{secret},
			}}, nil
	}}
	report, err := run(t, validConfig(t, StageJSIntel), []Stage{producer})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Documents) != 1 || report.Documents[0].Identity != doc.Identity {
		t.Errorf("report.Documents = %+v, want the document (the documents seen-map must never dedup against a results identity)", report.Documents)
	}
	if len(report.Results.JavaScript) != 1 || report.Results.JavaScript[0].Identity() != js.Identity() {
		t.Errorf("report.Results.JavaScript = %+v, want the JavaScript asset (the results seen-map must never dedup against a document identity)", report.Results.JavaScript)
	}
	if len(report.Results.Secrets) != 1 || report.Results.Secrets[0].Identity() != secret.Identity() {
		t.Errorf("report.Results.Secrets = %+v, want the secret candidate (the results seen-map must never dedup against a document identity)", report.Results.Secrets)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("flags = %v truncated %v, want none", report.StickyFlags, report.Truncated)
	}
}

func TestRunDocumentsCapFlag(t *testing.T) {
	d1 := mustDocument(t, "https://cdn.example.com/a.js", "a")
	d2 := mustDocument(t, "https://cdn.example.com/b.js", "b")
	producer := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeCompleted, Documents: []Document{d1, d2}}, nil
	}}
	cfg := validConfig(t, StageJSIntel)
	cfg.StageBounds = map[StageName]StageConfig{StageJSIntel: {MaxOutput: 1}}
	report, err := run(t, cfg, []Stage{producer})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(report.Documents, []Document{d1}) {
		t.Errorf("report.Documents = %+v, want [d1] (tail dropped)", report.Documents)
	}
	if !report.Truncated {
		t.Error("report.Truncated must be set when the document channel was cut")
	}
	if !report.StickyFlags["documents_truncated"] {
		t.Errorf("StickyFlags = %v, want documents_truncated", report.StickyFlags)
	}
	// The stage's own outcome is untouched: completed + flag is the AGENTS
	// §0.6 carve-out, never a silent completed.
	if report.Stages[0].Outcome != OutcomeCompleted {
		t.Errorf("stage outcome = %q, want completed (runner-side cap, stage untouched)", report.Stages[0].Outcome)
	}
	if report.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed with the documents_truncated flag (carve-out)", report.Outcome)
	}

	t.Run("cap larger than the channel is a no-cut no-flag", func(t *testing.T) {
		cfg := validConfig(t, StageJSIntel)
		cfg.StageBounds = map[StageName]StageConfig{StageJSIntel: {MaxOutput: 100}}
		report, err := run(t, cfg, []Stage{producer})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Documents) != 2 || report.Truncated || len(report.StickyFlags) != 0 {
			t.Errorf("documents = %d truncated %v flags %v, want 2/false/none", len(report.Documents), report.Truncated, report.StickyFlags)
		}
	})
}

func TestRunDocumentsMergedOnFailure(t *testing.T) {
	// A failed stage's retained documents are still merged (mirroring the
	// Additions/results semantics).
	d1 := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	producer := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		return StageResult{Outcome: OutcomeFailed, Err: context.DeadlineExceeded, Documents: []Document{d1}}, nil
	}}
	consumer := &fakeStage{name: StageSecretIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		if len(in.Documents) != 1 {
			t.Errorf("consumer input = %d documents, want the failed stage's retained output", len(in.Documents))
		}
		return StageResult{Outcome: OutcomeCompleted}, nil
	}}
	report, err := run(t, validConfig(t, StageJSIntel, StageSecretIntel), []Stage{producer, consumer})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(report.Documents, []Document{d1}) {
		t.Errorf("report.Documents = %+v, want the failed stage's documents retained", report.Documents)
	}
	if report.Stages[0].Outcome != OutcomeFailed || report.Outcome != OutcomePartial {
		t.Errorf("outcomes = %q/%q, want failed stage + partial fold", report.Stages[0].Outcome, report.Outcome)
	}
}

func TestRunPreCancelledNoDocuments(t *testing.T) {
	d1 := mustDocument(t, "https://cdn.example.com/app.js", "var a = 1;")
	var ran bool
	producer := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		ran = true
		return StageResult{Outcome: OutcomeCompleted, Documents: []Document{d1}}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Run(ctx, validConfig(t, StageJSIntel), nil, newFakeClock(testTime), []Stage{producer})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ran {
		t.Error("stage ran despite a pre-cancelled context")
	}
	if len(report.Documents) != 0 {
		t.Errorf("report.Documents = %+v, want none for a pre-cancelled run", report.Documents)
	}
	if report.Truncated || len(report.StickyFlags) != 0 {
		t.Errorf("flags = %v truncated %v, want none", report.StickyFlags, report.Truncated)
	}
	if report.Outcome != OutcomeCancelled {
		t.Errorf("Outcome = %q, want cancelled", report.Outcome)
	}
}

func TestRunDocumentsDeterministic(t *testing.T) {
	cfg := validConfig(t, StageJSIntel, StageSecretIntel)
	stages := func() []Stage {
		return []Stage{
			&fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeCompleted, Documents: []Document{
					mustDocument(t, "https://cdn.example.com/b.js", "b"),
					mustDocument(t, "https://cdn.example.com/a.js", "a"),
					mustDocument(t, "https://cdn.example.com/b.js", "b"), // duplicate
				}}, nil
			}},
			&fakeStage{name: StageSecretIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
				return StageResult{Outcome: OutcomeCompleted}, nil
			}},
		}
	}
	r1, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	r2, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), stages())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Errorf("runs differ (documents must be deterministic):\n%+v\n%+v", r1, r2)
	}
	if len(r1.Documents) != 2 {
		t.Errorf("report.Documents = %d, want 2 (deduped)", len(r1.Documents))
	}
	// Defensive: the run's document channel never aliases a stage's slice —
	// mutating the stage's returned slice after Run cannot reach the report.
	var res StageResult
	st := &fakeStage{name: StageJSIntel, run: func(ctx context.Context, in StageInput) (StageResult, error) {
		res = StageResult{Outcome: OutcomeCompleted, Documents: []Document{mustDocument(t, "https://cdn.example.com/app.js", "x")}}
		return res, nil
	}}
	report, err := run(t, validConfig(t, StageJSIntel), []Stage{st})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	res.Documents[0] = Document{Identity: asset.Identity{Kind: "javascript", Value: "https://evil.example.com/x"}}
	if len(report.Documents) != 1 || report.Documents[0].Identity.Value != "https://cdn.example.com/app.js" {
		t.Errorf("report.Documents aliased the stage's slice: %+v", report.Documents)
	}
}
