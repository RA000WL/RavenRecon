package secrentel

import (
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func fixedTime(seconds int) time.Time {
	return time.Unix(1700000000+int64(seconds), 0).UTC()
}

func TestPrepareDocumentValidation(t *testing.T) {
	now := fixedTime(0)
	good := Document{Kind: KindJS, Content: []byte("var a=1;")}

	if _, err := prepareDocument(Document{Kind: "bogus", Content: []byte("x")}, now); err == nil || !strings.Contains(err.Error(), "unknown document kind") {
		t.Errorf("unknown kind must fail: %v", err)
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Filename: strings.Repeat("f", maxFilenameBytes+1)}, now); err == nil {
		t.Error("oversized filename must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Repo: strings.Repeat("r", maxRepoBytes+1)}, now); err == nil {
		t.Error("oversized repo must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Technology: make([]string, maxTechPerDocument+1)}, now); err == nil {
		t.Error("too many technology hints must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Technology: []string{"OK", ""}}, now); err == nil {
		t.Error("empty technology hint must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Technology: []string{strings.Repeat("t", maxTechNameBytes+1)}}, now); err == nil {
		t.Error("oversized technology hint must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Hostname: "not_a_host!!"}, now); err == nil {
		t.Error("invalid hostname must fail")
	}
	if _, err := prepareDocument(Document{Kind: KindJS, Source: strings.Repeat("s", maxSourceNameBytes+1)}, now); err == nil {
		t.Error("oversized source must fail")
	}
	if _, err := prepareDocument(good, now); err != nil {
		t.Fatalf("good document must prepare: %v", err)
	}
}

func TestPrepareDocumentDefaultsAndTruncation(t *testing.T) {
	now := fixedTime(0)
	sd, err := prepareDocument(Document{Kind: KindEnv, Content: []byte("A=1")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if sd.source != "secrentel" {
		t.Errorf("default source = %q, want secrentel", sd.source)
	}
	if !sd.observedAt.Equal(now) {
		t.Errorf("observedAt = %v, want %v", sd.observedAt, now)
	}
	if sd.truncated {
		t.Error("small document must not truncate")
	}

	big := Document{Kind: KindJS, Content: make([]byte, MaxDocumentBytes+1024)}
	for i := range big.Content {
		big.Content[i] = byte('a' + i%26)
	}
	sd, err = prepareDocument(big, now)
	if err != nil {
		t.Fatal(err)
	}
	if !sd.truncated {
		t.Error("oversized document must be truncated")
	}
	if len(sd.content) != MaxDocumentBytes {
		t.Errorf("scanned prefix = %d bytes, want %d", len(sd.content), MaxDocumentBytes)
	}

	// Zero ObservedAt is stamped with the run clock.
	sd, err = prepareDocument(Document{Kind: KindJSON, Content: []byte("{}"), ObservedAt: fixedTime(5)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !sd.observedAt.Equal(fixedTime(5)) {
		t.Errorf("explicit ObservedAt must be kept: %v", sd.observedAt)
	}
}

func TestScanIdentityDeterminism(t *testing.T) {
	now := fixedTime(0)
	base := Document{Kind: KindJS, Content: []byte("var a=1;"), Filename: "app.js", Hostname: "cdn.example.com"}

	a, err := prepareDocument(base, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := prepareDocument(base, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.identity != b.identity {
		t.Error("identical documents must produce identical scan identities")
	}
	if a.identity.Kind != "document" || len(a.identity.Value) != 64 {
		t.Errorf("identity = %v, want kind document with 64-hex value", a.identity)
	}

	// Every result-relevant input changes the identity.
	mutations := []func(*Document){
		func(d *Document) { d.Kind = KindJSON },
		func(d *Document) { d.Content = []byte("var a=2;") },
		func(d *Document) { d.Filename = "other.js" },
		func(d *Document) { d.Hostname = "other.example.com" },
		func(d *Document) { d.Technology = []string{"next.js"} },
	}
	for i, mut := range mutations {
		d := base
		mut(&d)
		sd, err := prepareDocument(d, now)
		if err != nil {
			t.Fatal(err)
		}
		if sd.identity == a.identity {
			t.Errorf("mutation %d must change the scan identity", i)
		}
	}

	// URL documents: the URL identity participates.
	u, err := asset.ParseURL("https://cdn.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	withURL := base
	withURL.URL = &u
	sd, err := prepareDocument(withURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if sd.hostname != "cdn.example.com" {
		t.Errorf("hostname derived from URL = %q", sd.hostname)
	}
	u2, _ := asset.ParseURL("https://other.example.com/app.js", asset.Provenance{})
	other := withURL
	other.URL = &u2
	sd2, _ := prepareDocument(other, now)
	if sd.identity == sd2.identity {
		t.Error("a different URL must change the scan identity")
	}
}

func TestCandidateSourceAndEdgeKinds(t *testing.T) {
	now := fixedTime(0)

	// A JavaScript source asset drives javascript_to_secret_candidate (the
	// Phase 7 kind — jsintel compatibility); a URL drives the Phase 8 kind;
	// none drives no edge.
	js, err := asset.NewJavaScript("https://cdn.example.com/app.js", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	jsID := js.Identity()
	sd, err := prepareDocument(Document{Kind: KindJS, Content: []byte("x"), SourceAsset: &jsID}, now)
	if err != nil {
		t.Fatal(err)
	}
	from, kind, ok := sd.edgeSource()
	if !ok || kind != asset.RelationshipJavaScriptToSecretCandidate || from != jsID {
		t.Errorf("edgeSource = %v/%v/%v", from, kind, ok)
	}
	if sd.candidateSource() != jsID {
		t.Errorf("candidateSource must be the source asset identity")
	}

	u, _ := asset.ParseURL("https://x.example.com/a.js", asset.Provenance{})
	urlID := u.Identity()
	sd, err = prepareDocument(Document{Kind: KindJS, Content: []byte("x"), SourceAsset: &urlID}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, kind, ok = sd.edgeSource()
	if !ok || kind != asset.RelationshipURLToSecretCandidate {
		t.Errorf("URL edge kind = %v/%v", kind, ok)
	}

	sd, err = prepareDocument(Document{Kind: KindJS, Content: []byte("x")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := sd.edgeSource(); ok {
		t.Error("no source asset and no URL means no edge")
	}
	u3, _ := asset.ParseURL("https://plain.example.com/x.js", asset.Provenance{})
	sd, err = prepareDocument(Document{Kind: KindJS, Content: []byte("x"), URL: &u3}, now)
	if err != nil {
		t.Fatal(err)
	}
	from, kind, ok = sd.edgeSource()
	if !ok || kind != asset.RelationshipURLToSecretCandidate || from != u3.Identity() {
		t.Errorf("URL-only document edge = %v/%v/%v", from, kind, ok)
	}
	if sd.candidateSource() != sd.identity {
		t.Error("candidateSource falls back to the scan identity")
	}
}
