package detect

import (
	"strconv"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// JavaScript content channel tests (SDK v2.1, NEW-118): retained script
// bodies attached to observed script assets — normalization,
// validation, sorting, cloning, fingerprinting, and the minor version
// contract. All hermetic, no network.

func mustContentJS(t testing.TB, rawURL string) asset.JavaScript {
	t.Helper()
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	return js
}

func contentSnapshot(js asset.JavaScript, body string) Snapshot {
	return Snapshot{
		JavaScript:        []asset.JavaScript{js},
		JavaScriptContent: []JavaScriptContent{{Identity: js.Identity(), Body: body}},
	}
}

func TestNormalizeSnapshotJSContentAccepts(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/app.js")
	c, err := normalizeSnapshot(contentSnapshot(js, `el.innerHTML = location.hash;`))
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	if len(c.context.JavaScriptContent) != 1 {
		t.Fatalf("contents = %d, want 1", len(c.context.JavaScriptContent))
	}
	got := c.context.JavaScriptContent[0]
	if got.Identity != js.Identity() || got.Body != `el.innerHTML = location.hash;` {
		t.Fatalf("content = %+v, want the attached body", got)
	}
	if _, ok := c.observed[js.Identity()]; !ok {
		t.Fatal("script identity missing from the observed set")
	}
}

func TestNormalizeSnapshotJSContentRejections(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/app.js")
	other := mustContentJS(t, "https://www.example.com/other.js")
	cases := map[string]Snapshot{
		"zero identity": {
			JavaScript:        []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{{Body: "x"}},
		},
		"wrong kind": {
			JavaScript: []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{{
				Identity: asset.Identity{Kind: asset.KindHost, Value: "www.example.com"},
				Body:     "x",
			}},
		},
		"unattributed identity": {
			JavaScript:        []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{{Identity: other.Identity(), Body: "x"}},
		},
		"invalid utf8": {
			JavaScript:        []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{{Identity: js.Identity(), Body: "ok\xff\xfe"}},
		},
		"over body bound": {
			JavaScript:        []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{{Identity: js.Identity(), Body: strings.Repeat("x", 2<<20+1)}},
		},
		"duplicate identity": {
			JavaScript: []asset.JavaScript{js},
			JavaScriptContent: []JavaScriptContent{
				{Identity: js.Identity(), Body: "a"},
				{Identity: js.Identity(), Body: "b"},
			},
		},
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeSnapshot(snap); err == nil {
				t.Fatalf("normalizeSnapshot accepted %s content (want rejection)", name)
			}
		})
	}

	t.Run("over count bound", func(t *testing.T) {
		var scripts []asset.JavaScript
		var contents []JavaScriptContent
		for i := 0; i < MaxSnapshotJSContents+1; i++ {
			js, err := asset.NewJavaScript("https://h"+strconv.Itoa(i)+".example.com/app.js", asset.Provenance{Source: "test"})
			if err != nil {
				t.Fatalf("NewJavaScript: %v", err)
			}
			scripts = append(scripts, js)
			contents = append(contents, JavaScriptContent{Identity: js.Identity(), Body: "x"})
		}
		snap := Snapshot{JavaScript: scripts, JavaScriptContent: contents}
		if _, err := normalizeSnapshot(snap); err == nil {
			t.Fatalf("normalizeSnapshot accepted %d contents over bound %d", len(contents), MaxSnapshotJSContents)
		}
	})

	t.Run("over total bytes bound", func(t *testing.T) {
		// Full-size bodies whose sum exceeds the total budget: each body
		// is individually legal, the SET is not.
		perBody := strings.Repeat("x", MaxSnapshotJSContentBodyBytes)
		n := MaxSnapshotJSContentBytes/len(perBody) + 1
		var scripts []asset.JavaScript
		var contents []JavaScriptContent
		for i := 0; i < n; i++ {
			js, err := asset.NewJavaScript("https://h"+strconv.Itoa(i)+".example.com/app.js", asset.Provenance{Source: "test"})
			if err != nil {
				t.Fatalf("NewJavaScript: %v", err)
			}
			scripts = append(scripts, js)
			contents = append(contents, JavaScriptContent{Identity: js.Identity(), Body: perBody})
		}
		snap := Snapshot{JavaScript: scripts, JavaScriptContent: contents}
		if _, err := normalizeSnapshot(snap); err == nil {
			t.Fatalf("normalizeSnapshot accepted %d bytes over total bound %d", n*len(perBody), MaxSnapshotJSContentBytes)
		}
	})
}

func TestNormalizeSnapshotJSContentSorted(t *testing.T) {
	jsA := mustContentJS(t, "https://www.example.com/a.js")
	jsB := mustContentJS(t, "https://www.example.com/b.js")
	snap := Snapshot{
		JavaScript: []asset.JavaScript{jsA, jsB},
		JavaScriptContent: []JavaScriptContent{
			{Identity: jsB.Identity(), Body: "b"},
			{Identity: jsA.Identity(), Body: "a"},
		},
	}
	c, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	got := c.context.JavaScriptContent
	if len(got) != 2 || got[0].Identity != jsA.Identity() || got[1].Identity != jsB.Identity() {
		t.Fatalf("contents not identity-sorted: %+v", got)
	}
}

func TestFingerprintChangesWithBody(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/app.js")
	fpOf := func(body string) string {
		t.Helper()
		c, err := normalizeSnapshot(contentSnapshot(js, body))
		if err != nil {
			t.Fatalf("normalizeSnapshot: %v", err)
		}
		fp, err := fingerprintSnapshot(c)
		if err != nil {
			t.Fatalf("fingerprintSnapshot: %v", err)
		}
		return fp
	}
	a, b := fpOf("var x = 1;"), fpOf("var x = 2;")
	if a == b {
		t.Fatal("identical fingerprints for different bodies: changed content would serve stale findings")
	}
	// Empty contents fingerprint deterministically.
	c, err := normalizeSnapshot(Snapshot{JavaScript: []asset.JavaScript{js}})
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	e1, err := fingerprintSnapshot(c)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	e2, err := fingerprintSnapshot(c)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	if e1 != e2 {
		t.Fatal("empty-contents fingerprint not deterministic")
	}
}

func TestCloneCoversJSContent(t *testing.T) {
	js := mustContentJS(t, "https://www.example.com/app.js")
	src := &Context{
		JavaScript:        []asset.JavaScript{js},
		JavaScriptContent: []JavaScriptContent{{Identity: js.Identity(), Body: "original"}},
	}
	a := cloneContextForRule(src)
	b := cloneContextForRule(src)
	a.JavaScriptContent[0].Body = "mutated"
	a.JavaScriptContent = append(a.JavaScriptContent, JavaScriptContent{Identity: js.Identity(), Body: "injected"})
	for _, peer := range []*Context{b, src} {
		if len(peer.JavaScriptContent) != 1 || peer.JavaScriptContent[0].Body != "original" {
			t.Errorf("JavaScriptContent leaked through the clone: %+v", peer.JavaScriptContent)
		}
	}
}

func TestAPIMinorBump21(t *testing.T) {
	if APIMajor != 2 || APIMinor != 1 {
		t.Fatalf("SDK API level is %d.%d, want 2.1 (additive content channel)", APIMajor, APIMinor)
	}
	// Backward compatibility: packs compiled against 2.0 keep loading.
	if err := CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v (minor bumps must stay backward compatible)", err)
	}
	if err := CheckAPIVersion(2, 1); err != nil {
		t.Fatalf("CheckAPIVersion(2,1): %v", err)
	}
	if err := CheckAPIVersion(2, 2); err == nil {
		t.Fatal("CheckAPIVersion(2,2) accepted: this build predates that minor")
	}
	if err := CheckAPIVersion(1, 0); err == nil {
		t.Fatal("CheckAPIVersion(1,0) accepted: major mismatch must fail")
	}
}
