package urlintel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestIngestUserinfoRedactedAtConstruction pins the credential-redaction fix
// (audit finding M-3): a raw line carrying userinfo must be redacted at the
// single ingest construction point (parseRawURL), so asset.URL.Original
// equals the canonical form everywhere downstream — the report entry AND the
// on-disk cache record payload are credential-free.
func TestIngestUserinfoRedactedAtConstruction(t *testing.T) {
	cfg := testConfig()
	cfg.Cache = openTestCache(t, newFakeClock(fixedTime), 0)
	cfg.Metrics = &Metrics{}

	const raw = "http://user:pass@example.com/path?a=1"
	const canonical = "http://example.com/path?a=1"
	rep := runIngest(t, cfg, []string{raw})

	// (a) The emitted entry's URL carries no userinfo: Original equals the
	// canonical form.
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
	}
	e := rep.Entries[0]
	if e.URL.String() != canonical {
		t.Fatalf("URL = %q, want %q", e.URL.String(), canonical)
	}
	if e.URL.Original != canonical {
		t.Fatalf("URL.Original = %q, want the canonical form %q (userinfo must be redacted)", e.URL.Original, canonical)
	}
	if strings.Contains(e.URL.Original, "user:pass") {
		t.Fatalf("URL.Original leaks the credential: %q", e.URL.Original)
	}

	// (b) The cache record payload contains no userinfo: a raw scan of the
	// stored bytes (any smuggled field would show up) plus the typed check.
	u := mustURL(t, canonical)
	key, err := urlKey(u, cfg.Adapter, cfg.ParseParameters)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("cache miss for the stored observation (state %v)", out.State)
	}
	if data := string(out.Record.Data); strings.Contains(data, "user:pass") {
		t.Fatalf("stored record leaks the credential: %s", data)
	}
	var st storedURL
	if err := json.Unmarshal(out.Record.Data, &st); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	if st.URL.Original != canonical {
		t.Fatalf("stored URL.Original = %q, want the canonical form %q", st.URL.Original, canonical)
	}
	if st.Target != u.Identity().String() {
		t.Fatalf("stored target = %q, want %q", st.Target, u.Identity().String())
	}
}

// TestIngestUserinfoVariantsMergeRedacted pins the merge behavior: two lines
// differing ONLY in userinfo merge by identity (identity excludes userinfo)
// into one entry whose URL carries no userinfo. Both lines are redacted at
// ingest, so no unredacted Original can re-enter via a later observation of
// the same identity — the redacted first-seen Original survives the merge.
func TestIngestUserinfoVariantsMergeRedacted(t *testing.T) {
	rep := runIngest(t, testConfig(), []string{
		"http://user:pass@example.com/x",
		"http://other:secret@example.com/x",
	})

	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (identity excludes userinfo)", len(rep.Entries))
	}
	e := rep.Entries[0]
	const canonical = "http://example.com/x"
	if e.URL.String() != canonical || e.URL.Original != canonical {
		t.Fatalf("merged URL = %q (Original %q), want canonical %q with no userinfo",
			e.URL.String(), e.URL.Original, canonical)
	}
	for _, credential := range []string{"user:pass", "other:secret", "pass@", "secret@"} {
		if strings.Contains(e.URL.Original, credential) {
			t.Fatalf("merged URL.Original leaks %q: %q", credential, e.URL.Original)
		}
	}
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", e.Status)
	}
	// The report-level merged asset is redacted too.
	urls := rep.AllURLs()
	if len(urls) != 1 || urls[0].Original != canonical {
		t.Fatalf("AllURLs[0] = %+v, want the redacted canonical URL", urls)
	}
}

// TestIngestNoUserinfoUntouched pins that a line WITHOUT userinfo passes
// through unchanged: Original already equals the canonical form, so the
// redaction re-parse is a no-op and the exact raw spelling survives.
func TestIngestNoUserinfoUntouched(t *testing.T) {
	const raw = "http://example.com/path?a=1"
	rep := runIngest(t, testConfig(), []string{raw})
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
	}
	e := rep.Entries[0]
	if e.URL.Original != raw || e.URL.String() != raw {
		t.Fatalf("URL = %q (Original %q), want the untouched canonical line %q",
			e.URL.String(), e.URL.Original, raw)
	}
}
