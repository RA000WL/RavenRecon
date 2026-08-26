package asset

import (
	"encoding/json"
	"strings"
	"testing"
)

// The pins in this file are the REVIEW-2026-08-25.md regressions for the
// URL model: R2-H1 (invalid UTF-8 rejection + identity stability across
// JSON persistence) and R2-M5 (credential redaction in ParseURL errors).

// TestParseURLRejectsInvalidUTF8 is the R2-H1 regression: invalid UTF-8 is
// rejected at the ingestion boundary instead of flowing into
// identity-bearing fields, where json.Marshal on cache put would silently
// rewrite the bytes to U+FFFD and mutate the stored identity. Before the
// fix both inputs parsed successfully.
func TestParseURLRejectsInvalidUTF8(t *testing.T) {
	p := NewProvenance("manual")
	for _, raw := range []string{
		"https://example.com/?q=\xff\xfe", // invalid bytes in the query value
		"https://example.com/\xff?q=1",    // invalid bytes in the path
	} {
		u, err := ParseURL(raw, p)
		if err == nil {
			t.Fatalf("ParseURL(%q) = %v, want invalid-UTF-8 rejection", raw, u)
		}
		if !strings.Contains(err.Error(), "valid UTF-8") {
			t.Errorf("ParseURL(%q) error %q does not mention valid UTF-8", raw, err)
		}
	}
}

// TestURLIdentityStableAcrossJSONRoundTrip is the R2-H1 regression pin: a
// URL's identity must survive a JSON persistence round trip unchanged.
// It also pins that the literal multibyte query form and its
// percent-encoded spelling share ONE identity: before the fix the multibyte
// form stayed as raw non-ASCII bytes in the canonical query while the
// encoded form stayed "%C3%A9", splitting one observation into two ids.
func TestURLIdentityStableAcrossJSONRoundTrip(t *testing.T) {
	p := NewProvenance("manual")
	parsed := make(map[string]URL)
	for _, raw := range []string{
		"https://example.com/?q=caf%C3%A9", // percent-encoded form
		"https://example.com/?q=café",      // literal multibyte form
	} {
		u, err := ParseURL(raw, p)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		b, err := json.Marshal(u)
		if err != nil {
			t.Fatalf("Marshal(%q): %v", raw, err)
		}
		var back URL
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("Unmarshal(%q): %v", raw, err)
		}
		if !back.Identity().Equal(u.Identity()) {
			t.Errorf("identity drifted across JSON round trip for %q: %s != %s", raw, u.ID(), back.ID())
		}
		parsed[raw] = u
	}

	enc := parsed["https://example.com/?q=caf%C3%A9"]
	lit := parsed["https://example.com/?q=café"]
	if !enc.Identity().Equal(lit.Identity()) {
		t.Errorf("percent-encoded and multibyte query forms split into two identities: %s vs %s", enc.ID(), lit.ID())
	}
}

// TestParseURLRedactsCredentialsInError is the R2-M5 regression: ParseURL
// rejections must never embed userinfo credentials in the error text —
// errors get logged reflexively. Before the fix the error wrapped %q(raw),
// leaking the password verbatim.
func TestParseURLRedactsCredentialsInError(t *testing.T) {
	p := NewProvenance("manual")
	_, err := ParseURL("https://user:hunter2@example.com:99999/", p)
	if err == nil {
		t.Fatalf("ParseURL with out-of-range port 99999 must fail")
	}
	msg := err.Error()
	if strings.Contains(msg, "hunter2") || strings.Contains(msg, "user:") {
		t.Errorf("ParseURL error leaks userinfo credentials: %q", msg)
	}
	if !strings.Contains(msg, "example.com") {
		t.Errorf("ParseURL error should keep the host for diagnosis, got %q", msg)
	}
}
