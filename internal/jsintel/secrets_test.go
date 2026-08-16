// Secret candidate extraction tests: the regex families, dynamic-template
// skipping, per-file dedup, and the per-file cap. Detection only — no
// verification is ever represented.
package jsintel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testSecretsConfig returns a Config for secret extraction unit tests.
func testSecretsConfig() Config {
	return Config{Source: "test-src", Clock: newFakeClock(fixedTime)}
}

func TestExtractSecrets(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u, Prov: asset.Provenance{Source: "test-src"}}
	parsed := Parsed{Strings: []StringLit{
		{Value: `"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz012345"`},
		{Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{Value: "AKIAIOSFODNN7EXAMPLE"},
		{Value: "AIza" + strings.Repeat("x", 35)},
		{Value: "sk_" + "live_abcdefghijklmnopqrstuvwxyz0123"},
		{Value: "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"},
		{Value: "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ=="},
	}}
	out := extractSecrets(js, parsed, testSecretsConfig())

	if len(out.secrets) != 7 {
		t.Fatalf("secrets = %d, want 7 (one per family)", len(out.secrets))
	}
	if len(out.edges) != 7 {
		t.Fatalf("edges = %d, want 7 (1:1 with secrets)", len(out.edges))
	}
	byType := map[asset.SecretType]int{}
	for _, s := range out.secrets {
		byType[s.Type]++
		if !s.Source.Equal(js.Identity()) {
			t.Errorf("secret source = %q, want %q", s.Source, js.Identity())
		}
		if s.Prov.Source != "test-src" || !s.Prov.DiscoveredAt.Equal(fixedTime) {
			t.Errorf("secret provenance = %+v, want test-src at %v", s.Prov, fixedTime)
		}
	}
	want := map[asset.SecretType]int{
		asset.SecretTypeBearer:     1,
		asset.SecretTypeJWT:        1,
		asset.SecretTypeAWS:        1,
		asset.SecretTypeGoogle:     1,
		asset.SecretTypeStripe:     1,
		asset.SecretTypeGitHub:     1,
		asset.SecretTypePrivateKey: 1,
	}
	for typ, n := range want {
		if byType[typ] != n {
			t.Errorf("count of %s = %d, want %d", typ, byType[typ], n)
		}
	}
	// The private key candidate carries the BEGIN marker plus up to
	// privateKeyMaterialBytes following bytes (here the literal is shorter
	// than the bound, so the whole literal is the value).
	for _, s := range out.secrets {
		if s.Type == asset.SecretTypePrivateKey {
			if !strings.HasPrefix(s.Value, "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("private key value = %q, want the BEGIN marker prefix", s.Value)
			}
			if len(s.Value) > len("-----BEGIN PRIVATE KEY-----")+privateKeyMaterialBytes {
				t.Errorf("private key value length = %d, exceeds marker + %d bytes", len(s.Value), privateKeyMaterialBytes)
			}
			if !strings.HasSuffix(s.Value, "=") {
				t.Errorf("private key value = %q, want the following key material retained", s.Value)
			}
		}
	}
	if out.skipped != 0 || out.dropped != 0 {
		t.Errorf("skipped/dropped = %d/%d, want 0/0", out.skipped, out.dropped)
	}
}

func TestExtractSecretsDedupAndSkipped(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{Strings: []StringLit{
		{Value: "AKIAIOSFODNN7EXAMPLE"},
		{Value: "AKIAIOSFODNN7EXAMPLE"},          // duplicate: one candidate
		{Value: "key-${secret}", Template: true}, // dynamic: skipped
	}}
	out := extractSecrets(js, parsed, testSecretsConfig())

	if len(out.secrets) != 1 {
		t.Fatalf("secrets = %d, want 1 (deduplicated)", len(out.secrets))
	}
	if out.secrets[0].Type != asset.SecretTypeAWS || out.secrets[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("secret = %+v, want the AWS candidate", out.secrets[0])
	}
	if out.skipped != 1 {
		t.Errorf("skipped = %d, want 1 (dynamic template)", out.skipped)
	}
}

func TestExtractSecretsCap(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	cfg := testSecretsConfig()
	cfg.MaxSecretsPerFile = 2
	parsed := Parsed{Strings: []StringLit{
		{Value: "AKIAIOSFODNN7EXAMPLE"},
		{Value: "sk_" + "live_abcdefghijklmnopqrstuvwxyz0123"},
		{Value: "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"},
	}}
	out := extractSecrets(js, parsed, cfg)

	if len(out.secrets) != 2 {
		t.Fatalf("secrets = %d, want 2 (cap)", len(out.secrets))
	}
	if len(out.edges) != 2 {
		t.Errorf("edges = %d, want 2 (1:1 with retained secrets)", len(out.edges))
	}
	if out.dropped != 1 {
		t.Errorf("dropped = %d, want 1", out.dropped)
	}
}
