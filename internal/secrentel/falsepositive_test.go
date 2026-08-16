package secrentel

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestClassifyValueSuppressesKnownExamples(t *testing.T) {
	cases := []struct {
		value string
		typ   asset.SecretType
	}{
		{"AKIAIOSFODNN7EXAMPLE", asset.SecretTypeAWS},                     // AWS's documented example
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", asset.SecretTypeAWS}, // AWS's documented example secret
		{"sk_live_CHANGEME1234567890123456", asset.SecretTypeStripe},
		{"your-api-key-here123456", asset.SecretTypeAPIKey},
		{"lorem ipsum dolor sit amet", asset.SecretTypeGeneric},
		{"aaaaaaaaaaaaaaaaaaaa", asset.SecretTypeGeneric}, // uniform run
		{"XXXXXXXXXXXXXXXXXXXX", asset.SecretTypeGeneric}, // XXXX filler
		{"REPLACE_ME_BEFORE_PROD", asset.SecretTypeGeneric},
		{"XXXXXXXXXXXXXXXXXXXX", asset.SecretTypeGeneric},
		{"sampletoken123456789", asset.SecretTypeAPIKey},
		{"password", asset.SecretTypeGeneric}, // short human word
	}
	for _, tt := range cases {
		if reason := classifyValue(tt.value, tt.typ); reason == "" {
			t.Errorf("classifyValue(%q) must be suppressed", tt.value)
		}
	}
}

func TestClassifyValueKeepsRealisticValues(t *testing.T) {
	kept := []struct {
		value string
		typ   asset.SecretType
	}{
		// GitHub's documented example token carries NO marker; it stays a
		// (low-confidence) candidate — suppression is for marked values
		// only, by design.
		{"ghp_16C7e42F292c6912E7710c838347Ae178B4a", asset.SecretTypeGitHub},
		{"AKIA" + detRand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 7, 3), asset.SecretTypeAWS},
		{"ghp_" + detRand(36, alnumMixed, 11, 2), asset.SecretTypeGitHub},
		{"sk_live_" + detRand(24, alnumMixed, 13, 1), asset.SecretTypeStripe},
		{detRand(40, alnumMixed+"/+=", 17, 4), asset.SecretTypeGeneric}, // long random values are never "short words"
		{"postgres://admin:" + detRand(16, alnumMixed, 7, 9) + "@db.example.com/prod", asset.SecretTypePostgreSQLURL},
	}
	for _, tt := range kept {
		if reason := classifyValue(tt.value, tt.typ); reason != "" {
			t.Errorf("classifyValue(%q) wrongly suppressed: %s", tt.value, reason)
		}
	}
}

func TestClassifyContextFlags(t *testing.T) {
	cases := []struct {
		filename string
		path     string
		wantFlag bool
	}{
		{"config/production.env", "", false},
		{"test/config.env", "", true},
		{"", "/js/app.example.js", true},
		{"", "/assets/bundle.min.js", false},
		{"docs/setup.md", "", true},
		{"spec/database.yml", "", true},
		{"mock-server.js", "", true},
	}
	for _, tt := range cases {
		flags := classifyContext(tt.filename, tt.path)
		if (len(flags) > 0) != tt.wantFlag {
			t.Errorf("classifyContext(%q, %q) = %v, wantFlag=%v", tt.filename, tt.path, flags, tt.wantFlag)
		}
		if len(flags) > 3 {
			t.Errorf("flags not bounded: %v", flags)
		}
	}
}
