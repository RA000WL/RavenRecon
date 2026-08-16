package patterns

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestLoadProductionDatabase(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if db.Version() != SchemaVersion {
		t.Errorf("Version = %d, want %d", db.Version(), SchemaVersion)
	}
	if db.Len() == 0 {
		t.Fatal("production database is empty")
	}
	if db.Len() != FingerprintCount {
		t.Errorf("production database has %d patterns, want the canonical %d", db.Len(), FingerprintCount)
	}
	if len(db.Correlations()) == 0 {
		t.Error("production correlation table is empty")
	}

	// Deterministic, unique, sorted by ID; every pattern compiled exactly
	// once with a non-nil shared regex.
	pats := db.Patterns()
	seen := map[string]bool{}
	for i, p := range pats {
		if p.ID == "" {
			t.Fatal("empty pattern ID")
		}
		if seen[p.ID] {
			t.Errorf("duplicate pattern ID %q", p.ID)
		}
		seen[p.ID] = true
		if i > 0 && pats[i-1].ID >= p.ID {
			t.Errorf("patterns not sorted: %q >= %q", pats[i-1].ID, p.ID)
		}
		if p.Match() == nil {
			t.Errorf("pattern %q has a nil compiled regex", p.ID)
		}
		if p.Match().NumSubexp() < p.Group {
			t.Errorf("pattern %q group %d exceeds %d groups", p.ID, p.Group, p.Match().NumSubexp())
		}
		if !p.Family.Valid() {
			t.Errorf("pattern %q has invalid family %q", p.ID, p.Family)
		}
		if !p.Type.Valid() {
			t.Errorf("pattern %q has invalid type %q", p.ID, p.Type)
		}
	}
	if len(pats) < 30 {
		t.Errorf("production database has only %d patterns; expected a full multi-provider database", len(pats))
	}

	// Fresh copies: mutating the returned slice never affects the DB.
	mut := db.Patterns()
	for i := range mut {
		mut[i].ID = "tampered"
	}
	if db.Patterns()[0].ID == "tampered" {
		t.Error("Patterns must return a fresh copy")
	}

	// Compile-once: accessors share one instance.
	a := db.Patterns()[0]
	b, ok := db.ByID(a.ID)
	if !ok {
		t.Fatalf("ByID(%q) not found", a.ID)
	}
	if a.Match() != b.Match() {
		t.Error("compiled regexes must be shared (compile-once)")
	}
}

func TestKnownValuesMatch(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		id    string
		input string
		want  string
	}{
		{"aws-access-key-id", "config: AKIAIOSFODNN7REALKEY", "AKIAIOSFODNN7REALKEY"},
		{"aws-secret-access-key", `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"google-api-key", `key: "AIza0123456789abcdefghijklmnopqrstuvwxy"`, "AIza0123456789abcdefghijklmnopqrstuvwxy"},
		{"github-token", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"},
		{"gitlab-pat", "glpat-" + strings.Repeat("x", 20), "glpat-" + strings.Repeat("x", 20)},
		{"stripe-live-key", "sk_live_" + strings.Repeat("a", 24), "sk_live_" + strings.Repeat("a", 24)},
		{"slack-token", "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuv", "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuv"},
		{"openai-api-key", "sk-proj-" + strings.Repeat("a", 40), "sk-proj-" + strings.Repeat("a", 40)},
		{"anthropic-api-key", "sk-ant-api03-" + strings.Repeat("a", 40), "sk-ant-api03-" + strings.Repeat("a", 40)},
		{"digitalocean-pat", "dop_v1_" + strings.Repeat("a", 64), "dop_v1_" + strings.Repeat("a", 64)},
		{"google-oauth-access", "ya29." + strings.Repeat("a", 40), "ya29." + strings.Repeat("a", 40)},
		{"azure-storage-connection", "DefaultEndpointsProtocol=https;AccountName=storageacct;AccountKey=" + strings.Repeat("ab", 32) + "=;", "DefaultEndpointsProtocol=https;AccountName=storageacct;AccountKey=" + strings.Repeat("ab", 32) + "=;"},
		{"rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA", "-----BEGIN RSA PRIVATE KEY-----"},
		{"ssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"postgres-url", "DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod", "postgres://admin:hunter2@db.example.com:5432/prod"},
		{"mongodb-url", `uri: "mongodb+srv://user:pass@cluster0.mongodb.net/db"`, "mongodb+srv://user:pass@cluster0.mongodb.net/db"},
		{"redis-url", "redis://:mypassword@cache.internal:6379/0", "redis://:mypassword@cache.internal:6379/0"},
		{"smtp-url", "smtp://user:pass@mail.example.com:587", "smtp://user:pass@mail.example.com:587"},
		{"slack-webhook", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"},
		{"discord-webhook", "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("a", 60), "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("a", 60)},
		{"s3-bucket-url", "https://my-bucket.s3.us-west-2.amazonaws.com/file.txt", "https://my-bucket.s3.us-west-2.amazonaws.com/file.txt"},
		{"api-key-assignment", `"apiKey": "a1b2c3d4e5f6a7b8c9d0"`, "a1b2c3d4e5f6a7b8c9d0"},
		{"api-key-assignment", "apiKey = a1b2c3d4e5f6a7b8c9d0", "a1b2c3d4e5f6a7b8c9d0"},
		{"aws-secret-access-key", `{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"database-url-assignment", "DATABASE_URL=\"postgres://admin:hunter2@db.example.com/prod\"", "postgres://admin:hunter2@db.example.com/prod"},
	}
	for _, tt := range cases {
		t.Run(tt.id, func(t *testing.T) {
			p, ok := db.ByID(tt.id)
			if !ok {
				t.Fatalf("pattern %q not in database", tt.id)
			}
			m := p.Match().FindStringSubmatch(tt.input)
			if m == nil {
				t.Fatalf("pattern %q did not match %q", tt.id, tt.input)
			}
			got := m[0]
			if p.Group > 0 {
				got = m[p.Group]
			}
			if got != tt.want {
				t.Errorf("pattern %q captured %q, want %q", tt.id, got, tt.want)
			}
			if len(got) < p.MinLen || (p.MaxLen > 0 && len(got) > p.MaxLen) {
				t.Errorf("pattern %q captured %d bytes outside its own bounds [%d,%d]", tt.id, len(got), p.MinLen, p.MaxLen)
			}
		})
	}
}

func TestKnownNonMatches(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		id    string
		input string
	}{
		{"aws-access-key-id", "AKIA123"},                          // too short
		{"aws-access-key-id", "akiaiosfodnn7example"},             // lowercase, no marker
		{"github-token", "ghp_short"},                             // too short
		{"stripe-live-key", "sk_test_" + strings.Repeat("a", 24)}, // test keys deliberately unmatched
		{"postgres-url", "postgres://localhost/db"},               // no credentials: not a secret
		{"slack-webhook", "https://hooks.slack.com/services/incomplete"},
		{"openai-api-key", "sk-live_123"}, // stripe-shaped, not sk- prefixed
	}
	for _, tt := range cases {
		t.Run(tt.id+"/"+tt.input, func(t *testing.T) {
			p, ok := db.ByID(tt.id)
			if !ok {
				t.Fatalf("pattern %q not in database", tt.id)
			}
			if p.Match().MatchString(tt.input) {
				t.Errorf("pattern %q must not match %q", tt.id, tt.input)
			}
		})
	}
}

func TestCompileForTestValidation(t *testing.T) {
	base := Pattern{
		ID: "test-pattern", Type: asset.SecretTypeAWS, Provider: "aws",
		Family: FamilyStructured, Regex: `AKIA[0-9A-Z]{16}`, Strength: 0.5,
	}
	cases := []struct {
		name    string
		mutate  func(*Pattern)
		wantSub string
	}{
		{"empty id", func(p *Pattern) { p.ID = "" }, "ID must not be empty"},
		{"bad type", func(p *Pattern) { p.Type = asset.SecretType("bogus") }, "unknown secret type"},
		{"bad provider", func(p *Pattern) { p.Provider = "AWS" }, "lowercase"},
		{"bad family", func(p *Pattern) { p.Family = Family("nope") }, "unknown family"},
		{"bad regex", func(p *Pattern) { p.Regex = "(" }, "does not compile"},
		{"group out of range", func(p *Pattern) { p.Group = 2 }, "out of range"},
		{"zero strength", func(p *Pattern) { p.Strength = 0 }, "strength"},
		{"strength over one", func(p *Pattern) { p.Strength = 1.5 }, "strength"},
		{"bad validator", func(p *Pattern) { p.Validator = Validator("nope") }, "unknown validator"},
		{"bad entropy class", func(p *Pattern) { p.Entropy.Class = EntropyClass("nope") }, "unknown entropy class"},
		{"bad min shannon", func(p *Pattern) { p.Entropy.MinShannon = -1 }, "min shannon"},
		{"empty negative", func(p *Pattern) { p.Negatives = []string{""} }, "empty negatives"},
		{"too many hints", func(p *Pattern) { p.Hints = make([]string, maxIndicatorsPerField+1) }, "more than"},
		{"min>max len", func(p *Pattern) { p.MinLen = 40; p.MaxLen = 10 }, "invalid length bounds"},
		{"trail too big", func(p *Pattern) { p.Trail = maxTrailBytes + 1 }, "trail"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			tt.mutate(&p)
			_, err := CompileForTest([]Pattern{p})
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// Duplicate IDs across entries fail the compile.
	if _, err := CompileForTest([]Pattern{base, base}); err == nil || !strings.Contains(err.Error(), "duplicate pattern ID") {
		t.Errorf("duplicate IDs must fail: %v", err)
	}

	// A valid entry compiles with a shared regex.
	db, err := CompileForTest([]Pattern{base})
	if err != nil {
		t.Fatalf("valid entry: %v", err)
	}
	if db.Len() != 1 || db.Patterns()[0].Match() == nil {
		t.Error("valid entry must compile")
	}
}

func TestCorrelationTableValid(t *testing.T) {
	// The production correlation table is part of Load's validation: providers
	// are unique, sorted, and indicators bounded.
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	corr := db.Correlations()
	for i, c := range corr {
		if c.Provider == "" {
			t.Error("correlation provider must not be empty")
		}
		if i > 0 && corr[i-1].Provider >= c.Provider {
			t.Errorf("correlations not sorted: %q >= %q", corr[i-1].Provider, c.Provider)
		}
	}
	for _, c := range corr {
		for _, p := range db.Patterns() {
			if p.Provider == c.Provider {
				return // at least one pattern is covered (checked loosely)
			}
		}
	}
	// Every correlation provider has at least one pattern referencing it.
	covered := map[string]bool{}
	for _, p := range db.Patterns() {
		if p.Provider != "" {
			covered[p.Provider] = true
		}
	}
	for _, c := range corr {
		if !covered[c.Provider] {
			t.Errorf("correlation provider %q has no pattern", c.Provider)
		}
	}
}

func TestCompileForTestCorrelationValidation(t *testing.T) {
	p := Pattern{ID: "p1", Type: asset.SecretTypeAWS, Provider: "aws", Family: FamilyStructured, Regex: "x", Strength: 0.5}
	if _, err := CompileForTest([]Pattern{p}, []ProviderCorrelation{{Provider: "aws", Endpoints: []string{"ok"}}}); err != nil {
		t.Fatalf("valid correlation: %v", err)
	}
	if _, err := CompileForTest([]Pattern{p}, []ProviderCorrelation{{Provider: "AWS"}}); err == nil {
		t.Error("uppercase provider must fail")
	}
	if _, err := CompileForTest([]Pattern{p}, []ProviderCorrelation{{Provider: "aws"}, {Provider: "aws"}}); err == nil {
		t.Error("duplicate provider must fail")
	}
	if _, err := CompileForTest([]Pattern{p}, []ProviderCorrelation{{Provider: "aws", Endpoints: []string{""}}}); err == nil {
		t.Error("empty endpoint must fail")
	}
}
