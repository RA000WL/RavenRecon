package secrentel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

func loadDB(t *testing.T) *patterns.DB {
	t.Helper()
	db, err := patterns.Load()
	if err != nil {
		t.Fatalf("patterns.Load: %v", err)
	}
	return db
}

func scanOf(t *testing.T, d Document) (scannedDocument, scanOutcome) {
	t.Helper()
	sd, err := prepareDocument(d, fixedTime(0))
	if err != nil {
		t.Fatalf("prepareDocument: %v", err)
	}
	return sd, scanDocument(sd, loadDB(t), defaultScanLimits())
}

func findByValue(out scanOutcome, prefix string) *scannedCandidate {
	for i := range out.candidates {
		if strings.HasPrefix(out.candidates[i].value, prefix) {
			return &out.candidates[i]
		}
	}
	return nil
}

// Realistic synthetic values with genuine entropy.
var (
	awsKeyID    = "AKIA" + detRand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 7, 3)
	awsSecret   = detRand(40, alnumMixed+"/+=", 17, 4)
	githubToken = "ghp_" + detRand(36, alnumMixed, 11, 2)
	jwtValue    = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + detRand(24, alnumMixed, 13, 5)
)

func TestScanJavaScriptWithAWSCorrelation(t *testing.T) {
	content := fmt.Sprintf(
		`const config={region:"us-east-1",aws_access_key_id:"%s",aws_secret_access_key:"%s",endpoint:"https://my-bucket.s3.us-west-2.amazonaws.com/assets"};`,
		awsKeyID, awsSecret)
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte(content), Technology: []string{"aws-sdk"}})

	key := findByValue(out, "AKIA")
	if key == nil {
		t.Fatalf("AWS access key not found; candidates: %+v counts: %+v", out.candidates, out.counts)
	}
	if key.typ != asset.SecretTypeAWS || key.provider != "aws" {
		t.Errorf("key type/provider = %s/%s", key.typ, key.provider)
	}
	if key.context.NameHint == "" {
		t.Errorf("aws_access_key_id assignment must produce a name hint: %+v", key.context)
	}
	if key.location.Line != 1 || key.location.Column < 2 {
		t.Errorf("minified single-line JS location = %+v, want line 1", key.location)
	}

	// Multi-evidence correlation: key + secret pair + endpoint + technology.
	factors := map[string]float64{}
	for _, f := range key.confidence.Factors {
		factors[f.Name] = f.Weight
	}
	for _, want := range []string{"pair", "endpoint", "technology"} {
		if _, ok := factors[want]; !ok {
			t.Errorf("missing %s factor in %+v", want, key.confidence.Factors)
		}
	}
	if key.confidence.Level != LevelHigh {
		t.Errorf("correlated AWS key should be High, got %s (%.2f): %+v", key.confidence.Level, key.confidence.Score, key.confidence.Factors)
	}
	if len(key.related) == 0 {
		t.Error("pair siblings must be linked")
	}

	sec := findByValue(out, awsSecret[:8])
	if sec == nil {
		t.Fatal("AWS secret not found")
	}
	if sec.typ != asset.SecretTypeAWS {
		t.Errorf("secret type = %s", sec.typ)
	}

	// Evidence, edges, deterministic ordering.
	if len(out.evidence) == 0 || len(out.edges) == 0 {
		t.Error("evidence records and edges must be produced")
	}
	for i := 1; i < len(out.candidates); i++ {
		if out.candidates[i-1].id >= out.candidates[i].id {
			t.Error("candidates must be sorted by ID")
		}
	}
}

func TestScanStructuredDuplicateValueSuppressed(t *testing.T) {
	// The apiKey assignment captures the Google key value; the structured
	// google-api-key pattern identifies the same value better, so the
	// contextual duplicate is dropped.
	gkey := "AIza" + detRand(35, alnumMixed, 7, 6)
	_, out := scanOf(t, Document{Kind: KindJSON, Content: []byte(fmt.Sprintf(`{"apiKey": "%s"}`, gkey))})

	var google, apiKey int
	for _, c := range out.candidates {
		if c.typ == asset.SecretTypeGoogle {
			google++
		}
		if c.typ == asset.SecretTypeAPIKey {
			apiKey++
		}
	}
	if google != 1 {
		t.Errorf("google candidates = %d, want 1", google)
	}
	if apiKey != 0 {
		t.Errorf("contextual api_key duplicate must be dropped, got %d", apiKey)
	}
	// The api-key assignment captures the value; the contextual duplicate
	// is dropped. (The generic family no longer fires on "apiKey": bare
	// key names were removed from its alternation.)
	if out.counts.DroppedDuplicateValue != 1 {
		t.Errorf("DroppedDuplicateValue = %d, want 1", out.counts.DroppedDuplicateValue)
	}
}

func TestScanFalsePositivesSuppressed(t *testing.T) {
	content := []byte(
		`A=AKIAIOSFODNN7EXAMPLE
B=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
C=placeholder-value-1234567890
D=secret: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)
	sd, err := prepareDocument(Document{Kind: KindEnv, Content: content}, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	out := scanDocument(sd, loadDB(t), defaultScanLimits())

	// The AWS example key is suppressed by the pattern negative AND the FP
	// value engine; the example secret has no pattern (contextual regex
	// matches "B=..."? no — no assignment shape) — only the marked values
	// that match patterns count here.
	if len(out.candidates) != 0 {
		t.Errorf("no candidates expected from example values, got %+v", out.candidates)
	}
	if out.counts.SuppressedFP == 0 && out.counts.DroppedNegative == 0 {
		t.Errorf("example values must be suppressed: %+v", out.counts)
	}
}

func TestScanEntropyDropsProse(t *testing.T) {
	// A 40-char uniform value matches the aws secret regex shape but has
	// zero entropy: the entropy rule drops it.
	content := []byte(`aws_secret_access_key: abababababababababababababababababababab`)
	_, out := scanOf(t, Document{Kind: KindYAML, Content: content})
	if len(out.candidates) != 0 {
		t.Errorf("uniform value must be dropped by the entropy rule, got %+v", out.candidates)
	}
	if out.counts.DroppedEntropy != 1 {
		t.Errorf("DroppedEntropy = %d, want 1 (counts %+v)", out.counts.DroppedEntropy, out.counts)
	}
}

func TestScanValidatorDropsBadJWT(t *testing.T) {
	// Valid JWT shape (three base64url segments) but the header is not a
	// JSON object with alg: the structural validator drops it.
	bad := "eyJmb28iOiJiYXIifQ" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + detRand(20, alnumMixed, 7, 1)
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte("t('" + bad + "')")})
	if len(out.candidates) != 0 {
		t.Errorf("malformed JWT must be dropped, got %+v", out.candidates)
	}
	if out.counts.DroppedValidator != 1 {
		t.Errorf("DroppedValidator = %d, want 1", out.counts.DroppedValidator)
	}

	// A structurally valid JWT is kept and carries the jwt_structure
	// evidence trail.
	_, out = scanOf(t, Document{Kind: KindJS, Content: []byte("t('" + jwtValue + "')")})
	if c := findByValue(out, "eyJ"); c == nil {
		t.Fatalf("valid JWT must be kept: %+v", out.counts)
	}
}

func TestScanPrivateKeyBlocks(t *testing.T) {
	rsa := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA" + detRand(60, alnumMixed+"/+", 7, 2) + "\n-----END RSA PRIVATE KEY-----"
	ssh := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk" + detRand(60, alnumMixed, 5, 8) + "\n-----END OPENSSH PRIVATE KEY-----"
	_, out := scanOf(t, Document{Kind: KindConfig, Content: []byte(rsa + "\n" + ssh)})

	var rsaFound, sshFound bool
	for _, c := range out.candidates {
		if c.typ == asset.SecretTypeRSAPrivateKey {
			rsaFound = true
			if !strings.Contains(c.value, "MIIEpAIBAAKCAQEA") {
				t.Errorf("RSA candidate must include trailing key material: %q", c.value)
			}
		}
		if c.typ == asset.SecretTypeSSHPrivateKey {
			sshFound = true
		}
	}
	if !rsaFound || !sshFound {
		t.Errorf("rsa=%v ssh=%v (candidates %+v)", rsaFound, sshFound, out.candidates)
	}
}

func TestScanDatabaseURLsAndWebhooks(t *testing.T) {
	env := []byte(fmt.Sprintf(
		"DATABASE_URL=postgres://admin:%s@db.internal.example.com:5432/prod\nREDIS_URL=redis://:%s@cache.internal:6379/0\nSLACK=https://hooks.slack.com/services/T12345678/B12345678/%s\n",
		detRand(16, alnumMixed, 7, 9), detRand(16, alnumMixed, 11, 3), detRand(24, "abcdefghijklmnopqrstuvwxyz", 7, 1)))
	_, out := scanOf(t, Document{Kind: KindEnv, Content: env})

	types := map[asset.SecretType]int{}
	for _, c := range out.candidates {
		types[c.typ]++
	}
	for _, want := range []asset.SecretType{asset.SecretTypePostgreSQLURL, asset.SecretTypeRedisURL, asset.SecretTypeWebhookURL} {
		if types[want] == 0 {
			t.Errorf("missing %s candidate; types: %v", want, types)
		}
	}
	// The DATABASE_URL assignment's captured value duplicates the postgres
	// structured match: exactly one postgres_url candidate, no database_url.
	if types[asset.SecretTypeDatabaseURL] != 0 {
		t.Errorf("database_url duplicate not dropped: %v", types)
	}
}

func TestScanS3BucketURLClampedLow(t *testing.T) {
	// A bare S3 bucket URL is observation material, not a secret: the
	// pure-endpoint URL cap holds it at Low, the endpoint factor is
	// suppressed (the value IS the endpoint), and the clamp is recorded.
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte(`const u = "https://my-bucket.s3.us-east-1.amazonaws.com/file.txt";`)})
	c := findByValue(out, "https://my-bucket")
	if c == nil {
		t.Fatalf("S3 bucket URL must still be reported: %+v", out.candidates)
	}
	if c.typ != asset.SecretTypeS3 {
		t.Errorf("type = %s, want s3", c.typ)
	}
	if c.confidence.Level.rank() > LevelLow.rank() || c.confidence.Score > urlTypeCap {
		t.Errorf("S3 bucket URL must cap at Low: %s %.2f", c.confidence.Level, c.confidence.Score)
	}
	if hasFactor(c.confidence, "endpoint") {
		t.Errorf("endpoint factor must be suppressed when the value is the endpoint: %+v", c.confidence.Factors)
	}
	if !hasFactor(c.confidence, "url_type_cap") {
		t.Errorf("url_type_cap factor must record the clamp: %+v", c.confidence.Factors)
	}
}

func TestScanCredentialLessDBURLClampedLow(t *testing.T) {
	// A DATABASE_URL without credentials is not a secret: even with a
	// strong assignment-name context (which used to reach Medium), the
	// pure-endpoint URL cap holds it at Low.
	_, out := scanOf(t, Document{Kind: KindEnv, Content: []byte("DATABASE_URL=postgres://db.example.com/prod")})
	c := findByValue(out, "postgres://db.example.com")
	if c == nil {
		t.Fatalf("credential-less DB URL must still be reported: %+v", out.candidates)
	}
	if c.typ != asset.SecretTypeDatabaseURL {
		t.Errorf("type = %s, want database_url", c.typ)
	}
	if c.confidence.Level.rank() > LevelLow.rank() || c.confidence.Score > urlTypeCap {
		t.Errorf("credential-less DB URL must cap at Low: %s %.2f", c.confidence.Level, c.confidence.Score)
	}
	if !hasFactor(c.confidence, "url_type_cap") {
		t.Errorf("url_type_cap factor must record the clamp: %+v", c.confidence.Factors)
	}
}

func TestScanUserinfoDBURLGetsCredentialsFactor(t *testing.T) {
	// A connection string WITH user:pass@ authority carries real
	// credentials: the url_credentials factor fires, the endpoint factor is
	// suppressed (the scheme literally contains the provider's endpoint
	// indicator), and the candidate is at least Medium.
	_, out := scanOf(t, Document{Kind: KindEnv, Content: []byte("DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod")})
	c := findByValue(out, "postgres://")
	if c == nil {
		t.Fatalf("userinfo postgres URL must be reported: %+v", out.candidates)
	}
	if c.typ != asset.SecretTypePostgreSQLURL {
		t.Errorf("type = %s, want postgres_url", c.typ)
	}
	if !hasFactor(c.confidence, "url_credentials") {
		t.Errorf("url_credentials factor missing: %+v", c.confidence.Factors)
	}
	if hasFactor(c.confidence, "endpoint") {
		t.Errorf("endpoint factor must be suppressed (the value contains the endpoint): %+v", c.confidence.Factors)
	}
	if c.confidence.Level.rank() < LevelMedium.rank() {
		t.Errorf("credential-bearing DB URL must be at least Medium: %s %.2f", c.confidence.Level, c.confidence.Score)
	}
	if hasFactor(c.confidence, "url_type_cap") {
		t.Errorf("postgres_url is not a capped type: %+v", c.confidence.Factors)
	}
}

func TestScanDiscordWebhookMediumNotCapped(t *testing.T) {
	// Discord webhooks are URL-shaped but genuinely sensitive: pattern 0.85
	// + strong context reaches High and is gated to Medium (one non-pattern
	// factor) — the same level with or without the (suppressed) endpoint
	// factor.
	content := fmt.Sprintf("DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/%s",
		strings.Repeat("a", 60))
	_, out := scanOf(t, Document{Kind: KindEnv, Content: []byte(content)})
	c := findByValue(out, "https://discord.com")
	if c == nil {
		t.Fatalf("discord webhook must be reported: %+v", out.candidates)
	}
	if c.typ != asset.SecretTypeWebhookURL || c.provider != "discord" {
		t.Errorf("type/provider = %s/%s, want webhook_url/discord", c.typ, c.provider)
	}
	if c.confidence.Level != LevelMedium {
		t.Errorf("discord webhook level = %s, want medium (High gated): %+v", c.confidence.Level, c.confidence.Factors)
	}
	if hasFactor(c.confidence, "endpoint") {
		t.Errorf("endpoint factor must be suppressed (the value is the discord.com endpoint): %+v", c.confidence.Factors)
	}
	if hasFactor(c.confidence, "url_type_cap") {
		t.Errorf("webhook URLs must not carry the url_type_cap: %+v", c.confidence.Factors)
	}
}

func TestScanPairBoostedKeyHighBucketStaysLow(t *testing.T) {
	// The pair factor must never let a pure-endpoint URL escape its Low
	// ceiling, while the same evidence legitimately lifts the AWS key to
	// High.
	content := fmt.Sprintf(
		`const c={aws_access_key_id:"%s",aws_secret_access_key:"%s",bucket:"https://my-bucket.s3.us-east-1.amazonaws.com/x"};`,
		awsKeyID, awsSecret)
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte(content)})

	key := findByValue(out, "AKIA")
	if key == nil {
		t.Fatal("AWS key not found")
	}
	if key.confidence.Level != LevelHigh {
		t.Errorf("pair-boosted AWS key must stay High: %s %.2f", key.confidence.Level, key.confidence.Score)
	}

	bucket := findByValue(out, "https://my-bucket")
	if bucket == nil {
		t.Fatal("S3 bucket URL not found")
	}
	if !hasFactor(bucket.confidence, "pair") {
		t.Errorf("bucket must share the same-provider pair link: %+v", bucket.confidence.Factors)
	}
	if bucket.confidence.Level.rank() > LevelLow.rank() || bucket.confidence.Score > urlTypeCap {
		t.Errorf("pair recompute must keep the bucket at Low: %s %.2f", bucket.confidence.Level, bucket.confidence.Score)
	}
}

func TestScanCommentStateIndexCappedDeterministic(t *testing.T) {
	// More string literals than maxTrackedIntervals: the string-state
	// index is capped and comment detection falls back to the legacy line
	// scan — bounded, deterministic, panic-free, and still honest about
	// real line comments.
	var b strings.Builder
	for i := 0; i < maxTrackedIntervals+64; i++ {
		b.WriteString(`"x";`)
	}
	b.WriteString("// " + awsKeyID)
	d := Document{Kind: KindJS, Content: []byte(b.String())}

	sd1, out1 := scanOf(t, d)
	_ = sd1
	c1 := findByValue(out1, "AKIA")
	if c1 == nil {
		t.Fatal("candidate in the legacy-fallback region must be found")
	}
	if !c1.context.InComment {
		t.Error("key in a line comment must be flagged in-comment under the legacy fallback")
	}

	sd2, err := prepareDocument(d, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	out2 := scanDocument(sd2, loadDB(t), defaultScanLimits())
	if len(out1.candidates) != len(out2.candidates) {
		t.Fatalf("candidate count differs across runs: %d vs %d", len(out1.candidates), len(out2.candidates))
	}
	for i := range out1.candidates {
		if out1.candidates[i].id != out2.candidates[i].id ||
			out1.candidates[i].context.InComment != out2.candidates[i].context.InComment {
			t.Errorf("candidate %d diverges across runs: %+v vs %+v",
				i, out1.candidates[i], out2.candidates[i])
		}
	}
}

func TestScanDeduplicatesRepeatedValues(t *testing.T) {
	// The same key repeated in one minified bundle: one candidate.
	content := []byte(fmt.Sprintf(`a="%s";b="%s";c="%s";`, githubToken, githubToken, githubToken))
	_, out := scanOf(t, Document{Kind: KindJS, Content: content})
	if n := len(out.candidates); n != 1 {
		t.Errorf("repeated value must dedupe to one candidate, got %d: %+v", n, out.candidates)
	}
}

func TestScanUnicodeAndMinifiedBundles(t *testing.T) {
	// Unicode content around a key: byte-based matching still finds it.
	content := []byte(fmt.Sprintf("const 提示=\"🚀\", k=\"%s\"; // ✅", awsKeyID))
	_, out := scanOf(t, Document{Kind: KindJS, Content: content})
	if findByValue(out, "AKIA") == nil {
		t.Fatalf("unicode content must not hide matches: %+v", out.counts)
	}

	// A large minified bundle (1 MiB) scans bounded.
	var b strings.Builder
	b.WriteString("/*! bundle v1 */")
	for i := 0; b.Len() < 1<<20; i++ {
		fmt.Fprintf(&b, `function f%d(){var s%d="%s";return s%d};`, i, i, detRand(24, alnumMixed, 7, i%37), i)
	}
	b.WriteString(awsKeyID)
	sd, err := prepareDocument(Document{Kind: KindJS, Content: []byte(b.String())}, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	out = scanDocument(sd, loadDB(t), defaultScanLimits())
	if findByValue(out, "AKIA") == nil {
		t.Fatal("key at the end of a 1 MiB bundle must be found")
	}
}

func TestScanCandidateCapOverflow(t *testing.T) {
	// 100 distinct AWS keys in one document: the candidate cap drops the
	// excess honestly.
	var b strings.Builder
	for i := 0; i < 100; i++ {
		// Distinct by construction: a deterministic pseudo-random tail plus
		// the index in hex (the bare detRand sequence repeats with the
		// charset period).
		fmt.Fprintf(&b, "\"AKIA%s%02X\"\n", detRand(14, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 7, i), i)
	}
	sd, err := prepareDocument(Document{Kind: KindJSON, Content: []byte(b.String())}, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	out := scanDocument(sd, loadDB(t), defaultScanLimits())
	if len(out.candidates) != defaultScanLimits().maxCandidates {
		t.Errorf("candidates = %d, want capped at %d", len(out.candidates), defaultScanLimits().maxCandidates)
	}
	if out.counts.OverflowDropped == 0 {
		t.Errorf("overflow must be counted: %+v", out.counts)
	}
}

func TestScanDocumentationContextCapsConfidence(t *testing.T) {
	_, out := scanOf(t, Document{Kind: KindEnv, Content: []byte("key=" + awsKeyID), Filename: "config/test.env"})
	c := findByValue(out, "AKIA")
	if c == nil {
		t.Fatal("candidate must still be reported from a test file")
	}
	if len(c.fpFlags) == 0 {
		t.Fatal("test filename must set FP context flags")
	}
	if c.confidence.Score > fpContextCap || c.confidence.Level.rank() > LevelLow.rank() {
		t.Errorf("documentation context must cap at Low: %s %.2f", c.confidence.Level, c.confidence.Score)
	}
}

func TestScanEvidenceAndEdges(t *testing.T) {
	u, _ := asset.ParseURL("https://cdn.example.com/app.js", asset.Provenance{})
	_, out := scanOf(t, Document{Kind: KindJS, Content: []byte("k=" + awsKeyID), URL: &u})

	c := findByValue(out, "AKIA")
	if c == nil {
		t.Fatal("candidate missing")
	}
	if len(c.evidenceIDs) == 0 || len(c.evidenceIDs) > defaultScanLimits().maxEvidencePerCand {
		t.Errorf("evidence IDs = %d, want 1..%d", len(c.evidenceIDs), defaultScanLimits().maxEvidencePerCand)
	}
	for _, ev := range out.evidence {
		if ev.Method != asset.MethodSecret {
			t.Errorf("evidence method = %s, want secret", ev.Method)
		}
	}
	// The URL edge uses the Phase 8 kind; candidate→evidence edges exist.
	var haveURLEdge, haveEvidEdge bool
	for _, r := range out.edges {
		if r.Kind == asset.RelationshipURLToSecretCandidate && r.From == u.Identity() {
			haveURLEdge = true
		}
		if r.Kind == asset.RelationshipSecretCandidateToEvidence {
			haveEvidEdge = true
		}
	}
	if !haveURLEdge {
		t.Error("url_to_secret_candidate edge missing")
	}
	if !haveEvidEdge {
		t.Error("secret_candidate_to_evidence edge missing")
	}
	// The canonical asset is materialized with the bounded value.
	if c.cand.Value != c.value || c.cand.ID() != c.id || c.cand.Prov.Confidence != c.confidence.Score {
		t.Errorf("canonical asset inconsistent: %+v", c.cand)
	}
}

func TestScanEmptyDocument(t *testing.T) {
	_, out := scanOf(t, Document{Kind: KindJSON, Content: nil})
	if len(out.candidates) != 0 {
		t.Errorf("empty document must produce no candidates, got %+v", out.candidates)
	}
}

func TestScanDeterministic(t *testing.T) {
	d := Document{Kind: KindJS, Content: []byte(fmt.Sprintf("a=%s;b=%s", awsKeyID, githubToken))}
	sd1, out1 := scanOf(t, d)
	sd2, err := prepareDocument(d, fixedTime(0))
	if err != nil {
		t.Fatal(err)
	}
	out2 := scanDocument(sd2, loadDB(t), defaultScanLimits())
	if sd1.identity != sd2.identity {
		t.Error("identity must be deterministic")
	}
	if len(out1.candidates) != len(out2.candidates) {
		t.Fatalf("candidate count differs: %d vs %d", len(out1.candidates), len(out2.candidates))
	}
	for i := range out1.candidates {
		if out1.candidates[i].id != out2.candidates[i].id ||
			out1.candidates[i].confidence.Score != out2.candidates[i].confidence.Score {
			t.Errorf("candidate %d diverges between identical scans", i)
		}
	}
}
