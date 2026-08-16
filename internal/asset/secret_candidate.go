package asset

import (
	"fmt"
	"unicode/utf8"
)

// SecretType classifies a detected secret candidate into one of the known
// categories. String values are the canonical lowercase forms ("jwt", "aws",
// ...); the value IS the canonical form and is embedded in the asset identity,
// so types are never normalized at use time — unknown values are rejected at
// construction.
//
// Phase 7 models secret CANDIDATES for detection only: no verification, no
// severity, and no exploitation is represented anywhere in the model.
type SecretType string

const (
	// SecretTypeJWT: JSON Web Tokens.
	SecretTypeJWT SecretType = "jwt"
	// SecretTypeAWS: AWS access key candidates.
	SecretTypeAWS SecretType = "aws"
	// SecretTypeGoogle: Google API key candidates.
	SecretTypeGoogle SecretType = "google"
	// SecretTypeFirebase: Firebase configuration key candidates.
	SecretTypeFirebase SecretType = "firebase"
	// SecretTypeStripe: Stripe API key candidates.
	SecretTypeStripe SecretType = "stripe"
	// SecretTypeGitHub: GitHub token candidates.
	SecretTypeGitHub SecretType = "github"
	// SecretTypeBearer: generic bearer-token candidates.
	SecretTypeBearer SecretType = "bearer"
	// SecretTypePrivateKey: private key block candidates.
	SecretTypePrivateKey SecretType = "private_key"
	// SecretTypeGeneric: candidates that matched no specific pattern.
	SecretTypeGeneric SecretType = "generic"

	// Phase 8 (secret intelligence) extensions. The values are the canonical
	// lowercase provider/type forms; the Phase 7 values above are frozen and
	// never renamed, so Phase 7 identities stay stable.

	// SecretTypeAzure: Microsoft Azure key and connection candidates.
	SecretTypeAzure SecretType = "azure"
	// SecretTypeGitLab: GitLab token candidates.
	SecretTypeGitLab SecretType = "gitlab"
	// SecretTypeTwilio: Twilio key and token candidates.
	SecretTypeTwilio SecretType = "twilio"
	// SecretTypeSlack: Slack token candidates.
	SecretTypeSlack SecretType = "slack"
	// SecretTypeDiscord: Discord token and webhook candidates.
	SecretTypeDiscord SecretType = "discord"
	// SecretTypeOpenAI: OpenAI API key candidates.
	SecretTypeOpenAI SecretType = "openai"
	// SecretTypeAnthropic: Anthropic API key candidates.
	SecretTypeAnthropic SecretType = "anthropic"
	// SecretTypeRSAPrivateKey: RSA private key block candidates (BEGIN RSA
	// PRIVATE KEY).
	SecretTypeRSAPrivateKey SecretType = "rsa_private_key"
	// SecretTypeSSHPrivateKey: OpenSSH private key block candidates (BEGIN
	// OPENSSH PRIVATE KEY).
	SecretTypeSSHPrivateKey SecretType = "ssh_private_key"
	// SecretTypePublicKey: public key candidates (PEM PUBLIC KEY blocks and
	// ssh-rsa/ssh-ed25519 authorization key forms).
	SecretTypePublicKey SecretType = "public_key"
	// SecretTypeOAuth: OAuth refresh/access token candidates with known
	// provider prefixes.
	SecretTypeOAuth SecretType = "oauth"
	// SecretTypeAPIKey: structured generic API key candidates (fixed charset
	// and length with a provider-shaped context).
	SecretTypeAPIKey SecretType = "api_key"
	// SecretTypeDatabaseURL: connection-string candidates for SQL databases.
	SecretTypeDatabaseURL SecretType = "database_url"
	// SecretTypeRedisURL: redis:// connection-string candidates.
	SecretTypeRedisURL SecretType = "redis_url"
	// SecretTypeMongoDBURL: mongodb:// connection-string candidates.
	SecretTypeMongoDBURL SecretType = "mongodb_url"
	// SecretTypePostgreSQLURL: postgres:// connection-string candidates.
	SecretTypePostgreSQLURL SecretType = "postgres_url"
	// SecretTypeMySQLURL: mysql:// connection-string candidates.
	SecretTypeMySQLURL SecretType = "mysql_url"
	// SecretTypeWebhookURL: webhook endpoint candidates (Slack, Discord, and
	// generic webhook services).
	SecretTypeWebhookURL SecretType = "webhook_url"
	// SecretTypeSMTP: SMTP credential candidates (smtp:// URLs with embedded
	// userinfo).
	SecretTypeSMTP SecretType = "smtp"
	// SecretTypeS3: S3 bucket URL candidates.
	SecretTypeS3 SecretType = "s3"
	// SecretTypeCloudflare: Cloudflare token candidates.
	SecretTypeCloudflare SecretType = "cloudflare"
	// SecretTypeDigitalOcean: DigitalOcean token candidates.
	SecretTypeDigitalOcean SecretType = "digitalocean"
	// SecretTypeVercel: Vercel token candidates.
	SecretTypeVercel SecretType = "vercel"
	// SecretTypeNetlify: Netlify token candidates.
	SecretTypeNetlify SecretType = "netlify"
	// SecretTypeRailway: Railway token candidates.
	SecretTypeRailway SecretType = "railway"
	// SecretTypeCustomToken: caller-defined/custom-deployment token shapes
	// (site-specific prefixes discovered through configuration, not matched by
	// the built-in database).
	SecretTypeCustomToken SecretType = "custom_token"
)

// String returns the canonical lowercase type value.
func (t SecretType) String() string { return string(t) }

// Valid reports whether t is one of the 35 known secret types.
func (t SecretType) Valid() bool {
	switch t {
	case SecretTypeJWT, SecretTypeAWS, SecretTypeGoogle, SecretTypeFirebase,
		SecretTypeStripe, SecretTypeGitHub, SecretTypeBearer,
		SecretTypePrivateKey, SecretTypeGeneric,
		SecretTypeAzure, SecretTypeGitLab, SecretTypeTwilio, SecretTypeSlack,
		SecretTypeDiscord, SecretTypeOpenAI, SecretTypeAnthropic,
		SecretTypeRSAPrivateKey, SecretTypeSSHPrivateKey, SecretTypePublicKey,
		SecretTypeOAuth, SecretTypeAPIKey, SecretTypeDatabaseURL,
		SecretTypeRedisURL, SecretTypeMongoDBURL, SecretTypePostgreSQLURL,
		SecretTypeMySQLURL, SecretTypeWebhookURL, SecretTypeSMTP, SecretTypeS3,
		SecretTypeCloudflare, SecretTypeDigitalOcean, SecretTypeVercel,
		SecretTypeNetlify, SecretTypeRailway, SecretTypeCustomToken:
		return true
	}
	return false
}

// ParseSecretType validates s and returns the canonical type. An unknown
// value is an error: types are never silently coerced.
func ParseSecretType(s string) (SecretType, error) {
	t := SecretType(s)
	if !t.Valid() {
		return "", fmt.Errorf("unknown secret type %q", s)
	}
	return t, nil
}

// KnownSecretTypes returns every secret type in canonical sorted order. The
// returned slice is a fresh copy; callers may mutate it freely.
func KnownSecretTypes() []SecretType {
	return []SecretType{
		SecretTypeAnthropic, SecretTypeAPIKey, SecretTypeAWS, SecretTypeAzure,
		SecretTypeBearer, SecretTypeCloudflare, SecretTypeCustomToken,
		SecretTypeDatabaseURL, SecretTypeDigitalOcean, SecretTypeDiscord,
		SecretTypeFirebase, SecretTypeGeneric, SecretTypeGitHub,
		SecretTypeGitLab, SecretTypeGoogle, SecretTypeJWT, SecretTypeMongoDBURL,
		SecretTypeMySQLURL, SecretTypeNetlify, SecretTypeOAuth, SecretTypeOpenAI,
		SecretTypePostgreSQLURL, SecretTypePrivateKey, SecretTypePublicKey,
		SecretTypeRailway, SecretTypeRedisURL, SecretTypeRSAPrivateKey,
		SecretTypeS3, SecretTypeSlack, SecretTypeSMTP, SecretTypeSSHPrivateKey,
		SecretTypeStripe, SecretTypeTwilio, SecretTypeVercel,
		SecretTypeWebhookURL,
	}
}

// Bounds applied by NewSecretCandidate.
const (
	// maxSecretCandidateValueBytes bounds the STORED candidate value. Raw
	// values longer than this are truncated at ingestion (see
	// NewSecretCandidate); the identity always covers exactly the stored
	// bytes.
	maxSecretCandidateValueBytes = 512
	// secretCandidateTruncationMarker marks a value that was truncated at
	// ingestion. It is U+2026 ("…", 3 bytes in UTF-8), chosen because it is
	// visually unambiguous and cannot be confused with an emitted byte.
	secretCandidateTruncationMarker = "…"
)

// SecretCandidate is one detected secret candidate observed in a source
// asset. Phase 7 models detection only: the candidate is never verified
// against a live service and carries no severity.
//
// The identity is "type/value/source" where value is the STORED (already
// truncated) value and source is the percent-encoded identity of the source
// asset the candidate was observed in. Because truncation happens before
// identity derivation, two observations whose raw values differ only after
// the 512-byte bound are the SAME secret candidate asset — the identity
// covers exactly what is stored, and re-ingesting the stored value reproduces
// the same identity. The source asset participates in the identity: the same
// value observed in two different assets is two distinct candidates, never
// one merged record that silently drops one asset's attribution.
type SecretCandidate struct {
	// Type classifies the candidate (see SecretType).
	Type SecretType `json:"type"`

	// Value is the detected candidate string, truncated to at most
	// maxSecretCandidateValueBytes bytes with the
	// secretCandidateTruncationMarker suffix when the raw observation was
	// longer.
	Value string `json:"value"`

	// Source is the identity of the asset the candidate was observed in,
	// e.g. a JavaScript asset identity.
	Source Identity `json:"source"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewSecretCandidate builds a validated SecretCandidate.
//
// The observed value is NEVER rejected for length: if it exceeds
// maxSecretCandidateValueBytes it is truncated to a rune-safe prefix of at
// most 509 bytes plus the secretCandidateTruncationMarker ("…"), for a stored
// size of at most 512 bytes. A value that is empty after truncation is an
// error (a candidate must carry at least one stored byte). The identity is
// derived from the STORED value (see SecretCandidate.Identity).
func NewSecretCandidate(t SecretType, value string, source Identity, p Provenance) (SecretCandidate, error) {
	if !t.Valid() {
		return SecretCandidate{}, fmt.Errorf("invalid secret type %q", t)
	}
	if source.IsZero() {
		return SecretCandidate{}, fmt.Errorf("secret candidate source identity must not be zero")
	}
	stored := truncateSecretCandidateValue(value)
	if stored == "" {
		return SecretCandidate{}, fmt.Errorf("secret candidate value must not be empty")
	}
	return SecretCandidate{Type: t, Value: stored, Source: source, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity value is "type/value/source", each component percent-encoded
// (service.go's percentEncode), so separators inside a value or source
// identity can never blur the boundaries. The encoded value is the STORED
// value — the one truncateSecretCandidateValue produced — so the identity
// covers exactly what is stored, never the original raw observation. The
// source component is the canonical identity string of the source asset
// (e.g. "javascript:https://cdn.example.com/app.js"), encoded like any other
// component: the same value observed in two different source assets is two
// distinct candidates.
func (s SecretCandidate) Identity() Identity {
	return Identity{
		Kind: KindSecretCandidate,
		Value: s.Type.String() + "/" + percentEncode(s.Value) + "/" +
			percentEncode(s.Source.String()),
	}
}

// ID returns the canonical identity string.
func (s SecretCandidate) ID() string { return s.Identity().String() }

// String returns the canonical identity value, e.g.
// "jwt/eyJhbGciOiJIUzI1NiJ9/host%3Awww%2Eexample%2Ecom".
func (s SecretCandidate) String() string { return s.Identity().Value }

// truncateSecretCandidateValue bounds a raw observed value to
// maxSecretCandidateValueBytes bytes, replicating the evidence truncation
// mechanics with this type's own constants. Values within the bound are
// returned unchanged. Longer values are truncated to a rune-safe prefix of at
// most 509 bytes plus the "…" marker (3 bytes) for a total of at most 512
// bytes. The result carries no information about whether truncation happened
// beyond the marker itself; callers that need the flag should compare lengths
// before calling.
func truncateSecretCandidateValue(raw string) string {
	if len(raw) <= maxSecretCandidateValueBytes {
		return raw
	}
	prefix := raw[:maxSecretCandidateValueBytes-len(secretCandidateTruncationMarker)]
	// Trim an incomplete trailing UTF-8 sequence so the marker never follows
	// a torn rune. For valid UTF-8 this loop does not run.
	for len(prefix) > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix)
		if r != utf8.RuneError || size > 1 {
			break
		}
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + secretCandidateTruncationMarker
}

// MergeSecretCandidates combines two observations of the same secret
// candidate.
//
// All identifying fields (type, value, source) are part of the identity, so
// the only mergeable state is provenance: the earliest observation wins,
// mirroring MergeEvidence and the other Merge primitives.
func MergeSecretCandidates(a, b SecretCandidate) (SecretCandidate, error) {
	if !a.Identity().Equal(b.Identity()) {
		return SecretCandidate{}, mergeMismatch(KindSecretCandidate, a.Identity(), b.Identity())
	}
	m := a
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}
