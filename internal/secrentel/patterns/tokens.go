package patterns

import "github.com/RA000WL/RavenRecon/internal/asset"

// tokenTable holds the generic token families: JWTs, bearer headers, OAuth
// assignments, generic API-key assignments, and the deliberately weak generic
// secret assignment (a random base64 blob under a generic name — capped at
// Low by the family contract, never more than a weak signal on its own).
func tokenTable() []Pattern {
	return []Pattern{
		{
			ID:        "jwt",
			Type:      asset.SecretTypeJWT,
			Provider:  "",
			Family:    FamilyStructured,
			Regex:     `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`,
			Strength:  0.85,
			MinLen:    30,
			MaxLen:    512,
			Validator: ValidatorJWTStructure,
			Hints:     []string{"jwt", "token", "id_token"},
			Positives: []string{"bearer", "authorization"},
		},
		{
			ID:        "bearer-token",
			Type:      asset.SecretTypeBearer,
			Provider:  "",
			Family:    FamilyContextual,
			Regex:     `(?i)bearer\s+[A-Za-z0-9\-._~+/=]{20,512}`,
			Anchors:   []string{"bearer"},
			Strength:  0.6,
			MinLen:    27,
			MaxLen:    512,
			Hints:     []string{"authorization", "bearer"},
			Positives: []string{"authorization", "token"},
		},
		{
			ID:       "oauth-token-assignment",
			Type:     asset.SecretTypeOAuth,
			Provider: "",
			Family:   FamilyContextual,
			Regex:    `(?i)(?:access|refresh)_?token\s*["']?\s*[:=]\s*["']?([A-Za-z0-9_.\-/+=]{16,512})["']?`,
			Anchors: []string{
				"access_token", "accesstoken", "access-token",
				"refresh_token", "refreshtoken", "refresh-token",
			},
			Group:     1,
			Strength:  0.5,
			MinLen:    16,
			MaxLen:    512,
			Entropy:   EntropyRule{MinShannon: 3.0},
			Hints:     []string{"access_token", "refresh_token", "oauth_token"},
			Positives: []string{"oauth"},
		},
		{
			ID:       "api-key-assignment",
			Type:     asset.SecretTypeAPIKey,
			Provider: "",
			Family:   FamilyContextual,
			Regex:    `(?i)(?:x[_-]?)?api[_-]?keys?\s*["']?\s*[:=]\s*["']?([A-Za-z0-9_.\-]{16,64})["']?`,
			Anchors:  []string{"api_key", "apikey", "api-key"},
			Group:    1,
			Strength: 0.5,
			MinLen:   16,
			MaxLen:   64,
			Entropy:  EntropyRule{MinShannon: 3.0},
			Hints:    []string{"api_key", "apikey", "x_api_key"},
		},
		{
			// The deliberately weak generic family: a base64-shaped value
			// under a generic secret/password/passwd/token name. High entropy
			// is REQUIRED (the entropy rule drops prose and placeholders), and
			// the FamilyGeneric cap keeps the score at Low by contract. Bare
			// "key" and "pwd" names are deliberately excluded: three-letter
			// names are noise-prone in object literals, and every compound
			// name carrying them (secretkey, pwd_hash) matches the longer
			// alternation anyway.
			ID:       "generic-secret-assignment",
			Type:     asset.SecretTypeGeneric,
			Provider: "",
			Family:   FamilyGeneric,
			Regex:    `(?i)(?:secret|password|passwd|token)s?\s*["']?\s*[:=]\s*["']([A-Za-z0-9+/=]{20,64})["']`,
			Anchors:  []string{"secret", "password", "passwd", "token"},
			Group:    1,
			Strength: 0.35,
			MinLen:   20,
			MaxLen:   64,
			Entropy:  EntropyRule{MinShannon: 3.5, MinNormalized: 0.6, Class: ClassBase64},
			Hints:    []string{"secret", "password", "token"},
		},
	}
}
