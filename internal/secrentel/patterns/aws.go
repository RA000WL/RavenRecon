package patterns

import "github.com/RA000WL/RavenRecon/internal/asset"

// awsTable holds AWS secret shapes: the structured access key ID, the
// context-shaped secret access key and session token, and the S3 bucket URL
// (an observation-grade shape used mainly for provider correlation).
func awsTable() []Pattern {
	return []Pattern{
		{
			ID:        "aws-access-key-id",
			Type:      asset.SecretTypeAWS,
			Provider:  "aws",
			Family:    FamilyStructured,
			Regex:     `(?:AKIA|ASIA)[0-9A-Z]{16}`,
			Strength:  0.9,
			MinLen:    20,
			MaxLen:    20,
			Validator: ValidatorMixedAlnum,
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"aws_access_key_id", "access_key_id", "accesskeyid", "aws_key"},
			Positives: []string{"aws", "amazon"},
		},
		{
			ID:       "aws-secret-access-key",
			Type:     asset.SecretTypeAWS,
			Provider: "aws",
			Family:   FamilyContextual,
			// The variable name is part of the match; the value is group 1
			// (exactly 40 base64 characters).
			Regex:     `(?i)aws_?secret_?access_?key\s*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`,
			Anchors:   []string{"secret"},
			Group:     1,
			Strength:  0.75,
			MinLen:    40,
			MaxLen:    40,
			Entropy:   EntropyRule{MinShannon: 3.2, MinNormalized: 0.55, Class: ClassBase64},
			Hints:     []string{"aws_secret_access_key", "secret_access_key"},
			Positives: []string{"aws", "amazon"},
		},
		{
			ID:        "aws-session-token",
			Type:      asset.SecretTypeAWS,
			Provider:  "aws",
			Family:    FamilyContextual,
			Regex:     `(?i)aws_?session_?token\s*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{80,800})["']?`,
			Anchors:   []string{"session"},
			Group:     1,
			Strength:  0.7,
			MinLen:    80,
			MaxLen:    800,
			Entropy:   EntropyRule{MinShannon: 3.4, MinNormalized: 0.6, Class: ClassBase64},
			Hints:     []string{"aws_session_token", "session_token"},
			Positives: []string{"aws", "amazon"},
		},
		{
			ID:       "s3-bucket-url",
			Type:     asset.SecretTypeS3,
			Provider: "aws",
			Family:   FamilyStructured,
			Regex: `https?://(?:[a-z0-9][a-z0-9.-]{0,62}\.s3[.-][a-z0-9-]{1,32}\.amazonaws\.com` +
				`|s3[.-][a-z0-9-]{1,32}\.amazonaws\.com/[a-z0-9._-]{1,63})` +
				`(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.35,
			MinLen:    16,
			MaxLen:    512,
			Hints:     []string{"s3", "bucket"},
			Positives: []string{"aws", "amazon"},
		},
	}
}
