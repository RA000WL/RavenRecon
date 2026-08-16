package patterns

import "github.com/RA000WL/RavenRecon/internal/asset"

// saasTable holds SaaS provider token shapes: source hosting (GitHub,
// GitLab), payments (Stripe — live keys only; test keys are deliberately not
// matched), messaging (Twilio, Slack, Discord), and AI providers (OpenAI,
// Anthropic).
func saasTable() []Pattern {
	return []Pattern{
		{
			ID:        "github-token",
			Type:      asset.SecretTypeGitHub,
			Provider:  "github",
			Family:    FamilyStructured,
			Regex:     `(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,82}`,
			Strength:  0.9,
			MinLen:    40,
			MaxLen:    93,
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"github_token", "gh_token", "github_pat"},
			Positives: []string{"github"},
		},
		{
			ID:        "gitlab-pat",
			Type:      asset.SecretTypeGitLab,
			Provider:  "gitlab",
			Family:    FamilyStructured,
			Regex:     `glpat-[0-9A-Za-z_-]{20,64}`,
			Strength:  0.9,
			MinLen:    26,
			MaxLen:    70,
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"gitlab_token", "gitlab_pat"},
			Positives: []string{"gitlab"},
		},
		{
			// Live secret and restricted keys only: sk_test_/rk_test_ are
			// publishable test credentials, not production secrets, and are
			// deliberately not matched (documented false-positive reduction).
			ID:       "stripe-live-key",
			Type:     asset.SecretTypeStripe,
			Provider: "stripe",
			Family:   FamilyStructured,
			Regex:    `(?:sk|rk)_live_[0-9A-Za-z]{16,64}`,
			// The alternation prefix defeats RE2's literal-prefix fast path;
			// the required "_live_" substring gates it cheaply.
			Anchors:   []string{"_live_"},
			Strength:  0.9,
			MinLen:    25,
			MaxLen:    73,
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"stripe_secret_key", "stripe_key"},
			Positives: []string{"stripe"},
		},
		{
			ID:        "twilio-api-key",
			Type:      asset.SecretTypeTwilio,
			Provider:  "twilio",
			Family:    FamilyStructured,
			Regex:     `SK[0-9a-f]{32}`,
			Strength:  0.7,
			MinLen:    34,
			MaxLen:    34,
			Validator: ValidatorHex,
			Entropy:   EntropyRule{MinShannon: 3.5, MinNormalized: 0.85, Class: ClassHex},
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"twilio_api_key"},
			Positives: []string{"twilio"},
		},
		{
			ID:        "twilio-auth-token",
			Type:      asset.SecretTypeTwilio,
			Provider:  "twilio",
			Family:    FamilyContextual,
			Regex:     `(?i)twilio[^;\n]{0,24}(?:auth )?token\s*["']?\s*[:=]\s*["']?([0-9a-f]{32})["']?`,
			Anchors:   []string{"twilio"},
			Group:     1,
			Strength:  0.75,
			MinLen:    32,
			MaxLen:    32,
			Validator: ValidatorHex,
			Entropy:   EntropyRule{MinShannon: 3.2, MinNormalized: 0.8, Class: ClassHex},
			Hints:     []string{"twilio_auth_token"},
			Positives: []string{"twilio"},
		},
		{
			ID:        "slack-token",
			Type:      asset.SecretTypeSlack,
			Provider:  "slack",
			Family:    FamilyStructured,
			Regex:     `xox[abprs]-[0-9A-Za-z-]{16,250}`,
			Strength:  0.9,
			MinLen:    21,
			MaxLen:    255,
			Negatives: []string{"EXAMPLE", "xxxx"},
			Hints:     []string{"slack_token", "slack_bot_token", "slack_webhook"},
			Positives: []string{"slack"},
		},
		{
			ID:        "discord-webhook",
			Type:      asset.SecretTypeWebhookURL,
			Provider:  "discord",
			Family:    FamilyStructured,
			Regex:     `https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{5,25}/[A-Za-z0-9_-]{40,120}`,
			Strength:  0.85,
			MinLen:    40,
			MaxLen:    200,
			Hints:     []string{"discord_webhook", "webhook_url"},
			Positives: []string{"discord"},
		},
		{
			// Discord bot token shape: base64 user id '.' short signature '.'
			// secret tail.
			ID:       "discord-bot-token",
			Type:     asset.SecretTypeDiscord,
			Provider: "discord",
			Family:   FamilyStructured,
			Regex:    `[MNO][A-Za-z0-9_-]{22,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}`,
			// The leading character class defeats RE2's literal-prefix fast
			// path; the gate requires provider-adjacent context in the
			// document (a bare shape with no discord/bot-token context
			// anywhere is, by the false-positive mission, not worth the
			// scan).
			Anchors: []string{
				"discord",
				"bot_token",
				"bottoken",
			},
			Strength:  0.75,
			MinLen:    50,
			MaxLen:    100,
			Hints:     []string{"discord_token", "bot_token"},
			Positives: []string{"discord"},
		},
		{
			ID:        "openai-api-key",
			Type:      asset.SecretTypeOpenAI,
			Provider:  "openai",
			Family:    FamilyStructured,
			Regex:     `sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,128}`,
			Strength:  0.85,
			MinLen:    23,
			MaxLen:    140,
			Negatives: []string{"EXAMPLE", "YOUR_API_KEY", "xxxx"},
			Hints:     []string{"openai_api_key", "openai_key"},
			Positives: []string{"openai"},
		},
		{
			ID:        "anthropic-api-key",
			Type:      asset.SecretTypeAnthropic,
			Provider:  "anthropic",
			Family:    FamilyStructured,
			Regex:     `sk-ant-(?:api|admin)[0-9]{0,3}-[0-9A-Za-z_-]{24,128}`,
			Strength:  0.9,
			MinLen:    31,
			MaxLen:    145,
			Negatives: []string{"EXAMPLE"},
			Hints:     []string{"anthropic_api_key", "anthropic_key"},
			Positives: []string{"anthropic"},
		},
	}
}
