package patterns

import "github.com/RA000WL/RavenRecon/internal/asset"

// dataWebTable holds data-store and webhook shapes: credential-bearing
// connection strings (the userinfo user:pass@host is REQUIRED — a
// credential-less URL is not a secret), the DATABASE_URL assignment family,
// SMTP URLs, and webhook endpoints.
func dataWebTable() []Pattern {
	return []Pattern{
		{
			ID:        "postgres-url",
			Type:      asset.SecretTypePostgreSQLURL,
			Provider:  "postgres",
			Family:    FamilyStructured,
			Regex:     `postgres(?:ql)?://[^@\s"']{1,64}:[^@\s"']{3,128}@[A-Za-z0-9._:-]{1,253}(?::[0-9]{1,5})?(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.85,
			MinLen:    15,
			MaxLen:    512,
			Hints:     []string{"database_url", "postgres_url", "pg_url"},
			Positives: []string{"postgres", "pg", "database"},
		},
		{
			ID:        "mysql-url",
			Type:      asset.SecretTypeMySQLURL,
			Provider:  "mysql",
			Family:    FamilyStructured,
			Regex:     `mysql://[^@\s"']{1,64}:[^@\s"']{3,128}@[A-Za-z0-9._:-]{1,253}(?::[0-9]{1,5})?(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.8,
			MinLen:    12,
			MaxLen:    512,
			Hints:     []string{"database_url", "mysql_url"},
			Positives: []string{"mysql", "database"},
		},
		{
			ID:        "mongodb-url",
			Type:      asset.SecretTypeMongoDBURL,
			Provider:  "mongodb",
			Family:    FamilyStructured,
			Regex:     `mongodb(?:\+srv)?://[^@\s"']{1,64}:[^@\s"']{3,128}@[A-Za-z0-9._:-]{1,253}(?::[0-9]{1,5})?(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.85,
			MinLen:    17,
			MaxLen:    512,
			Hints:     []string{"mongodb_uri", "mongo_url", "database_url"},
			Positives: []string{"mongo", "database"},
		},
		{
			ID:        "redis-url",
			Type:      asset.SecretTypeRedisURL,
			Provider:  "redis",
			Family:    FamilyStructured,
			Regex:     `rediss?://[^@\s"']{0,64}:[^@\s"']{3,128}@[A-Za-z0-9._:-]{1,253}(?::[0-9]{1,5})?(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.8,
			MinLen:    13,
			MaxLen:    512,
			Hints:     []string{"redis_url", "cache_url"},
			Positives: []string{"redis", "cache"},
		},
		{
			ID:        "database-url-assignment",
			Type:      asset.SecretTypeDatabaseURL,
			Provider:  "",
			Family:    FamilyContextual,
			Regex:     `(?i)(?:database|db)_?url\s*["']?\s*[:=]\s*["']?([a-z][a-z0-9+.-]*://[^\s"']{8,512})["']?`,
			Anchors:   []string{"database", "db_url", "dburl"},
			Group:     1,
			Strength:  0.7,
			MinLen:    12,
			MaxLen:    512,
			Hints:     []string{"database_url", "db_url"},
			Positives: []string{"database"},
		},
		{
			ID:        "smtp-url",
			Type:      asset.SecretTypeSMTP,
			Provider:  "smtp",
			Family:    FamilyStructured,
			Regex:     `smtps?://[^@\s"']{0,64}:[^@\s"']{3,128}@[A-Za-z0-9._:-]{1,253}(?::[0-9]{1,5})?(?:/[^\s"'<>]{0,256})?`,
			Strength:  0.8,
			MinLen:    13,
			MaxLen:    512,
			Hints:     []string{"smtp_url", "mail_url"},
			Positives: []string{"smtp", "mail"},
		},
		{
			ID:        "slack-webhook",
			Type:      asset.SecretTypeWebhookURL,
			Provider:  "slack",
			Family:    FamilyStructured,
			Regex:     `https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{18,}`,
			Strength:  0.9,
			MinLen:    40,
			MaxLen:    200,
			Hints:     []string{"slack_webhook", "webhook_url"},
			Positives: []string{"slack"},
		},
		{
			ID:       "generic-webhook",
			Type:     asset.SecretTypeWebhookURL,
			Provider: "",
			Family:   FamilyStructured,
			Regex:    `https?://[a-z0-9.-]{1,253}/[A-Za-z0-9_./-]{0,128}/webhooks?/[A-Za-z0-9_\-./]{16,200}`,
			Strength: 0.6,
			MinLen:   30,
			MaxLen:   400,
			Hints:    []string{"webhook_url", "callback_url"},
		},
	}
}

// correlationTable is the provider correlation data consumed by the engine's
// multi-evidence correlation stage: endpoint substrings observed in the same
// document and technology-name substrings reported by callers raise the
// confidence of same-provider candidates.
func correlationTable() []ProviderCorrelation {
	return []ProviderCorrelation{
		{
			Provider:  "aws",
			Endpoints: []string{"amazonaws.com", "s3.amazonaws.com"},
			Tech:      []string{"aws", "amplify"},
		},
		{
			Provider:  "azure",
			Endpoints: []string{"blob.core.windows.net", "azure.com"},
			Tech:      []string{"azure"},
		},
		{
			Provider:  "cloudflare",
			Endpoints: []string{"cloudflare.com", "cloudflareinsights.com"},
			Tech:      []string{"cloudflare"},
		},
		{
			Provider:  "digitalocean",
			Endpoints: []string{"digitaloceanspaces.com", "digitalocean.com"},
			Tech:      []string{"digitalocean"},
		},
		{
			Provider:  "discord",
			Endpoints: []string{"discord.com", "discordapp.com"},
			Tech:      []string{"discord"},
		},
		{
			Provider:  "firebase",
			Endpoints: []string{"firebaseio.com", "firebaseapp.com"},
			Tech:      []string{"firebase"},
		},
		{
			Provider:  "github",
			Endpoints: []string{"api.github.com", "github.com"},
			Tech:      []string{"github"},
		},
		{
			Provider:  "gitlab",
			Endpoints: []string{"gitlab.com", "gitlab"},
			Tech:      []string{"gitlab"},
		},
		{
			Provider:  "google",
			Endpoints: []string{"googleapis.com"},
			Tech:      []string{"google", "gcp"},
		},
		{
			Provider:  "mongodb",
			Endpoints: []string{"mongodb.net", "mongodb.com"},
			Tech:      []string{"mongo"},
		},
		{
			Provider:  "mysql",
			Endpoints: []string{"mysql"},
			Tech:      []string{"mysql"},
		},
		{
			Provider:  "netlify",
			Endpoints: []string{"netlify.com", "netlify.app"},
			Tech:      []string{"netlify"},
		},
		{
			Provider:  "openai",
			Endpoints: []string{"openai.com"},
			Tech:      []string{"openai"},
		},
		{
			Provider:  "anthropic",
			Endpoints: []string{"anthropic.com"},
			Tech:      []string{"anthropic"},
		},
		{
			Provider:  "postgres",
			Endpoints: []string{"postgres", "rds.amazonaws.com"},
			Tech:      []string{"postgres"},
		},
		{
			Provider:  "railway",
			Endpoints: []string{"railway.app", "up.railway.app"},
			Tech:      []string{"railway"},
		},
		{
			Provider:  "redis",
			Endpoints: []string{"redis", "rediss"},
			Tech:      []string{"redis"},
		},
		{
			Provider:  "slack",
			Endpoints: []string{"slack.com", "hooks.slack.com"},
			Tech:      []string{"slack"},
		},
		{
			Provider:  "smtp",
			Endpoints: []string{":587", ":465", ":25"},
			Tech:      []string{"smtp"},
		},
		{
			Provider:  "stripe",
			Endpoints: []string{"api.stripe.com", "js.stripe.com"},
			Tech:      []string{"stripe"},
		},
		{
			Provider:  "twilio",
			Endpoints: []string{"twilio.com"},
			Tech:      []string{"twilio"},
		},
		{
			Provider:  "vercel",
			Endpoints: []string{"vercel.com", "vercel.app"},
			Tech:      []string{"vercel", "next.js"},
		},
	}
}
