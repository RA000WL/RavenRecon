package priority

// riskTable is the production risk indicator catalog: signals that raise a
// surface's priority because they indicate higher-value or more sensitive
// attack surface. Like the interestingness table, entries reference ONLY
// data the earlier phases emit.
//
// Documented omissions (no emitting phase produces the data):
//
//   - security-header ABSENCE (e.g. "no CSP"): httpprobe captures the
//     headers that ARE present; reasoning about absent defensive headers
//     would be a vulnerability judgment, which this engine explicitly does
//     not make. Only positive disclosure observations (technology-revealing
//     headers) are cataloged.
func riskTable() []Indicator {
	return []Indicator{
		// --- high-value secret types ------------------------------------
		{
			ID:       "high-value-secret-type",
			Category: "high_value_secret",
			Weight:   0.6,
			Field:    FieldSecretType,
			// The canonical 35-type vocabulary minus definitionally
			// low-value shapes: public_key (not a secret), generic and
			// bearer (unattributed shapes — the secrentel engine already
			// caps their confidence), api_key (medium-value shape), and
			// custom_token (user-defined shape whose value the secrentel
			// engine cannot attribute).
			// "private_key" substring-matches rsa_private_key and
			// ssh_private_key.
			Terms: []string{
				"aws", "azure", "google", "firebase", "github", "gitlab",
				"stripe", "twilio", "slack", "discord", "openai", "anthropic",
				"jwt", "private_key", "oauth", "database_url", "redis_url",
				"mongodb_url", "postgres_url", "mysql_url", "webhook_url",
				"smtp", "s3", "cloudflare", "digitalocean", "vercel",
				"netlify", "railway",
			},
			Reason:         "high-value secret candidate type %s observed",
			Recommendation: "A high-value secret candidate type %s was observed; route the candidate to the offline verification queue and assess the disclosure path — never test it online from recon.",
		},
		// --- privileged / authentication technologies --------------------
		{
			ID:             "privileged-auth-tech-name",
			Category:       "privileged_auth_tech",
			Weight:         0.4,
			Field:          FieldTechName,
			Terms:          []string{"auth0", "okta", "keycloak", "cognito", "identityserver", "shibboleth", "forgerock", "authy"},
			Reason:         "identity-provider technology %s observed",
			Recommendation: "Identity-provider technology %s governs access to this surface; map its configuration endpoints and tenant exposure.",
		},
		{
			ID:             "privileged-auth-tech-category",
			Category:       "privileged_auth_tech",
			Weight:         0.35,
			Field:          FieldTechCategory,
			Terms:          []string{"authentication"},
			Reason:         "authentication technology category observed (%s)",
			Recommendation: "An authentication technology category (%s) is in play; review session and token handling on this surface.",
		},
		// --- cloud infrastructure ----------------------------------------
		{
			ID:             "cloud-tech-category",
			Category:       "cloud_infrastructure",
			Weight:         0.4,
			Field:          FieldTechCategory,
			Terms:          []string{"cloud_provider", "storage"},
			Reason:         "cloud technology category observed (%s)",
			Recommendation: "Cloud technology category (%s) observed; enumerate the cloud service's exposed endpoints and naming patterns.",
		},
		{
			ID:             "cloud-tech-name",
			Category:       "cloud_infrastructure",
			Weight:         0.35,
			Field:          FieldTechName,
			Terms:          []string{"aws", "azure", "google cloud", "gcp", "cloudflare", "digitalocean", "heroku", "vercel", "netlify", "firebase"},
			Reason:         "cloud technology %s observed",
			Recommendation: "Cloud technology %s observed; note the region and service hints this surface discloses.",
		},
		// --- internal exposure -------------------------------------------
		{
			ID:             "internal-host-label",
			Category:       "internal_exposure",
			Weight:         0.5,
			Field:          FieldHost,
			Terms:          []string{"internal", "intranet", "corp", "admin", "staging", "vpn", "bastion", "backup", "jenkins", "gitlab", "dev.", "test."},
			Reason:         "internal-suggesting host label \"%s\" observed",
			Recommendation: "The host label \"%s\" suggests an internal-origin system now reachable externally; prioritize mapping its full surface.",
		},
		{
			ID:       "private-address-host",
			Category: "internal_exposure",
			Weight:   0.5,
			Field:    FieldHost,
			// Private, loopback, and link-local address ranges as they
			// appear in host/url identities (dns host->ip observations and
			// IP-host URLs).
			Regex:          `^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1|fc00:|fe80:)`,
			Reason:         "private network address observed in host identity",
			Recommendation: "A private network address appeared in a public-facing host identity; verify the boundary and record which service exposed it.",
		},
		// --- management interfaces ---------------------------------------
		{
			ID:             "management-port",
			Category:       "management_interface",
			Weight:         0.35,
			Field:          FieldPort,
			Terms:          []string{"8080", "8443", "9000", "9090"},
			Reason:         "common management port %s observed",
			Recommendation: "The management port %s commonly serves administrative consoles; identify the service behind it.",
		},
		{
			ID:             "management-service-name",
			Category:       "management_interface",
			Weight:         0.5,
			Field:          FieldServiceName,
			Terms:          []string{"jenkins", "kibana", "prometheus", "grafana", "consul", "etcd", "rabbitmq", "kafka-management", "redis", "mongodb"},
			Reason:         "management service name \"%s\" observed",
			Recommendation: "The management service \"%s\" typically exposes operational endpoints; inventory its interface.",
		},
		// --- feature flags ------------------------------------------------
		{
			ID:             "feature-flag-parameter",
			Category:       "feature_flag",
			Weight:         0.3,
			Field:          FieldParameterName,
			Terms:          []string{"flag", "feature", "experiment", "toggle", "rollout", "killswitch"},
			Reason:         "feature-flag-suggesting parameter name \"%s\" observed",
			Recommendation: "The feature-flag parameter %s may toggle behavior; record observed values and defaults.",
		},
		// --- legacy / experimental APIs -----------------------------------
		{
			ID:             "legacy-api-path",
			Category:       "legacy_api",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"deprecated", "experimental", "beta", "legacy", "alpha", "/v1/"},
			Reason:         "legacy/experimental API path segment \"%s\" observed",
			Recommendation: "The legacy/experimental API path segment %s may lag current controls; inventory its endpoints and versions.",
		},
		// --- developer tooling ---------------------------------------------
		{
			ID:             "developer-tooling-path",
			Category:       "developer_tooling",
			Weight:         0.4,
			Field:          FieldPath,
			Terms:          []string{"graphiql", "playground", "swagger", "api-docs", "/debug", "/devtools"},
			Reason:         "developer tooling path segment \"%s\" observed",
			Recommendation: "Developer tooling on the path %s often discloses internals; catalog what it renders without authentication.",
		},
		// --- technology disclosure headers ---------------------------------
		{
			ID:       "disclosure-header",
			Category: "disclosure_header",
			Weight:   0.3,
			Field:    FieldHeader,
			// Positive observations only (see the table doc): headers that
			// disclose the serving technology. Absent defensive headers are
			// deliberately NOT cataloged — that would be a vulnerability
			// judgment.
			Terms: []string{
				"x-powered-by:", "x-aspnet-version:", "x-aspnetmvc-version:",
				"x-runtime:", "x-debug:", "x-generator:", "x-drupal-cache:",
				"x-redirect-by:",
			},
			Reason:         "technology-disclosing response header \"%s\" observed",
			Recommendation: "The response header \"%s\" discloses the serving technology; use it to select matching fingerprints and documentation.",
		},
	}
}

// LoadRisk merges, validates, and compiles the production risk indicator
// catalog. Any data-model violation fails the load.
func LoadRisk() (*Catalog, error) {
	return compile("risk", riskTable())
}
