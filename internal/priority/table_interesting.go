package priority

// interestingnessTable is the production interestingness catalog: which
// observed signals make a surface worth a researcher's attention. Entries
// reference ONLY data the earlier phases emit.
//
// Documented omissions from the spec's indicator families (no emitting
// phase produces the data):
//
//   - page TITLES: httpprobe counts the body and never retains content, so
//     no title-based signal exists; only status/headers/metadata are real.
//   - MULTIPART request hints: no phase observes request bodies, so upload
//     detection uses paths and parameter names only.
//   - response BODY content: bodies are counted, never retained.
func interestingnessTable() []Indicator {
	return []Indicator{
		// --- admin / admin panels -------------------------------------
		{
			ID:             "admin-path",
			Category:       "admin",
			Weight:         0.5,
			Field:          FieldPath,
			Terms:          []string{"/admin", "/administrator", "/wp-admin", "/adm"},
			Reason:         "administrative path segment \"%s\" observed",
			Recommendation: "Map the administrative path %s: note its reachability, authentication requirements, and any exposed sub-entries for the report.",
		},
		{
			ID:             "admin-panel-path",
			Category:       "admin_panel",
			Weight:         0.45,
			Field:          FieldPath,
			Terms:          []string{"/dashboard", "/console", "/panel", "/cpanel", "/manage", "/manager", "/backoffice"},
			Reason:         "administrative panel path segment \"%s\" observed",
			Recommendation: "Enumerate the administrative panel path %s for management functionality and note what it exposes.",
		},
		// --- internal / staging / dev / test ---------------------------
		{
			ID:             "internal-path",
			Category:       "internal",
			Weight:         0.5,
			Field:          FieldPath,
			Terms:          []string{"/internal", "/_internal", "/intranet", "/internal-api"},
			Reason:         "internal-facing path segment \"%s\" observed",
			Recommendation: "The internal-facing path %s suggests non-public surface; verify its exposure boundary and record what it serves.",
		},
		{
			ID:             "debug-path",
			Category:       "debug",
			Weight:         0.5,
			Field:          FieldPath,
			Terms:          []string{"/debug", "/devtools", "/_debug", "/debugging", "/trace"},
			Reason:         "debugging path segment \"%s\" observed",
			Recommendation: "The debugging path %s may reveal diagnostics; catalog what it exposes without altering state.",
		},
		{
			ID:       "staging-path",
			Category: "staging",
			Weight:   0.45,
			Field:    FieldPath,
			// Boundary regex: /staging matches, /staging-api matches,
			// /stagger does not.
			Regex:          `/(?:staging|stage)(?:[/.]|$)`,
			Reason:         "staging path segment observed",
			Recommendation: "Staging deployments often relax controls; compare this staging path's exposure with production and document differences.",
		},
		{
			ID:       "dev-path",
			Category: "dev",
			Weight:   0.4,
			Field:    FieldPath,
			// Boundary regex: /dev and /development match, /devices does not.
			Regex:          `/(?:dev|development)(?:[/.]|$)`,
			Reason:         "development path segment observed",
			Recommendation: "The development path suggests a non-production deployment; record what this surface discloses.",
		},
		{
			ID:       "test-path",
			Category: "test",
			Weight:   0.3,
			Field:    FieldPath,
			// Boundary regex: /test, /testing, /sandbox match,
			// /testimonials does not.
			Regex:          `/(?:test|testing|sandbox|qa)(?:[/.]|$)`,
			Reason:         "test/sandbox path segment observed",
			Recommendation: "Test and sandbox paths often run weaker configurations; inventory this surface's behavior for the report.",
		},
		// --- API surfaces ----------------------------------------------
		{
			ID:             "api-path",
			Category:       "api",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"/api", "/rest", "/rpc", "/soap"},
			Reason:         "API path segment \"%s\" observed",
			Recommendation: "Inventory the API surface under the path %s: document methods, parameters, and error behavior for follow-up testing.",
		},
		{
			ID:             "api-versioned-path",
			Category:       "versioned_api",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"/api/v1", "/api/v2", "/api/v3", "/v1/", "/v2/", "/v3/", "/v4/"},
			Reason:         "versioned API path segment \"%s\" observed",
			Recommendation: "The versioned API path segment %s indicates a documented API surface; enumerate sibling versions and deprecation state.",
		},
		{
			ID:             "graphql-path",
			Category:       "graphql",
			Weight:         0.45,
			Field:          FieldPath,
			Terms:          []string{"/graphql", "/api/graphql", "/graphiql"},
			Reason:         "GraphQL path segment \"%s\" observed",
			Recommendation: "The GraphQL path %s deserves schema inventory: check read-only introspection and record the exposed types.",
		},
		{
			ID:             "graphql-tech-category",
			Category:       "graphql",
			Weight:         0.4,
			Field:          FieldTechCategory,
			Terms:          []string{"graphql"},
			Reason:         "GraphQL technology category observed (%s)",
			Recommendation: "GraphQL technology (%s) observed; inventory schema exposure and the query surface it accepts.",
		},
		// --- API documentation / developer tooling ----------------------
		{
			ID:             "api-docs-path",
			Category:       "api_docs",
			Weight:         0.55,
			Field:          FieldPath,
			Terms:          []string{"/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc", "/apidocs"},
			Reason:         "API documentation path segment \"%s\" observed",
			Recommendation: "API documentation at the path %s enumerates endpoints; harvest it as the authoritative map of the API surface.",
		},
		{
			ID:             "devtools-path",
			Category:       "developer_tools",
			Weight:         0.5,
			Field:          FieldPath,
			Terms:          []string{"graphiql", "playground", "/docs", "/debugger", "/swagger-ui", "/api-docs", "/altair", "/voyager"},
			Reason:         "developer tooling path segment \"%s\" observed",
			Recommendation: "Interactive developer tooling at the path %s should be inventoried; note its accessibility and what it renders.",
		},
		{
			ID:             "well-known-path",
			Category:       "well_known",
			Weight:         0.35,
			Field:          FieldPath,
			Terms:          []string{"/.well-known"},
			Reason:         "well-known path segment \"%s\" observed",
			Recommendation: "The well-known path segment %s hosts standard endpoints; enumerate which well-known records are exposed.",
		},
		// --- management / observability interfaces ----------------------
		{
			ID:             "actuator-path",
			Category:       "actuator",
			Weight:         0.6,
			Field:          FieldPath,
			Terms:          []string{"/actuator"},
			Reason:         "management actuator path segment \"%s\" observed",
			Recommendation: "The management actuator path %s exposes framework administration endpoints; inventory which actuator sections respond.",
		},
		{
			ID:             "metrics-path",
			Category:       "metrics",
			Weight:         0.45,
			Field:          FieldPath,
			Terms:          []string{"/metrics", "/_metrics", "/prometheus/metrics", "/stats", "/statistic"},
			Reason:         "metrics path segment \"%s\" observed",
			Recommendation: "The metrics path %s can disclose internal topology; record what measurements it exposes.",
		},
		{
			ID:             "jenkins-path",
			Category:       "jenkins",
			Weight:         0.55,
			Field:          FieldPath,
			Terms:          []string{"/jenkins", "/job/"},
			Reason:         "Jenkins path segment \"%s\" observed",
			Recommendation: "The Jenkins path %s indicates CI surface; record its version banner and authentication posture.",
		},
		{
			ID:             "kibana-path",
			Category:       "kibana",
			Weight:         0.55,
			Field:          FieldPath,
			Terms:          []string{"/kibana", "/app/kibana"},
			Reason:         "Kibana path segment \"%s\" observed",
			Recommendation: "The Kibana path %s indicates a data-UI surface; note its accessibility and version disclosure.",
		},
		{
			ID:             "kibana-tech-name",
			Category:       "kibana",
			Weight:         0.5,
			Field:          FieldTechName,
			Terms:          []string{"kibana", "elasticsearch"},
			Reason:         "observability technology %s observed",
			Recommendation: "Observability technology %s observed; probe for exposed dashboards and index listings.",
		},
		{
			ID:             "prometheus-path",
			Category:       "prometheus",
			Weight:         0.4,
			Field:          FieldPath,
			Terms:          []string{"/prometheus", "/grafana", "/alertmanager"},
			Reason:         "monitoring path segment \"%s\" observed",
			Recommendation: "Monitoring surface at the path %s detected; inventory dashboards and health endpoints.",
		},
		{
			ID:             "monitoring-tech-category",
			Category:       "prometheus",
			Weight:         0.4,
			Field:          FieldTechCategory,
			Terms:          []string{"monitoring"},
			Reason:         "monitoring technology category observed (%s)",
			Recommendation: "Monitoring technology category (%s) observed; enumerate the monitoring stack's exposed interfaces.",
		},
		// --- source maps and bundles ------------------------------------
		{
			ID:             "sourcemap-kind",
			Category:       "source_map",
			Weight:         0.5,
			Field:          FieldKind,
			Kind:           "source_map",
			Reason:         "source map asset observed",
			Recommendation: "A source map asset is exposed; recover the mapped source tree and review it for embedded endpoints and configuration.",
		},
		{
			ID:             "sourcemap-path",
			Category:       "source_map",
			Weight:         0.35,
			Field:          FieldPath,
			Terms:          []string{".js.map", "js.map", ".map"},
			Reason:         "source map path segment \"%s\" observed",
			Recommendation: "The source map path %s is exposed; retrieve it and review the mapped sources for disclosed logic.",
		},
		{
			ID:             "large-js-bundle",
			Category:       "large_js_bundle",
			Weight:         0.3,
			Field:          FieldJSBundleSize,
			MinJSBytes:     1 << 20, // 1 MiB (jsintel retention clamps to [64 KiB, 8 MiB])
			Reason:         "large JavaScript bundle observed (>= 1 MiB)",
			Recommendation: "The large JavaScript bundle (>= 1 MiB) rewards deep review; parse it for endpoints, routes, and embedded configuration.",
		},
		{
			ID:             "build-manifest-path",
			Category:       "build_manifest",
			Weight:         0.35,
			Field:          FieldPath,
			Terms:          []string{"webpack", "/vite/", "rollup", "package.json", "manifest.json", "asset-manifest", "build-manifest", "bundle.", "chunk.", "vendor."},
			Reason:         "build manifest segment \"%s\" observed",
			Recommendation: "The build artifact path segment %s discloses the build layout; use it to locate chunks, source maps, and internal paths.",
		},
		{
			ID:             "build-tool-tech-category",
			Category:       "build_manifest",
			Weight:         0.35,
			Field:          FieldTechCategory,
			Terms:          []string{"build_tool"},
			Reason:         "build tool technology category observed (%s)",
			Recommendation: "Build tool technology category (%s) observed; enumerate emitted manifests and chunk maps.",
		},
		// --- authentication ---------------------------------------------
		{
			ID:             "auth-path",
			Category:       "authentication",
			Weight:         0.4,
			Field:          FieldPath,
			Terms:          []string{"/login", "/signin", "/sign-in", "/signup", "/register", "/sso", "/oauth", "/authorize", "/session", "/auth"},
			Reason:         "authentication path segment \"%s\" observed",
			Recommendation: "The authentication path %s defines the entry point to protected surface; record its flow, providers, and parameters.",
		},
		{
			ID:             "auth-tech-category",
			Category:       "authentication",
			Weight:         0.45,
			Field:          FieldTechCategory,
			Terms:          []string{"authentication"},
			Reason:         "authentication technology category observed (%s)",
			Recommendation: "Authentication technology category (%s) observed; map the login flow and session handling.",
		},
		{
			ID:             "auth-tech-name",
			Category:       "authentication",
			Weight:         0.45,
			Field:          FieldTechName,
			Terms:          []string{"auth0", "okta", "keycloak", "firebase", "cognito", "identityserver"},
			Reason:         "authentication technology %s observed",
			Recommendation: "Identity technology %s observed; inventory its configured flows, redirect targets, and tenant hints.",
		},
		// --- upload / file management -----------------------------------
		{
			ID:             "upload-path",
			Category:       "upload",
			Weight:         0.45,
			Field:          FieldPath,
			Terms:          []string{"/upload", "/uploads", "/file-upload", "/attach"},
			Reason:         "upload path segment \"%s\" observed",
			Recommendation: "The upload path %s accepts file submission; record accepted types and any client-side validation only.",
		},
		{
			ID:             "upload-parameter",
			Category:       "upload",
			Weight:         0.4,
			Field:          FieldParameterName,
			Terms:          []string{"file", "filename", "attachment", "avatar", "upload", "document"},
			Reason:         "upload-suggesting parameter name \"%s\" observed",
			Recommendation: "The upload-suggesting parameter %s marks a file-submission seam; note it for authorized testing.",
		},
		{
			ID:             "file-management-path",
			Category:       "file_management",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"/files", "/file", "/download", "/downloads", "/static/", "/assets/", "/media/", "/backup", "/export", "/import"},
			Reason:         "file management path segment \"%s\" observed",
			Recommendation: "The file management path %s serves static content; enumerate the directory's exposure and any listings.",
		},
		// --- search ------------------------------------------------------
		{
			ID:             "search-path",
			Category:       "search",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"/search", "/query", "/find", "/lookup"},
			Reason:         "search path segment \"%s\" observed",
			Recommendation: "The search path %s accepts queries; note its parameter handling for follow-up inspection.",
		},
		{
			ID:             "search-parameter",
			Category:       "search",
			Weight:         0.3,
			Field:          FieldParameterName,
			Terms:          []string{"query", "search", "keyword", "terms"},
			Reason:         "search parameter name \"%s\" observed",
			Recommendation: "The search parameter %s feeds a query engine; record how it is interpreted.",
		},
		// --- messaging ---------------------------------------------------
		{
			ID:             "messaging-path",
			Category:       "messaging",
			Weight:         0.35,
			Field:          FieldPath,
			Terms:          []string{"/chat", "/message", "/messages", "/messaging", "/ws", "/websocket", "/socket.io", "/realtime"},
			Reason:         "messaging path segment \"%s\" observed",
			Recommendation: "The messaging path %s indicates realtime endpoints; document the protocol and handshake shape.",
		},
		{
			ID:             "websocket-endpoint-method",
			Category:       "messaging",
			Weight:         0.4,
			Field:          FieldEndpointMethod,
			Terms:          []string{"ws"},
			Reason:         "websocket endpoint class observed (%s)",
			Recommendation: "A websocket endpoint class (%s) was observed; record its message protocol for authorized testing.",
		},
		{
			ID:             "message-queue-tech-category",
			Category:       "messaging",
			Weight:         0.35,
			Field:          FieldTechCategory,
			Terms:          []string{"message_queue"},
			Reason:         "message queue technology category observed (%s)",
			Recommendation: "Message queue technology category (%s) observed; note any exposed management or stats interfaces.",
		},
		// --- payment -----------------------------------------------------
		{
			ID:             "payment-path",
			Category:       "payment",
			Weight:         0.5,
			Field:          FieldPath,
			Terms:          []string{"payment", "checkout", "billing", "/cart", "/pay", "paypal", "stripe"},
			Reason:         "payment path segment \"%s\" observed",
			Recommendation: "The payment path %s handles transactional surface; map its flow and parameter set.",
		},
		{
			ID:             "payment-tech-name",
			Category:       "payment",
			Weight:         0.5,
			Field:          FieldTechName,
			Terms:          []string{"stripe", "paypal", "braintree", "adyen", "square"},
			Reason:         "payment technology %s observed",
			Recommendation: "Payment technology %s observed; inventory its integration surface (forms, webhooks, redirects).",
		},
		// --- account -----------------------------------------------------
		{
			ID:             "account-path",
			Category:       "account",
			Weight:         0.3,
			Field:          FieldPath,
			Terms:          []string{"/account", "/profile", "/settings", "/preferences", "/user", "/users", "/me"},
			Reason:         "account path segment \"%s\" observed",
			Recommendation: "The account path %s exposes user-facing functionality; enumerate its actions and parameters.",
		},
	}
}

// LoadInterestingness merges, validates, and compiles the production
// interestingness catalog. Any data-model violation fails the load, so a
// malformed table can never reach the scoring engine.
func LoadInterestingness() (*Catalog, error) {
	return compile("interestingness", interestingnessTable())
}
