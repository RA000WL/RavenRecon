package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// infraTable returns the infrastructure fingerprints: databases, search
// engines, message queues, monitoring, storage, containers, orchestration,
// and analytics.
//
// Database note: MySQL/PostgreSQL/MongoDB/Redis/SQLite/MariaDB/MSSQL/Oracle
// serve no standard HTTP surface, so their markers are conservative admin-UI
// and text-mention markers with documented limits and LOW weights — an
// admin panel (phpMyAdmin, pgAdmin) proves the panel, not the database, and
// a text mention proves nothing by itself. The engine pass must treat these
// entries as evidence-only.
func infraTable() []Fingerprint {
	return []Fingerprint{
		{
			// phpMyAdmin is the standard MySQL admin UI. Documented limit:
			// this fires on the panel, not on MySQL itself.
			Name:     "mysql",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "phpmyadmin", Weight: 0.5},
			},
		},
		{
			// pgAdmin is the standard PostgreSQL admin UI. Documented limit:
			// this fires on the panel, not on PostgreSQL itself.
			Name:     "postgresql",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "pgadmin", Weight: 0.5},
			},
		},
		{
			// mongo-express is a common MongoDB admin UI. Documented limit:
			// this fires on the panel, not on MongoDB itself.
			Name:     "mongodb",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "mongo-express", Weight: 0.5},
			},
		},
		{
			// UNCERTAIN: Redis serves no HTTP surface; "server: redis" fires
			// only on explicit misconfigured banners. Kept for spec coverage
			// at low weight.
			Name:     "redis",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: redis", Weight: 0.3},
			},
		},
		{
			// UNCERTAIN: SQLite has no HTTP marker; this fires only when a
			// page's text mentions "SQLite" (admin panels showing the DB
			// type). Evidence-only at low weight.
			Name:     "sqlite",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "SQLite", Weight: 0.2},
			},
		},
		{
			// phpMyAdmin serves MariaDB too; overlap with the mysql entry.
			// Documented limit: fires on the panel, not on MariaDB itself.
			Name:     "mariadb",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "phpmyadmin", Weight: 0.4},
			},
		},
		{
			// UNCERTAIN: MSSQL serves no HTTP surface; "microsoft sql server"
			// fires only on error pages and debug output that mention it.
			// Evidence-only at low weight.
			Name:     "mssql",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "microsoft sql server", Weight: 0.2},
			},
		},
		{
			// UNCERTAIN: Oracle serves no standard HTTP surface; "oracle
			// database" fires only on admin panels and debug output that
			// mention it. Evidence-only at low weight.
			Name:     "oracle",
			Category: asset.CategoryDatabase,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "oracle database", Weight: 0.2},
			},
		},
		{
			// Elasticsearch's _search / _cat API paths and its
			// application/vnd.elasticsearch+json content type. One entry
			// covers both spec mentions ("elasticsearch" as datastore and
			// "elastic (search)" as search engine); canonical category is
			// search_engine.
			Name:     "elasticsearch",
			Category: asset.CategorySearchEngine,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/_search", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/_cat", Weight: 0.7},
				{Kind: IndicatorHeader, Match: "content-type: application/vnd.elasticsearch+json", Weight: 0.9},
			},
		},
		{
			// algoliasearch.min.js bundles and Algolia's docsearch script.
			Name:     "algolia",
			Category: asset.CategorySearchEngine,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "algoliasearch", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "docsearch", Weight: 0.4},
			},
		},
		{
			// Meilisearch's /indexes/ API path. The server emits no
			// documented distinctive response header (the X-Meilisearch-Client
			// header is client-sent) — hence the low weight.
			Name:     "meilisearch",
			Category: asset.CategorySearchEngine,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/indexes/", Weight: 0.5},
			},
		},
		{
			// Typesense responses carry an x-typesense header (verified by
			// projectdiscovery's nuclei template and shodan's
			// "x-typesense" search).
			Name:     "typesense",
			Category: asset.CategorySearchEngine,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-typesense", Weight: 0.8},
			},
		},
		{
			// Solr's /solr/ admin and API prefix.
			Name:     "solr",
			Category: asset.CategorySearchEngine,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/solr/", Weight: 0.8},
			},
		},
		{
			// RabbitMQ's management UI title and its /api/overview API path.
			Name:     "rabbitmq",
			Category: asset.CategoryMessageQueue,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "RabbitMQ Management", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/api/overview", Weight: 0.6},
			},
		},
		{
			// Kafka serves no HTTP surface of its own; /connectors is the
			// Kafka Connect REST API (also used by Debezium-style
			// connectors — low). UNCERTAIN: kept for spec coverage.
			Name:     "kafka",
			Category: asset.CategoryMessageQueue,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/connectors", Weight: 0.4},
			},
		},
		{
			// SQS is AWS-managed with no HTTP UI; certificates under
			// sqs.<region>.amazonaws.com are the only passive marker
			// (cross-ref the aws cloud entry).
			Name:     "sqs",
			Category: asset.CategoryMessageQueue,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "sqs.", Weight: 0.5},
			},
		},
		{
			// Grafana's grafana_session cookie and the login page's
			// "Welcome to Grafana" text.
			Name:     "grafana",
			Category: asset.CategoryMonitoring,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "grafana_session", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "Welcome to Grafana", Weight: 0.7},
			},
		},
		{
			// Prometheus's exposition-format content type and /metrics
			// endpoint (also used by other exporters — low-ish).
			Name:     "prometheus",
			Category: asset.CategoryMonitoring,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "content-type: text/plain; version=0.0.4", Weight: 0.9},
				{Kind: IndicatorEndpointPath, Match: "/metrics", Weight: 0.6},
			},
		},
		{
			// Datadog APM's x-datadog-trace-id / x-datadog-parent-id headers
			// (present when tracing is enabled).
			Name:     "datadog",
			Category: asset.CategoryMonitoring,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-datadog-trace-id", Weight: 0.7},
				{Kind: IndicatorHeader, Match: "x-datadog-parent-id", Weight: 0.7},
			},
		},
		{
			// Sentry's x-sentry-error header on error responses and sentry
			// bundle names (CDN bundle names vary — low).
			Name:     "sentry",
			Category: asset.CategoryMonitoring,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-sentry-error", Weight: 0.7},
				{Kind: IndicatorScriptName, Match: "sentry", Weight: 0.3},
			},
		},
		{
			// New Relic APM's x-newrelic-id / x-newrelic-transaction headers.
			Name:     "new relic",
			Category: asset.CategoryMonitoring,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-newrelic-id", Weight: 0.6},
				{Kind: IndicatorHeader, Match: "x-newrelic-transaction", Weight: 0.6},
			},
		},
		{
			// S3's x-amz-bucket-region header (bucket-level responses) and
			// certificates under s3.<region>.amazonaws.com. Cross-ref the aws
			// cloud entry; canonical category is storage.
			Name:     "s3",
			Category: asset.CategoryStorage,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-amz-bucket-region", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "s3.", Weight: 0.5},
			},
		},
		{
			// GCS endpoints under storage.googleapis.com (cross-ref the
			// google cloud entry).
			Name:     "gcs",
			Category: asset.CategoryStorage,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "storage.googleapis.com", Weight: 0.9},
			},
		},
		{
			// Azure Blob endpoints under blob.core.windows.net and the
			// x-ms-blob-type header (cross-ref the azure entry).
			Name:     "azure blob",
			Category: asset.CategoryStorage,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "blob.core.windows.net", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-ms-blob-type", Weight: 0.9},
			},
		},
		{
			// Cloudflare R2 endpoints under r2.cloudflarestorage.com and
			// public buckets under r2.dev.
			Name:     "cloudflare r2",
			Category: asset.CategoryStorage,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "r2.cloudflarestorage.com", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "r2.dev", Weight: 0.6},
			},
		},
		{
			// Backblaze B2 endpoints under backblazeb2.com.
			Name:     "backblaze b2",
			Category: asset.CategoryStorage,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "backblazeb2.com", Weight: 0.9},
			},
		},
		{
			// Docker Registry's docker-distribution-api-version header and
			// the /v2/ registry API prefix.
			Name:     "docker",
			Category: asset.CategoryContainer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "docker-distribution-api-version", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/v2/", Weight: 0.5},
			},
		},
		{
			// UNCERTAIN: containerd serves no HTTP surface; "containerd"
			// fires only on text mentions. Evidence-only at low weight.
			Name:     "containerd",
			Category: asset.CategoryContainer,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "containerd", Weight: 0.2},
			},
		},
		{
			// Kubernetes' kube-apiserver exposes /version (whose body carries
			// "gitVersion":"v1.29.0") and the /apis/ API prefix. Conservative
			// per spec: no standard x-kubernetes-* response header.
			Name:     "kubernetes",
			Category: asset.CategoryOrchestration,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLRegex, Match: `"gitVersion":"v[0-9]+\.[0-9]+`, Weight: 0.6},
				{Kind: IndicatorEndpointPath, Match: "/apis/", Weight: 0.4},
			},
		},
		{
			// ECS is AWS-managed with no HTTP UI; certificates under
			// ecs.<region>.amazonaws.com are the only passive marker
			// (cross-ref the aws cloud entry).
			Name:     "ecs",
			Category: asset.CategoryOrchestration,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "ecs.", Weight: 0.5},
			},
		},
		{
			// Nomad's /v1/jobs HTTP API path.
			Name:     "nomad",
			Category: asset.CategoryOrchestration,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/v1/jobs", Weight: 0.5},
			},
		},
		{
			// Google Analytics' gtag.js / ga.js bundles served from
			// googletagmanager.com / google-analytics.com.
			Name:     "google analytics",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "gtag.js", Weight: 0.9},
				{Kind: IndicatorScriptPath, Match: "googletagmanager.com", Weight: 0.9},
				{Kind: IndicatorScriptName, Match: "ga.js", Weight: 0.7},
				{Kind: IndicatorScriptPath, Match: "google-analytics.com", Weight: 0.8},
			},
		},
		{
			// Matomo's matomo.js bundle and the piwik.js legacy name.
			Name:     "matomo",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "matomo.js", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "piwik.js", Weight: 0.8},
			},
		},
		{
			// Plausible's default script URL (plausible.io for cloud, and
			// the generic script.js basename for self-hosted — very low).
			Name:     "plausible",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "plausible.io", Weight: 0.7},
				{Kind: IndicatorScriptName, Match: "script.js", Weight: 0.2},
			},
		},
		{
			// Fathom's script is served from cdn.usefathom.com.
			Name:     "fathom",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "cdn.usefathom.com", Weight: 0.8},
			},
		},
		{
			// Hotjar's script is served from static.hotjar.com.
			Name:     "hotjar",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "static.hotjar.com", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "hotjar", Weight: 0.5},
			},
		},
		{
			// Segment's script is served from cdn.segment.com.
			Name:     "segment",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "cdn.segment.com", Weight: 0.7},
				{Kind: IndicatorScriptName, Match: "analytics.min.js", Weight: 0.3},
			},
		},
		{
			// Mixpanel's script is served from cdn.mxpnl.com; bundle names
			// carry "mixpanel" (lower weight).
			Name:     "mixpanel",
			Category: asset.CategoryAnalytics,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "cdn.mxpnl.com", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "mixpanel", Weight: 0.5},
			},
		},
	}
}
