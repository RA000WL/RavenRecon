package techintel

import "testing"

// megaObs builds a synthetic observation that fires as many fingerprints of
// the production DB as possible, using only documented markers from the DB's
// own tables. The URL path carries every endpoint_path marker (substring
// matching lets one path satisfy many); headers, cookies, body, TLS, and DNS
// carry their markers. The critical Content-Type headers come FIRST so the
// fixture stays robust against stale/truncated file views.
func megaObs(t *testing.T) Observation {
	t.Helper()
	path := "/api/rawdata/graphql/graphiql/docs/redoc/openapi.json/jsonrpc/rpc/soap/x.wsdl/services" +
		"/api/overview/connectors/v2/v1/jobs/apis/metrics/_cat/_search/indexes/solr" +
		"/tyk/apis/live/websocket/auth/v1/index.php/execute-api/wp-json/phpmyadmin/message-queues/multi-search"
	o := newObs(t, "https://fixture.example"+path)
	o.Headers = megaHeaders()
	o.Cookies = megaCookies()
	o.Body = megaBody()
	o.TLS = &TLSInfo{
		ALPN:    []string{"h3", "h2"},
		Issuer:  "CN=Google Trust Services LLC",
		Subject: "*.appspot.com *.azurewebsites.net *.blob.core.windows.net login.microsoftonline.com *.amazonaws.com *.digitaloceanspaces.com *.backblazeb2.com *.r2.cloudflarestorage.com *.auth0.com *.firebaseapp.com *.web.app *.okta.com *.amazoncognito.com storage.googleapis.com *.shopify.com s3.amazonaws.com",
	}
	o.DNS = &DNSInfo{CNAMEChain: []string{
		"fixture.example.cloudflare.net",
		"fixture.example.akamaized.net",
		"fixture.example.fastly.net",
		"fixture.example.azurefd.net",
		"fixture.example.sucuri.net",
	}}
	o.Source = "mega-fixture"
	return o
}

func megaHeaders() []HeaderEntry {
	h := func(name, value string) HeaderEntry { return HeaderEntry{Name: name, Value: value} }
	return []HeaderEntry{
		h("Content-Type", "application/json"),
		h("Content-Type", "application/graphql+json"),
		h("Content-Type", "application/grpc-web+proto"),
		h("Content-Type", "application/json-rpc"),
		h("Server", "nginx/1.25.3"),
		h("Server", "nginx/1.25.3 (Ubuntu)"),
		h("Server", "Apache/2.4.57 (Ubuntu)"),
		h("Server", "Microsoft-IIS/10.0"),
		h("Server", "LiteSpeed"),
		h("Server", "Caddy"),
		h("Server", "openresty/1.21.4.1"),
		h("Server", "HAProxy 2.8"),
		h("Server", "squid/6.0"),
		h("Server", "envoy 1.29"),
		h("Server", "Traefik"),
		h("X-Varnish", "12345"),
		h("Via", "1.1 varnish"),
		h("X-Squid-Error", "ERR_ACCESS_DENIED 0"),
		h("X-Envoy-Upstream-Service-Time", "34"),
		h("X-Trace-Url", "http://internal/trace/1"),
		h("X-Served-By", "cache-iad-kiad7000148"),
		h("X-Timer", "S1700000000.123"),
		h("X-Fastly-Request-ID", "abc123"),
		h("CF-Ray", "7a1b2c3d-EWR"),
		h("Server", "cloudflare"),
		h("CF-Cache-Status", "HIT"),
		h("CF-Mitigated", "challenge"),
		h("Server", "Sucuri/Cloudproxy"),
		h("X-Sucuri-ID", "123"),
		h("X-Iinfo", "12345"),
		h("Server", "Squarespace"),
		h("X-Wix-Request-Id", "123"),
		h("Server", "Shopify"),
		h("X-Generator", "Drupal 10 (https://www.drupal.org)"),
		h("X-Powered-By", "PHP/8.2.12"),
		h("Server", "Python/3.11.2"),
		h("Server", "GFE/2.0"),
		h("X-Goog-GFE-Request-Id", "123"),
		h("Docker-Distribution-Api-Version", "registry/2.0"),
		h("X-Elastic-Product", "Elasticsearch"),
		h("X-Typesense-Api-Key", "xyz"),
		h("X-Kong-Proxy-Latency", "1"),
		h("X-Kong-Upstream-Latency", "2"),
		h("Server", "kong"),
		h("X-Tyk-Api", "1"),
		h("X-Tyk-Authorization", "abc"),
		h("Ocp-Apim-Subscription-Key", "abc"),
		h("Ocp-Apim-Trace", "true"),
		h("X-Amzn-RequestId", "abc"),
		h("X-Amz-Apigw-Id", "abc"),
		h("Server", "awselb/2.0"),
		h("X-Amz-Request-Id", "abc"),
		h("X-Amz-Cf-Id", "abc"),
		h("Via", "1.1 cloudfront.net"),
		h("X-Amz-Cf-Pop", "EWR1-C1"),
		h("X-Amz-Bucket-Region", "us-east-1"),
		h("X-Ms-Request-Id", "abc"),
		h("X-Azure-Ref", "abc"),
		h("X-Powered-By", "ASP.NET"),
		h("X-AspNet-Version", "4.0.30319"),
		h("X-AspNetMvc-Version", "5.2"),
		h("X-Powered-By", "Next.js"),
		h("X-Powered-By", "Express"),
		h("X-Powered-By", "fastify"),
		h("X-Powered-By", "NestJS"),
		h("X-Powered-By", "Gin"),
		h("X-Powered-By", "Fiber"),
		h("X-Powered-By", "Echo"),
		h("X-Powered-By", "Phoenix"),
		h("X-Powered-By", "Phusion Passenger"),
		h("X-Runtime", "0.01"),
		h("X-Powered-By", "Laravel"),
		h("X-Application-Context", "app"),
		h("X-Frame-Options", "DENY"),
		h("X-Sentry-Error", "1"),
		h("X-Newrelic-Id", "1"),
		h("X-Newrelic-Transaction", "1"),
		h("X-Datadog-Trace-Id", "1"),
		h("X-Datadog-Parent-Id", "1"),
		h("X-Kafka-Admin", "1"),
		h("X-Meilisearch-Api-Key", "x"),
		h("X-Bunny-Foobar", "x"),
		h("X-Bunny-Region", "x"),
		h("X-Akamai-Transformed", "0"),
		h("X-Akamai-Request-Hash", "abc"),
		h("X-Nf-Request-Id", "123"),
		h("Server", "Netlify"),
		h("X-Vercel-Id", "123"),
		h("Server", "Vercel"),
		h("Fly-Request-Id", "123"),
		h("Server", "fly.io"),
		h("X-Railway-Request-Id", "123"),
		h("Server", "Railway"),
		h("X-Render-Origin-Server", "1"),
		h("Server", "render"),
		h("Via", "1.1 vegur"),
		h("X-Grpc-Web", "1"),
		h("X-Shopify-Access-Token", "x"),
	}
}

func megaCookies() []CookieEntry {
	return []CookieEntry{
		{Name: "__cf_bm", Value: "xyz"},
		{Name: "ak_bmsc", Value: "abc"},
		{Name: "cloudfront", Value: "x"},
		{Name: "BIGipServerpool", Value: "123"},
		{Name: "incap_ses_123", Value: "xyz"},
		{Name: "visid_incap_123", Value: "xyz"},
		{Name: "auth0", Value: "xyz"},
		{Name: "auth0_compat", Value: "xyz"},
		{Name: "okta-oauth-state", Value: "xyz"},
		{Name: "okta-oauth-nonce", Value: "xyz"},
		{Name: "cognito", Value: "xyz"},
		{Name: "KEYCLOAK_IDENTITY", Value: "xyz"},
		{Name: "KEYCLOAK_SESSION", Value: "xyz"},
		{Name: "AUTH_SESSION_ID", Value: "xyz"},
		{Name: "next-auth.session-token", Value: "xyz"},
		{Name: "laravel_session", Value: "xyz"},
		{Name: "XSRF-TOKEN", Value: "xyz"},
		{Name: "csrftoken", Value: "xyz"},
		{Name: "sessionid", Value: "xyz"},
		{Name: "_session_id", Value: "xyz"},
		{Name: "JSESSIONID", Value: "xyz"},
		{Name: "connect.sid", Value: "xyz"},
		{Name: "PHPSESSID", Value: "xyz"},
		{Name: "phx_session", Value: "xyz"},
		{Name: "grafana_session", Value: "xyz"},
		{Name: "session", Value: "xyz"},
		{Name: "ESTSAUTH", Value: "xyz"},
		{Name: "buid", Value: "xyz"},
		{Name: "__session", Value: "xyz"},
		{Name: "shopify", Value: "xyz"},
		{Name: "azure", Value: "xyz"},
	}
}

func megaBody() string {
	return "<html><head>" +
		`<meta name="generator" content="WordPress 6.4.2">` +
		`<meta name="generator" content="Drupal 10 (https://www.drupal.org)">` +
		`<meta name="generator" content="Joomla! 5.0 - Open Source Content Management">` +
		`<meta name="generator" content="Ghost 5.80">` +
		`<meta name="generator" content="Hugo 0.120.0">` +
		`<meta name="generator" content="Jekyll v4.3.2">` +
		`<meta name="generator" content="Astro v4.0.0">` +
		`<meta name="generator" content="Gatsby">` +
		"</head><body>" +
		`<div data-reactroot="">` +
		`<div ng-app ng-version="17.0.0">` +
		`<div data-v-7ba5bd90="">` +
		`<html q:version="1.0.0" q:base="/">` +
		`<script data-main="/js/main.js" src="require.js"></script>` +
		`<center>nginx</center>` +
		"IIS Windows Server" +
		"__VIEWSTATE" +
		"It works!" +
		"__NEXT_DATA__" +
		"self.__next_f.push" +
		"__NUXT__" +
		"___gatsby" +
		"__APOLLO_STATE__" +
		"webpackJsonp" +
		"webpackChunk" +
		"parcelRequire" +
		`/*#__PURE__*/` +
		"__turbopack_context__" +
		"rspack" +
		`{"gitVersion":"v1.29.0"}` +
		"swagger-ui" +
		"phpMyAdmin" +
		"pgAdmin" +
		"mongo-express" +
		"SQLite" +
		"Microsoft SQL Server" +
		"Oracle Database" +
		"RabbitMQ Management" +
		"Welcome to Grafana" +
		"Whitelabel Error Page" +
		"FastAPI - Swagger UI" +
		"cf-error-details" +
		"System.import" +
		"phx-update" +
		"sentry.io" +
		"__remix_context__" +
		`<div class="foo svelte-abc123">` +
		`<script type="module" crossorigin src="/main.js"></script>` +
		`{"statusCode":404,"message":"Not Found","error":"Not Found"}` +
		`<script src="/static/js/react.js"></script>` +
		`<script src="/_next/static/chunks/main.js"></script>` +
		`<script src="/_nuxt/entry.js"></script>` +
		`<script src="/build/entry.client.js"></script>` +
		`<script src="/page-data/app-data.json"></script>` +
		`<script src="/@vite/client"></script>` +
		`<script src="/_astro/astro.js"></script>` +
		`<script src="https://googletagmanager.com/gtag/js?id=G-1"></script>` +
		`<script src="https://www.google-analytics.com/analytics.js"></script>` +
		`<script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/react-relay@0.1/relay.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/vue.runtime.global.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/angular.min.js"></script>` +
		`<script src="/js/svelte.min.js"></script>` +
		`<script src="/js/solid.min.js"></script>` +
		`<script src="/js/qwik.core.js"></script>` +
		`<script src="/js/system.min.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/algoliasearch@4/algoliasearch.min.js"></script>` +
		`<script src="https://cdn.matomo.cloud/matomo.js"></script>` +
		`<script src="https://plausible.io/js/script.js"></script>` +
		`<script src="https://static.hotjar.com/c/hotjar-123.js"></script>` +
		`<script src="https://cdn.segment.com/analytics.js/v1/abc"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/apollo-client@2/apollo.js"></script>` +
		`<script src="https://cdn.usefathom.com/fathom.js"></script>` +
		`<script src="https://wixstatic.com/site.js"></script>` +
		`<script src="https://static.zdassets.com/zendesk.js"></script>` +
		`<script src="/wp-content/themes/t/js/main.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/esbuild@0.19/esbuild.min.js"></script>` +
		`<link rel="stylesheet" href="/_astro/astro.css">` +
		`<link rel="stylesheet" href="https://wixstatic.com/site.css">` +
		`<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/algolia.css">` +
		"//# sourceMappingURL=/static/js/main.js.map" +
		"</body></html>"
}
