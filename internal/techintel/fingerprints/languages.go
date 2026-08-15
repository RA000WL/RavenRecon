package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// languageTable returns the programming language and runtime fingerprints.
//
// Node.js is the runtime entry: the asset model's CategoryRuntime doc names
// Node.js as its canonical example, so the runtime category is represented
// here. Go is deliberately absent — Go's net/http emits no documented
// default marker (no Server header unless explicitly configured), so a Go
// fingerprint would be an invented indicator.
func languageTable() []Fingerprint {
	return []Fingerprint{
		{
			// PHP's default X-Powered-By: PHP/8.2.12 header (expose_php=On)
			// carries the version; .php path suffixes are a weak auxiliary
			// marker. Cross-ref the php session cookie entry (auth).
			Name:     "php",
			Category: asset.CategoryLanguage,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: php", Weight: 0.8, Version: &VersionSpec{Pattern: `(?i)php/([0-9.]+)`, Group: 1}},
				{Kind: IndicatorEndpointPath, Match: "index.php", Weight: 0.4},
			},
		},
		{
			// Python's stdlib SimpleHTTPRequestHandler banner is "Server:
			// SimpleHTTP/0.6 Python/3.11.2" — a real, documented marker,
			// though only for dev/static file servers. UNCERTAIN beyond that:
			// production Python frameworks set their own banners.
			Name:     "python",
			Category: asset.CategoryLanguage,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: python", Weight: 0.6, Version: &VersionSpec{Pattern: `(?i)python/([0-9.]+)`, Group: 1}},
			},
		},
		{
			// UNCERTAIN: Node's http server sends no default marker, and
			// Express (which most Node apps use) is detected by its own
			// entry. x-powered-by: node fires only on explicit deployments.
			// Kept for spec coverage at low weight.
			Name:     "node.js",
			Category: asset.CategoryRuntime,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: node", Weight: 0.3},
			},
		},
		{
			// JSESSIONID is the Java servlet standard (cross-ref spring /
			// spring session entries); X-Powered-By: Servlet appears on some
			// servlet containers (not universal — low).
			Name:     "java",
			Category: asset.CategoryLanguage,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "JSESSIONID", Weight: 0.4},
				{Kind: IndicatorHeader, Match: "x-powered-by: servlet", Weight: 0.4},
			},
		},
		{
			// Phusion Passenger sets X-Powered-By: Phusion Passenger for
			// Ruby apps (cross-ref the rails entry); X-Runtime is Rails'
			// request-time header (not Ruby-only — low).
			Name:     "ruby",
			Category: asset.CategoryLanguage,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: phusion", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-powered-by: passenger", Weight: 0.7},
				{Kind: IndicatorHeader, Match: "x-runtime", Weight: 0.4},
			},
		},
		{
			// ASP.NET's x-aspnet-version and X-Powered-By: ASP.NET headers
			// (cross-ref the asp.net framework and iis entries).
			Name:     ".net",
			Category: asset.CategoryLanguage,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-aspnet-version", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-powered-by: asp.net", Weight: 0.7},
			},
		},
	}
}
