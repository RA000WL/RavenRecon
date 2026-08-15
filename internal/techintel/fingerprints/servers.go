package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// serverTable returns the web server and reverse proxy fingerprints.
//
// Canonical category rule: Traefik, Envoy, HAProxy, Varnish, and Squid are
// reverse proxies and live under CategoryProxy; nginx, Apache, IIS,
// LiteSpeed, Caddy, and OpenResty are origin servers under CategoryServer.
// Overlaps are noted per entry (for example OpenResty also shows nginx
// markers, and Varnish's Via header also fires for Fastly).
func serverTable() []Fingerprint {
	return []Fingerprint{
		{
			// "Server: nginx/1.25.3 (Ubuntu)" — the value carries the
			// version; the default error page footer is "<center>nginx".
			Name:     "nginx",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: nginx", Weight: 0.9, Version: &VersionSpec{Pattern: `nginx/([0-9]+\.[0-9]+\.[0-9]+)`, Group: 1}},
				{Kind: IndicatorHTMLSubstring, Match: "<center>nginx", Weight: 0.6},
			},
		},
		{
			// "Server: Apache/2.4.57 (Ubuntu)" — the value carries the
			// version; "It works!" is Apache's classic default index page
			// (also used by other servers — low).
			Name:     "apache",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: apache", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)apache/([0-9]+\.[0-9]+\.[0-9]+)`, Group: 1}},
				{Kind: IndicatorHTMLSubstring, Match: "It works!", Weight: 0.3},
			},
		},
		{
			// "Server: Microsoft-IIS/10.0" — the value carries the version.
			// x-powered-by: asp.net fires for IIS-hosted ASP.NET (cross-ref
			// the asp.net framework entry).
			Name:     "iis",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: microsoft-iis", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)microsoft-iis/([0-9.]+)`, Group: 1}},
				{Kind: IndicatorHeader, Match: "x-powered-by: asp.net", Weight: 0.6},
			},
		},
		{
			// "Server: LiteSpeed" banners and the X-LiteSpeed-Cache header
			// emitted by LiteSpeed's cache layer.
			Name:     "litespeed",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: litespeed", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)litespeed/([0-9.]+)`, Group: 1}},
				{Kind: IndicatorHeader, Match: "x-litespeed-cache", Weight: 0.8},
			},
		},
		{
			// "Server: Caddy" — modern Caddy omits the version from the
			// banner by default, so the version pattern's group is optional.
			Name:     "caddy",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: caddy", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)caddy(?:/([0-9.]+))?`, Group: 1}},
			},
		},
		{
			// "Server: openresty/1.25.3.1" banners. OpenResty also carries
			// nginx markers — cross-ref the nginx entry.
			Name:     "openresty",
			Category: asset.CategoryServer,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: openresty", Weight: 0.9, Version: &VersionSpec{Pattern: `openresty/([0-9.]+)`, Group: 1}},
			},
		},
		{
			// "Server: haproxy/2.6.1" — HAProxy's default server banner
			// carries the version.
			Name:     "haproxy",
			Category: asset.CategoryProxy,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: haproxy", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)haproxy/([0-9.]+)`, Group: 1}},
			},
		},
		{
			// X-Varnish (request id), Via: varnish, and Server: varnish
			// banners. Fastly is Varnish-based and also emits Via — the
			// fastly entry carries its own distinctive headers.
			Name:     "varnish",
			Category: asset.CategoryProxy,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-varnish", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "via: varnish", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "server: varnish", Weight: 0.7},
			},
		},
		{
			// "Server: squid/5.7" banners and X-Squid-Error on error pages.
			Name:     "squid",
			Category: asset.CategoryProxy,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: squid", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)squid/([0-9.]+)`, Group: 1}},
				{Kind: IndicatorHeader, Match: "x-squid-error", Weight: 0.8},
			},
		},
		{
			// "Server: envoy" banners and Envoy's distinctive x-envoy-*
			// headers.
			Name:     "envoy",
			Category: asset.CategoryProxy,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: envoy", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-envoy-upstream-service-time", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-envoy-decorator-operation", Weight: 0.8},
			},
		},
		{
			// Traefik is a reverse proxy (canonical category proxy). Recent
			// Traefik does NOT set a Server header by default (low); the
			// dashboard API /api/rawdata is Traefik's own endpoint (often
			// auth-protected — low).
			Name:     "traefik",
			Category: asset.CategoryProxy,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: traefik", Weight: 0.5},
				{Kind: IndicatorEndpointPath, Match: "/api/rawdata", Weight: 0.5},
			},
		},
	}
}
