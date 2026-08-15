package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// frameworkTable returns the web application framework fingerprints.
// Each entry's comment names the observable marker and any uncertainty.
func frameworkTable() []Fingerprint {
	return []Fingerprint{
		{
			// react.js / react-dom.js bundles, and the data-reactroot root
			// attribute React leaves in rendered HTML.
			Name:     "react",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "react.js", Weight: 0.9},
				{Kind: IndicatorScriptName, Match: "react-dom", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "data-reactroot", Weight: 0.8},
			},
		},
		{
			// __NEXT_DATA__ (Pages Router), self.__next_f.push (App Router
			// flight payloads), /_next/static/ asset paths, and the default
			// X-Powered-By: Next.js header (often stripped in production).
			Name:     "next.js",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "__NEXT_DATA__", Weight: 1.0},
				{Kind: IndicatorHTMLSubstring, Match: "self.__next_f.push", Weight: 0.9},
				{Kind: IndicatorScriptPath, Match: "/_next/static/", Weight: 1.0},
				{Kind: IndicatorHeader, Match: "x-powered-by: next.js", Weight: 0.7},
			},
		},
		{
			// vue.runtime / vue.global / vue.min.js bundles and the data-v-
			// scoped-CSS attribute Vue's compiler adds to element classes.
			Name:     "vue",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "vue.runtime", Weight: 0.9},
				{Kind: IndicatorScriptName, Match: "vue.global", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "vue.min.js", Weight: 0.8},
				{Kind: IndicatorHTMLSubstring, Match: "data-v-", Weight: 0.7},
			},
		},
		{
			// Nuxt's __NUXT__ inline state and /_nuxt/ asset prefix.
			Name:     "nuxt",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "__NUXT__", Weight: 0.9},
				{Kind: IndicatorScriptPath, Match: "/_nuxt/", Weight: 0.9},
			},
		},
		{
			// The ng-version root attribute carries the exact version;
			// ng-app is the AngularJS 1.x marker; angular.js bundles.
			Name:     "angular",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorAttribute, Match: "ng-version", Weight: 1.0, Version: &VersionSpec{Pattern: `([0-9]+\.[0-9]+\.[0-9]+)`, Group: 1}},
				{Kind: IndicatorHTMLSubstring, Match: "ng-app", Weight: 0.7},
				{Kind: IndicatorScriptName, Match: "angular.min.js", Weight: 0.9},
				{Kind: IndicatorScriptName, Match: "angular.js", Weight: 0.9},
			},
		},
		{
			// svelte.min.js bundles and Svelte's scoped-class hashes
			// ("svelte-<hash>" inside class attributes).
			Name:     "svelte",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "svelte.min.js", Weight: 0.9},
				{Kind: IndicatorHTMLRegex, Match: `class="[^"]*svelte-[A-Za-z0-9]+`, Weight: 0.7},
			},
		},
		{
			// solid.js / solid.min.js bundles. No HTML attribute markers
			// are documented for Solid.
			Name:     "solid",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "solid.min.js", Weight: 0.9},
				{Kind: IndicatorScriptName, Match: "solid.js", Weight: 0.8},
			},
		},
		{
			// Remix's inline __remixContext / __remixManifest state and the
			// /build/ asset directory. UNCERTAIN: v2 (React Router 7) may
			// not emit the __remix* globals; /build/ is not Remix-exclusive.
			Name:     "remix",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "__remixContext", Weight: 0.6},
				{Kind: IndicatorHTMLSubstring, Match: "__remixManifest", Weight: 0.6},
				{Kind: IndicatorScriptPath, Match: "/build/", Weight: 0.4},
			},
		},
		{
			// The astro-island custom element, /_astro/ asset prefix (JS and
			// CSS), and the generator meta tag ("Astro v4.16.1").
			Name:     "astro",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "astro-island", Weight: 1.0},
				{Kind: IndicatorScriptPath, Match: "/_astro/", Weight: 0.9},
				{Kind: IndicatorCSSPath, Match: "/_astro/", Weight: 0.9},
				{Kind: IndicatorGenerator, Match: `Astro`, Weight: 0.9, Version: &VersionSpec{Pattern: `Astro\s+v?([0-9]+\.[0-9]+\.[0-9]+)`, Group: 1}},
			},
		},
		{
			// Qwik's qwik.core.js / qwikloader.js bundles and the q:version
			// / q:base attributes Qwik's optimizer emits.
			Name:     "qwik",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "qwik.core.js", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "qwikloader.js", Weight: 0.8},
				{Kind: IndicatorAttribute, Match: "q:version", Weight: 0.7},
				{Kind: IndicatorAttribute, Match: "q:base", Weight: 0.6},
			},
		},
		{
			// laravel_session and XSRF-TOKEN cookies; the csrf-token meta
			// (also used by other frameworks — low); the starter-kit
			// /api/user route; x-powered-by is NOT set by default (low).
			Name:     "laravel",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "laravel_session", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "XSRF-TOKEN", Weight: 0.7},
				{Kind: IndicatorMetaName, Match: "csrf-token", Weight: 0.3},
				{Kind: IndicatorEndpointPath, Match: "/api/user", Weight: 0.3},
				{Kind: IndicatorHeader, Match: "x-powered-by: laravel", Weight: 0.4},
			},
		},
		{
			// csrftoken / sessionid cookies (Django defaults) and the
			// X-Frame-Options: DENY default of Django's security middleware.
			// Conservative: sessionid and x-frame-options are not
			// Django-exclusive (low weights).
			Name:     "django",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "csrftoken", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "sessionid", Weight: 0.5},
				{Kind: IndicatorHeader, Match: "x-frame-options: deny", Weight: 0.4},
			},
		},
		{
			// Rails' default "<app>_session_id" cookie suffix and the
			// X-Powered-By: Phusion Passenger header.
			Name:     "rails",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "_session_id", Weight: 0.6},
				{Kind: IndicatorHeader, Match: "x-powered-by: phusion", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-runtime", Weight: 0.4},
			},
		},
		{
			// JSESSIONID is the Java servlet standard (not Spring-only);
			// "Whitelabel Error Page" is Spring Boot's default error page.
			Name:     "spring",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "JSESSIONID", Weight: 0.4},
				{Kind: IndicatorHTMLSubstring, Match: "Whitelabel Error Page", Weight: 0.7},
			},
		},
		{
			// x-aspnet-version (value is the version), __VIEWSTATE (WebForms
			// marker), and the default X-Powered-By: ASP.NET header.
			Name:     "asp.net",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-aspnet-version", Weight: 0.9, Version: &VersionSpec{Pattern: `([0-9]+\.[0-9]+(?:\.[0-9]+)*)`, Group: 1}},
				{Kind: IndicatorHTMLSubstring, Match: "__VIEWSTATE", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-powered-by: asp.net", Weight: 0.8},
			},
		},
		{
			// The default X-Powered-By: Express header and the connect.sid
			// cookie of express-session.
			Name:     "express",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: express", Weight: 0.8},
				{Kind: IndicatorCookie, Match: "connect.sid", Weight: 0.8},
			},
		},
		{
			// NestJS's default exception filter emits the JSON envelope
			// {"statusCode":N,"message":"...","error":"..."} while Express's
			// default error handler emits HTML. UNCERTAIN: shape is
			// Express-compatible; low weight.
			Name:     "nestjs",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLRegex, Match: `\{"statusCode":\d+,"message":"[^"]*","error":"[^"]*"\}`, Weight: 0.4},
			},
		},
		{
			// FastAPI's default /docs page title ("FastAPI - Swagger UI")
			// and its default /docs, /redoc, /openapi.json mount points
			// (shared with the openapi fingerprint — low).
			Name:     "fastapi",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "FastAPI - Swagger UI", Weight: 0.7},
				{Kind: IndicatorEndpointPath, Match: "/docs", Weight: 0.4},
				{Kind: IndicatorEndpointPath, Match: "/redoc", Weight: 0.4},
				{Kind: IndicatorEndpointPath, Match: "/openapi.json", Weight: 0.5},
			},
		},
		{
			// Flask's default session cookie is literally named "session"
			// (generic — low) and its default dev server sends
			// "Server: Werkzeug" (dev only — low-ish).
			Name:     "flask",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: werkzeug", Weight: 0.6},
				{Kind: IndicatorCookie, Match: "session", Weight: 0.5},
			},
		},
		{
			// Phoenix's phx_session cookie and LiveView's phx-* attributes
			// and /live/websocket socket path.
			Name:     "phoenix",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "phx_session", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "phx-update", Weight: 0.7},
				{Kind: IndicatorHTMLSubstring, Match: "phx-socket", Weight: 0.7},
				{Kind: IndicatorEndpointPath, Match: "/live/websocket", Weight: 0.6},
			},
		},
		{
			// UNCERTAIN: Gin sets no default marker. x-powered-by: gin fires
			// only on explicit deployments. Kept for spec coverage at low
			// weight; confidence scoring must not trust it.
			Name:     "gin",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: gin", Weight: 0.3},
			},
		},
		{
			// Fiber sets X-Powered-By: Fiber by default (documented Fiber
			// behavior).
			Name:     "fiber",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: fiber", Weight: 0.8},
			},
		},
		{
			// Echo sets X-Powered-By: Echo by default (documented Echo
			// behavior).
			Name:     "echo",
			Category: asset.CategoryFramework,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-powered-by: echo", Weight: 0.8},
			},
		},
	}
}
