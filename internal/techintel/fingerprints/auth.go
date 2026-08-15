package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// authTable returns the authentication and session fingerprints.
//
// Session-cookie entries (laravel session, django session, ...) deliberately
// mirror the framework entries (laravel, django, ...): the framework entries
// are the fuller fingerprints, and the session entries are the
// evidence-only cookie markers that fire regardless of framework. Names
// differ, so both can coexist.
func authTable() []Fingerprint {
	return []Fingerprint{
		{
			// Auth0's auth0 / auth0_compat session cookies on the universal
			// login flow, and hosted tenants under *.auth0.com.
			Name:     "auth0",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "auth0", Weight: 0.8},
				{Kind: IndicatorCookie, Match: "auth0_compat", Weight: 0.7},
				{Kind: IndicatorTLSCN, Match: "auth0.com", Weight: 0.5},
			},
		},
		{
			// Firebase Hosting certificates under firebaseapp.com / web.app
			// and Firebase's documented __session cookie.
			Name:     "firebase",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "firebaseapp.com", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "web.app", Weight: 0.6},
				{Kind: IndicatorCookie, Match: "__session", Weight: 0.6},
			},
		},
		{
			// Okta sign-in widget cookies (okta-oauth-*) and hosted tenants
			// under *.okta.com.
			Name:     "okta",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "okta-oauth", Weight: 0.8},
				{Kind: IndicatorTLSCN, Match: "okta.com", Weight: 0.6},
			},
		},
		{
			// Cognito hosted-UI domains under amazoncognito.com and the
			// cognito-idp.<region>.amazonaws.com API endpoints (cross-ref
			// the aws cloud entry).
			Name:     "aws cognito",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "amazoncognito.com", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "cognito-idp", Weight: 0.8},
			},
		},
		{
			// Azure AD's login.microsoftonline.com endpoints, the ESTSAUTH
			// cookie, and x-ms-request-id (cross-ref the azure entry; low).
			Name:     "azure ad",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "login.microsoftonline.com", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "ESTSAUTH", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-ms-request-id", Weight: 0.3},
			},
		},
		{
			// Keycloak's KEYCLOAK_IDENTITY / KEYCLOAK_SESSION cookies and
			// the AUTH_SESSION_ID cookie.
			Name:     "keycloak",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "KEYCLOAK_IDENTITY", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "KEYCLOAK_SESSION", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "AUTH_SESSION_ID", Weight: 0.7},
			},
		},
		{
			// NextAuth's default cookies (also emitted under the
			// __Secure-next-auth.* secure variants).
			Name:     "nextauth",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "next-auth.session-token", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "next-auth.csrf-token", Weight: 0.8},
			},
		},
		{
			// The session-cookie evidence for Laravel; cross-ref the laravel
			// framework entry.
			Name:     "laravel session",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "laravel_session", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "XSRF-TOKEN", Weight: 0.6},
			},
		},
		{
			// The session-cookie evidence for Django; sessionid is generic
			// (low); cross-ref the django framework entry.
			Name:     "django session",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "csrftoken", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "sessionid", Weight: 0.5},
			},
		},
		{
			// Rails' "<app>_session_id" cookie suffix; cross-ref the rails
			// framework entry.
			Name:     "rails session",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "_session_id", Weight: 0.6},
			},
		},
		{
			// JSESSIONID is the Java servlet standard and SESSION is Spring
			// Boot's default cookie name; neither is Spring-exclusive (low);
			// cross-refs to the spring framework and java language entries.
			Name:     "spring session",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "JSESSIONID", Weight: 0.4},
				{Kind: IndicatorCookie, Match: "SESSION", Weight: 0.4},
			},
		},
		{
			// The connect.sid cookie of express-session; cross-ref the
			// express framework entry.
			Name:     "express session",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "connect.sid", Weight: 0.8},
			},
		},
		{
			// Generic session-flag evidence entry: PHPSESSID is the PHP
			// session cookie, but a session cookie alone is weak evidence —
			// it fires on nearly any PHP application. EVIDENCE-ONLY at low
			// weight: the engine pass gates these indicators on the observed
			// Secure / HttpOnly / SameSite cookie flags (documented here so
			// the flag gating is a later-pass engine refinement, not a data
			// change).
			Name:     "php session cookie",
			Category: asset.CategoryAuthentication,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "PHPSESSID", Weight: 0.4},
			},
		},
	}
}
