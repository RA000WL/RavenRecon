package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// cloudTable returns the cloud platform fingerprints.
// Each entry's comment names the observable marker and any uncertainty.
func cloudTable() []Fingerprint {
	return []Fingerprint{
		{
			// x-amz-request-id on AWS API responses (also S3 — cross-ref the
			// storage s3 entry), the ELB "Server: awselb" banner, and
			// certificates under amazonaws.com (AWS-hosted vs AWS-branded:
			// low).
			Name:     "aws",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-amz-request-id", Weight: 0.7},
				{Kind: IndicatorHeader, Match: "server: awselb", Weight: 0.8},
				{Kind: IndicatorTLSCN, Match: "amazonaws.com", Weight: 0.4},
			},
		},
		{
			// App Service certificates under azurewebsites.net, cloudapp.net,
			// and x-ms-request-id (also Azure AD/Blob — cross-refs; low).
			Name:     "azure",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "azurewebsites.net", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "cloudapp.net", Weight: 0.7},
				{Kind: IndicatorHeader, Match: "x-ms-request-id", Weight: 0.4},
			},
		},
		{
			// App Engine certificates under appspot.com and API certificates
			// under googleapis.com (cross-ref the storage gcs entry).
			Name:     "google cloud",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "appspot.com", Weight: 0.9},
				{Kind: IndicatorTLSCN, Match: "googleapis.com", Weight: 0.8},
			},
		},
		{
			// Spaces endpoints under digitaloceanspaces.com — also object
			// storage (Spaces is DigitalOcean's S3-compatible product).
			Name:     "digitalocean",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorTLSCN, Match: "digitaloceanspaces.com", Weight: 0.9},
			},
		},
		{
			// Fly.io's proxy adds fly-request-id and fly-client-ip to every
			// response.
			Name:     "fly.io",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "fly-request-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "fly-client-ip", Weight: 0.7},
			},
		},
		{
			// Railway's edge adds Server: railway-hikari (and earlier
			// railway-edge) plus x-railway-request-id / x-railway-edge /
			// x-railway-fallback — all observed on live Railway apps.
			Name:     "railway",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: railway-hikari", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-railway-request-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-railway-edge", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-railway-fallback", Weight: 0.8},
			},
		},
		{
			// Render's origin proxy adds the x-render-origin-server header.
			Name:     "render",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-render-origin-server", Weight: 0.8},
			},
		},
		{
			// Heroku's router appends "Via: 1.1 vegur" (vegur is Heroku's
			// proxy) and historically x-heroku-* router headers.
			Name:     "heroku",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "via: 1.1 vegur", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-heroku", Weight: 0.6},
			},
		},
		{
			// Netlify's x-nf-request-id header, Server: Netlify banner, and
			// CNAME targets under netlify.app.
			Name:     "netlify",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-nf-request-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "server: netlify", Weight: 0.8},
				{Kind: IndicatorDNSCNAME, Match: "netlify.app", Weight: 0.6},
			},
		},
		{
			// Vercel's x-vercel-id / x-vercel-cache headers and CNAME
			// targets under cname.vercel-dns.com.
			Name:     "vercel",
			Category: asset.CategoryCloudProvider,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-vercel-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-vercel-cache", Weight: 0.8},
				{Kind: IndicatorDNSCNAME, Match: "cname.vercel-dns.com", Weight: 0.8},
			},
		},
	}
}
