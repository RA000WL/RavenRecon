package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// cdnTable returns the CDN and WAF fingerprints.
//
// Canonical category rule: CDNs live under CategoryCDN; WAF products under
// CategoryWAF. Cloudflare appears twice: the "cloudflare" entry (cdn) covers
// the proxy/CDN markers, and "cloudflare waf" (waf) covers the challenge and
// mitigation markers — see the cross-reference there.
func cdnTable() []Fingerprint {
	return []Fingerprint{
		{
			// cf-ray is Cloudflare's most distinctive header; __cf_bm is its
			// bot-management cookie; server: cloudflare and cf-cache-status
			// confirm the proxy layer. TLSALPN h3 is offered by Cloudflare
			// but not exclusive (low); CNAME targets under cloudflare.net
			// are common for proxied zones (low-ish).
			Name:     "cloudflare",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "cf-ray", Weight: 1.0},
				{Kind: IndicatorHeader, Match: "server: cloudflare", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "__cf_bm", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "cf-cache-status", Weight: 0.9},
				{Kind: IndicatorTLSALPN, Match: "h3", Weight: 0.3},
				{Kind: IndicatorDNSCNAME, Match: "cloudflare.net", Weight: 0.5},
			},
		},
		{
			// The WAF/challenge layer of Cloudflare: cf-mitigated headers on
			// mitigated responses and the challenge/block page markers.
			// Cross-ref: cf-ray and the other proxy markers belong to the
			// "cloudflare" (cdn) entry.
			Name:     "cloudflare waf",
			Category: asset.CategoryWAF,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "cf-mitigated", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "cf-error-details", Weight: 0.8},
				{Kind: IndicatorHTMLSubstring, Match: "cf-chl", Weight: 0.7},
			},
		},
		{
			// Akamai's x-akamai-* header family, the ak_bmsc bot-manager
			// cookie, and CNAME targets under akamaized.net.
			Name:     "akamai",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-akamai", Weight: 0.8},
				{Kind: IndicatorCookie, Match: "ak_bmsc", Weight: 0.9},
				{Kind: IndicatorDNSCNAME, Match: "akamaized.net", Weight: 0.7},
			},
		},
		{
			// Fastly's x-served-by / x-timer / x-fastly-request-id headers.
			// Fastly is Varnish-based, so via: varnish also fires (cross-ref
			// the varnish entry).
			Name:     "fastly",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-served-by", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-timer", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-fastly-request-id", Weight: 0.8},
			},
		},
		{
			// CloudFront's x-amz-cf-id and X-Cache: Hit from cloudfront
			// headers.
			Name:     "cloudfront",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-amz-cf-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-cache: cloudfront", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "via: cloudfront", Weight: 0.5},
			},
		},
		{
			// Bunny CDN's x-bunny-* header family (edge location, bucket
			// region); shared with Bunny Storage.
			Name:     "bunny",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-bunny", Weight: 0.8},
			},
		},
		{
			// Azure Front Door's x-azure-ref header, Via: Azure, and CNAME
			// targets under azurefd.net. Cross-ref the azure (cloud
			// provider) entry.
			Name:     "azure front door",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-azure-ref", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "via: azure", Weight: 0.5},
				{Kind: IndicatorDNSCNAME, Match: "azurefd.net", Weight: 0.7},
			},
		},
		{
			// Google's GFE/CDN layer: x-goog-gfe-request-id, Server: gfe,
			// and certificates issued by Google Trust Services (cross-ref
			// the google cloud entry).
			Name:     "google cdn",
			Category: asset.CategoryCDN,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-goog-gfe-request-id", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "server: gfe", Weight: 0.7},
				{Kind: IndicatorTLSIssuer, Match: "google trust services", Weight: 0.5},
			},
		},
		{
			// Imperva's x-iinfo header and X-CDN: Imperva.
			Name:     "imperva",
			Category: asset.CategoryWAF,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-iinfo", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "x-cdn: imperva", Weight: 0.8},
			},
		},
		{
			// Sucuri's x-sucuri-id header and its cloudproxy Server banner
			// ("Sucuri/Cloudproxy").
			Name:     "sucuri",
			Category: asset.CategoryWAF,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-sucuri-id", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "server: sucuri", Weight: 0.8},
			},
		},
		{
			// Incapsula's incap_ses_ and visid_incap_ session cookies.
			Name:     "incapsula",
			Category: asset.CategoryWAF,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "incap_ses_", Weight: 0.9},
				{Kind: IndicatorCookie, Match: "visid_incap_", Weight: 0.9},
			},
		},
		{
			// F5 BIG-IP's BIGipServer<pool> cookie, present on F5 load
			// balancers and WAF (ASM) deployments alike.
			Name:     "f5",
			Category: asset.CategoryWAF,
			Indicators: []Indicator{
				{Kind: IndicatorCookie, Match: "BIGipServer", Weight: 0.9},
			},
		},
	}
}
