package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// cmsTable returns the content management system fingerprints.
// Each entry's comment names the observable marker and any uncertainty.
func cmsTable() []Fingerprint {
	return []Fingerprint{
		{
			// WordPress's /wp-content/ asset prefix, /wp-json/ REST API, and
			// generator meta tag ("WordPress 6.4.2" — carries the version).
			Name:     "wordpress",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "/wp-content/", Weight: 0.9},
				{Kind: IndicatorEndpointPath, Match: "/wp-json/", Weight: 0.9},
				{Kind: IndicatorGenerator, Match: `WordPress`, Weight: 0.9, Version: &VersionSpec{Pattern: `WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`, Group: 1}},
			},
		},
		{
			// Drupal's generator meta tag and X-Generator header, both of
			// which carry the version ("Drupal 10 (https://www.drupal.org)").
			Name:     "drupal",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorGenerator, Match: `Drupal`, Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)drupal\s+([0-9.]+)`, Group: 1}},
				{Kind: IndicatorHeader, Match: "x-generator: drupal", Weight: 0.9, Version: &VersionSpec{Pattern: `(?i)drupal\s+([0-9.]+)`, Group: 1}},
			},
		},
		{
			// Joomla's generator meta tag ("Joomla! 5.0 - Open Source
			// Content Management" — carries the version).
			Name:     "joomla",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorGenerator, Match: `Joomla`, Weight: 0.9, Version: &VersionSpec{Pattern: `Joomla!\s*([0-9.]+)`, Group: 1}},
			},
		},
		{
			// Shopify's x-shopify-* response header family and the
			// Server: Shopify banner.
			Name:     "shopify",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-shopify", Weight: 0.9},
				{Kind: IndicatorHeader, Match: "server: shopify", Weight: 0.8},
			},
		},
		{
			// Squarespace serves "Server: Squarespace".
			Name:     "squarespace",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: squarespace", Weight: 0.9},
			},
		},
		{
			// Wix serves assets from static.wixstatic.com; x-wix-request-id
			// appears on Wix-hosted responses (uncertain — low).
			Name:     "wix",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "wixstatic.com", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-wix-request-id", Weight: 0.5},
			},
		},
		{
			// Ghost's generator meta tag ("Ghost 5.82.0" — carries the
			// version).
			Name:     "ghost",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorGenerator, Match: `Ghost`, Weight: 0.9, Version: &VersionSpec{Pattern: `Ghost\s+([0-9.]+)`, Group: 1}},
			},
		},
		{
			// Hugo's generator meta tag ("Hugo 0.128.0" — carries the
			// version).
			Name:     "hugo",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorGenerator, Match: `Hugo`, Weight: 0.9, Version: &VersionSpec{Pattern: `Hugo\s+([0-9.]+)`, Group: 1}},
			},
		},
		{
			// Gatsby's ___gatsby root element id and /page-data/ build
			// output prefix.
			Name:     "gatsby",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "___gatsby", Weight: 0.9},
				{Kind: IndicatorScriptPath, Match: "/page-data/", Weight: 0.8},
			},
		},
		{
			// Jekyll emits no generator tag by default, but GitHub Pages
			// injects one into every Jekyll build ("Jekyll v4.2.2" — carries
			// the version).
			Name:     "jekyll",
			Category: asset.CategoryCMS,
			Indicators: []Indicator{
				{Kind: IndicatorGenerator, Match: `Jekyll`, Weight: 0.7, Version: &VersionSpec{Pattern: `Jekyll\s+v?([0-9.]+)`, Group: 1}},
			},
		},
	}
}
