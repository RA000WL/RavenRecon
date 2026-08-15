package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// buildToolTable returns the frontend build tool fingerprints.
// Each entry's comment names the observable marker and any uncertainty.
func buildToolTable() []Fingerprint {
	return []Fingerprint{
		{
			// webpackJsonp (webpack <5) and webpackChunk (webpack 5) runtime
			// globals in emitted bundles; the common /static/js/ output
			// prefix (not exclusive — low); deployed .js.map source maps.
			Name:     "webpack",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "webpackJsonp", Weight: 0.8},
				{Kind: IndicatorHTMLSubstring, Match: "webpackChunk", Weight: 0.8},
				{Kind: IndicatorScriptPath, Match: "/static/js/", Weight: 0.4},
				{Kind: IndicatorSourceMapPath, Match: ".js.map", Weight: 0.3},
			},
		},
		{
			// The Vite dev server injects /@vite/client (dev only); build
			// entries use <script type="module" crossorigin> (typical of Vite
			// builds, not exclusive — low).
			Name:     "vite",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "/@vite/", Weight: 0.9},
				{Kind: IndicatorHTMLRegex, Match: `<script[^>]*type="module"[^>]*crossorigin`, Weight: 0.4},
			},
		},
		{
			// Parcel 2 bundles expose the parcelRequire runtime.
			Name:     "parcel",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "parcelRequire", Weight: 0.7},
			},
		},
		{
			// Rollup emits /*#__PURE__*/ annotations for tree-shaking
			// (some other bundlers emit them too — low); deployed .js.map
			// source maps are also common (very low).
			Name:     "rollup",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLRegex, Match: `/\*#__PURE__\*/`, Weight: 0.4},
				{Kind: IndicatorSourceMapPath, Match: ".js.map", Weight: 0.2},
			},
		},
		{
			// UNCERTAIN: Rspack is webpack-compatible and emits the webpack
			// runtime markers (caught by the webpack entry); it has no
			// documented default marker of its own. This fires only on pages
			// that mention Rspack (dev overlays, docs links). Kept for spec
			// coverage at low weight.
			Name:     "rspack",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "rspack", Weight: 0.2},
			},
		},
		{
			// Turbopack-generated code calls __turbopack_context__ helpers;
			// visible when such scripts are inlined. UNCERTAIN: mostly dev
			// builds; low weight.
			Name:     "turbopack",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLRegex, Match: `__turbopack_context__`, Weight: 0.5},
			},
		},
		{
			// require.js bundles, require.config() calls, and the data-main
			// entry attribute.
			Name:     "requirejs",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "require.js", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "require.config", Weight: 0.8},
				{Kind: IndicatorAttribute, Match: "data-main", Weight: 0.7},
			},
		},
		{
			// system.js / system.min.js bundles and System.import() calls.
			Name:     "systemjs",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "system.js", Weight: 0.8},
				{Kind: IndicatorScriptName, Match: "system.min.js", Weight: 0.8},
				{Kind: IndicatorHTMLSubstring, Match: "System.import", Weight: 0.6},
			},
		},
		{
			// esbuild's serve() API injects its HMR client at /esbuild.
			// UNCERTAIN: dev server only; low weight.
			Name:     "esbuild",
			Category: asset.CategoryBuildTool,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "/esbuild", Weight: 0.6},
			},
		},
	}
}
