// Import resolution and bounded expansion: the ONE shared reference
// resolver, the import graph extraction, and the expansion caps.
package jsintel

import (
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// resolveRef resolves a reference (URL, module specifier, or source map
// reference) against a base URL — the single shared resolution function.
// Every caller — parseLine (Base), parseHTML (page URL), import expansion,
// and source map normalization — goes through this same machinery.
//
// Returns:
//
//   - resolved=true, bare=false: ref is an absolute http(s) URL, a
//     protocol-relative (//host/path), root-relative (/path), or relative
//     (./x, ../x) reference that resolved to a canonical URL asset;
//   - resolved=false, bare=true: a BARE specifier — no scheme, no leading
//     "/", "//", "./", or "../" (react, @scope/pkg, lodash/fp). A bare
//     specifier has no relative meaning; the import collector treats it as
//     a third-party reference and no fetch is ever attempted;
//   - resolved=false, bare=false: an empty reference, an unsupported scheme
//     (data:, file:, javascript:, ...), or an unparseable reference.
//
// Relative references resolve against base's DIRECTORY with path.Clean
// semantics: "." segments vanish, ".." pops a segment and NEVER escapes the
// root, and "//" is preserved (matching the asset URL canonical form). The
// reference's query string is PRESERVED (re-canonicalized by the asset
// layer); a fragment in the reference is STRIPPED — fragments never reach
// the wire and must not differentiate candidates. Resolved URLs carry zero
// provenance: observation provenance is attached when the URL is actually
// fetched (the JS asset build).
func resolveRef(base asset.URL, ref string) (asset.URL, bool, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return asset.URL{}, false, false
	}
	if strings.HasPrefix(ref, "//") {
		if base.Scheme == "" {
			return asset.URL{}, false, false
		}
		return parseAbs(base.Scheme + ":" + ref)
	}
	if strings.HasPrefix(ref, "/") {
		if base.Scheme == "" || base.HostPort == "" {
			return asset.URL{}, false, false
		}
		return parseAbs(base.Scheme + "://" + base.HostPort + ref)
	}
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		if base.Scheme == "" || base.HostPort == "" {
			return asset.URL{}, false, false
		}
		u, ok := resolveRelative(base, ref)
		return u, ok, false
	}
	if scheme, rest, ok := strings.Cut(ref, ":"); ok && scheme != "" && !strings.Contains(scheme, "/") {
		if (strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")) && strings.HasPrefix(rest, "//") {
			return parseAbs(ref)
		}
		// A scheme'd reference that is not an http(s) URL: data:, file:,
		// javascript:, and friends are unsupported — never resolved, never
		// bare.
		return asset.URL{}, false, false
	}
	// No scheme and no relative prefix: a bare specifier.
	return asset.URL{}, false, true
}

// resolveImport is the import-expansion alias of resolveRef: an import
// specifier resolves exactly like any other reference, with the same bare
// and unsupported-scheme outcomes. Kept as a distinct, documented name so
// call sites read as intent.
func resolveImport(importer asset.URL, spec string) (asset.URL, bool, bool) {
	return resolveRef(importer, spec)
}

// resolveHTMLRef resolves an HTML attribute or Link-header URL against the
// page URL. HTML reference semantics differ from import specifiers in ONE
// way: a plain name (src="x.js") is a RELATIVE reference — HTML has no bare
// specifiers — so there is no bare outcome. Absolute http(s), protocol-
// relative, root-relative, and relative forms all resolve; unsupported
// schemes and unparseable references report resolved=false. A ZERO page URL
// resolves nothing — not even absolute references: no base means the
// observation is unusable.
func resolveHTMLRef(page asset.URL, ref string) (asset.URL, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || page.Scheme == "" {
		return asset.URL{}, false
	}
	if strings.HasPrefix(ref, "//") {
		if page.Scheme == "" {
			return asset.URL{}, false
		}
		u, ok, _ := parseAbs(page.Scheme + ":" + ref)
		return u, ok
	}
	if strings.HasPrefix(ref, "/") {
		if page.Scheme == "" || page.HostPort == "" {
			return asset.URL{}, false
		}
		u, ok, _ := parseAbs(page.Scheme + "://" + page.HostPort + ref)
		return u, ok
	}
	if scheme, rest, ok := strings.Cut(ref, ":"); ok && scheme != "" && !strings.Contains(scheme, "/") {
		if (strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")) && strings.HasPrefix(rest, "//") {
			u, ok, _ := parseAbs(ref)
			return u, ok
		}
		return asset.URL{}, false
	}
	if page.Scheme == "" || page.HostPort == "" {
		return asset.URL{}, false
	}
	// Relative — including plain names.
	return resolveRelative(page, ref)
}

// parseAbs canonicalizes an absolute URL string; the bare flag is always
// false (an absolute URL is never bare).
func parseAbs(raw string) (asset.URL, bool, bool) {
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		return asset.URL{}, false, false
	}
	return u, true, false
}

// resolveRelative is the shared relative-resolution core: it joins ref
// (./x, ../x, or a plain name) onto base's directory, applies root-clamped
// dot-segment cleaning, preserves the query, strips the fragment, and
// canonicalizes through the asset layer. Base must be a non-zero canonical
// URL.
func resolveRelative(base asset.URL, ref string) (asset.URL, bool) {
	pathPart := ref
	query := ""
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		pathPart = ref[:i]
		if ref[i] == '?' {
			q := ref[i+1:]
			if j := strings.IndexByte(q, '#'); j >= 0 {
				q = q[:j] // fragment stripped
			}
			query = q
		}
		// A leading '#' strips everything after it: the fragment never
		// reaches the wire and must not differentiate candidates.
	}
	dir := base.Path
	if i := strings.LastIndexByte(dir, '/'); i >= 0 {
		dir = dir[:i+1]
	} else {
		dir = "/"
	}
	cleaned := cleanPathSegments(dir + pathPart)
	raw := base.Scheme + "://" + base.HostPort + cleaned
	if query != "" {
		raw += "?" + query
	}
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		return asset.URL{}, false
	}
	return u, true
}

// cleanPathSegments applies root-clamped dot-segment resolution: "." and
// ".." segments are removed, ".." never escapes the root, and "//" is never
// collapsed (mirroring the asset layer's removeDotSegments). The empty
// path cleans to the root path "/".
func cleanPathSegments(p string) string {
	if p == "" {
		return "/"
	}
	var out []string
	if strings.HasPrefix(p, "/") {
		out = append(out, "")
		p = p[1:]
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case ".":
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return strings.Join(out, "/")
}

// importExtract is the bounded import extraction of ONE parsed file.
type importExtract struct {
	// imports are the analysis records of the RESOLVED imports in source
	// order (specifier as written, canonical URL, static/dynamic kind),
	// deduplicated by URL identity exactly like edges. They are the
	// stored-analysis payload of the D1 extraction; the cache-hit path
	// rebuilds edges and expansion candidates from them.
	imports []analysisImport
	// edges are the javascript_to_javascript edges from the importer to
	// each RESOLVED import URL, deduplicated in source order and bounded by
	// MaxImportsPerFile. Edges are recorded even when the target was never
	// fetched (depth/total caps): the graph is the honest observation.
	edges []asset.Relationship
	// external are the BARE specifiers (react, @scope/pkg, lodash/fp),
	// deduplicated, sorted, bounded by MaxImportsPerFile — the roadmap's
	// third-party library identification.
	external []string
	// resolved are the resolved import URLs in source order (1:1 with
	// edges): the engine's expansion candidates.
	resolved []asset.URL
	// dropped counts specifiers beyond the MaxImportsPerFile retention
	// cap (edges and bare alike) — reported through the Skipped metric.
	dropped int
	// skipped counts specifiers with unsupported schemes or unparseable
	// forms — reported through the Malformed metric.
	skipped int
}

// extractImports walks a parsed module's imports and produces the bounded
// import graph: resolved imports become edges (and expansion candidates),
// bare specifiers become external references, and nothing is ever resolved
// twice within one file. Dynamic imports whose specifier the parser could
// not statically resolve (Specifier "") are honest non-observations and are
// skipped silently.
//
// A resolved import whose specifier is not printable ASCII (a control
// character smuggled through an escape sequence) is skipped and counted
// malformed: the specifier enters the stored js.analyze record, whose decode
// re-validation requires printable ASCII, so a record this layer writes must
// never violate its own decode invariants (a non-printable specifier would
// otherwise be discarded and re-analyzed forever — self-healing, but a
// pathological loop on hostile input). BARE specifiers are held to the same
// contract — printable ASCII plus the maxParserStringBytes length bound —
// so the stored external list can never carry a specifier its own decode
// rejects.
func extractImports(importer asset.JavaScript, parsed Parsed, cfg Config) importExtract {
	var out importExtract
	seen := make(map[asset.Identity]struct{})
	extSeen := make(map[string]struct{})
	for _, imp := range parsed.Imports {
		if imp.Specifier == "" {
			continue
		}
		u, resolved, bare := resolveImport(importer.URL, imp.Specifier)
		if bare {
			// The bare path applies the same specifier validation as the
			// resolved path: non-printable ASCII (a control character
			// smuggled through an escape sequence) or a specifier longer
			// than maxParserStringBytes is skipped and counted malformed —
			// a bare specifier enters the stored js.analyze record, whose
			// decode re-validates both properties, so a record this layer
			// writes must never violate its own decode invariants. The
			// parser's addImport already bounds live specifiers; these
			// checks are defense for directly constructed or stored input.
			if !printableASCII(imp.Specifier) || len(imp.Specifier) > maxParserStringBytes {
				out.skipped++
				continue
			}
			if _, ok := extSeen[imp.Specifier]; ok {
				continue
			}
			extSeen[imp.Specifier] = struct{}{}
			if len(out.external) >= cfg.MaxImportsPerFile {
				out.dropped++
				continue
			}
			out.external = append(out.external, imp.Specifier)
			continue
		}
		if !resolved {
			out.skipped++
			continue
		}
		if _, ok := seen[u.Identity()]; ok {
			continue
		}
		if len(out.edges) >= cfg.MaxImportsPerFile {
			out.dropped++
			continue
		}
		if !printableASCII(imp.Specifier) {
			out.skipped++
			continue
		}
		seen[u.Identity()] = struct{}{}
		out.imports = append(out.imports, analysisImport{Specifier: imp.Specifier, URL: u, Kind: imp.Kind})
		to := asset.Identity{Kind: asset.KindJavaScript, Value: u.String()}
		if e, err := asset.NewRelationship(importer.Identity(), asset.RelationshipJavaScriptToJavaScript, to); err == nil {
			out.edges = append(out.edges, e)
		}
		out.resolved = append(out.resolved, u)
	}
	sort.Strings(out.external)
	return out
}
