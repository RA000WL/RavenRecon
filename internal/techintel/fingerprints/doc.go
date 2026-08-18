// Package fingerprints is RavenRecon's technology fingerprint database.
//
// This package is DATA ONLY. It defines the fingerprint data model
// (IndicatorKind, Tier, Indicator, VersionSpec, Fingerprint), the category
// tables (frameworks.go, buildtools.go, servers.go, cdns.go, clouds.go,
// auth.go, apis.go, cms.go, infra.go, languages.go), their validation, and
// the compile-once compiled form (DB). Detection and matching logic — the
// "engine" — is a later pass and lives outside this package.
//
// # Schema versioning
//
// SchemaVersion versions the database SCHEMA (the data model's layout).
// Cache keys for technology detection results MUST include it: bumping
// SchemaVersion invalidates every cached detection result by construction,
// mirroring internal/cache's schema versioning. Never reuse a bumped
// version number.
//
// # Content digest
//
// DB.Digest() is a stable content digest of the database's complete
// detection data: every fingerprint's name, category, and full indicator
// payload (kind, match, weight, version spec), serialized canonically
// (fingerprints sorted by name; see DB.Digest). Cache keys for technology
// detection results MUST include it alongside SchemaVersion: a DATA-ONLY
// edit to any table — a weight, match, kind, category, or version change
// that never bumps the schema — changes the digest and therefore
// invalidates every cached detection by construction, so stale results can
// never be replayed after a table edit. SchemaVersion stays the layout
// version; the digest is the content version. The engine computes the
// digest once per run at environment construction, never per observation.
//
// # Compile-once contract
//
// Load() validates every entry and compiles every regular expression
// (regex-kind Match values and Version patterns) exactly once into the
// returned DB. The engine must NEVER compile its own regular expressions:
// it consumes the compiled DB only. MatchRe and VersionRe are the exported
// accessors exposing the compile-once store (see Indicator).
//
// # Matching contract (for the engine pass)
//
// All literal Match values are matched case-insensitively as substrings of
// the observation for their kind:
//
//	header        -> the "Name: value" header line
//	cookie        -> the cookie name
//	html_substring-> the response HTML/body text
//	html_regex    -> regex search of the response HTML/body text (Match is a regex)
//	meta_name     -> the meta tag's name attribute
//	generator     -> regex search of the generator meta content (Match is a regex)
//	script_name   -> the script resource basename
//	script_path / css_path / sourcemap_path -> the resource URL path
//	attribute     -> the attribute name
//	endpoint_path -> the request path
//	tls_issuer / tls_cn -> the certificate issuer / subject CN
//	tls_alpn      -> an ALPN protocol offered during the handshake
//	dns_cname     -> the CNAME target
//
// Version patterns are applied to the matched value AS OBSERVED, with no
// case folding; use (?i) where the marker's case varies.
//
// # Tier semantics
//
// Indicators are tiered by how trivially a server operator can fake them:
//
//	TierSpoofable  — HTTP headers, cookies, and DNS CNAMEs: any operator
//	                 can emit them, so they never outweigh structural
//	                 evidence in confidence scoring.
//	TierStructural — HTML markers, script/CSS paths, endpoints, and TLS
//	                 certificate fields: harder to fake without actually
//	                 running the technology.
//
// The tier is derived from the indicator kind (IndicatorKind.Tier), never
// stored per entry, so data cannot mislabel it.
//
// # Marker policy
//
// The tables contain REAL, documented observable markers only. No invented
// indicators. Where a technology's marker is uncertain, the entry carries an
// explicit "uncertain" comment and a LOW weight, so confidence scoring
// (a later pass) will not over-trust it.
package fingerprints
