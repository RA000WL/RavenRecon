// Secret candidate extraction from parsed string/template literals.
//
// Phase 7 extracts CANDIDATES ONLY: no verification against a live service,
// no severity, no context, and no exploitation is ever represented. A later
// phase verifies candidates. Every candidate is a regex-family match bounded
// by the asset layer's own 512-byte stored-value cap; deduplication is per
// file by (type, value), and the per-file retention is bounded by
// MaxSecretsPerFile.
package jsintel

import (
	"regexp"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// privateKeyMaterialBytes bounds how much key material follows a private key
// BEGIN marker in the candidate value: the value is the marker plus up to
// this many following bytes. The asset layer's 512-byte stored-value cap
// then bounds the candidate as usual.
const privateKeyMaterialBytes = 256

// Package-level compiled secret family regexes. They are engine-owned,
// compiled once at init, deterministic, and NEVER derived from user input.
var (
	jwtRe        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	awsRe        = regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)
	googleRe     = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	firebaseRe   = regexp.MustCompile(`https://[a-z0-9-]+\.(?:firebaseio|firebaseapp)\.com`)
	stripeRe     = regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}`)
	githubRe     = regexp.MustCompile(`ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{20,}|gh[ousr]_[0-9A-Za-z]{36}`)
	bearerRe     = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}`)
	privateKeyRe = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
)

// secretFamily binds one regex to its SecretType.
type secretFamily struct {
	typ asset.SecretType
	re  *regexp.Regexp
}

// secretFamilies is the deterministic scan order: each family scans every
// scanned literal independently, so a literal matching several families
// (for example a bearer token whose payload is a JWT) yields one candidate
// per family.
var secretFamilies = []secretFamily{
	{asset.SecretTypeJWT, jwtRe},
	{asset.SecretTypeAWS, awsRe},
	{asset.SecretTypeGoogle, googleRe},
	{asset.SecretTypeFirebase, firebaseRe},
	{asset.SecretTypeStripe, stripeRe},
	{asset.SecretTypeGitHub, githubRe},
	{asset.SecretTypeBearer, bearerRe},
	{asset.SecretTypePrivateKey, privateKeyRe},
}

// secretExtract is the bounded secret candidate extraction of ONE parsed
// file.
type secretExtract struct {
	// secrets are the detected candidates, deduplicated by asset identity
	// in scan order and bounded by MaxSecretsPerFile.
	secrets []asset.SecretCandidate
	// edges are the javascript_to_secret_candidate edges (1:1 with
	// secrets).
	edges []asset.Relationship
	// skipped counts dynamic (${...}) template literals — partial
	// expressions that are never scanned — reported through the Malformed
	// metric.
	skipped int
	// dropped counts candidates beyond the MaxSecretsPerFile cap —
	// reported through the Skipped metric.
	dropped int
}

// extractSecrets scans every parsed string AND template literal value for
// the known secret families. Dynamic templates (value contains "${") are
// partial expressions and are skipped and counted, never scanned. For each
// match the matched text becomes the candidate value (the asset layer
// truncates to its 512-byte stored-value cap); the private key family's
// value is the BEGIN marker plus up to privateKeyMaterialBytes following
// bytes of key material. Deduplication is per file by (type, value);
// candidates beyond MaxSecretsPerFile are dropped and counted.
func extractSecrets(js asset.JavaScript, parsed Parsed, cfg Config) secretExtract {
	cfg = normalizeCaps(cfg)
	var out secretExtract
	seen := make(map[asset.Identity]struct{})
	prov := asset.Provenance{Source: cfg.Source, DiscoveredAt: cfg.Clock.Now().UTC()}

	add := func(t asset.SecretType, value string) {
		s, err := asset.NewSecretCandidate(t, value, js.Identity(), prov)
		if err != nil {
			out.skipped++
			return
		}
		if _, ok := seen[s.Identity()]; ok {
			return
		}
		if len(out.secrets) >= cfg.MaxSecretsPerFile {
			out.dropped++
			return
		}
		seen[s.Identity()] = struct{}{}
		out.secrets = append(out.secrets, s)
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToSecretCandidate, s.Identity()); err == nil {
			out.edges = append(out.edges, r)
		}
	}

	for _, lit := range parsed.Strings {
		if lit.Template && strings.Contains(lit.Value, "${") {
			out.skipped++
			continue
		}
		v := lit.Value
		for _, f := range secretFamilies {
			if f.typ == asset.SecretTypePrivateKey {
				// The value is the marker plus up to
				// privateKeyMaterialBytes following bytes.
				if loc := f.re.FindStringIndex(v); loc != nil {
					end := loc[1] + privateKeyMaterialBytes
					if end > len(v) {
						end = len(v)
					}
					add(f.typ, v[loc[0]:end])
				}
				continue
			}
			for _, loc := range f.re.FindAllStringIndex(v, -1) {
				add(f.typ, v[loc[0]:loc[1]])
			}
		}
	}
	return out
}
