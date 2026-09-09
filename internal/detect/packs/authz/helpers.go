package authz

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// authzFinding builds one canonical authz-pack finding. Subject must be an
// observed endpoint; evidence is a MethodDetection record on the subject
// with provenance Source "authz". Category is authorization, status open,
// timestamps from the injected Clock for determinism. Priority and
// confidence follow the medium/info split: reflection-backed divergent pairs
// carry medium/0.7, name-only pairs info/0.5 — never high, never a severity
// or exploitability claim (AGENTS §0.1). Rule 2 (authz.idor.path-object) is
// the fixed-info exception: the apis restidor signal carries no
// reflection_backed-equivalent marker to split on, so it always passes
// info/0.5 here. Truncation rides the completed+metadata carve-out
// (subjects_dropped + truncated metadata on every retained finding plus a
// LevelWarn log, via capSubjects) — the intended contract per AGENTS §0.6,
// never silent and never a second Finding.Truncated write path.
func authzFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, priority detect.FindingPriority, confidence float64, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "authz pack signal: "+ruleID, subject, asset.Provenance{Source: "authz"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryAuthorization.String(),
		Subject:    subject,
		Confidence: confidence,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   priority.String(),
		Status:     detect.StatusOpen.String(),
		Created:    dctx.Clock.Now().UTC(),
	})
}

// sortedKeys returns map keys in deterministic sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}

// capSubjects retains at most 256 subjects under the NEW-135 score-ordered
// truncation contract: score descending, then subject identity ascending
// (single-detector invocation, so the rule is fixed; nil scorer ⇒ pure
// identity order, byte-identical to the pre-NEW-135 prefix cut). It returns the
// kept subjects and the dropped count (0 when under the bound); callers
// surface a nonzero dropped via subjects_dropped + truncated metadata on
// every retained finding and a LevelWarn log — never silent.
func capSubjects(subjects []asset.Identity, scoreFor func(asset.Identity) float64) (kept []asset.Identity, dropped int) {
	sort.Slice(subjects, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if scoreFor != nil {
			si, sj = scoreFor(subjects[i]), scoreFor(subjects[j])
		}
		if si != sj {
			return si > sj
		}
		return subjects[i].String() < subjects[j].String()
	})
	if len(subjects) > 256 {
		return subjects[:256], len(subjects) - 256
	}
	return subjects, 0
}

// extractQueryParamNames extracts lowercased param names from a canonical
// endpoint query string (already sorted, without leading ?). It mirrors the
// triage extractParamNames pattern exactly — split on &, key before =,
// percent-decode, lowercase — and is used ONLY as a containment filter over
// triage-flagged params (N4): it never introduces a param the triage priors
// did not flag, so no direct endpoint-URL mining ever feeds emission.
func extractQueryParamNames(query string) map[string]struct{} {
	if query == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, p := range strings.Split(query, "&") {
		if p == "" {
			continue
		}
		k, _, _ := strings.Cut(p, "=")
		if k == "" {
			continue
		}
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			out[k] = struct{}{}
		}
	}
	return out
}

// splitParamList parses a comma-joined triage params/all_classes metadata
// value into lowercased tokens.
func splitParamList(s string) []string {
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// hasToken reports whether the comma-joined metadata value carries tok
// (exact, lowercased) — the precedence-shadow recovery probe for the idor
// token inside all_classes.
func hasToken(csv, tok string) bool {
	for _, t := range splitParamList(csv) {
		if t == tok {
			return true
		}
	}
	return false
}

// idorSignal is one endpoint's triage-IDOR signal: the triage-flagged param
// set plus whether live reflection evidence backs any flagged param.
type idorSignal struct {
	params map[string]struct{}
	backed bool
}

// triageIDORSignals indexes PriorFindings by endpoint-subject identity. A
// prior finding is relevant when it IS the triage.idor classification, or
// when it is any triage-pack finding whose all_classes carries the idor
// token — the precedence-shadow recovery: overlap precedence (RCE > SSRF >
// LFI > IDOR > ...) reports a shared param under its primary class only, so
// an idor-shaped param shadowed by a higher class (e.g. doc/edit under
// triage.ssrf) would otherwise vanish from this rule's view. Param names
// come ONLY from the findings' params metadata; the endpoint URL is never
// mined (N4). Multiple findings for one subject union (params) and OR
// (backed), deterministically.
func triageIDORSignals(priors []asset.Finding) map[asset.Identity]*idorSignal {
	out := make(map[asset.Identity]*idorSignal)
	for _, f := range priors {
		relevant := f.RuleID == depTriageIDOR ||
			(strings.HasPrefix(f.RuleID, "triage.") && hasToken(f.Metadata["all_classes"], "idor"))
		if !relevant {
			continue
		}
		sig := out[f.Subject]
		if sig == nil {
			sig = &idorSignal{params: make(map[string]struct{})}
			out[f.Subject] = sig
		}
		for _, p := range splitParamList(f.Metadata["params"]) {
			sig.params[p] = struct{}{}
		}
		if f.Metadata["reflection_backed"] == "true" {
			sig.backed = true
		}
	}
	return out
}

// endpointHost strips the canonical HostPort to its bare hostname: bracketed
// IPv6 loses brackets (and any port), IP literals pass through canonically,
// and host[:port] loses a numeric-port suffix. Result is lowercase — the URL
// layer already canonicalizes host case, so no second normalizer is
// introduced (AGENTS §0.5).
func endpointHost(hostPort string) string {
	hp := strings.ToLower(hostPort)
	if strings.HasPrefix(hp, "[") {
		if i := strings.Index(hp, "]"); i >= 0 {
			return hp[1:i]
		}
		return strings.Trim(hp, "[]")
	}
	if addr, err := netip.ParseAddr(hp); err == nil {
		return addr.String()
	}
	if i := strings.LastIndex(hp, ":"); i >= 0 {
		if port := hp[i+1:]; port != "" {
			numeric := true
			for j := 0; j < len(port); j++ {
				if port[j] < '0' || port[j] > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				return hp[:i]
			}
		}
	}
	return hp
}

// isIPLiteral reports whether host is an IP literal (v4 or v6).
func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// baseDomain returns the naive registrable base of host: the last two
// dot-labels. This is deliberately NOT a PSL implementation (stdlib only):
// multi-label public suffixes (co.uk, github.io, ...) over-group under this
// cut — two unrelated tenants under one such suffix read as same-domain and
// may pair. That errs toward a researcher-review candidate (verdict
// candidate-surface, never a claim), and the cut is documented here, not
// hidden. IP literals have no domain and yield "".
func baseDomain(host string) string {
	if host == "" || isIPLiteral(host) {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// sameBaseDomain reports whether two bare hostnames share a non-empty naive
// base domain.
func sameBaseDomain(a, b string) bool {
	ba, bb := baseDomain(a), baseDomain(b)
	return ba != "" && ba == bb
}

// authIndicatorNames is the O2-pinned A2 indicator universe: the cookie +
// header Match forms of internal/techintel/fingerprints/auth.go's authTable,
// lowercased, sorted. Pinned 2026-09-08 — a deliberate snapshot, not a live
// import (the fingerprints package is a techintel-internal vocabulary with
// no exported table accessor): when auth.go gains forms, this list updates
// deliberately with a version bump, never silently. TLS-CN forms
// (auth0.com, okta.com, login.microsoftonline.com, ...) are an explicit cut:
// TLS evidence attributes to certificates, not to endpoint hosts, and
// bridging that attribution is out of scope — A1 technology attribution
// covers provider presence where the pipeline linked it. Cookie-flag
// indicators (cookie_flag:*) are excluded by construction (no "cookie:"
// prefix, so they never match).
var authIndicatorNames = []string{
	"__session",
	"_session_id",
	"auth0",
	"auth0_compat",
	"auth_session_id",
	"connect.sid",
	"csrftoken",
	"estsauth",
	"jsessionid",
	"keycloak_identity",
	"keycloak_session",
	"laravel_session",
	"next-auth.csrf-token",
	"next-auth.session-token",
	"okta-oauth",
	"phpsessid",
	"session",
	"sessionid",
	"x-ms-request-id",
	"xsrf-token",
}

// authIndicatorHit reports whether evidence carries an observed auth
// session marker from the pinned A2 universe: MethodCookie evidence whose
// "cookie:" indicator remainder, or MethodHeader evidence whose "header:"
// indicator remainder, contains a pinned name (case-insensitive substring —
// covering exact names, prefix forms like okta-oauth-*, and suffix forms
// like <app>_session_id uniformly). Every other method, every unprefixed
// indicator, and every foreign channel is refused, so unrelated evidence
// sharing the snapshot channel can never flip an auth side.
func authIndicatorHit(ev asset.Evidence) bool {
	var rest string
	switch ev.Method {
	case asset.MethodCookie:
		r, ok := strings.CutPrefix(strings.ToLower(ev.Indicator), "cookie:")
		if !ok {
			return false
		}
		rest = r
	case asset.MethodHeader:
		r, ok := strings.CutPrefix(strings.ToLower(ev.Indicator), "header:")
		if !ok {
			return false
		}
		rest = r
	default:
		return false
	}
	if rest == "" {
		return false
	}
	for _, n := range authIndicatorNames {
		if strings.Contains(rest, n) {
			return true
		}
	}
	return false
}

// hostAuthenticated reports the auth side of one endpoint's host through
// the ONLY graph surface the SDK exposes (Neighbors) plus channel-typed
// evidence:
//
//   - A1 (techintel category): a host_to_technology edge from the host, or
//     an endpoint_to_technology edge from the endpoint itself, whose target
//     is a technology-kind identity in the authentication category
//     ("authentication/..." identity prefix).
//   - A2 (pinned indicators): cookie/header evidence matching the pinned
//     universe, sourced at the host, the endpoint, or the endpoint's URL
//     identity (techintel sources header/cookie evidence at observed URLs).
//
// Either signal marks the side authenticated. Absence of both marks it
// unauthenticated — an absence observation over the observed corpus, never a
// claim that no auth exists (fail-open pairing simply finds no divergence).
func hostAuthenticated(dctx *detect.Context, hostID, endpointID, urlID asset.Identity) bool {
	if dctx.GraphView != nil {
		for _, rel := range dctx.GraphView.Neighbors(hostID) {
			if rel.Kind == asset.RelationshipHostToTechnology &&
				rel.To.Kind == asset.KindTechnology &&
				strings.HasPrefix(rel.To.Value, string(asset.CategoryAuthentication)+"/") {
				return true
			}
		}
		for _, rel := range dctx.GraphView.Neighbors(endpointID) {
			if rel.Kind == asset.RelationshipEndpointToTechnology &&
				rel.To.Kind == asset.KindTechnology &&
				strings.HasPrefix(rel.To.Value, string(asset.CategoryAuthentication)+"/") {
				return true
			}
		}
	}
	for _, ev := range dctx.Evidence {
		if ev.Source != hostID && ev.Source != endpointID && ev.Source != urlID {
			continue
		}
		if authIndicatorHit(ev) {
			return true
		}
	}
	return false
}

// hostIdentityOf resolves the canonical host identity for a bare hostname
// through the asset layer (AGENTS §0.5): IP literals resolve to KindIP via
// NewIP, DNS names to KindHost via NewHost — a single value never carries
// an ambiguous identity, and this constructor never re-normalizes (the
// hostname arrives already canonical from the URL layer via endpointHost).
// A value neither builder accepts yields a zero identity, which matches no
// graph path — the flow stays fail-open quiet.
func hostIdentityOf(host string) asset.Identity {
	if ip, err := asset.NewIP(host, asset.Provenance{}); err == nil {
		return ip.Identity()
	}
	if h, err := asset.NewHost(host, asset.Provenance{}); err == nil {
		return h.Identity()
	}
	return asset.Identity{}
}
