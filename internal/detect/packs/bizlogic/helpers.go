package bizlogic

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// bizlogicFinding builds one canonical bizlogic-pack finding. Subject must
// be an observed endpoint (the flow's identity-smallest step); evidence is
// a MethodDetection record on the subject with provenance Source
// "bizlogic". Category is business_logic, priority always info, status
// open, timestamps from the injected Clock for determinism. Confidence is
// 0.5 for 2-step flows and 0.6 for 3+ steps — never medium or higher,
// never a severity or exploitability claim (AGENTS §0.1).
func bizlogicFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, confidence float64, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "bizlogic pack signal: "+ruleID, subject, asset.Provenance{Source: "bizlogic"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryBusinessLogic.String(),
		Subject:    subject,
		Confidence: confidence,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
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
// identity order, byte-identical to a prefix cut). It returns the kept
// subjects and the dropped count (0 when under the bound); callers surface
// a nonzero dropped via subjects_dropped + truncated metadata on every
// retained finding and a LevelWarn log — never silent.
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

// tokenSignal is one endpoint's T1 triage-IDOR signal: the triage-flagged
// param set for the IDOR class.
type tokenSignal struct {
	params map[string]struct{}
}

// triageTokenSignals indexes PriorFindings by endpoint-subject identity. A
// prior finding is relevant when it IS the triage.idor classification, or
// when it is any triage-pack finding whose all_classes carries the idor
// token — the precedence-shadow recovery: overlap precedence (RCE > SSRF >
// LFI > IDOR > ...) reports a shared param under its primary class only, so
// an idor-shaped param shadowed by a higher class (e.g. doc/edit under
// triage.ssrf) would otherwise vanish from this rule's view. Param names
// come ONLY from the findings' params metadata; the endpoint URL is never
// mined (N4). Multiple findings for one subject union (params),
// deterministically.
func triageTokenSignals(priors []asset.Finding) map[asset.Identity]*tokenSignal {
	out := make(map[asset.Identity]*tokenSignal)
	for _, f := range priors {
		relevant := f.RuleID == depTriageIDOR ||
			(strings.HasPrefix(f.RuleID, "triage.") && hasToken(f.Metadata["all_classes"], "idor"))
		if !relevant {
			continue
		}
		sig := out[f.Subject]
		if sig == nil {
			sig = &tokenSignal{params: make(map[string]struct{})}
			out[f.Subject] = sig
		}
		for _, p := range splitParamList(f.Metadata["params"]) {
			sig.params[p] = struct{}{}
		}
	}
	return out
}

// authzMembers returns the endpoint-subject identity set carrying an
// authz.idor.insecure-direct-object prior finding (the A1 auth-divergence
// signal). Subjects are the ONLY channel — peers ride metadata strings in
// the authz pack and never appear here, so membership is exact.
func authzMembers(priors []asset.Finding) map[asset.Identity]struct{} {
	out := make(map[asset.Identity]struct{})
	for _, f := range priors {
		if f.RuleID == depAuthzIDOR {
			out[f.Subject] = struct{}{}
		}
	}
	return out
}

// graphqlSubjects returns the endpoint-subject identity set the apis pack
// graded graphql (signal graphql_endpoint or graphql_introspection),
// read opportunistically: when the apis pack did not run there are no
// such priors and the set is empty — the path heuristic below still
// applies, so behavior stays deterministic either way.
func graphqlSubjects(priors []asset.Finding) map[asset.Identity]struct{} {
	out := make(map[asset.Identity]struct{})
	for _, f := range priors {
		if !strings.HasPrefix(f.RuleID, "api.") {
			continue
		}
		switch f.Metadata["signal"] {
		case "graphql_endpoint", "graphql_introspection":
			out[f.Subject] = struct{}{}
		}
	}
	return out
}

// robotsSubjects returns the endpoint-subject identity set the web pack
// graded robots.txt surface (signal robots_exposed), read
// opportunistically: a robots endpoint is a crawler utility surface, not a
// workflow step, so it never joins a candidate flow. When the web pack did
// not run the set is empty and nothing is excluded.
func robotsSubjects(priors []asset.Finding) map[asset.Identity]struct{} {
	out := make(map[asset.Identity]struct{})
	for _, f := range priors {
		if !strings.HasPrefix(f.RuleID, "web.") {
			continue
		}
		if f.Metadata["signal"] == "robots_exposed" {
			out[f.Subject] = struct{}{}
		}
	}
	return out
}

// isGraphQLClass reports whether an endpoint reads as GraphQL-grade: an
// apis-pack graphql signal on its subject (opportunistic), or a /graphql
// path in its canonical URL. Mixed-grade steps never form one flow — a
// GraphQL endpoint and a REST endpoint are different API styles and
// correlating them as one workflow would be unsound.
func isGraphQLClass(ep asset.Endpoint, graphqlPrior map[asset.Identity]struct{}) bool {
	if _, ok := graphqlPrior[ep.Identity()]; ok {
		return true
	}
	return strings.Contains(strings.ToLower(ep.URL.Path), "/graphql")
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
