// Package examples is RavenRecon's example detection rule pack (see doc.go
// for the pack documentation, the rule-by-rule matrix, and the usage
// sketch). This file is the pack itself: six mechanical demonstration rules
// expressed entirely on the exported detection SDK surface.
package examples

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// requiredAPIMajor and requiredAPIMinor are the SDK surface level this pack
// was compiled against. Rules verifies the level through CheckAPIVersion
// before any rule is handed out: a major mismatch means the pack must be
// recompiled, and a too-new required minor means this build predates the
// pack. The check runs on every call, so a load always validates the level.
const (
	requiredAPIMajor = 1
	requiredAPIMinor = 0
)

// Pack rule IDs. The "example." prefix and the information/discovery
// categories are the pack's content policy: mechanical demonstrations only,
// never vulnerability detections.
const (
	ruleAssetsCensus    = "example.assets.census"
	ruleDegreeIndex     = "example.relationships.degree-index"
	ruleMethodInventory = "example.evidence.method-inventory"
	ruleTechListing     = "example.technology.version-listing"
	ruleEndpointCover   = "example.endpoints.url-coverage"
	ruleAuditSummary    = "example.config.audit-summary"
)

// Rules returns the pack's six mechanical demonstration rules. The API
// compatibility check runs first, so an incompatible SDK level surfaces as
// a load-time error before any rule is registered. Every returned rule
// passes detect.ValidateRule, and the whole pack passes a registry's
// Register + Validate (the dependency pair is what Validate checks as a
// graph).
func Rules() ([]detect.Rule, error) {
	if err := detect.CheckAPIVersion(requiredAPIMajor, requiredAPIMinor); err != nil {
		return nil, fmt.Errorf("examples: %w", err)
	}

	rules := []detect.Rule{
		newRule(ruleAssetsCensus, "Asset Census",
			"Mechanically counts the corpus assets per asset kind and reports one informational finding per kind present. Demonstrates the assets input domain; the counts are pure corpus statistics, never security signals.",
			detect.CategoryDiscovery,
			[]detect.RuleInput{detect.InputAssets},
			assetCensusDetector, "1.0.0"),
		newRule(ruleDegreeIndex, "Relationship Degree Index",
			"Mechanically computes the in/out degree of every asset that participates in a relationship edge and reports one informational finding per node — degree findings are emitted only for nodes present in the observed corpus, because a relationship edge is validated for canonical form only and its endpoints may legally cite identities the snapshot never observed (the pack's second observed-corpus demonstration after endpoint-coverage). Demonstrates the relationships input domain and dependency-ordered scheduling: this rule declares the census rule as a dependency, and Registry.Validate accepts the pair as a graph.",
			detect.CategoryDiscovery,
			[]detect.RuleInput{detect.InputRelationships, detect.InputAssets},
			degreeIndexDetector, "1.0.1",
			ruleAssetsCensus), // dependency declared by rule ID, never by slice index
		newRule(ruleMethodInventory, "Evidence Method Inventory",
			"Mechanically groups the corpus evidence records by detection method and reports one informational finding per method present. Demonstrates the evidence input domain.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputEvidence},
			methodInventoryDetector, "1.0.0"),
		newRule(ruleTechListing, "Technology Version Listing",
			"Mechanically lists every technology observation with its category and observed version. Demonstrates the technology input domain and RequiredAssetTypes: the rule executes only when the corpus carries at least one technology asset, otherwise the engine skips it with an honest reason.",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputTechnology},
			technologyListingDetector, "1.0.0"),
		newRule(ruleEndpointCover, "Endpoint URL Coverage",
			"Mechanically reports one informational finding per observed endpoint, citing the endpoint's URL as a related asset when the corpus observed it. Demonstrates the endpoints input domain, finding evidence records, and the observed-corpus rule: a finding can never cite an asset the snapshot never produced.",
			detect.CategoryDiscovery,
			[]detect.RuleInput{detect.InputEndpoints},
			endpointCoverageDetector, "1.0.0"),
		newRule(ruleAuditSummary, "Config-Driven Audit Summary",
			"Mechanically summarizes the corpus secret candidates and script assets through the Context configuration and the Logger, and produces NO findings: a demonstration of the secrets and javascript input domains, the config map, the logging seam, and the empty-output path (an empty rule output is a valid, cacheable outcome).",
			detect.CategoryInformation,
			[]detect.RuleInput{detect.InputSecrets, detect.InputJavaScript},
			auditSummaryDetector, "1.0.0"),
	}

	// RequiredAssetTypes: these rules run only when their input kinds are
	// present in the corpus; otherwise the engine skips them with an honest
	// reason instead of executing them against nothing.
	rules[3].RequiredAssetTypes = []asset.Kind{asset.KindTechnology}
	rules[4].RequiredAssetTypes = []asset.Kind{asset.KindEndpoint}
	rules[5].RequiredAssetTypes = []asset.Kind{asset.KindJavaScript, asset.KindSecretCandidate}

	return rules, nil
}

// newRule fills the shared metadata every pack rule carries; the version,
// the detector, and the optional dependency rule IDs (declared by ID
// constant at the call site, never by slice index) are the only varying
// parts. Every field of the returned rule is complete, so each rule passes
// detect.ValidateRule unchanged.
func newRule(id, name, description string, category detect.Category, inputs []detect.RuleInput, det detect.Detector, version string, deps ...string) detect.Rule {
	return detect.Rule{
		ID:            id,
		Name:          name,
		Description:   description,
		Category:      category,
		Version:       version,
		Inputs:        inputs,
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Dependencies:  deps,
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "RavenRecon SDK examples",
		Enabled:       true,
		Detector:      det,
	}
}

// demoFinding builds one canonical mechanical finding: the subject is the
// asset the finding is about, the evidence record is a MethodDetection
// record observed on that same asset (the source must be an observed
// identity), and any related assets must also be observed — the engine
// rejects findings that cite assets the snapshot never produced. The
// creation time comes from the Context's injected Clock so reports stay
// deterministic under a fixed clock.
func demoFinding(dctx *detect.Context, ruleID, ruleName string, category detect.Category, subject asset.Identity, related []asset.Identity, metadata map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID,
		"mechanical demonstration signal", subject, asset.Provenance{Source: "examples"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:        ruleID,
		RuleName:      ruleName,
		Category:      category.String(),
		Subject:       subject,
		Confidence:    0.9,
		Evidence:      []asset.Evidence{ev},
		RelatedAssets: related,
		Metadata:      metadata,
		Priority:      detect.PriorityInfo.String(),
		Status:        detect.StatusOpen.String(),
		Created:       dctx.Clock.Now().UTC(),
	})
}

// assetCensusDetector counts the corpus assets per kind and emits one
// informational finding per kind present. Iteration is deterministic: the
// Context's Assets are already identity-sorted, and the kinds are emitted in
// sorted order.
func assetCensusDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type census struct {
		count    int
		first    asset.Identity
		firstSet bool
	}
	byKind := make(map[asset.Kind]*census)
	var kinds []asset.Kind
	for _, id := range dctx.Assets {
		c, ok := byKind[id.Kind]
		if !ok {
			c = &census{}
			byKind[id.Kind] = c
			kinds = append(kinds, id.Kind)
		}
		c.count++
		if !c.firstSet {
			c.first, c.firstSet = id, true
		}
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	var out []asset.Finding
	for _, k := range kinds {
		c := byKind[k]
		f, err := demoFinding(dctx, ruleAssetsCensus, "Asset Census", detect.CategoryDiscovery, c.first, nil,
			map[string]string{"kind": string(k), "count": strconv.Itoa(c.count)})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// degreeIndexDetector computes the in/out degree of every asset that
// participates in a relationship edge and emits one informational finding
// per node. A relationship edge is validated for canonical form only, so its
// endpoints may legally cite identities the corpus never observed — and the
// engine rejects any finding whose subject (or evidence source) was not
// observed. The observed set is therefore rebuilt from the Context's own
// observed collections — the exact identities the engine validates findings
// against — and degree findings are emitted ONLY for nodes present in the
// observed corpus: unobserved nodes are skipped. This is the pack's second
// observed-corpus demonstration (endpointCoverageDetector guards its related
// assets the same way). The emitted nodes are in sorted identity order, so
// the output is a deterministic function of the corpus.
func degreeIndexDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	in := make(map[asset.Identity]int)
	out := make(map[asset.Identity]int)
	nodes := make(map[asset.Identity]struct{})
	for _, rel := range dctx.Relationships { // ID-sorted, deduplicated
		in[rel.To]++
		out[rel.From]++
		nodes[rel.From] = struct{}{}
		nodes[rel.To] = struct{}{}
	}
	observed := make(map[asset.Identity]struct{})
	for _, id := range dctx.Assets {
		observed[id] = struct{}{}
	}
	for _, ev := range dctx.Evidence { // identity-sorted, merged
		observed[ev.Identity()] = struct{}{}
		if !ev.Source.IsZero() {
			observed[ev.Source] = struct{}{}
		}
	}
	for _, tech := range dctx.Technologies { // identity-sorted, merged
		observed[tech.Identity()] = struct{}{}
	}
	for _, sec := range dctx.Secrets { // identity-sorted, merged
		observed[sec.Identity()] = struct{}{}
	}
	for _, js := range dctx.JavaScript { // identity-sorted, merged
		observed[js.Identity()] = struct{}{}
	}
	for _, ep := range dctx.Endpoints { // identity-sorted, merged
		observed[ep.Identity()] = struct{}{}
	}
	order := make([]asset.Identity, 0, len(nodes))
	for id := range nodes {
		if _, ok := observed[id]; !ok {
			continue // legal relationship endpoint the corpus never observed
		}
		order = append(order, id)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })
	var findings []asset.Finding
	for _, node := range order {
		f, err := demoFinding(dctx, ruleDegreeIndex, "Relationship Degree Index", detect.CategoryDiscovery, node, nil,
			map[string]string{"in_degree": strconv.Itoa(in[node]), "out_degree": strconv.Itoa(out[node])})
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// methodInventoryDetector groups the corpus evidence records by detection
// method and emits one informational finding per method present. The subject
// is the first evidence record of the group (an observed identity); the
// groups are emitted in sorted method order.
func methodInventoryDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type group struct {
		count    int
		first    asset.Evidence
		firstSet bool
	}
	byMethod := make(map[asset.DetectionMethod]*group)
	var methods []asset.DetectionMethod
	for _, ev := range dctx.Evidence { // identity-sorted, merged
		g, ok := byMethod[ev.Method]
		if !ok {
			g = &group{}
			byMethod[ev.Method] = g
			methods = append(methods, ev.Method)
		}
		g.count++
		if !g.firstSet {
			g.first, g.firstSet = ev, true
		}
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i] < methods[j] })
	var out []asset.Finding
	for _, m := range methods {
		g := byMethod[m]
		f, err := demoFinding(dctx, ruleMethodInventory, "Evidence Method Inventory", detect.CategoryInformation,
			g.first.Identity(), nil, map[string]string{"method": m.String(), "count": strconv.Itoa(g.count)})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// technologyListingDetector emits one informational finding per observed
// technology, carrying the canonical name, category, and observed version
// (when present) as metadata.
func technologyListingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []asset.Finding
	for _, tech := range dctx.Technologies { // identity-sorted, merged
		meta := map[string]string{
			"technology": tech.Name,
			"category":   tech.Category.String(),
		}
		if tech.Version != "" {
			meta["version"] = tech.Version
		}
		f, err := demoFinding(dctx, ruleTechListing, "Technology Version Listing", detect.CategoryInformation,
			tech.Identity(), nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// endpointCoverageDetector emits one informational finding per observed
// endpoint. The finding cites the endpoint's URL as a related asset ONLY
// when the corpus observed that URL: the engine validates every related
// asset against the observed set, so citing an unobserved URL would fail the
// rule. The omission is the demonstration of the observed-corpus rule.
func endpointCoverageDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observed := make(map[asset.Identity]struct{}, len(dctx.Assets))
	for _, id := range dctx.Assets {
		observed[id] = struct{}{}
	}
	var out []asset.Finding
	for _, ep := range dctx.Endpoints { // identity-sorted, merged
		var related []asset.Identity
		if _, ok := observed[ep.URL.Identity()]; ok {
			related = append(related, ep.URL.Identity())
		}
		f, err := demoFinding(dctx, ruleEndpointCover, "Endpoint URL Coverage", detect.CategoryDiscovery,
			ep.Identity(), related, map[string]string{"method": ep.Method})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// auditSummaryDetector reads the Context configuration and writes through
// the Context Logger, then returns NO findings: the empty-output path. The
// summary counts are emitted in sorted type order, so the log lines are a
// deterministic function of the corpus and the configuration.
//
// Config keys:
//
//	example.audit_detail: when "true", one info line per secret type is
//	logged in addition to the summary line.
func auditSummaryDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	detail := dctx.Config["example.audit_detail"] == "true"
	byType := make(map[asset.SecretType]int)
	var types []asset.SecretType
	for _, sec := range dctx.Secrets { // identity-sorted, merged
		if _, ok := byType[sec.Type]; !ok {
			types = append(types, sec.Type)
		}
		byType[sec.Type]++
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	dctx.Logger.Log(detect.LevelInfo, ruleAuditSummary, fmt.Sprintf(
		"secret candidates: %d; types: %d; script assets: %d",
		len(dctx.Secrets), len(types), len(dctx.JavaScript)))
	if detail {
		for _, t := range types {
			dctx.Logger.Log(detect.LevelInfo, ruleAuditSummary,
				fmt.Sprintf("secret type %s: %d", t.String(), byType[t]))
		}
	}
	return nil, nil // an empty rule output is a valid, cacheable outcome
}
