package apis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func graphqlIntrospectionDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleGraphQLIntrospection+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	carrier := make(map[asset.Identity]string)
	var subjects []asset.Identity
	add := func(id asset.Identity, via string) {
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		carrier[id] = via
	}
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lowPath := strings.ToLower(ep.URL.Path)
		lowURL := strings.ToLower(ep.URL.String())
		if strings.Contains(lowPath, "/graphql") || strings.Contains(lowURL, "/graphql") {
			add(ep.Identity(), "endpoint")
		}
	}
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		hasIntrospection := strings.Contains(val, "__schema") || strings.Contains(val, "introspection") || strings.Contains(ind, "introspection") || strings.Contains(ind, "__schema")
		if hasIntrospection {
			if strings.Contains(ind, "graphql") || strings.Contains(val, "graphql") || strings.Contains(ind, "__schema") {
				src := ev.Source
				if src.IsZero() {
					continue
				}
				add(src, "introspection")
			}
		}
	}
	// Technology graphql alone is not introspection — skip per R2-M4.
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sig := "graphql_endpoint"
		if carrier[s] == "introspection" {
			sig = "graphql_introspection"
		}
		meta := map[string]string{"signal": sig}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		// Use same finder but differentiate signal; confidence lower for endpoint.
		cat := detect.CategoryAPI
		// For endpoint, informational confidence lower; but apisFinding sets 0.9 fixed.
		// Keep using apisFinding for both; signal distinguishes.
		f, err := apisFinding(dctx, ruleGraphQLIntrospection, "GraphQL Introspection", cat, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleGraphQLIntrospection, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleGraphQLIntrospection)
	return out, nil
}
