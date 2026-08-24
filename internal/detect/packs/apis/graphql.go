package apis

import (
	"context"
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
	var subjects []asset.Identity
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lowPath := strings.ToLower(ep.URL.Path)
		lowURL := strings.ToLower(ep.URL.String())
		if strings.Contains(lowPath, "/graphql") || strings.Contains(lowURL, "/graphql") {
			id := ep.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
			continue
		}
	}
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "graphql") || strings.Contains(val, "graphql") {
			if strings.Contains(ind, "introspection") || strings.Contains(val, "introspection") || strings.Contains(val, "graphql") {
				src := ev.Source
				if src.IsZero() {
					continue
				}
				if _, ok := seen[src]; !ok {
					seen[src] = struct{}{}
					subjects = append(subjects, src)
				}
			}
		}
	}
	for _, t := range dctx.Technologies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToLower(t.Name), "graphql") {
			id := t.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= 256 {
			break
		}
		f, err := apisFinding(dctx, ruleGraphQLIntrospection, "GraphQL Introspection", detect.CategoryAPI, s, nil, map[string]string{"signal": "graphql_introspection"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleGraphQLIntrospection)
	return out, nil
}
