package apis

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func openapiExposedDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleOpenAPIExposed+".disabled"] == "true" {
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
		if isOpenAPIDocPath(lowPath, lowURL) {
			id := ep.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "openapi") || strings.Contains(ind, "swagger") || strings.Contains(ind, "api-docs") ||
			strings.Contains(val, "openapi") || strings.Contains(val, "swagger") || strings.Contains(val, "api-docs") {
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
	for _, t := range dctx.Technologies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToLower(t.Name), "openapi") || strings.Contains(strings.ToLower(t.Name), "swagger") {
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
		f, err := apisFinding(dctx, ruleOpenAPIExposed, "OpenAPI Exposed", detect.CategoryInformation, s, nil, map[string]string{"signal": "openapi_exposed"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleOpenAPIExposed)
	return out, nil
}

func isOpenAPIDocPath(path, urlStr string) bool {
	if strings.Contains(path, "openapi.json") || strings.Contains(path, "openapi.yaml") || strings.Contains(path, "openapi.yml") {
		return true
	}
	if strings.Contains(path, "swagger.json") || strings.Contains(path, "swagger.yaml") || strings.Contains(path, "swagger.yml") {
		return true
	}
	if strings.Contains(path, "api-docs") {
		return true
	}
	if strings.Contains(urlStr, "openapi.json") || strings.Contains(urlStr, "swagger.json") || strings.Contains(urlStr, "api-docs") {
		return true
	}
	return false
}
