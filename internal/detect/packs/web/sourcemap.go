package web

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func sourcemapExposedDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["web.sourcemap.disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, js := range dctx.JavaScript {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uStr := strings.ToLower(js.URL.String())
		path := strings.ToLower(js.URL.Path)
		disc := strings.ToLower(js.DiscoverySource)
		ct := strings.ToLower(js.ContentType)
		isMap := strings.HasSuffix(path, ".map") || strings.Contains(uStr, ".map") || disc == "sourcemap" || strings.Contains(ct, "sourcemap") || strings.Contains(uStr, "sourcemap")
		if isMap {
			id := js.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	for _, ev := range dctx.Evidence {
		if ev.Method == asset.MethodSourceMap {
			src := ev.Source
			if src.IsZero() {
				continue
			}
			if _, ok := seen[src]; !ok {
				seen[src] = struct{}{}
				subjects = append(subjects, src)
			}
		}
		ind := strings.ToLower(ev.Indicator)
		if strings.Contains(ind, "sourcemap") {
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
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	var out []asset.Finding
	for _, s := range subjects {
		if len(out) >= 256 {
			break
		}
		f, err := webFinding(dctx, ruleSourceMapExposed, "Source Map Exposed", detect.CategoryInformation, s, nil, map[string]string{"signal": "sourcemap_exposed"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleSourceMapExposed)
	_ = strings.Join(sortedKeys(dctx.Config), ",")
	return out, nil
}
