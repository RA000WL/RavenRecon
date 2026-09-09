package web

import (
	"context"
	"fmt"
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
		path := strings.ToLower(js.URL.Path)
		disc := strings.ToLower(js.DiscoverySource)
		ct := strings.ToLower(js.ContentType)
		isMap := strings.HasSuffix(path, ".map") || disc == "sourcemap" || strings.Contains(ct, "sourcemap")
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
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "sourcemap_exposed"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := webFinding(dctx, ruleSourceMapExposed, "Source Map Exposed", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleSourceMapExposed, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleSourceMapExposed)
	return out, nil
}
