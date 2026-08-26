package web

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func corsWildcardDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["web.cors.disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, ev := range dctx.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ind := strings.ToLower(ev.Indicator)
		if ind == "header:access-control-allow-origin" && ev.Value == "*" {
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
		meta := map[string]string{"signal": "cors_wildcard", "value": "*"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := webFinding(dctx, ruleCORSWildcard, "CORS Wildcard", detect.CategoryMisconfig, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleCORSWildcard, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleCORSWildcard)
	return out, nil
}
