package web

import (
	"context"
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
	var out []asset.Finding
	for _, s := range subjects {
		if len(out) >= 256 {
			break
		}
		f, err := webFinding(dctx, ruleCORSWildcard, "CORS Wildcard", detect.CategoryMisconfig, s, nil, map[string]string{"signal": "cors_wildcard", "value": "*"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleCORSWildcard)
	_ = strings.Join(sortedKeys(dctx.Config), ",")
	return out, nil
}
