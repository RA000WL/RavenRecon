package web

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func robotsExposedDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["web.robots.disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uStr := strings.ToLower(ep.URL.String())
		path := strings.ToLower(ep.URL.Path)
		if strings.EqualFold(path, "/robots.txt") || strings.HasSuffix(uStr, "/robots.txt") {
			id := ep.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	for _, ev := range dctx.Evidence {
		ind := strings.ToLower(ev.Indicator)
		val := strings.ToLower(ev.Value)
		if strings.Contains(ind, "robots") || strings.Contains(val, "robots.txt") {
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
		if strings.Contains(strings.ToLower(t.Name), "robots") {
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
		if len(out) >= 256 {
			break
		}
		f, err := webFinding(dctx, ruleRobotsExposed, "Robots Exposed", detect.CategoryInformation, s, nil, map[string]string{"signal": "robots_exposed"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleRobotsExposed)
	_ = strings.Join(sortedKeys(dctx.Config), ",")
	return out, nil
}
