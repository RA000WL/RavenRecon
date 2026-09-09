package web

import (
	"context"
	"fmt"
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
		// Typed carriers only (NEW-108): both sides must name robots.txt
		// itself. A bare "robots" substring anywhere in the indicator (the
		// old left operand) fired on unrelated observations — e.g. an
		// indicator or value mentioning a "robots meta tag" — and dragged
		// its source into this informational finding.
		if strings.Contains(ind, "robots.txt") || strings.Contains(val, "robots.txt") {
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
		// Same typed-carrier bar as the evidence loop (NEW-108): the name
		// must reference robots.txt itself, so crawler/security products
		// merely containing "robots" in their name never fire here.
		if strings.Contains(strings.ToLower(t.Name), "robots.txt") {
			id := t.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "robots_exposed"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := webFinding(dctx, ruleRobotsExposed, "Robots Exposed", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleRobotsExposed, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleRobotsExposed)
	return out, nil
}
