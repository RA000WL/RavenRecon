package web

import (
	"context"
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func hstsMissingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["web.hsts.disabled"] == "true" {
		return nil, nil
	}
	var hosts []asset.Identity
	for _, id := range dctx.Assets {
		if id.Kind == asset.KindHost {
			hosts = append(hosts, id)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].String() < hosts[j].String() })
	var subjects []asset.Identity
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if hostHasHSTS(dctx, h) {
			continue
		}
		subjects = append(subjects, h)
	}
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
	var out []asset.Finding
	for _, h := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "hsts_missing", "host": h.Value}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := webFinding(dctx, ruleHSTSMissing, "HSTS Missing", detect.CategoryInformation, h, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleHSTSMissing, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleHSTSMissing)
	return out, nil
}
