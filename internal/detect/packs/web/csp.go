package web

import (
	"context"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func cspMissingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["web.csp.disabled"] == "true" {
		return nil, nil
	}
	if hasCSP(dctx) {
		return nil, nil
	}
	var hosts []asset.Identity
	for _, id := range dctx.Assets {
		if id.Kind == asset.KindHost {
			hosts = append(hosts, id)
		}
	}
	var out []asset.Finding
	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= 256 {
			break
		}
		f, err := webFinding(dctx, ruleCSPMissing, "CSP Missing", detect.CategoryInformation, h, nil, map[string]string{"signal": "csp_missing", "host": h.Value})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	// Deterministic Config handling.
	formatConfigKeys(dctx, ruleCSPMissing)
	_ = strings.Join(sortedKeys(dctx.Config), ",")
	return out, nil
}
