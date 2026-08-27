package triage

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func idorDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	return runTriage(ctx, dctx, ruleIDOR, "Triage IDOR")
}
