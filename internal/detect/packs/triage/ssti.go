package triage

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func sstiDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	return runTriage(ctx, dctx, ruleSSTI, "Triage SSTI")
}
