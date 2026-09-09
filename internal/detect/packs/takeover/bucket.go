package takeover

import (
	"context"
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func s3BucketDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleS3Bucket+".disabled"] == "true" {
		return nil, nil
	}
	// S3 bucket via endpoint host shape only — technology alone intentionally
	// insufficient for per-endpoint finding without endpoint shape (conservative
	// per §0.1; endpoint host shape is the signal).
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !isS3Endpoint(ep) {
			// Also check tech path: if endpoint's URL host was not S3 but we have S3 tech,
			// do not fire — technology alone is not sufficient for per-endpoint finding
			// without endpoint shape. Keep conservative.
			continue
		}
		id := ep.Identity()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		host := strings.ToLower(ep.URL.HostPort)
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		host = strings.Trim(host, "[]")
		metaFor[id] = map[string]string{
			"signal":   "takeover_s3_bucket",
			"provider": "s3",
			"host":     host,
			"category": "s3_bucket",
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := takeoverFinding(dctx, ruleS3Bucket, "Takeover S3 Bucket", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleS3Bucket, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleS3Bucket)
	return out, nil
}
