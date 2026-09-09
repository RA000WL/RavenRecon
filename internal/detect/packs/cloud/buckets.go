package cloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// bucketConfidence rates exact provider storage-host shapes: the host
// literally is a cloud-provider storage endpoint, so the observation is
// precise — though existence still implies nothing about access (§0.1).
const bucketConfidence = 0.9

// bucketURLDetector reports endpoints whose URL host is a known cloud
// storage endpoint shape (S3 path-style and virtual-hosted, Google Cloud
// Storage, Azure Blob Storage). Informational only: an observed bucket URL
// is a recon surface indicator, never a claim that the bucket is public,
// listable, or exploitable. One finding per matching endpoint.
func bucketURLDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleBucketURL+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	carrier := make(map[asset.Identity]string)
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		provider := bucketProvider(ep.URL.HostPort)
		if provider == "" {
			continue
		}
		id := ep.Identity()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		subjects = append(subjects, id)
		carrier[id] = provider
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "cloud_storage_endpoint", "provider": carrier[s]}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := cloudFinding(dctx, ruleBucketURL, "Cloud Bucket URL", bucketConfidence, s, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleBucketURL, fmt.Sprintf("truncated %d subjects over bound %d", dropped, maxFindingsPerRule))
	}
	formatConfigKeys(dctx, ruleBucketURL)
	return out, nil
}

// bucketProvider classifies a canonical HostPort against conservative,
// exact provider storage-host shapes; "" when the host matches none.
// Recognized: s3.amazonaws.com (with optional "<bucket>." prefix),
// storage.googleapis.com (same), blob.core.windows.net (with optional
// "<account>." prefix). Bracketed IPv6 hosts can never match.
func bucketProvider(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		return ""
	}
	host := strings.ToLower(hostport)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	switch {
	case host == "s3.amazonaws.com" || strings.HasSuffix(host, ".s3.amazonaws.com"):
		return "s3"
	case host == "storage.googleapis.com" || strings.HasSuffix(host, ".storage.googleapis.com"):
		return "gcs"
	case host == "blob.core.windows.net" || strings.HasSuffix(host, ".blob.core.windows.net"):
		return "azure"
	}
	return ""
}
