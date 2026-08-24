package cloud

import (
	"context"
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
	var out []asset.Finding
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= maxFindingsPerRule {
			break
		}
		provider := bucketProvider(ep.URL.HostPort)
		if provider == "" {
			continue
		}
		f, err := cloudFinding(dctx, ruleBucketURL, "Cloud Bucket URL", bucketConfidence, ep.Identity(),
			map[string]string{"signal": "cloud_storage_endpoint", "provider": provider})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
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
		host = host[:i] // strip a non-default port; the hostname itself is already canonical lowercase
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
