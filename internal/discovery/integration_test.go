//go:build integration

// Integration tests exercise the real subfinder, assetfinder, and amass
// binaries end to end. They are compiled only with -tags integration and skip
// unless RAVENRECON_RUN_INTEGRATION=1 (and the tool is installed), so they can
// never fail the normal test suite. They are smoke/diagnostic fixtures: tool
// failures in odd environments are logged, not asserted, because the parse and
// classification layers are already covered deterministically by the unit
// tests with fake runners.
package discovery

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func integrationEnv(t *testing.T) (asset.Domain, Config) {
	t.Helper()
	if os.Getenv("RAVENRECON_RUN_INTEGRATION") != "1" {
		t.Skip("set RAVENRECON_RUN_INTEGRATION=1 to run integration tests")
	}
	target, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Minute
	return target, cfg
}

func integrationSource(t *testing.T, cfg Config, name string) (Source, Detection) {
	t.Helper()
	src := registry[name](cfg.env(name))
	det := src.Detect(context.Background())
	if det.Status == StatusMissing {
		t.Skipf("%s not installed; skipping integration test", name)
	}
	t.Logf("%s detection: %s", name, det.Reason)
	return src, det
}

func TestIntegrationSubfinder(t *testing.T) {
	target, cfg := integrationEnv(t)
	src, det := integrationSource(t, cfg, "subfinder")
	dres, err := src.Discover(context.Background(), target)
	if err != nil {
		t.Logf("subfinder run error (logged, not asserted): %v", err)
		t.Logf("subfinder retained %d hosts despite the error", len(dres.Hosts))
		return
	}
	t.Logf("subfinder %s discovered %d hosts (malformed: %d, truncated: %t)",
		det.Version, len(dres.Hosts), dres.Malformed, dres.Truncated)
	if len(dres.Hosts) > 0 && dres.Hosts[0].Name == "" {
		t.Fatal("parsed a host with an empty name")
	}
}

func TestIntegrationAssetfinder(t *testing.T) {
	target, cfg := integrationEnv(t)
	src, det := integrationSource(t, cfg, "assetfinder")
	dres, err := src.Discover(context.Background(), target)
	if err != nil {
		t.Logf("assetfinder run error (logged, not asserted): %v", err)
		return
	}
	t.Logf("assetfinder (version flag unsupported; %s) discovered %d hosts (malformed: %d)",
		det.Reason, len(dres.Hosts), dres.Malformed)
}

func TestIntegrationAmass(t *testing.T) {
	target, cfg := integrationEnv(t)
	src, det := integrationSource(t, cfg, "amass")
	dres, err := src.Discover(context.Background(), target)
	if err != nil {
		t.Logf("amass run error (logged, not asserted; amass often requires setup): %v", err)
		return
	}
	t.Logf("amass %s discovered %d hosts (malformed: %d)", det.Version, len(dres.Hosts), dres.Malformed)
}
