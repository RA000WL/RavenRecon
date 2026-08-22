package importer

import (
	"net/netip"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func assetParseURL(raw string, p asset.Provenance) (asset.URL, error) {
	return asset.ParseURL(raw, p)
}

func assetNewIP(raw string, p asset.Provenance) (asset.IP, error) {
	return asset.NewIP(raw, p)
}

func assetNewHost(raw string, p asset.Provenance) (asset.Host, error) {
	return asset.NewHost(raw, p)
}

func assetNewJS(raw string, p asset.Provenance) (asset.JavaScript, error) {
	return asset.NewJavaScript(raw, p)
}

func parseCIDR(raw string) (string, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	return prefix.String(), true
}
