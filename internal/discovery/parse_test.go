package discovery

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func testProv() asset.Provenance {
	return asset.Provenance{Source: "subfinder", DiscoveredAt: fixedTime}
}

func TestParseHostLines(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		wantHosts []string
		wantMal   int
	}{
		{
			name:      "simple",
			out:       "api.example.com\nwww.example.com\n",
			wantHosts: []string{"api.example.com", "www.example.com"},
		},
		{
			name:      "normalization and dedup by identity",
			out:       "API.Example.COM.\napi.example.com\n api.example.com \n",
			wantHosts: []string{"api.example.com"},
		},
		{
			name:      "blank and whitespace lines",
			out:       "\n   \n\t\n\n",
			wantHosts: nil,
		},
		{
			name:      "CRLF",
			out:       "api.example.com\r\nwww.example.com\r\n",
			wantHosts: []string{"api.example.com", "www.example.com"},
		},
		{
			name:      "malformed mixed with valid",
			out:       "ok.example.com\n.example.com\nbad..name\n192.168.1.1\n",
			wantHosts: []string{"ok.example.com"},
			wantMal:   3,
		},
		{
			name:      "amass annotation format",
			out:       "example.com (FQDN) --> 1.2.3.4\nwww.example.com\n",
			wantHosts: []string{"example.com", "www.example.com"},
		},
		{
			name:      "empty",
			out:       "",
			wantHosts: nil,
		},
		{
			name:      "sorted output",
			out:       "z.example.com\na.example.com\nm.example.com\n",
			wantHosts: []string{"a.example.com", "m.example.com", "z.example.com"},
		},
		{
			name:      "duplicate across case",
			out:       "WWW.Example.COM\nwww.example.com\n",
			wantHosts: []string{"www.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, mal := parseHostLines([]byte(tc.out), testProv())
			if mal != tc.wantMal {
				t.Fatalf("malformed = %d, want %d", mal, tc.wantMal)
			}
			if len(hosts) != len(tc.wantHosts) {
				t.Fatalf("hosts = %v, want %v", names(hosts), tc.wantHosts)
			}
			for i := range hosts {
				if hosts[i].Name != tc.wantHosts[i] {
					t.Fatalf("hosts[%d] = %q, want %q (all: %v)", i, hosts[i].Name, tc.wantHosts[i], names(hosts))
				}
				if hosts[i].Prov.Source != "subfinder" {
					t.Fatalf("provenance source = %q, want subfinder", hosts[i].Prov.Source)
				}
				if hosts[i].Prov.DiscoveredAt != fixedTime {
					t.Fatalf("provenance time = %v, want %v", hosts[i].Prov.DiscoveredAt, fixedTime)
				}
			}
		})
	}
}

func names(hosts []asset.Host) []string {
	out := make([]string, len(hosts))
	for i, h := range hosts {
		out[i] = h.Name
	}
	return out
}

// TestParseHostLinesLargeOutputDedup verifies deduplication and bounded
// results on a large (but in-memory) input: identity-based dedup keeps memory
// proportional to unique hosts, not lines.
func TestParseHostLinesLargeOutputDedup(t *testing.T) {
	var out []byte
	for i := 0; i < 5000; i++ {
		out = append(out, []byte("api.example.com\n")...)
	}
	for i := 0; i < 1000; i++ {
		out = append(out, []byte("host.example.com\n")...)
	}
	hosts, mal := parseHostLines(out, testProv())
	if mal != 0 {
		t.Fatalf("malformed = %d, want 0", mal)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %d, want 2 (deduplicated)", len(hosts))
	}
}
