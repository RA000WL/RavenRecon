// The discriminating positive-path test for the production transport's
// DialTLSContext ServerName semantics (NEW-50): an https:// probe whose
// host is an IP literal must reach a REAL certificate verification against
// the certificate's IP SANs — net/http's addTLS semantics, ServerName set
// unconditionally when empty. Hermetic: loopback server, synthetic
// certificate.
package httpprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestProbeProductionTransportIPLiteralSuccess discriminates the dialer's
// ServerName semantics: probing https://127.0.0.1:PORT/ with the PRODUCTION
// transport must complete a real TLS handshake and capture its metadata.
//
// Under the pre-fix ParseIP guard the derived ServerName stayed empty for IP
// literals; crypto/tls rejects a verifying config with an empty ServerName
// outright ("either ServerName or InsecureSkipVerify"), so this probe failed
// LOCALLY before any packet was sent and classified completed/tls with no
// handshake state at all — a fabricated, cacheable negative. With addTLS
// semantics it verifies against the httptest certificate's 127.0.0.1 IP SAN,
// so this test fails if the unconditional assignment is ever undone.
func TestProbeProductionTransportIPLiteralSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ip-literal"))
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate()) // httptest's leaf carries a 127.0.0.1 IP SAN

	tr := newTransport()        // production transport: its DialTLSContext must stay active
	tr.DisableKeepAlives = true // no idle keep-alive goroutine may outlive the run
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}

	e, err := buildEnv(Config{Transport: tr}, nil)
	if err != nil {
		t.Fatalf("buildEnv: %v", err)
	}
	target, err := asset.ParseURL("https://"+srv.Listener.Addr().String()+"/",
		asset.Provenance{Source: "http-probe", DiscoveredAt: fixedTime})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", "https://"+srv.Listener.Addr().String()+"/", err)
	}
	pr := doProbe(context.Background(), mustHost(t, "www.example.com"), target,
		mustDomain(t, "example.com"), e, ProbeResult{Scheme: "https", Executed: true})

	if pr.Status != ProbeCompleted || pr.FailureReason != ReasonNone || !pr.TLS {
		t.Fatalf("ip-literal https probe = %+v (want completed/<none> with a REAL handshake: "+
			"an IP-literal host must receive a derived ServerName and verify against its IP SAN)", pr)
	}
	if pr.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", pr.StatusCode, http.StatusOK)
	}
	if pr.TLSMeta == nil || pr.TLSMeta.Certificate.Fingerprint == "" {
		t.Fatalf("completed ip-literal handshake captured no TLS metadata: %+v", pr.TLSMeta)
	}
}
