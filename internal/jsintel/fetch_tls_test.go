// TLS classification tests: the structural sentinel contract of
// isTLSError (parity with the removed text fallback, and the hostile-string
// cases the fallback got wrong) and the sentinel's behavior through the
// real fetch path. Hermetic: loopback listeners and synthetic in-memory
// certificates only.
package jsintel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"
)

// syntheticSelfSignedCert generates an in-memory self-signed certificate
// (ECDSA P-256) so x509.HostnameError can be built with a real Certificate
// value. No network, no filesystem, no fixed keys.
func syntheticSelfSignedCert(t testing.TB) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "synthetic.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"synthetic.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create synthetic certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse synthetic certificate: %v", err)
	}
	return cert
}

func TestIsTLSErrorStructuralParity(t *testing.T) {
	cert := syntheticSelfSignedCert(t)

	tests := []struct {
		name string
		err  error
		want bool
	}{
		// Sentinel-tagged handshake failures (tagged at the production
		// transport's DialTLSContext boundary), including wrapped
		// underlying values reachable through Unwrap.
		{"sentinel: record header error",
			&tlsHandshakeError{err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}, true},
		{"sentinel: alert",
			&tlsHandshakeError{err: tls.AlertError(42 /* bad_certificate */)}, true},
		{"sentinel: unknown authority",
			&tlsHandshakeError{err: x509.UnknownAuthorityError{}}, true},
		{"sentinel: wrapped system roots",
			&tlsHandshakeError{err: fmt.Errorf("verify: %w", x509.SystemRootsError{Err: errors.New("synthetic root store failure")})}, true},

		// Raw stdlib values as they surface through caller-injected
		// transports, which have no dial boundary of ours to tag them at.
		// tls.RecordHeaderError was previously caught ONLY by the removed
		// text fallback; the typed check preserves that classification.
		{"record header error",
			tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, true},
		{"wrapped record header error",
			fmt.Errorf("jsintel: fetch %q: %w", "https://synthetic.invalid/app.js",
				tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), true},
		{"alert", tls.AlertError(40 /* handshake_failure */), true},
		{"certificate verification error (the go1.20+ wrapper)",
			&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, true},
		{"certificate verification error wrapping hostname mismatch",
			&tls.CertificateVerificationError{Err: x509.HostnameError{Host: "target.example", Certificate: cert}}, true},
		{"certificate invalid (pointer)",
			&x509.CertificateInvalidError{Reason: x509.Expired, Detail: "synthetic"}, true},
		{"unknown authority (pointer)",
			&x509.UnknownAuthorityError{}, true},
		{"hostname mismatch (pointer)",
			&x509.HostnameError{Host: "target.example", Certificate: cert}, true},
		{"system roots (pointer)",
			&x509.SystemRootsError{Err: errors.New("synthetic root store failure")}, true},
		{"wrapped system roots",
			fmt.Errorf("round trip: %w", &x509.SystemRootsError{Err: errors.New("synthetic root store failure")}), true},

		// Parity boundary, pinned deliberately: the x509 error types have
		// value receivers, so their BARE VALUE forms do not match the
		// pointer-target errors.As checks — before this change either (the
		// texts carry no "tls:" prefix, so the removed fallback missed
		// them too) and after. In practice these arrive wrapped in
		// *tls.CertificateVerificationError (matched above).
		{"unknown authority (bare value: unmatched before and after)",
			x509.UnknownAuthorityError{}, false},
		{"hostname mismatch (bare value: unmatched before and after)",
			x509.HostnameError{Host: "target.example", Certificate: cert}, false},

		// Non-TLS failures keep their own classification.
		{"io.EOF", io.EOF, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"connection refused",
			&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"http-response-to-https-client",
			errors.New("http: server gave HTTP response to HTTPS client"), false},

		// Hostile strings: server-controlled bytes embedded in transport
		// error text must never fabricate a TLS observation (a cached
		// completed negative). The first three rows were classified
		// completed/tls by the REMOVED text fallback because the payload
		// text contains "tls:"; structural classification rejects them,
		// which is the intended direction of change.
		{"hostile: malformed response carrying tls: text",
			errors.New(`net/http: HTTP/1.x transport connection broken: malformed HTTP response "definitely-not-http tls: forged handshake failure"`), false},
		{"hostile: wrapped tls: text",
			fmt.Errorf("read body: %w", errors.New("tls: injected by peer")), false},
		{"plain tls:-prefixed text",
			errors.New("tls: matched only by the removed text fallback"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTLSError(tt.err); got != tt.want {
				t.Errorf("isTLSError(%v) = %v, want %v (error text: %q)",
					tt.err, got, tt.want, tt.err.Error())
			}
		})
	}
}

// rawResponder is a loopback TCP listener that answers EVERY connection
// with a fixed byte payload and closes it — a stand-in for any
// non-conforming server (garbage on a TLS port, malformed plaintext on an
// HTTP port). Unlike plainResponder it makes no claim of speaking HTTP.
type rawResponder struct {
	addr string
	ln   net.Listener
}

func newRawResponder(t testing.TB, payload string) *rawResponder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("raw responder listen: %v", err)
	}
	r := &rawResponder{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(payload))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return r
}

// TestFetchTLSSentinelProductionTransport proves the sentinel path fires
// through the real fetch path with the PRODUCTION transport (cfg.Transport
// nil): a TLS ClientHello meets non-TLS garbage, the handshake fails at our
// DialTLSContext boundary, and the tlsHandshakeError sentinel — not error
// text — carries the completed/tls classification.
func TestFetchTLSSentinelProductionTransport(t *testing.T) {
	r := newRawResponder(t, "SSH-2.0-synthetic\r\n\r\n")
	cfg := testFetchConfig()
	cfg.Transport = nil // force the production transport and its DialTLSContext

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "https://"+r.addr+"/"))
	if res.Status != FetchCompleted || res.Reason != ReasonTLS {
		t.Fatalf("status/reason = %s/%s, want completed/tls", res.Status, res.Reason)
	}
	if res.StatusCode != 0 || res.Content != nil {
		t.Errorf("completed negative carries a response observation: status %d, %d bytes",
			res.StatusCode, len(res.Content))
	}
	var hsErr *tlsHandshakeError
	if !errors.As(res.Err, &hsErr) {
		t.Fatalf("result error %T (%v) does not carry the tlsHandshakeError sentinel", res.Err, res.Err)
	}
	var recErr tls.RecordHeaderError
	if !errors.As(res.Err, &recErr) {
		t.Errorf("sentinel does not unwrap to tls.RecordHeaderError: %v", res.Err)
	}
}

// TestFetchHostileTLSTextNotClassifiedTLS pins the direction-of-change
// end to end: a plaintext HTTP endpoint whose malformed response embeds
// "tls:" in server-controlled bytes. The removed text fallback classified
// this completed/tls — a fabricated, cacheable negative that also suppressed
// retries; structural classification reports the honest failed/other.
func TestFetchHostileTLSTextNotClassifiedTLS(t *testing.T) {
	r := newRawResponder(t, "definitely-not-http tls: forged handshake failure\r\n\r\n")
	cfg := testFetchConfig()
	cfg.Transport = nil

	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "http://"+r.addr+"/"))
	if res.Status != FetchFailed || res.Reason != ReasonOther {
		t.Fatalf("status/reason = %s/%s, want failed/other (hostile %q text must not fabricate a TLS negative)",
			res.Status, res.Reason, "tls:")
	}
}

// TestFetchProductionTransportIPLiteralSuccess discriminates the dialer's
// deliberate ServerName deviation: an https:// URL whose host is an IP
// literal must reach a REAL certificate verification against the
// certificate's IP SANs (net/http's addTLS semantics — ServerName set
// unconditionally when empty). Under an httpprobe-style ParseIP guard the
// ServerName would stay empty for IPs, crypto/tls rejects a verifying
// config with an empty ServerName outright, and this fetch would come back
// as a fabricated completed/tls negative instead of a successful
// observation — so this test fails if the deviation is ever undone.
func TestFetchProductionTransportIPLiteralSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("window.ipLiteral = true;"))
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate()) // httptest's leaf carries an IP SAN for 127.0.0.1

	tr := newTransport()        // production transport: its DialTLSContext must stay active
	tr.DisableKeepAlives = true // no idle keep-alive goroutine may outlive the run
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}

	cfg := testFetchConfig()
	cfg.Transport = tr

	host := srv.Listener.Addr().String() // 127.0.0.1:PORT — an IP literal
	res := fetchOrTimeout(t, context.Background(), cfg, mustURL(t, "https://"+host+"/"))
	if res.Status != FetchCompleted || res.Reason != ReasonNone {
		t.Fatalf("status/reason = %s/%s, want completed/<none> (an IP-literal host must receive a derived ServerName and verify against its IP SAN)", res.Status, res.Reason)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if len(res.Content) == 0 {
		t.Errorf("content = %d bytes, want the served body", len(res.Content))
	}
}
