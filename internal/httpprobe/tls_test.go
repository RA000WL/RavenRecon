package httpprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// syntheticLeaf creates a real self-signed leaf certificate through
// x509.CreateCertificate — so Raw, RawSubject, and RawIssuer are the genuine
// DER encodings captureTLS reads — and returns the parsed certificate. The
// key is ed25519 unless rsaBits > 0 (RSA of that size). Serial, CN, and SAN
// names are caller-controlled; everything else is fixed.
func syntheticLeaf(t *testing.T, cn string, serial int64, dnsNames []string, rsaBits int) *x509.Certificate {
	t.Helper()
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	var (
		der []byte
		err error
	)
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	} else {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 key: %v", err)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	}
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return leaf
}

// TestCaptureTLSLearnMetadata pins the full 5C capture of a leaf
// certificate: the fingerprint is the sha256 of the DER encoding, and the
// subject/issuer/ALPN/DNSNames/validity/serial/signature algorithm/public
// key are captured as observed.
func TestCaptureTLSLearnMetadata(t *testing.T) {
	leaf := syntheticLeaf(t, "www.example.com", 0x1a2b3c,
		[]string{"www.example.com", "example.com", "*.cdn.example.com"}, 2048)
	cs := &tls.ConnectionState{
		PeerCertificates:   []*x509.Certificate{leaf},
		NegotiatedProtocol: "h2",
	}
	m, err := captureTLS(cs, newFakeClock(fixedTime))
	if err != nil {
		t.Fatalf("captureTLS: %v", err)
	}
	if m == nil {
		t.Fatal("captureTLS returned nil metadata")
	}

	sum := sha256.Sum256(leaf.Raw)
	if want := hex.EncodeToString(sum[:]); m.Certificate.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want the sha256 of the DER encoding %q", m.Certificate.Fingerprint, want)
	}
	if m.Certificate.Subject != "www.example.com" {
		t.Fatalf("certificate subject = %q, want the observed CN", m.Certificate.Subject)
	}
	if m.Certificate.Issuer != "www.example.com" {
		t.Fatalf("certificate issuer = %q, want the observed issuer CN", m.Certificate.Issuer)
	}
	if m.Subject != "www.example.com" {
		t.Fatalf("metadata subject = %q, want the observed CN", m.Subject)
	}
	if m.Issuer != leaf.Issuer.String() {
		t.Fatalf("metadata issuer = %q, want the observed issuer DN %q", m.Issuer, leaf.Issuer.String())
	}
	if len(m.ALPN) != 1 || m.ALPN[0] != "h2" {
		t.Fatalf("alpn = %v, want [h2] (the server's negotiated protocol)", m.ALPN)
	}
	wantNames := []string{"www.example.com", "example.com", "*.cdn.example.com"}
	if strings.Join(m.DNSNames, "|") != strings.Join(wantNames, "|") {
		t.Fatalf("dns names = %v, want %v in observation order", m.DNSNames, wantNames)
	}
	if strings.Join(m.Certificate.DNSNames, "|") != strings.Join(wantNames, "|") {
		t.Fatalf("certificate dns names = %v, want %v", m.Certificate.DNSNames, wantNames)
	}
	if !m.Certificate.NotBefore.Equal(leaf.NotBefore) || !m.Certificate.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("validity = %v..%v, want %v..%v", m.Certificate.NotBefore, m.Certificate.NotAfter, leaf.NotBefore, leaf.NotAfter)
	}
	if m.Certificate.Serial != leaf.SerialNumber.String() {
		t.Fatalf("serial = %q, want %q (as observed)", m.Certificate.Serial, leaf.SerialNumber.String())
	}
	if m.Certificate.SignatureAlgorithm != leaf.SignatureAlgorithm.String() {
		t.Fatalf("signature algorithm = %q, want %q", m.Certificate.SignatureAlgorithm, leaf.SignatureAlgorithm.String())
	}
	if m.Certificate.PublicKeyAlgorithm != leaf.PublicKeyAlgorithm.String() {
		t.Fatalf("public key algorithm = %q, want %q", m.Certificate.PublicKeyAlgorithm, leaf.PublicKeyAlgorithm.String())
	}
	if m.Certificate.PublicKeyBits != 2048 {
		t.Fatalf("public key bits = %d, want 2048 (the rsa modulus size)", m.Certificate.PublicKeyBits)
	}
	if !m.Certificate.SelfSigned {
		t.Fatal("self-signed flag must be true for a self-signed leaf")
	}
	if m.Certificate.ChainDepth != 1 {
		t.Fatalf("chain depth = %d, want 1", m.Certificate.ChainDepth)
	}
	if m.Certificate.Prov.Source != "http-probe" || !m.Certificate.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Fatalf("provenance = %+v, want http-probe at the injected clock", m.Certificate.Prov)
	}
}

// TestCaptureTLSEd25519KeyBits pins the ed25519 key-size observation: a
// fixed 256 bits.
func TestCaptureTLSEd25519KeyBits(t *testing.T) {
	leaf := syntheticLeaf(t, "ed.example.com", 7, nil, 0)
	m, err := captureTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, newFakeClock(fixedTime))
	if err != nil {
		t.Fatalf("captureTLS: %v", err)
	}
	if m.Certificate.PublicKeyBits != 256 {
		t.Fatalf("public key bits = %d, want 256 (ed25519)", m.Certificate.PublicKeyBits)
	}
	if m.Certificate.PublicKeyAlgorithm != "Ed25519" {
		t.Fatalf("public key algorithm = %q, want Ed25519", m.Certificate.PublicKeyAlgorithm)
	}
}

// TestCaptureTLSNilState pins the total-function boundary: a nil state or a
// state without peer certificates captures nothing and never fails.
func TestCaptureTLSNilState(t *testing.T) {
	if m, err := captureTLS(nil, newFakeClock(fixedTime)); m != nil || err != nil {
		t.Fatalf("captureTLS(nil) = %v, %v; want nil, nil", m, err)
	}
	if m, err := captureTLS(&tls.ConnectionState{}, newFakeClock(fixedTime)); m != nil || err != nil {
		t.Fatalf("captureTLS(no peer certificates) = %v, %v; want nil, nil", m, err)
	}
}

// TestCaptureTLSChainDepthSuppressesCert pins the chain-depth cap: a chain
// deeper than the model's 1..8 cap keeps the metadata and the handshake
// observation but suppresses the certificate asset with a diagnostic.
func TestCaptureTLSChainDepthSuppressesCert(t *testing.T) {
	leaf := syntheticLeaf(t, "deep.example.com", 9, nil, 0)
	chain := make([]*x509.Certificate, maxTLSMetadataChainDepth+1)
	for i := range chain {
		chain[i] = leaf
	}
	m, err := captureTLS(&tls.ConnectionState{PeerCertificates: chain}, newFakeClock(fixedTime))
	if m == nil {
		t.Fatal("captureTLS returned nil metadata for a suppressed certificate")
	}
	if !m.Certificate.Identity().IsZero() {
		t.Fatalf("certificate asset must be suppressed past the chain cap, got %+v", m.Certificate)
	}
	if err == nil {
		t.Fatal("chain-depth suppression must surface a diagnostic")
	}
	if !strings.Contains(err.Error(), "chain depth") {
		t.Fatalf("diagnostic = %v, want a chain-depth explanation", err)
	}
	if m.Subject != "deep.example.com" || m.Issuer == "" {
		t.Fatalf("metadata must survive suppression, got subject %q issuer %q", m.Subject, m.Issuer)
	}
}

// TestCaptureTLSChainDepthAtCap pins the boundary exactly: a chain of the
// model's maximum depth keeps the certificate asset with no diagnostic.
func TestCaptureTLSChainDepthAtCap(t *testing.T) {
	leaf := syntheticLeaf(t, "atcap.example.com", 10, nil, 0)
	chain := make([]*x509.Certificate, maxTLSMetadataChainDepth)
	for i := range chain {
		chain[i] = leaf
	}
	m, err := captureTLS(&tls.ConnectionState{PeerCertificates: chain}, newFakeClock(fixedTime))
	if err != nil {
		t.Fatalf("captureTLS: %v", err)
	}
	if m.Certificate.ChainDepth != maxTLSMetadataChainDepth {
		t.Fatalf("chain depth = %d, want %d", m.Certificate.ChainDepth, maxTLSMetadataChainDepth)
	}
}

// TestCaptureTLSFieldDrops pins the drop-not-truncate rule: values outside
// the retention bounds are dropped to "" / nil ("not observed"), never
// truncated into misleading data.
func TestCaptureTLSFieldDrops(t *testing.T) {
	oversizedCN := strings.Repeat("x", maxTLSMetadataSubjectBytes+1)
	nonPrintableCN := "bad\u0100cn" // multi-byte non-ASCII: outside printable ASCII

	t.Run("oversized subject and issuer are dropped", func(t *testing.T) {
		leaf := syntheticLeaf(t, oversizedCN, 1, nil, 0)
		m, err := captureTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, newFakeClock(fixedTime))
		if err != nil {
			t.Fatalf("captureTLS: %v", err)
		}
		if m.Subject != "" || m.Issuer != "" {
			t.Fatalf("subject/issuer = %q/%q, want both dropped (never truncated)", m.Subject, m.Issuer)
		}
		if m.Certificate.Subject != "" || m.Certificate.Issuer != "" {
			t.Fatalf("certificate subject/issuer = %q/%q, want both dropped", m.Certificate.Subject, m.Certificate.Issuer)
		}
		if m.Certificate.Identity().IsZero() {
			t.Fatal("the certificate asset keeps its fingerprint identity even when every field is dropped")
		}
	})

	t.Run("non-printable subject is dropped", func(t *testing.T) {
		leaf := syntheticLeaf(t, nonPrintableCN, 2, nil, 0)
		m, err := captureTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, newFakeClock(fixedTime))
		if err != nil {
			t.Fatalf("captureTLS: %v", err)
		}
		if m.Subject != "" || m.Issuer != "" {
			t.Fatalf("subject/issuer = %q/%q, want dropped (non-printable)", m.Subject, m.Issuer)
		}
	})

	t.Run("oversized alpn protocol is dropped", func(t *testing.T) {
		leaf := syntheticLeaf(t, "alpn.example.com", 3, nil, 0)
		cs := &tls.ConnectionState{
			PeerCertificates:   []*x509.Certificate{leaf},
			NegotiatedProtocol: strings.Repeat("p", maxTLSMetadataALPNBytes+1),
		}
		m, err := captureTLS(cs, newFakeClock(fixedTime))
		if err != nil {
			t.Fatalf("captureTLS: %v", err)
		}
		if m.ALPN != nil {
			t.Fatalf("alpn = %v, want nil (protocol beyond the byte cap is dropped, never truncated)", m.ALPN)
		}
	})

	t.Run("oversized dns name is dropped, cap-bounded list retained", func(t *testing.T) {
		names := []string{"good.example.com", strings.Repeat("d", maxTLSMetadataDNSNameBytes+1)}
		leaf := syntheticLeaf(t, "dns.example.com", 4, names, 0)
		m, err := captureTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, newFakeClock(fixedTime))
		if err != nil {
			t.Fatalf("captureTLS: %v", err)
		}
		if strings.Join(m.DNSNames, "|") != "good.example.com" {
			t.Fatalf("dns names = %v, want only the in-bounds entry", m.DNSNames)
		}
		if strings.Join(m.Certificate.DNSNames, "|") != "good.example.com" {
			t.Fatalf("certificate dns names = %v, want only the in-bounds entry", m.Certificate.DNSNames)
		}
	})

	t.Run("dns name count is capped", func(t *testing.T) {
		names := make([]string, maxTLSMetadataDNSEntries+10)
		for i := range names {
			names[i] = "n" + itoa(i) + ".example.com"
		}
		leaf := syntheticLeaf(t, "count.example.com", 5, names, 0)
		m, err := captureTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, newFakeClock(fixedTime))
		if err != nil {
			t.Fatalf("captureTLS: %v", err)
		}
		if len(m.DNSNames) != maxTLSMetadataDNSEntries {
			t.Fatalf("dns names = %d entries, want the %d cap", len(m.DNSNames), maxTLSMetadataDNSEntries)
		}
		if len(m.Certificate.DNSNames) != maxTLSMetadataDNSEntries {
			t.Fatalf("certificate dns names = %d entries, want the %d cap", len(m.Certificate.DNSNames), maxTLSMetadataDNSEntries)
		}
	})
}
