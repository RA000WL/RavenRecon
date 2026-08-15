package httpprobe

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Bounds on the TLS metadata observation (roadmap v0.6, sub-milestone 5C).
// These are fixed retention caps, deliberately NOT configuration: a hostile
// or misconfigured server can never grow memory or cache records without
// bound. They mirror the asset model's certificate bounds where the fields
// overlap, and they never enter cache keys — the metadata is observation
// material, not result semantics (exactly like headers and the body size).
const (
	// maxTLSMetadataALPNEntries bounds the retained ALPN list (a client
	// observes at most the one protocol the server negotiated; the cap
	// mirrors the techintel ingest bound).
	maxTLSMetadataALPNEntries = 32
	// maxTLSMetadataALPNBytes bounds one retained ALPN protocol name (RFC
	// 7301 permits up to 255 bytes; 64 is the retention cap).
	maxTLSMetadataALPNBytes = 64
	// maxTLSMetadataDNSEntries and maxTLSMetadataDNSNameBytes bound the
	// retained SAN DNS names, mirroring the asset model's bounds.
	maxTLSMetadataDNSEntries   = 32
	maxTLSMetadataDNSNameBytes = 253
	// maxTLSMetadataIssuerBytes and maxTLSMetadataSubjectBytes bound the
	// retained issuer DN and subject CN strings, mirroring the asset
	// model's subject/issuer bounds.
	maxTLSMetadataIssuerBytes  = 256
	maxTLSMetadataSubjectBytes = 256
	// maxTLSMetadataAlgoBytes bounds a retained signature or public-key
	// algorithm name, mirroring the asset model's algorithm bound (64): a
	// longer observed name would be silently dropped by the ignored
	// certificate builder error below, so it is dropped at capture instead.
	maxTLSMetadataAlgoBytes = 64
	// maxTLSMetadataChainDepth is the deepest observed certificate chain
	// the Phase 2 asset model can represent (see asset.WithChainDepth).
	// A deeper observed chain suppresses the certificate asset — the
	// metadata fields and the handshake observation are never lost.
	maxTLSMetadataChainDepth = 8
)

// TLSMetadata is the typed TLS observation of one probe target (roadmap
// v0.6, sub-milestone 5C): the metadata of the leaf certificate presented
// during a completed TLS handshake. It is nil for probes that completed no
// handshake (http probes, conn_refused, tls-failure, timeouts,
// cancellation).
//
// The ALPN, Issuer, Subject, and DNSNames fields carry exactly the shape
// techintel.TLSInfo consumes: a caller composing a techintel.Observation
// from a completed https ProbeResult copies those four fields into
// Observation.TLS. Issuer is the issuer DN string as observed (for example
// "CN=WR2,O=Google Trust Services" — the technology fingerprints match
// against it); Subject is the certificate subject CN string as observed.
// Values outside the retention bounds are dropped ("not observed"), never
// truncated into misleading data.
type TLSMetadata struct {
	// Certificate is the observed leaf certificate as a Phase 2 asset,
	// identified by the lowercase hex SHA-256 fingerprint of its DER
	// encoding, with the subject/issuer CNs, SAN DNS names, validity
	// window, serial, algorithms, key size, self-signed flag, and chain
	// depth observed. It is the zero asset when the leaf could not be
	// represented in the asset model (for example a chain deeper than the
	// model's 1..8 cap): the metadata fields above remain observed.
	Certificate asset.TLSCertificate `json:"certificate"`

	// ALPN lists the ALPN protocol negotiated during the handshake (the
	// server's selection, e.g. "h2"), in handshake order — at most one
	// entry, because a client observes only what the server selected.
	// Empty when no protocol was negotiated.
	ALPN []string `json:"alpn,omitempty"`

	// Issuer is the certificate issuer DN string as observed (for example
	// "CN=WR2,O=Google Trust Services"). Empty when the issuer has no
	// representable DN.
	Issuer string `json:"issuer,omitempty"`

	// Subject is the certificate subject CN string as observed (for
	// example "www.example.com"). Empty when the certificate has no
	// subject CN.
	Subject string `json:"subject,omitempty"`

	// DNSNames are the certificate's SAN DNS names, in observation order,
	// bounded at maxTLSMetadataDNSEntries entries of at most
	// maxTLSMetadataDNSNameBytes bytes each. Wildcards and other non-
	// hostname entries are retained as observed.
	DNSNames []string `json:"dns_names,omitempty"`
}

// boundTLSMetaString returns s when it is non-empty and within max bytes of
// printable ASCII — the retention rule for every bounded TLS metadata
// string — else "" ("not observed"). Values are dropped, never truncated:
// a partial subject or issuer string would be misleading observation data.
func boundTLSMetaString(s string, max int) string {
	if s == "" || len(s) > max {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

// boundTLSMetaNames bounds an observed SAN DNS-name list: at most
// maxTLSMetadataDNSEntries entries, each non-empty and within
// maxTLSMetadataDNSNameBytes bytes of printable ASCII. Entries beyond the
// count cap and entries outside the string bounds are dropped in
// observation order; the result is nil when nothing remains.
func boundTLSMetaNames(names []string) []string {
	var out []string
	for _, n := range names {
		if len(out) >= maxTLSMetadataDNSEntries {
			break
		}
		if b := boundTLSMetaString(n, maxTLSMetadataDNSNameBytes); b != "" {
			out = append(out, b)
		}
	}
	return out
}

// keyBits returns the observed public key size in bits for the key a
// certificate leaf presented, or 0 when it cannot be observed: RSA and DSA
// report the modulus bit length, ECDSA reports the curve bit size, Ed25519
// is fixed at 256 bits, and nil/other keys (including legacy DSA, which the
// stdlib no longer generates) report 0 — the asset model's "not observed"
// value.
func keyBits(k any) int {
	switch pk := k.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen()
	case *ecdsa.PublicKey:
		return pk.Curve.Params().BitSize
	case ed25519.PublicKey:
		return ed25519.PublicKeySize * 8
	case *dsa.PublicKey:
		return 0 // legacy, unobserved
	default:
		return 0
	}
}

// captureTLS derives the typed TLS metadata (5C) from a completed
// handshake's connection state. It is a pure, total function over the
// state: it never panics and never fails the probe. It returns (nil, nil)
// when the state carries no peer certificates (a completed handshake with
// nothing to observe).
//
// Observations outside the retention bounds are dropped field-by-field
// ("not observed"). The certificate asset is suppressed entirely — with a
// diagnostic — when the observed chain is deeper than the asset model's
// 1..8 cap; the handshake observation itself (ProbeResult.TLS) and the
// metadata fields are never lost.
func captureTLS(cs *tls.ConnectionState, clock runtime.Clock) (*TLSMetadata, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, nil
	}
	leaf := cs.PeerCertificates[0]
	m := &TLSMetadata{
		Issuer:   boundTLSMetaString(leaf.Issuer.String(), maxTLSMetadataIssuerBytes),
		Subject:  boundTLSMetaString(leaf.Subject.CommonName, maxTLSMetadataSubjectBytes),
		DNSNames: boundTLSMetaNames(leaf.DNSNames),
	}
	if p := cs.NegotiatedProtocol; p != "" {
		if b := boundTLSMetaString(p, maxTLSMetadataALPNBytes); b != "" {
			m.ALPN = []string{b}
		}
	}

	// The certificate asset is built from the SAME bounded observations
	// (the asset model's subject/issuer are the CN strings; the metadata
	// Issuer is the full DN string). The leaf's identity is the SHA-256
	// fingerprint of its DER encoding — always computable, never bounded.
	sum := sha256.Sum256(leaf.Raw)
	prov := asset.Provenance{Source: "http-probe", DiscoveredAt: clock.Now().UTC()}
	c, err := asset.NewTLSCertificate(hex.EncodeToString(sum[:]), prov)
	if err != nil {
		// Cannot happen: the fingerprint is always 64 lowercase hex
		// characters. Keep the defensive path honest.
		return m, fmt.Errorf("httpprobe: build tls certificate asset: %w", err)
	}
	depth := len(cs.PeerCertificates)
	if depth > maxTLSMetadataChainDepth {
		// The observed chain cannot be represented in the Phase 2 model:
		// suppress the certificate asset, keep the metadata. The probe
		// itself stays completed — the handshake and its HTTP response
		// were observed in full. This is the ONE material drop, so it is
		// the one drop that surfaces as a diagnostic.
		return m, fmt.Errorf("httpprobe: tls chain depth %d exceeds the asset model cap %d; certificate asset suppressed",
			depth, maxTLSMetadataChainDepth)
	}
	// Every field below is pre-bounded, so the builders fail only
	// defensively; on any failure the field is dropped silently ("not
	// observed" — the asset keeps its fingerprint identity). The
	// self-signed flag is observed by name identity (subject == issuer),
	// the definition reconnaissance tooling uses.
	c, _ = asset.WithSubject(c, m.Subject)
	c, _ = asset.WithIssuer(c, boundTLSMetaString(leaf.Issuer.CommonName, maxTLSMetadataIssuerBytes))
	c, _ = asset.WithDNSNames(c, m.DNSNames)
	c, _ = asset.WithValidity(c, leaf.NotBefore, leaf.NotAfter)
	c, _ = asset.WithSerial(c, boundTLSMetaString(leaf.SerialNumber.String(), maxTLSMetadataIssuerBytes))
	c, _ = asset.WithSignatureAlgorithm(c, boundTLSMetaString(leaf.SignatureAlgorithm.String(), maxTLSMetadataAlgoBytes))
	c, _ = asset.WithPublicKey(c, boundTLSMetaString(leaf.PublicKeyAlgorithm.String(), maxTLSMetadataAlgoBytes), keyBits(leaf.PublicKey))
	c, _ = asset.WithSelfSigned(c, bytes.Equal(leaf.RawSubject, leaf.RawIssuer))
	c, err = asset.WithChainDepth(c, depth)
	if err != nil {
		// Cannot happen: 1 <= depth <= maxTLSMetadataChainDepth here.
		return m, fmt.Errorf("httpprobe: tls certificate chain depth: %w", err)
	}
	m.Certificate = c
	return m, nil
}

// validateStoredTLS re-validates a stored TLS observation before it may be
// served as a hit (mirroring validateStoredURL): a completed-handshake flag
// is only ever true on an https probe; a metadata payload may only appear
// with a completed handshake on an https probe, must be within the
// retention bounds, and its embedded certificate asset — when present —
// must re-validate through the Phase 2 asset model (canonical fingerprint,
// bounded fields, chain depth 1..8). A payload failing any check refuses
// the whole record (deleted and recomputed by the self-healing path, never
// served), so a corrupt or tampered record can never produce bogus
// certificate observations.
func validateStoredTLS(m *TLSMetadata, scheme string, tls bool) error {
	if tls && scheme != "https" {
		return fmt.Errorf("stored result has a completed TLS handshake on an %s probe", scheme)
	}
	if m == nil {
		return nil
	}
	if scheme != "https" {
		return fmt.Errorf("stored result carries TLS metadata on an %s probe", scheme)
	}
	if !tls {
		return fmt.Errorf("stored result carries TLS metadata without a completed handshake")
	}
	// The at-most-one ALPN invariant (see TLSMetadata.ALPN): a genuine
	// capture observes only the one protocol the server negotiated, so a
	// stored record with more entries cannot come from this pipeline.
	if len(m.ALPN) > 1 {
		return fmt.Errorf("stored result tls alpn protocol list has %d entries; a client observes at most the one protocol the server negotiated", len(m.ALPN))
	}
	if err := validateStoredTLSStrings("alpn protocol", m.ALPN, maxTLSMetadataALPNEntries, maxTLSMetadataALPNBytes); err != nil {
		return err
	}
	if err := validateStoredTLSStrings("dns name", m.DNSNames, maxTLSMetadataDNSEntries, maxTLSMetadataDNSNameBytes); err != nil {
		return err
	}
	if err := validateStoredTLSString("issuer", m.Issuer, maxTLSMetadataIssuerBytes); err != nil {
		return err
	}
	if err := validateStoredTLSString("subject", m.Subject, maxTLSMetadataSubjectBytes); err != nil {
		return err
	}
	if m.Certificate.Fingerprint == "" {
		// A metadata-only payload (the certificate asset was suppressed at
		// capture, e.g. a chain deeper than the model cap).
		return nil
	}
	// Re-validate the embedded certificate asset field by field through the
	// Phase 2 builders: every bound the model enforces applies to stored
	// records too.
	c, err := asset.NewTLSCertificate(m.Certificate.Fingerprint, m.Certificate.Prov)
	if err != nil {
		return fmt.Errorf("stored result tls certificate: %w", err)
	}
	if _, err := asset.WithSubject(c, m.Certificate.Subject); err != nil {
		return fmt.Errorf("stored result tls certificate subject: %w", err)
	}
	if _, err := asset.WithIssuer(c, m.Certificate.Issuer); err != nil {
		return fmt.Errorf("stored result tls certificate issuer: %w", err)
	}
	if _, err := asset.WithDNSNames(c, m.Certificate.DNSNames); err != nil {
		return fmt.Errorf("stored result tls certificate dns names: %w", err)
	}
	if _, err := asset.WithSerial(c, m.Certificate.Serial); err != nil {
		return fmt.Errorf("stored result tls certificate serial: %w", err)
	}
	if _, err := asset.WithSignatureAlgorithm(c, m.Certificate.SignatureAlgorithm); err != nil {
		return fmt.Errorf("stored result tls certificate signature algorithm: %w", err)
	}
	if _, err := asset.WithPublicKey(c, m.Certificate.PublicKeyAlgorithm, m.Certificate.PublicKeyBits); err != nil {
		return fmt.Errorf("stored result tls certificate public key: %w", err)
	}
	if _, err := asset.WithSelfSigned(c, m.Certificate.SelfSigned); err != nil {
		return fmt.Errorf("stored result tls certificate self-signed: %w", err)
	}
	if _, err := asset.WithChainDepth(c, m.Certificate.ChainDepth); err != nil {
		return fmt.Errorf("stored result tls certificate chain depth: %w", err)
	}
	return nil
}

// validateStoredTLSString enforces the stored-string rule for one bounded
// TLS metadata string: empty is allowed ("not observed"), otherwise the
// value must be within max bytes of printable ASCII.
func validateStoredTLSString(what, s string, max int) error {
	if s == "" {
		return nil
	}
	if len(s) > max {
		return fmt.Errorf("stored result tls %s is %d bytes, longer than the %d maximum", what, len(s), max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("stored result tls %s contains a non-printable character", what)
		}
	}
	return nil
}

// validateStoredTLSStrings enforces the stored-list rule for one bounded
// TLS metadata list: at most maxEntries non-empty entries, each within max
// bytes of printable ASCII.
func validateStoredTLSStrings(what string, list []string, maxEntries, maxBytes int) error {
	if len(list) > maxEntries {
		return fmt.Errorf("stored result tls %s list has %d entries (cap %d)", what, len(list), maxEntries)
	}
	for i, v := range list {
		if v == "" {
			return fmt.Errorf("stored result tls %s entry %d is empty", what, i)
		}
		if err := validateStoredTLSString(what, v, maxBytes); err != nil {
			return err
		}
	}
	return nil
}
