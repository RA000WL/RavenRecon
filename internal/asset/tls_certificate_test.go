package asset

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// testTLSCertFingerprint is a deterministic canonical fingerprint: exactly
// 64 lowercase hex characters.
const testTLSCertFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testTLSFingerprint returns a deterministic 64-character lowercase hex
// fingerprint (32 bytes, hex-encoded). Different seeds produce different
// fingerprints.
func testTLSFingerprint(seed byte) string {
	raw := [32]byte{}
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw[:])
}

// fullCert builds a fully-populated certificate observation through the
// public constructors and setters, failing the test on any validation error.
// Empty strings, zero bits, false, depth 0, nil names, and zero times mean
// "not observed" and are set through the setters like any other value.
func fullCert(t *testing.T, fp string, prov Provenance, subject, issuer, serial, sigAlg, pkAlg string, pkBits int, selfSigned bool, depth int, dnsNames []string, nb, na time.Time) TLSCertificate {
	t.Helper()
	var err error
	c, err := NewTLSCertificate(fp, prov)
	if err != nil {
		t.Fatal(err)
	}
	if c, err = WithSubject(c, subject); err != nil {
		t.Fatal(err)
	}
	if c, err = WithIssuer(c, issuer); err != nil {
		t.Fatal(err)
	}
	if c, err = WithSerial(c, serial); err != nil {
		t.Fatal(err)
	}
	if c, err = WithSignatureAlgorithm(c, sigAlg); err != nil {
		t.Fatal(err)
	}
	if c, err = WithPublicKey(c, pkAlg, pkBits); err != nil {
		t.Fatal(err)
	}
	if c, err = WithSelfSigned(c, selfSigned); err != nil {
		t.Fatal(err)
	}
	if c, err = WithChainDepth(c, depth); err != nil {
		t.Fatal(err)
	}
	if c, err = WithDNSNames(c, dnsNames); err != nil {
		t.Fatal(err)
	}
	if c, err = WithValidity(c, nb, na); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewTLSCertificate(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "tls-observe", DiscoveredAt: at, Reference: "ref-1", Confidence: 0.9}

	c, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatalf("NewTLSCertificate: %v", err)
	}
	if c.Fingerprint != testTLSCertFingerprint {
		t.Errorf("Fingerprint = %q", c.Fingerprint)
	}
	if c.Prov != p {
		t.Errorf("Prov = %v, want %v", c.Prov, p)
	}
	if c.Identity().Kind != KindTLSCertificate {
		t.Errorf("kind = %q, want %q", c.Identity().Kind, KindTLSCertificate)
	}
	wantID := "tls_certificate:" + testTLSCertFingerprint
	if c.ID() != wantID {
		t.Errorf("ID = %q, want %q", c.ID(), wantID)
	}
	if c.String() != testTLSCertFingerprint {
		t.Errorf("String = %q, want the fingerprint", c.String())
	}
}

func TestNewTLSCertificateFingerprintValidation(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}

	cases := []struct {
		name    string
		fp      string
		wantSub string
	}{
		{"empty", "", "exactly 64 lowercase hex"},
		{"63 chars", strings.Repeat("a", 63), "exactly 64 lowercase hex"},
		{"65 chars", strings.Repeat("a", 65), "exactly 64 lowercase hex"},
		{"uppercase hex", strings.ToUpper(testTLSCertFingerprint), "lowercase hex"},
		{"mixed case", "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef", "lowercase hex"},
		{"non-hex letter", "g" + strings.Repeat("a", 63), "lowercase hex"},
		{"space", " " + strings.Repeat("a", 63), "lowercase hex"},
		{"non-ASCII", "é" + strings.Repeat("a", 63), "lowercase hex"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewTLSCertificate(tt.fp, p)
			if err == nil {
				t.Fatalf("expected error, got %#v", c)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}

	// The exact canonical form constructs, stored as given (never rewritten).
	c, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatalf("canonical fingerprint must construct: %v", err)
	}
	if c.Fingerprint != testTLSCertFingerprint {
		t.Errorf("Fingerprint must be stored as given, got %q", c.Fingerprint)
	}
}

func TestTLSCertificateSetters(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatal(err)
	}

	c, err := WithSubject(base, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithIssuer(c, "Example Issuer")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"www.example.com", "example.com"}
	c, err = WithDNSNames(c, names)
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithValidity(c, fixedTime(1), fixedTime(20))
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithSerial(c, "0a1b2c3d")
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithSignatureAlgorithm(c, "sha256WithRSAEncryption")
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithPublicKey(c, "rsa", 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithSelfSigned(c, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithChainDepth(c, 3)
	if err != nil {
		t.Fatal(err)
	}

	if c.Subject != "www.example.com" || c.Issuer != "Example Issuer" {
		t.Errorf("Subject/Issuer = %q/%q", c.Subject, c.Issuer)
	}
	if !reflect.DeepEqual(c.DNSNames, []string{"www.example.com", "example.com"}) {
		t.Errorf("DNSNames = %v", c.DNSNames)
	}
	if !c.NotBefore.Equal(fixedTime(1)) || !c.NotAfter.Equal(fixedTime(20)) {
		t.Errorf("window = %v..%v", c.NotBefore, c.NotAfter)
	}
	if c.Serial != "0a1b2c3d" || c.SignatureAlgorithm != "sha256WithRSAEncryption" {
		t.Errorf("Serial/SigAlg = %q/%q", c.Serial, c.SignatureAlgorithm)
	}
	if c.PublicKeyAlgorithm != "rsa" || c.PublicKeyBits != 2048 {
		t.Errorf("PublicKey = %q/%d", c.PublicKeyAlgorithm, c.PublicKeyBits)
	}
	if !c.SelfSigned || c.ChainDepth != 3 {
		t.Errorf("SelfSigned/ChainDepth = %v/%d", c.SelfSigned, c.ChainDepth)
	}
	if c.Fingerprint != testTLSCertFingerprint {
		t.Errorf("Fingerprint must be untouched: %q", c.Fingerprint)
	}
	if c.Prov != p {
		t.Errorf("Prov must be untouched: %v", c.Prov)
	}

	// Purity: the base input is unchanged by any setter.
	if base.Subject != "" || base.Issuer != "" || base.Serial != "" ||
		base.SignatureAlgorithm != "" || base.PublicKeyAlgorithm != "" ||
		base.PublicKeyBits != 0 || base.SelfSigned || base.ChainDepth != 0 ||
		base.DNSNames != nil || !base.NotBefore.IsZero() || !base.NotAfter.IsZero() {
		t.Errorf("setters must not mutate their input: %#v", base)
	}

	// WithDNSNames copies its input slice: mutating the caller's slice
	// afterwards cannot affect the certificate.
	names[0] = "tampered.example.com"
	if c.DNSNames[0] != "www.example.com" {
		t.Error("WithDNSNames must copy its input slice")
	}
}

func TestTLSCertificateSetterAcceptance(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		set  func() (TLSCertificate, error)
	}{
		{"subject at 256 bytes", func() (TLSCertificate, error) { return WithSubject(base, strings.Repeat("s", 256)) }},
		{"issuer at 256 bytes", func() (TLSCertificate, error) { return WithIssuer(base, strings.Repeat("i", 256)) }},
		{"serial at 256 bytes", func() (TLSCertificate, error) { return WithSerial(base, strings.Repeat("0", 256)) }},
		{"sigalg at 64 bytes", func() (TLSCertificate, error) { return WithSignatureAlgorithm(base, strings.Repeat("a", 64)) }},
		{"pkalg at 64 bytes", func() (TLSCertificate, error) { return WithPublicKey(base, strings.Repeat("k", 64), 2048) }},
		{"bits 0 accepted", func() (TLSCertificate, error) { return WithPublicKey(base, "rsa", 0) }},
		{"bits 65536 accepted", func() (TLSCertificate, error) { return WithPublicKey(base, "rsa", 65536) }},
		{"chain depth 1 accepted", func() (TLSCertificate, error) { return WithChainDepth(base, 1) }},
		{"chain depth 8 accepted", func() (TLSCertificate, error) { return WithChainDepth(base, 8) }},
		{"dns names 32 accepted", func() (TLSCertificate, error) {
			names := make([]string, 32)
			for i := range names {
				names[i] = fmt.Sprintf("san%d.example.com", i)
			}
			return WithDNSNames(base, names)
		}},
		{"dns name 253 bytes accepted", func() (TLSCertificate, error) {
			return WithDNSNames(base, []string{strings.Repeat("a", 253)})
		}},
		{"empty subject allowed", func() (TLSCertificate, error) { return WithSubject(base, "") }},
		{"no dns names allowed", func() (TLSCertificate, error) { return WithDNSNames(base, nil) }},
		{"empty signature algorithm allowed", func() (TLSCertificate, error) { return WithSignatureAlgorithm(base, "") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.set(); err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
		})
	}
}

func TestTLSCertificateSetterRejection(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	base, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		set     func() (TLSCertificate, error)
		wantSub string
	}{
		{"subject over 256", func() (TLSCertificate, error) { return WithSubject(base, strings.Repeat("s", 257)) }, "longer than the 256 maximum"},
		{"subject NUL", func() (TLSCertificate, error) { return WithSubject(base, "a\x00b") }, "non-printable character"},
		{"subject tab", func() (TLSCertificate, error) { return WithSubject(base, "a\tb") }, "non-printable character"},
		{"subject DEL", func() (TLSCertificate, error) { return WithSubject(base, "a\x7fb") }, "non-printable character"},
		{"subject non-ASCII", func() (TLSCertificate, error) { return WithSubject(base, "café") }, "non-printable character"},
		{"issuer over 256", func() (TLSCertificate, error) { return WithIssuer(base, strings.Repeat("i", 257)) }, "longer than the 256 maximum"},
		{"issuer NUL", func() (TLSCertificate, error) { return WithIssuer(base, "a\x00b") }, "non-printable character"},
		{"serial over 256", func() (TLSCertificate, error) { return WithSerial(base, strings.Repeat("0", 257)) }, "longer than the 256 maximum"},
		{"serial NUL", func() (TLSCertificate, error) { return WithSerial(base, "ab\x00cd") }, "non-printable character"},
		{"sigalg over 64", func() (TLSCertificate, error) { return WithSignatureAlgorithm(base, strings.Repeat("a", 65)) }, "longer than the 64 maximum"},
		{"pkalg over 64", func() (TLSCertificate, error) { return WithPublicKey(base, strings.Repeat("k", 65), 2048) }, "longer than the 64 maximum"},
		{"bits negative", func() (TLSCertificate, error) { return WithPublicKey(base, "rsa", -1) }, "outside 0..65536"},
		{"bits over 65536", func() (TLSCertificate, error) { return WithPublicKey(base, "rsa", 65537) }, "outside 0..65536"},
		{"chain depth 0", func() (TLSCertificate, error) { return WithChainDepth(base, 0) }, "outside 1..8"},
		{"chain depth 9", func() (TLSCertificate, error) { return WithChainDepth(base, 9) }, "outside 1..8"},
		{"chain depth negative", func() (TLSCertificate, error) { return WithChainDepth(base, -3) }, "outside 1..8"},
		{"dns names 33", func() (TLSCertificate, error) {
			names := make([]string, 33)
			for i := range names {
				names[i] = fmt.Sprintf("san%d.example.com", i)
			}
			return WithDNSNames(base, names)
		}, "more than the 32 maximum"},
		{"dns name over 253", func() (TLSCertificate, error) {
			return WithDNSNames(base, []string{strings.Repeat("a", 254)})
		}, "longer than the 253 maximum"},
		{"dns name empty", func() (TLSCertificate, error) {
			return WithDNSNames(base, []string{""})
		}, "must not be empty"},
		{"dns name NUL", func() (TLSCertificate, error) {
			return WithDNSNames(base, []string{"a\x00b"})
		}, "non-printable character"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.set()
			if err == nil {
				t.Fatalf("expected error, got %#v", got)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestTLSCertificateValidity(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	c, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatal(err)
	}
	c, err = WithValidity(c, fixedTime(10), fixedTime(20))
	if err != nil {
		t.Fatal(err)
	}

	// Expired = now.After(NotAfter): exactly at NotAfter is NOT expired
	// (the boundary pin), strictly after is.
	if c.Expired(fixedTime(20)) {
		t.Error("exactly at NotAfter must not be expired (Expired = now.After(NotAfter))")
	}
	if !c.Expired(fixedTime(21)) {
		t.Error("strictly after NotAfter must be expired")
	}
	if c.Expired(fixedTime(19)) {
		t.Error("inside the window must not be expired")
	}

	// NotYetValid = now.Before(NotBefore): exactly at NotBefore IS valid
	// (the boundary pin), strictly before is not.
	if c.NotYetValid(fixedTime(10)) {
		t.Error("exactly at NotBefore must be valid (NotYetValid = now.Before(NotBefore))")
	}
	if !c.NotYetValid(fixedTime(9)) {
		t.Error("strictly before NotBefore must be not-yet-valid")
	}
	if c.NotYetValid(fixedTime(11)) {
		t.Error("inside the window must not be not-yet-valid")
	}

	// Inside the window both helpers are false.
	if c.Expired(fixedTime(15)) || c.NotYetValid(fixedTime(15)) {
		t.Error("inside the window both helpers must be false")
	}

	// The helpers are pure: the certificate is unchanged.
	if !c.NotAfter.Equal(fixedTime(20)) || !c.NotBefore.Equal(fixedTime(10)) {
		t.Error("validity helpers must not mutate the certificate")
	}
}

func TestMergeTLSCertificates(t *testing.T) {
	fp := testTLSFingerprint(0x10)
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	p1 := Provenance{Source: "s1", DiscoveredAt: t1}
	p2 := Provenance{Source: "s2", DiscoveredAt: t2}
	zero := time.Time{}

	// build is a compact certificate constructor for the table.
	build := func(fp string, prov Provenance, subject, issuer string, serial, sigAlg string, pkAlg string, pkBits int, selfSigned bool, depth int, dnsNames []string, nb, na time.Time) TLSCertificate {
		t.Helper()
		return fullCert(t, fp, prov, subject, issuer, serial, sigAlg, pkAlg, pkBits, selfSigned, depth, dnsNames, nb, na)
	}

	cases := []struct {
		name string
		a, b TLSCertificate
		want TLSCertificate
	}{
		{
			name: "identical observations merge to earliest provenance",
			a:    build(fp, p1, "www.example.com", "issuer", "0a", "sha256", "rsa", 2048, false, 2, []string{"www.example.com"}, t1, t2),
			b:    build(fp, p2, "www.example.com", "issuer", "0a", "sha256", "rsa", 2048, false, 2, []string{"www.example.com"}, t1, t2),
			want: build(fp, p1, "www.example.com", "issuer", "0a", "sha256", "rsa", 2048, false, 2, []string{"www.example.com"}, t1, t2),
		},
		{
			name: "subject conflict: earlier observation wins",
			a:    build(fp, p1, "subject-early", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "subject-late", "", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "subject-early", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "subject conflict: earlier wins in both orders",
			a:    build(fp, p2, "subject-early", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p1, "subject-late", "", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "subject-late", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "subject unset on a: b's value wins",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "subject-b", "", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "subject-b", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "subject unset on b: a's value wins",
			a:    build(fp, p1, "subject-a", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "subject-a", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "issuer conflict: earlier observation wins",
			a:    build(fp, p1, "", "issuer-early", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "issuer-late", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "issuer-early", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "serial conflict: earlier observation wins",
			a:    build(fp, p1, "", "", "0a", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "0b", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "0a", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "sigalg conflict: earlier observation wins",
			a:    build(fp, p1, "", "", "", "sha256", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "sha1", "", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "sha256", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "pkalg conflict: earlier observation wins",
			a:    build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "ecdsa", 256, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
		},
		{
			name: "pubkey bits conflict: earlier observation wins",
			a:    build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "rsa", 4096, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
		},
		{
			name: "pubkey bits unset on b: a's value wins",
			a:    build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "rsa", 0, false, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "rsa", 2048, false, 1, nil, zero, zero),
		},
		{
			name: "self-signed conflict: earlier observation's flag, not OR",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, true, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
		{
			name: "self-signed conflict reversed: earlier observation's flag",
			a:    build(fp, p2, "", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p1, "", "", "", "", "", 0, true, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, true, 1, nil, zero, zero),
		},
		{
			name: "self-signed agreement passes through",
			a:    build(fp, p1, "", "", "", "", "", 0, true, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, true, 1, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, true, 1, nil, zero, zero),
		},
		{
			name: "chain depth is the max",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 2, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 5, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, false, 5, nil, zero, zero),
		},
		{
			name: "chain depth is the max in both orders",
			a:    build(fp, p2, "", "", "", "", "", 0, false, 5, nil, zero, zero),
			b:    build(fp, p1, "", "", "", "", "", 0, false, 2, nil, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, false, 5, nil, zero, zero),
		},
		{
			name: "dns names union sorted and deduplicated",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, []string{"b.example.com", "a.example.com"}, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 1, []string{"c.example.com", "b.example.com"}, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, false, 1, []string{"a.example.com", "b.example.com", "c.example.com"}, zero, zero),
		},
		{
			name: "dns names unset on a: b's list wins",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 1, []string{"x.example.com"}, zero, zero),
			want: build(fp, p1, "", "", "", "", "", 0, false, 1, []string{"x.example.com"}, zero, zero),
		},
		{
			name: "window conflict: earlier observation's window wins",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, nil, fixedTime(10), fixedTime(20)),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 1, nil, fixedTime(11), fixedTime(21)),
			want: build(fp, p1, "", "", "", "", "", 0, false, 1, nil, fixedTime(10), fixedTime(20)),
		},
		{
			name: "notafter unset on a: b's window end wins",
			a:    build(fp, p1, "", "", "", "", "", 0, false, 1, nil, fixedTime(10), zero),
			b:    build(fp, p2, "", "", "", "", "", 0, false, 1, nil, fixedTime(10), fixedTime(20)),
			want: build(fp, p1, "", "", "", "", "", 0, false, 1, nil, fixedTime(10), fixedTime(20)),
		},
		{
			name: "conflict with zero timestamps: unresolvable resolves to a",
			a:    build(fp, Provenance{Source: "s9"}, "subject-a", "", "", "", "", 0, false, 1, nil, zero, zero),
			b:    build(fp, Provenance{Source: "s8"}, "subject-b", "", "", "", "", 0, false, 1, nil, zero, zero),
			want: build(fp, Provenance{Source: "s8"}, "subject-a", "", "", "", "", 0, false, 1, nil, zero, zero),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, err := MergeTLSCertificates(tt.a, tt.b)
			if err != nil {
				t.Fatalf("MergeTLSCertificates: %v", err)
			}
			if !reflect.DeepEqual(m, tt.want) {
				t.Errorf("merged = %#v\nwant   = %#v", m, tt.want)
			}
			if m.ID() != "tls_certificate:"+fp {
				t.Errorf("ID = %q, want tls_certificate:%s", m.ID(), fp)
			}
		})
	}
}

func TestMergeTLSCertificatesIdentityMismatch(t *testing.T) {
	p := Provenance{Source: "manual", DiscoveredAt: fixedTime(10)}
	a, err := NewTLSCertificate(testTLSFingerprint(0x01), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTLSCertificate(testTLSFingerprint(0x02), p)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := MergeTLSCertificates(a, b); err == nil {
		t.Fatal("different fingerprints must refuse to merge")
	} else if !strings.Contains(err.Error(), "identities differ") {
		t.Errorf("error %q does not mention differing identities", err)
	}
}

// TestMergeTLSCertificatesBothOrders pins the merge contract that
// merge(a, b) == merge(b, a) field-for-field whenever the observations'
// DiscoveredAt times differ.
func TestMergeTLSCertificatesBothOrders(t *testing.T) {
	fp := testTLSFingerprint(0x40)
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	a := fullCert(t, fp, Provenance{Source: "s1", DiscoveredAt: t1},
		"subject-a", "issuer-a", "0a1b", "sha256WithRSA", "rsa", 2048, false, 2,
		[]string{"b.example.com", "a.example.com"}, fixedTime(10), fixedTime(20))
	b := fullCert(t, fp, Provenance{Source: "s2", DiscoveredAt: t2},
		"subject-b", "issuer-b", "0a2b", "ecdsa-with-SHA256", "ecdsa", 256, true, 5,
		[]string{"c.example.com", "b.example.com"}, fixedTime(11), fixedTime(21))

	mAB, err := MergeTLSCertificates(a, b)
	if err != nil {
		t.Fatal(err)
	}
	mBA, err := MergeTLSCertificates(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mAB, mBA) {
		t.Errorf("merge(a, b) != merge(b, a):\n a,b: %#v\n b,a: %#v", mAB, mBA)
	}

	// Spot checks on the merged values: a is the earlier observation, so
	// every conflicting bounded field takes a's value.
	if mAB.Subject != "subject-a" || mAB.Issuer != "issuer-a" || mAB.Serial != "0a1b" {
		t.Errorf("earlier observation's bounded fields must win: %#v", mAB)
	}
	if mAB.SignatureAlgorithm != "sha256WithRSA" || mAB.PublicKeyAlgorithm != "rsa" || mAB.PublicKeyBits != 2048 {
		t.Errorf("earlier observation's key fields must win: %#v", mAB)
	}
	if mAB.SelfSigned {
		t.Error("earlier observation's self-signed flag (false) must win, not OR")
	}
	if mAB.ChainDepth != 5 {
		t.Errorf("ChainDepth = %d, want max 5", mAB.ChainDepth)
	}
	if !reflect.DeepEqual(mAB.DNSNames, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Errorf("DNSNames = %v, want the sorted deduped union", mAB.DNSNames)
	}
	if mAB.Prov != (Provenance{Source: "s1", DiscoveredAt: t1}) {
		t.Errorf("Prov = %v, want earliest", mAB.Prov)
	}
	if !mAB.NotBefore.Equal(fixedTime(10)) || !mAB.NotAfter.Equal(fixedTime(20)) {
		t.Errorf("earlier observation's window must win: %v..%v", mAB.NotBefore, mAB.NotAfter)
	}
}

func TestMergeTLSCertificatesDNSNamesCap(t *testing.T) {
	fp := testTLSFingerprint(0x50)
	p1 := Provenance{Source: "s1", DiscoveredAt: fixedTime(10)}
	p2 := Provenance{Source: "s2", DiscoveredAt: fixedTime(12)}
	zero := time.Time{}

	// A union below the cap deduplicates and sorts (overlapping lists).
	a2, err := NewTLSCertificate(fp, p1)
	if err != nil {
		t.Fatal(err)
	}
	a2, err = WithDNSNames(a2, []string{"san-002", "san-001", "san-000"})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewTLSCertificate(fp, p2)
	if err != nil {
		t.Fatal(err)
	}
	b2, err = WithDNSNames(b2, []string{"san-001", "san-003"})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := MergeTLSCertificates(a2, b2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m2.DNSNames, []string{"san-000", "san-001", "san-002", "san-003"}) {
		t.Errorf("union = %v, want the sorted deduped union", m2.DNSNames)
	}

	// A 40-name disjoint union is capped at 32, never an error, and the
	// drop is deterministic: the 32 smallest unique names survive
	// (zero-padded names sort numerically).
	aNames := make([]string, 0, 20)
	bNames := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		aNames = append(aNames, fmt.Sprintf("san-%03d", i))
		bNames = append(bNames, fmt.Sprintf("san-%03d", i+20))
	}
	a := fullCert(t, fp, p1, "", "", "", "", "", 0, false, 1, aNames, zero, zero)
	b := fullCert(t, fp, p2, "", "", "", "", "", 0, false, 1, bNames, zero, zero)
	m, err := MergeTLSCertificates(a, b)
	if err != nil {
		t.Fatalf("a 40-name union must merge without error: %v", err)
	}
	want := make([]string, maxTLSCertificateDNSNames)
	for i := range want {
		want[i] = fmt.Sprintf("san-%03d", i)
	}
	if !reflect.DeepEqual(m.DNSNames, want) {
		t.Errorf("DNSNames = %v, want the first %d sorted unique names %v", m.DNSNames, maxTLSCertificateDNSNames, want)
	}
	if !sort.StringsAreSorted(m.DNSNames) {
		t.Errorf("DNSNames must be sorted: %v", m.DNSNames)
	}

	// The cap merge is order-independent.
	mBA, err := MergeTLSCertificates(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, mBA) {
		t.Errorf("cap merge must be order-independent:\n a,b: %#v\n b,a: %#v", m, mBA)
	}
}

func TestTLSCertificateSerializationRoundTrip(t *testing.T) {
	p := Provenance{Source: "tls-observe", DiscoveredAt: fixedTime(10), Reference: "ref-1", Confidence: 0.9}
	c := fullCert(t, testTLSCertFingerprint, p,
		"www.example.com", "Example Issuer", "0123456789abcdef",
		"sha256WithRSAEncryption", "rsa", 2048, false, 3,
		[]string{"www.example.com", "example.com"}, fixedTime(1), fixedTime(2))

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back TLSCertificate
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v (data: %s)", err, data)
	}
	if !reflect.DeepEqual(back, c) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\njson: %s", back, c, data)
	}
	if back.ID() != c.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), c.ID())
	}
}

func TestTLSCertificateRelationships(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	host, err := NewHost("www.example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	port, err := NewPort(443, "tcp", p)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewTLSCertificate(testTLSCertFingerprint, p)
	if err != nil {
		t.Fatal(err)
	}

	hostEdge, err := NewRelationship(host.Identity(), RelationshipHostToTLSCertificate, c.Identity())
	if err != nil {
		t.Fatalf("host->cert relationship: %v", err)
	}
	want := "host:www.example.com" + "host_to_tls_certificate\x00" + "tls_certificate:" + testTLSCertFingerprint
	if hostEdge.ID() != want {
		t.Errorf("ID = %q, want %q", hostEdge.ID(), want)
	}

	portEdge, err := NewRelationship(port.Identity(), RelationshipPortToTLSCertificate, c.Identity())
	if err != nil {
		t.Fatalf("port->cert relationship: %v", err)
	}
	if portEdge.ID() == hostEdge.ID() {
		t.Error("different kinds must not share an identity")
	}

	// Identical edges deduplicate.
	again, err := NewRelationship(host.Identity(), RelationshipHostToTLSCertificate, c.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if again.ID() != hostEdge.ID() {
		t.Error("identical edges must deduplicate")
	}

	// Reversed edges are distinct.
	rev, err := NewRelationship(c.Identity(), RelationshipHostToTLSCertificate, host.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if rev.ID() == hostEdge.ID() {
		t.Error("reversed edge must not share an identity")
	}
}

func TestTLSCertificateZeroValue(t *testing.T) {
	// The zero TLSCertificate is usable: a zero identity, never a
	// half-formed "tls_certificate:" identity (mirroring the zero-Host
	// fix), so callers can distinguish "no certificate asset". ID() of a
	// zero asset is the zero Identity's string form (":"), exactly like
	// the other assets.
	var c TLSCertificate
	if !c.Identity().IsZero() {
		t.Errorf("zero certificate must have a zero identity, got %v", c.Identity())
	}
	if c.ID() != ":" {
		t.Errorf("zero certificate ID = %q, want the zero identity string \":\"", c.ID())
	}
	if c.String() != "" {
		t.Errorf("zero certificate String = %q, want empty", c.String())
	}

	// Setters work on the zero value: a certificate can be built from
	// scratch, and the zero value never panics anywhere.
	got, err := WithChainDepth(c, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChainDepth != 3 {
		t.Errorf("ChainDepth = %d, want 3", got.ChainDepth)
	}
}
