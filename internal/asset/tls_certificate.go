package asset

import (
	"fmt"
	"sort"
	"time"
)

// Bounds applied by NewTLSCertificate and the With* builders.
const (
	// maxTLSCertificateSubjectBytes bounds an observed subject CN string.
	// Subjects are observations, not identity: case and punctuation are
	// preserved exactly as observed (see TLSCertificate).
	maxTLSCertificateSubjectBytes = 256
	// maxTLSCertificateIssuerBytes bounds an observed issuer CN string.
	maxTLSCertificateIssuerBytes = 256
	// maxTLSCertificateDNSNames bounds the number of observed SAN DNS
	// names retained per certificate observation.
	maxTLSCertificateDNSNames = 32
	// maxTLSCertificateDNSNameBytes bounds a single SAN DNS name (the DNS
	// name length limit).
	maxTLSCertificateDNSNameBytes = 253
	// maxTLSCertificateSerialBytes bounds an observed serial string (the
	// hex serial as observed).
	maxTLSCertificateSerialBytes = 256
	// maxTLSCertificateSignatureAlgorithmBytes bounds an observed
	// signature algorithm name.
	maxTLSCertificateSignatureAlgorithmBytes = 64
	// maxTLSCertificatePublicKeyAlgorithmBytes bounds an observed public
	// key algorithm name (mirroring the signature algorithm bound).
	maxTLSCertificatePublicKeyAlgorithmBytes = 64
	// maxTLSCertificatePublicKeyBits bounds an observed public key size in
	// bits (0..65536). Zero means "not observed".
	maxTLSCertificatePublicKeyBits = 65536
	// minTLSCertificateChainDepth and maxTLSCertificateChainDepth bound an
	// observed chain length in certificates, leaf included.
	minTLSCertificateChainDepth = 1
	maxTLSCertificateChainDepth = 8
)

// TLSCertificate is a TLS leaf certificate observed serving an asset,
// identified by the lowercase hex SHA-256 fingerprint of its DER encoding.
//
// The fingerprint is the canonical deterministic identity: the same
// certificate observed on many hosts is ONE asset. It must be supplied in
// canonical form — exactly 64 lowercase hex characters; uppercase or
// otherwise non-canonical input is rejected, never coerced, so identity
// inputs are never silently rewritten.
//
// Every other field is an OBSERVATION of that certificate, not part of the
// identity: subject and issuer case is preserved exactly as observed
// (certificate subject strings are observed data, not identity keys), and a
// changed or dropped observation never changes the asset's identity.
// Observed strings are bounded and printable-ASCII-only; the validity window
// is stored exactly as observed (no ordering is enforced between NotBefore
// and NotAfter); SAN DNS names are bounded in count and length but never
// hostname-validated, because SAN entries may legitimately be wildcards
// ("*.example.com"), IP literals, or otherwise non-hostname strings.
type TLSCertificate struct {
	// Fingerprint is the canonical identity: the lowercase hex SHA-256
	// fingerprint of the leaf certificate's DER encoding (64 hex chars).
	Fingerprint string `json:"fingerprint"`

	// Subject is the observed subject CN of the leaf, case-preserved.
	Subject string `json:"subject,omitempty"`

	// Issuer is the observed issuer CN, case-preserved.
	Issuer string `json:"issuer,omitempty"`

	// DNSNames are the observed SAN DNS names, in observation order
	// (MergeTLSCertificates emits the sorted unique union).
	DNSNames []string `json:"dns_names,omitempty"`

	// NotBefore is the observed validity window start.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the observed validity window end.
	NotAfter time.Time `json:"not_after"`

	// Serial is the observed serial number in its hex form.
	Serial string `json:"serial,omitempty"`

	// SignatureAlgorithm is the observed signature algorithm name.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// PublicKeyAlgorithm is the observed public key algorithm name.
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`

	// PublicKeyBits is the observed public key size in bits; zero means
	// not observed.
	PublicKeyBits int `json:"public_key_bits,omitempty"`

	// SelfSigned reports that the leaf was observed self-signed.
	SelfSigned bool `json:"self_signed,omitempty"`

	// ChainDepth is the number of certificates in the observed chain,
	// leaf included (1..8).
	ChainDepth int `json:"chain_depth"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewTLSCertificate builds a validated TLSCertificate carrying the given
// canonical fingerprint and provenance.
//
// The fingerprint must be exactly 64 lowercase hex characters (the SHA-256
// digest of the leaf's DER encoding). Any other form — including uppercase
// hex — is rejected, never coerced: the fingerprint is a canonical identity
// form, and silently rewriting it would blur distinct identity inputs.
func NewTLSCertificate(fingerprint string, p Provenance) (TLSCertificate, error) {
	if err := validateTLSCertificateFingerprint(fingerprint); err != nil {
		return TLSCertificate{}, fmt.Errorf("invalid tls certificate fingerprint %q: %w", fingerprint, err)
	}
	return TLSCertificate{Fingerprint: fingerprint, Prov: p}, nil
}

// validateTLSCertificateFingerprint enforces the canonical fingerprint form:
// exactly 64 lowercase hex characters. Uppercase hex is rejected (the
// canonical form boundary), never lowercased.
func validateTLSCertificateFingerprint(fp string) error {
	if len(fp) != 64 {
		return fmt.Errorf("fingerprint must be exactly 64 lowercase hex characters, got %d", len(fp))
	}
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("fingerprint must contain only lowercase hex characters [0-9a-f], got %q at index %d", c, i)
		}
	}
	return nil
}

// WithSubject returns a copy of t carrying the observed subject CN. It never
// mutates t.
//
// The subject is an observation, not an identity key: case is preserved
// exactly as observed, and no whitespace or case normalization is applied.
// Bounds: at most maxTLSCertificateSubjectBytes bytes of printable ASCII. An
// empty subject is allowed — a certificate may legitimately have an empty
// subject CN, and empty is the "unobserved" value merge treats as unset.
func WithSubject(t TLSCertificate, subject string) (TLSCertificate, error) {
	if err := validateTLSCertificateString("subject", subject, maxTLSCertificateSubjectBytes); err != nil {
		return TLSCertificate{}, err
	}
	out := t
	out.Subject = subject
	return out, nil
}

// WithIssuer returns a copy of t carrying the observed issuer CN. It never
// mutates t. Semantics and bounds mirror WithSubject.
func WithIssuer(t TLSCertificate, issuer string) (TLSCertificate, error) {
	if err := validateTLSCertificateString("issuer", issuer, maxTLSCertificateIssuerBytes); err != nil {
		return TLSCertificate{}, err
	}
	out := t
	out.Issuer = issuer
	return out, nil
}

// WithDNSNames returns a copy of t carrying the observed SAN DNS names. It
// never mutates t, and the list is copied, never aliased: later mutation of
// the caller's slice cannot affect the certificate.
//
// Bounds: at most maxTLSCertificateDNSNames entries, each non-empty and at
// most maxTLSCertificateDNSNameBytes bytes of printable ASCII. Entries are
// NOT hostname-validated: SANs may be wildcards, IP literals, or otherwise
// non-hostname strings, and the list is stored in observation order (merge
// canonicalizes to a sorted unique union).
func WithDNSNames(t TLSCertificate, names []string) (TLSCertificate, error) {
	if len(names) > maxTLSCertificateDNSNames {
		return TLSCertificate{}, fmt.Errorf("tls certificate has %d DNS names, more than the %d maximum", len(names), maxTLSCertificateDNSNames)
	}
	for _, n := range names {
		if n == "" {
			return TLSCertificate{}, fmt.Errorf("tls certificate DNS name must not be empty")
		}
		if len(n) > maxTLSCertificateDNSNameBytes {
			return TLSCertificate{}, fmt.Errorf("tls certificate DNS name is %d bytes, longer than the %d maximum", len(n), maxTLSCertificateDNSNameBytes)
		}
		for i := 0; i < len(n); i++ {
			if n[i] < 0x20 || n[i] > 0x7e {
				return TLSCertificate{}, fmt.Errorf("tls certificate DNS name %q contains a non-printable character", n)
			}
		}
	}
	out := t
	out.DNSNames = append([]string(nil), names...)
	return out, nil
}

// WithValidity returns a copy of t carrying the observed validity window. It
// never mutates t.
//
// The window is stored exactly as observed: no ordering is enforced between
// notBefore and notAfter, and either side may be the zero time ("not
// observed"). Expired and NotYetValid are pure functions of the stored
// window and behave deterministically for any window, including an inverted
// one.
func WithValidity(t TLSCertificate, notBefore, notAfter time.Time) (TLSCertificate, error) {
	out := t
	out.NotBefore = notBefore
	out.NotAfter = notAfter
	return out, nil
}

// WithSerial returns a copy of t carrying the observed serial number. It
// never mutates t. The serial is stored as observed (its expected form is
// hex, e.g. "0a1b2c3d"); only the size and printability bounds apply.
func WithSerial(t TLSCertificate, serial string) (TLSCertificate, error) {
	if err := validateTLSCertificateString("serial", serial, maxTLSCertificateSerialBytes); err != nil {
		return TLSCertificate{}, err
	}
	out := t
	out.Serial = serial
	return out, nil
}

// WithSignatureAlgorithm returns a copy of t carrying the observed signature
// algorithm name. It never mutates t.
func WithSignatureAlgorithm(t TLSCertificate, alg string) (TLSCertificate, error) {
	if err := validateTLSCertificateString("signature algorithm", alg, maxTLSCertificateSignatureAlgorithmBytes); err != nil {
		return TLSCertificate{}, err
	}
	out := t
	out.SignatureAlgorithm = alg
	return out, nil
}

// WithPublicKey returns a copy of t carrying the observed public key
// algorithm and size in bits. It never mutates t. The bits bound is
// 0..maxTLSCertificatePublicKeyBits inclusive; zero means "not observed".
func WithPublicKey(t TLSCertificate, alg string, bits int) (TLSCertificate, error) {
	if err := validateTLSCertificateString("public key algorithm", alg, maxTLSCertificatePublicKeyAlgorithmBytes); err != nil {
		return TLSCertificate{}, err
	}
	if bits < 0 || bits > maxTLSCertificatePublicKeyBits {
		return TLSCertificate{}, fmt.Errorf("tls certificate public key size %d bits is outside 0..%d", bits, maxTLSCertificatePublicKeyBits)
	}
	out := t
	out.PublicKeyAlgorithm = alg
	out.PublicKeyBits = bits
	return out, nil
}

// WithSelfSigned returns a copy of t carrying the observed self-signed flag.
// It never mutates t. The flag is an observation: false is meaningful
// ("not self-signed"), never "unset".
func WithSelfSigned(t TLSCertificate, selfSigned bool) (TLSCertificate, error) {
	out := t
	out.SelfSigned = selfSigned
	return out, nil
}

// WithChainDepth returns a copy of t carrying the observed chain length in
// certificates, leaf included. It never mutates t. The bound is
// minTLSCertificateChainDepth..maxTLSCertificateChainDepth inclusive.
func WithChainDepth(t TLSCertificate, depth int) (TLSCertificate, error) {
	if depth < minTLSCertificateChainDepth || depth > maxTLSCertificateChainDepth {
		return TLSCertificate{}, fmt.Errorf("tls certificate chain depth %d is outside %d..%d", depth, minTLSCertificateChainDepth, maxTLSCertificateChainDepth)
	}
	out := t
	out.ChainDepth = depth
	return out, nil
}

// validateTLSCertificateString enforces the shared bounds for bounded
// observed string fields: at most max bytes of printable ASCII. Empty values
// are allowed: they mean "not observed", and the merge treats them as unset.
func validateTLSCertificateString(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("tls certificate %s is %d bytes, longer than the %d maximum", field, len(s), max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("tls certificate %s %q contains a non-printable character", field, s)
		}
	}
	return nil
}

// Identity returns the deterministic identity used for deduplication. A
// zero TLSCertificate (no fingerprint) has a zero identity, so callers can
// distinguish "no certificate asset" from a fingerprint-carrying one via
// Identity().IsZero.
func (c TLSCertificate) Identity() Identity {
	if c.Fingerprint == "" {
		return Identity{}
	}
	return Identity{Kind: KindTLSCertificate, Value: c.Fingerprint}
}

// ID returns the canonical identity string.
func (c TLSCertificate) ID() string { return c.Identity().String() }

// String returns the canonical fingerprint.
func (c TLSCertificate) String() string { return c.Fingerprint }

// Expired reports whether the certificate's validity window has ended at
// now. The boundary is strict: Expired is true exactly when now is after
// NotAfter, so an observation made exactly at NotAfter is NOT expired. The
// helper is a pure function of the stored window with an injectable clock;
// it never mutates the certificate. A zero window (no NotAfter) is expired
// for any real-world now.
func (c TLSCertificate) Expired(now time.Time) bool { return now.After(c.NotAfter) }

// NotYetValid reports whether the certificate's validity window has not
// begun at now. The boundary is strict: NotYetValid is true exactly when now
// is before NotBefore, so an observation made exactly at NotBefore IS valid.
// The helper is a pure function of the stored window with an injectable
// clock; it never mutates the certificate. A zero window (no NotBefore) is
// not-yet-valid for no real-world now.
func (c TLSCertificate) NotYetValid(now time.Time) bool { return now.Before(c.NotBefore) }

// MergeTLSCertificates combines two observations of the same certificate.
//
// Rules, mirroring the other Merge primitives:
//   - identities (fingerprints) must match exactly, otherwise an error is
//     returned
//   - provenance is the earliest observation's
//   - conflicting bounded observation fields (Subject, Issuer, Serial,
//     SignatureAlgorithm, PublicKeyAlgorithm, PublicKeyBits, NotBefore,
//     NotAfter): the unset value loses to the set one; when both are set and
//     DIFFER, the value from the observation with the EARLIER DiscoveredAt
//     wins, and an exact tie (or an unresolvable comparison, e.g. a zero
//     timestamp) resolves deterministically to a's value. This is
//     deliberately the inverse of preferTechnologyVersion (where the later
//     observation wins): certificate fields describe ONE certificate, and
//     the earliest observation is the canonical record
//   - SelfSigned: on disagreement the earlier observation's flag wins (there
//     is no "unset" flag: false is a meaningful observation), ties resolve to
//     a
//   - DNSNames: unioned, sorted, and deduplicated, capped at
//     maxTLSCertificateDNSNames; entries beyond the cap are DROPPED, never an
//     error — mirroring MergeParameters' drop-not-error cap semantics (the
//     certificate model has no sticky Truncated flag, so the drop is silent
//     and documented here). The sorted-canonical form makes the merge
//     order-independent
//   - ChainDepth: the max of the two observations
//
// The result is deterministic and order-independent: merge(a, b) equals
// merge(b, a) field-for-field whenever the two observations' DiscoveredAt
// times differ (exact ties resolve to the first argument, like the other
// merge primitives).
func MergeTLSCertificates(a, b TLSCertificate) (TLSCertificate, error) {
	if !a.Identity().Equal(b.Identity()) {
		return TLSCertificate{}, mergeMismatch(KindTLSCertificate, a.Identity(), b.Identity())
	}
	m := a
	m.Subject = preferTLSCertificateString(a, b, a.Subject, b.Subject)
	m.Issuer = preferTLSCertificateString(a, b, a.Issuer, b.Issuer)
	m.Serial = preferTLSCertificateString(a, b, a.Serial, b.Serial)
	m.SignatureAlgorithm = preferTLSCertificateString(a, b, a.SignatureAlgorithm, b.SignatureAlgorithm)
	m.PublicKeyAlgorithm = preferTLSCertificateString(a, b, a.PublicKeyAlgorithm, b.PublicKeyAlgorithm)
	m.PublicKeyBits = preferTLSCertificateInt(a, b, a.PublicKeyBits, b.PublicKeyBits)
	m.NotBefore = preferTLSCertificateTime(a, b, a.NotBefore, b.NotBefore)
	m.NotAfter = preferTLSCertificateTime(a, b, a.NotAfter, b.NotAfter)
	m.SelfSigned = preferTLSCertificateSelfSigned(a, b)
	m.DNSNames = mergeTLSCertificateDNSNames(a, b)
	m.ChainDepth = a.ChainDepth
	if b.ChainDepth > m.ChainDepth {
		m.ChainDepth = b.ChainDepth
	}
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// tlsObservedEarlier reports whether b's observation predates a's. A
// zero-time observation on either side is unresolvable and reports false
// (ties resolve to a, the first argument).
func tlsObservedEarlier(a, b TLSCertificate) bool {
	return !a.Prov.DiscoveredAt.IsZero() && !b.Prov.DiscoveredAt.IsZero() && b.Prov.DiscoveredAt.Before(a.Prov.DiscoveredAt)
}

// preferTLSCertificateString picks the deterministic merged value for a
// conflicting bounded string field: the non-empty value wins; when both are
// non-empty and DIFFER, the earlier observation's value wins (see
// MergeTLSCertificates); an exact tie or an unresolvable comparison resolves
// to a's value.
func preferTLSCertificateString(a, b TLSCertificate, av, bv string) string {
	if av == "" {
		return bv
	}
	if bv == "" {
		return av
	}
	if av == bv {
		return av
	}
	if tlsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferTLSCertificateInt is preferTLSCertificateString for ints; zero is
// the unset value (public key size in bits).
func preferTLSCertificateInt(a, b TLSCertificate, av, bv int) int {
	if av == 0 {
		return bv
	}
	if bv == 0 {
		return av
	}
	if av == bv {
		return av
	}
	if tlsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferTLSCertificateTime is preferTLSCertificateString for times; the
// zero time is the unset value.
func preferTLSCertificateTime(a, b TLSCertificate, av, bv time.Time) time.Time {
	if av.IsZero() {
		return bv
	}
	if bv.IsZero() {
		return av
	}
	if av.Equal(bv) {
		return av
	}
	if tlsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferTLSCertificateSelfSigned resolves a disagreement between two
// observations of the self-signed flag. The flag is an observation with no
// "unset" value: false is meaningful ("not self-signed"). On disagreement
// the earlier observation's flag wins; an exact tie resolves to a.
func preferTLSCertificateSelfSigned(a, b TLSCertificate) bool {
	if a.SelfSigned == b.SelfSigned {
		return a.SelfSigned
	}
	if tlsObservedEarlier(a, b) {
		return b.SelfSigned
	}
	return a.SelfSigned
}

// mergeTLSCertificateDNSNames unions two observed SAN name lists into a
// sorted, deduplicated list capped at maxTLSCertificateDNSNames. The result
// is order-independent: both argument orders produce the identical list.
// The union is computed over the full input (duplicates are removed before
// the cap is applied); names beyond the cap are dropped silently, mirroring
// MergeParameters' drop-not-error cap semantics (documented on
// MergeTLSCertificates). The returned slice is fresh and aliases neither
// input.
func mergeTLSCertificateDNSNames(a, b TLSCertificate) []string {
	seen := make(map[string]struct{}, len(a.DNSNames)+len(b.DNSNames))
	for _, n := range a.DNSNames {
		seen[n] = struct{}{}
	}
	for _, n := range b.DNSNames {
		seen[n] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxTLSCertificateDNSNames {
		names = names[:maxTLSCertificateDNSNames]
	}
	if len(names) == 0 {
		return nil
	}
	return names
}
