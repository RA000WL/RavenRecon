package asset

// Kind identifies the asset type and namespaces identity values so that
// different asset kinds can never collide on the same key.
type Kind string

// Asset kinds currently implemented.
const (
	KindDomain     Kind = "domain"
	KindHost       Kind = "host"
	KindIP         Kind = "ip"
	KindPort       Kind = "port"
	KindService    Kind = "service"
	KindURL        Kind = "url"
	KindEndpoint   Kind = "endpoint"
	KindJavaScript Kind = "javascript"
	KindParameter  Kind = "parameter"
	KindTechnology Kind = "technology"
	KindEvidence   Kind = "evidence"
	// KindTLSCertificate identifies a TLS leaf certificate by the lowercase
	// hex SHA-256 fingerprint of its DER encoding; the same certificate
	// observed on many hosts is one asset.
	KindTLSCertificate Kind = "tls_certificate"
	// KindSecretCandidate identifies a detected secret candidate observed in
	// an asset. Phase 7 models candidates for DETECTION only: no
	// verification, severity, or exploitation is represented.
	KindSecretCandidate Kind = "secret_candidate"
	// KindSourceMap identifies a source map asset observed at a URL. The
	// model normalizes the observation; source map content is never parsed
	// by the asset layer.
	KindSourceMap Kind = "source_map"
)

// Identity is a namespaced, deterministic asset key used for deduplication.
//
// The Kind namespaces the Value, so for example the domain and host for
// "example.com" are different assets with different identities.
type Identity struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
}

// String returns the canonical "kind:value" representation.
func (i Identity) String() string { return string(i.Kind) + ":" + i.Value }

// Equal reports whether two identities are identical.
func (i Identity) Equal(o Identity) bool { return i == o }

// IsZero reports whether the identity is unset.
func (i Identity) IsZero() bool { return i.Kind == "" }
