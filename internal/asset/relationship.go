package asset

import (
	"fmt"
	"strings"
)

// RelationshipKind identifies the semantic meaning of a Relationship edge.
type RelationshipKind string

// Relationship kinds mirror the hierarchy recon stages are expected to produce.
// They are generic and do not reference specific tools or binaries.
const (
	// RelationshipHostToIP links a resolved host to its address (Host -> IP).
	RelationshipHostToIP RelationshipKind = "host_to_ip"
	// RelationshipHostToCNAME links a host to the canonical target of its
	// CNAME record (Host -> Host). The target is the final canonical name as
	// observed by the resolver; see the DNS pipeline's documented multi-hop
	// flattening limitation.
	RelationshipHostToCNAME RelationshipKind = "host_to_cname"
	// RelationshipIPToPort links a listening address to a port (IP -> Port).
	RelationshipIPToPort RelationshipKind = "ip_to_port"
	// RelationshipPortToService links a port to a service identified on it
	// (Port -> Service).
	RelationshipPortToService RelationshipKind = "port_to_service"
	// RelationshipHostToURL links a host to a URL served on it (Host -> URL).
	RelationshipHostToURL RelationshipKind = "host_to_url"
	// RelationshipURLToEndpoint links a base URL to an endpoint derived from it
	// (URL -> Endpoint).
	RelationshipURLToEndpoint RelationshipKind = "url_to_endpoint"
	// RelationshipURLToJavaScript links a page URL to a script resource it
	// references (URL -> JavaScript).
	RelationshipURLToJavaScript RelationshipKind = "url_to_javascript"
	// RelationshipURLToParameter links a URL to a parameter observed in it
	// (URL -> Parameter).
	RelationshipURLToParameter RelationshipKind = "url_to_parameter"
	// RelationshipEndpointToParameter links an endpoint to a parameter
	// observed in it (Endpoint -> Parameter).
	RelationshipEndpointToParameter RelationshipKind = "endpoint_to_parameter"
	// RelationshipHostToTechnology links a host to a technology observed on
	// it (Host -> Technology).
	RelationshipHostToTechnology RelationshipKind = "host_to_technology"
	// RelationshipURLToTechnology links a URL to a technology observed on it
	// (URL -> Technology).
	RelationshipURLToTechnology RelationshipKind = "url_to_technology"
	// RelationshipEndpointToTechnology links an endpoint to a technology
	// observed on it (Endpoint -> Technology).
	RelationshipEndpointToTechnology RelationshipKind = "endpoint_to_technology"
	// RelationshipTechnologyToEvidence links a technology to the evidence
	// observation that supported its detection (Technology -> Evidence).
	RelationshipTechnologyToEvidence RelationshipKind = "technology_to_evidence"
	// RelationshipHostToTLSCertificate links a host to the TLS certificate
	// observed serving it (Host -> TLSCertificate).
	RelationshipHostToTLSCertificate RelationshipKind = "host_to_tls_certificate"
	// RelationshipPortToTLSCertificate links a port to the TLS certificate
	// observed on it (Port -> TLSCertificate).
	RelationshipPortToTLSCertificate RelationshipKind = "port_to_tls_certificate"
	// RelationshipJavaScriptToJavaScript links a script resource to another
	// script resource it imports (JavaScript -> JavaScript).
	RelationshipJavaScriptToJavaScript RelationshipKind = "javascript_to_javascript"
	// RelationshipJavaScriptToEndpoint links a script resource to an endpoint
	// candidate it references (JavaScript -> Endpoint).
	RelationshipJavaScriptToEndpoint RelationshipKind = "javascript_to_endpoint"
	// RelationshipJavaScriptToSecretCandidate links a script resource to a
	// secret candidate observed in it (JavaScript -> SecretCandidate).
	RelationshipJavaScriptToSecretCandidate RelationshipKind = "javascript_to_secret_candidate"
	// RelationshipJavaScriptToSourceMap links a script resource to the source
	// map observed for it (JavaScript -> SourceMap).
	RelationshipJavaScriptToSourceMap RelationshipKind = "javascript_to_source_map"
	// RelationshipJavaScriptToTechnology links a script resource to a
	// technology observed in it (JavaScript -> Technology).
	RelationshipJavaScriptToTechnology RelationshipKind = "javascript_to_technology"
	// RelationshipURLToSecretCandidate links a URL asset to a secret
	// candidate observed in the content served at it (URL ->
	// SecretCandidate). Phase 8: documents scanned by the secret
	// intelligence engine that came from a canonical URL.
	RelationshipURLToSecretCandidate RelationshipKind = "url_to_secret_candidate"
	// RelationshipSecretCandidateToEvidence links a secret candidate to the
	// evidence observation that supported its classification
	// (SecretCandidate -> Evidence). Phase 8: the pattern match, entropy
	// assessment, context signals, and correlation records behind a
	// candidate.
	RelationshipSecretCandidateToEvidence RelationshipKind = "secret_candidate_to_evidence"
)

// Relationship is a typed, directed edge between two asset identities.
//
// It is the primitive a future correlation engine uses to build the asset
// graph. This phase provides the representation only — no graph storage or
// traversal.
type Relationship struct {
	// From is the identity of the source asset.
	From Identity `json:"from"`

	// Kind describes the edge semantics.
	Kind RelationshipKind `json:"kind"`

	// To is the identity of the destination asset.
	To Identity `json:"to"`
}

// NewRelationship validates and builds a Relationship.
func NewRelationship(from Identity, kind RelationshipKind, to Identity) (Relationship, error) {
	if from.IsZero() {
		return Relationship{}, fmt.Errorf("relationship source must not be zero")
	}
	if strings.TrimSpace(string(kind)) == "" {
		return Relationship{}, fmt.Errorf("relationship kind must not be empty")
	}
	if to.IsZero() {
		return Relationship{}, fmt.Errorf("relationship destination must not be zero")
	}
	return Relationship{From: from, Kind: kind, To: to}, nil
}

// ID returns a deterministic identity, so the same directed edge added twice
// deduplicates while the reverse or differently-kind edge stays distinct.
func (r Relationship) ID() string {
	return r.From.String() + string(r.Kind) + "\x00" + r.To.String()
}
