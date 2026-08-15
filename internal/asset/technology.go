package asset

import (
	"fmt"
	"strings"
)

// TechnologyCategory classifies a Technology asset into one of the 21
// spec-mandated categories. String values are the canonical lowercase forms
// ("cloud_provider", "api_gateway", ...); the value IS the canonical form and
// is embedded in the asset identity, so categories are never normalized at
// use time — unknown values are rejected at construction.
type TechnologyCategory string

const (
	// CategoryFramework: web application frameworks (React, Django, ...).
	CategoryFramework TechnologyCategory = "framework"
	// CategoryLanguage: programming languages (PHP, Python, ...).
	CategoryLanguage TechnologyCategory = "language"
	// CategoryRuntime: language runtimes (Node.js, ...).
	CategoryRuntime TechnologyCategory = "runtime"
	// CategoryServer: web servers (nginx, Apache, ...).
	CategoryServer TechnologyCategory = "server"
	// CategoryProxy: reverse proxies and load balancers (HAProxy, Varnish, ...).
	CategoryProxy TechnologyCategory = "proxy"
	// CategoryCDN: content delivery networks (Cloudflare, Akamai, ...).
	CategoryCDN TechnologyCategory = "cdn"
	// CategoryWAF: web application firewalls (Imperva, Sucuri, ...).
	CategoryWAF TechnologyCategory = "waf"
	// CategoryCloudProvider: cloud platforms (AWS, Azure, ...).
	CategoryCloudProvider TechnologyCategory = "cloud_provider"
	// CategoryBuildTool: frontend build tools (Webpack, Vite, ...).
	CategoryBuildTool TechnologyCategory = "build_tool"
	// CategoryAuthentication: authentication and session systems (Auth0,
	// Keycloak, session-cookie conventions, ...).
	CategoryAuthentication TechnologyCategory = "authentication"
	// CategoryAnalytics: analytics and tracking (Google Analytics, Matomo, ...).
	CategoryAnalytics TechnologyCategory = "analytics"
	// CategoryCMS: content management systems (WordPress, Drupal, ...).
	CategoryCMS TechnologyCategory = "cms"
	// CategoryDatabase: databases (MySQL, PostgreSQL, ...).
	CategoryDatabase TechnologyCategory = "database"
	// CategorySearchEngine: search engines (Elasticsearch, Solr, ...).
	CategorySearchEngine TechnologyCategory = "search_engine"
	// CategoryGraphQL: GraphQL servers and clients.
	CategoryGraphQL TechnologyCategory = "graphql"
	// CategoryMessageQueue: message queues (RabbitMQ, Kafka, ...).
	CategoryMessageQueue TechnologyCategory = "message_queue"
	// CategoryAPIGateway: API gateways (Kong, Tyk, ...).
	CategoryAPIGateway TechnologyCategory = "api_gateway"
	// CategoryMonitoring: monitoring and observability (Grafana, Sentry, ...).
	CategoryMonitoring TechnologyCategory = "monitoring"
	// CategoryStorage: object storage (S3, GCS, ...).
	CategoryStorage TechnologyCategory = "storage"
	// CategoryContainer: container runtimes (Docker, containerd).
	CategoryContainer TechnologyCategory = "container"
	// CategoryOrchestration: container orchestration (Kubernetes, Nomad, ...).
	CategoryOrchestration TechnologyCategory = "orchestration"
)

// String returns the canonical lowercase category value.
func (c TechnologyCategory) String() string { return string(c) }

// Valid reports whether c is one of the 21 known categories.
func (c TechnologyCategory) Valid() bool {
	switch c {
	case CategoryFramework, CategoryLanguage, CategoryRuntime, CategoryServer,
		CategoryProxy, CategoryCDN, CategoryWAF, CategoryCloudProvider,
		CategoryBuildTool, CategoryAuthentication, CategoryAnalytics, CategoryCMS,
		CategoryDatabase, CategorySearchEngine, CategoryGraphQL, CategoryMessageQueue,
		CategoryAPIGateway, CategoryMonitoring, CategoryStorage, CategoryContainer,
		CategoryOrchestration:
		return true
	}
	return false
}

// ParseTechnologyCategory validates s and returns the canonical category.
// An unknown value is an error: categories are never silently coerced.
func ParseTechnologyCategory(s string) (TechnologyCategory, error) {
	c := TechnologyCategory(s)
	if !c.Valid() {
		return "", fmt.Errorf("unknown technology category %q", s)
	}
	return c, nil
}

// KnownCategories returns every category in canonical sorted order. The
// returned slice is a fresh copy; callers may mutate it freely.
func KnownCategories() []TechnologyCategory {
	return []TechnologyCategory{
		CategoryAnalytics, CategoryAPIGateway, CategoryAuthentication,
		CategoryBuildTool, CategoryCDN, CategoryCloudProvider, CategoryCMS,
		CategoryContainer, CategoryDatabase, CategoryFramework, CategoryGraphQL,
		CategoryLanguage, CategoryMessageQueue, CategoryMonitoring,
		CategoryOrchestration, CategoryProxy, CategoryRuntime, CategorySearchEngine,
		CategoryServer, CategoryStorage, CategoryWAF,
	}
}

// Single-observation bounds applied by NewTechnology and WithVersion.
const (
	// maxTechnologyNameBytes bounds a canonical technology name. Names are
	// embedded in the identity value, so this also bounds identity sizes.
	maxTechnologyNameBytes = 128
	// maxTechnologyVersionBytes bounds an observed version string. Versions
	// are observations, not identity: a changed or dropped version never
	// changes the technology's identity.
	maxTechnologyVersionBytes = 64
)

// Technology is a technology detected on an asset, identified by its
// canonical name within its category.
//
// The canonical name form is: surrounding whitespace trimmed, lowercased,
// and every internal whitespace run collapsed to a single space
// ("API   Gateway" -> "api gateway"). Only printable ASCII is accepted.
// The identity is "category/name" ("cdn/cloudflare"), so the same name in
// two categories is two distinct technologies and deduplication is exact.
//
// Version is an OBSERVED version string and is deliberately not part of the
// identity: two observations of the same technology with different version
// strings are the same asset.
type Technology struct {
	// Name is the canonical technology name, e.g. "cloudflare" or "next.js".
	Name string `json:"name"`

	// Category classifies the technology (see TechnologyCategory).
	Category TechnologyCategory `json:"category"`

	// Version is an optional observed version string, e.g. "1.25.3". Not
	// part of the identity.
	Version string `json:"version,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewTechnology validates and normalizes name into a Technology.
func NewTechnology(name string, category TechnologyCategory, p Provenance) (Technology, error) {
	canonical, err := canonicalTechnologyName(name)
	if err != nil {
		return Technology{}, fmt.Errorf("invalid technology name %q: %w", name, err)
	}
	if !category.Valid() {
		return Technology{}, fmt.Errorf("invalid technology category %q", category)
	}
	return Technology{Name: canonical, Category: category, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity value is "category/name" with the name percent-encoded
// (service.go's percentEncode), so a "/" or ":" inside a name can never blur
// the category/name boundary: distinct names always produce distinct
// identity values. Version never enters the identity.
func (t Technology) Identity() Identity {
	return Identity{Kind: KindTechnology, Value: string(t.Category) + "/" + percentEncode(t.Name)}
}

// ID returns the canonical identity string.
func (t Technology) ID() string { return t.Identity().String() }

// String returns the canonical identity value, e.g. "cdn/cloudflare".
func (t Technology) String() string { return string(t.Category) + "/" + percentEncode(t.Name) }

// WithVersion returns a copy of t carrying the observed version. It never
// mutates t. The version must be non-empty, at most maxTechnologyVersionBytes
// bytes, and printable ASCII; the identity is unaffected.
func WithVersion(t Technology, version string) (Technology, error) {
	if err := validateTechnologyVersion(version); err != nil {
		return Technology{}, err
	}
	out := t
	out.Version = version
	return out, nil
}

// canonicalTechnologyName normalizes a technology name into its canonical
// form: surrounding whitespace trimmed, lowercased, internal whitespace runs
// collapsed to a single space. Non-printable and non-ASCII bytes are
// rejected; the canonical form is ASCII-only so identity values stay safe to
// embed in cache keys and paths.
func canonicalTechnologyName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", fmt.Errorf("technology name must not be empty")
	}
	if len(name) > maxTechnologyNameBytes {
		return "", fmt.Errorf("technology name is longer than %d bytes", maxTechnologyNameBytes)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return "", fmt.Errorf("technology name %q contains a non-printable character", name)
		}
	}
	return name, nil
}

// validateTechnologyVersion enforces the version bounds: non-empty, at most
// maxTechnologyVersionBytes bytes, printable ASCII. Versions are opaque
// observed bytes (e.g. "nginx/1.25.3 (Ubuntu)"); only the size and
// printability bounds apply.
func validateTechnologyVersion(version string) error {
	if version == "" {
		return fmt.Errorf("technology version must not be empty")
	}
	if len(version) > maxTechnologyVersionBytes {
		return fmt.Errorf("technology version is longer than %d bytes", maxTechnologyVersionBytes)
	}
	for i := 0; i < len(version); i++ {
		if version[i] < 0x20 || version[i] > 0x7e {
			return fmt.Errorf("technology version %q contains a non-printable character", version)
		}
	}
	return nil
}

// MergeTechnologies combines two observations of the same technology.
//
// Rules, mirroring the other Merge primitives:
//   - identities must match exactly, otherwise an error is returned
//   - provenance is the earliest observation's
//   - version selection: the non-empty version is preferred; when both are
//     non-empty and DIFFER, the version observed later wins (later
//     DiscoveredAt), and an exact tie resolves deterministically to a's
//     version
func MergeTechnologies(a, b Technology) (Technology, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Technology{}, mergeMismatch(KindTechnology, a.Identity(), b.Identity())
	}
	m := a
	m.Version = preferTechnologyVersion(a, b)
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// preferTechnologyVersion implements the deterministic version selection
// documented on MergeTechnologies.
func preferTechnologyVersion(a, b Technology) string {
	if a.Version == "" {
		return b.Version
	}
	if b.Version == "" {
		return a.Version
	}
	if a.Version == b.Version {
		return a.Version
	}
	// Both non-empty and different: the later observation wins; an exact
	// tie (or two zero timestamps) resolves to a, the first argument.
	if b.Prov.DiscoveredAt.After(a.Prov.DiscoveredAt) {
		return b.Version
	}
	return a.Version
}
