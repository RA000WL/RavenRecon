package detect

import (
	"fmt"
	"sort"
)

// Category is the typed classification of a rule and of the findings it
// emits. The vocabulary is fixed by the framework; unknown values are
// rejected at registration (mirroring the typed vocabularies of the earlier
// phases).
type Category string

// Rule categories. Every registered rule declares exactly one; every finding
// the rule emits carries the same category (the engine enforces the match).
const (
	CategoryInformation    Category = "information"
	CategoryMisconfig      Category = "misconfiguration"
	CategoryExposure       Category = "exposure"
	CategoryAuthentication Category = "authentication"
	CategoryAuthorization  Category = "authorization"
	CategoryConfiguration  Category = "configuration"
	CategoryDiscovery      Category = "discovery"
	CategoryCloud          Category = "cloud"
	CategoryAPI            Category = "api"
	CategoryJavaScript     Category = "javascript"
	CategorySecrets        Category = "secrets"
	CategoryInfrastructure Category = "infrastructure"
	CategoryBusinessLogic  Category = "business_logic"
	CategoryCustom         Category = "custom"
)

// String returns the canonical lowercase category label.
func (c Category) String() string { return string(c) }

// Valid reports whether c is one of the known categories.
func (c Category) Valid() bool {
	switch c {
	case CategoryInformation, CategoryMisconfig, CategoryExposure,
		CategoryAuthentication, CategoryAuthorization, CategoryConfiguration,
		CategoryDiscovery, CategoryCloud, CategoryAPI, CategoryJavaScript,
		CategorySecrets, CategoryInfrastructure, CategoryBusinessLogic,
		CategoryCustom:
		return true
	}
	return false
}

// ParseCategory parses a canonical category label.
func ParseCategory(s string) (Category, error) {
	c := Category(s)
	if !c.Valid() {
		return "", fmt.Errorf("unknown rule category %q", s)
	}
	return c, nil
}

// Categories returns every known category in canonical sorted order. The
// returned slice is a fresh copy; callers may mutate it freely.
func Categories() []Category {
	return []Category{
		CategoryAPI, CategoryAuthentication, CategoryAuthorization,
		CategoryBusinessLogic, CategoryCloud, CategoryConfiguration,
		CategoryCustom, CategoryDiscovery, CategoryExposure,
		CategoryInformation, CategoryInfrastructure, CategoryJavaScript,
		CategoryMisconfig, CategorySecrets,
	}
}

// sortedCategories is the sorted vocabulary used by validation error
// messages (deterministic diagnostics).
func sortedCategories() []string {
	cats := Categories()
	out := make([]string, len(cats))
	for i, c := range cats {
		out[i] = c.String()
	}
	sort.Strings(out)
	return out
}
