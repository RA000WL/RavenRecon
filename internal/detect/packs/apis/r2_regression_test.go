package apis

import (
	"context"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// The pins in this file are the REVIEW-2026-08-25.md R2-M4 precision
// regressions for the apis pack: year-shaped and pagination segments must
// not fire the REST IDOR indicator, and the GraphQL rule's introspection
// signal requires an actual introspection marker — bare path presence,
// a technology name, or any "graphql"-word evidence value is not enough.

func runApisSnapshot(t *testing.T, reg *detect.Registry, snap detect.Snapshot) detect.Report {
	t.Helper()
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// TestRestIDORExcludesYearAndPagination is the R2-M4 regression: an
// all-digit segment that is year-shaped (1900-2100) or short pagination
// (1-2 digits) is not an ID-oracle indicator. Before the fix both fired.
// A longer id-shaped segment still fires (the control guards against the
// exclusion collapsing into silence).
func TestRestIDORExcludesYearAndPagination(t *testing.T) {
	reg := registerApisPack(t)
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{
		mustEndpoint(t, "GET", "https://www.example.com/api/users/2024/profile"), // year-shaped
		mustEndpoint(t, "GET", "https://www.example.com/api/items/12/list"),      // 1-2 digit pagination
		mustEndpoint(t, "GET", "https://www.example.com/api/orders/54321/items"), // genuine id-shaped segment
	}}
	rep := runApisSnapshot(t, reg, snap)
	count := 0
	for _, f := range rep.Findings {
		if f.RuleID != ruleRestIDORIndicator {
			continue
		}
		count++
		if !strings.Contains(f.Subject.Value, "/orders/54321/") {
			t.Errorf("idor finding on unexpected subject %q, want only the id-shaped segment", f.Subject.Value)
		}
	}
	if count != 1 {
		t.Fatalf("rest idor findings = %d, want 1 (only /54321/); year and pagination segments must stay silent", count)
	}
}

// TestGraphQLRequiresIntrospectionSignal is the R2-M4 regression for the
// graphql rule's split signals. Bare /graphql path presence, a GraphQL
// technology name, and evidence whose value merely contains "graphql" are
// endpoint-grade carriers only; the "graphql_introspection" signal requires
// an actual marker ("__schema" or "introspection"). Before the fix every
// carrier emitted findings carrying the introspection signal.
func TestGraphQLRequiresIntrospectionSignal(t *testing.T) {
	reg := registerApisPack(t)

	t.Run("bare path, technology, and graphql-word value stay below introspection grade", func(t *testing.T) {
		host := mustHost(t, "www.example.com")
		ep := mustEndpoint(t, "POST", "https://www.example.com/graphql")
		ev := mustEvidence(t, asset.MethodHeader, "header:x-app-backend", "app-server (graphql enabled)", host.Identity())
		snap := detect.Snapshot{
			Endpoints:    []asset.Endpoint{ep},
			Evidence:     []asset.Evidence{ev},
			Technologies: []asset.Technology{mustTechnology(t, "GraphQL Gateway", asset.CategoryServer)},
		}
		rep := runApisSnapshot(t, reg, snap)
		count := 0
		for _, f := range rep.Findings {
			if f.RuleID != ruleGraphQLIntrospection {
				continue
			}
			count++
			if sig := f.Metadata["signal"]; sig != "graphql_endpoint" {
				t.Fatalf("graphql finding carries signal %q from a corpus with no introspection marker, want \"graphql_endpoint\" only", sig)
			}
		}
		if count != 1 {
			t.Fatalf("graphql findings = %d, want 1 (the bare endpoint carrier)", count)
		}
	})

	t.Run("explicit __schema marker upgrades to the introspection signal", func(t *testing.T) {
		host := mustHost(t, "www.example.com")
		ep := mustEndpoint(t, "POST", "https://www.example.com/graphql")
		ev := mustEvidence(t, asset.MethodHTML, "html:graphql-introspection", `{"data":{"__schema":{"types":[]}}}`, host.Identity())
		snap := detect.Snapshot{
			Endpoints: []asset.Endpoint{ep},
			Evidence:  []asset.Evidence{ev},
		}
		rep := runApisSnapshot(t, reg, snap)
		signals := map[string]int{}
		for _, f := range rep.Findings {
			if f.RuleID != ruleGraphQLIntrospection {
				continue
			}
			signals[f.Metadata["signal"]]++
		}
		if signals["graphql_introspection"] != 1 || signals["graphql_endpoint"] != 1 {
			t.Fatalf("signals = %v, want exactly one \"graphql_introspection\" (evidence source) and one \"graphql_endpoint\" (path carrier)", signals)
		}
	})
}
