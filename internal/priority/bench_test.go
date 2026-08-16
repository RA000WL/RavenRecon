package priority

import (
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func BenchmarkScoreEndpoint(b *testing.B) {
	ic, err := LoadInterestingness()
	if err != nil {
		b.Fatal(err)
	}
	rc, err := LoadRisk()
	if err != nil {
		b.Fatal(err)
	}
	sig := Signal{
		Identity: asset.Identity{Kind: asset.KindEndpoint, Value: "GET https://www.example.com/api/v2/users"},
		Kind:     asset.KindEndpoint,
		Path:     "/api/v2/users",
		Hostname: "www.example.com",
		Technologies: []TechSignal{
			{Name: "express", Category: "framework", Confidence: 0.85},
		},
		ParameterNames: []string{"query", "page"},
		Observations:   2,
		ScoredAt:       fixedTime(1),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScoreSurface(sig, ic, rc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScoreLargeCatalogHit(b *testing.B) {
	ic, err := LoadInterestingness()
	if err != nil {
		b.Fatal(err)
	}
	rc, err := LoadRisk()
	if err != nil {
		b.Fatal(err)
	}
	var techs, secrets = make([]TechSignal, 0, 12), make([]SecretSignal, 0, 6)
	for i := 0; i < 12; i++ {
		techs = append(techs, TechSignal{
			Name:       fmt.Sprintf("tech-%d", i),
			Category:   []string{"framework", "cloud_provider", "authentication", "monitoring", "graphql", "build_tool"}[i%6],
			Confidence: 0.5 + float64(i)/25,
		})
	}
	for i, typ := range []asset.SecretType{
		asset.SecretTypeAWS, asset.SecretTypeJWT, asset.SecretTypeGitHub,
		asset.SecretTypeDatabaseURL, asset.SecretTypeStripe, asset.SecretTypeOAuth,
	} {
		secrets = append(secrets, SecretSignal{Type: typ, Confidence: 0.5 + float64(i)/12})
	}
	sig := Signal{
		Identity:       asset.Identity{Kind: asset.KindEndpoint, Value: "GET https://admin.internal.example.com/api/v2/admin/actuator/swagger"},
		Kind:           asset.KindEndpoint,
		Path:           "/api/v2/admin/actuator/swagger/graphql/debug",
		Hostname:       "admin.internal.example.com",
		Port:           9090,
		Service:        "grafana",
		Headers:        []string{"x-powered-by: php/8.2", "x-runtime: 0.123", "content-type: text/html"},
		Technologies:   techs,
		Secrets:        secrets,
		ParameterNames: []string{"query", "feature_flag", "file", "attachment"},
		Observations:   4,
		ScoredAt:       fixedTime(1),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScoreSurface(sig, ic, rc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScoreNoHit(b *testing.B) {
	ic, err := LoadInterestingness()
	if err != nil {
		b.Fatal(err)
	}
	rc, err := LoadRisk()
	if err != nil {
		b.Fatal(err)
	}
	sig := Signal{
		Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/"},
		Kind:     asset.KindURL,
		Path:     "/home",
		Hostname: "www.example.com",
		ScoredAt: fixedTime(1),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScoreSurface(sig, ic, rc); err != nil {
			b.Fatal(err)
		}
	}
}
