package priority

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// synthSignals builds n deterministic, distinct signals spanning the
// catalog's signal families (paths, hosts, techs, secrets, params,
// headers, ports, services).
func synthSignals(n int) []Signal {
	paths := []string{
		"/api/v2/admin", "/actuator/health", "/static/app.js.map", "/graphql",
		"/search", "/home", "/api/v1/users", "/upload/avatars", "/.well-known/security.txt",
	}
	techs := []struct {
		name, cat string
		conf      float64
	}{
		{"express", "framework", 0.85},
		{"auth0", "authentication", 0.9},
		{"aws", "cloud_provider", 0.8},
		{"kibana", "monitoring", 0.7},
	}
	secrets := []struct {
		typ   asset.SecretType
		conf  float64
		value string
	}{
		{asset.SecretTypeAWS, 0.85, "secret_candidate:aws/x/y"},
		{asset.SecretTypeJWT, 0.7, "secret_candidate:jwt/x/y"},
		{asset.SecretTypeDatabaseURL, 0.75, "secret_candidate:database_url/x/y"},
	}
	sigs := make([]Signal, 0, n)
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("sub%03d.example.com", i%200)
		sig := Signal{
			Identity: asset.Identity{
				Kind:  asset.KindURL,
				Value: fmt.Sprintf("https://%s%s/item%06d", host, paths[i%len(paths)], i),
			},
			Kind:     asset.KindURL,
			Path:     fmt.Sprintf("%s/item%06d", paths[i%len(paths)], i),
			Hostname: host,
			ScoredAt: fixedTime(1),
		}
		if i%3 == 0 {
			tt := techs[i%len(techs)]
			sig.Technologies = []TechSignal{{
				Name: tt.name, Category: tt.cat, Confidence: tt.conf,
				Identity: tt.cat + "/" + tt.name,
			}}
		}
		if i%5 == 0 {
			ss := secrets[i%len(secrets)]
			sig.Secrets = []SecretSignal{{Type: ss.typ, Confidence: ss.conf, Identity: ss.value}}
		}
		if i%7 == 0 {
			sig.ParameterNames = []string{"query", "feature_flag"}
		}
		if i%11 == 0 {
			sig.Headers = []string{"x-powered-by: express"}
		}
		if i%13 == 0 {
			sig.Port = 8080
			sig.Service = "grafana"
		}
		sigs = append(sigs, sig)
	}
	return sigs
}

// feedAsync streams signals through a bounded channel (the production
// shape: a producer feeding the engine).
func feedAsync(sigs []Signal) chan Signal {
	ch := make(chan Signal, 1024)
	go func() {
		defer close(ch)
		for _, s := range sigs {
			ch <- s
		}
	}()
	return ch
}

// BenchmarkEngineScore100K measures 100k synthetic assets through the
// engine with 8 bounded workers and no cache: the pure score-throughput
// number.
func BenchmarkEngineScore100K(b *testing.B) {
	sigs := synthSignals(100_000)
	cfg := EngineConfig{Concurrency: 8, QueueSize: 1024, Clock: newEngineClock()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, err := Score(context.Background(), cfg, feedAsync(sigs))
		if err != nil {
			b.Fatal(err)
		}
		if rep.Completed != 100_000 {
			b.Fatalf("completed = %d", rep.Completed)
		}
	}
}

// BenchmarkEngineScore100KWarmCache measures the same run against a warm
// cache: every asset served from a validated cache hit, zero scorings. The
// setup pass warms the cache once (100k stores) and reports the average
// stored record size for the memory math.
func BenchmarkEngineScore100KWarmCache(b *testing.B) {
	sigs := synthSignals(100_000)
	fs := openBenchCache(b)
	cfg := EngineConfig{Concurrency: 8, QueueSize: 1024, Clock: newEngineClock(), Cache: fs}

	warm, err := Score(context.Background(), cfg, feedAsync(sigs))
	if err != nil {
		b.Fatal(err)
	}
	if warm.Completed != 100_000 {
		b.Fatalf("warmup completed = %d", warm.Completed)
	}
	var surfaceBytes int64
	for _, r := range warm.Assets {
		surfaceBytes += int64(len(marshalSurface(r.Surface)))
	}
	b.ReportMetric(float64(surfaceBytes)/float64(len(warm.Assets)), "surface-bytes/asset")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, err := Score(context.Background(), cfg, feedAsync(sigs))
		if err != nil {
			b.Fatal(err)
		}
		if rep.Completed != 100_000 || rep.Scored != 0 {
			b.Fatalf("completed = %d scored = %d (warm run must score nothing)", rep.Completed, rep.Scored)
		}
	}
}

// openBenchCache opens a cache in a fresh temp dir for benchmarks.
func openBenchCache(b *testing.B) *cache.FS {
	b.Helper()
	dir := filepath.Join(b.TempDir(), "cache")
	c, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	return c
}
