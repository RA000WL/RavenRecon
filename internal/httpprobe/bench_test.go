package httpprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Benchmarks exercise the full probe path hermetically: loopback HTTP and
// TLS servers behind the probe seam (every request keeps its canonical host
// — Host header and SNI — while the transport dials the resolved loopback
// address), a real bounded runtime.Pool, and a real filesystem-backed Phase
// 3 cache (no public Internet). They are command-gated (-bench only).
//
// Timing reality (measured 2026-08-14 on the benchmark machine,
// -benchtime=1x): the 10/100/1k workloads run in seconds (≈0.14 s, ≈1.1 s,
// and ≈10 s per cold pass); the 10k cold pass is ≈93 s, and the hit pass's
// UNTIMED warm-up costs the same ≈93 s again before its ≈0.3 s timed
// iteration — run them with -benchtime=1x and allow ≈3.5 minutes for the
// full 10/100/1k/10k cold+hit set, or ≈4.5 minutes for the spot command
// that also includes the ≈46 s concurrency sweep. Under `go test -short`
// (the CI-style default) the 10k workloads are skipped entirely, keeping
// the suite bounded; the 1k concurrency sweep still runs.
//
// Each host is probed at its two root targets (http+https): two requests
// per host on the cold pass, two cache records per host, and two pure
// cache hits per host on the hit pass — the hit pass's zero-request
// assertion pins that.

// benchWorkload is one benchmark sizing.
type benchWorkload struct {
	name  string
	hosts int
}

var benchWorkloads = []benchWorkload{
	{"10", 10},
	{"100", 100},
	{"1000", 1000},
	{"10000", 10000},
}

// benchHosts builds n deterministic in-scope hosts (h0..hN-1.example.com).
func benchHosts(n int) []asset.Host {
	hosts := make([]asset.Host, 0, n)
	for i := 0; i < n; i++ {
		h, err := asset.NewHost(fmt.Sprintf("h%d.example.com", i), asset.Provenance{})
		if err != nil {
			panic(err)
		}
		hosts = append(hosts, h)
	}
	return hosts
}

// wildcardCert returns a fresh self-signed ECDSA certificate covering
// *.example.com (the benchmark hosts), so every https probe completes a
// real TLS handshake with the loopback server. Generated per call — the
// benchmarks never share mutable state.
func wildcardCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "*.example.com"},
		DNSNames:              []string{"*.example.com", "example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// benchServer is a counting loopback server for the benchmarks: it counts
// requests and always answers 200 with a fixed body. The TLS variant
// terminates real handshakes with the wildcard *.example.com certificate.
type benchServer struct {
	srv *httptest.Server

	mu sync.Mutex
	n  int
}

// newBenchServer starts the server; tlsServer selects the TLS variant.
func newBenchServer(b *testing.B, tlsServer bool) *benchServer {
	b.Helper()
	bs := &benchServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bs.mu.Lock()
		bs.n++
		bs.mu.Unlock()
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	if tlsServer {
		cert, err := wildcardCert()
		if err != nil {
			b.Fatalf("wildcard cert: %v", err)
		}
		bs.srv = httptest.NewUnstartedServer(handler)
		bs.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		bs.srv.StartTLS()
	} else {
		bs.srv = httptest.NewServer(handler)
	}
	b.Cleanup(bs.srv.Close)
	return bs
}

// count reports the number of served requests.
func (bs *benchServer) count() int {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.n
}

// benchConfigAt returns the fixed benchmark configuration: real pool at the
// given concurrency, no rate limiting (throughput measurement), the loopback
// servers behind the probe seam, and the real FS cache rooted at dir. A
// cache open failure is fatal for the benchmark: silently proceeding would
// turn every cold pass into an uncached run and invalidate the
// measurements.
func benchConfigAt(b *testing.B, dir string, concurrency int, httpSrv, httpsSrv *benchServer) Config {
	cfg := DefaultConfig()
	cfg.Concurrency = concurrency
	cfg.QueueSize = 256
	cfg.Timeout = 0 // no per-job deadline: the loopback servers never block
	cfg.Rate = 0    // pacing disabled: the benchmark measures raw throughput
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(b, httpSrv.srv),
		httpsRT: transportFor(b, httpsSrv.srv),
	}
	c, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c
	return cfg
}

// benchConfig returns the fixed benchmark configuration at the default
// benchmark concurrency (16) shared by the fixed-concurrency passes.
func benchConfig(b *testing.B, dir string, httpSrv, httpsSrv *benchServer) Config {
	return benchConfigAt(b, dir, 16, httpSrv, httpsSrv)
}

// benchProbeAt runs the probe pipeline for one workload at one concurrency.
// When hitPass is false the cold pass is timed (two requests and two cache
// writes per host, all misses); when true an untimed warm-up pass populates
// the cache BEFORE the timed loop starts, so every timed iteration (all
// b.N of them) is a pure cache hit — the timed loop is never mixed with
// warm-up work, and the zero-request assertion checks the whole timed loop
// after it finishes.
func benchProbeAt(b *testing.B, wl benchWorkload, hitPass bool, concurrency int) {
	// The 10k workloads take minutes per pass; under -short they are
	// skipped so CI-style runs stay bounded (see the file header).
	if testing.Short() && wl.hosts >= 10000 {
		b.Skip("10k workloads take minutes each; skipped under -short")
	}

	hosts := benchHosts(wl.hosts)
	httpSrv := newBenchServer(b, false)
	httpsSrv := newBenchServer(b, true)
	cfg := benchConfigAt(b, b.TempDir(), concurrency, httpSrv, httpsSrv)
	domain := mustDomain(b, "example.com")
	ctx := context.Background()

	b.ResetTimer()
	if hitPass {
		// Untimed warm-up: populate the cache so the timed iterations below
		// are all pure hits. StopTimer excludes this cold pass from the
		// measurement; the zero-request assertion after the loop proves it.
		b.StopTimer()
		if _, err := Probe(ctx, domain, hosts, nil, cfg); err != nil {
			b.Fatalf("warm-up Probe: %v", err)
		}
		b.StartTimer()
	}

	var rep Report
	var err error
	if hitPass {
		before := httpSrv.count() + httpsSrv.count()
		for i := 0; i < b.N; i++ {
			rep, err = Probe(ctx, domain, hosts, nil, cfg)
			if err != nil {
				b.Fatalf("Probe: %v", err)
			}
		}
		// Every timed iteration must be a pure cache hit: zero requests.
		if got := httpSrv.count() + httpsSrv.count(); got != before {
			b.Fatalf("hit pass issued %d requests; want zero", got-before)
		}
	} else {
		for i := 0; i < b.N; i++ {
			rep, err = Probe(ctx, domain, hosts, nil, cfg)
			if err != nil {
				b.Fatalf("Probe: %v", err)
			}
		}
	}
	b.StopTimer()

	if len(rep.Results) != wl.hosts {
		b.Fatalf("results = %d, want %d", len(rep.Results), wl.hosts)
	}
}

// benchProbe runs one workload at the default benchmark concurrency (16).
func benchProbe(b *testing.B, wl benchWorkload, hitPass bool) {
	benchProbeAt(b, wl, hitPass, 16)
}

func BenchmarkProbeCold10(b *testing.B)    { benchProbe(b, benchWorkloads[0], false) }
func BenchmarkProbeCold100(b *testing.B)   { benchProbe(b, benchWorkloads[1], false) }
func BenchmarkProbeCold1000(b *testing.B)  { benchProbe(b, benchWorkloads[2], false) }
func BenchmarkProbeCold10000(b *testing.B) { benchProbe(b, benchWorkloads[3], false) }
func BenchmarkProbeHit10(b *testing.B)     { benchProbe(b, benchWorkloads[0], true) }
func BenchmarkProbeHit100(b *testing.B)    { benchProbe(b, benchWorkloads[1], true) }
func BenchmarkProbeHit1000(b *testing.B)   { benchProbe(b, benchWorkloads[2], true) }
func BenchmarkProbeHit10000(b *testing.B)  { benchProbe(b, benchWorkloads[3], true) }

// BenchmarkProbeColdConcurrency sweeps the probe concurrency dimension
// (F6): the fixed cold workload at 1/4/16/64 workers — measurement only,
// no optimization. Sizing: 1,000 hosts per point was measured (15.3 s at
// 1 worker, 9.6–9.9 s at 4/16/64 — the per-target cache writes are
// fsync-bound and fully serialized, so wall time barely moves above 4
// workers); the sweep pins 1,000 hosts (2,000 requests and 2,000 cache
// writes) so the whole sweep is ≈46 s even at -benchtime=1x. The sweep
// runs under -short too: 1,000 is below the 10k short-mode gate.
func BenchmarkProbeColdConcurrency(b *testing.B) {
	var sweepWorkload = benchWorkload{name: "sweep", hosts: 1000}
	for _, c := range []int{1, 4, 16, 64} {
		c := c
		b.Run(fmt.Sprintf("Concurrency%d", c), func(b *testing.B) {
			benchProbeAt(b, sweepWorkload, false, c)
		})
	}
}

// BenchmarkCaptureTLS measures the 5C TLS metadata capture from a completed
// handshake state: the pure derivation added by sub-milestone 5C (leaf
// certificate asset + ALPN/issuer/subject/DNS names). The synthetic leaf
// certificate and its handshake state are built ONCE outside the timed loop;
// the benchmark measures capture only.
func BenchmarkCaptureTLS(b *testing.B) {
	cert, err := wildcardCert()
	if err != nil {
		b.Fatalf("wildcard cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		b.Fatalf("parse leaf: %v", err)
	}
	cs := &tls.ConnectionState{
		PeerCertificates:   []*x509.Certificate{leaf},
		NegotiatedProtocol: "h2",
	}
	clk := wallClock{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, err := captureTLS(cs, clk)
		if err != nil {
			b.Fatalf("captureTLS: %v", err)
		}
		if m == nil || m.Certificate.Fingerprint == "" {
			b.Fatal("captureTLS produced no certificate metadata")
		}
	}
}
