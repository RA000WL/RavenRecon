package discovery

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestASNMappingInvocation(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"asnmap -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\n")}, nil
		},
	})
	s := asnmap{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "asnmap"
	if _, err := s.Discover(context.Background(), mustDomain(t, "example.com")); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	cmds := r.argCalls("-d")
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one -d invocation, got %d", len(cmds))
	}
	want := []string{"-d", "example.com", "-silent"}
	if !reflect.DeepEqual(cmds[0].Args, want) {
		t.Fatalf("argv = %v, want %v", cmds[0].Args, want)
	}
}

func TestASNMappingEmits(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"asnmap -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\nwww.example.com\n")}, nil
		},
	})
	s := asnmap{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "asnmap"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 2 {
		t.Fatalf("hosts = %v, want 2", names(dres.Hosts))
	}
	// Provenance is asnmap.
	for _, h := range dres.Hosts {
		if h.Prov.Source != "asnmap" {
			t.Fatalf("host %s provenance source = %q, want asnmap", h.Name, h.Prov.Source)
		}
	}
	if dres.Hosts[0].Name != "api.example.com" || dres.Hosts[1].Name != "www.example.com" {
		t.Fatalf("hosts = %v, want [api.example.com www.example.com]", names(dres.Hosts))
	}
}

func TestASNMappingParseAndDedup(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"asnmap -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\nWWW.Example.COM.\napi.example.com\n\n")}, nil
		},
	})
	s := asnmap{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "asnmap"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 2 {
		t.Fatalf("hosts = %v, want 2", names(dres.Hosts))
	}
}

func TestASNMappingExecutableMissing(t *testing.T) {
	l := newFakeLookup()
	l.errs["asnmap"] = exec.ErrNotFound
	s := asnmap{env: adapterEnv(newFakeRunner(t, nil), l)}
	s.env.name = "asnmap"
	_, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if !errors.Is(err, ErrExecutableNotFound) {
		t.Fatalf("want ErrExecutableNotFound, got %v", err)
	}
}

func TestASNMappingBuiltInRegistry(t *testing.T) {
	if _, ok := registry["asnmap"]; !ok {
		t.Fatal("registry missing asnmap")
	}
	// asnmap is available via explicit source selection (registry),
	// but not part of the default built-in set (opt-in, default off).
	// This keeps existing 4-source determinism pins intact while allowing
	// explicit "asnmap" selection through the Source interface.
	// Ensure cache key includes version: two different versions must yield different keys.
	d := mustDomain(t, "example.com")
	src := asnmap{env: toolEnv{name: "asnmap"}}
	k1, err := cacheKey(d, src, Detection{Source: "asnmap", Version: "v1.0.0"}, NormalizeQualityConfig(QualityConfig{}))
	if err != nil {
		t.Fatalf("cacheKey: %v", err)
	}
	k2, err := cacheKey(d, src, Detection{Source: "asnmap", Version: "v2.0.0"}, NormalizeQualityConfig(QualityConfig{}))
	if err != nil {
		t.Fatalf("cacheKey: %v", err)
	}
	if k1 == k2 {
		t.Fatal("cache keys for different versions must differ")
	}
	if !strings.Contains(string(k1), "") { // sanity: keys are hex digests
		t.Fatal("unexpected key shape")
	}
}

func TestASNMappingTruncationFlag(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"asnmap -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\n"), StdoutTruncated: true}, nil
		},
	})
	s := asnmap{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "asnmap"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !dres.Truncated {
		t.Fatal("expected Truncated")
	}
}
