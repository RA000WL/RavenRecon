package discovery

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// adapterEnv builds a toolEnv bound to the fakes. The scripted fakeLookup is
// adapted to the LookupFunc seam via its method value.
func adapterEnv(runner Runner, lookup fakeLookup) toolEnv {
	return toolEnv{
		runner:        runner,
		lookup:        lookup.LookPath,
		limits:        Limits{MaxOutput: 4096},
		detectTimeout: time.Second,
		now:           func() time.Time { return fixedTime },
	}
}

func TestSubfinderInvocation(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\n")}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	if _, err := s.Discover(context.Background(), mustDomain(t, "example.com")); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	cmds := r.argCalls("-d")
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one -d invocation, got %d", len(cmds))
	}
	// Passive-only boundary: exact argv is asserted so the invocation cannot
	// silently drift toward active options.
	want := []string{"-d", "example.com", "-silent"}
	if !reflect.DeepEqual(cmds[0].Args, want) {
		t.Fatalf("argv = %v, want %v", cmds[0].Args, want)
	}
}

func TestSubfinderParseAndDedup(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\nWWW.Example.COM.\napi.example.com\n\n")}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 2 {
		t.Fatalf("hosts = %v, want 2", names(dres.Hosts))
	}
	if dres.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0", dres.Malformed)
	}
	if dres.Truncated {
		t.Fatal("unexpected truncation")
	}
}

func TestSubfinderNonZeroExitWithPartialOutput(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\n"), ExitCode: 1}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if !strings.Contains(err.Error(), "exit") {
		t.Fatalf("error %v should mention the exit", err)
	}
	// The partial output must be retained, not discarded.
	if len(dres.Hosts) != 1 || dres.Hosts[0].Name != "api.example.com" {
		t.Fatalf("partial hosts = %v, want [api.example.com]", names(dres.Hosts))
	}
}

func TestSubfinderNonZeroExitNoOutput(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("boom\n"), ExitCode: 1}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if len(dres.Hosts) != 0 {
		t.Fatalf("expected no hosts, got %v", names(dres.Hosts))
	}
}

func TestSubfinderEmptySuccess(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 0 {
		t.Fatalf("expected no hosts, got %v", names(dres.Hosts))
	}
}

func TestSubfinderExecutableMissing(t *testing.T) {
	l := newFakeLookup()
	l.errs["subfinder"] = errors.New("not found in PATH")
	s := subfinder{env: adapterEnv(newFakeRunner(t, nil), l)}
	s.env.name = "subfinder"
	_, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if !errors.Is(err, ErrExecutableNotFound) {
		t.Fatalf("want ErrExecutableNotFound, got %v", err)
	}
}

func TestSubfinderCancellation(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){})
	r.blockKeys = map[string]bool{"subfinder -d example.com -silent": true}
	r.blockStarted = make(chan struct{})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-r.blockStarted
		cancel()
	}()
	_, err := s.Discover(ctx, mustDomain(t, "example.com"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestSubfinderTruncationFlag(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -d example.com -silent": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("api.example.com\n"), StdoutTruncated: true}, nil
		},
	})
	s := subfinder{env: adapterEnv(r, newFakeLookup())}
	s.env.name = "subfinder"
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !dres.Truncated {
		t.Fatal("expected Truncated")
	}
}

func TestAssetfinderInvocation(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"assetfinder example.com": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("www.example.com\n")}, nil
		},
	})
	a := assetfinder{env: adapterEnv(r, newFakeLookup())}
	a.env.name = "assetfinder"
	if _, err := a.Discover(context.Background(), mustDomain(t, "example.com")); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	cmds := r.argCalls("example.com")
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one positional invocation, got %d", len(cmds))
	}
	if want := []string{"example.com"}; !reflect.DeepEqual(cmds[0].Args, want) {
		t.Fatalf("argv = %v, want %v", cmds[0].Args, want)
	}
}

func TestAssetfinderMalformedLines(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"assetfinder example.com": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("ok.example.com\n..\n-x.example.com\n  \n")}, nil
		},
	})
	a := assetfinder{env: adapterEnv(r, newFakeLookup())}
	a.env.name = "assetfinder"
	dres, err := a.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 1 || dres.Hosts[0].Name != "ok.example.com" {
		t.Fatalf("hosts = %v, want [ok.example.com]", names(dres.Hosts))
	}
	if dres.Malformed != 2 {
		t.Fatalf("malformed = %d, want 2", dres.Malformed)
	}
}

func TestAmassInvocationPassiveOnly(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"amass enum -passive -d example.com": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("mail.example.com\n")}, nil
		},
	})
	a := amass{env: adapterEnv(r, newFakeLookup())}
	a.env.name = "amass"
	if _, err := a.Discover(context.Background(), mustDomain(t, "example.com")); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	cmds := r.argCalls("enum")
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one enum invocation, got %d", len(cmds))
	}
	// Passive-only boundary: the exact argv is asserted; amass's default
	// active enumeration must never be reachable from here.
	want := []string{"enum", "-passive", "-d", "example.com"}
	if !reflect.DeepEqual(cmds[0].Args, want) {
		t.Fatalf("argv = %v, want %v", cmds[0].Args, want)
	}
}

func TestAmassAnnotationFormat(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"amass enum -passive -d example.com": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("example.com (FQDN) --> 1.2.3.4\nwww.example.com\n")}, nil
		},
	})
	a := amass{env: adapterEnv(r, newFakeLookup())}
	a.env.name = "amass"
	dres, err := a.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 2 {
		t.Fatalf("hosts = %v, want 2", names(dres.Hosts))
	}
	if dres.Hosts[0].Name != "example.com" || dres.Hosts[1].Name != "www.example.com" {
		t.Fatalf("hosts = %v, want [example.com www.example.com]", names(dres.Hosts))
	}
}

func TestAmassStderrOnlySuccess(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"amass enum -passive -d example.com": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("noise\n")}, nil
		},
	})
	a := amass{env: adapterEnv(r, newFakeLookup())}
	a.env.name = "amass"
	dres, err := a.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(dres.Hosts) != 0 {
		t.Fatalf("stderr-only output must yield no hosts, got %v", names(dres.Hosts))
	}
}
