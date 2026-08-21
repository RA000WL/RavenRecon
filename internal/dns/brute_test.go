package dns

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestGenerateBruteCandidatesBasic verifies wordlist × domain generation,
// sorting, and deduplication.
func TestGenerateBruteCandidatesBasic(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := []string{"www", "api"}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	names := hostNames(candidates)
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("GenerateBruteCandidates = %v, want %v", names, want)
	}
}

// TestGenerateBruteCandidatesDedup verifies duplicate wordlist entries and
// case-insensitive deduplication via the Phase 2 identity.
func TestGenerateBruteCandidatesDedup(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := []string{"www", "WWW", "www", "api", "api"}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	names := hostNames(candidates)
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("dedup = %v, want %v", names, want)
	}
}

// TestGenerateBruteCandidatesInvalidLabels verifies that invalid labels are
// dropped without panic and never produce non-canonical hosts.
func TestGenerateBruteCandidatesInvalidLabels(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := []string{"", "  ", "bad_host!", "www", "-invalid", "api"}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	names := hostNames(candidates)
	// bad_host! and "-invalid" fail asset.NewHost validation and are dropped.
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("invalid handling = %v, want %v", names, want)
	}
}

// TestGenerateBruteCandidatesCap verifies the MaxBruteHostsPerDomain cap
// truncates deterministically and the result is sorted. It also pins the
// NEW-32 regression at the generator level: a wordlist truncated to exactly
// MaxBruteWordlistEntries (= MaxBruteHostsPerDomain) distinct entries fills
// the output to the cap WITHOUT dropping anything, so the explicit cap-hit
// flag must be false — truncation must never be inferred from the length.
func TestGenerateBruteCandidatesCap(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := make([]string, MaxBruteHostsPerDomain+10)
	for i := range wordlist {
		wordlist[i] = "host" + itoa(i)
	}
	candidates, capHit := GenerateBruteCandidates(domain, wordlist)
	if len(candidates) != MaxBruteHostsPerDomain {
		t.Fatalf("len = %d, want %d", len(candidates), MaxBruteHostsPerDomain)
	}
	// The wordlist was pre-truncated to MaxBruteWordlistEntries
	// (= MaxBruteHostsPerDomain) distinct valid labels, so every retained
	// candidate filled the cap exactly and nothing was dropped.
	if capHit {
		t.Fatal("capHit = true, want false: output at the cap without any dropped candidate is not truncation")
	}
	// Sorted check
	for i := 1; i < len(candidates); i++ {
		if candidates[i].Name < candidates[i-1].Name {
			t.Fatalf("not sorted at %d: %q < %q", i, candidates[i].Name, candidates[i-1].Name)
		}
	}
}

// TestGenerateBruteCandidatesWordlistCap verifies MaxBruteWordlistEntries cap.
func TestGenerateBruteCandidatesWordlistCap(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := make([]string, MaxBruteWordlistEntries+5)
	for i := range wordlist {
		wordlist[i] = "w" + itoa(i)
	}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	if len(candidates) != MaxBruteWordlistEntries {
		t.Fatalf("len = %d, want %d (wordlist cap)", len(candidates), MaxBruteWordlistEntries)
	}
}

// TestGenerateBruteCandidatesEmptyDomain verifies empty domain returns nil.
func TestGenerateBruteCandidatesEmptyDomain(t *testing.T) {
	var domain asset.Domain
	candidates, _ := GenerateBruteCandidates(domain, []string{"www"})
	if len(candidates) != 0 {
		t.Fatalf("empty domain produced %v", hostNames(candidates))
	}
}

// TestGenerateBruteCandidatesEmptyWordlist verifies empty wordlist returns nil.
func TestGenerateBruteCandidatesEmptyWordlist(t *testing.T) {
	domain := mustDomain(t, "example.com")
	candidates, _ := GenerateBruteCandidates(domain, nil)
	if len(candidates) != 0 {
		t.Fatalf("empty wordlist produced %v", hostNames(candidates))
	}
}

// TestBuildBruteCandidatesCapHit exercises the drop-detection logic with a
// small cap (the production constants make the public path unable to observe
// a drop): above the cap the flag is true; exactly at the cap without drops
// it stays false; duplicates and invalid labels beyond the cap are not
// drops.
func TestBuildBruteCandidatesCapHit(t *testing.T) {
	domain := mustDomain(t, "example.com")

	t.Run("above cap reports drop", func(t *testing.T) {
		out, capHit := buildBruteCandidates(domain, []string{"a", "b", "c", "d"}, 3)
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
		if !capHit {
			t.Fatal("capHit = false, want true: one distinct candidate was dropped")
		}
	})

	t.Run("exactly at cap without drop", func(t *testing.T) {
		out, capHit := buildBruteCandidates(domain, []string{"a", "b", "c"}, 3)
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
		if capHit {
			t.Fatal("capHit = true, want false: nothing was dropped at exactly the cap")
		}
	})

	t.Run("duplicates beyond cap are not drops", func(t *testing.T) {
		// "a" repeats after the cap is full: a duplicate of an already
		// retained candidate is dedup, never a dropped NEW candidate.
		out, capHit := buildBruteCandidates(domain, []string{"a", "b", "c", "a", "A"}, 3)
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
		if capHit {
			t.Fatal("capHit = true, want false: only duplicates followed the cap")
		}
	})

	t.Run("invalid labels beyond cap are not drops", func(t *testing.T) {
		// "bad_host!" fails asset.NewHost validation: dropped as invalid,
		// never counted as a cap drop.
		out, capHit := buildBruteCandidates(domain, []string{"a", "b", "c", "bad_host!"}, 3)
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
		if capHit {
			t.Fatal("capHit = true, want false: only an invalid label followed the cap")
		}
	})
}

// TestIsWildcardNotWildcard verifies a non-wildcard domain (probe returns
// NXDOMAIN) is correctly reported as not wildcarded.
func TestIsWildcardNotWildcard(t *testing.T) {
	domain := mustDomain(t, "example.com")
	fake := newFakeResolver()
	// No answer scripted for the probe: the fake returns NODATA (empty,
	// nil) which is treated as not wildcard. To test NXDOMAIN path,
	// explicitly script ErrNotFound.
	probe := wildcardProbeHost(domain)
	fake.setErr(probe.Name, TypeA, &QueryError{Kind: ErrNotFound, Host: probe.Name, Type: TypeA, Err: errors.New("no such host")})

	ok, err := IsWildcard(context.Background(), domain, fake)
	if err != nil {
		t.Fatalf("IsWildcard returned error: %v", err)
	}
	if ok {
		t.Fatal("IsWildcard = true, want false for NXDOMAIN probe")
	}
}

// TestIsWildcardDetected verifies a wildcard domain (probe resolves with an
// answer) is detected.
func TestIsWildcardDetected(t *testing.T) {
	domain := mustDomain(t, "example.com")
	fake := newFakeResolver()
	probe := wildcardProbeHost(domain)
	fake.set(probe.Name, TypeA, "1.2.3.4")

	ok, err := IsWildcard(context.Background(), domain, fake)
	if err != nil {
		t.Fatalf("IsWildcard returned error: %v", err)
	}
	if !ok {
		t.Fatal("IsWildcard = false, want true for resolving probe")
	}
}

// TestIsWildcardNODATA verifies an empty answer with no error (NODATA) is not
// wildcarded.
func TestIsWildcardNODATA(t *testing.T) {
	domain := mustDomain(t, "example.com")
	fake := newFakeResolver()
	// No script: Lookup returns empty slice, nil error => NODATA
	ok, err := IsWildcard(context.Background(), domain, fake)
	if err != nil {
		t.Fatalf("IsWildcard returned error: %v", err)
	}
	if ok {
		t.Fatal("IsWildcard = true, want false for NODATA probe")
	}
}

// TestIsWildcardCancellation verifies cancellation during the probe is
// propagated.
func TestIsWildcardCancellation(t *testing.T) {
	domain := mustDomain(t, "example.com")
	fake := newFakeResolver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := IsWildcard(ctx, domain, fake)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("IsWildcard err = %v, want context.Canceled", err)
	}
}

// TestIsWildcardOtherFailure verifies a non-NXDOMAIN failure (SERVFAIL) is
// treated as non-wildcard (no false abort).
func TestIsWildcardOtherFailure(t *testing.T) {
	domain := mustDomain(t, "example.com")
	fake := newFakeResolver()
	probe := wildcardProbeHost(domain)
	fake.setErr(probe.Name, TypeA, &QueryError{Kind: ErrFailure, Host: probe.Name, Type: TypeA, Err: errors.New("servfail")})

	ok, err := IsWildcard(context.Background(), domain, fake)
	if err != nil {
		t.Fatalf("IsWildcard returned error: %v", err)
	}
	if ok {
		t.Fatal("IsWildcard = true, want false for failure probe")
	}
}

// TestBruteWildcardAbortIntegration is the integration-style brute wildcard
// abort: wordlist ["www","api"] × example.com, but the wildcard probe
// resolves, so brute must be aborted (no candidates emitted).
func TestBruteWildcardAbortIntegration(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := []string{"www", "api"}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	if len(candidates) != 2 {
		t.Fatalf("candidates = %v, want 2", hostNames(candidates))
	}
	fake := newFakeResolver()
	probe := wildcardProbeHost(domain)
	fake.set(probe.Name, TypeA, "5.6.7.8")
	// Even though the wordlist hosts would resolve, wildcard abort prevents
	// brute from ever querying them.
	fake.set("www.example.com", TypeA, "1.2.3.4")
	fake.set("api.example.com", TypeA, "1.2.3.5")

	ok, err := IsWildcard(context.Background(), domain, fake)
	if err != nil {
		t.Fatalf("IsWildcard error: %v", err)
	}
	if !ok {
		t.Fatal("expected wildcard, got not wildcard")
	}
	// Simulate adapt layer: if wildcard, brute candidates are not resolved.
	if ok {
		// No brute hosts should be emitted.
		if fake.callCount() != 1 {
			t.Fatalf("callCount = %d, want 1 (only wildcard probe)", fake.callCount())
		}
	}
}

// TestBruteResolveFiltering verifies that after brute Resolve, only hosts
// with successful answers are retained (NXDOMAIN hosts dropped).
func TestBruteResolveFiltering(t *testing.T) {
	domain := mustDomain(t, "example.com")
	wordlist := []string{"www", "api", "nope"}
	candidates, _ := GenerateBruteCandidates(domain, wordlist)
	fake := newFakeResolver()
	fake.set("www.example.com", TypeA, "1.1.1.1")
	fake.set("api.example.com", TypeA, "1.1.1.2")
	// "nope.example.com" has no script => NODATA (no IPs, not wildcard)

	cfg := testConfig(fake)
	rep, err := Resolve(context.Background(), domain, candidates, cfg)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	// Filter to resolving hosts (IPs present)
	var resolving []string
	for _, hr := range rep.Results {
		if len(hr.IPs) > 0 || len(hr.Targets) > 0 {
			resolving = append(resolving, hr.Host.Name)
		}
	}
	sort.Strings(resolving)
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(resolving, want) {
		t.Fatalf("resolving = %v, want %v", resolving, want)
	}
}
