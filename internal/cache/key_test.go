package cache

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func mustKey(t *testing.T, parts KeyParts) Key {
	t.Helper()
	k, err := NewKey(parts)
	if err != nil {
		t.Fatalf("NewKey(%+v) failed: %v", parts, err)
	}
	if len(string(k)) != 64 {
		t.Fatalf("key length = %d, want 64", len(string(k)))
	}
	for _, c := range string(k) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("key contains non-hex byte %q", c)
		}
	}
	return k
}

func baseParts(op, target string) KeyParts {
	return KeyParts{Operation: op, Target: target}
}

func TestNewKeyDeterministic(t *testing.T) {
	p := KeyParts{
		Operation: "dns.resolve",
		Target:    "host:example.com",
		Config:    map[string]string{"recurse": "true", "type": "A"},
		Tool:      ToolInfo{Name: "dnsx", Version: "1.2.0"},
	}
	a := mustKey(t, p)
	b := mustKey(t, p)
	if a != b {
		t.Fatalf("expected deterministic key, got %s then %s", a, b)
	}
}

// TestNewKeyEquivalentNormalizedTargets verifies the Phase 2 integration: two
// raw inputs that normalize to the same asset identity produce the same key,
// because normalization happens before KeyParts is built.
func TestNewKeyEquivalentNormalizedTargets(t *testing.T) {
	h1, err := asset.NewHost("Example.COM", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(Example.COM): %v", err)
	}
	h2, err := asset.NewHost("example.com.", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(example.com.): %v", err)
	}
	if h1.Identity() != h2.Identity() {
		t.Fatalf("identities differ: %q vs %q", h1.Identity(), h2.Identity())
	}
	k1 := mustKey(t, baseParts("dns.resolve", h1.Identity().String()))
	k2 := mustKey(t, baseParts("dns.resolve", h2.Identity().String()))
	if k1 != k2 {
		t.Fatalf("equivalent normalized targets produced different keys: %s != %s", k1, k2)
	}
}

func TestNewKeyDifferentTargets(t *testing.T) {
	if a, b := mustKey(t, baseParts("op", "host:example.com")), mustKey(t, baseParts("op", "host:other.org")); a == b {
		t.Fatal("different targets collided")
	}
}

func TestNewKeyDifferentAssetKinds(t *testing.T) {
	// host:example.com and domain:example.com are different identities.
	if a, b := mustKey(t, baseParts("op", "host:example.com")), mustKey(t, baseParts("op", "domain:example.com")); a == b {
		t.Fatal("different asset kinds collided")
	}
}

func TestNewKeyDifferentOperations(t *testing.T) {
	if a, b := mustKey(t, baseParts("dns.resolve", "host:example.com")), mustKey(t, baseParts("http.probe", "host:example.com")); a == b {
		t.Fatal("different operations collided")
	}
}

func TestNewKeyConfigAffectsKey(t *testing.T) {
	p := baseParts("dns.resolve", "host:example.com")
	fast := mustKey(t, KeyParts{Operation: p.Operation, Target: p.Target, Config: map[string]string{"mode": "fast"}})
	thorough := mustKey(t, KeyParts{Operation: p.Operation, Target: p.Target, Config: map[string]string{"mode": "thorough"}})
	if fast == thorough {
		t.Fatal("different configuration collided")
	}
}

func TestNewKeyConfigOrderIndependent(t *testing.T) {
	m1 := map[string]string{"a": "1", "b": "2", "c": "3"}
	m2 := map[string]string{"c": "3", "b": "2", "a": "1"}
	p1 := KeyParts{Operation: "op", Target: "host:example.com", Config: m1}
	p2 := KeyParts{Operation: "op", Target: "host:example.com", Config: m2}
	if a, b := mustKey(t, p1), mustKey(t, p2); a != b {
		t.Fatalf("config order changed the key: %s != %s", a, b)
	}
}

func TestNewKeyConfigNilVsEmpty(t *testing.T) {
	a := mustKey(t, KeyParts{Operation: "op", Target: "host:example.com", Config: nil})
	b := mustKey(t, KeyParts{Operation: "op", Target: "host:example.com", Config: map[string]string{}})
	if a != b {
		t.Fatalf("nil and empty config produced different keys: %s != %s", a, b)
	}
}

func TestNewKeyToolAffectsKey(t *testing.T) {
	noTool := mustKey(t, baseParts("passive-discovery", "domain:example.com"))
	withTool := mustKey(t, KeyParts{
		Operation: "passive-discovery",
		Target:    "domain:example.com",
		Tool:      ToolInfo{Name: "subfinder", Version: "2.6.2"},
	})
	otherVersion := mustKey(t, KeyParts{
		Operation: "passive-discovery",
		Target:    "domain:example.com",
		Tool:      ToolInfo{Name: "subfinder", Version: "2.6.3"},
	})
	if noTool == withTool || withTool == otherVersion {
		t.Fatal("tool identity did not affect the key")
	}
}

func TestNewKeyWhitespaceTrimmed(t *testing.T) {
	a := mustKey(t, baseParts("dns.resolve", "host:example.com"))
	b, err := NewKey(KeyParts{Operation: "  dns.resolve  ", Target: "  host:example.com  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a != b {
		t.Fatal("surrounding whitespace changed the key")
	}
}

func TestNewKeyEmptyOperationError(t *testing.T) {
	if _, err := NewKey(baseParts("", "host:example.com")); err == nil {
		t.Fatal("expected error for empty operation")
	}
	if _, err := NewKey(baseParts("   ", "host:example.com")); err == nil {
		t.Fatal("expected error for blank operation")
	}
}

func TestNewKeyEmptyTargetError(t *testing.T) {
	if _, err := NewKey(baseParts("op", "")); err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestNewKeyUnsafeTargetRemainsOpaque verifies that hostile target strings are
// hashed, never reflected into the key bytes, so they cannot influence the
// filesystem path layout.
func TestNewKeyUnsafeTargetRemainsOpaque(t *testing.T) {
	unsafeTargets := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"..\\..\\win",
		"host:example.com/../../evil",
		"a\x00b",
	}
	for _, tt := range unsafeTargets {
		key := mustKey(t, baseParts("op", tt))
		for _, bad := range []byte{'/', '\\', '.', 0} {
			if strings.IndexByte(string(key), bad) >= 0 && bad != '.' {
				t.Fatalf("key contains forbidden byte %q for target %q", bad, tt)
			}
		}
		if len(string(key)) != 64 {
			t.Fatalf("key length = %d for target %q", len(string(key)), tt)
		}
	}
}
