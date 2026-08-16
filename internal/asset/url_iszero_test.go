package asset

import "testing"

// TestURLIsZero pins the zero-URL contract: a zero URL means "not observed"
// and is never a valid observation, while every parsed URL is non-zero.
func TestURLIsZero(t *testing.T) {
	var zero URL
	if !zero.IsZero() {
		t.Errorf("zero URL IsZero() = false, want true")
	}

	// A URL with any identity field set is not zero.
	partials := []URL{
		{Scheme: "http"},
		{HostPort: "example.com"},
		{Path: "/"},
		{Query: "a=1"},
		{Fragment: "frag"},
		{Original: "http://example.com/"},
	}
	for _, p := range partials {
		if p.IsZero() {
			t.Errorf("URL with a set field %+v IsZero() = true, want false", p)
		}
	}

	// Every parsed canonical URL is non-zero.
	for _, raw := range []string{
		"http://example.com/",
		"https://example.com:8443/a/b?x=1#frag",
		"http://127.0.0.1:8080/",
	} {
		u, err := ParseURL(raw, Provenance{})
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		if u.IsZero() {
			t.Errorf("parsed %q IsZero() = true, want false", raw)
		}
	}
}

// TestDefaultPorts pins the default-port table shared by http(s) and the
// ws/wss schemes (RFC 6455 section 3: ws defaults to 80, wss to 443). An
// explicit default port is STRIPPED from a canonical URL, so "ws://h:80/x"
// and "wss://h:443/x" canonicalize to their portless forms.
func TestDefaultPorts(t *testing.T) {
	if !isDefaultPort("http", "80") || !isDefaultPort("ws", "80") {
		t.Error("http/ws default port must be 80")
	}
	if !isDefaultPort("https", "443") || !isDefaultPort("wss", "443") {
		t.Error("https/wss default port must be 443")
	}
	if isDefaultPort("http", "443") || isDefaultPort("ws", "443") ||
		isDefaultPort("https", "80") || isDefaultPort("wss", "80") {
		t.Error("cross-scheme defaults must not match")
	}
	if isDefaultPort("ws", "8080") || isDefaultPort("wss", "8443") {
		t.Error("non-default ws/wss ports must be retained")
	}

	u, err := ParseURL("ws://example.com:80/", Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(ws): %v", err)
	}
	if u.HostPort != "example.com" {
		t.Errorf("ws://example.com:80 HostPort = %q, want example.com (default port stripped)", u.HostPort)
	}
	u, err = ParseURL("wss://example.com:443/", Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(wss): %v", err)
	}
	if u.HostPort != "example.com" {
		t.Errorf("wss://example.com:443 HostPort = %q, want example.com (default port stripped)", u.HostPort)
	}
	for _, raw := range []string{"ws://example.com:8080/", "wss://example.com:8443/"} {
		u, err := ParseURL(raw, Provenance{})
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		if u.HostPort != "example.com:8080" && u.HostPort != "example.com:8443" {
			t.Errorf("ParseURL(%q) HostPort = %q, want the explicit port retained", raw, u.HostPort)
		}
	}
}
