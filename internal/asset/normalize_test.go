package asset

import (
	"strings"
	"testing"
)

func TestNewDomain(t *testing.T) {
	p := NewProvenance("manual")

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "lowercase", in: "example.com", want: "example.com"},
		{name: "uppercase", in: "EXAMPLE.COM", want: "example.com"},
		{name: "trailing dot", in: "example.com.", want: "example.com"},
		{name: "leading space", in: "  example.com", want: "example.com"},
		{name: "trailing space", in: "example.com  ", want: "example.com"},
		{name: "subdomain", in: "api.example.com", want: "api.example.com"},
		{name: "digit leading label", in: "0.example.com", want: "0.example.com"},
		{name: "single char label", in: "a.example.com", want: "a.example.com"},
		{name: "max length", in: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), want: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},

		{name: "empty", in: "", wantErr: true},
		{name: "only dot", in: ".", wantErr: true},
		{name: "leading dot", in: ".example.com", wantErr: true},
		{name: "double dot", in: "example..com", wantErr: true},
		{name: "double trailing dot", in: "example.com..", wantErr: true},
		{name: "leading hyphen", in: "-example.com", wantErr: true},
		{name: "trailing hyphen", in: "example-.com", wantErr: true},
		{name: "underscore", in: "exa_mple.com", wantErr: true},
		{name: "space inside", in: "exa mple.com", wantErr: true},
		{name: "non-ascii", in: "éxample.com", wantErr: true},
		{name: "bare ipv4", in: "1.2.3.4", wantErr: true},
		{name: "bare ipv6", in: "::1", wantErr: true},
		{name: "ipv6 bracketed", in: "[::1]", wantErr: true},
		{name: "label too long", in: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			".com", wantErr: true},
		{name: "hostname too long", in: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDomain(tt.in, p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewDomain(%q) expected error, got %v", tt.in, d)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewDomain(%q) unexpected error: %v", tt.in, err)
			}
			if d.Name != tt.want {
				t.Errorf("NewDomain(%q).Name = %q, want %q", tt.in, d.Name, tt.want)
			}
			if d.Original != tt.in {
				t.Errorf("NewDomain(%q).Original = %q, want original preserved", tt.in, d.Original)
			}
		})
	}
}

func TestNewHost(t *testing.T) {
	p := NewProvenance("manual")

	valid := []string{"api.example.com", "API.EXAMPLE.COM", "api.example.com.", " api.example.com "}
	for _, in := range valid {
		h, err := NewHost(in, p)
		if err != nil {
			t.Fatalf("NewHost(%q) unexpected error: %v", in, err)
		}
		if h.Name != "api.example.com" {
			t.Errorf("NewHost(%q).Name = %q, want api.example.com", in, h.Name)
		}
	}

	invalid := []string{"", "1.2.3.4", "::1", "-x.com", "x_.com", "é.example"}
	for _, in := range invalid {
		if _, err := NewHost(in, p); err == nil {
			t.Errorf("NewHost(%q) expected error, got nil", in)
		}
	}
}

func TestNewIP(t *testing.T) {
	p := NewProvenance("manual")

	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "1.2.3.4", want: "1.2.3.4", ok: true},
		{in: " 1.2.3.4 ", want: "1.2.3.4", ok: true},
		{in: "127.0.0.1", want: "127.0.0.1", ok: true},
		{in: "::1", want: "::1", ok: true},
		{in: "2001:DB8::1", want: "2001:db8::1", ok: true},
		{in: "::ffff:1.2.3.4", want: "1.2.3.4", ok: true},
		{in: "", ok: false},
		{in: "1.2.3", ok: false},
		{in: "300.1.1.1", ok: false},
		{in: "abc", ok: false},
		{in: "[::1]", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ip, err := NewIP(tt.in, p)
			if tt.ok {
				if err != nil {
					t.Fatalf("NewIP(%q) unexpected error: %v", tt.in, err)
				}
				if ip.String() != tt.want {
					t.Errorf("NewIP(%q).String() = %q, want %q", tt.in, ip.String(), tt.want)
				}
			} else if err == nil {
				t.Errorf("NewIP(%q) expected error, got %v", tt.in, ip)
			}
		})
	}
}

func TestNewPort(t *testing.T) {
	p := NewProvenance("manual")

	tests := []struct {
		num       int
		proto     string
		wantID    string
		wantProto string
		wantErr   bool
	}{
		{num: 80, proto: "", wantID: "80", wantProto: ""},
		{num: 80, proto: "TCP", wantID: "80/tcp", wantProto: "tcp"},
		{num: 53, proto: "udp", wantID: "53/udp", wantProto: "udp"},
		{num: 443, proto: " Udp ", wantID: "443/udp", wantProto: "udp"},
		{num: 0, proto: "", wantErr: true},
		{num: 65536, proto: "", wantErr: true},
		{num: -1, proto: "", wantErr: true},
		{num: 80, proto: "sctp", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.wantID, func(t *testing.T) {
			port, err := NewPort(tt.num, tt.proto, p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewPort(%d,%q) expected error", tt.num, tt.proto)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPort(%d,%q) unexpected error: %v", tt.num, tt.proto, err)
			}
			if port.ID() != "port:"+tt.wantID {
				t.Errorf("port ID = %q, want %q", port.ID(), "port:"+tt.wantID)
			}
			if port.Protocol != tt.wantProto {
				t.Errorf("port protocol = %q, want %q", port.Protocol, tt.wantProto)
			}
		})
	}
}

func TestNewService(t *testing.T) {
	p := NewProvenance("manual")
	httpPort, _ := NewPort(80, "tcp", p)
	udpPort, _ := NewPort(53, "udp", p)

	s, err := NewService("http", httpPort, p)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if s.ID() != "service:80/tcp/http" {
		t.Errorf("service ID = %q, want service:80/tcp/http", s.ID())
	}

	s2, err := NewService("HTTP", httpPort, p)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if s.ID() == s2.ID() {
		t.Error("service names should be case-sensitive in identity")
	}

	s3, err := NewService("dns", udpPort, p)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if s.ID() == s3.ID() {
		t.Error("different port/name services should have different identities")
	}

	bad := []string{"", "has space", "tab\tname", string(make([]byte, 129))}
	for _, name := range bad {
		if _, err := NewService(name, httpPort, p); err == nil {
			t.Errorf("NewService(%q) expected error", name)
		}
	}

	// Regression: a "/" inside the name must never be confused with the
	// port/name separator. Under the old identity scheme both of these
	// collapsed to "80/tcp/x".
	rawPort, _ := NewPort(80, "", p)
	collideA, _ := NewService("x", httpPort, p)    // Port 80/tcp, name "x"
	collideB, _ := NewService("tcp/x", rawPort, p) // Port 80, name "tcp/x"
	if collideA.ID() == collideB.ID() {
		t.Errorf("identity collision: %q and %q share %q", collideA.ID(), collideB.ID(), collideA.ID())
	}
	if collideA.ID() != "service:80/tcp/x" {
		t.Errorf("service ID = %q, want service:80/tcp/x", collideA.ID())
	}
	if collideB.ID() != "service:80/tcp%2Fx" {
		t.Errorf("service ID = %q, want service:80/tcp%%2Fx", collideB.ID())
	}

	// A literal "%2F" in the name (escaped as %25) must stay distinct from a
	// raw "/" in the name after encoding.
	literal, _ := NewService("tcp%2Fx", httpPort, p) // Port 80/tcp, name "tcp%2Fx"
	slash, _ := NewService("tcp/x", httpPort, p)     // Port 80/tcp, name "tcp/x"
	if literal.ID() == slash.ID() {
		t.Errorf("identity collision: %q and %q share %q", literal.ID(), slash.ID(), literal.ID())
	}
	if literal.ID() != "service:80/tcp/tcp%252Fx" {
		t.Errorf("service ID = %q, want service:80/tcp/tcp%%252Fx", literal.ID())
	}
	if slash.ID() != "service:80/tcp/tcp%2Fx" {
		t.Errorf("service ID = %q, want service:80/tcp/tcp%%2Fx", slash.ID())
	}
}

func TestPercentEncode(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"x", "x"},
		{"http", "http"},
		{"nginx-1.2", "nginx%2D1%2E2"},
		{"tcp/x", "tcp%2Fx"},
		{"tcp%2Fx", "tcp%252Fx"},
		{"a b", "a%20b"},
		{"a+b", "a%2Bb"},
		{"a#b", "a%23b"},
		{"a&b=c", "a%26b%3Dc"},
	}
	for _, tt := range tests {
		if got := percentEncode(tt.in); got != tt.want {
			t.Errorf("percentEncode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewEndpoint(t *testing.T) {
	p := NewProvenance("manual")

	e, err := NewEndpoint("", "https://example.com/api", p)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if e.Method != "GET" {
		t.Errorf("default method = %q, want GET", e.Method)
	}
	if e.ID() != "endpoint:GET https://example.com/api" {
		t.Errorf("endpoint ID = %q", e.ID())
	}

	e2, err := NewEndpoint("post", "https://example.com/api", p)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if e2.Method != "POST" || e.ID() == e2.ID() {
		t.Errorf("POST endpoint should differ: method=%q", e2.Method)
	}

	for _, m := range []string{"G ET", "GET;FOO", "GET\tX", "GET\x00"} {
		if _, err := NewEndpoint(m, "https://example.com", p); err == nil {
			t.Errorf("NewEndpoint(method=%q) expected error", m)
		}
	}
}

func TestNewJavaScript(t *testing.T) {
	p := NewProvenance("manual")

	j, err := NewJavaScript("https://example.com/app.js", p)
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	if j.ID() != "javascript:https://example.com/app.js" {
		t.Errorf("js ID = %q", j.ID())
	}

	if _, err := NewJavaScript("not-a-url", p); err == nil {
		t.Error("NewJavaScript(not-a-url) expected error")
	}
}
