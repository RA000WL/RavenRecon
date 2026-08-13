package asset

import (
	"fmt"
	"strings"
)

// Service is a service identified by a name and the port it is observed on.
type Service struct {
	// Name is the canonical service name, e.g. "http" or "nginx".
	Name string `json:"name"`

	// Port is the port the service is observed on.
	Port Port `json:"port"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewService builds a validated Service.
func NewService(name string, port Port, p Provenance) (Service, error) {
	if len(name) == 0 {
		return Service{}, fmt.Errorf("service name must not be empty")
	}
	if len(name) > 128 {
		return Service{}, fmt.Errorf("service name is longer than 128 characters")
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] > 0x7e {
			return Service{}, fmt.Errorf("service name %q contains a non-printable character", name)
		}
	}
	return Service{Name: name, Port: port, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The service name is percent-encoded (every byte outside [a-zA-Z0-9], two
// uppercase hex digits) so a "/" inside a name can never be confused with the
// port/name separator: Service{Port: 80/tcp, Name: "x"} and
// Service{Port: 80, Name: "tcp/x"} are distinct identities.
func (s Service) Identity() Identity {
	return Identity{Kind: KindService, Value: s.Port.String() + "/" + percentEncode(s.Name)}
}

// ID returns the canonical identity string.
func (s Service) ID() string { return s.Identity().String() }

// percentEncode escapes every byte outside [a-zA-Z0-9] as %XX with two
// uppercase hex digits. The encoding is injective (%-pairs unescape
// unambiguously), so distinct names can never produce the same encoded form.
func percentEncode(s string) string {
	const hexDigit = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigit[c>>4])
		b.WriteByte(hexDigit[c&0x0f])
	}
	return b.String()
}
