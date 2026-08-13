package asset

import (
	"fmt"
	"strconv"
	"strings"
)

// Port is a transport port.
type Port struct {
	// Number is the port number.
	Number uint16 `json:"number"`

	// Protocol is "tcp", "udp", or empty when the transport is unknown.
	Protocol string `json:"protocol,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewPort builds a validated Port.
func NewPort(number int, protocol string, p Provenance) (Port, error) {
	if number < 1 || number > 65535 {
		return Port{}, fmt.Errorf("port number %d is outside 1..65535", number)
	}
	proto := strings.ToLower(strings.TrimSpace(protocol))
	switch proto {
	case "", "tcp", "udp":
	default:
		return Port{}, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return Port{Number: uint16(number), Protocol: proto, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
func (p Port) Identity() Identity {
	return Identity{Kind: KindPort, Value: p.String()}
}

// ID returns the canonical identity string.
func (p Port) ID() string { return p.Identity().String() }

// String returns the canonical port representation, e.g. "80" or "53/udp".
func (p Port) String() string {
	if p.Protocol == "" {
		return strconv.Itoa(int(p.Number))
	}
	return strconv.Itoa(int(p.Number)) + "/" + p.Protocol
}
