package asset

import (
	"fmt"
	"net/netip"
	"strings"
)

// normalizeHostname returns the lowercase canonical form of a DNS hostname.
// It trims surrounding whitespace and removes a single trailing root dot.
//
// Non-ASCII input is rejected: full IDNA/punycode normalization is not
// implemented yet, and silently treating distinct Unicode spellings as the
// same name would be unsafe.
func normalizeHostname(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("hostname must not be empty")
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("hostname is empty after removing trailing dot")
	}
	for _, r := range s {
		if r > 0x7f {
			return "", fmt.Errorf("hostname contains non-ASCII characters; IDN/punycode normalization is not implemented")
		}
	}
	return strings.ToLower(s), nil
}

// validateHostname enforces DNS label rules on an already-lowercased
// canonical hostname.
//
// Leading underscores are permitted per RFC 8552 service labels
// (e.g. "_dmarc", "_acme-challenge", "s1._domainkey"): a label may start
// with '_' followed by one or more [a-z0-9-] characters, with the remainder
// subject to the same hyphen rules as ordinary labels. Mid-label underscores
// remain rejected per RFC 952/1123 (e.g. "exa_mple" is invalid), as are bare
// "_" and "__*" labels.
func validateHostname(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("hostname is %d characters, longer than the 253 maximum", len(s))
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return fmt.Errorf("hostname contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q is %d characters, longer than the 63 maximum", label, len(label))
		}
		if label[0] == '_' {
			if len(label) == 1 {
				return fmt.Errorf("label %q must not be only underscore", label)
			}
			rest := label[1:]
			if rest[0] == '-' || rest[len(rest)-1] == '-' {
				return fmt.Errorf("label %q must not start or end with a hyphen", label)
			}
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return fmt.Errorf("label %q contains invalid character %q", label, c)
				}
			}
			continue
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("label %q contains invalid character %q", label, c)
			}
		}
	}
	return nil
}

// normalizeHost validates and canonicalizes a hostname, rejecting values that
// are IP addresses. IP literals are not hostnames; use the IP asset instead so
// a single value never has an ambiguous identity.
func normalizeHost(s string) (string, error) {
	canonical, err := normalizeHostname(s)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(canonical); err == nil {
		return "", fmt.Errorf("value %q is an IP address, not a hostname", s)
	}
	if err := validateHostname(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}
