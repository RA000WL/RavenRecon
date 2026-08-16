package secrentel

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// Offline structural validators. They are pure functions of the matched
// value — no network, no provider contact, no verification of any kind
// beyond shape (the Phase 8 boundary).

var uuidValidatorRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// runValidator applies one validator to a matched value.
func runValidator(v patterns.Validator, value string) bool {
	switch v {
	case patterns.ValidatorNone:
		return true
	case patterns.ValidatorHex:
		return isHex(value)
	case patterns.ValidatorBase64Decodable:
		return len(value)%4 == 0 && decodeOK(base64.StdEncoding, value)
	case patterns.ValidatorUUID:
		return uuidValidatorRe.MatchString(value)
	case patterns.ValidatorMixedAlnum:
		return hasDigit(value) && hasLetter(value)
	case patterns.ValidatorJWTStructure:
		return validJWTShape(value)
	}
	return false
}

// isHex reports whether every byte is a hex digit.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			return false
		}
	}
	return true
}

// decodeOK reports whether s fully decodes under enc.
func decodeOK(enc *base64.Encoding, s string) bool {
	_, err := enc.DecodeString(s)
	return err == nil
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// validJWTShape: three dot-separated segments; the header segment decodes as
// URL-safe base64 to a JSON object carrying an "alg" member. The signature
// is only shape-checked (never cryptographically verified — Phase 8 verifies
// nothing online).
func validJWTShape(value string) bool {
	a, b, c, ok := split3(value)
	if !ok {
		return false
	}
	if a == "" || b == "" || c == "" {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(header, &obj); err != nil {
		return false
	}
	_, hasAlg := obj["alg"]
	return hasAlg
}

// split3 splits s on "." into exactly three parts.
func split3(s string) (string, string, string, bool) {
	i := indexByte(s, '.')
	if i < 0 {
		return "", "", "", false
	}
	j := indexByte(s[i+1:], '.')
	if j < 0 {
		return "", "", "", false
	}
	j += i + 1
	if indexByte(s[j+1:], '.') >= 0 {
		return "", "", "", false
	}
	return s[:i], s[i+1 : j], s[j+1:], true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
