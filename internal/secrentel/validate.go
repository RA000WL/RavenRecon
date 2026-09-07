package secrentel

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"time"

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

// jwtExpiry is the offline expiry reading of a JWT candidate's "exp" claim:
// a pure function of the matched value (no clock injection — the comparison
// point is the scan-time wall clock; fixtures use epoch-edge exp values so
// tests stay deterministic for decades).
type jwtExpiry int

const (
	// jwtExpiryNone: no usable "exp" claim (absent, non-numeric, or the
	// payload does not decode) — expiry says nothing about this token.
	jwtExpiryNone jwtExpiry = iota
	// jwtExpiryValid: "exp" is present and in the future.
	jwtExpiryValid
	// jwtExpiryExpired: "exp" is present and in the past (now >= exp, the
	// standard exp boundary: the token MUST NOT be accepted at or after
	// its expiry).
	jwtExpiryExpired
)

// jwtExpiryState decodes the JWT payload's "exp" claim (base64url, JSON
// number — the only "exp" form RFC 7519 allows). It returns the expiry
// reading and whether an "exp" claim was usable: ok is false exactly when
// the reading is jwtExpiryNone. Malformed tokens, undecodable payloads,
// and non-numeric "exp" members all report (jwtExpiryNone, false) — never
// an error, never a panic. The Validator contract is untouched:
// runValidator still reports shape as a bool; expiry only labels and caps
// downstream confidence.
func jwtExpiryState(value string) (jwtExpiry, bool) {
	_, payload, _, ok := split3(value)
	if !ok || payload == "" {
		return jwtExpiryNone, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(payload); err != nil {
			return jwtExpiryNone, false
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return jwtExpiryNone, false
	}
	exp, ok := obj["exp"].(float64)
	if !ok {
		return jwtExpiryNone, false
	}
	if float64(time.Now().Unix()) >= exp {
		return jwtExpiryExpired, true
	}
	return jwtExpiryValid, true
}

// isJWTExpired reports whether value is a JWT-shaped token carrying a past
// "exp" claim. It is the confidence layer's only expiry query: expired
// tokens prove history, not live access, so they are labeled and capped —
// never boosted.
func isJWTExpired(value string) bool {
	st, ok := jwtExpiryState(value)
	return ok && st == jwtExpiryExpired
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
