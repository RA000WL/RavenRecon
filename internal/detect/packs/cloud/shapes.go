package cloud

import (
	"strings"
)

// awsCredentialIndicator conservatively reports whether s carries an AWS
// access-key indicator: a whole-token AKIA/ASIA access-key-ID shape, with
// the providers' documented EXAMPLE-convention values suppressed
// case-sensitively (mirroring secrentel's fpExampleMarkers) — documentation
// dumps quoting example keys are the classic false-positive source.
func awsCredentialIndicator(s string) bool {
	if strings.Contains(s, "EXAMPLE") {
		return false
	}
	return hasAWSAccessKeyShape(s)
}

// hasAWSAccessKeyShape scans s for "AKIA" or "ASIA" followed by exactly 16
// uppercase alphanumeric characters, delimited by non-identifier bytes on
// both sides so longer tokens can never match partially. Hand-rolled rather
// than regexp so the hot path stays allocation-free and the shape contract
// reads as code.
func hasAWSAccessKeyShape(s string) bool {
	const keyLen = 20 // 4-byte prefix + 16 identifier bytes
	for i := 0; i+keyLen <= len(s); i++ {
		if s[i] != 'A' || (s[i+1:i+4] != "KIA" && s[i+1:i+4] != "SIA") {
			continue
		}
		if i > 0 && isKeyTokenByte(s[i-1]) {
			continue
		}
		shaped := true
		for j := i + 4; j < i+keyLen; j++ {
			c := s[j]
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				shaped = false
				break
			}
		}
		if !shaped {
			continue
		}
		if i+keyLen < len(s) && isKeyTokenByte(s[i+keyLen]) {
			continue
		}
		return true
	}
	return false
}

// isKeyTokenByte reports whether c could extend (or absorb) an identifier
// token adjacent to a candidate key shape.
func isKeyTokenByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
