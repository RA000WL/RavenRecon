package patterns

import "github.com/RA000WL/RavenRecon/internal/asset"

// keyTable holds key material shapes: RSA, OpenSSH, and other PEM private
// key blocks (the marker plus trailing key material via Trail), and public
// keys (definitionally not secrets — the FamilyPublic cap keeps them at Low,
// where they are still useful correlation and inventory observations).
func keyTable() []Pattern {
	return []Pattern{
		{
			ID:       "rsa-private-key",
			Type:     asset.SecretTypeRSAPrivateKey,
			Provider: "",
			Family:   FamilyStructured,
			Regex:    `-----BEGIN RSA PRIVATE KEY-----`,
			Trail:    120,
			Strength: 0.95,
			MinLen:   31,
			MaxLen:   151,
			Hints:    []string{"private_key", "privatekey"},
		},
		{
			ID:       "ssh-private-key",
			Type:     asset.SecretTypeSSHPrivateKey,
			Provider: "",
			Family:   FamilyStructured,
			Regex:    `-----BEGIN OPENSSH PRIVATE KEY-----`,
			Trail:    120,
			Strength: 0.95,
			MinLen:   35,
			MaxLen:   155,
			Hints:    []string{"private_key", "id_rsa", "id_ed25519"},
		},
		{
			ID:       "private-key-block",
			Type:     asset.SecretTypePrivateKey,
			Provider: "",
			Family:   FamilyStructured,
			Regex:    `-----BEGIN (?:EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`,
			Trail:    120,
			Strength: 0.95,
			MinLen:   26,
			MaxLen:   146,
			Hints:    []string{"private_key", "privatekey"},
		},
		{
			ID:       "pem-public-key",
			Type:     asset.SecretTypePublicKey,
			Provider: "",
			Family:   FamilyPublic,
			Regex:    `-----BEGIN (?:RSA |EC |DSA )?PUBLIC KEY-----`,
			Trail:    60,
			Strength: 0.3,
			MinLen:   26,
			MaxLen:   86,
			Hints:    []string{"public_key"},
		},
		{
			ID:       "ssh-public-key",
			Type:     asset.SecretTypePublicKey,
			Provider: "",
			Family:   FamilyPublic,
			Regex:    `ssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]{60,320}`,
			Strength: 0.3,
			MinLen:   70,
			MaxLen:   340,
			Hints:    []string{"authorized_keys", "id_rsa.pub"},
		},
	}
}
