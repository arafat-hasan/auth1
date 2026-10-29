package keyring

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// thumbprint returns the kid of pub: its RFC 7638 thumbprint, SHA-256, base64url without padding.
func thumbprint(pub crypto.PublicKey) (string, error) {
	k, err := jwk.Import(pub)
	if err != nil {
		return "", fmt.Errorf("import the public key: %w", err)
	}
	sum, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}
