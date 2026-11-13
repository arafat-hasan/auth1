package clientkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/arafat-hasan/auth1/internal/app"
)

// MaxSize bounds a JWKS, read from a file or fetched (TDD-05 §2).
const MaxSize = 64 << 10

// Parse returns the usable keys of the JWKS data by kid (TDD-05 §2). A key is used when it has a
// kid, its use is absent or sig, it is RSA of at least 2048 bits (RS256) or P-256 (ES256), and its
// alg, if given, is that one; any other key is skipped. Data over MaxSize, not a JWKS, with a
// repeated kid or with no usable key is an error.
func Parse(data []byte) (map[string]app.PublicKey, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("JWKS over %d bytes", MaxSize)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("not a JWKS")
	}
	keys := make(map[string]app.PublicKey, len(set.Keys))
	kids := map[string]bool{}
	for _, raw := range set.Keys {
		k, err := jwk.ParseKey(raw)
		if err != nil {
			continue
		}
		kid, _ := k.KeyID()
		if kid == "" {
			continue
		}
		if kids[kid] {
			return nil, fmt.Errorf("kid %q is repeated", kid)
		}
		kids[kid] = true
		if pk, ok := usable(k, kid); ok {
			keys[kid] = pk
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable key: each needs a kid, use sig and RSA 2048+ (RS256) or P-256 (ES256)")
	}
	return keys, nil
}

// usable returns k as the public key kid when it may verify a client assertion.
func usable(k jwk.Key, kid string) (app.PublicKey, bool) {
	if use, ok := k.KeyUsage(); ok && use != "sig" {
		return app.PublicKey{}, false
	}
	raw, err := jwk.PublicRawKeyOf(k)
	if err != nil {
		return app.PublicKey{}, false
	}
	var alg string
	switch p := raw.(type) {
	case *rsa.PublicKey:
		if p.N.BitLen() < 2048 {
			return app.PublicKey{}, false
		}
		alg = "RS256"
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return app.PublicKey{}, false
		}
		alg = "ES256"
	default:
		return app.PublicKey{}, false
	}
	if a, ok := k.Algorithm(); ok && a.String() != alg {
		return app.PublicKey{}, false
	}
	return app.PublicKey{Kid: kid, Alg: alg, Key: raw}, true
}
