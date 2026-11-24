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

// Parse returns the usable keys of the JWKS data by kid (TDD-05 §2), and why each other key was
// skipped. A key is used when it has a kid, its use is absent or sig, it is RSA of at least 2048
// bits (RS256) or P-256 (ES256), and its alg, if given, is that one. Data over MaxSize, not a JWKS,
// with a kid repeated among the keys that parse, or with no usable key is an error.
func Parse(data []byte) (keys map[string]app.PublicKey, skipped []string, err error) {
	if len(data) > MaxSize {
		return nil, nil, fmt.Errorf("JWKS over %d bytes", MaxSize)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, nil, errors.New("not a JWKS")
	}
	keys = make(map[string]app.PublicKey, len(set.Keys))
	kids := map[string]bool{}
	for i, raw := range set.Keys {
		k, err := jwk.ParseKey(raw)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: does not parse", name(raw, i)))
			continue
		}
		kid, _ := k.KeyID()
		if kid == "" {
			skipped = append(skipped, fmt.Sprintf("key %d: no kid", i))
			continue
		}
		if kids[kid] {
			return nil, nil, fmt.Errorf("kid %q is repeated", kid)
		}
		kids[kid] = true
		pk, why := usable(k, kid)
		if why != "" {
			skipped = append(skipped, fmt.Sprintf("kid %q: %s", kid, why))
			continue
		}
		keys[kid] = pk
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("no usable key: each needs a kid, use sig and RSA 2048+ (RS256) or P-256 (ES256)")
	}
	return keys, skipped, nil
}

// name names the key raw, the ith of its set, by its kid when it has one.
func name(raw json.RawMessage, i int) string {
	var k struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &k) == nil && k.Kid != "" {
		return fmt.Sprintf("kid %q", k.Kid)
	}
	return fmt.Sprintf("key %d", i)
}

// usable returns k as the public key kid when it may verify a client assertion, or why not.
func usable(k jwk.Key, kid string) (app.PublicKey, string) {
	if use, ok := k.KeyUsage(); ok && use != "sig" {
		return app.PublicKey{}, "use is not sig"
	}
	raw, err := jwk.PublicRawKeyOf(k)
	if err != nil {
		return app.PublicKey{}, "not a public key"
	}
	var alg string
	switch p := raw.(type) {
	case *rsa.PublicKey:
		if p.N.BitLen() < 2048 {
			return app.PublicKey{}, "RSA under 2048 bits"
		}
		alg = "RS256"
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return app.PublicKey{}, "EC on a curve other than P-256"
		}
		alg = "ES256"
	default:
		return app.PublicKey{}, "neither RSA nor EC"
	}
	if a, ok := k.Algorithm(); ok && a.String() != alg {
		return app.PublicKey{}, fmt.Sprintf("alg %s does not fit the key, whose alg is %s", a, alg)
	}
	return app.PublicKey{Kid: kid, Alg: alg, Key: raw}, ""
}
