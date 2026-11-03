package fakes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"slices"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
)

var (
	_ app.TokenSigner = (*Keys)(nil)
	_ app.PublicKeys  = (*Keys)(nil)
)

// testKey is one signing key of Keys.
type testKey struct {
	kid     string
	alg     string
	private crypto.Signer
	public  crypto.PublicKey
}

// testKeys are generated once per test binary, RSA generation being slow: an RS256 key (RSA
// 2048) and an ES256 key (P-256).
var testKeys = sync.OnceValue(func() []testKey {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return []testKey{
		{kid: thumbprint(&r.PublicKey), alg: "RS256", private: r, public: &r.PublicKey},
		{kid: thumbprint(&e.PublicKey), alg: "ES256", private: e, public: &e.PublicKey},
	}
})

func thumbprint(pub crypto.PublicKey) string {
	k, err := jwk.Import(pub)
	if err != nil {
		panic(err)
	}
	sum, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}

// Keys is a signing keyring in memory, for tests of code that signs or verifies tokens through
// app.TokenSigner and app.PublicKeys. It holds an RS256 and an ES256 key, both published, the
// RS256 one signing. Every Keys shares the same two keys. It is safe for concurrent use.
type Keys struct {
	mu        sync.Mutex
	signer    string // kid; empty: no key signs
	published []string
}

// NewKeys returns a keyring whose RS256 key signs and whose two keys are published.
func NewKeys() *Keys {
	ks := testKeys()
	return &Keys{signer: ks[0].kid, published: []string{ks[0].kid, ks[1].kid}}
}

// Kids returns the kids of the RS256 and the ES256 key.
func (k *Keys) Kids() (rsaKid, ecKid string) {
	ks := testKeys()
	return ks[0].kid, ks[1].kid
}

// SetActive makes the key kid the signing key. An unknown kid panics as a test bug.
func (k *Keys) SetActive(kid string) {
	find(kid)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.signer = kid
}

// Unpublish removes the key kid from the published set; it still signs if it is the signing key.
func (k *Keys) Unpublish(kid string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.published = slices.DeleteFunc(k.published, func(p string) bool { return p == kid })
}

// NoSigner leaves the keyring without a signing key: Sign returns app.ErrNoSigningKey.
func (k *Keys) NoSigner() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.signer = ""
}

// Private returns the private key kid, for tests that forge tokens. An unknown kid panics.
func (k *Keys) Private(kid string) crypto.Signer {
	return find(kid).private
}

// Sign implements app.TokenSigner.
func (k *Keys) Sign(payload []byte, typ string) (string, error) {
	k.mu.Lock()
	kid := k.signer
	k.mu.Unlock()
	if kid == "" {
		return "", app.ErrNoSigningKey
	}
	key := find(kid)
	alg, ok := jwa.LookupSignatureAlgorithm(key.alg)
	if !ok {
		return "", fmt.Errorf("fakes: unknown alg %s", key.alg)
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kid); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.TypeKey, typ); err != nil {
		return "", err
	}
	tok, err := jws.Sign(payload, jws.WithKey(alg, key.private, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("fakes: sign: %w", err)
	}
	return string(tok), nil
}

// Key implements app.PublicKeys.
func (k *Keys) Key(kid string) (app.PublicKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !slices.Contains(k.published, kid) {
		return app.PublicKey{}, false
	}
	key := find(kid)
	return app.PublicKey{Kid: kid, Alg: key.alg, Key: key.public}, true
}

// Published implements app.PublicKeys.
func (k *Keys) Published() ([]app.PublicKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]app.PublicKey, len(k.published))
	for i, kid := range k.published {
		key := find(kid)
		out[i] = app.PublicKey{Kid: kid, Alg: key.alg, Key: key.public}
	}
	return out, true
}

func find(kid string) testKey {
	for _, key := range testKeys() {
		if key.kid == kid {
			return key
		}
	}
	panic("fakes: unknown kid " + kid)
}
