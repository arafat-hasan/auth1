package assertiontest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Client is a service client: its id and one signing key, RS256 (2048 bits) or ES256.
type Client struct {
	id   string
	alg  jwa.SignatureAlgorithm
	kid  string
	key  crypto.Signer
	jwks []byte
}

// NewClient returns client id with a new key for alg, "RS256" or "ES256". The key's kid is its
// RFC 7638 thumbprint.
func NewClient(t testing.TB, id, alg string) *Client {
	t.Helper()
	var key crypto.Signer
	var err error
	switch alg {
	case "RS256":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatalf("assertiontest: alg %q is not RS256 or ES256", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := jwa.LookupSignatureAlgorithm(alg)
	pub, err := jwk.Import(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tp)
	for k, v := range map[string]any{jwk.KeyIDKey: kid, jwk.AlgorithmKey: sa, jwk.KeyUsageKey: "sig"} {
		if err := pub.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{id: id, alg: sa, kid: kid, key: key, jwks: jwks}
}

// ID is the client id.
func (c *Client) ID() string { return c.id }

// Kid is the key's kid.
func (c *Client) Kid() string { return c.kid }

// JWKS is the client's public key set, the content of its jwks_file or jwks_uri.
func (c *Client) JWKS() []byte { return c.jwks }

// Option changes one assertion.
type Option func(*mint)

type mint struct {
	claims, header map[string]any
	alg            jwa.SignatureAlgorithm
	key            any // nil: unsigned
}

// Claims sets claims over the defaults; a nil value removes the claim.
func Claims(m map[string]any) Option { return func(x *mint) { merge(x.claims, m) } }

// Header sets protected header parameters over the default kid; a nil value removes one. alg is
// always the signer's.
func Header(m map[string]any) Option { return func(x *mint) { merge(x.header, m) } }

// SignedBy signs with other's key and algorithm, keeping this client's kid.
func SignedBy(other *Client) Option {
	return func(x *mint) { x.alg, x.key = other.alg, other.key }
}

// Unsigned makes an unsecured JWS: alg none and an empty signature.
func Unsigned() Option { return func(x *mint) { x.key = nil } }

// HMAC signs with HS256 and secret, as an attacker holding a public key might.
func HMAC(secret []byte) Option { return func(x *mint) { x.alg, x.key = jwa.HS256(), secret } }

func merge(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			delete(dst, k)
		} else {
			dst[k] = v
		}
	}
}

// Mint returns an assertion for audience aud issued at now: iss = sub = the client id, iat now,
// exp a minute later and a random jti, signed with the client's key under its kid, then changed
// by opts.
func (c *Client) Mint(t testing.TB, aud string, now time.Time, opts ...Option) string {
	t.Helper()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	x := &mint{
		claims: map[string]any{
			"iss": c.id, "sub": c.id, "aud": aud,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": hex.EncodeToString(jti),
		},
		header: map[string]any{"kid": c.kid},
		alg:    c.alg, key: c.key,
	}
	for _, o := range opts {
		o(x)
	}
	body, err := json.Marshal(x.claims)
	if err != nil {
		t.Fatal(err)
	}
	if x.key == nil {
		h := maps.Clone(x.header)
		h["alg"] = "none"
		hj, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	}
	h := jws.NewHeaders()
	for k, v := range x.header {
		if err := h.Set(k, v); err != nil {
			t.Fatalf("assertiontest: header %s: %v", k, err)
		}
	}
	tok, err := jws.Sign(body, jws.WithKey(x.alg, x.key, jws.WithProtectedHeaders(h)))
	if err != nil {
		t.Fatalf("assertiontest: sign: %v", err)
	}
	return string(tok)
}
