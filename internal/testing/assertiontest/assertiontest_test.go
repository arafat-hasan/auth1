package assertiontest_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/testing/assertiontest"
)

var now = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

const aud = "https://id.example.test/v1/oauth/token"

// part decodes one segment of a compact JWS.
func part(t *testing.T, tok string, i int) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMintVerifies(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			c := assertiontest.NewClient(t, "reports", alg)
			set, err := jwk.Parse(c.JWKS())
			if err != nil {
				t.Fatal(err)
			}
			key, ok := set.LookupKeyID(c.Kid())
			if !ok {
				t.Fatalf("JWKS has no key %s", c.Kid())
			}
			if a, _ := key.Algorithm(); a.String() != alg {
				t.Errorf("JWK alg = %v, want %s", a, alg)
			}
			tok := c.Mint(t, aud, now)
			sa, _ := jwa.LookupSignatureAlgorithm(alg)
			if _, err := jws.Verify([]byte(tok), jws.WithKey(sa, key)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if d := cmp.Diff(map[string]any{"alg": alg, "kid": c.Kid()}, part(t, tok, 0)); d != "" {
				t.Errorf("header (-want +got):\n%s", d)
			}
			claims := part(t, tok, 1)
			jti, _ := claims["jti"].(string)
			if jti == "" {
				t.Error("no jti")
			}
			want := map[string]any{"iss": "reports", "sub": "reports", "aud": aud, "iat": float64(now.Unix()),
				"exp": float64(now.Add(time.Minute).Unix()), "jti": jti}
			if d := cmp.Diff(want, claims); d != "" {
				t.Errorf("claims (-want +got):\n%s", d)
			}
			if again := c.Mint(t, aud, now); part(t, again, 1)["jti"] == jti {
				t.Error("two assertions share a jti")
			}
		})
	}
}

func TestMintOptions(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "RS256")
	other := assertiontest.NewClient(t, "billing", "ES256")

	tok := c.Mint(t, aud, now, assertiontest.Claims(map[string]any{"exp": 1, "iat": nil}),
		assertiontest.Header(map[string]any{"kid": nil, "typ": "JWT"}))
	if h := part(t, tok, 0); h["kid"] != nil || h["typ"] != "JWT" {
		t.Errorf("header = %v", h)
	}
	if cl := part(t, tok, 1); cl["exp"] != float64(1) || cl["iat"] != nil {
		t.Errorf("claims = %v", cl)
	}

	signed := c.Mint(t, aud, now, assertiontest.SignedBy(other))
	if h := part(t, signed, 0); h["alg"] != "ES256" || h["kid"] != c.Kid() {
		t.Errorf("signed by another: header = %v", h)
	}
	if h := part(t, c.Mint(t, aud, now, assertiontest.Unsigned()), 0); h["alg"] != "none" {
		t.Errorf("unsigned: header = %v", h)
	}
	if h := part(t, c.Mint(t, aud, now, assertiontest.HMAC([]byte("secret-of-32-bytes-or-so-padding"))), 0); h["alg"] != "HS256" {
		t.Errorf("hmac: header = %v", h)
	}
}
