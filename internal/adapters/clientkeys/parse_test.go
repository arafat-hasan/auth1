package clientkeys_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/arafat-hasan/auth1/internal/adapters/clientkeys"
)

// Keys made once: generating RSA keys is slow.
var (
	rsa2048, _ = rsa.GenerateKey(rand.Reader, 2048)
	rsa1024, _ = rsa.GenerateKey(rand.Reader, 1024)
	p256, _    = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _    = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
)

// jwkOf returns key as a JWK with the given parameters set; a nil value leaves one out.
func jwkOf(t testing.TB, key any, params map[string]any) json.RawMessage {
	t.Helper()
	k, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range params {
		if v == nil {
			continue
		}
		if err := k.Set(name, v); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shortRSA is a 1024-bit RSA JWK, written by hand: jwx refuses to build one.
func shortRSA(t testing.TB) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"kty": "RSA", "kid": "short",
		"n": base64.RawURLEncoding.EncodeToString(rsa1024.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsa1024.E)).Bytes()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// set returns a JWKS of keys.
func set(t testing.TB, keys ...json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	t.Parallel()
	good := func(t testing.TB) json.RawMessage {
		return jwkOf(t, rsa2048.Public(), map[string]any{"kid": "good", "alg": "RS256", "use": "sig"})
	}
	tests := []struct {
		name    string
		data    func(t testing.TB) []byte
		want    map[string]string // kid → alg
		wantErr bool
	}{
		{name: "RSA 2048", data: func(t testing.TB) []byte { return set(t, good(t)) }, want: map[string]string{"good": "RS256"}},
		{name: "P-256 without alg or use", data: func(t testing.TB) []byte {
			return set(t, jwkOf(t, p256.Public(), map[string]any{"kid": "ec"}))
		}, want: map[string]string{"ec": "ES256"}},
		{name: "private key published as public", data: func(t testing.TB) []byte {
			return set(t, jwkOf(t, rsa2048, map[string]any{"kid": "priv"}))
		}, want: map[string]string{"priv": "RS256"}},
		{name: "unusable keys skipped", data: func(t testing.TB) []byte {
			return set(t, good(t),
				jwkOf(t, p256.Public(), nil), // no kid
				jwkOf(t, p256.Public(), map[string]any{"kid": "enc", "use": "enc"}),
				shortRSA(t),
				jwkOf(t, p384.Public(), map[string]any{"kid": "p384"}),
				jwkOf(t, rsa2048.Public(), map[string]any{"kid": "mismatch", "alg": "ES256"}),
				jwkOf(t, p256.Public(), map[string]any{"kid": "rs384", "alg": "RS384"}),
				jwkOf(t, []byte("0123456789abcdef0123456789abcdef"), map[string]any{"kid": "oct"}),
				json.RawMessage(`{"kty":"OKP","crv":"X25519","kid":"x","x":"AAAA"}`),
			)
		}, want: map[string]string{"good": "RS256"}},
		{name: "repeated kid", data: func(t testing.TB) []byte {
			return set(t, good(t), jwkOf(t, p256.Public(), map[string]any{"kid": "good"}))
		}, wantErr: true},
		{name: "no usable key", data: func(t testing.TB) []byte {
			return set(t, shortRSA(t))
		}, wantErr: true},
		{name: "empty set", data: func(testing.TB) []byte { return []byte(`{"keys":[]}`) }, wantErr: true},
		{name: "a single key, not a set", data: func(t testing.TB) []byte { return good(t) }, wantErr: true},
		{name: "not JSON", data: func(testing.TB) []byte { return []byte("keys") }, wantErr: true},
		{name: "over 64 KiB", data: func(t testing.TB) []byte {
			b := set(t, good(t))
			return append(b[:len(b)-1], []byte(`,"pad":"`+strings.Repeat("x", 64<<10)+`"}`)...)
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := clientkeys.Parse(tt.data(t))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse = %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Parse = %d keys, want %d", len(got), len(tt.want))
			}
			for kid, alg := range tt.want {
				pk, ok := got[kid]
				if !ok || pk.Kid != kid || pk.Alg != alg {
					t.Errorf("key %s = %+v, want alg %s", kid, pk, alg)
					continue
				}
				switch pk.Key.(type) {
				case *rsa.PublicKey, *ecdsa.PublicKey:
				default:
					t.Errorf("key %s is a %T, not a public key", kid, pk.Key)
				}
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(set(f, jwkOf(f, rsa2048.Public(), map[string]any{"kid": "a"})))
	f.Add(set(f, jwkOf(f, p256.Public(), map[string]any{"kid": "b", "alg": "ES256"})))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"c","x":"","y":""}]}`))
	f.Add([]byte(`{"keys":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := clientkeys.Parse(data)
		if err != nil {
			return
		}
		if len(keys) == 0 {
			t.Fatal("no error and no key")
		}
		for kid, pk := range keys {
			if kid == "" || pk.Kid != kid {
				t.Fatalf("kid %q holds %q", kid, pk.Kid)
			}
			switch k := pk.Key.(type) {
			case *rsa.PublicKey:
				if pk.Alg != "RS256" || k.N.BitLen() < 2048 {
					t.Fatalf("RSA key %s: alg %s, %d bits", kid, pk.Alg, k.N.BitLen())
				}
			case *ecdsa.PublicKey:
				if pk.Alg != "ES256" || k.Curve != elliptic.P256() {
					t.Fatalf("EC key %s: alg %s", kid, pk.Alg)
				}
			default:
				t.Fatalf("key %s is a %T", kid, pk.Key)
			}
		}
	})
}

var _ crypto.PublicKey = rsa2048.Public()
