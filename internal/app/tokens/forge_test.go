package tokens_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"maps"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// The helpers below build tokens the issuer never would, to check that Validate refuses them.

// validClaims returns the claims of a full token that e issues, as decoded JSON values.
func validClaims(t *testing.T, e *env) map[string]any {
	t.Helper()
	got, err := e.iss.IssueAccess(session(), acct(account.StatusActive), client())
	if err != nil {
		t.Fatal(err)
	}
	_, claims := decode(t, got.Token)
	return claims
}

// with returns a copy of claims with the given changes; a nil value removes the claim.
func with(claims map[string]any, changes map[string]any) map[string]any {
	out := maps.Clone(claims)
	for k, v := range changes {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// sign returns claims as a compact JWS signed with alg and key, whose protected header also
// holds hdr (kid, typ and anything else). jws.Sign sets alg itself.
func sign(t *testing.T, alg jwa.SignatureAlgorithm, key any, hdr map[string]any, claims map[string]any, opts ...jws.SignOption) string {
	t.Helper()
	h := jws.NewHeaders()
	for k, v := range hdr {
		if err := h.Set(k, v); err != nil {
			t.Fatalf("header %s: %v", k, err)
		}
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, jws.WithKey(alg, key, jws.WithProtectedHeaders(h)))
	tok, err := jws.Sign(body, opts...)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(tok)
}

// unsigned returns header.payload. with an empty signature: an alg none token.
func unsigned(t *testing.T, hdr map[string]any, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(hdr) + "." + enc(claims) + "."
}

// rsaPublicDER is the RSA key's public key, PKIX DER: the secret of an HS256 confusion attack.
func rsaPublicDER(t *testing.T, e *env) []byte {
	t.Helper()
	rsaKid, _ := e.keys.Kids()
	der, err := x509.MarshalPKIXPublicKey(e.keys.Private(rsaKid).Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}
