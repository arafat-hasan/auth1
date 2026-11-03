package fakes

import (
	"errors"
	"slices"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
)

// header returns the protected header's alg, kid and typ of the compact JWS tok.
func header(t *testing.T, tok string) (alg, kid, typ string) {
	t.Helper()
	msg, err := jws.Parse([]byte(tok))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	a, _ := h.Algorithm()
	kid, _ = h.KeyID()
	typ, _ = h.Type()
	return a.String(), kid, typ
}

func verifies(t *testing.T, k *Keys, tok string) {
	t.Helper()
	_, kid, _ := header(t, tok)
	pk, ok := k.Key(kid)
	if !ok {
		t.Fatalf("kid %s is not published", kid)
	}
	alg, ok := jwa.LookupSignatureAlgorithm(pk.Alg)
	if !ok {
		t.Fatalf("unknown alg %s", pk.Alg)
	}
	if _, err := jws.Verify([]byte(tok), jws.WithKey(alg, pk.Key)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func kids(pks []app.PublicKey) []string {
	out := make([]string, len(pks))
	for i, pk := range pks {
		out[i] = pk.Kid
	}
	return out
}

func TestKeysSignVerifies(t *testing.T) {
	t.Parallel()
	k := NewKeys()
	rsaKid, ecKid := k.Kids()
	if rsaKid == "" || ecKid == "" || rsaKid == ecKid {
		t.Fatalf("Kids() = %q, %q", rsaKid, ecKid)
	}
	if pks, ok := k.Published(); !ok || !slices.Equal(kids(pks), []string{rsaKid, ecKid}) {
		t.Fatalf("Published() = %v, %v; want both keys", kids(pks), ok)
	}

	tok, err := k.Sign([]byte(`{"sub":"x"}`), "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if alg, kid, typ := header(t, tok); alg != "RS256" || kid != rsaKid || typ != "at+jwt" {
		t.Errorf("header = %s, %s, %s; want RS256, %s, at+jwt", alg, kid, typ, rsaKid)
	}
	verifies(t, k, tok)

	k.SetActive(ecKid)
	tok, err = k.Sign([]byte(`{"sub":"x"}`), "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if alg, kid, _ := header(t, tok); alg != "ES256" || kid != ecKid {
		t.Errorf("after SetActive: alg %s, kid %s; want ES256, %s", alg, kid, ecKid)
	}
	verifies(t, k, tok)

	k.Unpublish(rsaKid)
	if _, ok := k.Key(rsaKid); ok {
		t.Error("Key finds an unpublished kid")
	}
	if pks, _ := k.Published(); !slices.Equal(kids(pks), []string{ecKid}) {
		t.Errorf("Published() after Unpublish = %v", kids(pks))
	}

	k.NoSigner()
	if _, err := k.Sign([]byte(`{}`), "at+jwt"); !errors.Is(err, app.ErrNoSigningKey) {
		t.Errorf("Sign after NoSigner: %v; want ErrNoSigningKey", err)
	}
	if k.Private(rsaKid) == nil || k.Private(ecKid) == nil {
		t.Error("Private returns nil for a known kid")
	}
}
