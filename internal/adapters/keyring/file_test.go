package keyring

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

// The example key of RFC 7638 §3.1 and its thumbprint.
const (
	rfc7638N   = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638Kid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

func TestThumbprintKnownAnswer(t *testing.T) {
	t.Parallel()
	n, err := base64.RawURLEncoding.DecodeString(rfc7638N)
	if err != nil {
		t.Fatal(err)
	}
	got, err := thumbprint(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	if got != rfc7638Kid {
		t.Errorf("thumbprint = %s, want %s", got, rfc7638Kid)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	for _, abs := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%v", abs), func(t *testing.T) {
			t.Parallel()
			r, e := rsaKeys(), ecKeys()
			path := writeKeyring(t, t.TempDir(), []spec{
				{alg: AlgRS256, state: StateRetired, key: r[0], enc: pkcs1},
				{alg: AlgRS256, state: StateActive, key: r[1], enc: pkcs8},
				{alg: AlgES256, state: StateNext, key: e[0], enc: sec1},
				{alg: AlgES256, state: StateNext, key: e[1], enc: pkcs8},
			}, abs)
			f, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			want := []struct {
				alg   string
				state State
				kid   string
			}{
				{AlgRS256, StateRetired, kidOf(t, r[0])},
				{AlgRS256, StateActive, kidOf(t, r[1])},
				{AlgES256, StateNext, kidOf(t, e[0])},
				{AlgES256, StateNext, kidOf(t, e[1])},
			}
			if len(f.Keys) != len(want) {
				t.Fatalf("%d keys, want %d", len(f.Keys), len(want))
			}
			for i, w := range want {
				k := f.Keys[i]
				if k.Alg != w.alg || k.State != w.state || k.Kid != w.kid {
					t.Errorf("keys[%d] = %s, want %s %s %s", i, k, w.alg, w.state, w.kid)
				}
				if k.private == nil {
					t.Errorf("keys[%d] has no private key", i)
				}
			}
			if f.Active().Kid != kidOf(t, r[1]) {
				t.Errorf("Active = %s", f.Active())
			}
			if f.Path != path {
				t.Errorf("Path = %s, want %s", f.Path, path)
			}
		})
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Parallel()
	r, e := rsaKeys(), ecKeys()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	active := spec{alg: AlgRS256, state: StateActive, key: r[0]}
	twoBlocks := append(pemOf(t, r[1], pkcs8), pemOf(t, r[2], pkcs8)...)
	tests := []struct {
		name  string
		specs []spec
		yaml  string // the keyring file, instead of specs
		want  string // in the error, after the keyring's path
	}{
		{name: "no keys", yaml: "keys: []\n", want: ": no keys"},
		{name: "empty file", yaml: "", want: ": no keys"},
		{name: "no active key", specs: []spec{{alg: AlgRS256, state: StateNext, key: r[0]}},
			want: ": 0 active keys; exactly one is required"},
		{name: "two active keys", specs: []spec{active, {alg: AlgES256, state: StateActive, key: e[0]}},
			want: ": 2 active keys; exactly one is required"},
		{name: "RSA under 2048 bits", specs: []spec{active, {alg: AlgRS256, state: StateNext, key: rsa1024()}},
			want: ": keys[1]: an RSA key of 1024 bits; RS256 needs at least 2048"},
		{name: "wrong curve", specs: []spec{active, {alg: AlgES256, state: StateNext, key: ecP384()}},
			want: ": keys[1]: an EC key on P-384; ES256 needs P-256"},
		{name: "RSA key for ES256", specs: []spec{active, {alg: AlgES256, state: StateNext, key: r[1]}},
			want: ": keys[1]: an RSA key; ES256 needs an EC P-256 key"},
		{name: "EC key for RS256", specs: []spec{active, {alg: AlgRS256, state: StateNext, key: e[0]}},
			want: ": keys[1]: an EC key; RS256 needs an RSA key"},
		{name: "Ed25519 key", specs: []spec{active, {alg: AlgES256, state: StateNext, key: ed}},
			want: ": keys[1]: a ed25519.PrivateKey key; ES256 needs an EC P-256 key"},
		{name: "unknown alg", specs: []spec{active, {alg: "HS256", state: StateNext, key: r[1]}},
			want: `: keys[1]: alg "HS256" is not RS256 or ES256`},
		{name: "unknown state", specs: []spec{active, {alg: AlgRS256, state: "pending", key: r[1]}},
			want: `: keys[1]: state "pending" is not next, active or retired`},
		{name: "duplicate in another encoding", specs: []spec{active, {alg: AlgRS256, state: StateRetired, key: r[0], enc: pkcs1}},
			want: ": keys[1]: the same key as keys[0]"},
		{name: "missing PEM file", specs: []spec{active, {alg: AlgRS256, state: StateNext}},
			want: ": keys[1]: open "},
		{name: "two PEM blocks", specs: []spec{active, {alg: AlgRS256, state: StateNext, pem: twoBlocks}},
			want: ": keys[1]: private_key_file holds more than one PEM block"},
		{name: "not PEM", specs: []spec{active, {alg: AlgRS256, state: StateNext, pem: []byte("not a key\n")}},
			want: ": keys[1]: private_key_file is not PEM"},
		{name: "certificate", specs: []spec{active, {alg: AlgRS256, state: StateNext, pem: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")}},
			want: `: keys[1]: PEM block "CERTIFICATE" is not PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY`},
		{name: "corrupt DER", specs: []spec{active, {alg: AlgRS256, state: StateNext, pem: []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")}},
			want: ": keys[1]: private_key_file: cannot parse the PRIVATE KEY"},
		{name: "unknown field", yaml: "keys:\n  - alg: RS256\n    state: active\n    privat_key_file: k.pem\n",
			want: "field privat_key_file not found"},
		{name: "two YAML documents", yaml: "keys: []\n---\nkeys:\n  - alg: RS256\n    state: active\n    private_key_file: k.pem\n",
			want: ": more than one YAML document"},
		{name: "no private_key_file", yaml: "keys:\n  - alg: RS256\n    state: active\n",
			want: ": keys[0]: private_key_file is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			var path string
			if tt.specs != nil {
				path = writeKeyring(t, dir, tt.specs, false)
			} else {
				path = filepath.Join(dir, "keyring.yaml")
				writeFile(t, path, []byte(tt.yaml))
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load succeeded")
			}
			msg := err.Error()
			if !strings.Contains(msg, "signing keyring "+path) || !strings.Contains(msg, tt.want) {
				t.Errorf("error %q, want the path %s and %q", msg, path, tt.want)
			}
			assertNoKeyMaterial(t, msg)
		})
	}
}

// keyMaterial returns strings that would show a test key's private or public numbers or PEM.
func keyMaterial() []string {
	out := []string{"BEGIN", "MII"}
	for _, k := range rsaKeys() {
		out = append(out, k.D.String(), k.N.String(), k.Primes[0].String(), k.N.Text(16))
	}
	for _, k := range ecKeys() {
		d, _ := k.Bytes()
		out = append(out, new(big.Int).SetBytes(d).String(), base64.RawURLEncoding.EncodeToString(d))
	}
	return out
}

func assertNoKeyMaterial(t *testing.T, s string) {
	t.Helper()
	for _, m := range keyMaterial() {
		if strings.Contains(s, m) {
			t.Fatalf("key material %.20s… printed in %.200s…", m, s)
		}
	}
}

// formatted is v through every fmt verb that could expose fields, and through slog's text and
// JSON handlers.
func formatted(v any) string {
	var b bytes.Buffer
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		fmt.Fprintf(&b, verb+"\n", v)
	}
	slog.New(slog.NewTextHandler(&b, nil)).Info("m", "v", v)
	slog.New(slog.NewJSONHandler(&b, nil)).Info("m", "v", v)
	return b.String()
}

func TestKeyNeverPrinted(t *testing.T) {
	t.Parallel()
	r, e := rsaKeys(), ecKeys()
	f, err := Load(writeKeyring(t, t.TempDir(), []spec{
		{alg: AlgRS256, state: StateActive, key: r[0]},
		{alg: AlgES256, state: StateNext, key: e[0]},
	}, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{f, *f, f.Keys, f.Keys[0], &f.Keys[1], struct{ K Key }{f.Keys[0]}} {
		out := formatted(v)
		assertNoKeyMaterial(t, out)
		if !strings.Contains(out, f.Keys[0].Kid) && !strings.Contains(out, f.Keys[1].Kid) {
			t.Errorf("no kid in %q", out)
		}
	}
}
