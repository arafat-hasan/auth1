package keyring

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Test keys, generated once per test binary: RSA generation is slow.
var (
	rsaKeys = sync.OnceValue(func() []*rsa.PrivateKey {
		out := make([]*rsa.PrivateKey, 3)
		for i := range out {
			out[i] = mustRSA(2048)
		}
		return out
	})
	rsa1024 = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(1024) })
	ecKeys  = sync.OnceValue(func() []*ecdsa.PrivateKey {
		return []*ecdsa.PrivateKey{mustEC(elliptic.P256()), mustEC(elliptic.P256())}
	})
	ecP384 = sync.OnceValue(func() *ecdsa.PrivateKey { return mustEC(elliptic.P384()) })
)

func mustRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return k
}

func mustEC(c elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// The PEM encodings of a private key.
type encoding int

const (
	pkcs8 encoding = iota
	pkcs1          // RSA only
	sec1           // EC only
)

// pemOf encodes key.
func pemOf(t *testing.T, key any, enc encoding) []byte {
	t.Helper()
	var block *pem.Block
	switch enc {
	case pkcs8:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	case pkcs1:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))}
	case sec1:
		der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	}
	return pem.EncodeToMemory(block)
}

// spec is one key of a test keyring file.
type spec struct {
	alg   string
	state State
	key   any // a private key; nil writes no PEM
	enc   encoding
	file  string // the PEM's name; "" for k<i>.pem
	pem   []byte // written instead of key when set
}

// writeKeyring writes keyring.yaml and its PEM files into dir and returns the keyring's path.
// private_key_file is relative unless abs is set.
func writeKeyring(t *testing.T, dir string, specs []spec, abs bool) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("keys:\n")
	for i, s := range specs {
		name := s.file
		if name == "" {
			name = "k" + string(rune('0'+i)) + ".pem"
		}
		data := s.pem
		if data == nil && s.key != nil {
			data = pemOf(t, s.key, s.enc)
		}
		if data != nil {
			writeFile(t, filepath.Join(dir, name), data)
		}
		if abs {
			name = filepath.Join(dir, name)
		}
		b.WriteString("  - alg: " + s.alg + "\n    state: " + string(s.state) + "\n    private_key_file: " + name + "\n")
	}
	path := filepath.Join(dir, "keyring.yaml")
	writeFile(t, path, []byte(b.String()))
	return path
}

// writeFile replaces path atomically, as a mounted secret changes.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// kidOf returns the kid of a private key's public half.
func kidOf(t *testing.T, key any) string {
	t.Helper()
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	}
	kid, err := thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	return kid
}
