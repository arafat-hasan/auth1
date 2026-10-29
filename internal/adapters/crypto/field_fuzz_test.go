package crypto_test

import (
	"bytes"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// FuzzOpen checks that Open never panics, and opens nothing but what was sealed.
func FuzzOpen(f *testing.F) {
	k, err := crypto.ParseKeyring(keyringYAML(entry{1, 1, "active"}, entry{2, 50, "decrypt"}), crypto.StateDecrypt)
	if err != nil {
		f.Fatal(err)
	}
	fc := crypto.NewFieldCrypto(k)
	plaintext := []byte("Ada Lovelace")
	sealed, err := fc.Seal(place, plaintext)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add(sealed[:31])
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00, 0x02})
	f.Add(bytes.Repeat([]byte{0x01}, 31))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := fc.Open(place, in)
		if err != nil {
			return
		}
		// Fuzzing workers each seal their own seed, with another nonce, so the only check that
		// holds in every process is on the plaintext: nothing else was ever sealed under the key.
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Open accepted % x as %q", in, got)
		}
	})
}
