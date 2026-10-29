package crypto_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
)

var (
	_ app.FieldCrypto = (*crypto.FieldCrypto)(nil)

	rowID = uuid.MustParse("0190a5d3-7b2c-7e01-8f00-0123456789ab")
	place = app.NewPlace("accounts", "display_name", rowID)
)

// headerKid returns the key id of a ciphertext.
func headerKid(ct []byte) uint16 { return binary.BigEndian.Uint16(ct[1:3]) }

func mustSeal(t *testing.T, f *crypto.FieldCrypto, p app.Place, plaintext []byte) []byte {
	t.Helper()
	ct, err := f.Seal(p, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return ct
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	for _, plaintext := range [][]byte{{}, {'x'}, bytes.Repeat([]byte("Ada Lovelace "), 400)} {
		ct := mustSeal(t, f, place, plaintext)
		if len(ct) != 1+2+12+len(plaintext)+16 {
			t.Errorf("len = %d for %d bytes of plaintext", len(ct), len(plaintext))
		}
		if ct[0] != 0x01 || headerKid(ct) != 1 {
			t.Errorf("header % x, want version 1 and key id 1", ct[:3])
		}
		got, err := f.Open(place, ct)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Open = %q, want %q", got, plaintext)
		}
	}
}

func TestSealNonceFresh(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	a, b := mustSeal(t, f, place, []byte("same")), mustSeal(t, f, place, []byte("same"))
	if bytes.Equal(a[3:15], b[3:15]) || bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext share a nonce")
	}
}

func TestSealUsesActiveKey(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "decrypt"}, entry{2, 50, "active"}, entry{3, 99, "decrypt"}))
	for range 100 {
		if kid := headerKid(mustSeal(t, f, place, []byte("x"))); kid != 2 {
			t.Fatalf("sealed under key %d, want the active key 2", kid)
		}
	}
}

func TestOpenUnderDecryptKey(t *testing.T) {
	t.Parallel()
	before := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	ct := mustSeal(t, before, place, []byte("Ada"))
	after := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "decrypt"}, entry{2, 50, "active"}))
	got, err := after.Open(place, ct)
	if err != nil || string(got) != "Ada" {
		t.Errorf("Open under the decrypt key = %q, %v", got, err)
	}
	if kid := headerKid(mustSeal(t, after, place, []byte("Ada"))); kid != 2 {
		t.Errorf("after rotation sealed under %d, want 2", kid)
	}
}

func TestAssociatedData(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{7, 1, "active"}))
	ct := mustSeal(t, f, place, []byte("Ada"))
	block, err := aes.NewCipher(keyBytes(1))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ad := []byte("auth1|accounts|display_name|0190a5d3-7b2c-7e01-8f00-0123456789ab")
	got, err := aead.Open(nil, ct[3:15], ct[15:], ad)
	if err != nil || string(got) != "Ada" {
		t.Errorf("stdlib Open with the literal associated data = %q, %v", got, err)
	}
}

// TestOpenOtherPlace is T-35: a ciphertext copied to another row, column or table fails to open.
func TestOpenOtherPlace(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	tokenHash := bytes.Repeat([]byte{0xab}, 32)
	for _, tt := range []struct {
		name     string
		from, to app.Place
	}{
		{"row id", place, app.NewPlace("accounts", "display_name", uuid.MustParse("0190a5d3-7b2c-7e01-8f00-0123456789ac"))},
		{"column", app.NewPlace("challenges", "secret", rowID), app.NewPlace("challenges", "target_value", rowID)},
		{"table", app.NewPlace("challenges", "secret", rowID), app.NewPlace("flows", "secret", rowID)},
		{"key row", app.NewKeyPlace("refresh_tokens", "successor_enc", tokenHash),
			app.NewKeyPlace("refresh_tokens", "successor_enc", bytes.Repeat([]byte{0xac}, 32))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ct := mustSeal(t, f, tt.from, []byte("secret"))
			if _, err := f.Open(tt.from, ct); err != nil {
				t.Fatalf("Open in its own place: %v", err)
			}
			if got, err := f.Open(tt.to, ct); !errors.Is(err, app.ErrCiphertextInvalid) {
				t.Errorf("Open in another place = %q, %v; want ErrCiphertextInvalid", got, err)
			}
		})
	}
}

func TestOpenTamperedEveryByte(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}, entry{0x0101, 50, "decrypt"}))
	ct := mustSeal(t, f, place, []byte("Ada Lovelace"))
	for i := range ct {
		tampered := bytes.Clone(ct)
		tampered[i] ^= 0x01
		got, err := f.Open(place, tampered)
		switch {
		case err == nil:
			t.Errorf("byte %d flipped: opened as %q", i, got)
		case i == 1 || i == 2:
			// The key id: an unknown id, or another key's (0x0101) whose tag fails.
			if !errors.Is(err, app.ErrUnknownKey) && !errors.Is(err, app.ErrCiphertextInvalid) {
				t.Errorf("byte %d flipped: %v", i, err)
			}
		case !errors.Is(err, app.ErrCiphertextInvalid):
			t.Errorf("byte %d flipped: %v, want ErrCiphertextInvalid", i, err)
		}
	}
}

func TestOpenMalformed(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	empty := mustSeal(t, f, place, nil)
	if len(empty) != 31 {
		t.Fatalf("empty plaintext sealed to %d bytes, want 31", len(empty))
	}
	if got, err := f.Open(place, empty); err != nil || len(got) != 0 {
		t.Errorf("Open of the shortest ciphertext = %q, %v", got, err)
	}
	withVersion := func(v byte) []byte { c := bytes.Clone(empty); c[0] = v; return c }
	withKid := func(id uint16) []byte { c := bytes.Clone(empty); binary.BigEndian.PutUint16(c[1:3], id); return c }
	for _, tt := range []struct {
		name string
		in   []byte
		want error
	}{
		{"nil", nil, crypto.ErrCiphertextShort},
		{"one byte", []byte{0x01}, crypto.ErrCiphertextShort},
		{"30 bytes", empty[:30], crypto.ErrCiphertextShort},
		{"version 0", withVersion(0x00), crypto.ErrUnsupportedVersion},
		{"version 2", withVersion(0x02), crypto.ErrUnsupportedVersion},
		{"unknown key id", withKid(9), app.ErrUnknownKey},
		{"key id 0", withKid(0), app.ErrUnknownKey},
		{"tag", append(bytes.Clone(empty[:30]), empty[30]^0x80), crypto.ErrAuthentication},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := f.Open(place, tt.in)
			if !errors.Is(err, tt.want) {
				t.Errorf("Open = %v, want %v", err, tt.want)
			}
		})
	}
	for _, err := range []error{crypto.ErrCiphertextShort, crypto.ErrUnsupportedVersion, crypto.ErrAuthentication} {
		if !errors.Is(err, app.ErrCiphertextInvalid) {
			t.Errorf("%v does not wrap app.ErrCiphertextInvalid", err)
		}
	}
}

func TestPlaceInvalid(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	ct := mustSeal(t, f, place, []byte("x"))
	for name, p := range map[string]app.Place{
		"empty table":    {Table: "", Column: "display_name", Row: rowID.String()},
		"empty column":   {Table: "accounts", Column: "", Row: rowID.String()},
		"empty row":      {Table: "accounts", Column: "display_name", Row: ""},
		"| in table":     {Table: "acc|ounts", Column: "display_name", Row: rowID.String()},
		"| in column":    {Table: "accounts", Column: "display|name", Row: rowID.String()},
		"| in row":       {Table: "accounts", Column: "display_name", Row: "a|b"},
		"nil uuid":       app.NewPlace("accounts", "display_name", uuid.Nil),
		"empty key row":  app.NewKeyPlace("refresh_tokens", "successor_enc", nil),
		"zero-value all": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := f.Seal(p, []byte("x")); !errors.Is(err, app.ErrPlaceInvalid) {
				t.Errorf("Seal = %v, want ErrPlaceInvalid", err)
			}
			if _, err := f.Open(p, ct); !errors.Is(err, app.ErrPlaceInvalid) {
				t.Errorf("Open = %v, want ErrPlaceInvalid", err)
			}
		})
	}
}

func TestErrorsCarryNoSecrets(t *testing.T) {
	t.Parallel()
	f := crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"}))
	plaintext := []byte("Ada Lovelace")
	ct := mustSeal(t, f, place, plaintext)
	other := app.NewPlace("accounts", "display_name", uuid.MustParse("0190a5d3-7b2c-7e01-8f00-0123456789ac"))
	tampered := bytes.Clone(ct)
	tampered[20] ^= 1
	var errs []error
	for _, in := range [][]byte{ct[:5], tampered} {
		_, err := f.Open(place, in)
		errs = append(errs, err)
	}
	_, err := f.Open(other, ct)
	errs = append(errs, err)
	_, err = f.Seal(app.Place{Table: "accounts", Column: "", Row: rowID.String()}, plaintext)
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("no error")
		}
		for _, secret := range []string{rowID.String(), other.Row, string(plaintext), b64(keyBytes(1))} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q contains %q", err, secret)
			}
		}
	}
}
