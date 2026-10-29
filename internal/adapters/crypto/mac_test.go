package crypto_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
)

var (
	_ app.BlindIndex = (*crypto.BlindIndex)(nil)
	_ app.MAC        = (*crypto.MAC)(nil)
)

func mustBlindIndex(t *testing.T) *crypto.BlindIndex {
	t.Helper()
	b, err := crypto.NewBlindIndex(mustKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMAC(t *testing.T) *crypto.MAC {
	t.Helper()
	m, err := crypto.NewMAC(mustKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestZeroKeyRefused(t *testing.T) {
	t.Parallel()
	if b, err := crypto.NewBlindIndex(crypto.Key{}); err == nil || b != nil {
		t.Errorf("NewBlindIndex(zero key) = %v, %v; want an error", b, err)
	}
	if m, err := crypto.NewMAC(crypto.Key{}); err == nil || m != nil {
		t.Errorf("NewMAC(zero key) = %v, %v; want an error", m, err)
	}
}

// The known-answer vectors below were computed with OpenSSL, under the key 00 01 … 1f:
//
//	printf 'email\000a@example.com' | openssl dgst -sha256 -mac HMAC -macopt hexkey:0001…1f
//
// They pin the inputs' layout, so that stored indexes and MACs stay valid across releases.

func TestBlindIndexKnownAnswer(t *testing.T) {
	t.Parallel()
	b := mustBlindIndex(t)
	for _, tt := range []struct{ typ, value, want string }{
		{"email", "a@example.com", "c76b5f7cdd73f8618fdbd7183598f618532e1204d0cdfe3b0ff2535be6f76138"},
		{"phone", "+447700900123", "960367073b87276b670d2792ee63748db9d1878a62e1b47425e87b6b8b1dec00"},
	} {
		got, err := b.Compute(tt.typ, []byte(tt.value))
		if err != nil {
			t.Fatalf("Compute(%s): %v", tt.typ, err)
		}
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("Compute(%s, %s) = %x, want %s", tt.typ, tt.value, got, tt.want)
		}
	}
}

func TestBlindIndexDiffersByType(t *testing.T) {
	t.Parallel()
	b := mustBlindIndex(t)
	email, err := b.Compute("email", []byte("+447700900123"))
	if err != nil {
		t.Fatal(err)
	}
	phone, err := b.Compute("phone", []byte("+447700900123"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(email, phone) {
		t.Error("the same value has the same index under two types")
	}
	// The 0x00 separator keeps ("ab", "c") and ("a", "bc") apart.
	ab, _ := b.Compute("ab", []byte("c"))
	a, _ := b.Compute("a", []byte("bc"))
	if bytes.Equal(ab, a) {
		t.Error("type and value boundaries collide")
	}
}

func TestBlindIndexStable(t *testing.T) {
	t.Parallel()
	// Two instances under the same key, as after a restart, give the same index.
	x, _ := mustBlindIndex(t).Compute("email", []byte("a@example.com"))
	y, _ := mustBlindIndex(t).Compute("email", []byte("a@example.com"))
	if !bytes.Equal(x, y) || len(x) != 32 {
		t.Errorf("indexes %x and %x", x, y)
	}
}

func TestBlindIndexTypeInvalid(t *testing.T) {
	t.Parallel()
	b := mustBlindIndex(t)
	for _, typ := range []string{"", "em\x00ail", "\x00"} {
		if got, err := b.Compute(typ, []byte("a@example.com")); !errors.Is(err, app.ErrBlindIndexType) || got != nil {
			t.Errorf("Compute(%q) = %x, %v; want ErrBlindIndexType", typ, got, err)
		}
	}
}

func TestOTPKnownAnswer(t *testing.T) {
	t.Parallel()
	got := mustMAC(t).OTP(rowID, []byte("123456"))
	if want := "a9b97d2fb1fc3a28ac72c36e603cd3d905cf663fe517f45af646158aa43b5db0"; hex.EncodeToString(got) != want {
		t.Errorf("OTP = %x, want %s", got, want)
	}
}

func TestRecoveryCodeKnownAnswer(t *testing.T) {
	t.Parallel()
	got := mustMAC(t).RecoveryCode(rowID, []byte("ABCDE12345"))
	if want := "43ed2adfc18120dd11fe7f1ac60dea64b7c8b3626d5f12d7e7379ce25169ed8c"; hex.EncodeToString(got) != want {
		t.Errorf("RecoveryCode = %x, want %s", got, want)
	}
}

func TestMACsDomainSeparated(t *testing.T) {
	t.Parallel()
	m := mustMAC(t)
	for _, code := range []string{"123456", "ABCDE12345", ""} {
		if bytes.Equal(m.OTP(rowID, []byte(code)), m.RecoveryCode(rowID, []byte(code))) {
			t.Errorf("OTP and RecoveryCode are equal for %q", code)
		}
	}
}

func TestSHA256(t *testing.T) {
	t.Parallel()
	got := crypto.SHA256([]byte("abc"))
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; hex.EncodeToString(got) != want {
		t.Errorf("SHA256(abc) = %x, want %s", got, want)
	}
}
