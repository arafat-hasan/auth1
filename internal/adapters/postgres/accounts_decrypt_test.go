package postgres_test

import (
	"sync/atomic"
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
)

// countingCrypto counts the fields it opens.
type countingCrypto struct {
	app.FieldCrypto
	opens atomic.Int64
}

func (c *countingCrypto) Open(place app.Place, ciphertext []byte) ([]byte, error) {
	c.opens.Add(1)
	return c.FieldCrypto.Open(place, ciphertext)
}

// TestNoBulkDecrypt checks that lookups decrypt nothing and reads decrypt only the fields of the
// one account they return (TDD-01 §6).
func TestNoBulkDecrypt(t *testing.T) {
	t.Parallel()
	counter := &countingCrypto{}
	e := accountsDBWith(t, func(fc app.FieldCrypto) app.FieldCrypto {
		counter.FieldCrypto = fc
		return counter
	})
	// Three pending holders of one phone, the first verified.
	first := e.newAccount(phone, "ada@example.org")
	e.create(t, first)
	e.create(t, e.newAccount(phone, ""))
	e.create(t, e.newAccount(phone, ""))
	if err := e.verify(t, first.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	e.replaceCodes(t, first.ID, e.codes(2, "mac-"))
	if ok, err := e.repo.StartTOTP(t.Context(), first.ID, secretA); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := e.repo.ConfirmTOTP(t.Context(), first.ID, 1); err != nil || !ok {
		t.Fatal(ok, err)
	}

	for _, c := range []struct {
		name string
		call func() error
		want int64
	}{
		{"FindCurrent", func() error { _, err := e.repo.FindCurrent(t.Context(), "phone", phone); return err }, 0},
		{"FindVerified", func() error { _, err := e.repo.FindVerified(t.Context(), "phone", phone); return err }, 0},
		{"UseRecoveryCode", func() error { _, err := e.repo.UseRecoveryCode(t.Context(), first.ID, []byte("mac-a")); return err }, 0},
		{"AcceptTOTPStep", func() error { _, err := e.repo.AcceptTOTPStep(t.Context(), first.ID, 2); return err }, 0},
		{"Roles", func() error { _, err := e.repo.Roles(t.Context(), first.ID); return err }, 0},
		{"TOTPFactor", func() error { _, err := e.repo.TOTPFactor(t.Context(), first.ID); return err }, 1},
		{"Get", func() error { _, err := e.repo.Get(t.Context(), first.ID); return err }, 1},
		{"Identifiers", func() error { _, err := e.repo.Identifiers(t.Context(), first.ID); return err }, 2},
	} {
		before := counter.opens.Load()
		if err := c.call(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := counter.opens.Load() - before; got != c.want {
			t.Errorf("%s opened %d fields, want %d", c.name, got, c.want)
		}
	}
}
