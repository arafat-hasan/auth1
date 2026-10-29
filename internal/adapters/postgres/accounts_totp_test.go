package postgres_test

import (
	"bytes"
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

var (
	secretA = []byte("aaaaaaaaaaaaaaaaaaaa") // 20 bytes, as TDD-03 §4.1 draws
	secretB = []byte("bbbbbbbbbbbbbbbbbbbb")
)

// totpAccount creates an account and starts enrolment with secretA.
func (e *accountsEnv) totpAccount(t *testing.T) account.NewAccount {
	t.Helper()
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	if ok, err := e.repo.StartTOTP(t.Context(), na.ID, secretA); err != nil || !ok {
		t.Fatalf("StartTOTP = %t, %v", ok, err)
	}
	return na
}

// confirmedTOTP creates an account with a TOTP factor on secretA confirmed at step.
func (e *accountsEnv) confirmedTOTP(t *testing.T, step int64) account.NewAccount {
	t.Helper()
	na := e.totpAccount(t)
	if ok, err := e.repo.ConfirmTOTP(t.Context(), na.ID, step); err != nil || !ok {
		t.Fatalf("ConfirmTOTP = %t, %v", ok, err)
	}
	return na
}

// factor returns the account's TOTP factor, failing the test on an error.
func (e *accountsEnv) factor(t *testing.T, na account.NewAccount) account.TOTPFactor {
	t.Helper()
	f, err := e.repo.TOTPFactor(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestAcceptTOTPStepOnce checks I-19: a step is accepted at most once, and never one at or before
// the last accepted step.
func TestAcceptTOTPStepOnce(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.confirmedTOTP(t, 100)
	for _, c := range []struct {
		step int64
		want bool
	}{
		{100, false}, // accepted at confirmation
		{101, true},
		{101, false},
		{100, false},
		{103, true},
		{102, false},
	} {
		got, err := e.repo.AcceptTOTPStep(t.Context(), na.ID, c.step)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("AcceptTOTPStep(%d) = %t, want %t", c.step, got, c.want)
		}
	}
	if f := e.factor(t, na); f.LastStep == nil || *f.LastStep != 103 {
		t.Errorf("last step = %v, want 103", f.LastStep)
	}
}

func TestAcceptTOTPStepUnconfirmedRefused(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.totpAccount(t)
	if ok, err := e.repo.AcceptTOTPStep(t.Context(), na.ID, 100); err != nil || ok {
		t.Errorf("unconfirmed factor: %t, %v; want refused", ok, err)
	}
	if ok, err := e.repo.AcceptTOTPStep(t.Context(), e.ids.New(), 100); err != nil || ok {
		t.Errorf("no factor: %t, %v; want refused", ok, err)
	}
}

// TestStartTOTPKeepsConfirmed checks that a restarted enrolment replaces an unconfirmed secret
// but never a confirmed factor (TDD-03 §4).
func TestStartTOTPKeepsConfirmed(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.totpAccount(t)
	if ok, err := e.repo.StartTOTP(t.Context(), na.ID, secretB); err != nil || !ok {
		t.Fatalf("restart = %t, %v", ok, err)
	}
	if f := e.factor(t, na); !bytes.Equal(f.Secret, secretB) || f.ConfirmedAt != nil {
		t.Fatalf("after restart: %v", f)
	}
	if ok, err := e.repo.ConfirmTOTP(t.Context(), na.ID, 100); err != nil || !ok {
		t.Fatalf("confirm = %t, %v", ok, err)
	}
	if ok, err := e.repo.StartTOTP(t.Context(), na.ID, secretA); err != nil || ok {
		t.Errorf("start over a confirmed factor = %t, %v; want refused", ok, err)
	}
	if f := e.factor(t, na); !bytes.Equal(f.Secret, secretB) || f.ConfirmedAt == nil {
		t.Errorf("confirmed factor changed: %v", f)
	}
}

func TestConfirmTOTP(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.confirmedTOTP(t, 100)
	f := e.factor(t, na)
	if f.ConfirmedAt == nil || f.LastStep == nil || *f.LastStep != 100 {
		t.Errorf("after confirmation: %v", f)
	}
	if ok, err := e.repo.ConfirmTOTP(t.Context(), na.ID, 101); err != nil || ok {
		t.Errorf("second confirmation = %t, %v; want refused", ok, err)
	}
	_, err := e.repo.TOTPFactor(t.Context(), e.ids.New())
	checkCode(t, err, domain.CodeNotFound)
}

// TestReplaceTOTP checks the replacement of TDD-03 §5.2, which accepts a step only after the last
// one, under the old secret or the new (I-19 is per account).
func TestReplaceTOTP(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.confirmedTOTP(t, 100)
	if ok, err := e.repo.ReplaceTOTP(t.Context(), na.ID, secretB, 100); err != nil || ok {
		t.Errorf("replace at the last step = %t, %v; want refused", ok, err)
	}
	if ok, err := e.repo.ReplaceTOTP(t.Context(), na.ID, secretB, 101); err != nil || !ok {
		t.Fatalf("replace = %t, %v", ok, err)
	}
	f := e.factor(t, na)
	if !bytes.Equal(f.Secret, secretB) || f.ConfirmedAt == nil || f.LastStep == nil || *f.LastStep != 101 {
		t.Errorf("after replacement: %v", f)
	}
	other := e.totpAccount(t)
	if ok, err := e.repo.ReplaceTOTP(t.Context(), other.ID, secretB, 200); err != nil || ok {
		t.Errorf("replace an unconfirmed factor = %t, %v; want refused", ok, err)
	}
}

func TestDeleteTOTP(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.confirmedTOTP(t, 100)
	if err := e.repo.DeleteTOTP(t.Context(), na.ID); err != nil {
		t.Fatal(err)
	}
	_, err := e.repo.TOTPFactor(t.Context(), na.ID)
	checkCode(t, err, domain.CodeNotFound)
	if err := e.repo.DeleteTOTP(t.Context(), na.ID); err != nil {
		t.Errorf("deleting no factor: %v", err)
	}
}

// TestTOTPSecretNotPlaintext checks that the secret is stored encrypted, bound to its account.
func TestTOTPSecretNotPlaintext(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.totpAccount(t)
	var raw []byte
	if err := e.su.QueryRowContext(t.Context(), "SELECT secret FROM totp_factors WHERE account_id = ?", na.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secretA) {
		t.Error("totp_factors.secret holds its plaintext")
	}
	if got, err := e.fc.Open(app.NewPlace("totp_factors", "secret", na.ID), raw); err != nil || !bytes.Equal(got, secretA) {
		t.Errorf("secret opens to %q, %v", got, err)
	}
}
