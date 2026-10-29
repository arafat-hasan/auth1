package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

var reasons = []string{"abuse", "chargeback"}

// activeAccount creates an account and activates it.
func (e *accountsEnv) activeAccount(t *testing.T, phone string) account.NewAccount {
	t.Helper()
	na := e.newAccount(phone, "")
	e.create(t, na)
	e.do(t, func(ctx context.Context) error { return e.repo.Activate(ctx, na.ID) })
	return na
}

// apply decides change for the account as it is stored and applies it in one transaction.
func (e *accountsEnv) apply(t *testing.T, id uuid.UUID, change account.Change) account.Decision {
	t.Helper()
	var d account.Decision
	e.do(t, func(ctx context.Context) error {
		a, err := e.repo.GetForUpdate(ctx, id)
		if err != nil {
			return err
		}
		if d, err = account.Transition(a.Status, change, reasons, time.Now()); err != nil {
			return err
		}
		return e.repo.ApplyStatus(ctx, id, d)
	})
	return d
}

// TestApplyStatusRoundTrip checks that every kind of Decision is stored as it is and satisfies
// the accounts CHECKs.
func TestApplyStatusRoundTrip(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.activeAccount(t, "")
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)

	for _, c := range []struct {
		name   string
		change account.Change
	}{
		{"suspend until", account.Change{To: account.StatusSuspended, ReasonCode: "abuse", Until: &until}},
		{"suspend open", account.Change{To: account.StatusSuspended, ReasonCode: "chargeback"}},
		{"ban", account.Change{To: account.StatusBanned, ReasonCode: "abuse"}},
		{"reactivate", account.Change{To: account.StatusActive}},
		{"delete", account.Change{To: account.StatusDeleted}},
	} {
		before, err := e.repo.Get(t.Context(), na.ID)
		if err != nil {
			t.Fatal(err)
		}
		d := e.apply(t, na.ID, c.change)
		got, err := e.repo.Get(t.Context(), na.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != d.Status || got.StatusReason != d.Reason || !equalTime(got.StatusUntil, d.Until) {
			t.Errorf("%s: stored %s %q %v, want %s %q %v", c.name,
				got.Status, got.StatusReason, got.StatusUntil, d.Status, d.Reason, d.Until)
		}
		if !got.StatusChangedAt.After(before.StatusChangedAt) {
			t.Errorf("%s: status_changed_at not moved", c.name)
		}
	}
}

// equalTime reports whether a and b are both nil or the same instant.
func equalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// TestApplyStatusNoop checks that an unchanged Decision writes nothing.
func TestApplyStatusNoop(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.activeAccount(t, "")
	before, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := e.apply(t, na.ID, account.Change{To: account.StatusActive}); d.Changed {
		t.Fatalf("active to active changed: %+v", d)
	}
	got, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StatusChangedAt.Equal(before.StatusChangedAt) {
		t.Errorf("status_changed_at moved on a no-op")
	}
	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		return e.repo.ApplyStatus(ctx, e.ids.New(), account.Decision{Changed: true, Status: account.StatusActive})
	})
	checkCode(t, err, domain.CodeNotFound)
}

// TestApplyStatusDeleteErases checks deletion's effects inside the aggregate: the password, the
// TOTP factor and the recovery codes are erased and every identifier is released.
func TestApplyStatusDeleteErases(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.activeAccount(t, phone)
	if err := e.verify(t, na.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.repo.StartTOTP(t.Context(), na.ID, secretA); err != nil || !ok {
		t.Fatal(ok, err)
	}
	e.replaceCodes(t, na.ID, e.codes(2, "mac-"))

	e.apply(t, na.ID, account.Change{To: account.StatusDeleted})

	if _, err := e.repo.PasswordCredential(t.Context(), na.ID); !isCode(err, domain.CodeNotFound) {
		t.Errorf("password after deletion: %v", err)
	}
	if _, err := e.repo.TOTPFactor(t.Context(), na.ID); !isCode(err, domain.CodeNotFound) {
		t.Errorf("TOTP factor after deletion: %v", err)
	}
	if n := e.unused(t, na.ID); n != 0 {
		t.Errorf("%d recovery codes after deletion", n)
	}
	if ids, err := e.repo.Identifiers(t.Context(), na.ID); err != nil || len(ids) != 0 {
		t.Errorf("identifiers after deletion: %v, %v", ids, err)
	}
	other := e.newAccount(phone, "")
	e.create(t, other)
	if err := e.verify(t, other.Identifiers[0].ID); err != nil {
		t.Errorf("released phone not verifiable: %v", err)
	}
}

// TestApplyStatusOutsideTransaction checks that a change is refused outside UnitOfWork.Do: it
// was decided from the status read under the account's lock, which only a transaction holds.
func TestApplyStatusOutsideTransaction(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.activeAccount(t, "")
	for _, change := range []account.Change{
		{To: account.StatusSuspended, ReasonCode: "abuse"}, // no effects
		{To: account.StatusDeleted},                        // effects
	} {
		d, err := account.Transition(account.StatusActive, change, reasons, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.repo.ApplyStatus(t.Context(), na.ID, d); !errors.Is(err, postgres.ErrNoTransaction) {
			t.Errorf("ApplyStatus to %s outside Do: %v", change.To, err)
		}
	}
	if got, err := e.repo.Get(t.Context(), na.ID); err != nil || got.Status != account.StatusActive {
		t.Errorf("status = %s, %v; want active", got.Status, err)
	}
}

// isCode reports whether err is a *domain.Error with code.
func isCode(err error, code domain.Code) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Code == code
}
