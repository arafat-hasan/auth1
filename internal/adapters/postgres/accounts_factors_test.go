package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
)

func TestFailFactor(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	a := e.newAccount("", "factor@example.org")
	e.create(t, a)
	fail := func() (n int) {
		t.Helper()
		e.do(t, func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, a.ID); err != nil {
				return err
			}
			var err error
			n, err = e.repo.FailFactor(ctx, a.ID, time.Hour)
			return err
		})
		return n
	}
	if n := fail(); n != 1 {
		t.Errorf("first failure: %d", n)
	}
	if n := fail(); n != 2 {
		t.Errorf("second failure: %d", n)
	}
	got, err := e.repo.Get(t.Context(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FactorFailures != 2 || got.FactorFailuresSince == nil || time.Since(*got.FactorFailuresSince) > time.Minute {
		t.Errorf("stored: %d since %v", got.FactorFailures, got.FactorFailuresSince)
	}

	// A window that has ended starts again at 1, from now.
	e.exec(t, "UPDATE accounts SET factor_failures_since = now() - interval '61 minutes' WHERE id = ?", a.ID)
	if n := fail(); n != 1 {
		t.Errorf("after the window: %d", n)
	}
	if got, _ := e.repo.Get(t.Context(), a.ID); time.Since(*got.FactorFailuresSince) > time.Minute {
		t.Errorf("window not restarted: %v", got.FactorFailuresSince)
	}

	// The counter is not the account's version: a failure moves it only through the lock.
	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, err := e.repo.FailFactor(ctx, a.ID, time.Hour)
		return err
	})
	if !errors.Is(err, postgres.ErrLockOrder) {
		t.Errorf("without the account lock: %v, want ErrLockOrder", err)
	}
	if _, err := e.repo.FailFactor(t.Context(), a.ID, time.Hour); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("outside a transaction: %v, want ErrNoTransaction", err)
	}
}
