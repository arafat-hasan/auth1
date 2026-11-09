package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var _ app.Savepoints = (*postgres.UnitOfWork)(nil)

// event writes one event about id.
func (e *outboxEnv) event(ctx context.Context, id uuid.UUID) error {
	return e.outbox.Event(ctx, "account.profile_updated", id, map[string]any{"changed": []string{"locale"}})
}

// TestSavepointRestoresLockRecords: a savepoint whose fn fails discards fn's writes, and the lock
// and event it recorded, so the commit that follows neither moves the version of an account fn
// only locked nor counts its discarded event (TDD-05 §4, I-10).
func TestSavepointRestoresLockRecords(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)

	e.do(t, func(ctx context.Context) error {
		err := e.uow.Savepoint(ctx, func(ctx context.Context) error {
			if err := e.lock(ctx, id); err != nil {
				return err
			}
			if err := e.event(ctx, id); err != nil {
				return err
			}
			return errSentinel
		})
		if !errors.Is(err, errSentinel) {
			t.Errorf("Savepoint = %v, want fn's error", err)
		}
		return nil
	})
	if v := e.version(t, id); v != 1 {
		t.Errorf("version = %d, want 1: the rolled-back lock moved it", v)
	}
	if rows := e.rows(t); len(rows) != 0 {
		t.Errorf("outbox rows = %v, want none", rows)
	}
}

// TestSavepointKeepsEarlierLock: a lock and an event taken before the savepoint survive its
// rollback; one taken after a successful savepoint commits as without it.
func TestSavepointKeepsEarlierLock(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)

	e.do(t, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.event(ctx, id); err != nil {
			return err
		}
		_ = e.uow.Savepoint(ctx, func(ctx context.Context) error {
			if err := e.event(ctx, id); err != nil {
				return err
			}
			return errSentinel
		})
		return e.uow.Savepoint(ctx, func(ctx context.Context) error { return e.event(ctx, id) })
	})
	if diff := cmp.Diff([]int64{2, 3}, e.eventVersions(t)); diff != "" {
		t.Errorf("event versions (-want +got):\n%s", diff)
	}
	if v := e.version(t, id); v != 3 {
		t.Errorf("version = %d, want 3", v)
	}
}

// TestSavepointNested: an inner savepoint's rollback keeps the outer savepoint's work.
func TestSavepointNested(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)

	e.do(t, func(ctx context.Context) error {
		return e.uow.Savepoint(ctx, func(ctx context.Context) error {
			if err := e.lock(ctx, id); err != nil {
				return err
			}
			if err := e.event(ctx, id); err != nil {
				return err
			}
			if err := e.uow.Savepoint(ctx, func(ctx context.Context) error {
				if err := e.event(ctx, id); err != nil {
					return err
				}
				return errSentinel
			}); !errors.Is(err, errSentinel) {
				t.Errorf("inner Savepoint = %v, want fn's error", err)
			}
			return nil
		})
	})
	if diff := cmp.Diff([]int64{2}, e.eventVersions(t)); diff != "" {
		t.Errorf("event versions (-want +got):\n%s", diff)
	}
	if v := e.version(t, id); v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
}

func TestSavepointOutsideTransaction(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	called := false
	err := e.uow.Savepoint(t.Context(), func(context.Context) error { called = true; return nil })
	if !errors.Is(err, postgres.ErrNoTransaction) || called {
		t.Errorf("Savepoint outside Do = %v, fn called = %v; want ErrNoTransaction and no call", err, called)
	}
}

// TestSavepointForgetsLocks: the locks a rolled-back savepoint took are released, so the
// transaction no longer counts them for the lock order (G-5): a method needing one is refused,
// and a lock they would forbid is allowed.
func TestSavepointForgetsLocks(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	nf := e.newFlow(acc, flow.KindRegistration, handle("a"))
	e.open(t, nf)
	c := e.otpChallenge(nf.ID, idID, email, "123456")
	e.openChallenges(t, nf, c)
	found, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	failing := func(lock func(ctx context.Context) error) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			if err := lock(ctx); err != nil {
				t.Fatalf("lock under the savepoint: %v", err)
			}
			return errSentinel
		}
	}
	lockAccount := func(ctx context.Context) error { _, err := e.repo.GetForUpdate(ctx, acc); return err }
	lockFlow := func(ctx context.Context) error { _, err := e.flows.LockFlow(ctx, found); return err }

	for name, tc := range map[string]struct {
		before, undone, after func(ctx context.Context) error
	}{
		"account": {
			undone: lockAccount,
			after:  lockFlow,
		},
		"flow": {
			before: lockAccount,
			undone: lockFlow,
			after: func(ctx context.Context) error {
				return e.flows.Update(ctx, nf.ID, flow.RegistrationState{}, 0)
			},
		},
		"challenges": {
			before: func(ctx context.Context) error {
				if err := lockAccount(ctx); err != nil {
					return err
				}
				return lockFlow(ctx)
			},
			undone: func(ctx context.Context) error { _, err := e.flows.LockChallenges(ctx, nf.ID); return err },
			after:  func(ctx context.Context) error { _, err := e.flows.CloseChallenge(ctx, c.ID, true); return err },
		},
	} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if tc.before != nil {
				if err := tc.before(ctx); err != nil {
					return err
				}
			}
			if err := e.uow.Savepoint(ctx, failing(tc.undone)); !errors.Is(err, errSentinel) {
				t.Fatalf("%s: Savepoint = %v", name, err)
			}
			return tc.after(ctx)
		})
		if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s: after the savepoint's rollback = %v, want ErrLockOrder", name, err)
		}
	}
}

// TestSavepointForgetsSessionLock: after a rolled-back savepoint that locked a session, the
// transaction may lock an account again.
func TestSavepointForgetsSessionLock(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	other := e.sessionAccount(t)
	e.do(t, func(ctx context.Context) error {
		if err := e.uow.Savepoint(ctx, func(ctx context.Context) error {
			if _, err := e.sessions.LockSession(ctx, s.AccountID, s.ID); err != nil {
				t.Fatalf("LockSession: %v", err)
			}
			return errSentinel
		}); !errors.Is(err, errSentinel) {
			t.Fatalf("Savepoint = %v", err)
		}
		_, err := e.repo.GetForUpdate(ctx, other)
		return err
	})
}
