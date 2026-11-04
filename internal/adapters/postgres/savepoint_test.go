package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
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
