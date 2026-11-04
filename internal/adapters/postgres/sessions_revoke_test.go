package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// another creates another session of the account, whose first token is name's.
func (e *sessionsEnv) another(t *testing.T, accountID uuid.UUID, name string) session.NewSession {
	t.Helper()
	s := e.newSession(accountID)
	e.createSession(t, s, name)
	return s
}

// underAccount runs fn in a transaction of its own, under the account's lock.
func (e *sessionsEnv) underAccount(t *testing.T, accountID uuid.UUID, fn func(ctx context.Context) error) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, accountID); err != nil {
			return err
		}
		return fn(ctx)
	})
}

// checkRevoked fails the test unless name's session is revoked for reason, or, for an empty
// reason, not revoked.
func (e *sessionsEnv) checkRevoked(t *testing.T, name string, reason session.RevokeReason) {
	t.Helper()
	_, s := e.find(t, name)
	if s.RevokeReason != reason || (s.RevokedAt != nil) != (reason != "") {
		t.Errorf("%s: revoked at %v for %q, want %q", name, s.RevokedAt, s.RevokeReason, reason)
	}
}

func TestRevoke(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	e.start(t, "b")
	e.do(t, func(ctx context.Context) error {
		_, s, err := e.sessions.FindToken(ctx, tokenHash("a"), grace)
		if err != nil {
			return err
		}
		if ok, err := e.sessions.Revoke(ctx, s.ID, session.RevokeSignedOut); err != nil || !ok {
			t.Fatalf("revoke: %v, %v", ok, err)
		}
		ok, err := e.sessions.Revoke(ctx, s.ID, session.RevokeRefreshReuse)
		if ok {
			t.Error("a revoked session was revoked again")
		}
		return err
	})
	if _, s := e.find(t, "a"); s.Live {
		t.Error("the revoked session is live")
	}
	e.checkRevoked(t, "a", session.RevokeSignedOut)
	e.checkRevoked(t, "b", "")
}

// sessionSet is an account with two live sessions, an expired one and one revoked already, beside
// a live session of another account.
func (e *sessionsEnv) sessionSet(t *testing.T) (accountID uuid.UUID, live1, live2 session.NewSession) {
	t.Helper()
	live1 = e.start(t, "live1")
	accountID = live1.AccountID
	live2 = e.another(t, accountID, "live2")
	expired := e.another(t, accountID, "expired")
	e.exec(t, "UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE id = ?", expired.ID)
	revoked := e.another(t, accountID, "revoked")
	e.exec(t, "UPDATE sessions SET revoked_at = now(), revoke_reason = 'operator' WHERE id = ?", revoked.ID)
	e.start(t, "other")
	return accountID, live1, live2
}

func TestRevokeAll(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	acc, _, _ := e.sessionSet(t)
	e.underAccount(t, acc, func(ctx context.Context) error {
		n, err := e.sessions.RevokeAll(ctx, acc, session.RevokePasswordReset)
		if n != 2 {
			t.Errorf("revoked %d, want 2", n)
		}
		return err
	})
	e.checkRevoked(t, "live1", session.RevokePasswordReset)
	e.checkRevoked(t, "live2", session.RevokePasswordReset)
	e.checkRevoked(t, "expired", "")
	e.checkRevoked(t, "revoked", session.RevokeOperator)
	e.checkRevoked(t, "other", "")
}

func TestRevokeAllExcept(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	acc, keep, _ := e.sessionSet(t)
	e.underAccount(t, acc, func(ctx context.Context) error {
		n, err := e.sessions.RevokeAllExcept(ctx, acc, keep.ID, session.RevokePasswordChanged)
		if n != 1 {
			t.Errorf("revoked %d, want 1", n)
		}
		return err
	})
	e.checkRevoked(t, "live1", "")
	e.checkRevoked(t, "live2", session.RevokePasswordChanged)
	e.checkRevoked(t, "expired", "")
	e.checkRevoked(t, "revoked", session.RevokeOperator)
	e.checkRevoked(t, "other", "")
}

func TestListLive(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	acc, live1, live2 := e.sessionSet(t)
	got, err := e.sessions.ListLive(t.Context(), acc)
	if err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for _, s := range got {
		ids = append(ids, s.ID)
		if !s.Live || s.AccountID != acc || s.ClientID != "web" || s.UserAgent != "Mozilla/5.0" {
			t.Errorf("listed %+v", s)
		}
	}
	if diff := cmp.Diff([]uuid.UUID{live2.ID, live1.ID}, ids); diff != "" {
		t.Errorf("live sessions, newest first (-want +got):\n%s", diff)
	}
	if got, err := e.sessions.ListLive(t.Context(), e.ids.New()); err != nil || len(got) != 0 {
		t.Errorf("an unknown account: %v, %v", got, err)
	}
}

// TestSessionLockOrder checks G-5: every method that needs a lock refuses, without querying,
// outside a transaction and without its lock: the account for Create and the revocations of an
// account, the session for Rotate, Successor and Revoke.
func TestSessionLockOrder(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	acc := s.AccountID
	calls := map[string]func(ctx context.Context) error{
		"Create": func(ctx context.Context) error { return e.sessions.Create(ctx, e.newSession(acc), tokenHash("z")) },
		"RevokeAll": func(ctx context.Context) error {
			_, err := e.sessions.RevokeAll(ctx, acc, session.RevokeOperator)
			return err
		},
		"RevokeAllExcept": func(ctx context.Context) error {
			_, err := e.sessions.RevokeAllExcept(ctx, acc, s.ID, session.RevokeOperator)
			return err
		},
		"Rotate": func(ctx context.Context) error {
			_, err := e.sessions.Rotate(ctx, s.ID, tokenHash("a"), tokenHash("b"), rawToken("b"), idleTTL)
			return err
		},
		"Successor": func(ctx context.Context) error {
			_, _, err := e.sessions.Successor(ctx, s.ID, tokenHash("a"), grace)
			return err
		},
		"Revoke": func(ctx context.Context) error {
			_, err := e.sessions.Revoke(ctx, s.ID, session.RevokeOperator)
			return err
		},
	}
	outside := map[string]func(ctx context.Context) error{
		"FindToken": func(ctx context.Context) error {
			_, _, err := e.sessions.FindToken(ctx, tokenHash("a"), grace)
			return err
		},
		"LockSession": func(ctx context.Context) error { _, err := e.sessions.LockSession(ctx, acc, s.ID); return err },
	}
	for name, call := range outside {
		if err := call(t.Context()); !errors.Is(err, postgres.ErrNoTransaction) {
			t.Errorf("%s outside a transaction: %v, want ErrNoTransaction", name, err)
		}
	}
	for name, call := range calls {
		if err := call(t.Context()); !errors.Is(err, postgres.ErrNoTransaction) {
			t.Errorf("%s outside a transaction: %v, want ErrNoTransaction", name, err)
		}
		if err := e.uow.Do(t.Context(), call); !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s without its lock: %v, want ErrLockOrder", name, err)
		}
	}
	// With only the account locked, the session methods still refuse.
	for _, name := range []string{"Rotate", "Successor", "Revoke"} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, acc); err != nil {
				return err
			}
			return calls[name](ctx)
		})
		if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s with the account locked only: %v, want ErrLockOrder", name, err)
		}
	}
	// Nothing changed.
	if tok, got := e.find(t, "a"); !tok.Current() || !got.Live {
		t.Errorf("the session: live %v, token current %v", got.Live, tok.Current())
	}
	if rows := e.tokenRows(t); len(rows) != 1 {
		t.Errorf("%d tokens, want 1", len(rows))
	}
	if got, _ := e.sessions.ListLive(t.Context(), acc); len(got) != 1 {
		t.Errorf("%d live sessions, want 1", len(got))
	}
}

// TestRevokeUnknownReason checks that a revocation with a reason outside TDD-04 §2 is refused
// before querying: a revoked session always says why.
func TestRevokeUnknownReason(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	for _, reason := range []session.RevokeReason{"", "expired"} {
		calls := map[string]func(ctx context.Context) error{
			"Revoke": func(ctx context.Context) error {
				if _, err := e.sessions.LockSession(ctx, s.AccountID, s.ID); err != nil {
					return err
				}
				_, err := e.sessions.Revoke(ctx, s.ID, reason)
				return err
			},
			"RevokeAll": func(ctx context.Context) error {
				if _, err := e.repo.GetForUpdate(ctx, s.AccountID); err != nil {
					return err
				}
				_, err := e.sessions.RevokeAll(ctx, s.AccountID, reason)
				return err
			},
			"RevokeAllExcept": func(ctx context.Context) error {
				if _, err := e.repo.GetForUpdate(ctx, s.AccountID); err != nil {
					return err
				}
				_, err := e.sessions.RevokeAllExcept(ctx, s.AccountID, e.ids.New(), reason)
				return err
			},
		}
		for name, call := range calls {
			if err := e.uow.Do(t.Context(), call); !errors.Is(err, session.ErrRevokeReason) {
				t.Errorf("%s(%q): %v, want ErrRevokeReason", name, reason, err)
			}
		}
	}
	e.checkRevoked(t, "a", "")
}
