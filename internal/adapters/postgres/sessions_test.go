package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

var _ app.Sessions = (*postgres.Sessions)(nil)

// grace is the refresh_reuse_grace the tests use.
const grace = 10 * time.Second

// sessionsEnv is the sessions repository beside the accounts one, on one database.
type sessionsEnv struct {
	*accountsEnv
	sessions *postgres.Sessions
	n        int // the last account number sessionAccount used
}

// sessionsDB returns a fresh environment.
func sessionsDB(t *testing.T) *sessionsEnv {
	t.Helper()
	e := accountsDB(t)
	return &sessionsEnv{accountsEnv: e, sessions: postgres.NewSessions(e.app, e.fc)}
}

// sessionAccount creates a pending account of its own and returns its id.
func (e *sessionsEnv) sessionAccount(t *testing.T) uuid.UUID {
	t.Helper()
	e.n++
	a := e.newAccount("", fmt.Sprintf("holder%d@example.org", e.n))
	e.create(t, a)
	return a.ID
}

// rawToken is a distinct 32-byte refresh token for name, and tokenHash its stored hash.
func rawToken(name string) session.Secret { return crypto.SHA256([]byte("token:" + name)) }
func tokenHash(name string) []byte        { return crypto.SHA256(rawToken(name)) }

// newSession is a session of the account with an hour of idle time and a day in all.
func (e *sessionsEnv) newSession(accountID uuid.UUID) session.NewSession {
	device := e.ids.New()
	return session.NewSession{
		ID: e.ids.New(), AccountID: accountID, ClientID: "web", AMR: []string{"pwd", "otp"},
		AuthTime: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond), DeviceID: &device,
		UserAgent: "Mozilla/5.0", IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
	}
}

// start creates a session of a new account whose first token is name's, and returns it.
func (e *sessionsEnv) start(t *testing.T, name string) session.NewSession {
	t.Helper()
	s := e.newSession(e.sessionAccount(t))
	e.createSession(t, s, name)
	return s
}

// createSession stores s with name's token, in its own transaction, under the account lock.
func (e *sessionsEnv) createSession(t *testing.T, s session.NewSession, name string) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, s.AccountID); err != nil {
			return err
		}
		return e.sessions.Create(ctx, s, tokenHash(name))
	})
}

// find reads name's token and its session in a transaction of its own.
func (e *sessionsEnv) find(t *testing.T, name string) (session.Token, session.Session) {
	t.Helper()
	var (
		tok session.Token
		s   session.Session
	)
	e.do(t, func(ctx context.Context) error {
		var err error
		tok, s, err = e.sessions.FindToken(ctx, tokenHash(name), grace)
		return err
	})
	return tok, s
}

func TestCreateAndFindToken(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.start(t, "a")

	tok, got := e.find(t, "a")
	if !cmp.Equal(tok.Hash, tokenHash("a")) || tok.SessionID != ns.ID || tok.RotatedAt != nil || tok.InGrace {
		t.Errorf("token = %+v, want current, out of grace, of session %s", tok, ns.ID)
	}
	if !tok.Current() || tok.IssuedAt.IsZero() {
		t.Errorf("token issued at %v, current %v", tok.IssuedAt, tok.Current())
	}
	want := session.Session{
		ID: ns.ID, AccountID: ns.AccountID, ClientID: ns.ClientID, AMR: ns.AMR, AuthTime: ns.AuthTime,
		DeviceID: ns.DeviceID, UserAgent: ns.UserAgent, Live: true,
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(session.Session{},
		"CreatedAt", "LastUsedAt", "IdleExpiresAt", "AbsoluteExpiresAt")); diff != "" {
		t.Errorf("session (-want +got):\n%s", diff)
	}
	if !got.LastUsedAt.Equal(got.CreatedAt) || !tok.IssuedAt.Equal(got.CreatedAt) {
		t.Errorf("created %v, last used %v, token issued %v: want one time", got.CreatedAt, got.LastUsedAt, tok.IssuedAt)
	}
	if d := got.IdleExpiresAt.Sub(got.CreatedAt); d != ns.IdleTTL {
		t.Errorf("idle expiry after %v, want %v", d, ns.IdleTTL)
	}
	if d := got.AbsoluteExpiresAt.Sub(got.CreatedAt); d != ns.AbsoluteTTL {
		t.Errorf("absolute expiry after %v, want %v", d, ns.AbsoluteTTL)
	}
}

// TestCreateIdleCapped checks that a session whose idle time is longer than its life expires idle
// at its absolute expiry.
func TestCreateIdleCapped(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.newSession(e.sessionAccount(t))
	ns.IdleTTL, ns.AbsoluteTTL = 2*time.Hour, time.Hour
	e.createSession(t, ns, "a")
	if _, got := e.find(t, "a"); !got.IdleExpiresAt.Equal(got.AbsoluteExpiresAt) {
		t.Errorf("idle expiry %v, want the absolute one %v", got.IdleExpiresAt, got.AbsoluteExpiresAt)
	}
}

func TestFindTokenUnknown(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, _, err := e.sessions.FindToken(ctx, tokenHash("b"), grace)
		return err
	})
	checkCode(t, err, domain.CodeSessionInvalid)
}

// TestFindTokenLive checks that the database judges a session live: a revoked session, and one
// past either expiry, are not.
func TestFindTokenLive(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	sets := map[string]string{
		"revoked":  "revoked_at = now(), revoke_reason = 'operator'",
		"idle":     "idle_expires_at = now() - interval '1 second'",
		"absolute": "absolute_expires_at = now() - interval '1 second'",
	}
	for name, set := range sets {
		s := e.start(t, name)
		e.exec(t, "UPDATE sessions SET "+set+" WHERE id = ?", s.ID)
		if _, got := e.find(t, name); got.Live {
			t.Errorf("%s session is live", name)
		}
	}
	e.start(t, "live")
	if _, got := e.find(t, "live"); !got.Live {
		t.Error("live session is not live")
	}
	if _, got := e.find(t, "revoked"); got.RevokedAt == nil || got.RevokeReason != session.RevokeOperator {
		t.Errorf("revoked session: at %v, reason %q", got.RevokedAt, got.RevokeReason)
	}
}

// TestFindTokenLocksSession checks that FindToken locks the session row (TDD-04 §3 step 1): while
// one transaction holds it, another cannot find the token.
func TestFindTokenLocksSession(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	h := e.holdSession(t, "a", nil)

	second := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if _, err := postgres.Conn(ctx, e.app).ExecContext(ctx, "SET LOCAL lock_timeout = '100ms'"); err != nil {
			return err
		}
		_, _, err := e.sessions.FindToken(ctx, tokenHash("a"), grace)
		return err
	})
	h.release()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(second, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("second FindToken = %v, want lock_not_available (55P03)", second)
	}
}

// held is a transaction holding a session's lock on another goroutine, from holdSession.
type held struct {
	release  func()        // lets the transaction go on; safe to call more than once
	finished chan struct{} // closed when the transaction has ended
	err      error         // the transaction's error, once finished is closed
}

// wait waits for the transaction to end and returns its error.
func (h *held) wait() error {
	<-h.finished
	return h.err
}

// holdSession finds name's token, current, in a transaction on another goroutine, locking its
// session, and returns once it holds the lock. The transaction then waits for release, runs then
// (when not nil) and commits. The test's cleanup releases it, so a test that fails early leaks
// neither the lock nor the connection.
func (e *sessionsEnv) holdSession(t *testing.T, name string, then func(ctx context.Context) error) *held {
	t.Helper()
	var (
		once    sync.Once
		release = make(chan struct{})
		locked  = make(chan struct{})
	)
	h := &held{release: func() { once.Do(func() { close(release) }) }, finished: make(chan struct{})}
	t.Cleanup(func() { h.release(); <-h.finished })
	go func() {
		defer close(h.finished)
		h.err = e.uow.Do(t.Context(), func(ctx context.Context) error {
			tok, _, err := e.sessions.FindToken(ctx, tokenHash(name), grace)
			if err != nil {
				return err
			}
			if !tok.Current() {
				return fmt.Errorf("token %s is not current", name)
			}
			close(locked)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if then == nil {
				return nil
			}
			return then(ctx)
		})
	}()
	select {
	case <-locked:
	case <-h.finished:
		t.Fatalf("holding %s's session: %v", name, h.err)
	}
	return h
}

func TestLockSession(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	other := e.sessionAccount(t)
	e.do(t, func(ctx context.Context) error {
		got, err := e.sessions.LockSession(ctx, s.AccountID, s.ID)
		if err == nil && (got.ID != s.ID || !got.Live) {
			t.Errorf("locked %+v", got)
		}
		return err
	})
	for name, ids := range map[string][2]uuid.UUID{
		"other account": {other, s.ID},
		"unknown":       {s.AccountID, e.ids.New()},
	} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			_, err := e.sessions.LockSession(ctx, ids[0], ids[1])
			return err
		})
		if de := (*domain.Error)(nil); !errors.As(err, &de) || de.Code != domain.CodeNotFound {
			t.Errorf("%s: %v, want NOT_FOUND", name, err)
		}
	}
}

// TestGetForUpdateAfterSessionLock checks the reverse of G-5: once a session is locked, the
// transaction may not lock an account.
func TestGetForUpdateAfterSessionLock(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if _, _, err := e.sessions.FindToken(ctx, tokenHash("a"), grace); err != nil {
			return err
		}
		_, err := e.repo.GetForUpdate(ctx, s.AccountID)
		return err
	})
	if !errors.Is(err, postgres.ErrLockOrder) {
		t.Errorf("GetForUpdate after a session lock: %v, want ErrLockOrder", err)
	}
}
