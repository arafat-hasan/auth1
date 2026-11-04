package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// idleTTL is the refresh_idle_ttl the tests rotate with.
const idleTTL = time.Hour

// rotateIn finds from's token, locking its session, and rotates it to to's, in the transaction of
// ctx. It returns what Rotate returned, or false when the token found is not current.
func (e *sessionsEnv) rotateIn(ctx context.Context, from, to string) (bool, error) {
	tok, s, err := e.sessions.FindToken(ctx, tokenHash(from), grace)
	if err != nil || !tok.Current() {
		return false, err
	}
	return e.sessions.Rotate(ctx, s.ID, tokenHash(from), tokenHash(to), rawToken(to), idleTTL)
}

// rotate rotates from's token to to's in a transaction of its own and fails the test unless it
// rotated.
func (e *sessionsEnv) rotate(t *testing.T, from, to string) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		ok, err := e.rotateIn(ctx, from, to)
		if err == nil && !ok {
			t.Errorf("rotating %s to %s did not rotate", from, to)
		}
		return err
	})
}

// tokenRow is a row of refresh_tokens as superuser reads it.
type tokenRow struct {
	hash, successorHash, successorEnc []byte
	session                           uuid.UUID
	rotated                           bool
}

// tokenRows reads every row of refresh_tokens as superuser, keyed by hash.
func (e *sessionsEnv) tokenRows(t *testing.T) map[string]tokenRow {
	t.Helper()
	rows, err := e.su.QueryContext(t.Context(),
		"SELECT token_hash, session_id, rotated_at IS NOT NULL, successor_hash, successor_enc FROM refresh_tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]tokenRow{}
	for rows.Next() {
		var r tokenRow
		if err := rows.Scan(&r.hash, &r.session, &r.rotated, &r.successorHash, &r.successorEnc); err != nil {
			t.Fatal(err)
		}
		got[string(r.hash)] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRotate(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.start(t, "a")
	e.exec(t, `UPDATE sessions SET created_at = created_at - interval '1 minute',
		last_used_at = last_used_at - interval '1 minute' WHERE id = ?`, ns.ID)
	_, before := e.find(t, "a")

	e.rotate(t, "a", "b")

	rows := e.tokenRows(t)
	if a := rows[string(tokenHash("a"))]; !a.rotated || !cmp.Equal(a.successorHash, tokenHash("b")) || a.successorEnc == nil {
		t.Errorf("rotated token: rotated %v, successor hash %x, successor held %v", a.rotated, a.successorHash, a.successorEnc != nil)
	}
	tok, after := e.find(t, "b")
	if !tok.Current() || tok.SessionID != ns.ID {
		t.Errorf("successor %+v, want current of session %s", tok, ns.ID)
	}
	if !after.LastUsedAt.After(before.LastUsedAt) {
		t.Errorf("last used %v, was %v: want later", after.LastUsedAt, before.LastUsedAt)
	}
	if d := after.IdleExpiresAt.Sub(after.LastUsedAt); d != idleTTL {
		t.Errorf("idle expiry %v after use, want %v", d, idleTTL)
	}
	if tok, _ := e.find(t, "a"); tok.Current() || !tok.InGrace {
		t.Errorf("presented token: current %v, in grace %v; want rotated, in grace", tok.Current(), tok.InGrace)
	}
}

// TestRotateIdleCapped checks that rotation never moves the idle expiry past the absolute one.
func TestRotateIdleCapped(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.start(t, "a")
	e.exec(t, "UPDATE sessions SET absolute_expires_at = now() + interval '30 minutes' WHERE id = ?", ns.ID)
	e.rotate(t, "a", "b")
	if _, s := e.find(t, "b"); !s.IdleExpiresAt.Equal(s.AbsoluteExpiresAt) {
		t.Errorf("idle expiry %v, want the absolute one %v", s.IdleExpiresAt, s.AbsoluteExpiresAt)
	}
}

// TestI3RotateOnce checks I-3 in Rotate itself: a token already rotated does not rotate again,
// even under the session lock, and the second call writes nothing.
func TestI3RotateOnce(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.start(t, "a")
	e.do(t, func(ctx context.Context) error {
		if ok, err := e.rotateIn(ctx, "a", "b"); err != nil || !ok {
			t.Fatalf("first rotation: %v, %v", ok, err)
		}
		ok, err := e.sessions.Rotate(ctx, ns.ID, tokenHash("a"), tokenHash("c"), rawToken("c"), idleTTL)
		if ok {
			t.Error("I-3: a rotated token rotated again")
		}
		return err
	})
	rows := e.tokenRows(t)
	if len(rows) != 2 {
		t.Errorf("%d tokens, want 2", len(rows))
	}
	if a := rows[string(tokenHash("a"))]; !cmp.Equal(a.successorHash, tokenHash("b")) {
		t.Errorf("successor hash %x, want b's", a.successorHash)
	}
}

// TestRotateOtherSession checks that Rotate finds the token only in its own session.
func TestRotateOtherSession(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	other := e.start(t, "x")
	e.do(t, func(ctx context.Context) error {
		if _, err := e.sessions.LockSession(ctx, other.AccountID, other.ID); err != nil {
			return err
		}
		ok, err := e.sessions.Rotate(ctx, other.ID, tokenHash("a"), tokenHash("b"), rawToken("b"), idleTTL)
		if ok {
			t.Error("rotated a token of another session")
		}
		return err
	})
	if len(e.tokenRows(t)) != 2 {
		t.Error("a successor was stored")
	}
}

// TestI3ConcurrentRotation checks I-3 under concurrency, and what the loser sees: two transactions
// present one token; the second waits for the session lock while the first rotates it, then finds
// the token rotated and within the grace window, follows it to the first's successor, and cannot
// rotate it again (TDD-04 §3 steps 1, 4).
func TestI3ConcurrentRotation(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	ns := e.start(t, "a")

	var first bool
	h := e.holdSession(t, "a", func(ctx context.Context) error {
		var err error
		first, err = e.sessions.Rotate(ctx, ns.ID, tokenHash("a"), tokenHash("b"), rawToken("b"), idleTTL)
		return err
	})
	var (
		seen      session.Token
		followed  []byte
		second    bool
		secondErr = make(chan error, 1)
	)
	go func() {
		secondErr <- e.uow.Do(t.Context(), func(ctx context.Context) error {
			var err error
			if seen, _, err = e.sessions.FindToken(ctx, tokenHash("a"), grace); err != nil {
				return err
			}
			if followed, _, err = e.sessions.Successor(ctx, ns.ID, tokenHash("a"), grace); err != nil {
				return err
			}
			second, err = e.sessions.Rotate(ctx, ns.ID, tokenHash("a"), tokenHash("c"), rawToken("c"), idleTTL)
			return err
		})
	}()
	e.waitForLockWaiter(t, h)
	h.release()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Errorf("I-3: first rotated %v, second rotated %v; want exactly the first", first, second)
	}
	if seen.Current() || !seen.InGrace {
		t.Errorf("the waiting FindToken saw current %v, in grace %v; want rotated, in grace", seen.Current(), seen.InGrace)
	}
	if !bytes.Equal(followed, rawToken("b")) {
		t.Error("the waiting transaction did not follow the token to the first's successor")
	}
	if rows := e.tokenRows(t); len(rows) != 2 {
		t.Errorf("%d tokens, want 2", len(rows))
	}
}

// waitForLockWaiter waits until a backend on the test's database is waiting for a row lock. It
// fails at once when h, the transaction holding the lock, ends first.
func (e *sessionsEnv) waitForLockWaiter(t *testing.T, h *held) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-h.finished:
			t.Fatalf("the transaction holding the lock ended: %v", h.err)
		default:
		}
		var n int
		if err := e.su.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no transaction waited for the session lock")
}

// TestSessionsStoreNoPlaintext checks that refresh_tokens holds token hashes and the sealed
// successor only, sealed at the presented token's row.
func TestSessionsStoreNoPlaintext(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	e.rotate(t, "a", "b")

	rows := e.tokenRows(t)
	if len(rows) != 2 {
		t.Fatalf("%d tokens, want 2", len(rows))
	}
	for _, r := range rows {
		for _, col := range [][]byte{r.hash, r.successorHash, r.successorEnc} {
			for _, raw := range [][]byte{rawToken("a"), rawToken("b")} {
				if bytes.Contains(col, raw) {
					t.Errorf("token %x stores a raw token", r.hash)
				}
			}
		}
	}
	if _, ok := rows[string(tokenHash("b"))]; !ok {
		t.Error("the successor is not stored by its hash")
	}
	enc := rows[string(tokenHash("a"))].successorEnc
	got, err := e.fc.Open(app.NewKeyPlace("refresh_tokens", "successor_enc", tokenHash("a")), enc)
	if err != nil || !bytes.Equal(got, rawToken("b")) {
		t.Errorf("successor at its place: %v, equal %v", err, bytes.Equal(got, rawToken("b")))
	}
	if _, err := e.fc.Open(app.NewKeyPlace("refresh_tokens", "successor_enc", tokenHash("b")), enc); !errors.Is(err, app.ErrCiphertextInvalid) {
		t.Errorf("successor at another row: %v, want ErrCiphertextInvalid", err)
	}
}
