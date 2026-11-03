package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// successor follows name's token in the session s, under its lock, in a transaction of its own.
func (e *sessionsEnv) successor(t *testing.T, s session.NewSession, name string) ([]byte, bool) {
	t.Helper()
	var (
		got []byte
		ok  bool
	)
	e.do(t, func(ctx context.Context) error {
		if _, err := e.sessions.LockSession(ctx, s.AccountID, s.ID); err != nil {
			return err
		}
		var err error
		got, ok, err = e.sessions.Successor(ctx, s.ID, tokenHash(name), grace)
		return err
	})
	return got, ok
}

// checkSuccessor fails the test unless following from leads to want's token.
func (e *sessionsEnv) checkSuccessor(t *testing.T, s session.NewSession, from, want string) {
	t.Helper()
	got, ok := e.successor(t, s, from)
	if !ok || !cmp.Equal(got, rawToken(want)) {
		t.Errorf("following %s: %v, value is %s's %v; want %s's", from, ok, want, cmp.Equal(got, rawToken(want)), want)
	}
}

// checkReuse fails the test unless following from finds nothing: the presentation is reuse.
func (e *sessionsEnv) checkReuse(t *testing.T, s session.NewSession, from string) {
	t.Helper()
	if got, ok := e.successor(t, s, from); ok || got != nil {
		t.Errorf("following %s: %v, %d bytes; want reuse", from, ok, len(got))
	}
}

// TestSuccessorChain checks that a chain of up to 3 steps, each within the grace window, leads to
// the newest token's value, and that a longer one is reuse (TDD-04 §3 step 4).
func TestSuccessorChain(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")

	e.checkReuse(t, s, "a") // current: there is nothing to follow
	e.rotate(t, "a", "b")
	e.checkSuccessor(t, s, "a", "b")
	e.rotate(t, "b", "c")
	e.checkSuccessor(t, s, "a", "c")
	e.checkSuccessor(t, s, "b", "c")
	e.rotate(t, "c", "d")
	e.checkSuccessor(t, s, "a", "d")
	e.rotate(t, "d", "e")
	e.checkReuse(t, s, "a")
	e.checkSuccessor(t, s, "b", "e")
}

// TestSuccessorOtherSession checks that a token is followed only in its own session.
func TestSuccessorOtherSession(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	e.start(t, "a")
	other := e.start(t, "x")
	e.rotate(t, "a", "b")
	e.checkReuse(t, other, "a")
}

// TestSuccessorOutsideGrace checks that the refresh path ignores a successor's value once the
// grace window has passed, whether or not the erase has removed it, at the first step or later
// (TDD-04 §3, I-13, R-3).
func TestSuccessorOutsideGrace(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	past := "UPDATE refresh_tokens SET rotated_at = now() - ? * interval '1 microsecond' WHERE token_hash = ?"

	s := e.start(t, "a")
	e.rotate(t, "a", "b")
	e.exec(t, past, (grace + time.Second).Microseconds(), tokenHash("a"))
	if tok, _ := e.find(t, "a"); tok.InGrace {
		t.Error("a token rotated past the window is in grace")
	}
	e.checkReuse(t, s, "a")

	s = e.start(t, "p")
	e.rotate(t, "p", "q")
	e.rotate(t, "q", "r")
	e.exec(t, past, (grace + time.Second).Microseconds(), tokenHash("q"))
	e.checkReuse(t, s, "p")

	// A second inside the window, the token is still in grace.
	s = e.start(t, "m")
	e.rotate(t, "m", "n")
	e.exec(t, past, (grace - time.Second).Microseconds(), tokenHash("m"))
	if tok, _ := e.find(t, "m"); !tok.InGrace {
		t.Error("a token rotated inside the window is not in grace")
	}
	e.checkSuccessor(t, s, "m", "n")
}

// TestSuccessorErased checks that a token whose successor's value is gone is reuse.
func TestSuccessorErased(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	s := e.start(t, "a")
	e.rotate(t, "a", "b")
	e.exec(t, "UPDATE refresh_tokens SET successor_enc = NULL WHERE token_hash = ?", tokenHash("a"))
	if tok, _ := e.find(t, "a"); tok.InGrace {
		t.Error("a token without its successor's value is in grace")
	}
	e.checkReuse(t, s, "a")
}
