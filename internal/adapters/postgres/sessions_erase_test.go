package postgres_test

import (
	"testing"
	"time"
)

// TestI13EraseSuccessors checks I-13: after the erase, no successor's value older than the grace
// window survives, and one inside the window is kept and still followed.
func TestI13EraseSuccessors(t *testing.T) {
	t.Parallel()
	e := sessionsDB(t)
	past := "UPDATE refresh_tokens SET rotated_at = now() - ? * interval '1 microsecond' WHERE token_hash = ?"

	inside := e.start(t, "a")
	e.rotate(t, "a", "b")
	e.start(t, "p")
	e.rotate(t, "p", "q")
	e.exec(t, past, (grace + time.Second).Microseconds(), tokenHash("p"))
	e.start(t, "x")
	e.rotate(t, "x", "y")
	e.exec(t, past, time.Hour.Microseconds(), tokenHash("x"))

	n, err := e.sessions.EraseSuccessors(t.Context(), grace)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("erased %d, want 2", n)
	}
	var left int
	if err := e.su.QueryRowContext(t.Context(), `SELECT count(*) FROM refresh_tokens
		WHERE successor_enc IS NOT NULL AND rotated_at < now() - ? * interval '1 microsecond'`,
		grace.Microseconds()).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("I-13: %d successors older than the grace window survive the erase", left)
	}
	if rows := e.tokenRows(t); rows[string(tokenHash("a"))].successorEnc == nil {
		t.Error("the erase removed a successor inside the window")
	}
	e.checkSuccessor(t, inside, "a", "b")

	if n, err := e.sessions.EraseSuccessors(t.Context(), grace); err != nil || n != 0 {
		t.Errorf("a second erase: %d, %v; want 0", n, err)
	}
}
