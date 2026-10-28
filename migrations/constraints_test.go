package migrations_test

import (
	"testing"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// TestVerifiedIdentifierUnique checks I-1: a verified, current value belongs to one account.
func TestVerifiedIdentifierUnique(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	a, b := newAccount(t, db), newAccount(t, db)
	bidx := []byte("bidx-1")

	first, err := insertIdentifier(t, db, a, "email", bidx, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = insertIdentifier(t, db, b, "email", bidx, true)
	wantCode(t, err, uniqueViolation, "identifiers_verified_unique")

	pending, err := insertIdentifier(t, db, b, "email", bidx, false)
	if err != nil {
		t.Fatalf("an unverified identifier with a taken value: %v", err)
	}
	_, err = db.ExecContext(t.Context(), `UPDATE identifiers SET verified_at = now() WHERE id = $1`, pending)
	wantCode(t, err, uniqueViolation, "identifiers_verified_unique")

	mustExec(t, db, `UPDATE identifiers SET retired_at = now() WHERE id = $1`, first)
	if _, err := db.ExecContext(t.Context(), `UPDATE identifiers SET verified_at = now() WHERE id = $1`, pending); err != nil {
		t.Errorf("verifying a value its first owner retired: %v", err)
	}
	if _, err := insertIdentifier(t, db, a, "phone", bidx, true); err != nil {
		t.Errorf("the same blind index under another type: %v", err)
	}
}

// TestOneCurrentIdentifierPerType checks I-2: an account has at most one current identifier per
// type.
func TestOneCurrentIdentifierPerType(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	a := newAccount(t, db)

	first, err := insertIdentifier(t, db, a, "email", []byte("bidx-1"), true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = insertIdentifier(t, db, a, "email", []byte("bidx-2"), false)
	wantCode(t, err, uniqueViolation, "identifiers_current_per_type")

	if _, err := insertIdentifier(t, db, a, "phone", []byte("bidx-3"), false); err != nil {
		t.Errorf("a current identifier of another type: %v", err)
	}
	mustExec(t, db, `UPDATE identifiers SET retired_at = now() WHERE id = $1`, first)
	if _, err := insertIdentifier(t, db, a, "email", []byte("bidx-2"), false); err != nil {
		t.Errorf("a new email once the first is retired: %v", err)
	}
}

// TestClosedChallengeHoldsNoSecret checks I-5, and the same rule for a flow's pending secret.
func TestClosedChallengeHoldsNoSecret(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	ctx := t.Context()
	flow := newFlow(t, db, newAccount(t, db))
	insert := `
		INSERT INTO challenges (id, flow_id, purpose, method, target_value, target_bidx, secret_mac,
		                        secret, max_attempts, expires_at, closed_at, created_at)
		VALUES ($1, $2, 'verify', 'email_code', '\x00', '\x01', $3, $4, 5,
		        now() + interval '10 minutes', $5, now())`

	_, err := db.ExecContext(ctx, insert, newID(t), flow, []byte("mac-1"), []byte("secret"), "now")
	wantCode(t, err, checkViolation, "")

	ch := newID(t)
	mustExec(t, db, insert, ch, flow, []byte("mac-2"), []byte("secret"), nil)
	_, err = db.ExecContext(ctx, `UPDATE challenges SET closed_at = now() WHERE id = $1`, ch)
	wantCode(t, err, checkViolation, "")
	if _, err := db.ExecContext(ctx, `UPDATE challenges SET closed_at = now(), secret = NULL WHERE id = $1`, ch); err != nil {
		t.Errorf("closing a challenge and erasing its secret: %v", err)
	}

	for _, tc := range []struct{ name, close, closeErasing string }{
		{"completed",
			`UPDATE flows SET completed_at = now() WHERE id = $1`,
			`UPDATE flows SET completed_at = now(), pending_secret = NULL WHERE id = $1`},
		{"cancelled",
			`UPDATE flows SET cancelled_at = now() WHERE id = $1`,
			`UPDATE flows SET cancelled_at = now(), pending_secret = NULL WHERE id = $1`},
	} {
		f := newFlow(t, db, newAccount(t, db))
		mustExec(t, db, `UPDATE flows SET pending_secret = '\x01' WHERE id = $1`, f)
		_, err := db.ExecContext(ctx, tc.close, f)
		wantCode(t, err, checkViolation, "")
		if _, err := db.ExecContext(ctx, tc.closeErasing, f); err != nil {
			t.Errorf("a flow %s with its pending secret erased: %v", tc.name, err)
		}
	}
}

// TestAccountChecks checks the status CHECKs of accounts.
func TestAccountChecks(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	for _, tc := range []struct {
		name   string
		status string
		reason any
		until  bool
		ok     bool
	}{
		{"unknown status", "frozen", nil, false, false},
		{"pending", "pending", nil, false, true},
		{"active", "active", nil, false, true},
		{"deleted", "deleted", nil, false, true},
		{"active with a reason", "active", "abuse", false, false},
		{"deleted with a reason", "deleted", "abuse", false, false},
		{"suspended without a reason", "suspended", nil, false, false},
		{"banned without a reason", "banned", nil, false, false},
		{"suspended with a reason", "suspended", "abuse", false, true},
		{"banned with a reason", "banned", "abuse", false, true},
		{"suspended until a date", "suspended", "abuse", true, true},
		{"banned until a date", "banned", "abuse", true, false},
		{"active until a date", "active", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := insertAccount(t, db, tc.status, tc.reason)
			if err == nil && tc.until {
				_, err = db.ExecContext(t.Context(), `UPDATE accounts SET status_until = now() + interval '1 day' WHERE id = $1`, id)
			}
			if tc.ok {
				if err != nil {
					t.Errorf("refused: %v", err)
				}
				return
			}
			wantCode(t, err, checkViolation, "")
		})
	}
}

// TestOutbox checks the outbox CHECK and the order of one account's events (I-8).
func TestOutbox(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	insert := func(destination string, subject, version any) error {
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO outbox (id, destination, subject, account_version, type, body, created_at, next_attempt_at)
			VALUES ($1, $2, $3, $4, 'test.type', '{}', now(), now())`, newID(t), destination, subject, version)
		return err
	}
	subject := newID(t)

	wantCode(t, insert("event", subject, nil), checkViolation, "")
	wantCode(t, insert("event", nil, 1), checkViolation, "")
	wantCode(t, insert("delivery", subject, 1), checkViolation, "")
	wantCode(t, insert("other", nil, nil), checkViolation, "")
	for _, d := range []struct {
		what    string
		subject any
	}{{"a delivery", nil}, {"a delivery with a subject", subject}, {"a second delivery with that subject", subject}} {
		if err := insert("delivery", d.subject, nil); err != nil {
			t.Errorf("%s: %v", d.what, err)
		}
	}
	if err := insert("event", subject, 1); err != nil {
		t.Fatalf("an event: %v", err)
	}
	wantCode(t, insert("event", subject, 1), uniqueViolation, "outbox_event_order")
	if err := insert("event", subject, 2); err != nil {
		t.Errorf("the account's next event: %v", err)
	}
	if err := insert("event", newID(t), 1); err != nil {
		t.Errorf("another account's event with the same version: %v", err)
	}
}
