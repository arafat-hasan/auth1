package migrations_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver
)

// SQLSTATEs the tests expect.
const (
	uniqueViolation       = "23505"
	checkViolation        = "23514"
	insufficientPrivilege = "42501"
)

func open(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// mustExec runs a statement that the test needs to succeed.
func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// wantCode fails t unless err is a PostgreSQL error with the SQLSTATE code and, when constraint is
// not empty, raised by that constraint or index.
func wantCode(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Errorf("err = %v; want SQLSTATE %s", err, code)
		return
	}
	if pgErr.Code != code || (constraint != "" && pgErr.ConstraintName != constraint) {
		t.Errorf("err = %s on %q (%s); want %s on %q", pgErr.Code, pgErr.ConstraintName, pgErr.Message, code, constraint)
	}
}

func newID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// insertAccount inserts an account with status and reason (nil for none).
func insertAccount(t *testing.T, db *sql.DB, status string, reason any) (uuid.UUID, error) {
	t.Helper()
	id := newID(t)
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO accounts (id, status, status_reason, status_changed_at, display_name, locale,
		                      registered_via, created_at, updated_at)
		VALUES ($1, $2, $3, now(), '\x00', 'en', 'test-client', now(), now())`, id, status, reason)
	return id, err
}

// newAccount inserts an active account.
func newAccount(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id, err := insertAccount(t, db, "active", nil)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	return id
}

// insertIdentifier inserts a current identifier, verified or not.
func insertIdentifier(t *testing.T, db *sql.DB, account uuid.UUID, typ string, bidx []byte, verified bool) (uuid.UUID, error) {
	t.Helper()
	id := newID(t)
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO identifiers (id, account_id, type, value, value_bidx, verified_at, created_at)
		VALUES ($1, $2, $3, '\x00', $4, CASE WHEN $5 THEN now() END, now())`, id, account, typ, bidx, verified)
	return id, err
}

// newFlow inserts an open sign-in flow for account.
func newFlow(t *testing.T, db *sql.DB, account uuid.UUID) uuid.UUID {
	t.Helper()
	id := newID(t)
	mustExec(t, db, `
		INSERT INTO flows (id, kind, account_id, client_id, expires_at, created_at)
		VALUES ($1, 'sign_in', $2, 'test-client', now() + interval '10 minutes', now())`, id, account)
	return id
}
