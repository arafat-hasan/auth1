package postgres_test

import (
	"log/slog"
	"testing"

	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// leaderDB returns the superuser's pool and a function making leaders as auth1_app.
func leaderDB(t *testing.T) (*bun.DB, func() *postgres.Leader) {
	t.Helper()
	dsn := pgtest.DSN(t)
	su := openPool(t, dsn)
	appDSN := pgtest.As(t, dsn, pgtest.App)
	return su, func() *postgres.Leader {
		l, err := postgres.NewLeader(dbConfig(dsnFile(t, appDSN)), config.EnvDevelopment, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close(t.Context()) })
		return l
	}
}

// openPool opens a pool on dsn, closed when the test ends.
func openPool(t *testing.T, dsn string) *bun.DB {
	t.Helper()
	db, err := postgres.Open(dbConfig(dsnFile(t, dsn)), config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// thisDB limits a pg_locks query to the test's own database: advisory locks are per database, but
// pg_locks shows the whole server, where the package's other tests hold the same job locks.
const thisDB = "database = (SELECT oid FROM pg_database WHERE datname = current_database())"

// holders returns the backend pids holding the job lock in the test's database.
func holders(t *testing.T, su *bun.DB, lock int32) []int {
	t.Helper()
	rows, err := su.QueryContext(t.Context(), `
		SELECT pid FROM pg_locks
		WHERE `+thisDB+` AND locktype = 'advisory' AND classid = ? AND objid = ? AND objsubid = 2
		  AND granted`,
		postgres.JobLockClass, lock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var pids []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, pid)
	}
	return pids
}

// lead calls l.Lead and fails the test unless it answers want; an error is allowed with false.
func lead(t *testing.T, l *postgres.Leader, lock int32, want bool) {
	t.Helper()
	got, err := l.Lead(t.Context(), lock)
	if got != want || (want && err != nil) {
		t.Fatalf("Lead(%d) = %v, %v; want %v", lock, got, err, want)
	}
}

// TestLeaderExclusive checks TDD-08 §7: one holder per job lock, kept across calls, and locks
// independent of each other.
func TestLeaderExclusive(t *testing.T) {
	t.Parallel()
	su, newLeader := leaderDB(t)
	a, b := newLeader(), newLeader()
	lead(t, a, 1, true)
	lead(t, b, 1, false)
	lead(t, a, 1, true)
	lead(t, a, 1, true)
	if n := len(holders(t, su, 1)); n != 1 {
		t.Errorf("%d holders of lock 1, want 1", n)
	}
	lead(t, b, 2, true)
	lead(t, a, 2, false)
	var count int
	if err := su.QueryRowContext(t.Context(), `
		SELECT count(*) FROM pg_locks
		WHERE `+thisDB+` AND locktype = 'advisory' AND classid = ? AND objsubid = 2`,
		postgres.JobLockClass).Scan(&count); err != nil || count != 2 {
		t.Errorf("advisory job locks %d, %v; want 2", count, err)
	}
}

// TestLeaderHandOver checks that a leader whose connection dies loses the lock, says so, and the
// other takes it; the old one does not take it back.
func TestLeaderHandOver(t *testing.T) {
	t.Parallel()
	su, newLeader := leaderDB(t)
	a, b := newLeader(), newLeader()
	lead(t, a, 1, true)
	pids := holders(t, su, 1)
	if len(pids) != 1 {
		t.Fatalf("holders %v", pids)
	}
	if _, err := su.ExecContext(t.Context(), "SELECT pg_terminate_backend(?, 5000)", pids[0]); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.Lead(t.Context(), 1); ok || err == nil {
		t.Fatalf("A after its connection died: %v, %v; want false with an error", ok, err)
	}
	lead(t, b, 1, true)
	lead(t, a, 1, false)
	lead(t, b, 1, true)
}

// TestLeaderClose checks that closing a leader releases its locks, and that a closed leader leads
// nothing again.
func TestLeaderClose(t *testing.T) {
	t.Parallel()
	_, newLeader := leaderDB(t)
	a, b := newLeader(), newLeader()
	lead(t, a, 1, true)
	if err := a.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	lead(t, b, 1, true)
	lead(t, b, 2, true)
	if err := b.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.Lead(t.Context(), 3); ok || err == nil {
		t.Errorf("Lead after Close = %v, %v; want false with an error", ok, err)
	}
}

// TestLeaderNilLogger checks that a leader built without a logger survives losing its connection.
func TestLeaderNilLogger(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	su := openPool(t, dsn)
	l, err := postgres.NewLeader(dbConfig(dsnFile(t, pgtest.As(t, dsn, pgtest.App))), config.EnvDevelopment, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close(t.Context()) })
	lead(t, l, 1, true)
	if _, err := su.ExecContext(t.Context(), "SELECT pg_terminate_backend(?, 5000)", holders(t, su, 1)[0]); err != nil {
		t.Fatal(err)
	}
	if ok, _ := l.Lead(t.Context(), 1); ok {
		t.Error("led on a dead connection")
	}
}
