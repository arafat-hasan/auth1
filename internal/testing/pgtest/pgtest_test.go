package pgtest

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver

	deploypg "github.com/arafat-hasan/auth1/deploy/postgres"
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

func ping(dsn string, timeout time.Duration) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}

func TestDockerGate(t *testing.T) {
	t.Parallel()
	down := errors.New("no docker")
	for _, tc := range []struct {
		name       string
		health     error
		require    bool
		skip, fail bool
	}{
		{"healthy", nil, false, false, false},
		{"healthy, required", nil, true, false, false},
		{"unhealthy", down, false, true, false},
		{"unhealthy, required", down, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			skip, fail := gate(tc.health, tc.require)
			if skip != tc.skip || fail != tc.fail {
				t.Errorf("gate = %v, %v; want %v, %v", skip, fail, tc.skip, tc.fail)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	ctx := t.Context()
	var first string
	t.Run("databases are separate", func(t *testing.T) {
		a, b := Empty(t), Empty(t)
		if a == b {
			t.Fatalf("Empty returned %q twice", a)
		}
		first = a
		dbA, dbB := open(t, a), open(t, b)
		if _, err := dbA.ExecContext(ctx, "CREATE TABLE only_in_a (id int)"); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := dbB.QueryRowContext(ctx, "SELECT count(*) FROM pg_tables WHERE tablename = 'only_in_a'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Error("a table created in one database is visible in the other")
		}
	})
	if first == "" {
		return
	}
	if err := ping(first, 5*time.Second); err == nil {
		t.Error("the database still exists after its test ended")
	}
}

func TestServerStopStart(t *testing.T) {
	s := NewServer(t)
	if err := ping(s.DSN(), 5*time.Second); err != nil {
		t.Fatalf("ping before stop: %v", err)
	}
	s.Stop(t)
	start := time.Now()
	if err := ping(s.DSN(), 2*time.Second); err == nil {
		t.Fatal("ping succeeded while the server was stopped")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("ping took longer than its timeout")
	}
	s.Start(t)
	if err := ping(s.DSN(), 5*time.Second); err != nil {
		t.Fatalf("ping after start: %v", err)
	}
}

func TestDSNFromTemplate(t *testing.T) {
	a, b := DSN(t), DSN(t)
	if a == b {
		t.Fatalf("DSN returned %q twice", a)
	}
	dbA, dbB := open(t, a), open(t, b)
	var ok bool
	if err := dbA.QueryRowContext(t.Context(), "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&ok); err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("schema_migrations is missing: the template was not migrated")
	}
	var owner string
	if err := dbA.QueryRowContext(t.Context(), "SELECT relowner::regrole::text FROM pg_class WHERE oid = 'schema_migrations'::regclass").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != Migrator {
		t.Errorf("schema_migrations is owned by %s; want %s: the migrations did not run as the migrator", owner, Migrator)
	}
	if _, err := dbA.ExecContext(t.Context(), "CREATE TABLE only_in_a (id int)"); err != nil {
		t.Fatal(err)
	}
	if err := dbB.QueryRowContext(t.Context(), "SELECT to_regclass('only_in_a') IS NOT NULL").Scan(&ok); err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a table created in one database is visible in the other")
	}
}

func TestRoles(t *testing.T) {
	ctx := t.Context()
	dsn := Empty(t)
	admin := open(t, dsn)

	var owner string
	if err := admin.QueryRowContext(ctx, "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'public'").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != Migrator {
		t.Errorf("public is owned by %s; want %s", owner, Migrator)
	}

	app := open(t, As(t, dsn, App))
	_, err := app.ExecContext(ctx, "CREATE TABLE made_by_app (i int)")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%s creating a table: %v; want insufficient_privilege (42501)", App, err)
	}

	migrator := open(t, As(t, dsn, Migrator))
	if _, err := migrator.ExecContext(ctx, "CREATE TABLE made_by_migrator (i int)"); err != nil {
		t.Errorf("%s creating a table: %v", Migrator, err)
	}

	if _, err := admin.ExecContext(ctx, deploypg.RolesSQL); err != nil {
		t.Errorf("running the roles script a second time: %v", err)
	}
}
