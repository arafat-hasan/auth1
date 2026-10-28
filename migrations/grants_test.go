package migrations_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/migrations"
)

// TestMissingRole runs the migration on a cluster where roles.sql has not run: it fails naming
// the role, and applies nothing.
func TestMissingRole(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.NewServer(t).DSN())

	_, err := migrate.New(db, migrations.FS).Up(t.Context())
	if err == nil || !strings.Contains(err.Error(), `role "auth1_migrator" does not exist`) || !strings.Contains(err.Error(), "deploy/postgres/roles.sql") {
		t.Fatalf("up without the roles: %v; want an error naming auth1_migrator and roles.sql", err)
	}
	if left := queryStrings(t, db, `
		SELECT 'applied ' || version FROM schema_migrations
		UNION ALL
		SELECT 'table ' || relname FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relname NOT LIKE 'schema_migrations%'`); len(left) > 0 {
		t.Errorf("the failed migration left %q", left)
	}
}

// TestAppGrants checks the grants of TDD-01 §4.1 on every table: a table added later without its
// grants fails here.
func TestAppGrants(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	all := queryStrings(t, db, `
		SELECT relname FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p') AND NOT relispartition
		  AND relname <> 'schema_migrations'
		ORDER BY relname`)
	if len(all) < len(tables) {
		t.Fatalf("found %d tables; is the schema migrated?", len(all))
	}
	dml := []string{"auth1_app DELETE", "auth1_app INSERT", "auth1_app SELECT", "auth1_app UPDATE"}
	for _, table := range all {
		want := dml
		if table == "auth_audit" {
			want = partitionGrants // I-11
		}
		if got := auditGrants(t, db, table); !slices.Equal(got, want) {
			t.Errorf("grants on %s:\n got %q\nwant %q", table, got, want)
		}
	}
	if got := auditGrants(t, db, "schema_migrations"); len(got) > 0 {
		t.Errorf("grants on schema_migrations: %q; want none", got)
	}
}

// TestAuditImmutable checks I-11 as the service: audit rows are never deleted, and only their IP
// and user agent change.
func TestAuditImmutable(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	app := open(t, pgtest.As(t, dsn, pgtest.App))
	ctx := t.Context()

	var partition string
	if err := app.QueryRowContext(ctx, `
		INSERT INTO auth_audit (actor_kind, action, outcome, ip, user_agent)
		VALUES ('anonymous', 'test.action', 'ok', '192.0.2.1', 'test-agent')
		RETURNING tableoid::regclass::text`).Scan(&partition); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := app.ExecContext(ctx, `UPDATE auth_audit SET ip = NULL, user_agent = NULL`); err != nil {
		t.Errorf("clearing ip and user_agent: %v", err)
	}
	for _, refused := range []string{
		`DELETE FROM auth_audit`,
		`UPDATE auth_audit SET action = 'other.action'`,
		`UPDATE auth_audit SET details = '{"x": 1}'`,
		`TRUNCATE auth_audit`,
		`DELETE FROM ` + partition,
		`UPDATE ` + partition + ` SET action = 'other.action'`,
		`TRUNCATE ` + partition,
	} {
		_, err := app.ExecContext(ctx, refused)
		t.Run(refused, func(t *testing.T) { wantCode(t, err, insufficientPrivilege, "") })
	}
	var n int
	if err := app.QueryRowContext(ctx, `SELECT count(*) FROM auth_audit WHERE action = 'test.action'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit rows after the refused statements: %d, %v; want 1", n, err)
	}
}

// TestAppCannotChangeSchema checks that the service can neither create nor change nor drop
// anything.
func TestAppCannotChangeSchema(t *testing.T) {
	t.Parallel()
	app := open(t, pgtest.As(t, pgtest.DSN(t), pgtest.App))
	for _, refused := range []string{
		`CREATE TABLE made_by_app (i int)`,
		`CREATE FUNCTION made_by_app() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`ALTER TABLE accounts ADD COLUMN x int`,
		`CREATE INDEX made_by_app ON accounts (locale)`,
		`DROP TABLE accounts`,
		`DROP TABLE schema_migrations`,
		`DROP FUNCTION auth_audit_create_partitions(integer)`,
	} {
		_, err := app.ExecContext(t.Context(), refused)
		t.Run(refused, func(t *testing.T) { wantCode(t, err, insufficientPrivilege, "") })
	}
}

// TestAppCanWrite checks that the service can insert, update and delete through the grants, with
// no sequence grant needed.
func TestAppCanWrite(t *testing.T) {
	t.Parallel()
	app := open(t, pgtest.As(t, pgtest.DSN(t), pgtest.App))
	account := newAccount(t, app)
	identifier, err := insertIdentifier(t, app, account, "email", []byte("bidx-1"), true)
	if err != nil {
		t.Fatalf("insert identifier: %v", err)
	}
	mustExec(t, app, `
		INSERT INTO outbox (id, destination, subject, account_version, type, body, created_at, next_attempt_at)
		VALUES ($1, 'event', $2, 1, 'test.type', '{}', now(), now())`, newID(t), account)
	mustExec(t, app, `UPDATE accounts SET version = version + 1, updated_at = now() WHERE id = $1`, account)
	mustExec(t, app, `UPDATE outbox SET published_at = now() WHERE subject = $1`, account)
	mustExec(t, app, `DELETE FROM outbox WHERE subject = $1`, account)
	mustExec(t, app, `DELETE FROM identifiers WHERE id = $1`, identifier)
	mustExec(t, app, `DELETE FROM accounts WHERE id = $1`, account)
}
