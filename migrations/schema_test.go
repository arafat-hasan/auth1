package migrations_test

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/migrations"
)

// tables are the tables of TDD-01 §4, sorted.
var tables = []string{
	"account_roles", "accounts", "auth_audit", "challenges", "client_assertions", "flows",
	"idempotency_keys", "identifiers", "outbox", "password_credentials", "recovery_codes",
	"refresh_tokens", "sessions", "sign_in_throttles", "signing_keys", "sms_budget", "totp_factors",
}

// queryStrings runs a query that returns one text column.
func queryStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestUpDownUp applies 000001 to an empty database as the migrator, reverts it, checks that
// nothing is left behind, and applies it again.
func TestUpDownUp(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := open(t, pgtest.As(t, pgtest.Empty(t), pgtest.Migrator))
	r := migrate.New(db, migrations.FS)

	applied, err := r.Up(ctx)
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if len(applied) != 1 || applied[0].File() != "000001_init.up.sql" {
		t.Fatalf("up applied %v; want 000001_init", applied)
	}
	got := queryStrings(t, db, `
		SELECT relname FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p') AND NOT relispartition
		  AND relname <> 'schema_migrations'
		ORDER BY relname`)
	if !slices.Equal(got, tables) {
		t.Errorf("tables after up:\n got %q\nwant %q", got, tables)
	}

	if _, err := r.Down(ctx, 1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if left := queryStrings(t, db, `
		SELECT relkind::text || ' ' || relname FROM pg_class
		WHERE relnamespace = 'public'::regnamespace
		  AND relname NOT IN ('schema_migrations', 'schema_migrations_pkey')
		UNION ALL
		SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace
		UNION ALL
		SELECT 'type ' || typname FROM pg_type
		WHERE typnamespace = 'public'::regnamespace AND typname NOT IN ('schema_migrations', '_schema_migrations')
		ORDER BY 1`); len(left) > 0 {
		t.Errorf("down left %q behind", left)
	}

	if _, err := r.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// TestForeignKeysIndexed fails when a foreign key has no full index that starts with its columns,
// so that deleting a referenced row (the purges of TDD-01 §5) does not scan the referencing table.
func TestForeignKeysIndexed(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	if n := queryStrings(t, db, `SELECT conname FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace`); len(n) == 0 {
		t.Fatal("found no foreign key; is the schema migrated?")
	}
	for _, fk := range queryStrings(t, db, `
		SELECT c.conrelid::regclass || '.' || c.conname FROM pg_constraint c
		WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace
		  AND NOT EXISTS (
		      SELECT FROM pg_index i
		      WHERE i.indrelid = c.conrelid AND i.indpred IS NULL
		        AND (i.indkey::int2[])[0:cardinality(c.conkey) - 1] = c.conkey)
		ORDER BY 1`) {
		t.Errorf("foreign key %s has no index that starts with its columns", fk)
	}
}
