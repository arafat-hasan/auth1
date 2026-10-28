package migrations_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// invalidParameter is the SQLSTATE of an out-of-range months argument.
const invalidParameter = "22023"

// partitionGrants are the grants every audit partition has, as auditGrants lists them.
var partitionGrants = []string{"auth1_app INSERT", "auth1_app SELECT", "auth1_app UPDATE (ip)", "auth1_app UPDATE (user_agent)"}

// auditPartitions lists the partitions of auth_audit as "name bound", the bound read in UTC.
func auditPartitions(t *testing.T, db *sql.DB) []string {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SET LOCAL TimeZone = 'UTC'`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.QueryContext(t.Context(), `
		SELECT c.relname || ' ' || pg_get_expr(c.relpartbound, c.oid)
		FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'auth_audit'::regclass
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
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

// wantPartitions returns what auditPartitions lists for the current UTC month and the next
// months months, the month read from the database's clock.
func wantPartitions(t *testing.T, db *sql.DB, months int) []string {
	t.Helper()
	var first time.Time
	if err := db.QueryRowContext(t.Context(), `SELECT date_trunc('month', now() AT TIME ZONE 'UTC')`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	const layout = "2006-01-02 15:04:05+00"
	var out []string
	for i := range months + 1 {
		start := first.AddDate(0, i, 0)
		out = append(out, fmt.Sprintf("auth_audit_%s FOR VALUES FROM ('%s') TO ('%s')",
			start.Format("2006_01"), start.Format(layout), start.AddDate(0, 1, 0).Format(layout)))
	}
	return out
}

// auditGrants lists the privileges on table that are granted to roles other than its owner, as
// "grantee PRIVILEGE" or "grantee PRIVILEGE (column)", sorted; PUBLIC appears as "PUBLIC".
func auditGrants(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	return queryStrings(t, db, `
		WITH acl AS (
		    SELECT (aclexplode(c.relacl)).*, NULL::name AS col, c.relowner
		    FROM pg_class c WHERE c.oid = $1::regclass
		    UNION ALL
		    SELECT (aclexplode(a.attacl)).*, a.attname, c.relowner
		    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		    WHERE a.attrelid = $1::regclass AND a.attacl IS NOT NULL
		)
		SELECT CASE grantee WHEN 0 THEN 'PUBLIC' ELSE grantee::regrole::text END || ' ' ||
		       privilege_type || coalesce(' (' || col || ')', '')
		FROM acl WHERE grantee <> relowner ORDER BY 1`, table)
}

// createPartitions calls the partition function on db.
func createPartitions(t *testing.T, db interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, months any) (int, error) {
	t.Helper()
	var n int
	err := db.QueryRowContext(t.Context(), `SELECT auth_audit_create_partitions($1)`, months).Scan(&n)
	return n, err
}

// TestInitialPartitions checks that the migration creates this month's and next month's audit
// partitions, with UTC bounds, no DEFAULT partition, and the grants of the parent.
func TestInitialPartitions(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))

	if got, want := auditPartitions(t, db), wantPartitions(t, db, 1); !slices.Equal(got, want) {
		t.Errorf("partitions:\n got %q\nwant %q", got, want)
	}
	var defaultPartition bool
	if err := db.QueryRowContext(t.Context(), `SELECT partdefid <> 0 FROM pg_partitioned_table WHERE partrelid = 'auth_audit'::regclass`).Scan(&defaultPartition); err != nil {
		t.Fatal(err)
	}
	if defaultPartition {
		t.Error("auth_audit has a DEFAULT partition")
	}
	for _, p := range auditPartitions(t, db) {
		name, _, _ := strings.Cut(p, " ")
		if got := auditGrants(t, db, name); !slices.Equal(got, partitionGrants) {
			t.Errorf("grants on %s:\n got %q\nwant %q", name, got, partitionGrants)
		}
	}
}

// TestCreatePartitions calls the function as the service, as the partition job will.
func TestCreatePartitions(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	admin, app := open(t, dsn), open(t, pgtest.As(t, dsn, pgtest.App))

	for _, tc := range []struct {
		months, created int
	}{{2, 1}, {2, 0}, {0, 0}, {1, 0}} {
		n, err := createPartitions(t, app, tc.months)
		if err != nil {
			t.Fatalf("create(%d): %v", tc.months, err)
		}
		if n != tc.created {
			t.Errorf("create(%d) created %d; want %d", tc.months, n, tc.created)
		}
	}
	if got, want := auditPartitions(t, admin), wantPartitions(t, admin, 2); !slices.Equal(got, want) {
		t.Errorf("partitions:\n got %q\nwant %q", got, want)
	}
	newest := wantPartitions(t, admin, 2)[2]
	name, _, _ := strings.Cut(newest, " ")
	if got := auditGrants(t, admin, name); !slices.Equal(got, partitionGrants) {
		t.Errorf("grants on %s:\n got %q\nwant %q", name, got, partitionGrants)
	}
}

// TestCreatePartitionsTimeZone checks that the bounds are UTC months whatever the caller's
// TimeZone.
func TestCreatePartitionsTimeZone(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	admin, app := open(t, dsn), open(t, pgtest.As(t, dsn, pgtest.App))

	for i, zone := range []string{"Pacific/Kiritimati", "Pacific/Pago_Pago"} { // UTC+14, UTC-11
		conn, err := app.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(t.Context(), `SELECT set_config('TimeZone', $1, false)`, zone); err != nil {
			t.Fatal(err)
		}
		if n, err := createPartitions(t, conn, 2+i); err != nil || n != 1 {
			t.Errorf("create(%d) in %s = %d, %v; want 1", 2+i, zone, n, err)
		}
		_ = conn.Raw(func(any) error { return driver.ErrBadConn }) // discard it: its session was changed
		_ = conn.Close()
	}
	if got, want := auditPartitions(t, admin), wantPartitions(t, admin, 3); !slices.Equal(got, want) {
		t.Errorf("partitions:\n got %q\nwant %q", got, want)
	}
}

// TestCreatePartitionsConcurrent checks that two job replicas calling the function at once both
// succeed and create each partition once.
func TestCreatePartitionsConcurrent(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	admin := open(t, dsn)
	callers := []*sql.DB{open(t, pgtest.As(t, dsn, pgtest.App)), open(t, pgtest.As(t, dsn, pgtest.App))}

	var wg sync.WaitGroup
	created := make([]int, len(callers))
	errs := make([]error, len(callers))
	for i, db := range callers {
		wg.Go(func() { created[i], errs[i] = createPartitions(t, db, 4) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent calls: %v", err)
	}
	if sum := created[0] + created[1]; sum != 3 {
		t.Errorf("the calls created %d partitions between them; want 3", sum)
	}
	if got, want := auditPartitions(t, admin), wantPartitions(t, admin, 4); !slices.Equal(got, want) {
		t.Errorf("partitions:\n got %q\nwant %q", got, want)
	}
}

// TestCreatePartitionsRange checks that months outside 0…12 is refused and creates nothing.
func TestCreatePartitionsRange(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	admin, app := open(t, dsn), open(t, pgtest.As(t, dsn, pgtest.App))
	before := auditPartitions(t, admin)

	for _, months := range []any{-1, 13, nil} {
		_, err := createPartitions(t, app, months)
		wantCode(t, err, invalidParameter, "")
	}
	if after := auditPartitions(t, admin); !slices.Equal(after, before) {
		t.Errorf("partitions changed:\n got %q\nwant %q", after, before)
	}
}

// TestAuditRouting checks that a row lands in its month's partition, and that a row with no
// partition is refused, since there is no DEFAULT partition.
func TestAuditRouting(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	var partition string
	if err := db.QueryRowContext(t.Context(), `
		INSERT INTO auth_audit (actor_kind, action, outcome) VALUES ('system', 'test.action', 'ok')
		RETURNING tableoid::regclass::text`).Scan(&partition); err != nil {
		t.Fatal(err)
	}
	if want, _, _ := strings.Cut(wantPartitions(t, db, 0)[0], " "); partition != want {
		t.Errorf("the row went to %s; want %s", partition, want)
	}
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO auth_audit (at, actor_kind, action, outcome)
		VALUES (now() + interval '3 months', 'system', 'test.action', 'ok')`)
	wantCode(t, err, checkViolation, "")
}

// TestPublicCannotCall checks that a role other than the service cannot call the function.
func TestPublicCannotCall(t *testing.T) {
	t.Parallel()
	db := open(t, pgtest.DSN(t))
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn }) // discard it: its session was changed
		_ = conn.Close()
	}()
	// Roles belong to the container, which this package's tests share; only this test uses this one.
	if _, err := conn.ExecContext(t.Context(), `DROP ROLE IF EXISTS audit_other; CREATE ROLE audit_other NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP ROLE IF EXISTS audit_other`)
	})
	if _, err := conn.ExecContext(t.Context(), `SET ROLE audit_other`); err != nil {
		t.Fatal(err)
	}
	_, err = createPartitions(t, conn, 1)
	wantCode(t, err, insufficientPrivilege, "")
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && !strings.Contains(pgErr.Message, "function auth_audit_create_partitions") {
		t.Errorf("refused for another reason: %s", pgErr.Message)
	}
}
