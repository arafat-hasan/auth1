package migrate_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver

	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// okFS holds three migrations; the third sleeps and is not idempotent.
var okFS = os.DirFS("testdata/ok")

func openDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// mapFS copies fsys into a MapFS, so a test can change one file.
func mapFS(t *testing.T, fsys fs.FS) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = &fstest.MapFile{Data: data}
	}
	return out
}

func versions(ms []migrate.Migration) []int64 {
	out := []int64{}
	for _, m := range ms {
		out = append(out, m.Version)
	}
	return out
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(t.Context(), "SELECT to_regclass($1) IS NOT NULL", name).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func appliedCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustUp(t *testing.T, r *migrate.Runner, want ...int64) {
	t.Helper()
	got, err := r.Up(t.Context())
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !slices.Equal(versions(got), want) {
		t.Fatalf("Up applied %v, want %v", versions(got), want)
	}
}

func mustDown(t *testing.T, r *migrate.Runner, n int, want ...int64) {
	t.Helper()
	got, err := r.Down(t.Context(), n)
	if err != nil {
		t.Fatalf("Down(%d): %v", n, err)
	}
	if !slices.Equal(versions(got), want) {
		t.Fatalf("Down(%d) reverted %v, want %v", n, versions(got), want)
	}
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want one containing %q", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}

func TestUpDownStatus(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	r := migrate.New(db, okFS)

	states, err := r.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 {
		t.Fatalf("Status = %+v; want 3 states", states)
	}
	for _, s := range states {
		if s.Applied || s.FileMissing {
			t.Errorf("state %+v; want pending", s)
		}
	}
	if tableExists(t, db, "schema_migrations") {
		t.Error("Status created schema_migrations; only Up may")
	}

	mustUp(t, r, 1, 2, 3)
	for _, tbl := range []string{"widgets", "gadgets", "slow"} {
		if !tableExists(t, db, tbl) {
			t.Errorf("table %s missing after Up", tbl)
		}
	}
	states, err = r.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if !s.Applied || s.AppliedAt.IsZero() || s.Name == "" {
			t.Errorf("state %+v; want applied with a time and a name", s)
		}
	}
	mustUp(t, r)

	mustDown(t, r, 1, 3)
	if tableExists(t, db, "slow") {
		t.Error("table slow remains after Down(1)")
	}
	mustDown(t, r, 2, 2, 1)
	states, err = r.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if s.Applied {
			t.Errorf("state %+v; want pending", s)
		}
	}
	mustUp(t, r, 1, 2, 3)
}

func TestConcurrentUp(t *testing.T) {
	dsn := pgtest.Empty(t)
	runners := []*migrate.Runner{migrate.New(openDB(t, dsn), okFS), migrate.New(openDB(t, dsn), okFS)}

	var (
		wg      sync.WaitGroup
		barrier = make(chan struct{})
		applied [2][]migrate.Migration
		errs    [2]error
	)
	for i, r := range runners {
		wg.Go(func() {
			<-barrier
			applied[i], errs[i] = r.Up(context.WithoutCancel(t.Context()))
		})
	}
	close(barrier)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}
	if n := len(applied[0]) + len(applied[1]); n != 3 {
		t.Errorf("the runners applied %d migrations between them (%v, %v); want 3", n, versions(applied[0]), versions(applied[1]))
	}
	if n := appliedCount(t, openDB(t, dsn)); n != 3 {
		t.Errorf("schema_migrations has %d rows; want 3", n)
	}
}

func TestUpRefuses(t *testing.T) {
	t.Run("changed checksum", func(t *testing.T) {
		db := openDB(t, pgtest.Empty(t))
		first := mapFS(t, okFS)
		delete(first, "000002_gadgets.up.sql")
		delete(first, "000002_gadgets.down.sql")
		delete(first, "000003_slow.up.sql")
		delete(first, "000003_slow.down.sql")
		mustUp(t, migrate.New(db, first), 1)

		changed := mapFS(t, okFS)
		changed["000001_widgets.up.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE widgets (id bigint);")}
		_, err := migrate.New(db, changed).Up(t.Context())
		wantErr(t, err, "000001_widgets.up.sql")
		if tableExists(t, db, "gadgets") {
			t.Error("a refused Up applied a migration")
		}
	})

	t.Run("missing down file", func(t *testing.T) {
		db := openDB(t, pgtest.Empty(t))
		fsys := mapFS(t, okFS)
		delete(fsys, "000002_gadgets.down.sql")
		_, err := migrate.New(db, fsys).Up(t.Context())
		wantErr(t, err, "000002_gadgets.down.sql")
		if tableExists(t, db, "widgets") {
			t.Error("a refused Up applied a migration")
		}
	})

	t.Run("pending below applied", func(t *testing.T) {
		db := openDB(t, pgtest.Empty(t))
		later := mapFS(t, okFS)
		delete(later, "000001_widgets.up.sql")
		delete(later, "000001_widgets.down.sql")
		mustUp(t, migrate.New(db, later), 2, 3)
		_, err := migrate.New(db, okFS).Up(t.Context())
		wantErr(t, err, "000001_widgets.up.sql")
		if tableExists(t, db, "widgets") {
			t.Error("a refused Up applied a migration")
		}
	})
}

func TestUnknownApplied(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	mustUp(t, migrate.New(db, okFS), 1, 2, 3)

	older := mapFS(t, okFS)
	for _, f := range []string{"000002_gadgets.up.sql", "000002_gadgets.down.sql", "000003_slow.up.sql", "000003_slow.down.sql"} {
		delete(older, f)
	}
	r := migrate.New(db, older)
	mustUp(t, r)
	states, err := r.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	missing := map[int64]bool{}
	for _, s := range states {
		if !s.Applied {
			t.Errorf("state %+v; want applied", s)
		}
		missing[s.Version] = s.FileMissing
	}
	if want := map[int64]bool{1: false, 2: true, 3: true}; !maps.Equal(missing, want) {
		t.Errorf("file missing by version = %v; want %v", missing, want)
	}
	_, err = r.Down(t.Context(), 1)
	wantErr(t, err, "3")
	if n := appliedCount(t, db); n != 3 {
		t.Errorf("schema_migrations has %d rows after a refused Down; want 3", n)
	}
}

func TestDownRefuses(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	r := migrate.New(db, okFS)
	mustUp(t, r, 1, 2, 3)
	for _, n := range []int{0, -1, 4} {
		if _, err := r.Down(t.Context(), n); err == nil {
			t.Errorf("Down(%d) succeeded; want an error", n)
		}
	}
	if n := appliedCount(t, db); n != 3 {
		t.Errorf("schema_migrations has %d rows after refused Downs; want 3", n)
	}

	changed := mapFS(t, okFS)
	changed["000003_slow.up.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE slow (id bigint);")}
	_, err := migrate.New(db, changed).Down(t.Context(), 1)
	wantErr(t, err, "000003_slow.up.sql")
}

func TestFailingMigration(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	fsys := fstest.MapFS{
		"000001_good.up.sql":   {Data: []byte("CREATE TABLE good (id int);")},
		"000001_good.down.sql": {Data: []byte("DROP TABLE good;")},
		"000002_bad.up.sql":    {Data: []byte("CREATE TABLE a (id int); SELECT 1/0;")},
		"000002_bad.down.sql":  {Data: []byte("DROP TABLE a;")},
	}
	applied, err := migrate.New(db, fsys).Up(t.Context())
	wantErr(t, err, "000002_bad.up.sql")
	if !slices.Equal(versions(applied), []int64{1}) {
		t.Errorf("Up applied %v before failing; want [1]", versions(applied))
	}
	if !tableExists(t, db, "good") || tableExists(t, db, "a") {
		t.Error("want good present and a rolled back")
	}
	if n := appliedCount(t, db); n != 1 {
		t.Errorf("schema_migrations has %d rows; want 1", n)
	}

	fsys["000002_bad.up.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE a (id int);")}
	mustUp(t, migrate.New(db, fsys), 2)
}

func TestDownWithoutTable(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	_, err := migrate.New(db, okFS).Down(t.Context(), 1)
	wantErr(t, err, "only 0 applied")
	if tableExists(t, db, "schema_migrations") {
		t.Error("Down created schema_migrations; only Up may")
	}
}

// roleCounter names the roles TestStatusReadOnlyRole creates; roles are shared by every database
// of the container.
var roleCounter atomic.Int64

// TestStatusReadOnlyRole runs Status as a role that may read schema_migrations but not create
// tables, as the application's role is (TDD-01 §4.1).
func TestStatusReadOnlyRole(t *testing.T) {
	dsn := pgtest.Empty(t)
	owner := openDB(t, dsn)
	mustUp(t, migrate.New(owner, okFS), 1, 2, 3)

	role := fmt.Sprintf("reader_%d_%d", os.Getpid(), roleCounter.Add(1))
	for _, q := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD 'reader'",
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		"GRANT SELECT ON schema_migrations TO " + role,
	} {
		if _, err := owner.ExecContext(t.Context(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() {
		for _, q := range []string{"DROP OWNED BY " + role, "DROP ROLE " + role} {
			if _, err := owner.ExecContext(context.Background(), q); err != nil {
				t.Errorf("%s: %v", q, err)
			}
		}
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "reader")
	r := migrate.New(openDB(t, u.String()), okFS)

	states, err := r.Status(t.Context())
	if err != nil {
		t.Fatalf("Status as a read-only role: %v", err)
	}
	for _, s := range states {
		if !s.Applied {
			t.Errorf("state %+v; want applied", s)
		}
	}
	_, err = r.Up(t.Context())
	wantErr(t, err, "schema_migrations")
}

func TestStatusShowsChanged(t *testing.T) {
	db := openDB(t, pgtest.Empty(t))
	mustUp(t, migrate.New(db, okFS), 1, 2, 3)

	changed := mapFS(t, okFS)
	changed["000002_gadgets.up.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE gadgets (id bigint);")}
	states, err := migrate.New(db, changed).Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, s := range states {
		got[s.Version] = s.Changed
	}
	if want := map[int64]bool{1: false, 2: true, 3: false}; !maps.Equal(got, want) {
		t.Errorf("changed by version = %v; want %v", got, want)
	}
}

func TestWaitBoundsTheLock(t *testing.T) {
	dsn := pgtest.Empty(t)
	holder, err := openDB(t, dsn).Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(t.Context(), "SELECT pg_advisory_lock($1)", int64(0x61757468316d6967)); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = migrate.New(openDB(t, dsn), okFS, migrate.WithWait(100*time.Millisecond)).Status(t.Context())
	wantErr(t, err, "migration lock")
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Status took %v; want about the 100ms wait", d)
	}
}
