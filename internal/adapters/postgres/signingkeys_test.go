package postgres_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

var _ app.SigningKeyStore = (*postgres.SigningKeys)(nil)

// signingKeysDB returns the store on a migrated database, used as auth1_app, and a superuser pool
// on the same database for setting and reading the rows.
func signingKeysDB(t *testing.T) (*postgres.SigningKeys, *bun.DB) {
	t.Helper()
	dsn := pgtest.DSN(t)
	open := func(dsn string) *bun.DB {
		db, err := postgres.Open(dbConfig(dsnFile(t, dsn)), config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return postgres.NewSigningKeys(open(pgtest.As(t, dsn, pgtest.App))), open(dsn)
}

// exec runs a statement as superuser.
func exec(t *testing.T, db *bun.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

type keyRow struct {
	firstPublished     time.Time
	activated, retired sql.NullTime
}

func row(t *testing.T, db *bun.DB, kid string) keyRow {
	t.Helper()
	var r keyRow
	err := db.QueryRowContext(t.Context(),
		"SELECT first_published_at, activated_at, retired_at FROM signing_keys WHERE kid = ?", kid).
		Scan(&r.firstPublished, &r.activated, &r.retired)
	if err != nil {
		t.Fatalf("row %s: %v", kid, err)
	}
	return r
}

func TestPublishKeepsFirstTime(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	if err := store.Publish(ctx, []app.SigningKeyRecord{{Kid: "k1", Alg: "RS256"}}); err != nil {
		t.Fatal(err)
	}
	exec(t, su, "UPDATE signing_keys SET first_published_at = now() - interval '1 hour' WHERE kid = 'k1'")
	before := row(t, su, "k1").firstPublished
	err := store.Publish(ctx, []app.SigningKeyRecord{{Kid: "k1", Alg: "RS256"}, {Kid: "k2", Alg: "ES256"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := row(t, su, "k1").firstPublished; !got.Equal(before) {
		t.Errorf("k1 first_published_at = %v, want it kept at %v", got, before)
	}
	var alg string
	if err := su.QueryRowContext(ctx, "SELECT alg FROM signing_keys WHERE kid = 'k2'").Scan(&alg); err != nil {
		t.Fatal(err)
	}
	if alg != "ES256" {
		t.Errorf("k2 alg = %q, want ES256", alg)
	}
	if err := store.Publish(ctx, nil); err != nil {
		t.Errorf("Publish(nil) = %v", err)
	}
}

// TestActivateUsesDatabaseClock pins I-14: a key signs only after min_publish_before_use, on the
// database's clock.
func TestActivateUsesDatabaseClock(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	if err := store.Publish(ctx, []app.SigningKeyRecord{{Kid: "k1", Alg: "RS256"}}); err != nil {
		t.Fatal(err)
	}
	const wait = 15 * time.Minute

	exec(t, su, "UPDATE signing_keys SET first_published_at = now() - interval '14 min 59 s'")
	ok, err := store.Activate(ctx, "k1", wait)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(t, su, "k1"); ok || r.activated.Valid {
		t.Fatalf("published 14m59s ago: Activate = %v, activated_at %v; want false and null", ok, r.activated)
	}

	exec(t, su, "UPDATE signing_keys SET first_published_at = now() - interval '15 min'")
	ok, err = store.Activate(ctx, "k1", wait)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(t, su, "k1"); !ok || !r.activated.Valid {
		t.Fatalf("published 15m ago: Activate = %v, activated_at %v; want true and set", ok, r.activated)
	}

	if ok, err := store.Activate(ctx, "unknown", wait); err != nil || ok {
		t.Errorf("unknown kid: Activate = %v, %v; want false, nil", ok, err)
	}
}

func TestActivateKeepsFirstActivation(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	if err := store.Publish(ctx, []app.SigningKeyRecord{{Kid: "k1", Alg: "RS256"}}); err != nil {
		t.Fatal(err)
	}
	exec(t, su, `UPDATE signing_keys SET first_published_at = now() - interval '2 hours',
		activated_at = now() - interval '1 hour', retired_at = now() - interval '30 min'`)
	first := row(t, su, "k1").activated.Time
	if ok, err := store.Activate(ctx, "k1", time.Minute); err != nil || !ok {
		t.Fatalf("Activate = %v, %v", ok, err)
	}
	r := row(t, su, "k1")
	if !r.activated.Time.Equal(first) {
		t.Errorf("activated_at = %v, want the first activation %v", r.activated.Time, first)
	}
	if r.retired.Valid {
		t.Errorf("retired_at = %v, want it cleared for a key that signs again", r.retired.Time)
	}
}

func TestLatestActivated(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	recs := []app.SigningKeyRecord{{Kid: "a", Alg: "RS256"}, {Kid: "b", Alg: "RS256"}, {Kid: "c", Alg: "RS256"}, {Kid: "d", Alg: "RS256"}}
	if err := store.Publish(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if got, err := store.LatestActivated(ctx, []string{"a", "b", "c"}); err != nil || got != "" {
		t.Errorf("none activated: LatestActivated = %q, %v; want \"\"", got, err)
	}
	exec(t, su, "UPDATE signing_keys SET activated_at = now() - interval '2 hours' WHERE kid = 'a'")
	exec(t, su, "UPDATE signing_keys SET activated_at = now() - interval '1 hour' WHERE kid = 'b'")
	exec(t, su, "UPDATE signing_keys SET activated_at = now() WHERE kid = 'd'") // not in the list
	if got, err := store.LatestActivated(ctx, []string{"a", "b", "c"}); err != nil || got != "b" {
		t.Errorf("LatestActivated = %q, %v; want b", got, err)
	}
	if got, err := store.LatestActivated(ctx, nil); err != nil || got != "" {
		t.Errorf("no kids: LatestActivated = %q, %v; want \"\"", got, err)
	}
}

func TestRetireOnce(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	if err := store.Publish(ctx, []app.SigningKeyRecord{{Kid: "k1", Alg: "RS256"}, {Kid: "k2", Alg: "RS256"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(ctx, []string{"k1"}); err != nil {
		t.Fatal(err)
	}
	exec(t, su, "UPDATE signing_keys SET retired_at = retired_at - interval '1 hour' WHERE kid = 'k1'")
	first := row(t, su, "k1").retired
	if err := store.Retire(ctx, []string{"k1"}); err != nil {
		t.Fatal(err)
	}
	if got := row(t, su, "k1").retired; !got.Valid || !got.Time.Equal(first.Time) {
		t.Errorf("retired_at = %v, want the first retirement %v", got, first)
	}
	if row(t, su, "k2").retired.Valid {
		t.Error("k2 retired, want only the keys named")
	}
	if err := store.Retire(ctx, nil); err != nil {
		t.Errorf("Retire(nil) = %v", err)
	}
}

func TestRetiringWindow(t *testing.T) {
	t.Parallel()
	store, su := signingKeysDB(t)
	ctx := t.Context()
	recs := []app.SigningKeyRecord{{Kid: "in", Alg: "RS256"}, {Kid: "out", Alg: "RS256"}, {Kid: "null", Alg: "RS256"}}
	if err := store.Publish(ctx, recs); err != nil {
		t.Fatal(err)
	}
	const window = 20 * time.Minute
	exec(t, su, "UPDATE signing_keys SET retired_at = now() - interval '20 min' + interval '1 s' WHERE kid = 'in'")
	exec(t, su, "UPDATE signing_keys SET retired_at = now() - interval '20 min' - interval '1 s' WHERE kid = 'out'")
	got, err := store.Retiring(ctx, []string{"in", "out", "null", "unknown"}, window)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"in", "null"}, got); diff != "" {
		t.Errorf("Retiring (-want +got):\n%s", diff)
	}
	if got, err := store.Retiring(ctx, nil, window); err != nil || len(got) != 0 {
		t.Errorf("no kids: Retiring = %v, %v", got, err)
	}
}
