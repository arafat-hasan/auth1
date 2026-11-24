package postgres_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

var _ app.ClientAssertions = (*postgres.ClientAssertions)(nil)

// assertionsDB returns the repository on a fresh database as auth1_app, and the superuser pool.
func assertionsDB(t *testing.T) (*postgres.ClientAssertions, *bun.DB) {
	t.Helper()
	dsn := pgtest.DSN(t)
	open := func(dsn string, maxConns int) *bun.DB {
		cfg := dbConfig(dsnFile(t, dsn))
		cfg.MaxConns = maxConns
		db, err := postgres.Open(cfg, config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return postgres.NewClientAssertions(open(pgtest.As(t, dsn, pgtest.App), 20)), open(dsn, 2)
}

var assertionExpiry = time.Date(2026, 11, 13, 10, 5, 30, 0, time.UTC)

func TestRecordOnce(t *testing.T) {
	t.Parallel()
	repo, su := assertionsDB(t)
	ctx := context.Background()
	for i, want := range []bool{true, false} {
		fresh, err := repo.Record(ctx, "reports", "jti-1", assertionExpiry)
		if err != nil || fresh != want {
			t.Fatalf("Record #%d = %t, %v; want %t", i+1, fresh, err, want)
		}
	}
	var exp time.Time
	if err := su.QueryRowContext(ctx, `SELECT expires_at FROM client_assertions WHERE client_id = 'reports' AND jti = 'jti-1'`).Scan(&exp); err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(assertionExpiry) {
		t.Errorf("expires_at = %s, want %s", exp, assertionExpiry)
	}
}

// TestRecordPerClient: a jti is new per client; another client may use the same one.
func TestRecordPerClient(t *testing.T) {
	t.Parallel()
	repo, _ := assertionsDB(t)
	for _, client := range []string{"reports", "billing"} {
		if fresh, err := repo.Record(context.Background(), client, "jti-1", assertionExpiry); err != nil || !fresh {
			t.Errorf("Record(%s) = %t, %v; want true", client, fresh, err)
		}
	}
}

// TestRecordConcurrent: of concurrent records of one (client, jti), exactly one is fresh, so a
// replayed assertion yields at most one token (TDD-05 §2).
func TestRecordConcurrent(t *testing.T) {
	t.Parallel()
	repo, _ := assertionsDB(t)
	var fresh atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Go(func() {
			<-start
			ok, err := repo.Record(context.Background(), "reports", "jti-race", assertionExpiry)
			if err != nil {
				t.Error(err)
			}
			if ok {
				fresh.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if n := fresh.Load(); n != 1 {
		t.Errorf("%d fresh records, want exactly 1", n)
	}
}
