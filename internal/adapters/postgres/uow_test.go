package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

var _ app.UnitOfWork = (*postgres.UnitOfWork)(nil)

var errSentinel = errors.New("sentinel")

// itemsDB opens a pool of maxConns on a new database with an items table.
func itemsDB(t *testing.T, maxConns int) *bun.DB {
	t.Helper()
	cfg := dbConfig(dsnFile(t, pgtest.DSN(t)))
	cfg.MaxConns = maxConns
	db, err := postgres.Open(cfg, config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE items (id int PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	return db
}

func newUoW(db *bun.DB) *postgres.UnitOfWork {
	return postgres.NewUnitOfWork(db, 2*time.Second, noop.NewTracerProvider())
}

func insert(ctx context.Context, db *bun.DB, id int) error {
	_, err := postgres.Conn(ctx, db).ExecContext(ctx, "INSERT INTO items (id) VALUES (?)", id)
	return err
}

func count(t *testing.T, db *bun.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM items").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDoCommits(t *testing.T) {
	db := itemsDB(t, 2)
	if err := newUoW(db).Do(t.Context(), func(ctx context.Context) error { return insert(ctx, db, 1) }); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db); n != 1 {
		t.Errorf("%d rows after a committed Do; want 1", n)
	}
}

func TestDoRollsBackOnError(t *testing.T) {
	db := itemsDB(t, 2)
	err := newUoW(db).Do(t.Context(), func(ctx context.Context) error {
		if err := insert(ctx, db, 1); err != nil {
			return err
		}
		return errSentinel
	})
	if !errors.Is(err, errSentinel) {
		t.Fatalf("Do = %v; want the sentinel", err)
	}
	if n := count(t, db); n != 0 {
		t.Errorf("%d rows after a failed Do; want 0", n)
	}
}

func TestDoRollsBackOnPanic(t *testing.T) {
	db := itemsDB(t, 2)
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Errorf("recovered %v; want the panic to continue as \"boom\"", r)
			}
		}()
		_ = newUoW(db).Do(t.Context(), func(ctx context.Context) error {
			if err := insert(ctx, db, 1); err != nil {
				t.Error(err)
			}
			panic("boom")
		})
	}()
	if n := count(t, db); n != 0 {
		t.Errorf("%d rows after a panic; want 0", n)
	}
	if inUse := db.Stats().InUse; inUse != 0 {
		t.Errorf("%d connections in use after a panic; want 0", inUse)
	}
}

func TestDoReadCommitted(t *testing.T) {
	db := itemsDB(t, 2)
	var name string
	if err := db.QueryRowContext(t.Context(), "SELECT current_database()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "ALTER DATABASE "+name+" SET default_transaction_isolation = 'serializable'"); err != nil {
		t.Fatal(err)
	}
	// The setting applies to new sessions; drop the pooled ones.
	db.SetMaxIdleConns(0)
	db.SetMaxIdleConns(2)

	var level string
	err := newUoW(db).Do(t.Context(), func(ctx context.Context) error {
		return postgres.Conn(ctx, db).QueryRowContext(ctx, "SHOW transaction_isolation").Scan(&level)
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != "read committed" {
		t.Errorf("isolation %q; want read committed", level)
	}
	var def string
	if err := db.QueryRowContext(t.Context(), "SHOW default_transaction_isolation").Scan(&def); err != nil {
		t.Fatal(err)
	}
	if def != "serializable" {
		t.Fatalf("default isolation %q: the test did not change the default", def)
	}
}

func TestNestedDoJoins(t *testing.T) {
	db := itemsDB(t, 2)
	u := newUoW(db)
	txid := func(ctx context.Context) (int64, error) {
		var id int64
		err := postgres.Conn(ctx, db).QueryRowContext(ctx, "SELECT txid_current()").Scan(&id)
		return id, err
	}
	err := u.Do(t.Context(), func(ctx context.Context) error {
		if err := insert(ctx, db, 1); err != nil {
			return err
		}
		outer, err := txid(ctx)
		if err != nil {
			return err
		}
		if err := u.Do(ctx, func(ctx context.Context) error {
			inner, err := txid(ctx)
			if err != nil {
				return err
			}
			if inner != outer {
				t.Errorf("inner transaction %d, outer %d; want one transaction", inner, outer)
			}
			var n int
			if err := postgres.Conn(ctx, db).QueryRowContext(ctx, "SELECT count(*) FROM items").Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				t.Errorf("the inner Do sees %d rows; want the outer insert", n)
			}
			return insert(ctx, db, 2)
		}); err != nil {
			return err
		}
		return errSentinel
	})
	if !errors.Is(err, errSentinel) {
		t.Fatalf("Do = %v; want the sentinel", err)
	}
	if n := count(t, db); n != 0 {
		t.Errorf("%d rows after the outer Do failed; want 0", n)
	}
}

func TestConnOutsideDo(t *testing.T) {
	db := itemsDB(t, 1)
	if got := postgres.Conn(t.Context(), db); got != bun.IDB(db) {
		t.Errorf("Conn outside Do = %T; want the pool", got)
	}
}

func TestDoCommitFailure(t *testing.T) {
	db := itemsDB(t, 2)
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE d (id int, CONSTRAINT d_id UNIQUE (id) DEFERRABLE INITIALLY DEFERRED)"); err != nil {
		t.Fatal(err)
	}
	err := newUoW(db).Do(t.Context(), func(ctx context.Context) error {
		_, err := postgres.Conn(ctx, db).ExecContext(ctx, "INSERT INTO d (id) VALUES (1), (1)")
		return err
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23505" {
		t.Fatalf("Do = %v; want the commit's unique violation", err)
	}
}

// holdConnection runs a Do that keeps the pool's only connection until release is closed.
func holdConnection(t *testing.T, db *bun.DB) (release func()) {
	t.Helper()
	held, done := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = newUoW(db).Do(context.WithoutCancel(t.Context()), func(context.Context) error {
			close(held)
			<-done
			return nil
		})
	})
	<-held
	return func() { close(done); wg.Wait() }
}

func TestDoAcquireTimeout(t *testing.T) {
	db := itemsDB(t, 1)
	release := holdConnection(t, db)
	defer release()

	ran := false
	start := time.Now()
	err := postgres.NewUnitOfWork(db, 50*time.Millisecond, noop.NewTracerProvider()).Do(t.Context(), func(context.Context) error {
		ran = true
		return nil
	})
	if d := time.Since(start); d > time.Second {
		t.Errorf("Do took %v; want about the 50ms acquire timeout", d)
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUnavailable {
		t.Errorf("Do = %v; want UNAVAILABLE", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Do = %v; want it to wrap the deadline", err)
	}
	if ran {
		t.Error("fn ran without a connection")
	}
}

func TestDoCallerCancelled(t *testing.T) {
	db := itemsDB(t, 1)
	release := holdConnection(t, db)
	defer release()

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	err := postgres.NewUnitOfWork(db, time.Second, noop.NewTracerProvider()).Do(ctx, func(context.Context) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do = %v; want the caller's cancellation", err)
	}
	var de *domain.Error
	if errors.As(err, &de) {
		t.Errorf("Do = %v; want no domain error when the caller gave up", err)
	}
}

func TestDoSpan(t *testing.T) {
	db := itemsDB(t, 2)
	sr := tracetest.NewSpanRecorder()
	u := postgres.NewUnitOfWork(db, time.Second, sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)))

	if err := u.Do(t.Context(), func(ctx context.Context) error {
		return u.Do(ctx, func(ctx context.Context) error { return insert(ctx, db, 1) })
	}); err != nil {
		t.Fatal(err)
	}
	_ = u.Do(t.Context(), func(context.Context) error { return errSentinel })

	spans := sr.Ended()
	if len(spans) != 2 {
		t.Fatalf("%d spans; want one per outer Do", len(spans))
	}
	for i, s := range spans {
		if s.Name() != "db.transaction" || s.SpanKind() != trace.SpanKindClient {
			t.Errorf("span %d: %q %v; want db.transaction, client", i, s.Name(), s.SpanKind())
		}
		var system string
		for _, a := range s.Attributes() {
			if a.Key == "db.system.name" {
				system = a.Value.AsString()
			}
			if strings.Contains(a.Value.String(), "postgres://") {
				t.Errorf("span %d attribute %s holds a DSN", i, a.Key)
			}
		}
		if system != "postgresql" {
			t.Errorf("span %d: db.system.name %q", i, system)
		}
	}
	if spans[0].Status().Code.String() != "Unset" || spans[1].Status().Code.String() != "Error" {
		t.Errorf("statuses %v, %v; want Unset, Error", spans[0].Status().Code, spans[1].Status().Code)
	}
}
