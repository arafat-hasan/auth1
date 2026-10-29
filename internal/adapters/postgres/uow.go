package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// txKey is the context key of the open transaction.
type txKey struct{}

// unavailable is the domain failure for a pool that hands out no connection in time.
var unavailable = &domain.Error{Code: domain.CodeUnavailable, Detail: "The service is temporarily unavailable."}

// UnitOfWork implements app.UnitOfWork with one READ COMMITTED transaction (TDD-01 §4.2, §6).
type UnitOfWork struct {
	db             *bun.DB
	acquireTimeout time.Duration
	tracer         trace.Tracer
}

// NewUnitOfWork returns a UnitOfWork on db. acquireTimeout (database.acquire_timeout) bounds the
// wait for a connection, which database/sql does not bound itself.
func NewUnitOfWork(db *bun.DB, acquireTimeout time.Duration, tp trace.TracerProvider) *UnitOfWork {
	return &UnitOfWork{db: db, acquireTimeout: acquireTimeout, tracer: tp.Tracer("github.com/arafat-hasan/auth1/internal/adapters/postgres")}
}

// Do runs fn in a transaction, which repositories reach through Conn. It commits once when fn
// returns nil and rolls back when fn returns an error or panics; the panic continues after the
// rollback. A Do inside fn joins the open transaction. Do returns UNAVAILABLE wrapping the cause
// when no connection is free within the acquire timeout, when the transaction cannot begin, or
// when COMMIT could not be sent; when ctx ends first, ctx's error. A COMMIT that fails after it
// was sent is returned as it is: it may have been applied, so it is not safe to retry.
func (u *UnitOfWork) Do(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if inTx(ctx) {
		return fn(ctx)
	}

	ctx, span := u.tracer.Start(ctx, "db.transaction",
		trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(semconv.DBSystemNamePostgreSQL))
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, "rolled back")
		}
		span.End()
	}()

	conn, err := u.acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return failure(ctx, "begin transaction", err)
	}
	// panicked stays true when fn panics; the panic then continues past the rollback by itself.
	committed, panicked := false, true
	defer func() {
		if committed {
			return
		}
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back: %w", rerr))
		}
		if panicked {
			span.SetStatus(codes.Error, "panic") // the span ends in the deferred call above
		}
	}()

	err = fn(context.WithValue(ctx, txKey{}, tx))
	panicked = false
	if err != nil {
		return err
	}
	committed = true
	if err := tx.Commit(); err != nil {
		if pgconn.SafeToRetry(err) {
			return failure(ctx, "commit", err)
		}
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// acquire takes a connection from the pool within the acquire timeout.
func (u *UnitOfWork) acquire(ctx context.Context) (bun.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, u.acquireTimeout)
	defer cancel()
	conn, err := u.db.Conn(actx)
	if err != nil {
		return bun.Conn{}, failure(ctx, "acquire database connection", err)
	}
	return conn, nil
}

// failure is the error of op failing with err for want of the database: ctx's error when ctx has
// ended, otherwise UNAVAILABLE wrapping err.
func failure(ctx context.Context, op string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", op, ctx.Err())
	}
	return fmt.Errorf("%s: %w: %w", op, unavailable, err)
}

// Conn returns the executor for a repository: the transaction Do opened, when ctx carries one,
// otherwise the pool.
func Conn(ctx context.Context, db *bun.DB) bun.IDB {
	if tx, ok := ctx.Value(txKey{}).(bun.Tx); ok {
		return tx
	}
	return db
}

// inTx reports whether ctx carries the transaction UnitOfWork.Do opened.
func inTx(ctx context.Context) bool {
	_, ok := ctx.Value(txKey{}).(bun.Tx)
	return ok
}
