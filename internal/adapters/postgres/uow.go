package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// txKey is the context key of the open transaction, a *txn.
type txKey struct{}

// txn is the transaction Do opened and the rows locked in it: accounts, and the flows,
// challenges and sessions whose methods check the lock order (G-5). A use case runs on one
// goroutine, so txn has no lock of its own, as bun.Tx has none.
type txn struct {
	tx         bun.Tx
	locked     []*lockedAccount // in lock order
	flows      map[uuid.UUID]flow.Kind
	challenges []uuid.UUID
	sessions   []uuid.UUID
	savepoints int // savepoints taken so far, which names the next one
}

// txnRecords is what a txn has recorded at a savepoint, restored when the savepoint rolls back.
type txnRecords struct {
	locked     []lockedAccount
	flows      map[uuid.UUID]flow.Kind
	challenges int
	sessions   int
}

// records returns a copy of what the transaction has recorded so far.
func (t *txn) records() txnRecords {
	r := txnRecords{flows: maps.Clone(t.flows), challenges: len(t.challenges), sessions: len(t.sessions)}
	for _, a := range t.locked {
		r.locked = append(r.locked, *a)
	}
	return r
}

// restore goes back to the records r: rolling back to a savepoint releases the row locks taken
// after it and discards the events written after it.
func (t *txn) restore(r txnRecords) {
	t.locked = t.locked[:0]
	for _, a := range r.locked {
		t.locked = append(t.locked, &a)
	}
	t.flows = r.flows
	t.challenges = t.challenges[:r.challenges]
	t.sessions = t.sessions[:r.sessions]
}

// lockedAccount is an account locked in the transaction: the version read under the lock and the
// events written about it so far.
type lockedAccount struct {
	id      uuid.UUID
	version int64
	events  int64
}

// lock records that the transaction locked the account, read at version. A second lock keeps the
// first record: the row has not changed under the lock. Take the lock outside a savepoint: rolling
// back to one releases the row locks taken after it, and the record would outlive the lock.
func (t *txn) lock(id uuid.UUID, version int64) {
	if t.account(id) == nil {
		t.locked = append(t.locked, &lockedAccount{id: id, version: version})
	}
}

// lockFlow records that the transaction locked the flow id, of kind. As for lock, take the lock
// outside a savepoint.
func (t *txn) lockFlow(id uuid.UUID, kind flow.Kind) {
	if t.flows == nil {
		t.flows = make(map[uuid.UUID]flow.Kind)
	}
	t.flows[id] = kind
}

// lockChallenge records that the transaction locked the challenge id, as lockFlow.
func (t *txn) lockChallenge(id uuid.UUID) {
	if !slices.Contains(t.challenges, id) {
		t.challenges = append(t.challenges, id)
	}
}

// lockSession records that the transaction locked the session id. As for lock, take the lock
// outside a savepoint.
func (t *txn) lockSession(id uuid.UUID) {
	if !slices.Contains(t.sessions, id) {
		t.sessions = append(t.sessions, id)
	}
}

// account returns the locked account id, or nil when the transaction has not locked it.
func (t *txn) account(id uuid.UUID) *lockedAccount {
	for _, a := range t.locked {
		if a.id == id {
			return a
		}
	}
	return nil
}

// finish moves each locked account to its version plus the number of events written about it,
// or plus one when there were none: a change without an event still moves the version
// (TDD-06 §2, TDD-01 §4.2, I-10).
func (t *txn) finish(ctx context.Context) error {
	for _, a := range t.locked {
		res, err := t.tx.ExecContext(ctx, "UPDATE accounts SET version = ?, updated_at = now() WHERE id = ?",
			a.version+max(1, a.events), a.id)
		if err != nil {
			return fmt.Errorf("set account version: %w", err)
		}
		if err := oneRow(res, "set account version", "account"); err != nil {
			return err
		}
	}
	return nil
}

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

// Do runs fn in a transaction, which repositories reach through Conn. When fn returns nil, Do
// moves the version of every account fn locked with Accounts.GetForUpdate (TDD-06 §2) and commits
// once. It rolls back when fn or that update returns an error, or fn panics; the panic continues
// after the rollback. A Do inside fn joins the open transaction. Do returns UNAVAILABLE wrapping
// the cause when no connection is free within the acquire timeout, when the transaction cannot
// begin, or when COMMIT could not be sent; when ctx ends first, ctx's error. A COMMIT that fails after it
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

	t := &txn{tx: tx}
	err = fn(context.WithValue(ctx, txKey{}, t))
	panicked = false
	if err != nil {
		return err
	}
	if err = t.finish(ctx); err != nil {
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

// Savepoint implements app.Savepoints: it runs fn under a savepoint of the transaction Do opened.
// When fn returns an error, it rolls back to the savepoint, restores the locks and events the
// transaction had recorded there (the rollback released the later row locks and discarded the
// later events), and returns fn's error; when that rollback fails, fn's error joined with one
// matching app.ErrSavepointRollback. Otherwise it releases the savepoint. Outside a
// transaction it returns ErrNoTransaction without calling fn.
func (u *UnitOfWork) Savepoint(ctx context.Context, fn func(ctx context.Context) error) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("savepoint: %w", ErrNoTransaction)
	}
	t.savepoints++
	name := fmt.Sprintf("auth1_sp_%d", t.savepoints)
	before := t.records()
	if _, err := t.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("savepoint: %w", err)
	}
	if err := fn(ctx); err != nil {
		if _, rerr := t.tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rerr != nil {
			return errors.Join(err, fmt.Errorf("roll back to savepoint: %w: %w", app.ErrSavepointRollback, rerr))
		}
		t.restore(before)
		return err
	}
	if _, err := t.tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name); err != nil {
		return fmt.Errorf("release savepoint: %w", err)
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
	if t := txFrom(ctx); t != nil {
		return t.tx
	}
	return db
}

// txFrom returns the transaction UnitOfWork.Do opened, or nil when ctx carries none.
func txFrom(ctx context.Context) *txn {
	t, _ := ctx.Value(txKey{}).(*txn)
	return t
}

// inTx reports whether ctx carries the transaction UnitOfWork.Do opened.
func inTx(ctx context.Context) bool {
	return txFrom(ctx) != nil
}
