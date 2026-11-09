package app

import (
	"context"
	"errors"
)

// UnitOfWork runs a use case in one database transaction (SDD §6.3, TDD-01 §6). Do commits once
// when fn returns nil and rolls back when it returns an error or panics; the panic continues. A Do
// inside fn joins the open transaction. fn makes no network call and hashes no password (G-4).
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context) error) error
}

// Savepoints runs part of a use case under a savepoint of the open transaction (TDD-05 §4): when
// fn returns an error, its writes, and the locks and events recorded since the savepoint, are
// discarded, and the transaction goes on. Savepoint returns fn's error, or an error outside a
// transaction.
type Savepoints interface {
	Savepoint(ctx context.Context, fn func(ctx context.Context) error) error
}

// ErrSavepointRollback is matched by the error of a Savepoint whose fn failed and that then could
// not roll back: the transaction is unusable, and the fn's error is not its outcome.
var ErrSavepointRollback = errors.New("savepoint not rolled back")
