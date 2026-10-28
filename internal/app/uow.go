package app

import "context"

// UnitOfWork runs a use case in one database transaction (SDD §6.3, TDD-01 §6). Do commits once
// when fn returns nil and rolls back when it returns an error or panics; the panic continues. A Do
// inside fn joins the open transaction. fn makes no network call and hashes no password (G-4).
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context) error) error
}
