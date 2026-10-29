package app

import (
	"context"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// Accounts is the repository of the account aggregate: the account row with its identifiers,
// password, roles, TOTP factor and recovery codes (TDD-01 §4, §6). Records hold plaintext; the
// repository encrypts and decrypts through FieldCrypto and computes blind indexes itself.
// Identifier values are normalised by the caller. Times the repository stores are the database's
// now(), the start of the transaction. Errors are NOT_FOUND only where a method says so, and no
// error text holds an identifier value, a hash or a secret.
//
// A use case that changes an account first locks it with GetForUpdate and ends with BumpVersion
// (I-10, TDD-01 §4.2); the account row is the first lock it takes (G-5).
type Accounts interface {
	// Create stores a pending account at version 1 with its identifiers, password and roles. It
	// runs inside UnitOfWork.Do. A verified identifier whose value another account holds verified
	// is IDENTIFIER_TAKEN.
	Create(ctx context.Context, a account.NewAccount) error
	// Get returns the account; NOT_FOUND when there is none.
	Get(ctx context.Context, id uuid.UUID) (account.Account, error)
	// GetForUpdate is Get, locking the row until the transaction ends. It runs inside
	// UnitOfWork.Do.
	GetForUpdate(ctx context.Context, id uuid.UUID) (account.Account, error)
	// BumpVersion adds n (≥ 1) to the account's version, sets updated_at, and returns the new
	// version; NOT_FOUND when there is no account.
	BumpVersion(ctx context.Context, id uuid.UUID, n int64) (int64, error)
}
