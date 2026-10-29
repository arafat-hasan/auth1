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

	// Identifiers returns the account's current identifiers, decrypted, sorted by type: at most
	// one per type (I-2).
	Identifiers(ctx context.Context, accountID uuid.UUID) ([]account.Identifier, error)
	// FindVerified returns the verified, current identifier of type idType with value; NOT_FOUND
	// when no account holds it verified (I-1). It decrypts nothing: Value is the value given.
	FindVerified(ctx context.Context, idType, value string) (account.Identifier, error)
	// FindCurrent returns every current identifier of type idType with value, verified or not,
	// sorted by id: unverified ones may belong to several pending accounts. It decrypts nothing:
	// Value is the value given.
	FindCurrent(ctx context.Context, idType, value string) ([]account.Identifier, error)
	// AddIdentifier stores id as a current identifier of the account, verified now when
	// id.Verified. A verified value another account holds verified is IDENTIFIER_TAKEN. A second
	// current identifier of one type (I-2) is a caller's bug: retire the old one first.
	AddIdentifier(ctx context.Context, accountID uuid.UUID, id account.NewIdentifier) error
	// VerifyIdentifier marks the current, unverified identifier id verified now; NOT_FOUND when
	// there is no such identifier, and IDENTIFIER_TAKEN when another account holds its value
	// verified (I-1, T-1).
	VerifyIdentifier(ctx context.Context, id uuid.UUID) error
	// RetireIdentifier retires the current identifier id now, releasing its value; NOT_FOUND
	// when there is no current identifier id.
	RetireIdentifier(ctx context.Context, id uuid.UUID) error
	// RetireIdentifiers retires every current identifier of the account.
	RetireIdentifiers(ctx context.Context, accountID uuid.UUID) error

	// Roles returns the account's roles, sorted by name.
	Roles(ctx context.Context, accountID uuid.UUID) ([]account.Role, error)
	// SetRoles makes roles the account's set: roles not in it are removed, new ones are granted
	// now by grantedBy (empty when not recorded), and roles kept keep their grant.
	SetRoles(ctx context.Context, accountID uuid.UUID, roles []string, grantedBy string) error

	// PasswordCredential returns the account's password; NOT_FOUND when it has none.
	PasswordCredential(ctx context.Context, accountID uuid.UUID) (account.PasswordCredential, error)
	// SetPassword stores or replaces the account's password, changed now. pepperKID is opaque.
	SetPassword(ctx context.Context, accountID uuid.UUID, hash, pepperKID string) error
	// Activate moves a pending account that has a password to active (registration and
	// invitation completion). Any other account is an error: activation never breaks I-17.
	Activate(ctx context.Context, accountID uuid.UUID) error
}
