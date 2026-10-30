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
// A use case that changes an account first locks it with GetForUpdate (I-10, TDD-01 §4.2); the
// account row is the first lock it takes (G-5). The lock is the change's mark: when the
// transaction commits, UnitOfWork moves the version past the events written about the account,
// by one when there were none (TDD-06 §2).
type Accounts interface {
	// Create stores a pending account at version 1 with its identifiers, password and roles. It
	// runs inside UnitOfWork.Do. A verified identifier whose value another account holds verified
	// is IDENTIFIER_TAKEN.
	Create(ctx context.Context, a account.NewAccount) error
	// Get returns the account; NOT_FOUND when there is none.
	Get(ctx context.Context, id uuid.UUID) (account.Account, error)
	// GetForUpdate is Get, locking the row until the transaction ends, and marking the account
	// changed: its version moves when the transaction commits. It runs inside UnitOfWork.Do.
	GetForUpdate(ctx context.Context, id uuid.UUID) (account.Account, error)
	// ApplyStatus stores the status change d decided by account.Transition; NOT_FOUND when there
	// is no account. An unchanged d writes nothing. Of d's effects it applies those inside the
	// aggregate, EraseCredentials and ReleaseIdentifiers; the caller applies RevokeSessions and
	// CancelFlows through their repositories. A change runs inside UnitOfWork.Do, under the lock
	// GetForUpdate took to read the status it was decided from.
	ApplyStatus(ctx context.Context, id uuid.UUID, d account.Decision) error

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
	// verified (I-1, T-1). After IDENTIFIER_TAKEN, here or from AddIdentifier, the transaction
	// stays usable, so the use case can still consume the challenge (TDD-02 §3).
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

	// TOTPFactor returns the account's TOTP factor with its secret decrypted; NOT_FOUND when it
	// has none.
	TOTPFactor(ctx context.Context, accountID uuid.UUID) (account.TOTPFactor, error)
	// StartTOTP stores secret as the account's unconfirmed factor, replacing an unconfirmed one
	// (TDD-03 §4). It reports false, changing nothing, when the account has a confirmed factor.
	StartTOTP(ctx context.Context, accountID uuid.UUID, secret []byte) (bool, error)
	// ConfirmTOTP confirms the unconfirmed factor, now, with step accepted (TDD-03 §4). It
	// reports false when there is no unconfirmed factor or step is not after its last step.
	ConfirmTOTP(ctx context.Context, accountID uuid.UUID, step int64) (bool, error)
	// AcceptTOTPStep records step as accepted on the confirmed factor (TDD-03 §3.1). It reports
	// false when there is no confirmed factor or step is not after the last accepted one: the
	// code was used already (I-19), and the caller treats it as wrong.
	AcceptTOTPStep(ctx context.Context, accountID uuid.UUID, step int64) (bool, error)
	// ReplaceTOTP replaces the confirmed factor's secret, confirmed now with step accepted
	// (TDD-03 §5.2). It reports false when there is no confirmed factor or step is not after the
	// last accepted one, so no step is accepted twice across the replacement (I-19).
	ReplaceTOTP(ctx context.Context, accountID uuid.UUID, secret []byte, step int64) (bool, error)
	// DeleteTOTP deletes the account's factor, if any.
	DeleteTOTP(ctx context.Context, accountID uuid.UUID) error

	// ReplaceRecoveryCodes deletes every recovery code of the account, used or not, and stores
	// codes as the new batch (TDD-03 §5.3). It runs inside UnitOfWork.Do.
	ReplaceRecoveryCodes(ctx context.Context, accountID, batch uuid.UUID, codes []account.RecoveryCode) error
	// UseRecoveryCode marks the account's unused code with mac used, now (TDD-03 §3.2). It reports
	// false when the account has no unused code with mac: a code is accepted at most once (I-18).
	UseRecoveryCode(ctx context.Context, accountID uuid.UUID, mac []byte) (bool, error)
	// UnusedRecoveryCodes returns how many unused recovery codes the account has.
	UnusedRecoveryCodes(ctx context.Context, accountID uuid.UUID) (int, error)
	// DeleteRecoveryCodes deletes every recovery code of the account.
	DeleteRecoveryCodes(ctx context.Context, accountID uuid.UUID) error
}
