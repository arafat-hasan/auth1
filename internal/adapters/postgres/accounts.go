package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// ErrNoTransaction is returned, without querying, by a method that must run inside
// UnitOfWork.Do when ctx carries no transaction: a row lock or a multi-row write would end with
// its own statement.
var ErrNoTransaction = errors.New("postgres: no transaction open")

// The places of the account aggregate's encrypted columns (TDD-01 §3.1).
const (
	tableAccounts    = "accounts"
	tableIdentifiers = "identifiers"
	tableTOTP        = "totp_factors"
)

// Accounts implements app.Accounts on accounts, identifiers, password_credentials,
// account_roles, totp_factors and recovery_codes (TDD-01 §4, §6).
type Accounts struct {
	db   *bun.DB
	fc   app.FieldCrypto
	bidx app.BlindIndex
}

// NewAccounts returns the repository on db, encrypting through fc and indexing identifiers with
// bidx.
func NewAccounts(db *bun.DB, fc app.FieldCrypto, bidx app.BlindIndex) *Accounts {
	return &Accounts{db: db, fc: fc, bidx: bidx}
}

// inTx reports whether ctx carries the transaction UnitOfWork.Do opened.
func inTx(ctx context.Context) bool {
	_, ok := ctx.Value(txKey{}).(bun.Tx)
	return ok
}

// notFound is the NOT_FOUND failure for what.
func notFound(what string) error {
	return &domain.Error{Code: domain.CodeNotFound, Detail: "the " + what + " was not found"}
}

// Create implements app.Accounts.
func (r *Accounts) Create(ctx context.Context, a account.NewAccount) error {
	if !inTx(ctx) {
		return fmt.Errorf("create account: %w", ErrNoTransaction)
	}
	name, err := r.fc.Seal(app.NewPlace(tableAccounts, "display_name", a.ID), []byte(a.DisplayName))
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	db := Conn(ctx, r.db)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO accounts (id, status, status_changed_at, display_name, locale, registered_via, created_at, updated_at)
		VALUES (?, 'pending', now(), ?, ?, ?, now(), now())`,
		a.ID, name, a.Locale, a.RegisteredVia); err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	for _, id := range a.Identifiers {
		if err := r.insertIdentifier(ctx, a.ID, id); err != nil {
			return fmt.Errorf("create account: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO password_credentials (account_id, hash, pepper_kid, changed_at) VALUES (?, ?, ?, now())",
		a.ID, a.Password.Hash, a.Password.PepperKID); err != nil {
		return fmt.Errorf("create account: store password: %w", err)
	}
	for _, role := range a.Roles {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO account_roles (account_id, role, granted_at, granted_by) VALUES (?, ?, now(), nullif(?, ''))",
			a.ID, role, a.GrantedBy); err != nil {
			return fmt.Errorf("create account: grant role: %w", err)
		}
	}
	return nil
}

// insertIdentifier stores id for accountID, encrypted and indexed; verified now when id.Verified.
func (r *Accounts) insertIdentifier(ctx context.Context, accountID uuid.UUID, id account.NewIdentifier) error {
	value, err := r.fc.Seal(app.NewPlace(tableIdentifiers, "value", id.ID), []byte(id.Value))
	if err != nil {
		return fmt.Errorf("store identifier: %w", err)
	}
	bidx, err := r.bidx.Compute(id.Type, []byte(id.Value))
	if err != nil {
		return fmt.Errorf("store identifier: %w", err)
	}
	if _, err := Conn(ctx, r.db).ExecContext(ctx, `
		INSERT INTO identifiers (id, account_id, type, value, value_bidx, verified_at, created_at)
		VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN now() END, now())`,
		id.ID, accountID, id.Type, value, bidx, id.Verified); err != nil {
		return fmt.Errorf("store identifier: %w", err)
	}
	return nil
}

// accountColumns are the columns scanAccount reads, in its order.
const accountColumns = `id, status, coalesce(status_reason, ''), status_until, status_changed_at, display_name,
	locale, registered_via, factor_failures, factor_failures_since, version, created_at, updated_at`

// Get implements app.Accounts.
func (r *Accounts) Get(ctx context.Context, id uuid.UUID) (account.Account, error) {
	return r.get(ctx, id, "")
}

// GetForUpdate implements app.Accounts.
func (r *Accounts) GetForUpdate(ctx context.Context, id uuid.UUID) (account.Account, error) {
	if !inTx(ctx) {
		return account.Account{}, fmt.Errorf("lock account: %w", ErrNoTransaction)
	}
	return r.get(ctx, id, " FOR UPDATE")
}

// get reads one account, with lock appended to the query.
func (r *Accounts) get(ctx context.Context, id uuid.UUID, lock string) (account.Account, error) {
	var (
		a                   account.Account
		status              string
		name                []byte
		until, failuresFrom sql.NullTime
	)
	err := Conn(ctx, r.db).QueryRowContext(ctx, "SELECT "+accountColumns+" FROM accounts WHERE id = ?"+lock, id).Scan(
		&a.ID, &status, &a.StatusReason, &until, &a.StatusChangedAt, &name,
		&a.Locale, &a.RegisteredVia, &a.FactorFailures, &failuresFrom, &a.Version, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return account.Account{}, notFound("account")
	}
	if err != nil {
		return account.Account{}, fmt.Errorf("read account: %w", err)
	}
	plain, err := r.fc.Open(app.NewPlace(tableAccounts, "display_name", a.ID), name)
	if err != nil {
		return account.Account{}, fmt.Errorf("read account: display name: %w", err)
	}
	a.Status, a.DisplayName = account.Status(status), string(plain)
	a.StatusUntil, a.FactorFailuresSince = timePtr(until), timePtr(failuresFrom)
	a.StatusChangedAt, a.CreatedAt, a.UpdatedAt = a.StatusChangedAt.UTC(), a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	return a, nil
}

// BumpVersion implements app.Accounts.
func (r *Accounts) BumpVersion(ctx context.Context, id uuid.UUID, n int64) (int64, error) {
	if n < 1 {
		return 0, fmt.Errorf("bump account version: increment %d is not positive", n)
	}
	var v int64
	err := Conn(ctx, r.db).QueryRowContext(ctx,
		"UPDATE accounts SET version = version + ?, updated_at = now() WHERE id = ? RETURNING version", n, id).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, notFound("account")
	}
	if err != nil {
		return 0, fmt.Errorf("bump account version: %w", err)
	}
	return v, nil
}

// timePtr is t's time, or nil when it is null. Times are UTC, as the domain keeps them.
func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}
