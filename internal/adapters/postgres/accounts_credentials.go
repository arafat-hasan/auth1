package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// errNotActivated is Activate's error for an account that is not pending, or has no password.
var errNotActivated = errors.New("account not activated: it is not pending or has no password")

// Roles implements app.Accounts.
func (r *Accounts) Roles(ctx context.Context, accountID uuid.UUID) ([]account.Role, error) {
	rows, err := Conn(ctx, r.db).QueryContext(ctx, `
		SELECT role, granted_at, coalesce(granted_by, '') FROM account_roles
		WHERE account_id = ? ORDER BY role`, accountID)
	if err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []account.Role
	for rows.Next() {
		var role account.Role
		if err := rows.Scan(&role.Name, &role.GrantedAt, &role.GrantedBy); err != nil {
			return nil, fmt.Errorf("read roles: %w", err)
		}
		role.GrantedAt = role.GrantedAt.UTC()
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	return out, nil
}

// SetRoles implements app.Accounts, in one statement: both parts see the same snapshot, so a
// role kept is neither deleted nor granted again.
func (r *Accounts) SetRoles(ctx context.Context, accountID uuid.UUID, roles []string, grantedBy string) error {
	if roles == nil {
		roles = []string{}
	}
	_, err := Conn(ctx, r.db).ExecContext(ctx, `
		WITH removed AS (
			DELETE FROM account_roles WHERE account_id = ? AND NOT (role = ANY (?::text[]))
		)
		INSERT INTO account_roles (account_id, role, granted_at, granted_by)
		SELECT ?, role, now(), nullif(?, '') FROM unnest(?::text[]) AS role
		ON CONFLICT (account_id, role) DO NOTHING`,
		accountID, pgdialect.Array(roles), accountID, grantedBy, pgdialect.Array(roles))
	if err != nil {
		return fmt.Errorf("set roles: %w", err)
	}
	return nil
}

// PasswordCredential implements app.Accounts.
func (r *Accounts) PasswordCredential(ctx context.Context, accountID uuid.UUID) (account.PasswordCredential, error) {
	var p account.PasswordCredential
	err := Conn(ctx, r.db).QueryRowContext(ctx,
		"SELECT hash, pepper_kid, changed_at FROM password_credentials WHERE account_id = ?", accountID).
		Scan(&p.Hash, &p.PepperKID, &p.ChangedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return account.PasswordCredential{}, notFound("password")
	}
	if err != nil {
		return account.PasswordCredential{}, fmt.Errorf("read password: %w", err)
	}
	p.ChangedAt = p.ChangedAt.UTC()
	return p, nil
}

// SetPassword implements app.Accounts.
func (r *Accounts) SetPassword(ctx context.Context, accountID uuid.UUID, hash, pepperKID string) error {
	if _, err := Conn(ctx, r.db).ExecContext(ctx, `
		INSERT INTO password_credentials (account_id, hash, pepper_kid, changed_at) VALUES (?, ?, ?, now())
		ON CONFLICT (account_id) DO UPDATE SET hash = excluded.hash, pepper_kid = excluded.pepper_kid, changed_at = now()`,
		accountID, hash, pepperKID); err != nil {
		return fmt.Errorf("store password: %w", err)
	}
	return nil
}

// RehashPassword implements app.Accounts.
func (r *Accounts) RehashPassword(ctx context.Context, accountID uuid.UUID, oldHash, hash, pepperKID string) (bool, error) {
	t := txFrom(ctx)
	if t == nil {
		return false, fmt.Errorf("rehash password: %w", ErrNoTransaction)
	}
	if t.account(accountID) == nil {
		return false, fmt.Errorf("rehash password: %w", ErrLockOrder)
	}
	res, err := t.tx.ExecContext(ctx,
		"UPDATE password_credentials SET hash = ?, pepper_kid = ? WHERE account_id = ? AND hash = ?",
		hash, pepperKID, accountID, oldHash)
	if err != nil {
		return false, fmt.Errorf("rehash password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rehash password: %w", err)
	}
	return n == 1, nil
}

// Activate implements app.Accounts. The password check is in the statement, so it holds against
// a concurrent erasure too.
func (r *Accounts) Activate(ctx context.Context, accountID uuid.UUID) error {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		UPDATE accounts SET status = 'active', status_changed_at = now()
		WHERE id = ? AND status = 'pending'
		  AND EXISTS (SELECT 1 FROM password_credentials WHERE account_id = accounts.id)`, accountID)
	if err != nil {
		return fmt.Errorf("activate account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("activate account: %w", err)
	}
	if n == 0 {
		return errNotActivated
	}
	return nil
}

// FailFactor implements app.Accounts with TDD-07 §3's statement, the window configured.
func (r *Accounts) FailFactor(ctx context.Context, accountID uuid.UUID, window time.Duration) (int, error) {
	t := txFrom(ctx)
	if t == nil {
		return 0, fmt.Errorf("count factor failure: %w", ErrNoTransaction)
	}
	if t.account(accountID) == nil {
		return 0, fmt.Errorf("count factor failure: %w", ErrLockOrder)
	}
	var n int
	err := t.tx.QueryRowContext(ctx, `
		UPDATE accounts
		SET factor_failures = CASE WHEN factor_failures_since IS NULL OR factor_failures_since <= now() - make_interval(secs => ?)
		                           THEN 1 ELSE factor_failures + 1 END,
		    factor_failures_since = CASE WHEN factor_failures_since IS NULL OR factor_failures_since <= now() - make_interval(secs => ?)
		                           THEN now() ELSE factor_failures_since END
		WHERE id = ?
		RETURNING factor_failures`, window.Seconds(), window.Seconds(), accountID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count factor failure: %w", err)
	}
	return n, nil
}
