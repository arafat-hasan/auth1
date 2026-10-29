package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// identifierColumns are the columns scanIdentifier reads, in its order, without value.
const identifierColumns = "id, account_id, type, verified_at, retired_at, created_at"

// scanIdentifier reads identifierColumns from row.
func scanIdentifier(row interface{ Scan(...any) error }, dest *account.Identifier, extra ...any) error {
	var verified, retired sql.NullTime
	if err := row.Scan(append([]any{&dest.ID, &dest.AccountID, &dest.Type, &verified, &retired, &dest.CreatedAt}, extra...)...); err != nil {
		return err
	}
	dest.VerifiedAt, dest.RetiredAt, dest.CreatedAt = timePtr(verified), timePtr(retired), dest.CreatedAt.UTC()
	return nil
}

// Identifiers implements app.Accounts.
func (r *Accounts) Identifiers(ctx context.Context, accountID uuid.UUID) ([]account.Identifier, error) {
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+identifierColumns+", value FROM identifiers"+
		" WHERE account_id = ? AND retired_at IS NULL ORDER BY type", accountID)
	if err != nil {
		return nil, fmt.Errorf("read identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []account.Identifier
	for rows.Next() {
		var (
			id    account.Identifier
			value []byte
		)
		if err := scanIdentifier(rows, &id, &value); err != nil {
			return nil, fmt.Errorf("read identifiers: %w", err)
		}
		plain, err := r.fc.Open(app.NewPlace(tableIdentifiers, "value", id.ID), value)
		if err != nil {
			return nil, fmt.Errorf("read identifiers: value: %w", err)
		}
		id.Value = string(plain)
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read identifiers: %w", err)
	}
	return out, nil
}

// FindVerified implements app.Accounts.
func (r *Accounts) FindVerified(ctx context.Context, idType, value string) (account.Identifier, error) {
	bidx, err := r.bidx.Compute(idType, []byte(value))
	if err != nil {
		return account.Identifier{}, fmt.Errorf("find identifier: %w", err)
	}
	var id account.Identifier
	err = scanIdentifier(Conn(ctx, r.db).QueryRowContext(ctx, "SELECT "+identifierColumns+" FROM identifiers"+
		" WHERE type = ? AND value_bidx = ? AND verified_at IS NOT NULL AND retired_at IS NULL", idType, bidx), &id)
	if errors.Is(err, sql.ErrNoRows) {
		return account.Identifier{}, notFound("identifier")
	}
	if err != nil {
		return account.Identifier{}, fmt.Errorf("find identifier: %w", err)
	}
	id.Value = value
	return id, nil
}

// FindCurrent implements app.Accounts.
func (r *Accounts) FindCurrent(ctx context.Context, idType, value string) ([]account.Identifier, error) {
	bidx, err := r.bidx.Compute(idType, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("find identifiers: %w", err)
	}
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+identifierColumns+" FROM identifiers"+
		" WHERE type = ? AND value_bidx = ? AND retired_at IS NULL ORDER BY id", idType, bidx)
	if err != nil {
		return nil, fmt.Errorf("find identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []account.Identifier
	for rows.Next() {
		var id account.Identifier
		if err := scanIdentifier(rows, &id); err != nil {
			return nil, fmt.Errorf("find identifiers: %w", err)
		}
		id.Value = value
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find identifiers: %w", err)
	}
	return out, nil
}

// AddIdentifier implements app.Accounts.
func (r *Accounts) AddIdentifier(ctx context.Context, accountID uuid.UUID, id account.NewIdentifier) error {
	return r.insertIdentifier(ctx, accountID, id)
}

// VerifyIdentifier implements app.Accounts.
func (r *Accounts) VerifyIdentifier(ctx context.Context, id uuid.UUID) error {
	db := Conn(ctx, r.db)
	res, err := withSavepoint(ctx, db, func() (sql.Result, error) {
		return db.ExecContext(ctx, `
			UPDATE identifiers SET verified_at = now()
			WHERE id = ? AND verified_at IS NULL AND retired_at IS NULL`, id)
	})
	if err != nil {
		return constraintError("verify identifier", err)
	}
	return oneRow(res, "verify identifier", "identifier")
}

// RetireIdentifier implements app.Accounts.
func (r *Accounts) RetireIdentifier(ctx context.Context, id uuid.UUID) error {
	res, err := Conn(ctx, r.db).ExecContext(ctx,
		"UPDATE identifiers SET retired_at = now() WHERE id = ? AND retired_at IS NULL", id)
	if err != nil {
		return fmt.Errorf("retire identifier: %w", err)
	}
	return oneRow(res, "retire identifier", "identifier")
}

// RetireIdentifiers implements app.Accounts.
func (r *Accounts) RetireIdentifiers(ctx context.Context, accountID uuid.UUID) error {
	if _, err := Conn(ctx, r.db).ExecContext(ctx,
		"UPDATE identifiers SET retired_at = now() WHERE account_id = ? AND retired_at IS NULL", accountID); err != nil {
		return fmt.Errorf("retire identifiers: %w", err)
	}
	return nil
}

// oneRow checks that the conditional update res changed a row: none is NOT_FOUND for what.
func oneRow(res sql.Result, op, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n == 0 {
		return notFound(what)
	}
	return nil
}
