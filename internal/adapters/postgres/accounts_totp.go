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

// totpPlace is where an account's TOTP secret is stored: totp_factors is keyed by account id.
func totpPlace(accountID uuid.UUID) app.Place {
	return app.NewPlace(tableTOTP, "secret", accountID)
}

// TOTPFactor implements app.Accounts.
func (r *Accounts) TOTPFactor(ctx context.Context, accountID uuid.UUID) (account.TOTPFactor, error) {
	var (
		f         account.TOTPFactor
		secret    []byte
		confirmed sql.NullTime
		last      sql.NullInt64
	)
	err := Conn(ctx, r.db).QueryRowContext(ctx,
		"SELECT secret, confirmed_at, last_step, created_at FROM totp_factors WHERE account_id = ?", accountID).
		Scan(&secret, &confirmed, &last, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return account.TOTPFactor{}, notFound("TOTP factor")
	}
	if err != nil {
		return account.TOTPFactor{}, fmt.Errorf("read TOTP factor: %w", err)
	}
	if f.Secret, err = r.fc.Open(totpPlace(accountID), secret); err != nil {
		return account.TOTPFactor{}, fmt.Errorf("read TOTP factor: secret: %w", err)
	}
	f.ConfirmedAt, f.CreatedAt = timePtr(confirmed), f.CreatedAt.UTC()
	if last.Valid {
		f.LastStep = &last.Int64
	}
	return f, nil
}

// StartTOTP implements app.Accounts.
func (r *Accounts) StartTOTP(ctx context.Context, accountID uuid.UUID, secret []byte) (bool, error) {
	sealed, err := r.fc.Seal(totpPlace(accountID), secret)
	if err != nil {
		return false, fmt.Errorf("start TOTP enrolment: %w", err)
	}
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		INSERT INTO totp_factors (account_id, secret, created_at) VALUES (?, ?, now())
		ON CONFLICT (account_id) DO UPDATE SET secret = excluded.secret, last_step = NULL, created_at = now()
		WHERE totp_factors.confirmed_at IS NULL`, accountID, sealed)
	if err != nil {
		return false, fmt.Errorf("start TOTP enrolment: %w", err)
	}
	return changed(res, "start TOTP enrolment")
}

// ConfirmTOTP implements app.Accounts.
func (r *Accounts) ConfirmTOTP(ctx context.Context, accountID uuid.UUID, step int64) (bool, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		UPDATE totp_factors SET confirmed_at = now(), last_step = ?
		WHERE account_id = ? AND confirmed_at IS NULL AND (last_step IS NULL OR last_step < ?)`,
		step, accountID, step)
	if err != nil {
		return false, fmt.Errorf("confirm TOTP factor: %w", err)
	}
	return changed(res, "confirm TOTP factor")
}

// AcceptTOTPStep implements app.Accounts with the conditional update of TDD-03 §3.1 (I-19).
func (r *Accounts) AcceptTOTPStep(ctx context.Context, accountID uuid.UUID, step int64) (bool, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		UPDATE totp_factors SET last_step = ?
		WHERE account_id = ? AND confirmed_at IS NOT NULL AND (last_step IS NULL OR last_step < ?)`,
		step, accountID, step)
	if err != nil {
		return false, fmt.Errorf("accept TOTP step: %w", err)
	}
	return changed(res, "accept TOTP step")
}

// ReplaceTOTP implements app.Accounts.
func (r *Accounts) ReplaceTOTP(ctx context.Context, accountID uuid.UUID, secret []byte, step int64) (bool, error) {
	sealed, err := r.fc.Seal(totpPlace(accountID), secret)
	if err != nil {
		return false, fmt.Errorf("replace TOTP factor: %w", err)
	}
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		UPDATE totp_factors SET secret = ?, confirmed_at = now(), last_step = ?
		WHERE account_id = ? AND confirmed_at IS NOT NULL AND (last_step IS NULL OR last_step < ?)`,
		sealed, step, accountID, step)
	if err != nil {
		return false, fmt.Errorf("replace TOTP factor: %w", err)
	}
	return changed(res, "replace TOTP factor")
}

// DeleteTOTP implements app.Accounts.
func (r *Accounts) DeleteTOTP(ctx context.Context, accountID uuid.UUID) error {
	if _, err := Conn(ctx, r.db).ExecContext(ctx, "DELETE FROM totp_factors WHERE account_id = ?", accountID); err != nil {
		return fmt.Errorf("delete TOTP factor: %w", err)
	}
	return nil
}

// changed reports whether the conditional statement res changed a row.
func changed(res sql.Result, op string) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return n > 0, nil
}
