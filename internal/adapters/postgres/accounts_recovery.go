package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// ReplaceRecoveryCodes implements app.Accounts.
func (r *Accounts) ReplaceRecoveryCodes(ctx context.Context, accountID, batch uuid.UUID, codes []account.RecoveryCode) error {
	if !inTx(ctx) {
		return fmt.Errorf("replace recovery codes: %w", ErrNoTransaction)
	}
	if err := r.DeleteRecoveryCodes(ctx, accountID); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	if len(codes) == 0 {
		return nil
	}
	q := "INSERT INTO recovery_codes (id, account_id, code_mac, batch, created_at) VALUES "
	args := make([]any, 0, 4*len(codes))
	for i, c := range codes {
		if i > 0 {
			q += ", "
		}
		q += "(?, ?, ?, ?, now())"
		args = append(args, c.ID, accountID, c.MAC, batch)
	}
	if _, err := Conn(ctx, r.db).ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	return nil
}

// UseRecoveryCode implements app.Accounts with the conditional update of TDD-03 §3.2 (I-18).
func (r *Accounts) UseRecoveryCode(ctx context.Context, accountID uuid.UUID, mac []byte) (bool, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx,
		"UPDATE recovery_codes SET used_at = now() WHERE account_id = ? AND code_mac = ? AND used_at IS NULL",
		accountID, mac)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return changed(res, "use recovery code")
}

// UnusedRecoveryCodes implements app.Accounts.
func (r *Accounts) UnusedRecoveryCodes(ctx context.Context, accountID uuid.UUID) (int, error) {
	var n int
	if err := Conn(ctx, r.db).QueryRowContext(ctx,
		"SELECT count(*) FROM recovery_codes WHERE account_id = ? AND used_at IS NULL", accountID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}

// DeleteRecoveryCodes implements app.Accounts.
func (r *Accounts) DeleteRecoveryCodes(ctx context.Context, accountID uuid.UUID) error {
	if _, err := Conn(ctx, r.db).ExecContext(ctx, "DELETE FROM recovery_codes WHERE account_id = ?", accountID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	return nil
}
