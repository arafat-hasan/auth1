package main

import (
	"context"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(resetPlaintextTOTPSecretsUp, resetPlaintextTOTPSecretsDown)
}

// Migration: 20240101000006_reset_plaintext_totp_secrets
// TOTP secrets are now stored encrypted at the application layer.
// Any existing plaintext secrets are incompatible with the new encryption scheme,
// so affected users must re-setup 2FA after this migration.
func resetPlaintextTOTPSecretsUp(ctx context.Context, db *bun.DB) error {
	_, err := db.ExecContext(ctx, `
		UPDATE users
		SET is_2fa_enabled = FALSE,
		    totp_secret = NULL
		WHERE is_2fa_enabled = TRUE
	`)
	return err
}

func resetPlaintextTOTPSecretsDown(ctx context.Context, db *bun.DB) error {
	// Intentionally a no-op: we cannot recover plaintext secrets.
	return nil
}
