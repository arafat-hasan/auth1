package main

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(addEmailOutboxUp, addEmailOutboxDown)
}

func addEmailOutboxUp(ctx context.Context, db *bun.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS email_outbox (
			id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			idempotency_key  TEXT        UNIQUE,
			event_type       TEXT        NOT NULL,
			payload          JSONB       NOT NULL,
			status           TEXT        NOT NULL DEFAULT 'pending',
			attempts         INT         NOT NULL DEFAULT 0,
			last_error       TEXT,
			created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			published_at     TIMESTAMPTZ
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create email_outbox table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_email_outbox_pending
			ON email_outbox (status, created_at)
			WHERE status = 'pending'
	`)
	if err != nil {
		return fmt.Errorf("failed to create email_outbox index: %w", err)
	}

	return nil
}

func addEmailOutboxDown(ctx context.Context, db *bun.DB) error {
	_, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS email_outbox`)
	if err != nil {
		return fmt.Errorf("failed to drop email_outbox table: %w", err)
	}
	return nil
}
