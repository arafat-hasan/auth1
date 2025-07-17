package main

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(initUsersTableUp, initUsersTableDown)
}

// Migration: 20240101000001_init_users_table
func initUsersTableUp(ctx context.Context, db *bun.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			phone TEXT UNIQUE,
			password_hash TEXT,
			is_verified BOOLEAN NOT NULL DEFAULT FALSE,
			is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			totp_secret TEXT,
			last_login_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create updated_at trigger function
	_, err = db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql'
	`)
	if err != nil {
		return fmt.Errorf("failed to create updated_at trigger function: %w", err)
	}

	// Create trigger for users table
	_, err = db.ExecContext(ctx, `
		CREATE TRIGGER update_users_updated_at 
		BEFORE UPDATE ON users
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
	`)
	if err != nil {
		return fmt.Errorf("failed to create users updated_at trigger: %w", err)
	}

	return nil
}

func initUsersTableDown(ctx context.Context, db *bun.DB) error {
	// Drop trigger first
	_, err := db.ExecContext(ctx, `DROP TRIGGER IF EXISTS update_users_updated_at ON users`)
	if err != nil {
		return fmt.Errorf("failed to drop users updated_at trigger: %w", err)
	}

	// Drop function
	_, err = db.ExecContext(ctx, `DROP FUNCTION IF EXISTS update_updated_at_column()`)
	if err != nil {
		return fmt.Errorf("failed to drop updated_at trigger function: %w", err)
	}

	// Drop table
	_, err = db.ExecContext(ctx, `DROP TABLE IF EXISTS users`)
	if err != nil {
		return fmt.Errorf("failed to drop users table: %w", err)
	}

	return nil
}
