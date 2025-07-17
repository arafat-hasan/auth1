package main

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(addUserIndexesUp, addUserIndexesDown)
}

// Migration: 20240101000002_add_user_indexes
func addUserIndexesUp(ctx context.Context, db *bun.DB) error {
	queries := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)`,
		`CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_verified ON users(is_verified)`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_2fa_enabled ON users(is_2fa_enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at)`,
	}

	for _, query := range queries {
		_, err := db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

func addUserIndexesDown(ctx context.Context, db *bun.DB) error {
	queries := []string{
		`DROP INDEX IF EXISTS idx_users_email`,
		`DROP INDEX IF EXISTS idx_users_phone`,
		`DROP INDEX IF EXISTS idx_users_created_at`,
		`DROP INDEX IF EXISTS idx_users_is_verified`,
		`DROP INDEX IF EXISTS idx_users_is_2fa_enabled`,
		`DROP INDEX IF EXISTS idx_users_last_login_at`,
	}

	for _, query := range queries {
		_, err := db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to drop index: %w", err)
		}
	}

	return nil
}
