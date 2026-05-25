package main

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(enhanceUsersTableUp, enhanceUsersTableDown)
}

// Migration: 20240101000004_enhance_users_table
// Add additional fields for platform-agnostic use
func enhanceUsersTableUp(ctx context.Context, db *bun.DB) error {
	// Add new columns to users table
	_, err := db.ExecContext(ctx, `
		-- Add account status and security fields
		ALTER TABLE users
		ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
		ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP,
		ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP,
		ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMP,
		
		-- Add role and metadata fields for platform-agnostic use
		ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user',
		ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}',
		
		-- Add password management fields
		ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP,
		ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE,

		-- Add tracking fields
		ADD COLUMN IF NOT EXISTS last_password_reset_at TIMESTAMP
	`)
	if err != nil {
		return fmt.Errorf("failed to add columns to users table: %w", err)
	}

	// Create indexes for new columns
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
		CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active) WHERE deleted_at IS NULL;
		CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
		CREATE INDEX IF NOT EXISTS idx_users_metadata ON users USING gin(metadata);
	`)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Create password_reset_tokens table
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS password_reset_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			used_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			ip_address INET
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create password_reset_tokens table: %w", err)
	}

	// Create indexes for password_reset_tokens
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_password_reset_user_id ON password_reset_tokens(user_id);
		CREATE INDEX IF NOT EXISTS idx_password_reset_token_hash ON password_reset_tokens(token_hash) WHERE used_at IS NULL;
		CREATE INDEX IF NOT EXISTS idx_password_reset_expires_at ON password_reset_tokens(expires_at);
	`)
	if err != nil {
		return fmt.Errorf("failed to create password_reset_tokens indexes: %w", err)
	}

	// Create audit_logs table for tracking important events
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE SET NULL,
			event_type VARCHAR(100) NOT NULL,
			event_data JSONB DEFAULT '{}',
			ip_address INET,
			user_agent TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create audit_logs table: %w", err)
	}

	// Create indexes for audit_logs
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
	`)
	if err != nil {
		return fmt.Errorf("failed to create audit_logs indexes: %w", err)
	}

	return nil
}

func enhanceUsersTableDown(ctx context.Context, db *bun.DB) error {
	// Drop audit_logs table
	_, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS audit_logs`)
	if err != nil {
		return fmt.Errorf("failed to drop audit_logs table: %w", err)
	}

	// Drop password_reset_tokens table
	_, err = db.ExecContext(ctx, `DROP TABLE IF EXISTS password_reset_tokens`)
	if err != nil {
		return fmt.Errorf("failed to drop password_reset_tokens table: %w", err)
	}

	// Drop new columns from users table
	_, err = db.ExecContext(ctx, `
		ALTER TABLE users
		DROP COLUMN IF EXISTS is_active,
		DROP COLUMN IF EXISTS deleted_at,
		DROP COLUMN IF EXISTS email_verified_at,
		DROP COLUMN IF EXISTS phone_verified_at,
		DROP COLUMN IF EXISTS role,
		DROP COLUMN IF EXISTS metadata,
		DROP COLUMN IF EXISTS password_changed_at,
		DROP COLUMN IF EXISTS must_change_password,
		DROP COLUMN IF EXISTS last_password_reset_at
	`)
	if err != nil {
		return fmt.Errorf("failed to drop columns from users table: %w", err)
	}

	return nil
}
