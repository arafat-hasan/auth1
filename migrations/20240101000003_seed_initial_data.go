package main

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(seedInitialDataUp, seedInitialDataDown)
}

// Migration: 20240101000003_seed_initial_data
func seedInitialDataUp(ctx context.Context, db *bun.DB) error {
	// Insert admin user for development/testing
	// Note: The password hash below is for 'admin123' - change this in production!
	query := `INSERT INTO users (email, name, password_hash, is_verified, created_at, updated_at)
VALUES ('admin@auth1.dev', 'System Administrator', '$2a$10$K7bXJaHAVIZdFHOgFcz7FuJSLZQjQMGLuNLKnQH2bxuqHLSIJGHvG', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING`
	
	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to seed initial data: %w", err)
	}

	return nil
}

func seedInitialDataDown(ctx context.Context, db *bun.DB) error {
	// Remove seeded data
	query := `DELETE FROM users WHERE email = 'admin@auth1.dev'`
	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to remove seed data: %w", err)
	}

	return nil
}
