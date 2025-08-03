package main

import (
	"context"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(seedInitialDataUp, seedInitialDataDown)
}

// Migration: 20240101000003_seed_initial_data
func seedInitialDataUp(ctx context.Context, db *bun.DB) error {
	// This migration is now deprecated in favor of environment-specific seeding
	// Use ./migrate seed command to populate environment-specific data
	// This migration remains for backward compatibility but does nothing
	return nil
}

func seedInitialDataDown(ctx context.Context, db *bun.DB) error {
	// This migration is now deprecated in favor of environment-specific seeding
	// Manual cleanup of seed data should be done per environment if needed
	return nil
}
