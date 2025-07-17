package main

import (
	"github.com/uptrace/bun/migrate"
)

// Migrations is the collection of all database migrations
var Migrations = migrate.NewMigrations()

func init() {
	// Auto-discover migrations from individual files
	// Each migration file should call Migrations.MustRegister() in its init function
}
