package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/migrate"

	"auth1/internal/config"
)

var (
	migrator *migrate.Migrator
	db       *bun.DB
	logger   *logrus.Logger
)

func main() {
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Load migration configuration (database only)
	cfg, err := loadMigrationConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup database
	db, err = setupDatabase(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to setup database: %v", err)
	}
	defer db.Close()

	// Setup migrator
	migrator = migrate.NewMigrator(db, Migrations)

	// Setup CLI commands
	rootCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration tool for auth1",
		Long:  "A robust database migration tool using Bun's migration system",
	}

	// Add subcommands
	rootCmd.AddCommand(
		createInitCmd(),
		createUpCmd(),
		createDownCmd(),
		createStatusCmd(),
		createResetCmd(),
		createCreateCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Command failed: %v", err)
	}
}

func setupDatabase(cfg *config.Config, logger *logrus.Logger) (*bun.DB, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.Info("Database connected successfully")
	return db, nil
}

// loadMigrationConfig loads only database configuration for migrations
// This avoids loading JWT keys which are not needed for migrations
func loadMigrationConfig() (*config.Config, error) {
	cfg := &config.Config{}

	// Set database defaults
	cfg.Database.Host = getEnvOrDefault("DATABASE_HOST", "localhost")
	cfg.Database.Port = getEnvOrDefault("DATABASE_PORT", "5432")
	cfg.Database.User = getEnvOrDefault("DATABASE_USER", "auth1")
	cfg.Database.Password = getEnvOrDefault("DATABASE_PASSWORD", "password")
	cfg.Database.Name = getEnvOrDefault("DATABASE_NAME", "auth1")
	cfg.Database.SSLMode = getEnvOrDefault("DATABASE_SSL_MODE", "disable")

	return cfg, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func createInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize migration tracking table",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			if err := migrator.Init(ctx); err != nil {
				logger.Fatalf("Failed to initialize migrations: %v", err)
			}
			logger.Info("Migration tracking table initialized successfully")
		},
	}
}

func createUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Run pending migrations",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			group, err := migrator.Migrate(ctx)
			if err != nil {
				logger.Fatalf("Failed to run migrations: %v", err)
			}

			if group.IsZero() {
				logger.Info("No new migrations to run")
				return
			}

			logger.WithFields(logrus.Fields{
				"group":      group.String(),
				"migrations": len(group.Migrations),
			}).Info("Successfully ran migrations")
		},
	}
}

func createDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Rollback the last migration group",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			group, err := migrator.Rollback(ctx)
			if err != nil {
				logger.Fatalf("Failed to rollback migrations: %v", err)
			}

			if group.IsZero() {
				logger.Info("No migrations to rollback")
				return
			}

			logger.WithFields(logrus.Fields{
				"group":      group.String(),
				"migrations": len(group.Migrations),
			}).Info("Successfully rolled back migrations")
		},
	}
}

func createStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			ms, err := migrator.MigrationsWithStatus(ctx)
			if err != nil {
				logger.Fatalf("Failed to get migration status: %v", err)
			}

			fmt.Printf("Migration Status:\n")
			fmt.Printf("================\n")

			for _, m := range ms {
				status := "pending"
				if m.IsApplied() {
					status = fmt.Sprintf("applied at %s", m.MigratedAt.Format("2006-01-02 15:04:05"))
				}
				fmt.Printf("%-50s %s\n", m.Name, status)
			}
		},
	}
}

func createResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset database (rollback all migrations)",
		Run: func(cmd *cobra.Command, args []string) {
			// Add confirmation prompt
			fmt.Print("Are you sure you want to reset the database? This will rollback all migrations. (y/N): ")
			var confirmation string
			fmt.Scanln(&confirmation)

			if confirmation != "y" && confirmation != "Y" {
				logger.Info("Reset cancelled")
				return
			}

			ctx := context.Background()
			for {
				group, err := migrator.Rollback(ctx)
				if err != nil {
					logger.Fatalf("Failed to rollback migrations: %v", err)
				}
				if group.IsZero() {
					break
				}
				logger.WithFields(logrus.Fields{
					"group": group.String(),
				}).Info("Rolled back migration group")
			}
			logger.Info("Database reset completed")
		},
	}
}

func createCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new migration file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			file, err := migrator.CreateGoMigration(context.Background(), name)
			if err != nil {
				logger.Fatalf("Failed to create migration: %v", err)
			}

			logger.WithField("file", file.Path).Info("Created migration file")
		},
	}
}
