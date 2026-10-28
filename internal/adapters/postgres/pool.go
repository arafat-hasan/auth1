package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/arafat-hasan/auth1/internal/config"
)

// How long a pooled connection may stay idle, and live in all.
const (
	MaxConnIdleTime = 5 * time.Minute
	MaxConnLifetime = 30 * time.Minute
)

// Open builds the connection pool from the DSN in cfg.DSNFile. It does not connect, so it
// succeeds while PostgreSQL is down. Outside development it refuses a DSN that allows a
// connection without TLS. Errors name the file, never its contents.
func Open(cfg config.Database, env config.Environment) (*bun.DB, error) {
	pc, err := connConfig(cfg, env)
	if err != nil {
		return nil, err
	}
	sqldb := sql.OpenDB(stdlib.GetConnector(*pc))
	sqldb.SetMaxOpenConns(cfg.MaxConns)
	sqldb.SetMaxIdleConns(cfg.MaxConns)
	sqldb.SetConnMaxIdleTime(MaxConnIdleTime)
	sqldb.SetConnMaxLifetime(MaxConnLifetime)
	return bun.NewDB(sqldb, pgdialect.New()), nil
}

// OpenProbe builds the readiness probe's pool of one connection from the same DSN, with the same
// checks as Open. Being apart from the request pool, it reports whether PostgreSQL answers even
// when every request connection is busy. It does not connect.
func OpenProbe(cfg config.Database, env config.Environment) (*sql.DB, error) {
	pc, err := connConfig(cfg, env)
	if err != nil {
		return nil, err
	}
	sqldb := sql.OpenDB(stdlib.GetConnector(*pc))
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	sqldb.SetConnMaxLifetime(MaxConnLifetime)
	return sqldb, nil
}

// connConfig reads and parses the DSN in cfg.DSNFile and applies the TLS rule.
func connConfig(cfg config.Database, env config.Environment) (*pgx.ConnConfig, error) {
	path := cfg.DSNFile.Path()
	raw, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("read database.dsn_file: %w", err)
	}
	dsn := string(bytes.TrimSpace(raw))
	if dsn == "" {
		return nil, fmt.Errorf("database.dsn_file %s is empty", path)
	}
	pc, err := pgx.ParseConfig(dsn)
	if err != nil {
		// pgx's message quotes the DSN, so the cause is left out.
		return nil, fmt.Errorf("database.dsn_file %s: invalid DSN", path)
	}
	if env != config.EnvDevelopment && !tlsOnly(pc) {
		return nil, fmt.Errorf("database.dsn_file %s: sslmode must be require, verify-ca or verify-full outside development", path)
	}
	return pc, nil
}

// tlsOnly reports whether every connection attempt the config allows uses TLS. sslmode disable
// has no TLS config; allow and prefer (pgx's default) have a fallback without one.
func tlsOnly(pc *pgx.ConnConfig) bool {
	if pc.TLSConfig == nil {
		return false
	}
	for _, f := range pc.Fallbacks {
		if f.TLSConfig == nil {
			return false
		}
	}
	return true
}

// Ping returns the readiness check: a ping of probe, from OpenProbe, bounded by timeout.
func Ping(probe *sql.DB, timeout time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return probe.PingContext(ctx)
	}
}
