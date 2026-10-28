package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// dsnFile writes dsn to a file in a temporary directory and returns its path.
func dsnFile(t *testing.T, dsn string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dbConfig(path string) config.Database {
	return config.Database{DSNFile: config.NewSecretFile(path), MaxConns: 7, AcquireTimeout: 2 * time.Second}
}

const tlsRefusal = "sslmode must be require, verify-ca or verify-full outside development"

func TestOpenRefuses(t *testing.T) {
	t.Setenv("PGSSLMODE", "")

	missing := filepath.Join(t.TempDir(), "absent")
	for _, tc := range []struct {
		name     string
		path     string // when empty, a file holding dsn
		dsn      string
		env      config.Environment
		contains []string
		excludes []string
	}{
		{name: "missing file", path: missing, contains: []string{missing}},
		{name: "empty file", dsn: "", contains: []string{"is empty"}},
		{name: "blank file", dsn: " \n\t\n", contains: []string{"is empty"}},
		{
			name:     "malformed",
			dsn:      "postgres://u:hunter2@db.internal:notaport/x?sslmode=require",
			contains: []string{"invalid DSN"},
			excludes: []string{"hunter2", "db.internal"},
		},
		{name: "sslmode disable", dsn: "postgres://u@h/x?sslmode=disable", contains: []string{tlsRefusal}},
		{name: "sslmode allow", dsn: "postgres://u@h/x?sslmode=allow", contains: []string{tlsRefusal}},
		{name: "sslmode prefer", dsn: "postgres://u@h/x?sslmode=prefer", contains: []string{tlsRefusal}},
		{name: "no sslmode", dsn: "postgres://u@h/x", contains: []string{tlsRefusal}},
		{name: "keyword form, disable", dsn: "host=h user=u password=hunter2 sslmode=disable", contains: []string{tlsRefusal}, excludes: []string{"hunter2"}},
		{name: "staging, disable", dsn: "postgres://u@h/x?sslmode=disable", env: config.EnvStaging, contains: []string{tlsRefusal}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "" {
				path = dsnFile(t, tc.dsn)
			}
			env := tc.env
			if env == "" {
				env = config.EnvProduction
			}
			db, err := postgres.Open(dbConfig(path), env)
			if err == nil {
				_ = db.Close()
				t.Fatal("Open succeeded; want an error")
			}
			msg := err.Error()
			for _, c := range append(tc.contains, path) {
				if !strings.Contains(msg, c) {
					t.Errorf("error %q does not contain %q", msg, c)
				}
			}
			for _, x := range tc.excludes {
				if strings.Contains(msg, x) {
					t.Errorf("error %q contains %q", msg, x)
				}
			}
			probe, err := postgres.OpenProbe(dbConfig(path), env)
			if err == nil {
				_ = probe.Close()
				t.Fatal("OpenProbe succeeded; want an error")
			}
			if err.Error() != msg {
				t.Errorf("OpenProbe error %q; want Open's %q", err, msg)
			}
		})
	}
}

func TestOpenRefusesSSLModeFromEnvironment(t *testing.T) {
	t.Setenv("PGSSLMODE", "prefer")
	db, err := postgres.Open(dbConfig(dsnFile(t, "postgres://u@h/x")), config.EnvProduction)
	if err == nil {
		_ = db.Close()
		t.Fatal("Open succeeded; want the TLS refusal")
	}
	if !strings.Contains(err.Error(), tlsRefusal) {
		t.Errorf("error %q; want the TLS refusal", err)
	}
}

func TestOpenAccepts(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	for _, tc := range []struct {
		name string
		dsn  string
		env  config.Environment
	}{
		{"require", "postgres://u@h/x?sslmode=require", config.EnvProduction},
		{"verify-full", "postgres://u@h/x?sslmode=verify-full", config.EnvProduction},
		{"keyword form, verify-ca", "host=h user=u sslmode=verify-ca", config.EnvTest},
		{"development, disable", "postgres://u@h/x?sslmode=disable", config.EnvDevelopment},
		{"development, no sslmode", "postgres://u@h/x", config.EnvDevelopment},
		{"trailing newline", "postgres://u@h/x?sslmode=require\n", config.EnvProduction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := postgres.Open(dbConfig(dsnFile(t, tc.dsn)), tc.env)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			_ = db.Close()
		})
	}
}

func TestOpenPoolSettings(t *testing.T) {
	db, err := postgres.Open(dbConfig(dsnFile(t, "postgres://u@h/x?sslmode=require")), config.EnvProduction)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if got := db.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7", got)
	}
}

func TestPing(t *testing.T) {
	t.Run("reachable", func(t *testing.T) {
		probe, err := postgres.OpenProbe(dbConfig(dsnFile(t, pgtest.Empty(t))), config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = probe.Close() }()
		if err := postgres.Ping(probe, time.Second)(context.Background()); err != nil {
			t.Errorf("Ping: %v", err)
		}
	})
	t.Run("request pool busy", func(t *testing.T) {
		cfg := dbConfig(dsnFile(t, pgtest.Empty(t)))
		cfg.MaxConns = 1
		db, err := postgres.Open(cfg, config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		conn, err := db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()

		probe, err := postgres.OpenProbe(cfg, config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = probe.Close() }()
		if got := probe.Stats().MaxOpenConnections; got != 1 {
			t.Errorf("probe MaxOpenConnections = %d, want 1", got)
		}
		if err := postgres.Ping(probe, time.Second)(context.Background()); err != nil {
			t.Errorf("Ping with every request connection busy: %v", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		probe, err := postgres.OpenProbe(dbConfig(dsnFile(t, "postgres://u:hunter2@127.0.0.1:1/x?sslmode=disable")), config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = probe.Close() }()
		start := time.Now()
		err = postgres.Ping(probe, 200*time.Millisecond)(context.Background())
		if err == nil {
			t.Fatal("Ping succeeded; want an error")
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Ping took %v; want about its 200ms timeout", d)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error %q contains the password", err)
		}
	})
}
