package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// runMigrate runs "auth1 migrate args…" with environ over fsys and returns its output.
func runMigrate(t *testing.T, environ []string, fsys fs.FS, args ...string) (string, error) {
	t.Helper()
	cmd := newMigrateCmd(func() []string { return environ }, fsys)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateCreate(t *testing.T) {
	t.Parallel()

	t.Run("first", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		out, err := runMigrate(t, nil, nil, "create", "add_x", "--dir", dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"000001_add_x.up.sql", "000001_add_x.down.sql"} {
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path) //nolint:gosec // a test file in a temporary directory
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != 0 {
				t.Errorf("%s is not empty", name)
			}
			if !strings.Contains(out, path) {
				t.Errorf("output %q does not name %s", out, path)
			}
		}
	})

	t.Run("next number", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "000007_a.up.sql"), "")
		writeFile(t, filepath.Join(dir, "000007_a.down.sql"), "")
		if _, err := runMigrate(t, nil, nil, "create", "b", "--dir", dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "000008_b.up.sql")); err != nil {
			t.Error(err)
		}
	})

	for _, args := range [][]string{{"create", "Bad-Name"}, {"create"}, {"create", ""}} {
		t.Run("refuses "+strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if _, err := runMigrate(t, nil, nil, append(args, "--dir", dir)...); err == nil {
				t.Fatal("create succeeded; want an error")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("create left %d files", len(entries))
			}
		})
	}

	t.Run("does not overwrite", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		down := filepath.Join(dir, "000001_x.down.sql")
		writeFile(t, down, "keep")
		if _, err := runMigrate(t, nil, nil, "create", "x", "--dir", dir); err == nil {
			t.Fatal("create succeeded over an existing file; want an error")
		}
		if data, _ := os.ReadFile(down); string(data) != "keep" { //nolint:gosec // a test file
			t.Errorf("the existing file now holds %q", data)
		}
		if _, err := os.Stat(filepath.Join(dir, "000001_x.up.sql")); err == nil {
			t.Error("create left a half-made pair")
		}
	})
}

// developmentEnv is the override for running against a test database: development, so a DSN
// without TLS is accepted.
var developmentEnv = []string{"AUTH1_APP_ENVIRONMENT=development"}

func TestMigrateCommands(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	fsys := os.DirFS("internal/adapters/postgres/migrate/testdata/ok")
	dsn := filepath.Join(t.TempDir(), "dsn")
	writeFile(t, dsn, pgtest.Empty(t))
	base := []string{"--config", "config.example.yaml", "--dsn-file", dsn}
	run := func(args ...string) string {
		t.Helper()
		out, err := runMigrate(t, developmentEnv, fsys, append(args, base...)...)
		if err != nil {
			t.Fatalf("migrate %v: %v\n%s", args, err, out)
		}
		return out
	}

	if out := run("status"); strings.Count(out, "pending") != 3 {
		t.Errorf("status before up:\n%s", out)
	}
	out := run("up")
	for _, want := range []string{"applied 000001_widgets", "applied 000002_gadgets", "applied 000003_slow"} {
		if !strings.Contains(out, want) {
			t.Errorf("up output %q lacks %q", out, want)
		}
	}
	if again := run("up"); !strings.Contains(again, "up to date") {
		t.Errorf("second up: %q", again)
	}
	status := run("status")
	if !regexp.MustCompile(`000001  widgets  applied \d{4}-\d\d-\d\dT`).MatchString(status) {
		t.Errorf("status after up:\n%s", status)
	}
	if out := run("down"); !strings.Contains(out, "reverted 000003_slow") || strings.Contains(out, "000002") {
		t.Errorf("down: %q", out)
	}
	if out := run("down", "2"); !strings.Contains(out, "reverted 000002_gadgets") || !strings.Contains(out, "reverted 000001_widgets") {
		t.Errorf("down 2: %q", out)
	}

	if _, err := runMigrate(t, developmentEnv, fsys, append([]string{"down", "x"}, base...)...); err == nil {
		t.Error("down x succeeded; want a usage error")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	out, err := runMigrate(t, developmentEnv, fsys, "status", "--config", "config.example.yaml", "--dsn-file", missing)
	if err == nil || !strings.Contains(out, missing) {
		t.Errorf("status with a missing --dsn-file: %v, %q; want a problem naming %s", err, out, missing)
	}
}

func TestMigrateRefusesPlainDSNInProduction(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	fsys := os.DirFS("internal/adapters/postgres/migrate/testdata/ok")
	dsn := filepath.Join(t.TempDir(), "dsn")
	writeFile(t, dsn, pgtest.Empty(t))

	out, err := runMigrate(t, nil, fsys, "up", "--config", "config.example.yaml", "--dsn-file", dsn)
	if err == nil || !strings.Contains(err.Error(), "sslmode") {
		t.Fatalf("up in production with sslmode=disable: %v; want the TLS refusal", err)
	}
	if strings.Contains(out, "applied") {
		t.Errorf("up applied migrations: %q", out)
	}
}
