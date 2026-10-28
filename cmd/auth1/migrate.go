package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
)

// migrationName is the <name> part of a new migration's files.
var migrationName = regexp.MustCompile(`^[a-z0-9_]+$`)

// defaultMigrateWait is how long up, down and status wait for a connection and the migration lock.
const defaultMigrateWait = time.Minute

// newMigrateCmd builds "auth1 migrate" over the migrations in fsys (migrations.FS in main).
// environ supplies the AUTH1_ overrides (os.Environ in main).
func newMigrateCmd(environ func() []string, fsys fs.FS) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply, revert, report and create schema migrations",
		Long: "Schema migrations are plain SQL files embedded in the binary. Every command except " +
			"create holds a PostgreSQL advisory lock, so concurrent runs apply each migration once.",
	}

	// withRunner registers --config, --dsn-file and --wait on c and gives run a runner on the
	// database.
	withRunner := func(c *cobra.Command, run func(c *cobra.Command, args []string, r *migrate.Runner) error) *cobra.Command {
		var path, dsnFile string
		var wait time.Duration
		c.Flags().StringVar(&path, "config", "", "configuration file (YAML)")
		c.Flags().StringVar(&dsnFile, "dsn-file", "", "file holding the DSN; overrides database.dsn_file (for the schema owner)")
		c.Flags().DurationVar(&wait, "wait", defaultMigrateWait, "how long to wait for a connection and the migration lock (0: no limit)")
		_ = c.MarkFlagRequired("config")
		c.RunE = func(c *cobra.Command, args []string) error {
			if wait < 0 {
				return fmt.Errorf("--wait %v is negative", wait)
			}
			env := environ()
			if dsnFile != "" {
				env = append(env, "AUTH1_DATABASE_DSN_FILE="+dsnFile)
			}
			cfg, problems, err := loadConfig(path, env)
			if err != nil {
				return err
			}
			if len(problems) > 0 {
				return printProblems(c.ErrOrStderr(), problems)
			}
			db, err := postgres.Open(cfg.Database, cfg.App.Environment)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			return run(c, args, migrate.New(db.DB, fsys, migrate.WithWait(wait)))
		}
		return c
	}

	up := withRunner(&cobra.Command{
		Use:   "up",
		Short: "Apply every pending migration",
		Args:  cobra.NoArgs,
	}, func(c *cobra.Command, _ []string, r *migrate.Runner) error {
		done, err := r.Up(c.Context())
		if perr := printMigrations(c.OutOrStdout(), "applied", done); perr != nil {
			return errors.Join(err, perr)
		}
		if err == nil && len(done) == 0 {
			_, err = fmt.Fprintln(c.OutOrStdout(), "up to date")
		}
		return err
	})

	down := withRunner(&cobra.Command{
		Use:   "down [N]",
		Short: "Revert the last N applied migrations (default 1)",
		Args:  cobra.MaximumNArgs(1),
	}, func(c *cobra.Command, args []string, r *migrate.Runner) error {
		n := 1
		if len(args) == 1 {
			var err error
			if n, err = strconv.Atoi(args[0]); err != nil {
				return fmt.Errorf("down: count %q is not a number", args[0])
			}
		}
		done, err := r.Down(c.Context(), n)
		if perr := printMigrations(c.OutOrStdout(), "reverted", done); perr != nil {
			return errors.Join(err, perr)
		}
		return err
	})

	status := withRunner(&cobra.Command{
		Use:   "status",
		Short: "List applied and pending migrations",
		Args:  cobra.NoArgs,
	}, func(c *cobra.Command, _ []string, r *migrate.Runner) error {
		states, err := r.Status(c.Context())
		if err != nil {
			return err
		}
		for _, s := range states {
			state := "pending"
			if s.Applied {
				state = "applied " + s.AppliedAt.UTC().Format(time.RFC3339)
			}
			if s.FileMissing {
				state = "applied, no file " + s.AppliedAt.UTC().Format(time.RFC3339)
			}
			if s.Changed {
				state = "applied, changed " + s.AppliedAt.UTC().Format(time.RFC3339)
			}
			if _, err := fmt.Fprintf(c.OutOrStdout(), "%06d  %s  %s\n", s.Version, s.Name, state); err != nil {
				return err
			}
		}
		return nil
	})

	var dir string
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create the next numbered pair of empty migration files",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return createMigration(c.OutOrStdout(), dir, args[0])
		},
	}
	create.Flags().StringVar(&dir, "dir", "migrations", "directory of the migration files")

	cmd.AddCommand(up, down, status, create)
	return cmd
}

func printMigrations(out io.Writer, verb string, ms []migrate.Migration) error {
	for _, m := range ms {
		if _, err := fmt.Fprintf(out, "%s %06d_%s\n", verb, m.Version, m.Name); err != nil {
			return err
		}
	}
	return nil
}

// createMigration writes NNNNNN_<name>.up.sql and .down.sql, empty, into dir, numbered one above
// the highest version there. It never overwrites a file.
func createMigration(out io.Writer, dir, name string) error {
	if !migrationName.MatchString(name) {
		return fmt.Errorf("create: name %q is not lower-case letters, digits and _", name)
	}
	existing, err := migrate.Load(os.DirFS(dir))
	if err != nil {
		return err
	}
	next := int64(1)
	if len(existing) > 0 {
		next = existing[len(existing)-1].Version + 1
	}
	m := migrate.Migration{Version: next, Name: name}
	up, down := filepath.Join(dir, m.File()), filepath.Join(dir, m.DownFile())
	for i, path := range []string{up, down} {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path is built from --dir and a checked name
		if err != nil {
			if i == 1 {
				_ = os.Remove(up)
			}
			return fmt.Errorf("create: %w", err)
		}
		if err := f.Close(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, path); err != nil {
			return err
		}
	}
	return nil
}
