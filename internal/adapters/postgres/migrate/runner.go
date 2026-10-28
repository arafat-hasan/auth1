package migrate

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"
)

// lockKey is the advisory lock every command holds for its whole run ("auth1mig").
const lockKey int64 = 0x61757468316d6967

const createTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    bigint PRIMARY KEY,
	name       text NOT NULL,
	checksum   bytea NOT NULL,
	applied_at timestamptz NOT NULL
)`

// Runner applies, reverts and reports the migrations of an fs.FS. Each command takes a session
// advisory lock on one connection, so concurrent runs wait for each other, and runs every
// migration in its own transaction on that connection.
type Runner struct {
	db   *sql.DB
	fsys fs.FS
	wait time.Duration
}

// Option configures a Runner.
type Option func(*Runner)

// WithWait bounds how long a command waits for a connection and for the migration lock. Without
// it, a command waits as long as its context allows. It does not bound the migrations themselves.
func WithWait(d time.Duration) Option { return func(r *Runner) { r.wait = d } }

// New returns a Runner for the migrations at the root of fsys.
func New(db *sql.DB, fsys fs.FS, opts ...Option) *Runner {
	r := &Runner{db: db, fsys: fsys}
	for _, o := range opts {
		o(r)
	}
	return r
}

// State is one migration as Status reports it.
type State struct {
	Version     int64
	Name        string
	Applied     bool
	AppliedAt   time.Time // zero when pending
	FileMissing bool      // applied, but the FS has no such migration
	Changed     bool      // applied, but the up file no longer matches its checksum
}

// applied is a schema_migrations row.
type applied struct {
	version  int64
	name     string
	checksum []byte
	at       time.Time
}

func (a applied) base() string { return fmt.Sprintf("%06d_%s", a.version, a.name) }

// Up applies every pending migration in version order and returns those it applied. Before
// applying any, it refuses when a migration has no down file, an applied migration's up file no
// longer matches its checksum, or a pending migration is older than the newest applied one. An
// applied migration that the FS does not have is left alone. When a migration fails, those before
// it stay applied.
func (r *Runner) Up(ctx context.Context) ([]Migration, error) {
	var done []Migration
	err := r.session(ctx, true, func(conn *sql.Conn, files []Migration, rows map[int64]applied) error {
		var newest int64
		for _, a := range rows {
			newest = max(newest, a.version)
		}
		var pending []Migration
		for _, m := range files {
			if m.Down == nil {
				return fmt.Errorf("migration %s has no down file %s", m.File(), m.DownFile())
			}
			a, ok := rows[m.Version]
			switch {
			case ok:
				if err := checkSum(m, a); err != nil {
					return err
				}
			case m.Version < newest:
				return fmt.Errorf("migration file %s is older than the newest applied migration %06d", m.File(), newest)
			default:
				pending = append(pending, m)
			}
		}
		for _, m := range pending {
			if err := inTx(ctx, conn, m.Up, `INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES ($1, $2, $3, now())`,
				m.Version, m.Name, m.Checksum[:]); err != nil {
				return fmt.Errorf("apply %s: %w", m.File(), err)
			}
			done = append(done, m)
		}
		return nil
	})
	return done, err
}

// Down reverts the last n applied migrations, newest first, and returns those it reverted. It
// refuses, before reverting any, when n is below 1 or above the number applied, or when one of
// them has no file, no down file or a changed up file.
func (r *Runner) Down(ctx context.Context, n int) ([]Migration, error) {
	if n < 1 {
		return nil, fmt.Errorf("down: count %d is below 1", n)
	}
	var done []Migration
	err := r.session(ctx, false, func(conn *sql.Conn, files []Migration, rows map[int64]applied) error {
		if n > len(rows) {
			return fmt.Errorf("down: %d requested, but only %d applied", n, len(rows))
		}
		byVersion := map[int64]Migration{}
		for _, m := range files {
			byVersion[m.Version] = m
		}
		last := slices.SortedFunc(func(yield func(applied) bool) {
			for _, a := range rows {
				if !yield(a) {
					return
				}
			}
		}, func(a, b applied) int { return cmp.Compare(b.version, a.version) })[:n]

		todo := make([]Migration, 0, n)
		for _, a := range last {
			m, ok := byVersion[a.version]
			if !ok {
				return fmt.Errorf("applied migration %s has no file; it cannot be reverted", a.base())
			}
			if m.Down == nil {
				return fmt.Errorf("migration %s has no down file %s", m.File(), m.DownFile())
			}
			if err := checkSum(m, a); err != nil {
				return err
			}
			todo = append(todo, m)
		}
		for _, m := range todo {
			if err := inTx(ctx, conn, m.Down, `DELETE FROM schema_migrations WHERE version = $1`, m.Version); err != nil {
				return fmt.Errorf("revert %s: %w", m.DownFile(), err)
			}
			done = append(done, m)
		}
		return nil
	})
	return done, err
}

// Status returns every migration, applied or pending, in version order. It marks an applied
// migration whose up file has changed, which Up and Down would refuse.
func (r *Runner) Status(ctx context.Context) ([]State, error) {
	var out []State
	err := r.session(ctx, false, func(_ *sql.Conn, files []Migration, rows map[int64]applied) error {
		seen := map[int64]bool{}
		for _, m := range files {
			s := State{Version: m.Version, Name: m.Name}
			if a, ok := rows[m.Version]; ok {
				s.Applied, s.AppliedAt = true, a.at
				s.Changed = checkSum(m, a) != nil
			}
			seen[m.Version] = true
			out = append(out, s)
		}
		for _, a := range rows {
			if !seen[a.version] {
				out = append(out, State{Version: a.version, Name: a.name, Applied: true, AppliedAt: a.at, FileMissing: true})
			}
		}
		slices.SortFunc(out, func(a, b State) int { return cmp.Compare(a.Version, b.Version) })
		return nil
	})
	return out, err
}

// checkSum refuses an applied migration whose up file has changed.
func checkSum(m Migration, a applied) error {
	if !bytes.Equal(m.Checksum[:], a.checksum) {
		return fmt.Errorf("migration file %s has changed since it was applied (checksum mismatch)", m.File())
	}
	return nil
}

// session loads the migrations, takes the advisory lock on a dedicated connection, reads the
// schema_migrations table and calls fn. Only when create is set does it create the table, which
// needs the CREATE privilege; otherwise a missing table means nothing is applied, so a role that
// may only read can report status. The lock is released before returning; if releasing fails,
// the connection is discarded, which releases it too.
func (r *Runner) session(ctx context.Context, create bool, fn func(conn *sql.Conn, files []Migration, rows map[int64]applied) error) (err error) {
	files, err := Load(r.fsys)
	if err != nil {
		return err
	}
	wctx := ctx // bounds the wait for the connection and the lock
	if r.wait > 0 {
		var cancel context.CancelFunc
		wctx, cancel = context.WithTimeout(ctx, r.wait)
		defer cancel()
	}
	conn, err := r.db.Conn(wctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(wctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("take the migration lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey); uerr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("release the migration lock: %w", uerr))
		}
	}()

	if create {
		if _, err := conn.ExecContext(ctx, createTable); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
	}
	rows, err := readApplied(ctx, conn)
	if err != nil {
		return err
	}
	return fn(conn, files, rows)
}

// readApplied returns the schema_migrations rows by version, none when the table does not exist.
func readApplied(ctx context.Context, conn *sql.Conn) (map[int64]applied, error) {
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	if !exists {
		return map[int64]applied{}, nil
	}
	rs, err := conn.QueryContext(ctx, `SELECT version, name, checksum, applied_at FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer func() { _ = rs.Close() }()
	out := map[int64]applied{}
	for rs.Next() {
		var a applied
		if err := rs.Scan(&a.version, &a.name, &a.checksum, &a.at); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		out[a.version] = a
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return out, nil
}

// inTx runs script, then record with its arguments, in one transaction. The script is sent
// without arguments, so it may hold several statements.
func inTx(ctx context.Context, conn *sql.Conn, script []byte, record string, args ...any) (err error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, string(script)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, record, args...); err != nil {
		return err
	}
	return tx.Commit()
}
