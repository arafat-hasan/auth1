package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/arafat-hasan/auth1/internal/config"
)

// JobLockClass is the first key of every job lock, pg_try_advisory_lock(JobLockClass, <job lock>):
// "jobs" in ASCII. The two-key form never meets the migrator's single bigint key.
const JobLockClass int32 = 0x6a6f6273

// Leader elects this instance leader of the leader-elected jobs (TDD-08 §7): it holds their
// session-level advisory locks on a connection of its own, outside the pool (TDD-08 §8), one for
// every job. The locks live as long as that connection: when it is lost, so are they, and another
// replica takes them. It is safe for concurrent use.
type Leader struct {
	cfg    *pgx.ConnConfig
	logger *slog.Logger

	mu   sync.Mutex
	conn *pgx.Conn      // nil until the first Lead, and after a failure
	held map[int32]bool // the locks taken on conn
}

// NewLeader builds the leader from the DSN in cfg.DSNFile, with the checks of Open. It does not
// connect.
func NewLeader(cfg config.Database, env config.Environment, logger *slog.Logger) (*Leader, error) {
	pc, err := connConfig(cfg, env)
	if err != nil {
		return nil, err
	}
	return &Leader{cfg: pc, logger: logger}, nil
}

// Lead reports whether this instance holds the job lock lock, taking it when it is free. A lock
// already held is confirmed from pg_locks, never taken twice. It connects when it has no
// connection. When the connection fails, Lead closes it, forgets every lock, and returns false
// with the error: the server releases the locks of a lost session, so the instance has stopped
// leading every job, and it competes again at its next call.
func (l *Leader) Lead(ctx context.Context, lock int32) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		conn, err := pgx.ConnectConfig(ctx, l.cfg.Copy())
		if err != nil {
			return false, fmt.Errorf("leader: connect: %w", err)
		}
		l.conn, l.held = conn, map[int32]bool{}
	}
	var ok bool
	var err error
	if l.held[lock] {
		err = l.conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_locks
				WHERE locktype = 'advisory' AND pid = pg_backend_pid()
				  AND classid = $1 AND objid = $2 AND objsubid = 2 AND granted)`, JobLockClass, lock).Scan(&ok)
		if err == nil && !ok {
			err = fmt.Errorf("lock %d no longer held", lock)
		}
	} else {
		err = l.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", JobLockClass, lock).Scan(&ok)
	}
	if err != nil {
		l.drop(ctx)
		return false, fmt.Errorf("leader: lock %d: %w", lock, err)
	}
	l.held[lock] = ok
	return ok, nil
}

// Close closes the connection, releasing every lock.
func (l *Leader) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil
	}
	err := l.conn.Close(ctx)
	l.conn, l.held = nil, nil
	if err != nil {
		return fmt.Errorf("leader: close: %w", err)
	}
	return nil
}

// drop closes a failed connection and forgets its locks. l.mu is held.
func (l *Leader) drop(ctx context.Context) {
	if len(l.held) > 0 {
		l.logger.Warn("leader connection lost; job locks released")
	}
	_ = l.conn.Close(context.WithoutCancel(ctx))
	l.conn, l.held = nil, nil
}
