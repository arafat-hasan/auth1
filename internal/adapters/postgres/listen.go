package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/arafat-hasan/auth1/internal/config"
)

// How long the listener waits before reconnecting: listenRetryFirst, doubling up to listenRetryLast.
const (
	listenRetryFirst = time.Second
	listenRetryLast  = 30 * time.Second
)

// Listener holds the relay's LISTEN connection to auth1_outbox (TDD-06 §3.3): a connection of its
// own, outside the pool (TDD-08 §8), whose notifications wake the relay of their destination.
// The relay's poll remains the safety net, so a lost connection only delays wake-ups.
type Listener struct {
	cfg    *pgx.ConnConfig
	logger *slog.Logger
	wake   map[string]chan struct{}
}

// NewListener builds the listener from the DSN in cfg.DSNFile, with the checks of Open. It does
// not connect.
func NewListener(cfg config.Database, env config.Environment, logger *slog.Logger) (*Listener, error) {
	pc, err := connConfig(cfg, env)
	if err != nil {
		return nil, err
	}
	return &Listener{cfg: pc, logger: logger, wake: map[string]chan struct{}{
		"event": make(chan struct{}, 1), "delivery": make(chan struct{}, 1),
	}}, nil
}

// Wake returns the channel signalled when rows for destination (event or delivery) may be due.
// Signals coalesce: one pending signal stands for any number of notifications. The channel of an
// unknown destination is nil.
func (l *Listener) Wake(destination string) <-chan struct{} {
	return l.wake[destination]
}

// Run listens until ctx ends, then returns nil. A lost connection is logged and reopened after
// a growing delay; each new connection wakes every destination, since notifications sent while
// it was down were lost.
func (l *Listener) Run(ctx context.Context) error {
	delay := listenRetryFirst
	for {
		connected, err := l.listen(ctx)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // the connection ends with ctx; that is a stop, not a failure
		}
		if connected {
			delay = listenRetryFirst
		}
		l.logger.Warn("outbox listener lost", slog.Any("error", err), slog.Duration("retry_in", delay))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(2*delay, listenRetryLast)
	}
}

// listen connects, listens and signals notifications until the connection fails or ctx ends.
// connected reports whether LISTEN succeeded.
func (l *Listener) listen(ctx context.Context) (connected bool, err error) {
	conn, err := pgx.ConnectConfig(ctx, l.cfg.Copy())
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if _, err := conn.Exec(ctx, "LISTEN "+outboxChannel); err != nil {
		return false, fmt.Errorf("listen: %w", err)
	}
	for _, ch := range l.wake {
		signal(ch)
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return true, fmt.Errorf("wait for notification: %w", err)
		}
		if ch, ok := l.wake[n.Payload]; ok {
			signal(ch)
		}
	}
}

// signal sets ch's pending signal, unless one is already set.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
