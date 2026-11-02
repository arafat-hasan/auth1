package postgres_test

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// runListener starts a listener on dsn, stopped when the test ends.
func runListener(t *testing.T, dsn string) *postgres.Listener {
	t.Helper()
	l, err := postgres.NewListener(dbConfig(dsnFile(t, dsn)), config.EnvDevelopment, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("listener Run = %v, want nil when its context ends", err)
		}
	})
	return l
}

// waitWake fails the test unless ch is signalled within d.
func waitWake(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("no wake-up for %s within %v", what, d)
	}
}

// drain empties ch.
func drain(ch <-chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

// TestListenerWakes checks TDD-06 §3.3: a committed delivery wakes the delivery relay at once,
// and not the event relay. Connecting wakes both, since notifications before it were missed.
func TestListenerWakes(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	l := runListener(t, pgtest.As(t, e.dsn, pgtest.App))
	waitWake(t, l.Wake("delivery"), 10*time.Second, "the first connection (delivery)")
	waitWake(t, l.Wake("event"), time.Second, "the first connection (event)")

	e.notice(t, e.flowAccount(t))
	waitWake(t, l.Wake("delivery"), time.Second, "a committed delivery")
	select {
	case <-l.Wake("event"):
		t.Error("a delivery woke the event relay")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestListenerReconnects checks that the listener survives a lost connection: it reconnects,
// wakes every relay for what it missed, and is woken by later notifications.
func TestListenerReconnects(t *testing.T) {
	t.Parallel()
	s := pgtest.NewServer(t)
	l := runListener(t, s.DSN())
	waitWake(t, l.Wake("delivery"), 10*time.Second, "the first connection")
	drain(l.Wake("event"))

	s.Stop(t)
	s.Start(t)
	waitWake(t, l.Wake("delivery"), 15*time.Second, "the reconnection")

	db, err := sql.Open("pgx", s.DSN())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	drain(l.Wake("delivery"))
	if _, err := db.ExecContext(t.Context(), "SELECT pg_notify('auth1_outbox', 'delivery')"); err != nil {
		t.Fatal(err)
	}
	waitWake(t, l.Wake("delivery"), time.Second, "a notification after the reconnection")
}
