package jobs_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/internal/worker/jobs"
)

// dbConfig writes dsn to a file and returns the database section naming it.
func dbConfig(t *testing.T, dsn string) config.Database {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Database{DSNFile: config.NewSecretFile(path), MaxConns: 2}
}

// replica is one instance's scheduler, with its own leader connection and run count.
type replica struct {
	runs counting
	stop func()
}

func newReplica(t *testing.T, dsn string) *replica {
	t.Helper()
	l, err := postgres.NewLeader(dbConfig(t, dsn), config.EnvDevelopment, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	r := &replica{}
	s, err := jobs.New(jobs.Options{Elector: l, CheckEvery: 50 * time.Millisecond,
		Jobs: []jobs.Job{{Name: "flow-expiry", Lock: 1, Every: 50 * time.Millisecond, Run: r.runs.run}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	r.stop = func() { cancel(); <-done; _ = l.Close(context.Background()) }
	t.Cleanup(r.stop)
	return r
}

// holder returns the backend pid holding the job lock 1.
func holder(t *testing.T, su *bun.DB) int {
	t.Helper()
	var pid int
	if err := su.QueryRowContext(t.Context(), `
		SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = ? AND objid = 1 AND objsubid = 2 AND granted`,
		postgres.JobLockClass).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

// TestTwoSchedulersOneLeader checks WP-58's hand-over: of two schedulers, only the leader runs the
// job; when its lock connection is killed, the other takes over and the old leader stops.
func TestTwoSchedulersOneLeader(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	su, err := postgres.Open(dbConfig(t, dsn), config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = su.Close() })
	appDSN := pgtest.As(t, dsn, pgtest.App)
	a, b := newReplica(t, appDSN), newReplica(t, appDSN)

	eventually(t, 5*time.Second, "a leader runs", func() bool { return a.runs.runs.Load()+b.runs.runs.Load() >= 5 })
	leader, follower := a, b
	if b.runs.runs.Load() > 0 {
		leader, follower = b, a
	}
	if n := follower.runs.runs.Load(); n != 0 {
		t.Fatalf("both ran: %d and %d runs", leader.runs.runs.Load(), n)
	}

	if _, err := su.ExecContext(t.Context(), "SELECT pg_terminate_backend(?)", holder(t, su)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the follower takes over", func() bool { return follower.runs.runs.Load() > 0 })
	time.Sleep(100 * time.Millisecond) // a run the old leader had in flight
	stopped := leader.runs.runs.Load()
	time.Sleep(400 * time.Millisecond)
	if n := leader.runs.runs.Load(); n != stopped {
		t.Errorf("the old leader ran %d more times after the hand-over", n-stopped)
	}
	if n := follower.runs.runs.Load(); n < 3 {
		t.Errorf("the new leader ran %d times, want it running", n)
	}
}
