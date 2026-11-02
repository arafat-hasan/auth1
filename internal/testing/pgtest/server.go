package pgtest

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/testing/dockertest"
)

// Server is a PostgreSQL container of its own, for tests that stop and start it. Its DSN goes
// through a local proxy, so it stays the same when a restart moves the container's mapped port.
type Server struct {
	inst  *instance
	proxy *dockertest.Proxy
	dsn   string
}

// NewServer starts a dedicated container, removed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	dockertest.Check(t)
	inst, err := start()
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	t.Cleanup(func() {
		_ = inst.admin.Close()
		_ = inst.ctr.Terminate(context.Background())
	})
	p, err := dockertest.NewProxy(inst.base.Host)
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	t.Cleanup(p.Close)
	u := inst.base
	u.Host = p.Addr()
	return &Server{inst: inst, proxy: p, dsn: u.String()}
}

// DSN returns the DSN of the server's postgres database, valid across restarts.
func (s *Server) DSN() string { return s.dsn }

// Stop stops the container and drops every connection through the proxy.
func (s *Server) Stop(t testing.TB) {
	t.Helper()
	timeout := 10 * time.Second
	if err := s.inst.ctr.Stop(context.Background(), &timeout); err != nil {
		t.Fatalf("pgtest: stop: %v", err)
	}
	s.proxy.DropAll()
}

// Start starts the container again and returns once it accepts connections.
func (s *Server) Start(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := s.inst.ctr.Start(ctx); err != nil {
		t.Fatalf("pgtest: start: %v", err)
	}
	dsn, err := s.inst.ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("pgtest: connection string: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	s.proxy.SetTarget(u.Host)

	db, err := sql.Open("pgx", s.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for {
		pctx, pcancel := context.WithTimeout(ctx, time.Second)
		err := db.PingContext(pctx)
		pcancel()
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("pgtest: server not ready after start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
