package pgtest

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Server is a PostgreSQL container of its own, for tests that stop and start it. Its DSN goes
// through a local proxy, so it stays the same when a restart moves the container's mapped port.
type Server struct {
	inst  *instance
	proxy *proxy
	dsn   string
}

// NewServer starts a dedicated container, removed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	checkDocker(t)
	inst, err := start()
	if inst != nil {
		t.Cleanup(func() {
			_ = inst.admin.Close()
			_ = inst.ctr.Terminate(context.Background())
		})
	}
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	p, err := newProxy(inst.base.Host)
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	t.Cleanup(p.close)
	u := inst.base
	u.Host = p.addr()
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
	s.proxy.dropAll()
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
	s.proxy.target.Store(u.Host)

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

// proxy forwards TCP connections from a local listener to target.
type proxy struct {
	ln     net.Listener
	target atomic.Value // string, host:port
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newProxy(target string) (*proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{ln: ln, conns: map[net.Conn]struct{}{}}
	p.target.Store(target)
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		p.wg.Add(1)
		go p.forward(c)
	}
}

// forward copies c to and from a new connection to the target until either side closes.
func (p *proxy) forward(c net.Conn) {
	defer p.wg.Done()
	up, err := net.DialTimeout("tcp", p.target.Load().(string), 2*time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	p.track(c, up)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
	p.untrack(c, up)
}

func (p *proxy) track(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		p.conns[c] = struct{}{}
	}
}

func (p *proxy) untrack(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		delete(p.conns, c)
	}
}

// dropAll closes every forwarded connection.
func (p *proxy) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		_ = c.Close()
	}
}

// close stops the listener, drops every connection and waits for the goroutines.
func (p *proxy) close() {
	_ = p.ln.Close()
	p.dropAll()
	p.wg.Wait()
}
