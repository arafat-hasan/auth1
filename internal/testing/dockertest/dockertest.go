package dockertest

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// RequireEnv is the variable that, set to 1, turns a missing Docker into a test failure.
const RequireEnv = "AUTH1_REQUIRE_DOCKER"

// Docker's health, found once per test binary.
var (
	once   sync.Once
	health error
)

// Check skips t when Docker is not reachable, or fails it when RequireEnv is 1.
func Check(t testing.TB) {
	t.Helper()
	once.Do(func() {
		p, err := testcontainers.NewDockerProvider()
		if err != nil {
			health = err
			return
		}
		defer func() { _ = p.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		health = p.Health(ctx)
	})
	switch skip, fail := gate(health, os.Getenv(RequireEnv) == "1"); {
	case fail:
		t.Fatalf("Docker unavailable and %s=1: %v", RequireEnv, health)
	case skip:
		t.Skipf("Docker unavailable (set %s=1 to fail): %v", RequireEnv, health)
	}
}

// gate decides what a test does given Docker's health: run, skip, or fail when Docker is required.
func gate(health error, require bool) (skip, fail bool) {
	if health == nil {
		return false, false
	}
	return !require, require
}

// Proxy forwards TCP connections from a local listener to a target that may move, so a client's
// address survives a container restart that changes the mapped port.
type Proxy struct {
	ln     net.Listener
	target atomic.Value // string, host:port
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewProxy listens on a local port and forwards to target until Close.
func NewProxy(target string) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, conns: map[net.Conn]struct{}{}}
	p.target.Store(target)
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Addr is the proxy's host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// SetTarget sends new connections to target.
func (p *Proxy) SetTarget(target string) { p.target.Store(target) }

func (p *Proxy) serve() {
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
func (p *Proxy) forward(c net.Conn) {
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

func (p *Proxy) track(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		p.conns[c] = struct{}{}
	}
}

func (p *Proxy) untrack(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		delete(p.conns, c)
	}
}

// DropAll closes every forwarded connection.
func (p *Proxy) DropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		_ = c.Close()
	}
}

// Close stops the listener, drops every connection and waits for the goroutines.
func (p *Proxy) Close() {
	_ = p.ln.Close()
	p.DropAll()
	p.wg.Wait()
}
