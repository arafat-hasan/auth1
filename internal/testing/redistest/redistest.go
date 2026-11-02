package redistest

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/arafat-hasan/auth1/internal/testing/dockertest"
)

// Image is the Redis image the containers run.
const Image = "redis:8.2-alpine"

// startTimeout bounds starting a container and waiting for it to answer PING.
const startTimeout = 2 * time.Minute

// stopTimeout bounds removing the shared container when the test binary ends.
const stopTimeout = time.Minute

// The package's shared container, started once per test binary. Main removes it after the tests,
// as pgtest.Main does, since the testcontainers reaper cannot be relied on.
var (
	inMain atomic.Bool

	sharedOnce sync.Once
	sharedCtr  *tcredis.RedisContainer
	sharedAddr string
	sharedErr  error

	prefixCounter atomic.Int64
)

// Main runs the package's tests and then removes its shared container. Each test package that uses
// Addr calls it from its TestMain:
//
//	func TestMain(m *testing.M) { redistest.Main(m) }
//
// A failure to remove the container fails the run, so a leak is not missed.
func Main(m *testing.M) {
	inMain.Store(true)
	code := m.Run()
	if sharedCtr != nil {
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		err := sharedCtr.Terminate(ctx)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "redistest: remove %s container: %v\n", Image, err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

// Addr returns the host:port of the package's shared container.
func Addr(t testing.TB) string {
	t.Helper()
	if !inMain.Load() {
		t.Fatal("redistest: the test package's TestMain must call redistest.Main")
	}
	dockertest.Check(t)
	sharedOnce.Do(func() { sharedCtr, sharedAddr, sharedErr = start() })
	if sharedErr != nil {
		t.Fatalf("redistest: %v", sharedErr)
	}
	return sharedAddr
}

// Prefix returns a key prefix no other call in this test binary returns, so tests sharing the
// container do not share keys.
func Prefix(t testing.TB) string {
	t.Helper()
	return "t" + strconv.FormatInt(prefixCounter.Add(1), 10) + ":"
}

// start runs a container and returns it with its host:port once it answers PING. On an error it
// removes the container itself, since the caller gets none.
func start() (ctr *tcredis.RedisContainer, addr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	ctr, err = tcredis.Run(ctx, Image)
	if ctr != nil {
		defer func() {
			if err != nil {
				_ = ctr.Terminate(context.Background())
			}
		}()
	}
	if err != nil {
		return nil, "", fmt.Errorf("start %s: %w", Image, err)
	}
	addr, err = ctr.Endpoint(ctx, "")
	if err != nil {
		return nil, "", fmt.Errorf("endpoint: %w", err)
	}
	if err := waitPing(ctx, addr); err != nil {
		return nil, "", err
	}
	return ctr, addr, nil
}

// waitPing returns once addr answers PING, or ctx's end.
func waitPing(ctx context.Context, addr string) error {
	c := goredis.NewClient(&goredis.Options{Addr: addr, MaxRetries: -1})
	defer func() { _ = c.Close() }()
	for {
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		err := c.Ping(pctx).Err()
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%s not ready: %w", Image, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Server is a Redis container of its own, for tests that stop and start it. Its address goes
// through a local proxy, so it stays the same when a restart moves the container's mapped port.
type Server struct {
	ctr   *tcredis.RedisContainer
	proxy *dockertest.Proxy
}

// NewServer starts a dedicated container, removed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	dockertest.Check(t)
	ctr, addr, err := start()
	if err != nil {
		t.Fatalf("redistest: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
	p, err := dockertest.NewProxy(addr)
	if err != nil {
		t.Fatalf("redistest: %v", err)
	}
	t.Cleanup(p.Close)
	return &Server{ctr: ctr, proxy: p}
}

// Addr returns the server's host:port, valid across restarts.
func (s *Server) Addr() string { return s.proxy.Addr() }

// Stop stops the container and drops every connection through the proxy.
func (s *Server) Stop(t testing.TB) {
	t.Helper()
	timeout := 10 * time.Second
	if err := s.ctr.Stop(context.Background(), &timeout); err != nil {
		t.Fatalf("redistest: stop: %v", err)
	}
	s.proxy.DropAll()
}

// Start starts the container again and returns once it answers PING.
func (s *Server) Start(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := s.ctr.Start(ctx); err != nil {
		t.Fatalf("redistest: start: %v", err)
	}
	addr, err := s.ctr.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("redistest: endpoint: %v", err)
	}
	s.proxy.SetTarget(addr)
	if err := waitPing(ctx, s.Addr()); err != nil {
		t.Fatalf("redistest: %v", err)
	}
}
