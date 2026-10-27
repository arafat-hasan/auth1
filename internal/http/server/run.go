package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Listener is one server to run: a bound listener and its handler. Name identifies it in logs and
// errors.
type Listener struct {
	Name     string
	Listener net.Listener
	Handler  http.Handler
}

// Shutdown is the stop sequence after the context ends: Drain is called (it makes /readyz fail),
// keep-alives are disabled, and after DrainDelay every server is shut down, waiting at most
// Timeout for requests in flight.
type Shutdown struct {
	Drain      func() // nil for none
	DrainDelay time.Duration
	Timeout    time.Duration
}

// Run serves every listener until ctx is done, then stops them as s says, and returns when all
// have stopped. If a server fails, Run stops the others at once, without draining, and returns
// that error. A shutdown that passes s.Timeout closes the remaining connections and returns an
// error wrapping context.DeadlineExceeded.
func Run(ctx context.Context, logger *slog.Logger, ls []Listener, s Shutdown) error {
	errorLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	servers := make([]*http.Server, len(ls))
	g, gctx := errgroup.WithContext(ctx)
	for i, l := range ls {
		srv := NewServer(l.Handler, errorLog)
		servers[i] = srv
		logger.LogAttrs(ctx, slog.LevelInfo, "listening",
			slog.String("listener", l.Name), slog.String("address", l.Listener.Addr().String()))
		g.Go(func() error {
			if err := srv.Serve(l.Listener); !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve %s on %s: %w", l.Name, l.Listener.Addr(), err)
			}
			return nil
		})
	}
	g.Go(func() error {
		<-gctx.Done()
		if ctx.Err() != nil { // a signal, not a failed server
			drain(ctx, logger, servers, s)
		}
		return shutdown(ctx, logger, servers, s.Timeout)
	})
	return g.Wait()
}

// drain fails readiness, disables keep-alives and waits the drain delay, so load balancers stop
// sending requests before the listeners close.
func drain(ctx context.Context, logger *slog.Logger, servers []*http.Server, s Shutdown) {
	logger.LogAttrs(ctx, slog.LevelInfo, "draining", slog.Float64("delay", s.DrainDelay.Seconds()))
	if s.Drain != nil {
		s.Drain()
	}
	for _, srv := range servers {
		srv.SetKeepAlivesEnabled(false)
	}
	time.Sleep(s.DrainDelay)
}

// shutdown shuts every server down concurrently within timeout, closing any that overrun it.
func shutdown(ctx context.Context, logger *slog.Logger, servers []*http.Server, timeout time.Duration) error {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Go(func() {
			if err := srv.Shutdown(sctx); err != nil {
				errs[i] = fmt.Errorf("shutdown: %w", err)
				_ = srv.Close() // drop the connections still open
			}
		})
	}
	wg.Wait()
	err := errors.Join(errs...)
	logger.LogAttrs(ctx, slog.LevelInfo, "stopped", slog.Bool("clean", err == nil))
	return err
}
