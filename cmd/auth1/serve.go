package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// The stop sequence on SIGTERM: /readyz fails for drainDelay, so load balancers stop sending
// requests, then the servers get shutdownTimeout to finish the requests in flight (the write
// timeout, which no response outlives), then telemetry gets telemetryTimeout to flush. The total,
// 25s, stays within Kubernetes' default 30s grace period (TDD-08 §8).
const (
	drainDelay       = 5 * time.Second
	shutdownTimeout  = server.WriteTimeout
	telemetryTimeout = 5 * time.Second
)

// pingTimeout bounds the PostgreSQL readiness check.
const pingTimeout = time.Second

// errDraining is the draining check's error once shutdown has begun.
var errDraining = errors.New("shutting down")

// serveDeps are what serve would otherwise take from the operating system. Tests replace them.
type serveDeps struct {
	listen           func(network, addr string) (net.Listener, error)
	drainDelay       time.Duration
	shutdownTimeout  time.Duration
	telemetryTimeout time.Duration
}

func defaultServeDeps() serveDeps {
	return serveDeps{
		listen: net.Listen, drainDelay: drainDelay,
		shutdownTimeout: shutdownTimeout, telemetryTimeout: telemetryTimeout,
	}
}

// newServeCmd builds "auth1 serve". environ supplies the AUTH1_ overrides (os.Environ in main).
func newServeCmd(environ func() []string, info buildInfo, deps serveDeps) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the HTTP API until SIGINT or SIGTERM",
		Long: "Load and validate the configuration, then serve the HTTP API on http.listen and the " +
			"metrics on telemetry.metrics_listen. On SIGINT or SIGTERM, /readyz fails for 5s, then " +
			"requests in flight get 15s to finish and telemetry 5s to flush.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, path, environ(), info, deps)
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "configuration file (YAML)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// serve runs the servers until the command's context ends (main cancels it on SIGINT or SIGTERM).
func serve(cmd *cobra.Command, path string, environ []string, info buildInfo, deps serveDeps) (err error) {
	ctx := cmd.Context()
	cfg, problems, err := loadConfig(path, environ)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return printProblems(cmd.ErrOrStderr(), problems)
	}

	tel, err := telemetry.New(ctx, cfg.Telemetry, telemetry.BuildInfo{Version: info.Version})
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deps.telemetryTimeout)
		defer cancel()
		if serr := tel.Shutdown(sctx); serr != nil {
			err = errors.Join(err, fmt.Errorf("telemetry: %w", serr))
		}
	}()
	logger := tel.Logger()
	slog.SetDefault(logger)
	otel.SetTextMapPropagator(tel.Propagator())

	// The pool connects on first use, so serve starts while PostgreSQL is down; /readyz reports it.
	// It closes after the servers have shut down (deferred after telemetry, so it runs first).
	db, err := postgres.Open(cfg.Database, cfg.App.Environment)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close database pool: %w", cerr))
		}
	}()

	duration, err := telemetry.NewMetrics(tel.MeterProvider()).Histogram("http.server.request.duration")
	if err != nil {
		return err
	}
	var draining atomic.Bool
	checks := health.New(logger)
	checks.Register("draining", func(context.Context) error {
		if draining.Load() {
			return errDraining
		}
		return nil
	}, true)
	checks.Register("postgres", postgres.Ping(db, pingTimeout), true)

	listeners, err := bind(deps.listen, cfg.HTTP.Listen, cfg.Telemetry.MetricsListen)
	if err != nil {
		return err
	}
	router := server.NewRouter(server.Options{
		BasePath:        cfg.HTTP.BasePath,
		Logger:          logger,
		Problems:        problem.New(logger),
		TracerProvider:  tel.TracerProvider(),
		Propagator:      tel.Propagator(),
		RequestDuration: duration,
		Health:          checks,
	})
	return server.Run(ctx, logger, []server.Listener{
		{Name: "http", Listener: listeners[0], Handler: router},
		{Name: "metrics", Listener: listeners[1], Handler: tel.MetricsHandler()},
	}, server.Shutdown{
		Drain:      func() { draining.Store(true) },
		DrainDelay: deps.drainDelay,
		Timeout:    deps.shutdownTimeout,
	})
}

// bind opens the API and metrics listeners. If one fails, it closes those already open.
func bind(listen func(network, addr string) (net.Listener, error), httpAddr, metricsAddr string) ([]net.Listener, error) {
	var out []net.Listener
	for _, l := range []struct{ key, addr string }{{"http.listen", httpAddr}, {"telemetry.metrics_listen", metricsAddr}} {
		ln, err := listen("tcp", l.addr)
		if err != nil {
			for _, open := range out {
				_ = open.Close()
			}
			return nil, fmt.Errorf("listen on %s %q: %w", l.key, l.addr, err)
		}
		out = append(out, ln)
	}
	return out, nil
}
