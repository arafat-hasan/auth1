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
	"golang.org/x/sync/errgroup"

	"github.com/arafat-hasan/auth1/internal/adapters/keyring"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
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

	keys, problems := loadCryptoKeys(cfg.Encryption, logger)
	if len(problems) > 0 {
		return printProblems(cmd.ErrOrStderr(), problems)
	}

	// The pools connect on first use, so serve starts while PostgreSQL is down; /readyz reports it
	// through a probe pool of its own, so busy request connections do not fail readiness. They
	// close after the servers have shut down (deferred after telemetry, so they close first).
	db, err := postgres.Open(cfg.Database, cfg.App.Environment)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close database pool: %w", cerr))
		}
	}()
	probe, err := postgres.OpenProbe(cfg.Database, cfg.App.Environment)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := probe.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close database probe: %w", cerr))
		}
	}()

	metrics := telemetry.NewMetrics(tel.MeterProvider())
	duration, err := metrics.Histogram("http.server.request.duration")
	if err != nil {
		return err
	}
	jwksKeys, err := metrics.Gauge("auth1_jwks_keys")
	if err != nil {
		return err
	}
	kr, err := keyring.New(ctx, cfg.Keys.KeyringFile.Path(), postgres.NewSigningKeys(db), keyring.Options{
		MinPublishBeforeUse: cfg.Keys.MinPublishBeforeUse, AccessTTL: cfg.Tokens.AccessTTL,
		Logger: logger, Keys: jwksKeys,
	})
	if err != nil {
		return err
	}
	mode := cfg.ServiceAuth.Mode
	api, err := handlers.NewAPI(kr, handlers.MetadataOptions{
		Issuer: cfg.HTTP.Issuer, BasePath: cfg.HTTP.BasePath,
		ClientCredentials: mode == config.ServiceAuthClientCredentials || mode == config.ServiceAuthBoth,
	})
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
	checks.Register("postgres", postgres.Ping(probe, pingTimeout), true)
	checks.Register("keyring", kr.Ready, true)

	listeners, err := bind(deps.listen, cfg.HTTP.Listen, cfg.Telemetry.MetricsListen)
	if err != nil {
		return err
	}
	pw := problem.New(logger)
	router := server.NewRouter(server.Options{
		BasePath:        cfg.HTTP.BasePath,
		Logger:          logger,
		Problems:        pw,
		TracerProvider:  tel.TracerProvider(),
		Propagator:      tel.Propagator(),
		RequestDuration: duration,
		Health:          checks,
		Routes:          gen.Routes(api, pw),
	})

	// The keyring pollers run until the servers have stopped. They return only when their context
	// ends, so they never stop the servers.
	pollCtx, stopPolling := context.WithCancel(ctx)
	g, gctx := errgroup.WithContext(pollCtx)
	g.Go(func() error { return keys.fields.Run(gctx) })
	g.Go(func() error { return kr.Run(gctx) })
	err = server.Run(ctx, logger, []server.Listener{
		{Name: "http", Listener: listeners[0], Handler: router},
		{Name: "metrics", Listener: listeners[1], Handler: tel.MetricsHandler()},
	}, server.Shutdown{
		Drain:      func() { draining.Store(true) },
		DrainDelay: deps.drainDelay,
		Timeout:    deps.shutdownTimeout,
	})
	stopPolling()
	return errors.Join(err, g.Wait())
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
