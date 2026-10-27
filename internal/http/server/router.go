package server

import (
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/middleware"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
)

// The limits of TDD-07 §7.
const (
	MaxBodyBytes      = 64 << 10
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 15 * time.Second
	IdleTimeout       = 60 * time.Second
)

// notFoundDetail is the detail of the 404 for an unknown path or an unsupported method.
const notFoundDetail = "No such resource."

// Options are the dependencies of the API router.
type Options struct {
	BasePath        string // http.base_path: "" or "/segment…"
	Logger          *slog.Logger
	Problems        *problem.Writer
	TracerProvider  trace.TracerProvider
	Propagator      propagation.TextMapPropagator
	RequestDuration metric.Float64Histogram // http.server.request.duration
	Health          *health.Checker
	Routes          func(chi.Router) // registers the API routes under BasePath; nil for none
}

// NewRouter returns the API router. Every request passes request id, trace, access log, recover
// and body limit, in that order, so the middleware also covers the probes and the 404s. /livez and
// /readyz sit at the root; Routes are mounted under BasePath. An unknown path or an unsupported
// method answers 404 NOT_FOUND (SDD §10).
func NewRouter(o Options) http.Handler {
	r := chi.NewRouter()
	r.Use(
		requestid.Middleware,
		middleware.Trace(o.TracerProvider, o.Propagator),
		middleware.AccessLog(o.Logger, o.RequestDuration),
		middleware.Recover(o.Logger, o.Problems),
		middleware.BodyLimit(MaxBodyBytes, o.Problems),
	)
	notFound := func(w http.ResponseWriter, r *http.Request) {
		o.Problems.Write(w, r, &domain.Error{Code: domain.CodeNotFound, Detail: notFoundDetail})
	}
	r.NotFound(notFound)
	r.MethodNotAllowed(notFound)

	r.Method(http.MethodGet, "/livez", o.Health.Live())
	r.Method(http.MethodGet, "/readyz", o.Health.Ready())
	if o.Routes != nil {
		if o.BasePath == "" {
			r.Group(o.Routes)
		} else {
			r.Route(o.BasePath, o.Routes)
		}
	}
	return r
}

// NewServer returns an http.Server serving h with the TDD-07 §7 timeouts. errorLog receives the
// server's own errors (failed handshakes, bad requests); nil uses the log package's default.
func NewServer(h http.Handler, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		ErrorLog:          errorLog,
	}
}
