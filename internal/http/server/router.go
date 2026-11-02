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
	"github.com/arafat-hasan/auth1/internal/http/clientip"
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
	// ClientIP finds each request's client IP through the trusted proxies (TDD-07 §1); nil uses
	// the TCP peer.
	ClientIP *clientip.Resolver
	// APIMiddleware runs on the Routes and on every 404, after the router's own middleware: only
	// the probes and the Dev routes never pass it. It holds the L-1 rate limit.
	APIMiddleware []func(http.Handler) http.Handler
	// Dev registers the development-only routes, such as GET /dev/messages, at the root: they are
	// not part of the API contract. nil outside development.
	Dev func(chi.Router)
}

// NewRouter returns the API router. Every request passes request id, client IP, trace, access log,
// recover and body limit, in that order, so the middleware also covers the probes and the 404s;
// the Routes and the 404s then pass APIMiddleware. /livez, /readyz and the Dev routes sit at the root; Routes
// are mounted under BasePath. An unknown path or an unsupported method answers 404 NOT_FOUND
// (SDD §10).
func NewRouter(o Options) http.Handler {
	ips := o.ClientIP
	if ips == nil {
		ips, _ = clientip.New(nil) // trusts nothing, so cannot fail
	}
	r := chi.NewRouter()
	r.Use(
		requestid.Middleware,
		ips.Middleware,
		middleware.Trace(o.TracerProvider, o.Propagator),
		middleware.AccessLog(o.Logger, o.RequestDuration),
		middleware.Recover(o.Logger, o.Problems),
		middleware.BodyLimit(MaxBodyBytes, o.Problems),
	)
	notFound := func(w http.ResponseWriter, r *http.Request) {
		o.Problems.Write(w, r, &domain.Error{Code: domain.CodeNotFound, Detail: notFoundDetail})
	}
	// Unknown paths and unsupported methods are API requests too, so they pass APIMiddleware (L-1).
	limitedNotFound := chi.Chain(o.APIMiddleware...).HandlerFunc(notFound).ServeHTTP
	r.NotFound(limitedNotFound)
	r.MethodNotAllowed(limitedNotFound)

	// The probes also answer HEAD, which some load balancers send; net/http drops the body.
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		r.Method(m, "/livez", o.Health.Live())
		r.Method(m, "/readyz", o.Health.Ready())
	}
	if o.Dev != nil {
		r.Group(o.Dev)
	}
	if o.Routes != nil {
		api := func(r chi.Router) {
			r.Use(o.APIMiddleware...)
			o.Routes(r)
		}
		if o.BasePath == "" {
			r.Group(api)
		} else {
			r.Route(o.BasePath, func(r chi.Router) {
				// The subrouter's Use already wraps its 404s; the root's handler would pass
				// APIMiddleware twice.
				r.NotFound(notFound)
				r.MethodNotAllowed(notFound)
				api(r)
			})
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
