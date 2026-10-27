package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// AccessLog writes one line per request to logger, at info or at error for a 5xx, and records the
// request's duration on duration, the http.server.request.duration histogram (TDD-08 §5.1, §5.2).
// The line holds the method, the route pattern (empty when no route matched), the status, the
// duration in seconds, the bytes written and the request ids; never the raw path, query, headers
// or body (G-6). A request whose handler aborts with http.ErrAbortHandler is still logged, at
// error with aborted=true, and measured with error.type=aborted. It must be installed with
// chi.Router.Use, after requestid.Middleware.
func AccessLog(logger *slog.Logger, duration metric.Float64Histogram) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := wrap(w, r)
			completed := false
			defer func() { logRequest(logger, duration, ww, r, time.Since(start), !completed) }()
			next.ServeHTTP(ww, r)
			completed = true
		})
	}
}

// logRequest records the duration and writes the access-log line of one request.
func logRequest(logger *slog.Logger, duration metric.Float64Histogram, ww chimw.WrapResponseWriter,
	r *http.Request, elapsed time.Duration, aborted bool,
) {
	method := normalMethod(r.Method)
	route := routePattern(r)
	code := responseStatus(ww, aborted)

	labels := []attribute.KeyValue{semconv.HTTPRequestMethodKey.String(method)}
	if code != 0 {
		labels = append(labels, semconv.HTTPResponseStatusCode(code))
	}
	if route != "" {
		labels = append(labels, semconv.HTTPRoute(route))
	}
	if aborted {
		labels = append(labels, semconv.ErrorTypeKey.String(abortedType))
	}
	duration.Record(r.Context(), elapsed.Seconds(), metric.WithAttributes(labels...))

	level := slog.LevelInfo
	if aborted || code >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("method", method),
		slog.String("route", route),
		slog.Int("status", code),
		slog.Float64("duration", elapsed.Seconds()),
		slog.Int("bytes", ww.BytesWritten()),
		telemetry.RequestID(requestid.From(r.Context())),
	}
	if up := requestid.UpstreamFrom(r.Context()); up != "" {
		attrs = append(attrs, slog.String("upstream_request_id", up))
	}
	if aborted {
		attrs = append(attrs, slog.Bool("aborted", true))
	}
	logger.LogAttrs(r.Context(), level, "request", attrs...)
}
